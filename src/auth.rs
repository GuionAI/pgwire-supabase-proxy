use crate::error::ProxyError;
use async_trait::async_trait;
use futures::SinkExt;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use pgwire::api::auth::ServerParameterProvider;
use pgwire::api::{ClientInfo, PgWireConnectionState};
use pgwire::error::{PgWireError, PgWireResult};
use pgwire::messages::startup::{Authentication, BackendKeyData, ParameterStatus, SecretKey};
use pgwire::messages::response::{ReadyForQuery, TransactionStatus};
use pgwire::messages::{PgWireBackendMessage, PgWireFrontendMessage};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

pub const METADATA_USER_ID: &str = "pgwire_supabase_proxy.user_id";

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub iat: Option<i64>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

pub struct JwtAuthenticator {
    jwt_secret: Arc<RwLock<String>>,
}

impl JwtAuthenticator {
    pub fn new(jwt_secret: String) -> Self {
        Self {
            jwt_secret: Arc::new(RwLock::new(jwt_secret)),
        }
    }

    pub async fn validate_token(&self, token: &str) -> Result<Claims, ProxyError> {
        let secret = self.jwt_secret.read().await;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        decode::<Claims>(token, &DecodingKey::from_secret(secret.as_bytes()), &validation)
            .map_err(|e| {
                tracing::debug!(error = %e, "JWT validation failed");
                match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => ProxyError::JwtExpired,
                    _ => ProxyError::InvalidJwt(e.to_string()),
                }
            })
            .map(|td| td.claims)
    }
}

pub struct StartupHandler<S: ServerParameterProvider> {
    auth: Arc<JwtAuthenticator>,
    param_provider: Arc<S>,
}

impl<S: ServerParameterProvider> StartupHandler<S> {
    pub fn new(auth: Arc<JwtAuthenticator>, param_provider: Arc<S>) -> Self {
        Self { auth, param_provider }
    }
}

impl<S: ServerParameterProvider + Clone + Send + Sync + 'static> Clone for StartupHandler<S> {
    fn clone(&self) -> Self {
        Self {
            auth: self.auth.clone(),
            param_provider: self.param_provider.clone(),
        }
    }
}

#[async_trait]
impl<S> pgwire::api::auth::StartupHandler for StartupHandler<S>
where
    S: ServerParameterProvider + 'static,
{
    async fn on_startup<C>(
        &self,
        client: &mut C,
        message: PgWireFrontendMessage,
    ) -> PgWireResult<()>
    where
        C: ClientInfo
            + futures::Sink<PgWireBackendMessage>
            + Unpin
            + Send
            + Sync,
        C::Error: std::fmt::Debug,
        PgWireError: From<C::Error>,
    {
        let PgWireFrontendMessage::Startup(startup) = message else {
            return Ok(());
        };

        let token = startup
            .parameters
            .get("user")
            .ok_or_else(|| {
                PgWireError::ApiError(Box::new(ProxyError::InvalidStartup("missing user".into())))
            })?;

        tracing::info!(
            user_prefix = %token.chars().take(20).collect::<String>(),
            "connection attempt"
        );

        let claims = self.auth.validate_token(token).await.map_err(|e| {
            tracing::warn!(error = %e, "authentication failed");
            PgWireError::ApiError(Box::new(e))
        })?;

        tracing::info!(user_id = %claims.sub, "authenticated");

        client.metadata_mut().insert(METADATA_USER_ID.to_string(), claims.sub.clone());
        for (k, v) in &startup.parameters {
            client.metadata_mut().insert(k.clone(), v.clone());
        }

        client
            .send(PgWireBackendMessage::Authentication(Authentication::Ok))
            .await
            .map_err(|e| PgWireError::from(e))?;

        if let Some(params) = self.param_provider.server_parameters(client) {
            for (k, v) in params {
                client
                    .send(PgWireBackendMessage::ParameterStatus(ParameterStatus::new(k, v)))
                    .await
                    .map_err(|e| PgWireError::from(e))?;
            }
        }

        client
            .send(PgWireBackendMessage::BackendKeyData(BackendKeyData::new(
                0,
                SecretKey::I32(0),
            )))
            .await
            .map_err(|e| PgWireError::from(e))?;

        client
            .send(PgWireBackendMessage::ReadyForQuery(ReadyForQuery::new(
                TransactionStatus::Idle,
            )))
            .await
            .map_err(|e| PgWireError::from(e))?;
        client.set_state(PgWireConnectionState::ReadyForQuery);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_test_token(secret: &str, user_id: &str, exp_offset_secs: i64) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + exp_offset_secs;
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = Claims {
            sub: user_id.to_string(),
            exp: Some(exp),
            iat: Some(iat),
            role: Some("authenticated".to_string()),
            email: None,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_valid_jwt() {
        let secret = "test-secret-32-chars-minimum!";
        let token = make_test_token(secret, "user-123", 3600);

        let auth = JwtAuthenticator::new(secret.to_string());
        let result = auth.validate_token(&token).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub, "user-123");
    }

    #[tokio::test]
    async fn test_invalid_jwt() {
        let auth = JwtAuthenticator::new("test-secret".to_string());
        let result = auth.validate_token("invalid.token.here").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_expired_jwt() {
        let secret = "test-secret-32-chars-minimum!";
        let token = make_test_token(secret, "user-123", -3600);

        let auth = JwtAuthenticator::new(secret.to_string());
        let result = auth.validate_token(&token).await;
        assert!(matches!(result, Err(ProxyError::JwtExpired)));
    }
}
