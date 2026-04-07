//! JWT authentication utilities.

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// JWT claims extracted from the `sub` field.
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

/// Validates HS256 JWTs.
#[derive(Clone)]
pub struct JwtAuthenticator {
    jwt_secret: String,
}

impl JwtAuthenticator {
    pub fn new(jwt_secret: String) -> Self {
        Self { jwt_secret }
    }

    /// Decode and verify a JWT. Returns the claims on success.
    pub async fn validate_token(&self, token: &str) -> Result<Claims, crate::ProxyError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &validation,
        )
        .map_err(|e| {
            tracing::debug!(error = %e, "JWT validation failed");
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => crate::ProxyError::JwtExpired,
                _ => crate::ProxyError::InvalidJwt(e.to_string()),
            }
        })
        .map(|td| td.claims)
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
        let token = make_test_token(secret, "550e8400-e29b-41d4-a716-446655440000", 3600);

        let auth = JwtAuthenticator::new(secret.to_string());
        let result = auth.validate_token(&token).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub, "550e8400-e29b-41d4-a716-446655440000");
    }

    #[tokio::test]
    async fn test_expired_jwt() {
        let secret = "test-secret-32-chars-minimum!";
        let token = make_test_token(secret, "user-123", -3600);

        let auth = JwtAuthenticator::new(secret.to_string());
        let result = auth.validate_token(&token).await;
        assert!(matches!(result, Err(crate::ProxyError::JwtExpired)));
    }

    #[tokio::test]
    async fn test_invalid_jwt() {
        let auth = JwtAuthenticator::new("test-secret".to_string());
        let result = auth.validate_token("invalid.token.here").await;
        assert!(matches!(result, Err(crate::ProxyError::InvalidJwt(_))));
    }

    #[tokio::test]
    async fn test_wrong_secret_jwt() {
        let token = make_test_token("correct-secret-32-chars-minimum", "user-123", 3600);
        let auth = JwtAuthenticator::new("wrong-secret-32-chars-minimum!!".to_string());
        let result = auth.validate_token(&token).await;
        assert!(matches!(result, Err(crate::ProxyError::InvalidJwt(_))));
    }
}
