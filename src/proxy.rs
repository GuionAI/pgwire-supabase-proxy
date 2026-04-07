//! Byte-forward proxy core.

use crate::auth::{Claims, JwtAuthenticator};
use crate::error::ProxyError;
use crate::scram;
use crate::wire;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};



/// Start the byte-forward proxy server.
pub async fn serve(
    config: crate::Config,
    listener: TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,pgwire_supabase_proxy=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .try_init();

    let addr = listener.local_addr()?;
    tracing::info!(addr = %addr, "starting pgwire-supabase-proxy");

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (socket, peer_addr) = result?;
                tracing::info!(peer_addr = %peer_addr, "connection accepted");

                let config = config.clone();
                tokio::spawn(async move {
                    let result = handle_connection(socket, peer_addr, &config).await;
                    if let Err(e) = result {
                        tracing::error!(error = %e, peer_addr = %peer_addr, "connection error");
                    }
                });
            }
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received, stopping");
                break;
            }
        }
    }

    Ok(())
}

/// Handle one client connection.
async fn handle_connection(
    mut client: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    config: &crate::Config,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let start = std::time::Instant::now();

    // Step 2: Handle SSLRequest
    let mut first_msg_len_buf = [0u8; 4];
    client.read_exact(&mut first_msg_len_buf).await?;
    let first_msg_len = u32::from_be_bytes(first_msg_len_buf);

    let msg_len = if first_msg_len == 8 {
        let mut code_buf = [0u8; 4];
        client.read_exact(&mut code_buf).await?;
        let code = u32::from_be_bytes(code_buf);
        if code == 80877103 {
            client.write_all(b"N").await?;
            tracing::debug!(peer_addr = %peer_addr, "SSL request rejected");
            let mut len_buf = [0u8; 4];
            client.read_exact(&mut len_buf).await?;
            u32::from_be_bytes(len_buf)
        } else {
            first_msg_len
        }
    } else {
        first_msg_len
    };

    // Step 3: Parse StartupMessage
    let mut startup_buf = vec![0u8; (msg_len - 4) as usize];
    client.read_exact(&mut startup_buf).await?;
    let startup = wire::parse_startup_body(msg_len, &startup_buf)?;
    let user = startup
        .params
        .get("user")
        .cloned()
        .ok_or_else(|| ProxyError::ProtocolViolation("StartupMessage missing user".into()))?;
    let database = startup
        .params
        .get("database")
        .cloned()
        .unwrap_or_else(|| "postgres".to_string());

    tracing::debug!(peer_addr = %peer_addr, user = %user, database = %database, "startup received");

    // Step 4: Authenticate client
    wire::write_authentication_cleartext_password(&mut client).await?;
    let password = wire::read_password_message(&mut client).await?;

    // Step 5: Verify JWT
    let auth = JwtAuthenticator::new(config.jwt_secret.clone());
    let claims: Claims = match auth.validate_token(&password).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(peer_addr = %peer_addr, error = %e, "JWT verification failed");
            wire::write_error_response(&mut client, "28P01", "JWT verification failed").await?;
            return Ok(());
        }
    };
    let jwt_sub = claims.sub.clone();
    tracing::info!(peer_addr = %peer_addr, user_id = %jwt_sub, "client authenticated");

    // Validate sub claim
    if jwt_sub.len() > 128 || jwt_sub.bytes().any(|b| b == 0) {
        wire::write_error_response(&mut client, "28P01", "invalid sub claim").await?;
        return Ok(());
    }
    if !jwt_sub
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        wire::write_error_response(&mut client, "28P01", "invalid sub claim format").await?;
        return Ok(());
    }

    // Step 6: Open backend TCP
    let (backend_host, backend_port, backend_user, backend_password, backend_db) =
        parse_backend_url(&config.backend_postgres_url)?;

    let mut backend = match tokio::net::TcpStream::connect((backend_host.as_str(), backend_port)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(peer_addr = %peer_addr, error = %e, "backend TCP connect failed");
            wire::write_error_response(&mut client, "08001", &format!("backend connection failed: {}", e)).await?;
            return Ok(());
        }
    };
    tracing::debug!(peer_addr = %peer_addr, backend = %backend_host, "backend TCP opened");

    // Step 7: Send backend StartupMessage (plain TCP, no TLS)
    let mut backend_params = HashMap::new();
    backend_params.insert("user".into(), backend_user.clone());
    backend_params.insert("database".into(), backend_db.clone());
    backend_params.insert("application_name".into(), format!("psp/{}", user));
    backend_params.insert("client_encoding".into(), "UTF8".into());
    wire::write_startup_message(&mut backend, &backend_params).await?;

    // Step 9: Handle backend auth
    let auth_method = wire::read_authentication_method(&mut backend).await?;
    match auth_method {
        wire::AuthMethod::Ok => {
            tracing::debug!(peer_addr = %peer_addr, "backend auth: OK");
        }
        wire::AuthMethod::CleartextPassword => {
            wire::write_password_message(&mut backend, &backend_password).await?;
        }
        wire::AuthMethod::Sasl { mechanisms } => {
            if !mechanisms.contains(&"SCRAM-SHA-256".to_string()) {
                return Err(Box::new(ProxyError::BackendAuth(format!(
                    "unsupported SASL mechanisms: {:?}",
                    mechanisms
                ))));
            }
            scram::scram_sha_256_authenticate(&mut backend, &backend_user, &backend_password)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        }
        wire::AuthMethod::Md5Password { .. } => {
            return Err(Box::new(ProxyError::BackendAuth(
                "MD5 auth not supported".into(),
            )));
        }
    }

    // Step 10: Drain backend until ReadyForQuery
    let mut backend_params_response = Vec::new();
    loop {
        let msg = wire::read_backend_message(&mut backend).await?;
        match msg {
            wire::BackendMessage::ReadyForQuery { .. } => break,
            wire::BackendMessage::ParameterStatus { key, value } => {
                backend_params_response.push((key, value));
            }
            wire::BackendMessage::BackendKeyData { process_id, .. } => {
                tracing::debug!(
                    peer_addr = %peer_addr,
                    backend_pid = process_id,
                    "backend key data received"
                );
            }
            wire::BackendMessage::ErrorResponse {
                severity,
                code,
                message,
            } => {
                return Err(Box::new(ProxyError::BackendError(format!(
                    "{} {}: {}",
                    severity.unwrap_or_default(),
                    code.unwrap_or_default(),
                    message
                ))));
            }
            wire::BackendMessage::Unknown { .. } => {}
        }
    }

    // Step 11: Inject JWT claim
    let escaped_sub = escape_pg_string(&jwt_sub);
    let set_config_sql = format!(
        "SELECT set_config('request.jwt.claim.sub', E'{}', false); SET ROLE authenticated;",
        escaped_sub
    );
    wire::write_query(&mut backend, &set_config_sql).await?;

    loop {
        let msg = wire::read_backend_message(&mut backend).await?;
        match msg {
            wire::BackendMessage::ReadyForQuery { .. } => break,
            wire::BackendMessage::ErrorResponse { code, message, .. } => {
                tracing::error!(
                    peer_addr = %peer_addr,
                    code = ?code,
                    message = %message,
                    "set_config/ROLE failed"
                );
                wire::write_error_response(
                    &mut client,
                    &code.unwrap_or_else(|| "08006".into()),
                    &format!("backend session setup failed: {}", message),
                )
                .await?;
                return Ok(());
            }
            wire::BackendMessage::Unknown { .. } => {}
            _ => {}
        }
    }

    // Step 12: Complete client startup
    wire::write_authentication_ok(&mut client).await?;
    for (key, value) in &backend_params_response {
        wire::write_parameter_status(&mut client, key, value).await?;
    }
    let client_pid: i32 = rand::random();
    let client_secret: i32 = rand::random();
    wire::write_backend_key_data(&mut client, client_pid, client_secret).await?;
    wire::write_ready_for_query(&mut client, b'I').await?;
    client.flush().await?;

    tracing::info!(
        peer_addr = %peer_addr,
        user_id = %jwt_sub,
        "session ready — entering byte-forward mode"
    );

    // Step 13: Byte-forward (bidirectional, concurrent)
    let result = tokio::io::copy_bidirectional(&mut client, &mut backend).await;

    match result {
        Ok((bytes_to_backend, bytes_to_client)) => {
            tracing::info!(
                peer_addr = %peer_addr,
                user_id = %jwt_sub,
                duration_ms = start.elapsed().as_millis() as u64,
                bytes_to_backend,
                bytes_to_client,
                close_reason = "both sides closed",
                "connection closed"
            );
        }
        Err(e) => {
            tracing::error!(
                peer_addr = %peer_addr,
                user_id = %jwt_sub,
                duration_ms = start.elapsed().as_millis() as u64,
                error = %e,
                "connection closed with error"
            );
        }
    }

    Ok(())
}

/// Parse a backend Postgres URL into its components.
/// Accepts both `postgresql://` and `postgres://` schemes.
fn parse_backend_url(url: &str) -> Result<(String, u16, String, String, String), ProxyError> {
    let url = url
        .trim_start_matches("postgresql://")
        .trim_start_matches("postgres://");
    let (creds, rest) = url
        .split_once('@')
        .ok_or_else(|| ProxyError::InvalidStartup("backend URL missing '@'".into()))?;
    let (user, password) = creds
        .split_once(':')
        .ok_or_else(|| ProxyError::InvalidStartup("backend URL missing password".into()))?;
    let (host_port, db_and_query) = rest
        .split_once('/')
        .ok_or_else(|| ProxyError::InvalidStartup("backend URL missing '/db'".into()))?;
    let (host_port, _query) = host_port.split_once('?').unwrap_or((host_port, ""));
    let (host, port_str) = host_port.split_once(':').unwrap_or((host_port, "5432"));
    let port: u16 = port_str
        .parse()
        .map_err(|_| ProxyError::InvalidStartup("invalid backend port".into()))?;
    // Database name is the path component before any '?'
    let database = db_and_query
        .split('?')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("postgres");
    Ok((
        host.to_string(),
        port,
        user.to_string(),
        password.to_string(),
        database.to_string(),
    ))
}

fn escape_pg_string(s: &str) -> String {
    let mut r = String::with_capacity(s.len() * 2);
    for c in s.chars() {
        match c {
            '\'' => r.push_str("''"),
            '\\' => r.push_str("\\\\"),
            '\n' => r.push_str("\\n"),
            '\r' => r.push_str("\\r"),
            '\t' => r.push_str("\\t"),
            _ => r.push(c),
        }
    }
    r
}
