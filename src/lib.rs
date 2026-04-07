//! pgwire-supabase-proxy library
//!
//! A byte-forward Postgres proxy that authenticates clients via JWT,
//! opens a backend connection with its own credentials, injects the JWT
//! `sub` claim into the backend session, and then copies bytes transparently.

mod auth;
mod error;
mod proxy;
mod scram;
mod wire;

// Re-export Config for use by integration tests and main binary.
pub use auth::{Claims, JwtAuthenticator};
pub use error::ProxyError;
pub use proxy::serve;

/// Configuration for the byte-forward proxy.
#[derive(Clone, Debug)]
pub struct Config {
    /// Full Postgres connection URL for psp's backend connection.
    /// Must include sslmode=require (TLS is mandatory).
    pub backend_postgres_url: String,
    /// Secret used to validate incoming JWTs (HS256).
    pub jwt_secret: String,
    /// Address to listen on.
    pub listen_addr: String,
}

impl Config {
    pub fn new(
        backend_postgres_url: String,
        jwt_secret: String,
        listen_addr: String,
    ) -> Result<Self, ProxyError> {
        if backend_postgres_url.is_empty() {
            return Err(ProxyError::InvalidStartup(
                "backend_postgres_url must be non-empty".into(),
            ));
        }
        if jwt_secret.len() < 8 {
            return Err(ProxyError::InvalidStartup(format!(
                "jwt_secret too short ({} bytes, minimum 8)",
                jwt_secret.len()
            )));
        }
        // No TLS requirement in no-TLS MVP.
        Ok(Self {
            backend_postgres_url,
            jwt_secret,
            listen_addr,
        })
    }
}
