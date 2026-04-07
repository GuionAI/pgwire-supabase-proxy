//! pgwire-supabase-proxy library
//!
//! Exposes a `serve()` function for embedding the proxy and a `Config` struct
//! for configuring it programmatically (used by integration tests).

mod auth;
mod error;
mod handler;
mod pool;

pub use auth::{Claims, JwtAuthenticator, StartupHandler};
pub use error::ProxyError;
pub use handler::{ProxyQueryHandler, Session};
pub use pool::ConnectionManager;

use pgwire::api::auth::DefaultServerParameterProvider;
use pgwire::api::PgWireServerHandlers;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Configuration for the pgwire-supabase-proxy.
#[derive(Clone, Debug)]
pub struct Config {
    /// Postgres connection URL for the backend pool.
    pub database_url: String,
    /// Secret used to validate incoming JWTs.
    pub jwt_secret: String,
    /// Max connections per pool.
    pub max_connections: usize,
}

impl Config {
    pub fn new(database_url: String, jwt_secret: String, max_connections: usize) -> std::result::Result<Self, ProxyError> {
        if database_url.is_empty() {
            return Err(ProxyError::InvalidStartup("Config.database_url must be non-empty".into()));
        }
        if jwt_secret.len() < 8 {
            return Err(ProxyError::InvalidStartup(
                format!("Config.jwt_secret too short ({} bytes, minimum 8)", jwt_secret.len()),
            ));
        }
        if max_connections == 0 {
            return Err(ProxyError::InvalidStartup("Config.max_connections must be > 0".into()));
        }
        Ok(Self { database_url, jwt_secret, max_connections })
    }
}

/// The `AppFactory` wires together auth, session, and query handlers for pgwire.
pub struct AppFactory {
    startup: Arc<StartupHandler<DefaultServerParameterProvider>>,
    query: Arc<ProxyQueryHandler>,
}

impl AppFactory {
    /// Create a new AppFactory.
    pub fn new(jwt_secret: String, manager: Arc<ConnectionManager>) -> Self {
        let auth = Arc::new(JwtAuthenticator::new(jwt_secret));
        let param_provider = DefaultServerParameterProvider::default();
        let session: Arc<Session> = Arc::new(Session::new());
        let startup = Arc::new(StartupHandler::new(
            auth,
            Arc::new(param_provider),
            manager.clone(),
            session.clone(),
        ));
        let query = Arc::new(ProxyQueryHandler::new(manager, session));

        Self { startup, query }
    }
}

impl PgWireServerHandlers for AppFactory {
    fn startup_handler(&self) -> Arc<impl pgwire::api::auth::StartupHandler> {
        self.startup.clone()
    }

    fn simple_query_handler(&self) -> Arc<impl pgwire::api::query::SimpleQueryHandler> {
        self.query.clone()
    }

    fn extended_query_handler(&self) -> Arc<impl pgwire::api::query::ExtendedQueryHandler> {
        self.query.clone()
    }
}

/// Start the pgwire-supabase-proxy server.
///
/// `shutdown` is a future that resolves when the server should stop.
/// When it resolves, the accept loop exits gracefully.
pub async fn serve(
    config: Config,
    listener: TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing (idempotent — safe to call multiple times)
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,pgwire_supabase_proxy=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .try_init();

    let manager = Arc::new(ConnectionManager::new(
        config.database_url.clone(),
        config.max_connections,
    ));

    let addr = listener.local_addr()?;
    tracing::info!(addr = %addr, "starting pgwire-supabase-proxy");

    // Pin shutdown future so it can be polled in select!
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (socket, addr) = result?;
                tracing::info!(addr = %addr, "connection accepted");

                let factory = Arc::new(AppFactory::new(config.jwt_secret.clone(), manager.clone()));
                tokio::spawn(async move {
                    let result = pgwire::tokio::process_socket(socket, None, factory.clone()).await;
                    if let Err(e) = result {
                        tracing::error!(error = %e, "connection error");
                    }
                    // Arc<AppFactory> is dropped here → Arc<Session> refcount hits 0
                    // → Session::drop runs → DISCARD ALL on the backend connection.
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
