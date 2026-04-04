mod auth;
mod error;
mod handler;
mod pool;

use crate::auth::{JwtAuthenticator, StartupHandler};
use crate::handler::{ProxyQueryHandler, SessionRegistry};
use crate::pool::ConnectionManager;
use pgwire::api::auth::DefaultServerParameterProvider;
use pgwire::api::PgWireServerHandlers;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

struct AppFactory {
    startup: Arc<StartupHandler<DefaultServerParameterProvider>>,
    query: Arc<ProxyQueryHandler>,
}

impl AppFactory {
    fn new(jwt_secret: String, database_url: String, pool_size: usize) -> Self {
        let auth = Arc::new(JwtAuthenticator::new(jwt_secret));
        let param_provider = DefaultServerParameterProvider::default();
        let manager = Arc::new(ConnectionManager::new(database_url, pool_size));
        let registry = Arc::new(SessionRegistry::new());
        let startup = Arc::new(StartupHandler::new(
            auth,
            Arc::new(param_provider),
            registry.clone(),
            manager.clone(),
        ));
        let query = Arc::new(ProxyQueryHandler::new(manager, registry.clone()));

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

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,pgwire_supabase_proxy=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let jwt_secret = std::env::var("SUPABASE_JWT_SECRET").expect("SUPABASE_JWT_SECRET must be set");
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let listen_addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:5432".to_string())
        .parse()
        .expect("invalid LISTEN_ADDR");
    let pool_size: usize = std::env::var("POOL_SIZE")
        .unwrap_or_else(|_| "10".to_string())
        .parse()
        .expect("invalid POOL_SIZE");

    tracing::info!(addr = %listen_addr, "starting pgwire-supabase-proxy");

    let listener = TcpListener::bind(listen_addr).await?;

    loop {
        let (socket, addr) = listener.accept().await?;
        tracing::info!(addr = %addr, "connection accepted");

        let factory = Arc::new(AppFactory::new(
            jwt_secret.clone(),
            database_url.clone(),
            pool_size,
        ));
        tokio::spawn(async move {
            let result = pgwire::tokio::process_socket(socket, None, factory.clone()).await;
            if let Err(e) = result {
                tracing::error!(error = %e, "connection error");
            }
            // After process_socket returns (client disconnected), unregister this
            // connection's backend session so the connection is returned to the pool.
            factory.query.unregister_all().await;
        });
    }
}
