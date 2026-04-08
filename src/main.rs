//! Byte-forward Postgres proxy binary.

use pgwire_supabase_proxy::{serve, Config};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let backend_postgres_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let jwt_secret = std::env::var("SUPABASE_JWT_SECRET").expect("SUPABASE_JWT_SECRET must be set");
    let listen_addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:5432".to_string())
        .parse()
        .expect("invalid LISTEN_ADDR");

    let listener = TcpListener::bind(listen_addr).await?;

    let config = Config::new(backend_postgres_url, jwt_secret, listen_addr.to_string())?;

    serve(config, listener, async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await
}
