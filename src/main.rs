use pgwire_supabase_proxy::{serve, Config};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let jwt_secret =
        std::env::var("SUPABASE_JWT_SECRET").expect("SUPABASE_JWT_SECRET must be set");
    let database_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let listen_addr: SocketAddr = std::env::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:5432".to_string())
        .parse()
        .expect("invalid LISTEN_ADDR");
    let pool_size: usize = std::env::var("POOL_SIZE")
        .unwrap_or_else(|_| "10".to_string())
        .parse()
        .expect("invalid POOL_SIZE");

    let listener = TcpListener::bind(listen_addr).await?;

    let config = Config {
        database_url,
        jwt_secret,
        max_connections: pool_size,
    };

    serve(config, listener, async {
        let _ = tokio::signal::ctrl_c().await;
    }).await
}
