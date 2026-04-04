pub use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("invalid JWT: {0}")]
    InvalidJwt(String),

    #[error("JWT expired")]
    JwtExpired,

    #[error("database error: {0}")]
    Database(#[from] tokio_postgres::Error),

    #[error("pool error: {0}")]
    Pool(#[from] deadpool_postgres::PoolError),

    #[error("pgwire error: {0}")]
    PgWire(#[from] pgwire::error::PgWireError),

    #[error("invalid startup: {0}")]
    InvalidStartup(String),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("encoding error: {0}")]
    Encoding(String),
}

impl From<ProxyError> for pgwire::error::PgWireError {
    fn from(e: ProxyError) -> Self {
        pgwire::error::PgWireError::ApiError(Box::new(e))
    }
}
