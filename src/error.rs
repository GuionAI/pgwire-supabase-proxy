pub use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("invalid JWT: {0}")]
    InvalidJwt(String),

    #[error("JWT expired")]
    JwtExpired,

    #[error("protocol violation: {0}")]
    ProtocolViolation(String),

    #[error("backend auth error: {0}")]
    BackendAuth(String),

    #[error("backend error: {0}")]
    BackendError(String),

    #[error("connection closed")]
    ConnectionClosed,

    #[error("encoding error: {0}")]
    Encoding(String),

    #[error("invalid startup: {0}")]
    InvalidStartup(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
