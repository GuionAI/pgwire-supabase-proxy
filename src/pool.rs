use crate::error::ProxyError;
use crate::handler::escape_pg_string;
use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod};
use tokio::sync::Mutex;

/// Manages backend Postgres connection pools per user.
pub struct ConnectionManager {
    pools: std::sync::Arc<Mutex<lru::LruCache<String, Pool>>>,
    db_url: String,
    max_connections: usize,
}

impl ConnectionManager {
    pub fn new(database_url: String, max_connections: usize) -> Self {
        Self {
            pools: std::sync::Arc::new(Mutex::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(1024).unwrap(),
            ))),
            db_url: database_url,
            max_connections,
        }
    }

    /// Get or create a pool for the given user_id.
    pub async fn get_pool(&self, user_id: &str) -> Result<Pool, ProxyError> {
        let mut pools = self.pools.lock().await;
        if let Some(pool) = pools.get(user_id) {
            return Ok(pool.clone());
        }

        let mut cfg = Config::new();
        cfg.url = Some(self.db_url.clone());
        cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Clean,
        });
        cfg.pool = Some(deadpool_postgres::PoolConfig::new(self.max_connections));
        let pool = cfg
            .create_pool(
                Some(deadpool_postgres::Runtime::Tokio1),
                tokio_postgres::NoTls,
            )
            .map_err(|e| ProxyError::InvalidStartup(format!("failed to create pool: {}", e)))?;

        pools.push(user_id.to_string(), pool.clone());
        Ok(pool)
    }

    /// Check out a connection and set RLS context.
    pub async fn check_out(&self, user_id: &str) -> Result<deadpool_postgres::Object, ProxyError> {
        let pool = self.get_pool(user_id).await?;
        let client = pool.get().await?;

        // Set role to authenticated (bypassrls=false → RLS applies)
        client.simple_query("SET ROLE authenticated").await?;

        // Set request.jwt.claim.sub so auth.uid() works
        client
            .simple_query(&format!(
                "SET request.jwt.claim.sub = '{}'",
                escape_user_id(user_id)
            ))
            .await?;

        tracing::debug!(user_id = %user_id, "RLS context set");
        Ok(client)
    }
}

/// Escape a user_id for safe interpolation into a SET statement literal.
/// Delegates to `escape_pg_string` to keep a single escaping SSOT.
pub(crate) fn escape_user_id(user_id: &str) -> String {
    escape_pg_string(user_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_user_id_normal_uuid() {
        let uid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(escape_user_id(uid), uid);
    }

    #[test]
    fn test_escape_user_id_single_quote() {
        assert_eq!(escape_user_id("user'123"), "user''123");
    }

    #[test]
    fn test_escape_user_id_multiple_quotes() {
        assert_eq!(escape_user_id("a'b'c"), "a''b''c");
    }
}
