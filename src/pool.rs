use crate::error::ProxyError;
use deadpool_postgres::{Config, Pool};

/// Manages backend Postgres connection pools per user.
pub struct ConnectionManager {
    pools: std::sync::Arc<tokio::sync::RwLock<lru::LruCache<String, Pool>>>,
    #[allow(dead_code)]
    db_url: String,
    #[allow(dead_code)]
    max_connections: usize,
}

impl ConnectionManager {
    pub fn new(database_url: String, max_connections: usize) -> Self {
        Self {
            pools: std::sync::Arc::new(tokio::sync::RwLock::new(lru::LruCache::new(
                std::num::NonZeroUsize::new(1024).unwrap(),
            ))),
            db_url: database_url,
            max_connections,
        }
    }

    /// Get or create a pool for the given user_id.
    pub async fn get_pool(&self, user_id: &str) -> Result<Pool, ProxyError> {
        let mut pools = self.pools.write().await;
        if let Some(pool) = pools.get(user_id) {
            return Ok(pool.clone());
        }

        let mut cfg = Config::new();
        cfg.url = Some(self.db_url.clone());
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
        let escaped_user_id = user_id.replace('\'', "''");
        client
            .simple_query(&format!(
                "SET request.jwt.claim.sub = '{}'",
                escaped_user_id
            ))
            .await?;

        tracing::debug!(user_id = %user_id, "RLS context set");
        Ok(client)
    }

    /// Discard all session state before returning connection to pool.
    #[allow(dead_code)]
    pub async fn sanitize(client: &mut deadpool_postgres::Object) -> Result<(), ProxyError> {
        let _ = client.simple_query("DISCARD ALL").await;
        Ok(())
    }
}
