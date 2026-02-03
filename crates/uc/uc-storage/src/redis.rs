//! Redis storage backend (requires `redis` feature).
//!
//! This module provides a Redis-based storage backend with connection pooling
//! using bb8. It supports all StorageBackend operations including TTL management,
//! atomic operations, and bulk operations.

use crate::backend::StorageBackend;
use crate::config::RedisConfig;
use crate::error::{StorageError, StorageResult};
use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use bytes::Bytes;
use redis::AsyncCommands;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// Redis storage backend with connection pooling.
pub struct RedisBackend {
    /// Connection pool.
    pool: Pool<RedisConnectionManager>,
    /// Configuration.
    config: RedisConfig,
}

impl RedisBackend {
    /// Creates a new Redis backend with connection pooling.
    ///
    /// # Errors
    /// Returns an error if connection pool creation fails.
    pub async fn new(config: RedisConfig) -> StorageResult<Self> {
        debug!(url = %config.url, pool_size = config.pool_size, "Creating Redis backend");

        let manager = RedisConnectionManager::new(config.url.clone()).map_err(|e| {
            StorageError::ConnectionFailed {
                reason: format!("Failed to create Redis connection manager: {e}"),
            }
        })?;

        let pool = Pool::builder()
            .max_size(config.pool_size)
            .connection_timeout(config.connection_timeout())
            .build(manager)
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                reason: format!("Failed to create connection pool: {e}"),
            })?;

        // Test the connection
        {
            let mut conn = pool.get().await.map_err(|e| StorageError::ConnectionFailed {
                reason: format!("Failed to get connection from pool: {e}"),
            })?;

            redis::cmd("PING")
                .query_async::<String>(&mut *conn)
                .await
                .map_err(|e| StorageError::ConnectionFailed {
                    reason: format!("Redis PING failed: {e}"),
                })?;
        }

        debug!("Redis backend created successfully");

        Ok(Self { pool, config })
    }

    /// Gets a connection from the pool.
    async fn get_conn(
        &self,
    ) -> StorageResult<bb8::PooledConnection<'_, RedisConnectionManager>> {
        self.pool.get().await.map_err(|e| {
            warn!(error = %e, "Failed to get Redis connection");
            StorageError::PoolExhausted
        })
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &RedisConfig {
        &self.config
    }

    /// Returns pool statistics.
    #[must_use]
    pub fn pool_stats(&self) -> PoolStats {
        let state = self.pool.state();
        PoolStats {
            connections: state.connections,
            idle_connections: state.idle_connections,
        }
    }
}

/// Connection pool statistics.
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    /// Total number of connections.
    pub connections: u32,
    /// Number of idle connections.
    pub idle_connections: u32,
}

impl StorageBackend for RedisBackend {
    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Option<Bytes>>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            trace!(key = %key, "Redis GET");
            let mut conn = self.get_conn().await?;
            let result: Option<Vec<u8>> = conn.get(&key).await?;
            Ok(result.map(Bytes::from))
        })
    }

    fn set(
        &self,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = StorageResult<()>> + Send + '_>> {
        let key = key.to_string();
        let value = value.to_vec();
        Box::pin(async move {
            trace!(key = %key, ttl = ?ttl, "Redis SET");
            let mut conn = self.get_conn().await?;

            if let Some(ttl) = ttl {
                let seconds = ttl.as_secs().max(1);
                let _: () = conn.set_ex(&key, &value, seconds).await?;
            } else {
                let _: () = conn.set(&key, &value).await?;
            }

            Ok(())
        })
    }

    fn delete(&self, key: &str) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            trace!(key = %key, "Redis DEL");
            let mut conn = self.get_conn().await?;
            let deleted: i64 = conn.del(&key).await?;
            Ok(deleted > 0)
        })
    }

    fn keys(
        &self,
        pattern: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Vec<String>>> + Send + '_>> {
        let pattern = pattern.to_string();
        Box::pin(async move {
            trace!(pattern = %pattern, "Redis KEYS");
            let mut conn = self.get_conn().await?;
            let keys: Vec<String> = conn.keys(&pattern).await?;
            Ok(keys)
        })
    }

    fn increment(
        &self,
        key: &str,
        delta: i64,
    ) -> Pin<Box<dyn Future<Output = StorageResult<i64>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            trace!(key = %key, delta = delta, "Redis INCRBY");
            let mut conn = self.get_conn().await?;
            let result: i64 = conn.incr(&key, delta).await?;
            Ok(result)
        })
    }

    fn health_check(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            match self.get_conn().await {
                Ok(mut conn) => {
                    match redis::cmd("PING")
                        .query_async::<String>(&mut *conn)
                        .await
                    {
                        Ok(response) => response == "PONG",
                        Err(e) => {
                            warn!(error = %e, "Redis health check failed");
                            false
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Redis health check failed - no connection");
                    false
                }
            }
        })
    }

    fn backend_name(&self) -> &'static str {
        "redis"
    }

    fn exists(&self, key: &str) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            trace!(key = %key, "Redis EXISTS");
            let mut conn = self.get_conn().await?;
            let exists: bool = conn.exists(&key).await?;
            Ok(exists)
        })
    }

    fn set_nx(
        &self,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        let value = value.to_vec();
        Box::pin(async move {
            trace!(key = %key, ttl = ?ttl, "Redis SET NX");
            let mut conn = self.get_conn().await?;

            // Use SET with NX option for atomic set-if-not-exists
            let result: Option<String> = if let Some(ttl) = ttl {
                let seconds = ttl.as_secs().max(1);
                redis::cmd("SET")
                    .arg(&key)
                    .arg(&value)
                    .arg("NX")
                    .arg("EX")
                    .arg(seconds)
                    .query_async(&mut *conn)
                    .await?
            } else {
                redis::cmd("SET")
                    .arg(&key)
                    .arg(&value)
                    .arg("NX")
                    .query_async(&mut *conn)
                    .await?
            };

            // SET NX returns "OK" on success, nil on failure
            Ok(result.is_some())
        })
    }

    fn mget(
        &self,
        keys: &[&str],
    ) -> Pin<Box<dyn Future<Output = StorageResult<Vec<Option<Bytes>>>> + Send + '_>> {
        let keys: Vec<String> = keys.iter().map(|s| (*s).to_string()).collect();
        Box::pin(async move {
            if keys.is_empty() {
                return Ok(Vec::new());
            }

            trace!(count = keys.len(), "Redis MGET");
            let mut conn = self.get_conn().await?;

            let results: Vec<Option<Vec<u8>>> = conn.mget(&keys).await?;
            Ok(results.into_iter().map(|opt| opt.map(Bytes::from)).collect())
        })
    }

    fn mset(
        &self,
        pairs: &[(&str, &[u8])],
        ttl: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = StorageResult<()>> + Send + '_>> {
        let pairs: Vec<(String, Vec<u8>)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.to_vec()))
            .collect();
        Box::pin(async move {
            if pairs.is_empty() {
                return Ok(());
            }

            trace!(count = pairs.len(), ttl = ?ttl, "Redis MSET");
            let mut conn = self.get_conn().await?;

            if let Some(ttl) = ttl {
                // Use pipeline for MSET with TTL
                let seconds = ttl.as_secs().max(1);
                let mut pipe = redis::pipe();

                for (key, value) in &pairs {
                    pipe.cmd("SET")
                        .arg(key)
                        .arg(value)
                        .arg("EX")
                        .arg(seconds)
                        .ignore();
                }

                let _: () = pipe.query_async(&mut *conn).await?;
            } else {
                // Use native MSET for non-TTL case
                let items: Vec<(&str, &[u8])> = pairs
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_slice()))
                    .collect();
                let _: () = conn.mset(&items).await?;
            }

            Ok(())
        })
    }

    fn mdelete(
        &self,
        keys: &[&str],
    ) -> Pin<Box<dyn Future<Output = StorageResult<usize>> + Send + '_>> {
        let keys: Vec<String> = keys.iter().map(|s| (*s).to_string()).collect();
        Box::pin(async move {
            if keys.is_empty() {
                return Ok(0);
            }

            trace!(count = keys.len(), "Redis DEL (multi)");
            let mut conn = self.get_conn().await?;

            let deleted: i64 = conn.del(&keys).await?;
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            Ok(deleted as usize)
        })
    }

    fn ttl(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Option<i64>>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            trace!(key = %key, "Redis TTL");
            let mut conn = self.get_conn().await?;

            // Redis TTL returns:
            // -2 if key doesn't exist
            // -1 if key exists but has no TTL
            // positive value for TTL in seconds
            let ttl: i64 = conn.ttl(&key).await?;

            match ttl {
                -2 => Ok(None),           // Key doesn't exist
                -1 => Ok(Some(i64::MAX)), // No TTL (never expires)
                _ => Ok(Some(ttl)),
            }
        })
    }

    fn expire(
        &self,
        key: &str,
        ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            trace!(key = %key, ttl = ?ttl, "Redis EXPIRE");
            let mut conn = self.get_conn().await?;

            let seconds = ttl.as_secs().max(1);
            let result: bool = conn.expire(&key, seconds as i64).await?;
            Ok(result)
        })
    }

    fn persist(&self, key: &str) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            trace!(key = %key, "Redis PERSIST");
            let mut conn = self.get_conn().await?;

            let result: bool = conn.persist(&key).await?;
            Ok(result)
        })
    }
}

impl std::fmt::Debug for RedisBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stats = self.pool_stats();
        f.debug_struct("RedisBackend")
            .field("url", &self.config.url)
            .field("pool_connections", &stats.connections)
            .field("pool_idle", &stats.idle_connections)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require a running Redis instance.
    // Run with: cargo test --features redis -- --ignored

    fn redis_config() -> RedisConfig {
        RedisConfig {
            url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            pool_size: 5,
            ..Default::default()
        }
    }

    #[tokio::test]
    #[ignore = "requires Redis server"]
    async fn test_redis_connection() {
        let backend = RedisBackend::new(redis_config()).await.unwrap();
        assert!(backend.health_check().await);
    }

    #[tokio::test]
    #[ignore = "requires Redis server"]
    async fn test_redis_set_get() {
        let backend = RedisBackend::new(redis_config()).await.unwrap();
        let key = format!("test:set_get:{}", uuid_v4());

        // Set a value
        backend.set(&key, b"hello", None).await.unwrap();

        // Get it back
        let value = backend.get(&key).await.unwrap();
        assert_eq!(value, Some(Bytes::from("hello")));

        // Clean up
        backend.delete(&key).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis server"]
    async fn test_redis_set_with_ttl() {
        let backend = RedisBackend::new(redis_config()).await.unwrap();
        let key = format!("test:ttl:{}", uuid_v4());

        // Set with TTL
        backend
            .set(&key, b"expires", Some(Duration::from_secs(10)))
            .await
            .unwrap();

        // Check TTL
        let ttl = backend.ttl(&key).await.unwrap();
        assert!(ttl.is_some());
        let ttl_val = ttl.unwrap();
        assert!(ttl_val > 0 && ttl_val <= 10);

        // Clean up
        backend.delete(&key).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis server"]
    async fn test_redis_delete() {
        let backend = RedisBackend::new(redis_config()).await.unwrap();
        let key = format!("test:delete:{}", uuid_v4());

        // Set and delete
        backend.set(&key, b"to_delete", None).await.unwrap();
        let deleted = backend.delete(&key).await.unwrap();
        assert!(deleted);

        // Verify deleted
        let value = backend.get(&key).await.unwrap();
        assert!(value.is_none());

        // Delete non-existent
        let deleted = backend.delete(&key).await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    #[ignore = "requires Redis server"]
    async fn test_redis_exists() {
        let backend = RedisBackend::new(redis_config()).await.unwrap();
        let key = format!("test:exists:{}", uuid_v4());

        // Check non-existent
        assert!(!backend.exists(&key).await.unwrap());

        // Create and check
        backend.set(&key, b"exists", None).await.unwrap();
        assert!(backend.exists(&key).await.unwrap());

        // Clean up
        backend.delete(&key).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis server"]
    async fn test_redis_increment() {
        let backend = RedisBackend::new(redis_config()).await.unwrap();
        let key = format!("test:incr:{}", uuid_v4());

        // Increment non-existent key
        let val = backend.increment(&key, 5).await.unwrap();
        assert_eq!(val, 5);

        // Increment again
        let val = backend.increment(&key, 3).await.unwrap();
        assert_eq!(val, 8);

        // Decrement
        let val = backend.increment(&key, -2).await.unwrap();
        assert_eq!(val, 6);

        // Clean up
        backend.delete(&key).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis server"]
    async fn test_redis_set_nx() {
        let backend = RedisBackend::new(redis_config()).await.unwrap();
        let key = format!("test:setnx:{}", uuid_v4());

        // First set should succeed
        let set = backend.set_nx(&key, b"first", None).await.unwrap();
        assert!(set);

        // Second set should fail
        let set = backend.set_nx(&key, b"second", None).await.unwrap();
        assert!(!set);

        // Value should be first
        let value = backend.get(&key).await.unwrap();
        assert_eq!(value, Some(Bytes::from("first")));

        // Clean up
        backend.delete(&key).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis server"]
    async fn test_redis_keys() {
        let backend = RedisBackend::new(redis_config()).await.unwrap();
        let prefix = format!("test:keys:{}:", uuid_v4());

        // Create some keys
        for i in 0..3 {
            let key = format!("{prefix}{i}");
            backend.set(&key, b"value", None).await.unwrap();
        }

        // Find keys
        let pattern = format!("{prefix}*");
        let keys = backend.keys(&pattern).await.unwrap();
        assert_eq!(keys.len(), 3);

        // Clean up
        for key in keys {
            backend.delete(&key).await.unwrap();
        }
    }

    #[tokio::test]
    #[ignore = "requires Redis server"]
    async fn test_redis_mget_mset() {
        let backend = RedisBackend::new(redis_config()).await.unwrap();
        let prefix = format!("test:mget:{}:", uuid_v4());

        let key1 = format!("{prefix}1");
        let key2 = format!("{prefix}2");
        let key3 = format!("{prefix}3");

        // MSET
        let pairs: Vec<(&str, &[u8])> = vec![
            (key1.as_str(), b"value1".as_slice()),
            (key2.as_str(), b"value2".as_slice()),
        ];
        backend.mset(&pairs, None).await.unwrap();

        // MGET (including non-existent key)
        let keys = vec![key1.as_str(), key2.as_str(), key3.as_str()];
        let values = backend.mget(&keys).await.unwrap();

        assert_eq!(values.len(), 3);
        assert_eq!(values[0], Some(Bytes::from("value1")));
        assert_eq!(values[1], Some(Bytes::from("value2")));
        assert_eq!(values[2], None);

        // Clean up
        backend.mdelete(&keys).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis server"]
    async fn test_redis_expire_persist() {
        let backend = RedisBackend::new(redis_config()).await.unwrap();
        let key = format!("test:expire:{}", uuid_v4());

        // Set without TTL
        backend.set(&key, b"value", None).await.unwrap();

        // Add TTL
        let expired = backend.expire(&key, Duration::from_secs(100)).await.unwrap();
        assert!(expired);

        // Check TTL is set
        let ttl = backend.ttl(&key).await.unwrap();
        assert!(ttl.is_some());
        assert!(ttl.unwrap() > 0);

        // Remove TTL
        let persisted = backend.persist(&key).await.unwrap();
        assert!(persisted);

        // Check TTL is removed
        let ttl = backend.ttl(&key).await.unwrap();
        assert_eq!(ttl, Some(i64::MAX));

        // Clean up
        backend.delete(&key).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Redis server"]
    async fn test_redis_pool_stats() {
        let backend = RedisBackend::new(redis_config()).await.unwrap();
        let stats = backend.pool_stats();
        assert!(stats.connections > 0);
    }

    /// Generate a simple UUID-like string for test isolation.
    fn uuid_v4() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{:x}", nanos)
    }
}
