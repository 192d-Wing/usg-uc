//! PostgreSQL storage backend (requires `postgres` feature).
//!
//! This module provides a PostgreSQL-based storage backend with connection pooling
//! using sqlx. It supports all StorageBackend operations with persistent storage,
//! TTL management via expiry timestamps, and atomic operations.
//!
//! The backend creates a `kv_store` table automatically if it doesn't exist.

#![allow(clippy::cast_possible_truncation)]

use crate::backend::StorageBackend;
use crate::config::PostgresConfig;
use crate::error::{StorageError, StorageResult};
use bytes::Bytes;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;
use tracing::{debug, trace, warn};

/// PostgreSQL storage backend with connection pooling.
pub struct PostgresBackend {
    /// Connection pool.
    pool: PgPool,
    /// Configuration.
    config: PostgresConfig,
}

impl PostgresBackend {
    /// Creates a new PostgreSQL backend with connection pooling.
    ///
    /// This will also run migrations to ensure the schema is up to date.
    ///
    /// # Errors
    /// Returns an error if connection pool creation or migrations fail.
    pub async fn new(config: PostgresConfig) -> StorageResult<Self> {
        debug!(url = %config.url, "Creating PostgreSQL backend");

        let pool = PgPoolOptions::new()
            .min_connections(config.pool_min_size)
            .max_connections(config.pool_max_size)
            .acquire_timeout(config.connection_timeout())
            .connect(&config.url)
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                reason: format!("Failed to create PostgreSQL connection pool: {e}"),
            })?;

        // Run migrations if enabled
        if config.run_migrations {
            Self::run_migrations(&pool).await?;
        }

        debug!("PostgreSQL backend created successfully");

        Ok(Self { pool, config })
    }

    /// Runs database migrations to create required tables.
    async fn run_migrations(pool: &PgPool) -> StorageResult<()> {
        debug!("Running PostgreSQL migrations");

        // Create the key-value store table
        sqlx::query(
            r"
            CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                value BYTEA NOT NULL,
                expires_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
            ",
        )
        .execute(pool)
        .await
        .map_err(|e| StorageError::MigrationError {
            reason: format!("Failed to create kv_store table: {e}"),
        })?;

        // Create index on expires_at for efficient cleanup
        sqlx::query(
            r"
            CREATE INDEX IF NOT EXISTS idx_kv_store_expires_at
            ON kv_store (expires_at)
            WHERE expires_at IS NOT NULL
            ",
        )
        .execute(pool)
        .await
        .map_err(|e| StorageError::MigrationError {
            reason: format!("Failed to create expires_at index: {e}"),
        })?;

        // Create counters table for atomic increment operations
        sqlx::query(
            r"
            CREATE TABLE IF NOT EXISTS kv_counters (
                key TEXT PRIMARY KEY,
                value BIGINT NOT NULL DEFAULT 0,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            )
            ",
        )
        .execute(pool)
        .await
        .map_err(|e| StorageError::MigrationError {
            reason: format!("Failed to create kv_counters table: {e}"),
        })?;

        debug!("PostgreSQL migrations completed");
        Ok(())
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &PostgresConfig {
        &self.config
    }

    /// Returns the connection pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Cleans up expired entries from the database.
    ///
    /// This can be called periodically to remove expired entries.
    ///
    /// # Errors
    /// Returns an error if the cleanup query fails.
    pub async fn cleanup_expired(&self) -> StorageResult<u64> {
        let result = sqlx::query(
            r"
            DELETE FROM kv_store
            WHERE expires_at IS NOT NULL AND expires_at < NOW()
            ",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::PostgresError {
            reason: format!("Failed to cleanup expired entries: {e}"),
        })?;

        let deleted = result.rows_affected();
        if deleted > 0 {
            debug!(count = deleted, "Cleaned up expired entries");
        }
        Ok(deleted)
    }
}

impl StorageBackend for PostgresBackend {
    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Option<Bytes>>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            trace!(key = %key, "PostgreSQL GET");

            let row: Option<(Vec<u8>,)> = sqlx::query_as(
                r"
                SELECT value FROM kv_store
                WHERE key = $1
                AND (expires_at IS NULL OR expires_at > NOW())
                ",
            )
            .bind(&key)
            .fetch_optional(&self.pool)
            .await?;

            Ok(row.map(|(value,)| Bytes::from(value)))
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
            trace!(key = %key, ttl = ?ttl, "PostgreSQL SET");

            let expires_at =
                ttl.map(|d| chrono::Utc::now() + chrono::Duration::seconds(d.as_secs() as i64));

            sqlx::query(
                r"
                INSERT INTO kv_store (key, value, expires_at, updated_at)
                VALUES ($1, $2, $3, NOW())
                ON CONFLICT (key) DO UPDATE
                SET value = EXCLUDED.value,
                    expires_at = EXCLUDED.expires_at,
                    updated_at = NOW()
                ",
            )
            .bind(&key)
            .bind(&value)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;

            Ok(())
        })
    }

    fn delete(&self, key: &str) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            trace!(key = %key, "PostgreSQL DELETE");

            let result = sqlx::query(
                r"
                DELETE FROM kv_store WHERE key = $1
                ",
            )
            .bind(&key)
            .execute(&self.pool)
            .await?;

            Ok(result.rows_affected() > 0)
        })
    }

    fn keys(
        &self,
        pattern: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Vec<String>>> + Send + '_>> {
        let pattern = pattern.to_string();
        Box::pin(async move {
            trace!(pattern = %pattern, "PostgreSQL KEYS");

            // Convert glob pattern to SQL LIKE pattern
            let like_pattern = glob_to_like(&pattern);

            let rows: Vec<(String,)> = sqlx::query_as(
                r"
                SELECT key FROM kv_store
                WHERE key LIKE $1
                AND (expires_at IS NULL OR expires_at > NOW())
                ORDER BY key
                ",
            )
            .bind(&like_pattern)
            .fetch_all(&self.pool)
            .await?;

            Ok(rows.into_iter().map(|(key,)| key).collect())
        })
    }

    fn increment(
        &self,
        key: &str,
        delta: i64,
    ) -> Pin<Box<dyn Future<Output = StorageResult<i64>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            trace!(key = %key, delta = delta, "PostgreSQL INCREMENT");

            // Use INSERT ... ON CONFLICT for atomic increment
            let row: (i64,) = sqlx::query_as(
                r"
                INSERT INTO kv_counters (key, value, updated_at)
                VALUES ($1, $2, NOW())
                ON CONFLICT (key) DO UPDATE
                SET value = kv_counters.value + $2,
                    updated_at = NOW()
                RETURNING value
                ",
            )
            .bind(&key)
            .bind(delta)
            .fetch_one(&self.pool)
            .await?;

            Ok(row.0)
        })
    }

    fn health_check(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async move {
            match sqlx::query("SELECT 1").fetch_one(&self.pool).await {
                Ok(_) => true,
                Err(e) => {
                    warn!(error = %e, "PostgreSQL health check failed");
                    false
                }
            }
        })
    }

    fn backend_name(&self) -> &'static str {
        "postgres"
    }

    fn exists(&self, key: &str) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            trace!(key = %key, "PostgreSQL EXISTS");

            let row: Option<(i32,)> = sqlx::query_as(
                r"
                SELECT 1 FROM kv_store
                WHERE key = $1
                AND (expires_at IS NULL OR expires_at > NOW())
                ",
            )
            .bind(&key)
            .fetch_optional(&self.pool)
            .await?;

            Ok(row.is_some())
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
            trace!(key = %key, ttl = ?ttl, "PostgreSQL SET NX");

            let expires_at =
                ttl.map(|d| chrono::Utc::now() + chrono::Duration::seconds(d.as_secs() as i64));

            // Use INSERT ... ON CONFLICT DO NOTHING for atomic set-if-not-exists
            let result = sqlx::query(
                r"
                INSERT INTO kv_store (key, value, expires_at)
                VALUES ($1, $2, $3)
                ON CONFLICT (key) DO NOTHING
                ",
            )
            .bind(&key)
            .bind(&value)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;

            Ok(result.rows_affected() > 0)
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

            trace!(count = keys.len(), "PostgreSQL MGET");

            // Fetch all matching keys
            let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
                r"
                SELECT key, value FROM kv_store
                WHERE key = ANY($1)
                AND (expires_at IS NULL OR expires_at > NOW())
                ",
            )
            .bind(&keys)
            .fetch_all(&self.pool)
            .await?;

            // Build a map for quick lookup
            let map: std::collections::HashMap<String, Vec<u8>> = rows.into_iter().collect();

            // Return values in the same order as input keys
            Ok(keys
                .into_iter()
                .map(|k| map.get(&k).map(|v| Bytes::from(v.clone())))
                .collect())
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

            trace!(count = pairs.len(), ttl = ?ttl, "PostgreSQL MSET");

            let expires_at =
                ttl.map(|d| chrono::Utc::now() + chrono::Duration::seconds(d.as_secs() as i64));

            // Use a transaction for atomicity
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| StorageError::TransactionError {
                    reason: format!("Failed to begin transaction: {e}"),
                })?;

            for (key, value) in &pairs {
                sqlx::query(
                    r"
                    INSERT INTO kv_store (key, value, expires_at, updated_at)
                    VALUES ($1, $2, $3, NOW())
                    ON CONFLICT (key) DO UPDATE
                    SET value = EXCLUDED.value,
                        expires_at = EXCLUDED.expires_at,
                        updated_at = NOW()
                    ",
                )
                .bind(key)
                .bind(value)
                .bind(expires_at)
                .execute(&mut *tx)
                .await?;
            }

            tx.commit()
                .await
                .map_err(|e| StorageError::TransactionError {
                    reason: format!("Failed to commit transaction: {e}"),
                })?;

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

            trace!(count = keys.len(), "PostgreSQL MDELETE");

            let result = sqlx::query(
                r"
                DELETE FROM kv_store WHERE key = ANY($1)
                ",
            )
            .bind(&keys)
            .fetch_all(&self.pool)
            .await?;

            Ok(result.len())
        })
    }

    fn ttl(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Option<i64>>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            trace!(key = %key, "PostgreSQL TTL");

            let row: Option<(Option<chrono::DateTime<chrono::Utc>>,)> = sqlx::query_as(
                r"
                SELECT expires_at FROM kv_store WHERE key = $1
                ",
            )
            .bind(&key)
            .fetch_optional(&self.pool)
            .await?;

            match row {
                None => Ok(None),                    // Key doesn't exist
                Some((None,)) => Ok(Some(i64::MAX)), // No TTL (never expires)
                Some((Some(expires_at),)) => {
                    let now = chrono::Utc::now();
                    if expires_at <= now {
                        Ok(None) // Already expired
                    } else {
                        let ttl = (expires_at - now).num_seconds();
                        Ok(Some(ttl))
                    }
                }
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
            trace!(key = %key, ttl = ?ttl, "PostgreSQL EXPIRE");

            let expires_at = chrono::Utc::now() + chrono::Duration::seconds(ttl.as_secs() as i64);

            let result = sqlx::query(
                r"
                UPDATE kv_store SET expires_at = $2, updated_at = NOW() WHERE key = $1
                ",
            )
            .bind(&key)
            .bind(expires_at)
            .execute(&self.pool)
            .await?;

            Ok(result.rows_affected() > 0)
        })
    }

    fn persist(&self, key: &str) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            trace!(key = %key, "PostgreSQL PERSIST");

            let result = sqlx::query(
                r"
                UPDATE kv_store SET expires_at = NULL, updated_at = NOW()
                WHERE key = $1 AND expires_at IS NOT NULL
                ",
            )
            .bind(&key)
            .execute(&self.pool)
            .await?;

            Ok(result.rows_affected() > 0)
        })
    }
}

/// Converts a glob pattern to a SQL LIKE pattern.
fn glob_to_like(pattern: &str) -> String {
    let mut result = String::with_capacity(pattern.len() * 2);
    for ch in pattern.chars() {
        match ch {
            '*' => result.push('%'),
            '?' => result.push('_'),
            '%' => result.push_str("\\%"),
            '_' => result.push_str("\\_"),
            '\\' => result.push_str("\\\\"),
            _ => result.push(ch),
        }
    }
    result
}

impl std::fmt::Debug for PostgresBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostgresBackend")
            .field("url", &self.config.url)
            .field("pool_min_size", &self.config.pool_min_size)
            .field("pool_max_size", &self.config.pool_max_size)
            .finish()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::similar_names,
    clippy::uninlined_format_args
)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_to_like() {
        assert_eq!(glob_to_like("*"), "%");
        assert_eq!(glob_to_like("foo*"), "foo%");
        assert_eq!(glob_to_like("*bar"), "%bar");
        assert_eq!(glob_to_like("foo*bar"), "foo%bar");
        assert_eq!(glob_to_like("foo?bar"), "foo_bar");
        assert_eq!(glob_to_like("foo%bar"), "foo\\%bar");
        assert_eq!(glob_to_like("foo_bar"), "foo\\_bar");
        assert_eq!(glob_to_like("test:*:data"), "test:%:data");
    }

    // Integration tests require a running PostgreSQL instance.
    // Run with: cargo test --features postgres -- --ignored

    fn postgres_config() -> PostgresConfig {
        PostgresConfig {
            url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/sbc_test".to_string()),
            pool_min_size: 1,
            pool_max_size: 5,
            run_migrations: true,
            ..Default::default()
        }
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL server"]
    async fn test_postgres_connection() {
        let backend = PostgresBackend::new(postgres_config()).await.unwrap();
        assert!(backend.health_check().await);
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL server"]
    async fn test_postgres_set_get() {
        let backend = PostgresBackend::new(postgres_config()).await.unwrap();
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
    #[ignore = "requires PostgreSQL server"]
    async fn test_postgres_set_with_ttl() {
        let backend = PostgresBackend::new(postgres_config()).await.unwrap();
        let key = format!("test:ttl:{}", uuid_v4());

        // Set with TTL
        backend
            .set(&key, b"expires", Some(Duration::from_secs(100)))
            .await
            .unwrap();

        // Check TTL
        let ttl = backend.ttl(&key).await.unwrap();
        assert!(ttl.is_some());
        let ttl_val = ttl.unwrap();
        assert!(ttl_val > 0 && ttl_val <= 100);

        // Clean up
        backend.delete(&key).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL server"]
    async fn test_postgres_delete() {
        let backend = PostgresBackend::new(postgres_config()).await.unwrap();
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
    #[ignore = "requires PostgreSQL server"]
    async fn test_postgres_exists() {
        let backend = PostgresBackend::new(postgres_config()).await.unwrap();
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
    #[ignore = "requires PostgreSQL server"]
    async fn test_postgres_increment() {
        let backend = PostgresBackend::new(postgres_config()).await.unwrap();
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

        // Clean up (delete from counters table)
        sqlx::query("DELETE FROM kv_counters WHERE key = $1")
            .bind(&key)
            .execute(backend.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL server"]
    async fn test_postgres_set_nx() {
        let backend = PostgresBackend::new(postgres_config()).await.unwrap();
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
    #[ignore = "requires PostgreSQL server"]
    async fn test_postgres_keys() {
        let backend = PostgresBackend::new(postgres_config()).await.unwrap();
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
    #[ignore = "requires PostgreSQL server"]
    async fn test_postgres_mget_mset() {
        let backend = PostgresBackend::new(postgres_config()).await.unwrap();
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
    #[ignore = "requires PostgreSQL server"]
    async fn test_postgres_expire_persist() {
        let backend = PostgresBackend::new(postgres_config()).await.unwrap();
        let key = format!("test:expire:{}", uuid_v4());

        // Set without TTL
        backend.set(&key, b"value", None).await.unwrap();

        // Add TTL
        let expired = backend
            .expire(&key, Duration::from_secs(100))
            .await
            .unwrap();
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
    #[ignore = "requires PostgreSQL server"]
    async fn test_postgres_cleanup_expired() {
        let backend = PostgresBackend::new(postgres_config()).await.unwrap();
        let key = format!("test:cleanup:{}", uuid_v4());

        // Set with very short TTL (1 second)
        backend
            .set(&key, b"expires_soon", Some(Duration::from_secs(1)))
            .await
            .unwrap();

        // Wait for expiry
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Cleanup should remove expired entry
        let deleted = backend.cleanup_expired().await.unwrap();
        assert!(deleted >= 1);

        // Key should not exist
        let value = backend.get(&key).await.unwrap();
        assert!(value.is_none());
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
