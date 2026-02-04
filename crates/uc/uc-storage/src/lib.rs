//! # Storage Backends for USG SBC
//!
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::type_complexity)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::unused_async)]
//!
//! This crate provides pluggable storage backends for the USG Session Border Controller,
//! supporting:
//!
//! - **In-Memory**: Fast, local storage for single-node deployments
//! - **Redis**: Distributed caching with cluster support
//! - **PostgreSQL**: Persistent relational storage
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-28**: Protection of Information at Rest
//! - **AU-4**: Audit Log Storage Capacity
//! - **CP-9**: System Backup
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Storage Manager                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │   In-Memory   │      Redis       │     PostgreSQL           │
//! │   (HashMap)   │   (Cluster/Pool) │   (Connection Pool)      │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Example
//!
//! ```ignore
//! use uc_storage::{StorageBackend, StorageConfig, StorageManager};
//!
//! let config = StorageConfig::in_memory();
//! let storage = StorageManager::new(config).await?;
//!
//! storage.set("key", b"value", None).await?;
//! let value = storage.get("key").await?;
//! ```

pub mod backend;
pub mod config;
pub mod error;
pub mod memory;

#[cfg(feature = "redis")]
pub mod redis;

#[cfg(feature = "postgres")]
pub mod postgres;

pub use backend::StorageBackend;
pub use config::{
    PostgresConfig, PostgresSslMode, RedisConfig, RedisTlsConfig, RetryConfig, StorageBackendType,
    StorageConfig,
};
pub use error::{StorageError, StorageResult};
pub use memory::InMemoryBackend;

#[cfg(feature = "redis")]
pub use crate::redis::RedisBackend;

#[cfg(feature = "postgres")]
pub use postgres::PostgresBackend;

use bytes::Bytes;
use std::time::Duration;
use tracing::info;

/// Creates a storage backend based on configuration.
///
/// # Errors
/// Returns an error if the backend cannot be created.
pub async fn create_backend(config: &StorageConfig) -> StorageResult<Box<dyn StorageBackend>> {
    match config.backend {
        StorageBackendType::InMemory => {
            info!("Creating in-memory storage backend");
            Ok(Box::new(InMemoryBackend::new()))
        }
        #[cfg(feature = "redis")]
        StorageBackendType::Redis => {
            let redis_config = config
                .redis
                .as_ref()
                .ok_or_else(|| StorageError::ConfigError {
                    reason: "Redis backend requires redis configuration".to_string(),
                })?;
            info!(url = %redis_config.url, "Creating Redis storage backend");
            let backend = RedisBackend::new(redis_config.clone()).await?;
            Ok(Box::new(backend))
        }
        #[cfg(not(feature = "redis"))]
        StorageBackendType::Redis => Err(StorageError::ConfigError {
            reason: "Redis backend requires the 'redis' feature".to_string(),
        }),
        #[cfg(feature = "postgres")]
        StorageBackendType::Postgres => {
            let pg_config = config
                .postgres
                .as_ref()
                .ok_or_else(|| StorageError::ConfigError {
                    reason: "PostgreSQL backend requires postgres configuration".to_string(),
                })?;
            info!(database = %pg_config.database, "Creating PostgreSQL storage backend");
            let backend = PostgresBackend::new(pg_config.clone()).await?;
            Ok(Box::new(backend))
        }
        #[cfg(not(feature = "postgres"))]
        StorageBackendType::Postgres => Err(StorageError::ConfigError {
            reason: "PostgreSQL backend requires the 'postgres' feature".to_string(),
        }),
    }
}

/// Storage manager that wraps a storage backend.
pub struct StorageManager {
    backend: Box<dyn StorageBackend>,
    config: StorageConfig,
}

impl StorageManager {
    /// Creates a new storage manager with the given configuration.
    ///
    /// # Errors
    /// Returns an error if the backend cannot be created.
    pub async fn new(config: StorageConfig) -> StorageResult<Self> {
        let backend = create_backend(&config).await?;
        Ok(Self { backend, config })
    }

    /// Returns the storage backend type.
    #[must_use]
    pub fn backend_type(&self) -> StorageBackendType {
        self.config.backend
    }

    /// Gets a value by key.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn get(&self, key: &str) -> StorageResult<Option<Bytes>> {
        self.backend.get(key).await
    }

    /// Sets a value with optional TTL.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn set(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> StorageResult<()> {
        self.backend.set(key, value, ttl).await
    }

    /// Deletes a value by key.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn delete(&self, key: &str) -> StorageResult<bool> {
        self.backend.delete(key).await
    }

    /// Lists keys matching a pattern.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn keys(&self, pattern: &str) -> StorageResult<Vec<String>> {
        self.backend.keys(pattern).await
    }

    /// Atomically increments a counter.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub async fn increment(&self, key: &str, delta: i64) -> StorageResult<i64> {
        self.backend.increment(key, delta).await
    }

    /// Checks if the storage backend is healthy.
    pub async fn health_check(&self) -> bool {
        self.backend.health_check().await
    }
}

impl std::fmt::Debug for StorageManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageManager")
            .field("backend_type", &self.config.backend)
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_in_memory_backend() {
        let config = StorageConfig::in_memory();
        let manager = StorageManager::new(config).await.unwrap();

        assert!(matches!(
            manager.backend_type(),
            StorageBackendType::InMemory
        ));
    }

    #[tokio::test]
    async fn test_storage_manager_operations() {
        let config = StorageConfig::in_memory();
        let manager = StorageManager::new(config).await.unwrap();

        // Set a value
        manager.set("test-key", b"test-value", None).await.unwrap();

        // Get the value
        let value = manager.get("test-key").await.unwrap();
        assert_eq!(value, Some(Bytes::from("test-value")));

        // Delete the value
        let deleted = manager.delete("test-key").await.unwrap();
        assert!(deleted);

        // Verify it's gone
        let value = manager.get("test-key").await.unwrap();
        assert!(value.is_none());
    }

    #[tokio::test]
    async fn test_health_check() {
        let config = StorageConfig::in_memory();
        let manager = StorageManager::new(config).await.unwrap();

        assert!(manager.health_check().await);
    }
}
