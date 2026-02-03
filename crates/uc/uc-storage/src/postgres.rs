//! PostgreSQL storage backend (requires `postgres` feature).
//!
//! This module is only available when the `postgres` feature is enabled.

#![cfg(feature = "postgres")]

use crate::backend::StorageBackend;
use crate::config::PostgresConfig;
use crate::error::{StorageError, StorageResult};
use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// PostgreSQL storage backend.
pub struct PostgresBackend {
    _config: PostgresConfig,
}

impl PostgresBackend {
    /// Creates a new PostgreSQL backend.
    ///
    /// # Errors
    /// Returns an error if connection fails.
    pub async fn new(config: PostgresConfig) -> StorageResult<Self> {
        // TODO: Implement actual PostgreSQL connection
        Ok(Self { _config: config })
    }
}

impl StorageBackend for PostgresBackend {
    fn get(
        &self,
        _key: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Option<Bytes>>> + Send + '_>> {
        Box::pin(async move {
            Err(StorageError::ConfigError {
                reason: "PostgreSQL backend not yet implemented".to_string(),
            })
        })
    }

    fn set(
        &self,
        _key: &str,
        _value: &[u8],
        _ttl: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = StorageResult<()>> + Send + '_>> {
        Box::pin(async move {
            Err(StorageError::ConfigError {
                reason: "PostgreSQL backend not yet implemented".to_string(),
            })
        })
    }

    fn delete(&self, _key: &str) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        Box::pin(async move {
            Err(StorageError::ConfigError {
                reason: "PostgreSQL backend not yet implemented".to_string(),
            })
        })
    }

    fn keys(
        &self,
        _pattern: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Vec<String>>> + Send + '_>> {
        Box::pin(async move {
            Err(StorageError::ConfigError {
                reason: "PostgreSQL backend not yet implemented".to_string(),
            })
        })
    }

    fn increment(
        &self,
        _key: &str,
        _delta: i64,
    ) -> Pin<Box<dyn Future<Output = StorageResult<i64>> + Send + '_>> {
        Box::pin(async move {
            Err(StorageError::ConfigError {
                reason: "PostgreSQL backend not yet implemented".to_string(),
            })
        })
    }

    fn backend_name(&self) -> &'static str {
        "postgres"
    }
}
