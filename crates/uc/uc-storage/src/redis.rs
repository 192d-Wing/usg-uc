//! Redis storage backend (requires `redis` feature).
//!
//! This module is only available when the `redis` feature is enabled.

#![cfg(feature = "redis")]

use crate::backend::StorageBackend;
use crate::config::RedisConfig;
use crate::error::{StorageError, StorageResult};
use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Redis storage backend.
pub struct RedisBackend {
    _config: RedisConfig,
}

impl RedisBackend {
    /// Creates a new Redis backend.
    ///
    /// # Errors
    /// Returns an error if connection fails.
    pub async fn new(config: RedisConfig) -> StorageResult<Self> {
        // TODO: Implement actual Redis connection
        Ok(Self { _config: config })
    }
}

impl StorageBackend for RedisBackend {
    fn get(
        &self,
        _key: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Option<Bytes>>> + Send + '_>> {
        Box::pin(async move {
            Err(StorageError::ConfigError {
                reason: "Redis backend not yet implemented".to_string(),
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
                reason: "Redis backend not yet implemented".to_string(),
            })
        })
    }

    fn delete(&self, _key: &str) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        Box::pin(async move {
            Err(StorageError::ConfigError {
                reason: "Redis backend not yet implemented".to_string(),
            })
        })
    }

    fn keys(
        &self,
        _pattern: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Vec<String>>> + Send + '_>> {
        Box::pin(async move {
            Err(StorageError::ConfigError {
                reason: "Redis backend not yet implemented".to_string(),
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
                reason: "Redis backend not yet implemented".to_string(),
            })
        })
    }

    fn backend_name(&self) -> &'static str {
        "redis"
    }
}
