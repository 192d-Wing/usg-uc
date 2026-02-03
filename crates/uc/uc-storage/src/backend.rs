//! Storage backend trait definition.

use crate::error::StorageResult;
use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// Storage backend trait.
///
/// Provides a unified interface for different storage implementations.
pub trait StorageBackend: Send + Sync + 'static {
    /// Gets a value by key.
    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Option<Bytes>>> + Send + '_>>;

    /// Sets a value with optional TTL.
    fn set(
        &self,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = StorageResult<()>> + Send + '_>>;

    /// Deletes a value by key.
    fn delete(&self, key: &str) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>>;

    /// Lists keys matching a pattern.
    ///
    /// Pattern uses glob-style matching:
    /// - `*` matches any sequence of characters
    /// - `?` matches any single character
    fn keys(
        &self,
        pattern: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Vec<String>>> + Send + '_>>;

    /// Atomically increments a counter.
    ///
    /// If the key doesn't exist, it's initialized to 0 before incrementing.
    fn increment(
        &self,
        key: &str,
        delta: i64,
    ) -> Pin<Box<dyn Future<Output = StorageResult<i64>> + Send + '_>>;

    /// Checks if the storage backend is healthy.
    fn health_check(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(async { true })
    }

    /// Returns the backend name.
    fn backend_name(&self) -> &'static str;

    /// Checks if a key exists.
    fn exists(&self, key: &str) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            // Default implementation uses get
            // Backends can override for efficiency
            Ok(self.get(&key).await?.is_some())
        })
    }

    /// Sets a value only if it doesn't exist.
    fn set_nx(
        &self,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        let value = value.to_vec();
        Box::pin(async move {
            // Default implementation using exists + set (not atomic)
            // Backends should override for atomic implementation
            if self.exists(&key).await? {
                Ok(false)
            } else {
                self.set(&key, &value, ttl).await?;
                Ok(true)
            }
        })
    }

    /// Gets multiple values by keys.
    fn mget(
        &self,
        keys: &[&str],
    ) -> Pin<Box<dyn Future<Output = StorageResult<Vec<Option<Bytes>>>> + Send + '_>> {
        let keys: Vec<String> = keys.iter().map(|s| (*s).to_string()).collect();
        Box::pin(async move {
            let mut results = Vec::with_capacity(keys.len());
            for key in &keys {
                results.push(self.get(key).await?);
            }
            Ok(results)
        })
    }

    /// Sets multiple key-value pairs.
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
            for (key, value) in &pairs {
                self.set(key, value, ttl).await?;
            }
            Ok(())
        })
    }

    /// Deletes multiple keys.
    fn mdelete(
        &self,
        keys: &[&str],
    ) -> Pin<Box<dyn Future<Output = StorageResult<usize>> + Send + '_>> {
        let keys: Vec<String> = keys.iter().map(|s| (*s).to_string()).collect();
        Box::pin(async move {
            let mut count = 0;
            for key in &keys {
                if self.delete(key).await? {
                    count += 1;
                }
            }
            Ok(count)
        })
    }

    /// Sets a value with expiration time (TTL must be provided).
    fn setex(
        &self,
        key: &str,
        value: &[u8],
        ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = StorageResult<()>> + Send + '_>> {
        self.set(key, value, Some(ttl))
    }

    /// Gets the TTL of a key in seconds.
    ///
    /// Returns:
    /// - `Some(seconds)` if key exists with TTL
    /// - `Some(i64::MAX)` if key exists without TTL (never expires)
    /// - `None` if key doesn't exist
    fn ttl(
        &self,
        _key: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Option<i64>>> + Send + '_>> {
        // Default implementation doesn't support TTL queries
        Box::pin(async { Ok(None) })
    }

    /// Expires a key after the given duration.
    fn expire(
        &self,
        _key: &str,
        _ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        // Default implementation doesn't support expire
        Box::pin(async { Ok(false) })
    }

    /// Persists a key (removes expiration).
    fn persist(
        &self,
        _key: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        // Default implementation doesn't support persist
        Box::pin(async { Ok(false) })
    }
}
