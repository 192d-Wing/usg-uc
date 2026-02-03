//! In-memory storage backend.
//!
//! Provides a thread-safe, in-memory key-value store with optional TTL support.

use crate::backend::StorageBackend;
use crate::error::StorageResult;
use bytes::Bytes;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::debug;

/// Entry in the in-memory store.
struct Entry {
    /// The stored value.
    value: Bytes,
    /// When the entry expires (None = never).
    expires_at: Option<Instant>,
}

impl Entry {
    /// Creates a new entry.
    fn new(value: Bytes, ttl: Option<Duration>) -> Self {
        Self {
            value,
            expires_at: ttl.map(|d| Instant::now() + d),
        }
    }

    /// Checks if the entry has expired.
    fn is_expired(&self) -> bool {
        self.expires_at.map_or(false, |exp| Instant::now() > exp)
    }
}

/// In-memory storage backend.
pub struct InMemoryBackend {
    /// The key-value store.
    store: RwLock<HashMap<String, Entry>>,
    /// Counters for atomic increment operations.
    counters: RwLock<HashMap<String, AtomicI64>>,
}

impl InMemoryBackend {
    /// Creates a new in-memory backend.
    #[must_use]
    pub fn new() -> Self {
        debug!("Creating in-memory storage backend");
        Self {
            store: RwLock::new(HashMap::new()),
            counters: RwLock::new(HashMap::new()),
        }
    }

    /// Returns the number of entries in the store.
    pub async fn len(&self) -> usize {
        self.store.read().await.len()
    }

    /// Checks if the store is empty.
    pub async fn is_empty(&self) -> bool {
        self.store.read().await.is_empty()
    }

    /// Clears all entries from the store.
    pub async fn clear(&self) {
        self.store.write().await.clear();
        self.counters.write().await.clear();
    }

    /// Removes expired entries.
    pub async fn cleanup_expired(&self) -> usize {
        let mut store = self.store.write().await;
        let before = store.len();
        store.retain(|_, entry| !entry.is_expired());
        let removed = before - store.len();
        if removed > 0 {
            debug!(removed, "Cleaned up expired entries");
        }
        removed
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for InMemoryBackend {
    fn get(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Option<Bytes>>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            let store = self.store.read().await;
            let result = store.get(&key).and_then(|entry| {
                if entry.is_expired() {
                    None
                } else {
                    Some(entry.value.clone())
                }
            });
            Ok(result)
        })
    }

    fn set(
        &self,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = StorageResult<()>> + Send + '_>> {
        let key = key.to_string();
        let value = Bytes::copy_from_slice(value);
        Box::pin(async move {
            let mut store = self.store.write().await;
            store.insert(key, Entry::new(value, ttl));
            Ok(())
        })
    }

    fn delete(&self, key: &str) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            let mut store = self.store.write().await;
            let existed = store.remove(&key).is_some();

            // Also remove from counters
            let mut counters = self.counters.write().await;
            counters.remove(&key);

            Ok(existed)
        })
    }

    fn keys(
        &self,
        pattern: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Vec<String>>> + Send + '_>> {
        let pattern = pattern.to_string();
        Box::pin(async move {
            let store = self.store.read().await;
            let matched: Vec<String> = store
                .iter()
                .filter(|(k, entry)| !entry.is_expired() && matches_pattern(k, &pattern))
                .map(|(k, _)| k.clone())
                .collect();
            Ok(matched)
        })
    }

    fn increment(
        &self,
        key: &str,
        delta: i64,
    ) -> Pin<Box<dyn Future<Output = StorageResult<i64>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            let mut counters = self.counters.write().await;
            let counter = counters.entry(key).or_insert_with(|| AtomicI64::new(0));
            let new_value = counter.fetch_add(delta, Ordering::SeqCst) + delta;
            Ok(new_value)
        })
    }

    fn backend_name(&self) -> &'static str {
        "in_memory"
    }

    fn exists(&self, key: &str) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            let store = self.store.read().await;
            let exists = store.get(&key).map_or(false, |entry| !entry.is_expired());
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
        let value = Bytes::copy_from_slice(value);
        Box::pin(async move {
            let mut store = self.store.write().await;

            // Check if key exists and is not expired
            if let Some(entry) = store.get(&key) {
                if !entry.is_expired() {
                    return Ok(false);
                }
            }

            store.insert(key, Entry::new(value, ttl));
            Ok(true)
        })
    }

    fn ttl(
        &self,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = StorageResult<Option<i64>>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            let store = self.store.read().await;
            let result = store.get(&key).and_then(|entry| {
                if entry.is_expired() {
                    None
                } else {
                    match entry.expires_at {
                        Some(exp) => {
                            let remaining = exp.saturating_duration_since(Instant::now());
                            Some(remaining.as_secs() as i64)
                        }
                        None => Some(i64::MAX), // No expiration
                    }
                }
            });
            Ok(result)
        })
    }

    fn expire(
        &self,
        key: &str,
        ttl: Duration,
    ) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            let mut store = self.store.write().await;
            if let Some(entry) = store.get_mut(&key) {
                if !entry.is_expired() {
                    entry.expires_at = Some(Instant::now() + ttl);
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }

    fn persist(&self, key: &str) -> Pin<Box<dyn Future<Output = StorageResult<bool>> + Send + '_>> {
        let key = key.to_string();
        Box::pin(async move {
            let mut store = self.store.write().await;
            if let Some(entry) = store.get_mut(&key) {
                if !entry.is_expired() {
                    entry.expires_at = None;
                    return Ok(true);
                }
            }
            Ok(false)
        })
    }
}

impl std::fmt::Debug for InMemoryBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryBackend")
            .field("store", &"<locked>")
            .field("counters", &"<locked>")
            .finish()
    }
}

/// Checks if a key matches a glob pattern.
fn matches_pattern(key: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let mut key_chars = key.chars().peekable();
    let mut pattern_chars = pattern.chars().peekable();

    while let Some(p) = pattern_chars.next() {
        match p {
            '*' => {
                // Match any sequence
                if pattern_chars.peek().is_none() {
                    return true;
                }
                while key_chars.peek().is_some() {
                    if matches_pattern(
                        key_chars.clone().collect::<String>().as_str(),
                        pattern_chars.clone().collect::<String>().as_str(),
                    ) {
                        return true;
                    }
                    key_chars.next();
                }
                return false;
            }
            '?' => {
                // Match any single character
                if key_chars.next().is_none() {
                    return false;
                }
            }
            c => {
                if key_chars.next() != Some(c) {
                    return false;
                }
            }
        }
    }

    key_chars.peek().is_none()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_set_get() {
        let backend = InMemoryBackend::new();

        backend.set("key", b"value", None).await.unwrap();
        let result = backend.get("key").await.unwrap();

        assert_eq!(result, Some(Bytes::from("value")));
    }

    #[tokio::test]
    async fn test_delete() {
        let backend = InMemoryBackend::new();

        backend.set("key", b"value", None).await.unwrap();
        let deleted = backend.delete("key").await.unwrap();
        assert!(deleted);

        let result = backend.get("key").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_increment() {
        let backend = InMemoryBackend::new();

        let v1 = backend.increment("counter", 1).await.unwrap();
        assert_eq!(v1, 1);

        let v2 = backend.increment("counter", 5).await.unwrap();
        assert_eq!(v2, 6);

        let v3 = backend.increment("counter", -2).await.unwrap();
        assert_eq!(v3, 4);
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let backend = InMemoryBackend::new();

        backend
            .set("key", b"value", Some(Duration::from_millis(50)))
            .await
            .unwrap();

        // Should exist immediately
        let result = backend.get("key").await.unwrap();
        assert!(result.is_some());

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Should be expired
        let result = backend.get("key").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_keys_pattern() {
        let backend = InMemoryBackend::new();

        backend.set("user:1", b"a", None).await.unwrap();
        backend.set("user:2", b"b", None).await.unwrap();
        backend.set("session:1", b"c", None).await.unwrap();

        let user_keys = backend.keys("user:*").await.unwrap();
        assert_eq!(user_keys.len(), 2);

        let all_keys = backend.keys("*").await.unwrap();
        assert_eq!(all_keys.len(), 3);

        let specific = backend.keys("user:1").await.unwrap();
        assert_eq!(specific.len(), 1);
    }

    #[tokio::test]
    async fn test_set_nx() {
        let backend = InMemoryBackend::new();

        let set1 = backend.set_nx("key", b"value1", None).await.unwrap();
        assert!(set1);

        let set2 = backend.set_nx("key", b"value2", None).await.unwrap();
        assert!(!set2);

        let value = backend.get("key").await.unwrap();
        assert_eq!(value, Some(Bytes::from("value1")));
    }

    #[tokio::test]
    async fn test_exists() {
        let backend = InMemoryBackend::new();

        assert!(!backend.exists("key").await.unwrap());

        backend.set("key", b"value", None).await.unwrap();
        assert!(backend.exists("key").await.unwrap());

        backend.delete("key").await.unwrap();
        assert!(!backend.exists("key").await.unwrap());
    }

    #[tokio::test]
    async fn test_expire_and_persist() {
        let backend = InMemoryBackend::new();

        backend.set("key", b"value", None).await.unwrap();

        // Set expiration
        let expired = backend
            .expire("key", Duration::from_secs(60))
            .await
            .unwrap();
        assert!(expired);

        // Check TTL
        let ttl = backend.ttl("key").await.unwrap();
        assert!(ttl.unwrap() > 0);
        assert!(ttl.unwrap() <= 60);

        // Persist (remove expiration)
        let persisted = backend.persist("key").await.unwrap();
        assert!(persisted);

        let ttl = backend.ttl("key").await.unwrap();
        assert_eq!(ttl, Some(i64::MAX));
    }

    #[test]
    fn test_pattern_matching() {
        assert!(matches_pattern("hello", "*"));
        assert!(matches_pattern("hello", "hello"));
        assert!(matches_pattern("hello", "h*"));
        assert!(matches_pattern("hello", "*o"));
        assert!(matches_pattern("hello", "h*o"));
        assert!(matches_pattern("hello", "h?llo"));
        assert!(!matches_pattern("hello", "world"));
        assert!(!matches_pattern("hello", "h?o"));
        assert!(matches_pattern("user:123", "user:*"));
        assert!(matches_pattern("user:123:data", "user:*:data"));
    }
}
