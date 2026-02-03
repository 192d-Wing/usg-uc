//! DNS caching with TTL management.
//!
//! Provides TTL-aware caching for DNS records to reduce query load
//! and improve resolution performance.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, trace};

/// A cached DNS record with expiration tracking.
#[derive(Debug, Clone)]
pub struct CachedRecord<T> {
    /// The cached data.
    pub data: T,
    /// When this record was cached.
    pub cached_at: Instant,
    /// Original TTL from DNS response.
    pub original_ttl: Duration,
    /// Expiration time.
    pub expires_at: Instant,
}

impl<T> CachedRecord<T> {
    /// Creates a new cached record.
    pub fn new(data: T, ttl: Duration) -> Self {
        let now = Instant::now();
        Self {
            data,
            cached_at: now,
            original_ttl: ttl,
            expires_at: now + ttl,
        }
    }

    /// Returns true if this record has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Returns the remaining TTL.
    #[must_use]
    pub fn remaining_ttl(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }

    /// Returns the age of this cached record.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.cached_at.elapsed()
    }
}

/// Cache entry types for different record kinds.
#[derive(Debug, Clone)]
pub enum CacheEntry {
    /// A/AAAA records (IP addresses).
    Address(Vec<std::net::IpAddr>),
    /// SRV records.
    Srv(Vec<crate::srv::SrvRecord>),
    /// NAPTR records.
    Naptr(Vec<crate::naptr::NaptrRecord>),
    /// ENUM results.
    Enum(Vec<crate::r#enum::EnumResult>),
    /// Negative cache (NXDOMAIN or no records).
    Negative,
}

/// DNS cache with TTL-based expiration.
#[derive(Debug)]
pub struct DnsCache {
    /// Cache storage.
    entries: Arc<RwLock<HashMap<String, CachedRecord<CacheEntry>>>>,
    /// Maximum number of entries.
    max_entries: usize,
    /// Minimum TTL (overrides shorter TTLs).
    min_ttl: Duration,
    /// Maximum TTL (overrides longer TTLs).
    max_ttl: Duration,
    /// Negative cache TTL.
    negative_ttl: Duration,
}

impl DnsCache {
    /// Creates a new DNS cache.
    #[must_use]
    pub fn new(
        max_entries: usize,
        min_ttl: Duration,
        max_ttl: Duration,
        negative_ttl: Duration,
    ) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
            min_ttl,
            max_ttl,
            negative_ttl,
        }
    }

    /// Normalizes a TTL to be within configured bounds.
    fn normalize_ttl(&self, ttl: Duration) -> Duration {
        ttl.max(self.min_ttl).min(self.max_ttl)
    }

    /// Generates a cache key for a query.
    fn cache_key(name: &str, record_type: &str) -> String {
        format!("{}:{}", name.to_lowercase(), record_type)
    }

    /// Gets a cached entry.
    pub async fn get(&self, name: &str, record_type: &str) -> Option<CacheEntry> {
        let key = Self::cache_key(name, record_type);
        let entries = self.entries.read().await;

        if let Some(record) = entries.get(&key)
            && !record.is_expired()
        {
            trace!(key = %key, ttl = ?record.remaining_ttl(), "Cache hit");
            return Some(record.data.clone());
        }
        drop(entries);

        trace!(key = %key, "Cache miss");
        None
    }

    /// Puts an entry in the cache.
    pub async fn put(&self, name: &str, record_type: &str, entry: CacheEntry, ttl: Duration) {
        let key = Self::cache_key(name, record_type);
        let normalized_ttl = self.normalize_ttl(ttl);

        let mut entries = self.entries.write().await;

        // Evict expired entries if at capacity
        if entries.len() >= self.max_entries {
            Self::evict_expired_locked(&mut entries);
        }

        // If still at capacity, evict oldest entries
        while entries.len() >= self.max_entries {
            if let Some(oldest_key) = Self::find_oldest_locked(&entries) {
                entries.remove(&oldest_key);
            } else {
                break;
            }
        }

        let record = CachedRecord::new(entry, normalized_ttl);
        debug!(key = %key, ttl = ?normalized_ttl, "Cached DNS record");
        entries.insert(key, record);
    }

    /// Puts a negative cache entry.
    pub async fn put_negative(&self, name: &str, record_type: &str) {
        self.put(name, record_type, CacheEntry::Negative, self.negative_ttl)
            .await;
    }

    /// Removes an entry from the cache.
    pub async fn remove(&self, name: &str, record_type: &str) {
        let key = Self::cache_key(name, record_type);
        let mut entries = self.entries.write().await;
        entries.remove(&key);
    }

    /// Clears all cached entries.
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
    }

    /// Returns the number of cached entries.
    pub async fn len(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }

    /// Returns true if the cache is empty.
    pub async fn is_empty(&self) -> bool {
        let entries = self.entries.read().await;
        entries.is_empty()
    }

    /// Evicts expired entries.
    pub async fn evict_expired(&self) -> usize {
        let mut entries = self.entries.write().await;
        Self::evict_expired_locked(&mut entries)
    }

    /// Evicts expired entries (requires write lock).
    fn evict_expired_locked(entries: &mut HashMap<String, CachedRecord<CacheEntry>>) -> usize {
        let before = entries.len();
        entries.retain(|_, record| !record.is_expired());
        let evicted = before - entries.len();
        if evicted > 0 {
            debug!(count = evicted, "Evicted expired cache entries");
        }
        evicted
    }

    /// Finds the oldest entry key.
    fn find_oldest_locked(entries: &HashMap<String, CachedRecord<CacheEntry>>) -> Option<String> {
        entries
            .iter()
            .max_by_key(|(_, record)| record.age())
            .map(|(key, _)| key.clone())
    }

    /// Returns cache statistics.
    pub async fn stats(&self) -> CacheStats {
        let entries = self.entries.read().await;
        let total = entries.len();
        let expired = entries.values().filter(|r| r.is_expired()).count();
        let negative = entries
            .values()
            .filter(|r| matches!(r.data, CacheEntry::Negative))
            .count();
        drop(entries);

        CacheStats {
            total_entries: total,
            expired_entries: expired,
            negative_entries: negative,
            max_entries: self.max_entries,
        }
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(
            10000,
            Duration::from_secs(60),
            Duration::from_secs(86400),
            Duration::from_secs(300),
        )
    }
}

/// Cache statistics.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total entries in cache.
    pub total_entries: usize,
    /// Number of expired entries (pending eviction).
    pub expired_entries: usize,
    /// Number of negative cache entries.
    pub negative_entries: usize,
    /// Maximum allowed entries.
    pub max_entries: usize,
}

impl CacheStats {
    /// Returns the cache utilization as a percentage.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn utilization(&self) -> f64 {
        if self.max_entries == 0 {
            0.0
        } else {
            (self.total_entries as f64 / self.max_entries as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_record() {
        let record = CachedRecord::new("test data", Duration::from_secs(60));
        assert!(!record.is_expired());
        assert!(record.remaining_ttl() <= Duration::from_secs(60));
        assert!(record.age() < Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_cache_put_get() {
        let cache = DnsCache::default();

        cache
            .put(
                "example.com",
                "A",
                CacheEntry::Address(vec!["1.2.3.4".parse().unwrap()]),
                Duration::from_secs(300),
            )
            .await;

        let result = cache.get("example.com", "A").await;
        assert!(result.is_some());

        if let Some(CacheEntry::Address(addrs)) = result {
            assert_eq!(addrs.len(), 1);
        } else {
            panic!("Expected Address entry");
        }
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = DnsCache::default();
        let result = cache.get("nonexistent.com", "A").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cache_negative() {
        let cache = DnsCache::default();
        cache.put_negative("missing.com", "A").await;

        let result = cache.get("missing.com", "A").await;
        assert!(matches!(result, Some(CacheEntry::Negative)));
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let cache = DnsCache::default();
        cache
            .put(
                "example.com",
                "A",
                CacheEntry::Address(vec![]),
                Duration::from_secs(300),
            )
            .await;

        assert!(!cache.is_empty().await);
        cache.clear().await;
        assert!(cache.is_empty().await);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = DnsCache::new(
            100,
            Duration::from_secs(1),
            Duration::from_secs(3600),
            Duration::from_secs(60),
        );

        cache
            .put(
                "a.com",
                "A",
                CacheEntry::Address(vec![]),
                Duration::from_secs(60),
            )
            .await;
        cache.put_negative("b.com", "A").await;

        let stats = cache.stats().await;
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.negative_entries, 1);
        assert!(stats.utilization() > 0.0);
    }
}
