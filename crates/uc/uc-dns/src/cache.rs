//! DNS caching with TTL management.
//!
//! Provides TTL-aware caching for DNS records to reduce query load
//! and improve resolution performance.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, trace};

/// Maximum expired entries evicted by a single `put` at capacity.
///
/// NIST 800-53 Rev5: SC-5 (bounded work under the cache write lock).
const PUT_EVICT_BATCH: usize = 32;

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

/// Cache storage plus ordered indexes for O(log n) eviction.
///
/// NIST 800-53 Rev5: SC-5 — the cache is hard-bounded by `max_entries`; the
/// indexes keep eviction at capacity O(log n) so an insertion flood cannot
/// degrade into an O(n) scan per insert (O(n^2) CPU overall).
#[derive(Debug, Default)]
struct CacheInner {
    /// Key -> (record, insertion sequence number).
    entries: HashMap<String, (CachedRecord<CacheEntry>, u64)>,
    /// Insertion order index (oldest first): seq -> key.
    by_insert: BTreeMap<u64, String>,
    /// Expiry index (soonest first): (expires_at, seq) -> key.
    by_expiry: BTreeMap<(Instant, u64), String>,
    /// Next insertion sequence number.
    next_seq: u64,
}

impl CacheInner {
    fn len(&self) -> usize {
        self.entries.len()
    }

    /// Removes `key` and its index entries. O(log n).
    fn remove(&mut self, key: &str) -> bool {
        if let Some((record, seq)) = self.entries.remove(key) {
            self.by_insert.remove(&seq);
            self.by_expiry.remove(&(record.expires_at, seq));
            true
        } else {
            false
        }
    }

    /// Inserts (or replaces) `key`, keeping both indexes consistent.
    fn insert(&mut self, key: String, record: CachedRecord<CacheEntry>) {
        self.remove(&key);
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.by_insert.insert(seq, key.clone());
        self.by_expiry.insert((record.expires_at, seq), key.clone());
        self.entries.insert(key, (record, seq));
    }

    /// Evicts every entry whose expiry is at or before `now`, soonest first.
    fn evict_expired(&mut self, now: Instant, limit: usize) -> usize {
        let mut evicted = 0;
        while evicted < limit
            && let Some((&(expires_at, _), _)) = self.by_expiry.first_key_value()
        {
            if expires_at > now {
                break;
            }
            if let Some((_, key)) = self.by_expiry.pop_first() {
                if let Some((_, seq)) = self.entries.remove(&key) {
                    self.by_insert.remove(&seq);
                }
                evicted += 1;
            }
        }
        evicted
    }

    /// Evicts the oldest-inserted entry. O(log n).
    fn evict_oldest(&mut self) -> bool {
        self.by_insert
            .first_key_value()
            .map(|(_, key)| key.clone())
            .is_some_and(|key| self.remove(&key))
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.by_insert.clear();
        self.by_expiry.clear();
    }

    #[cfg(test)]
    fn indexes_consistent(&self) -> bool {
        self.entries.len() == self.by_insert.len()
            && self.entries.len() == self.by_expiry.len()
            && self.entries.iter().all(|(k, (r, seq))| {
                self.by_insert.get(seq) == Some(k)
                    && self.by_expiry.get(&(r.expires_at, *seq)) == Some(k)
            })
    }
}

/// DNS cache with TTL-based expiration.
#[derive(Debug)]
pub struct DnsCache {
    /// Cache storage and eviction indexes.
    inner: Arc<RwLock<CacheInner>>,
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
            inner: Arc::new(RwLock::new(CacheInner::default())),
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
        let inner = self.inner.read().await;

        if let Some((record, _)) = inner.entries.get(&key)
            && !record.is_expired()
        {
            trace!(key = %key, ttl = ?record.remaining_ttl(), "Cache hit");
            return Some(record.data.clone());
        }
        drop(inner);

        trace!(key = %key, "Cache miss");
        None
    }

    /// Puts an entry in the cache.
    ///
    /// At capacity, expired entries are evicted first (soonest expiry
    /// first), then the oldest-inserted live entries; each eviction is
    /// O(log n).
    pub async fn put(&self, name: &str, record_type: &str, entry: CacheEntry, ttl: Duration) {
        let key = Self::cache_key(name, record_type);
        let normalized_ttl = self.normalize_ttl(ttl);

        let mut inner = self.inner.write().await;

        // Overwriting an existing key never needs to evict another entry.
        inner.remove(&key);

        if inner.len() >= self.max_entries {
            // Bounded per put so one insert never drains the whole table under
            // the write lock; bulk cleanup is left to `evict_expired()`.
            let evicted = inner.evict_expired(Instant::now(), PUT_EVICT_BATCH);
            if evicted > 0 {
                debug!(count = evicted, "Evicted expired cache entries");
            }
        }

        while inner.len() >= self.max_entries {
            if !inner.evict_oldest() {
                break;
            }
        }

        let record = CachedRecord::new(entry, normalized_ttl);
        debug!(key = %key, ttl = ?normalized_ttl, "Cached DNS record");
        inner.insert(key, record);
    }

    /// Puts a negative cache entry.
    pub async fn put_negative(&self, name: &str, record_type: &str) {
        self.put(name, record_type, CacheEntry::Negative, self.negative_ttl)
            .await;
    }

    /// Removes an entry from the cache.
    pub async fn remove(&self, name: &str, record_type: &str) {
        let key = Self::cache_key(name, record_type);
        let mut inner = self.inner.write().await;
        inner.remove(&key);
    }

    /// Clears all cached entries.
    pub async fn clear(&self) {
        let mut inner = self.inner.write().await;
        inner.clear();
    }

    /// Returns the number of cached entries.
    pub async fn len(&self) -> usize {
        let inner = self.inner.read().await;
        inner.len()
    }

    /// Returns true if the cache is empty.
    pub async fn is_empty(&self) -> bool {
        let inner = self.inner.read().await;
        inner.entries.is_empty()
    }

    /// Evicts expired entries.
    pub async fn evict_expired(&self) -> usize {
        let mut inner = self.inner.write().await;
        let evicted = inner.evict_expired(Instant::now(), usize::MAX);
        drop(inner);
        if evicted > 0 {
            debug!(count = evicted, "Evicted expired cache entries");
        }
        evicted
    }

    /// Returns cache statistics.
    pub async fn stats(&self) -> CacheStats {
        let inner = self.inner.read().await;
        let total = inner.len();
        let expired = inner
            .entries
            .values()
            .filter(|(r, _)| r.is_expired())
            .count();
        let negative = inner
            .entries
            .values()
            .filter(|(r, _)| matches!(r.data, CacheEntry::Negative))
            .count();
        drop(inner);

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
            Duration::from_mins(1),
            Duration::from_hours(24),
            Duration::from_mins(5),
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
        let record = CachedRecord::new("test data", Duration::from_mins(1));
        assert!(!record.is_expired());
        assert!(record.remaining_ttl() <= Duration::from_mins(1));
        assert!(record.age() < Duration::from_millis(100));
    }

    #[allow(clippy::unwrap_used, clippy::panic)]
    #[tokio::test]
    async fn test_cache_put_get() {
        let cache = DnsCache::default();

        cache
            .put(
                "example.com",
                "A",
                CacheEntry::Address(vec!["1.2.3.4".parse().unwrap()]),
                Duration::from_mins(5),
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
                Duration::from_mins(5),
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
            Duration::from_hours(1),
            Duration::from_mins(1),
        );

        cache
            .put(
                "a.com",
                "A",
                CacheEntry::Address(vec![]),
                Duration::from_mins(1),
            )
            .await;
        cache.put_negative("b.com", "A").await;

        let stats = cache.stats().await;
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.negative_entries, 1);
        assert!(stats.utilization() > 0.0);
    }

    fn small_cache(max: usize) -> DnsCache {
        DnsCache::new(
            max,
            Duration::ZERO,
            Duration::from_hours(1),
            Duration::from_mins(1),
        )
    }

    #[tokio::test]
    async fn test_capacity_evicts_oldest_first() {
        let cache = small_cache(3);
        for i in 0..5 {
            cache
                .put(
                    &format!("h{i}.test"),
                    "A",
                    CacheEntry::Negative,
                    Duration::from_mins(5),
                )
                .await;
        }
        assert_eq!(cache.len().await, 3);
        assert!(cache.get("h0.test", "A").await.is_none());
        assert!(cache.get("h1.test", "A").await.is_none());
        for i in 2..5 {
            assert!(cache.get(&format!("h{i}.test"), "A").await.is_some());
        }
        assert!(cache.inner.read().await.indexes_consistent());
    }

    #[tokio::test]
    async fn test_overwrite_keeps_index_consistent() {
        let cache = small_cache(2);
        cache
            .put("a.test", "A", CacheEntry::Negative, Duration::from_mins(5))
            .await;
        cache
            .put("b.test", "A", CacheEntry::Negative, Duration::from_mins(5))
            .await;
        // Overwrite at capacity must not evict b.
        cache
            .put("a.test", "A", CacheEntry::Negative, Duration::from_mins(9))
            .await;
        assert_eq!(cache.len().await, 2);
        assert!(cache.get("b.test", "A").await.is_some());
        assert!(cache.inner.read().await.indexes_consistent());
        // a is now the newest; next insert evicts b.
        cache
            .put("c.test", "A", CacheEntry::Negative, Duration::from_mins(5))
            .await;
        assert!(cache.get("b.test", "A").await.is_none());
        assert!(cache.get("a.test", "A").await.is_some());
        assert!(cache.inner.read().await.indexes_consistent());
    }

    #[tokio::test]
    async fn test_expired_evicted_before_live() {
        let cache = small_cache(2);
        cache
            .put(
                "live.test",
                "A",
                CacheEntry::Negative,
                Duration::from_mins(5),
            )
            .await;
        cache
            .put("dead.test", "A", CacheEntry::Negative, Duration::ZERO)
            .await;
        cache
            .put(
                "new.test",
                "A",
                CacheEntry::Negative,
                Duration::from_mins(5),
            )
            .await;
        assert!(cache.get("live.test", "A").await.is_some());
        assert!(cache.get("new.test", "A").await.is_some());
        assert_eq!(cache.len().await, 2);
        assert!(cache.inner.read().await.indexes_consistent());
    }

    #[tokio::test]
    async fn test_random_ops_keep_indexes_consistent() {
        let cache = small_cache(16);
        // Deterministic LCG; no RNG dependency needed for the property.
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        for _ in 0..2000 {
            x = x.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let name = format!("n{}.test", (x >> 33) % 40);
            match (x >> 20) % 4 {
                0 => cache.remove(&name, "A").await,
                1 => {
                    cache
                        .put(&name, "A", CacheEntry::Negative, Duration::ZERO)
                        .await;
                }
                _ => {
                    cache
                        .put(&name, "A", CacheEntry::Negative, Duration::from_mins(5))
                        .await;
                }
            }
            assert!(cache.len().await <= 16);
        }
        cache.evict_expired().await;
        assert!(cache.inner.read().await.indexes_consistent());
    }
}
