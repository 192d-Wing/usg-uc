//! Bounded, single-flight STI certificate cache.
//!
//! - Positive entries live for `min(ttl, Cache-Control max-age, notAfter)`
//!   in a sharded O(1) LRU of at most `entries` URLs.
//! - Fetch/validation failures are cached for `negative_ttl` in a separate,
//!   smaller LRU (`entries / 4`), so a flood of bad `x5u` values can never
//!   evict good certificates. URLs refused by the URL policy are not cached
//!   at all (refusing them is already free).
//! - One fetch per URL at a time; concurrent callers wait on it.
//! - At most `max_concurrent_fetches` fetches run at once, and at most
//!   [`MAX_FETCHES_PER_HOST`] per `x5u` host; beyond either a caller fails
//!   fast with [`FetchError::Busy`] (never queues).
//! - At most `max_fetches_per_source` new fetches started on behalf of one
//!   SIP source (IPv4 address or IPv6 /64), so one peer presenting `x5u`
//!   URLs on many hosts it controls cannot hold every fetch permit
//!   (POA&M-190). Joining an in-flight fetch for the same URL is free.
//! - The fetch runs on its own task: a caller that stops waiting (deadline,
//!   CANCEL) does not cancel it, and its result still fills the cache,
//!   unless the trust anchors changed meanwhile ([`StiCertCache::invalidate`]
//!   bumps a generation and results of older generations are dropped).
//!
//! Lock order: `inflight` then a store shard; none is held across an await.
//! Hash maps use std's randomly keyed `SipHash` (attacker-chosen URL keys).
//!
//! ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection), SC-17, IA-5(2)

use crate::anchors::AnchorStore;
use crate::error::FetchError;
use crate::fetch::CertSource;
use crate::lru::Lru;
use crate::ssrf::X5uUrl;
use proto_stir_shaken::{Alg, KeyResolver, TnAuthEntry, TnAuthScope, VerifiedKey, VerifyingKey};
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Semaphore, watch};

/// Most certificates accepted in one `x5u` chain document.
const MAX_CHAIN_CERTS: usize = 8;
/// Most concurrent fetches to one `x5u` host (on top of the global cap), so
/// one slow or hostile host cannot take every fetch permit.
pub const MAX_FETCHES_PER_HOST: usize = 4;
/// Default most concurrent fetches started for one SIP source
/// ([`CacheConfig::max_fetches_per_source`]).
pub const DEFAULT_MAX_FETCHES_PER_SOURCE: usize = 4;
/// Most lock shards per store.
const MAX_SHARDS: usize = 16;

/// Cache limits and timeouts.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum cached URLs.
    pub entries: usize,
    /// Positive TTL cap.
    pub ttl_secs: u64,
    /// Negative TTL.
    pub negative_ttl_secs: u64,
    /// Per-fetch deadline.
    pub fetch_timeout: Duration,
    /// Concurrent fetches.
    pub max_concurrent_fetches: usize,
    /// Optional `x5u` host allow-list.
    pub allow_hosts: Vec<String>,
    /// Most concurrent fetches started for one SIP source ([`SourceKey`]);
    /// clamped to `1..=max_concurrent_fetches`.
    ///
    /// NIST 800-53 Rev5: SC-5 (POA&M-190)
    pub max_fetches_per_source: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            entries: 4096,
            ttl_secs: 3600,
            negative_ttl_secs: 60,
            fetch_timeout: Duration::from_millis(1500),
            max_concurrent_fetches: 32,
            allow_hosts: Vec::new(),
            max_fetches_per_source: DEFAULT_MAX_FETCHES_PER_SOURCE,
        }
    }
}

/// The SIP source a fetch is charged to.
///
/// An IPv4 address, an IPv6 /64 (one subscriber allocation, so address rotation within it does not
/// multiply the budget), or `Unspecified` for callers without a source
/// (budgeted like any other source, never exempt).
// POAM: POA&M-196, carriers sharing one source IP share one budget; a peer
// holding a /48 (or shorter) IPv6 prefix can present up to 65536 /64 keys,
// and spoofed UDP sources are charged to the spoofed key. Both remain
// bounded by `max_concurrent_fetches`; per-trunk charging is the follow-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKey {
    /// IPv4 source address.
    V4(std::net::Ipv4Addr),
    /// Upper 64 bits of an IPv6 source address.
    V6Prefix64(u64),
    /// No source known.
    Unspecified,
}

impl From<IpAddr> for SourceKey {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::V4(v4),
            // IPv4-mapped IPv6 is the same peer as its IPv4 form.
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map_or_else(|| Self::V6Prefix64((v6.to_bits() >> 64) as u64), Self::V4),
        }
    }
}

/// Validated keys are shared: a cache hit clones an `Arc`, not the
/// `TNAuthList` scope.
type Outcome = Result<Arc<VerifiedKey>, FetchError>;

/// A sharded LRU: each shard has its own lock and `cap / shards` entries,
/// so the total never exceeds `cap`.
struct Store<V> {
    hasher: std::collections::hash_map::RandomState,
    shards: Box<[Mutex<Lru<V>>]>,
}

impl<V: Clone> Store<V> {
    fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        let n = cap.min(MAX_SHARDS);
        // The remainder goes one each to the first shards, so the shard
        // capacities sum to exactly `cap`.
        let (base, extra) = (cap / n, cap % n);
        Self {
            hasher: std::collections::hash_map::RandomState::new(),
            shards: (0..n)
                .map(|i| Mutex::new(Lru::new(base + usize::from(i < extra))))
                .collect(),
        }
    }

    fn shard(&self, key: &str) -> Option<&Mutex<Lru<V>>> {
        let n = self.shards.len().max(1);
        let h = usize::try_from(self.hasher.hash_one(key) % n as u64).unwrap_or(0);
        self.shards.get(h)
    }

    fn get(&self, key: &str, now: u64) -> Option<V> {
        self.shard(key)?.lock().ok()?.get(key, now)
    }

    /// Inserts when `keep()` holds, checked under the shard lock so a
    /// concurrent [`Store::clear`] either sees the entry or `keep` sees
    /// what preceded the clear. Returns whether it was inserted.
    fn insert_if(&self, key: &str, val: V, expires: u64, keep: impl FnOnce() -> bool) -> bool {
        let Some(mut s) = self.shard(key).and_then(|s| s.lock().ok()) else {
            return false;
        };
        if !keep() {
            return false;
        }
        s.insert(key, val, expires);
        true
    }

    #[cfg(test)]
    fn capacity(&self) -> usize {
        self.shards
            .iter()
            .filter_map(|s| s.lock().ok().map(|l| l.cap()))
            .sum()
    }

    fn remove(&self, key: &str) {
        if let Some(mut s) = self.shard(key).and_then(|s| s.lock().ok()) {
            s.remove(key);
        }
    }

    fn len(&self) -> usize {
        self.shards
            .iter()
            .filter_map(|s| s.lock().ok().map(|l| l.len()))
            .sum()
    }

    fn clear(&self) {
        for s in &self.shards {
            if let Ok(mut l) = s.lock() {
                l.clear();
            }
        }
    }
}

/// Counters for status/metrics.
#[derive(Debug, Default)]
pub struct CacheStats {
    /// Cache hits (positive).
    pub hits: AtomicU64,
    /// Negative-cache hits.
    pub negative_hits: AtomicU64,
    /// Fetches started.
    pub fetches: AtomicU64,
    /// Fetches refused (busy).
    pub busy: AtomicU64,
    /// Fetches refused because the source's budget was spent (also
    /// counted in `busy`).
    pub busy_source: AtomicU64,
    /// Fetch results dropped because the anchors changed meanwhile.
    pub stale_results: AtomicU64,
}

/// Clock in Unix seconds (injectable for tests).
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

#[derive(Default)]
struct Inflight {
    /// Single-flight waiters by URL.
    urls: HashMap<String, watch::Receiver<Option<Outcome>>>,
    /// Running fetches by host (bounded by the global permit count).
    hosts: HashMap<String, usize>,
    /// Running fetches by source (bounded by the global permit count;
    /// entries removed at zero).
    sources: HashMap<SourceKey, usize>,
}

impl Inflight {
    fn release(&mut self, host: &str, source: SourceKey) {
        if let Some(n) = self.hosts.get_mut(host) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.hosts.remove(host);
            }
        }
        if let Some(n) = self.sources.get_mut(&source) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.sources.remove(&source);
            }
        }
    }
}

/// Releases a running fetch's URL/host/source slots when the fetch task
/// ends, including by panic or runtime shutdown, so counters cannot leak.
struct FetchSlot {
    cache: Arc<StiCertCache>,
    key: String,
    host: String,
    source: SourceKey,
    generation: u64,
}

impl Drop for FetchSlot {
    fn drop(&mut self) {
        if let Ok(mut m) = self.cache.inflight.lock() {
            // A newer generation may own this URL's slot now.
            if self.cache.generation() == self.generation {
                m.urls.remove(&self.key);
            }
            m.release(&self.host, self.source);
        }
    }
}

/// The STI certificate cache.
pub struct StiCertCache {
    cfg: CacheConfig,
    source: Arc<dyn CertSource>,
    anchors: Arc<AnchorStore>,
    positive: Store<Arc<VerifiedKey>>,
    negative: Store<FetchError>,
    inflight: Mutex<Inflight>,
    sem: Arc<Semaphore>,
    generation: AtomicU64,
    clock: Clock,
    /// Counters.
    pub stats: CacheStats,
}

impl std::fmt::Debug for StiCertCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StiCertCache")
            .field("cfg", &self.cfg)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

/// Current Unix time in seconds.
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl StiCertCache {
    /// Creates a cache.
    #[must_use]
    pub fn new(
        cfg: CacheConfig,
        source: Arc<dyn CertSource>,
        anchors: Arc<AnchorStore>,
    ) -> Arc<Self> {
        Self::with_clock(cfg, source, anchors, Arc::new(unix_now))
    }

    /// Creates a cache with an explicit clock.
    #[must_use]
    pub fn with_clock(
        cfg: CacheConfig,
        source: Arc<dyn CertSource>,
        anchors: Arc<AnchorStore>,
        clock: Clock,
    ) -> Arc<Self> {
        let permits = cfg.max_concurrent_fetches.max(1);
        let positive = Store::new(cfg.entries);
        let negative = Store::new((cfg.entries / 4).max(1));
        Arc::new(Self {
            cfg,
            source,
            anchors,
            positive,
            negative,
            inflight: Mutex::new(Inflight::default()),
            sem: Arc::new(Semaphore::new(permits)),
            generation: AtomicU64::new(0),
            clock,
            stats: CacheStats::default(),
        })
    }

    /// Number of cached URLs (positive and negative).
    #[must_use]
    pub fn len(&self) -> usize {
        self.positive.len().saturating_add(self.negative.len())
    }

    /// Number of cached failures.
    #[must_use]
    pub fn negative_len(&self) -> usize {
        self.negative.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Running fetches charged to `source` (0 when idle).
    #[must_use]
    pub fn inflight_for_source(&self, source: IpAddr) -> usize {
        self.inflight.lock().map_or(0, |m| {
            m.sources
                .get(&SourceKey::from(source))
                .copied()
                .unwrap_or(0)
        })
    }

    /// Distinct sources with a running fetch.
    #[must_use]
    pub fn inflight_sources(&self) -> usize {
        self.inflight.lock().map_or(0, |m| m.sources.len())
    }

    /// Fetches in flight.
    #[must_use]
    pub fn inflight(&self) -> usize {
        self.inflight.lock().map_or(0, |m| m.urls.len())
    }

    /// The trust-anchor store (for reload).
    #[must_use]
    pub const fn anchors(&self) -> &Arc<AnchorStore> {
        &self.anchors
    }

    /// Current anchor generation.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Call after the anchor set changed: drops every cached entry and
    /// bumps the generation so fetches that started under the old anchors
    /// cannot store their results; new lookups re-validate.
    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut m) = self.inflight.lock() {
            // Waiters already attached keep their receiver; new callers
            // start a fresh fetch under the new generation.
            m.urls.clear();
        }
        self.clear();
    }

    /// Drops every cached entry.
    pub fn clear(&self) {
        self.positive.clear();
        self.negative.clear();
    }

    fn lookup(&self, x5u: &str) -> Option<Outcome> {
        let now = (self.clock)();
        if let Some(k) = self.positive.get(x5u, now) {
            return Some(Ok(k));
        }
        self.negative.get(x5u, now).map(Err)
    }

    /// Stores a fetch result unless the anchor generation moved on since
    /// the fetch began. The generation is re-checked under the shard lock:
    /// [`Self::invalidate`] bumps it before clearing, so a result validated
    /// under removed anchors can never outlive the clear (SEC-010).
    /// Returns false when the result is stale.
    fn store(&self, x5u: &str, outcome: &Outcome, ttl: u64, generation: u64) -> bool {
        let current = || self.generation() == generation;
        let expires = (self.clock)().saturating_add(ttl);
        let stored = current()
            && match outcome {
                Ok(k) => {
                    self.negative.remove(x5u);
                    self.positive
                        .insert_if(x5u, Arc::clone(k), expires, current)
                }
                Err(e) => {
                    self.positive.remove(x5u);
                    self.negative.insert_if(x5u, e.clone(), expires, current)
                }
            };
        if !stored && !current() {
            self.stats.stale_results.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// [`Self::get_or_fetch_from`] for a caller without a SIP source; such
    /// fetches share the [`SourceKey::Unspecified`] budget, so all callers
    /// of this method together get at most `max_fetches_per_source`
    /// concurrent new fetches (default 4), not `max_concurrent_fetches`;
    /// excess callers get `Busy`. Bulk callers (warm-up, prefetch) should
    /// use [`Self::get_or_fetch_from`] with a distinct source.
    ///
    /// # Errors
    /// See [`Self::get_or_fetch_from`].
    pub async fn get_or_fetch(self: &Arc<Self>, x5u: &str, deadline: Duration) -> Outcome {
        self.get_or_fetch_keyed(SourceKey::Unspecified, x5u, deadline)
            .await
    }

    /// Returns the validated key for `x5u`, fetching it if needed. A new
    /// fetch is charged to `source` (see [`SourceKey`]); past
    /// `max_fetches_per_source` it fails fast with [`FetchError::Busy`].
    /// Waits at most `deadline`; on expiry returns [`FetchError::Timeout`]
    /// while the fetch continues in the background.
    ///
    /// ## NIST 800-53 Rev5: SC-5 (POA&M-190)
    ///
    /// # Errors
    /// The (possibly negative-cached) fetch/validation failure.
    pub async fn get_or_fetch_from(
        self: &Arc<Self>,
        source: IpAddr,
        x5u: &str,
        deadline: Duration,
    ) -> Outcome {
        self.get_or_fetch_keyed(SourceKey::from(source), x5u, deadline)
            .await
    }

    fn per_source_limit(&self) -> usize {
        self.cfg
            .max_fetches_per_source
            .clamp(1, self.cfg.max_concurrent_fetches.max(1))
    }

    async fn get_or_fetch_keyed(
        self: &Arc<Self>,
        source: SourceKey,
        x5u: &str,
        deadline: Duration,
    ) -> Outcome {
        if let Some(o) = self.lookup(x5u) {
            let counter = if o.is_ok() {
                &self.stats.hits
            } else {
                &self.stats.negative_hits
            };
            counter.fetch_add(1, Ordering::Relaxed);
            return o;
        }
        // Policy refusals are not cached: re-checking is cheaper than a
        // cache slot an attacker could fill with unique bad URLs.
        let url = X5uUrl::parse(x5u, &self.cfg.allow_hosts)?;

        let mut rx = {
            let Ok(mut inflight) = self.inflight.lock() else {
                return Err(FetchError::Busy);
            };
            if let Some(rx) = inflight.urls.get(x5u) {
                rx.clone()
            } else if let Some(o) = self.lookup(x5u) {
                // Filled between the first lookup and taking `inflight`.
                return o;
            } else {
                let per_host = inflight.hosts.get(&url.host).copied().unwrap_or(0);
                if per_host >= MAX_FETCHES_PER_HOST {
                    self.stats.busy.fetch_add(1, Ordering::Relaxed);
                    return Err(FetchError::Busy);
                }
                let per_source = inflight.sources.get(&source).copied().unwrap_or(0);
                if per_source >= self.per_source_limit() {
                    self.stats.busy.fetch_add(1, Ordering::Relaxed);
                    self.stats.busy_source.fetch_add(1, Ordering::Relaxed);
                    return Err(FetchError::Busy);
                }
                let Ok(permit) = Arc::clone(&self.sem).try_acquire_owned() else {
                    self.stats.busy.fetch_add(1, Ordering::Relaxed);
                    return Err(FetchError::Busy);
                };
                let (tx, rx) = watch::channel(None);
                inflight.urls.insert(x5u.to_owned(), rx.clone());
                *inflight.hosts.entry(url.host.clone()).or_insert(0) += 1;
                *inflight.sources.entry(source).or_insert(0) += 1;
                self.stats.fetches.fetch_add(1, Ordering::Relaxed);
                let generation = self.generation();
                let slot = FetchSlot {
                    cache: Arc::clone(self),
                    key: x5u.to_owned(),
                    host: url.host.clone(),
                    source,
                    generation,
                };
                tokio::spawn(async move {
                    let this = &slot.cache;
                    let (outcome, ttl) = this.fetch_and_validate(&url).await;
                    // Waiters on a fetch that straddled an anchor change get
                    // a failure, never a key validated under the old set.
                    let outcome = if this.store(&slot.key, &outcome, ttl, generation) {
                        outcome
                    } else {
                        Err(FetchError::Untrusted("anchors-changed"))
                    };
                    // Release slots before waking waiters (they may retry).
                    drop(slot);
                    let _ = tx.send(Some(outcome));
                    drop(permit);
                });
                rx
            }
        };

        let wait = async {
            loop {
                let current = rx.borrow_and_update().clone();
                if let Some(o) = current {
                    return o;
                }
                if rx.changed().await.is_err() {
                    return Err(FetchError::Transport("fetch-task-ended"));
                }
            }
        };
        tokio::time::timeout(deadline, wait)
            .await
            .unwrap_or(Err(FetchError::Timeout))
    }

    async fn fetch_and_validate(&self, url: &X5uUrl) -> (Outcome, u64) {
        let neg = self.cfg.negative_ttl_secs;
        let fetched = match self.source.fetch(url, self.cfg.fetch_timeout).await {
            Ok(f) => f,
            Err(e) => return (Err(e), neg),
        };
        let now = (self.clock)();
        let certs = match uc_crypto::x509::pem_certificates(&fetched.body) {
            Ok(c) if !c.is_empty() && c.len() <= MAX_CHAIN_CERTS => c,
            _ => return (Err(FetchError::Untrusted("chain-format")), neg),
        };
        let Some((ee, inter)) = certs.split_first() else {
            return (Err(FetchError::Untrusted("chain-format")), neg);
        };
        let anchors = self.anchors.current();
        let sti = match uc_crypto::x509::verify_sti_chain(&anchors.set, ee, inter, now) {
            Ok(s) => s,
            Err(uc_crypto::CryptoError::CertificateInvalid(r)) => {
                return (Err(FetchError::Untrusted(r)), neg);
            }
            Err(_) => return (Err(FetchError::Untrusted("chain-invalid")), neg),
        };
        // ATIS-1000080 §5.3: STI end-entity certificates carry TNAuthList.
        if sti.tn_auth.is_empty() {
            return (Err(FetchError::Untrusted("missing-tnauthlist")), neg);
        }
        let ttl = fetched
            .max_age_secs
            .map_or(self.cfg.ttl_secs, |m| m.min(self.cfg.ttl_secs))
            .min(sti.not_after.saturating_sub(now));
        let tn_auth = TnAuthScope {
            entries: sti
                .tn_auth
                .iter()
                .map(|e| match e {
                    uc_crypto::x509::TnAuthEntry::Spc(s) => TnAuthEntry::Spc(s.clone()),
                    uc_crypto::x509::TnAuthEntry::One(s) => TnAuthEntry::One(s.clone()),
                    uc_crypto::x509::TnAuthEntry::Range { start, count } => TnAuthEntry::Range {
                        start: start.clone(),
                        count: *count,
                    },
                })
                .collect(),
        };
        let key = Arc::new(VerifiedKey {
            key: Arc::new(P256Key(sti.public_key)),
            tn_auth,
            not_after: sti.not_after,
        });
        (Ok(key), ttl)
    }
}

impl KeyResolver for StiCertCache {
    fn cached(&self, x5u: &str) -> Option<Arc<VerifiedKey>> {
        self.lookup(x5u).and_then(Result::ok)
    }
}

/// A chain-validated P-256 public key.
///
/// CNSA-EXCEPTION: ATIS-1000074 mandates ES256.
#[derive(Debug)]
pub struct P256Key(pub Vec<u8>);

impl VerifyingKey for P256Key {
    fn alg(&self) -> Alg {
        Alg::Es256
    }

    fn verify(&self, input: &[u8], signature: &[u8]) -> bool {
        // CNSA-EXCEPTION: ATIS-1000074 mandates ES256 for SHAKEN.
        uc_crypto::interop::ecdsa_p256::verify(&self.0, input, signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PERF-011: shard capacities sum to exactly the configured total.
    #[test]
    fn shard_capacity_distributes_remainder() {
        for cap in [1, 15, 16, 17, 31, 100, 4096, 4097] {
            assert_eq!(Store::<u32>::new(cap).capacity(), cap, "cap {cap}");
        }
    }

    /// SEC-010: the keep check runs under the shard lock, and a failed
    /// check inserts nothing.
    #[test]
    fn insert_if_respects_keep() {
        let s = Store::<u32>::new(4);
        assert!(!s.insert_if("a", 1, 100, || false));
        assert_eq!(s.get("a", 0), None);
        assert!(s.insert_if("a", 1, 100, || true));
        assert_eq!(s.get("a", 0), Some(1));
    }

    /// QA (POA&M-190): source keying. Same IPv6 /64 shares a key, a
    /// different /64 does not; IPv4-mapped IPv6 equals its IPv4 form;
    /// Unspecified never collides with a real address.
    #[test]
    fn qa_source_key_mapping() {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let k = |s: &str| SourceKey::from(s.parse::<IpAddr>().unwrap());
        assert_eq!(k("2001:db8:1:2::1"), k("2001:db8:1:2:ffff:ffff:ffff:ffff"));
        assert_ne!(k("2001:db8:1:2::1"), k("2001:db8:1:3::1"));
        assert_eq!(k("::ffff:192.0.2.7"), k("192.0.2.7"));
        assert_eq!(
            k("::ffff:192.0.2.7"),
            SourceKey::V4(Ipv4Addr::new(192, 0, 2, 7))
        );
        assert_ne!(k("192.0.2.7"), k("192.0.2.8"));
        assert_eq!(
            SourceKey::from(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))),
            SourceKey::V6Prefix64(0x2001_0db8_0000_0000)
        );
        assert_ne!(k("0.0.0.0"), SourceKey::Unspecified);
        assert_ne!(k("::"), SourceKey::Unspecified);
    }
}
