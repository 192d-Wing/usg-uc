//! Per-source and aggregate stream connection caps.
//!
//! One source (an IPv4 address, or an IPv6 prefix of
//! `rate_limit.ipv6_prefix_len` bits) may hold at most
//! `transport.max_connections_per_source` accepted stream connections across
//! all TCP, TLS and WebSocket listeners. Without it one host can take the
//! whole listener pool with idle sockets.
//!
//! When aggregate caps are configured (`with_aggregate_caps`), every
//! connection also counts against a wider aggregate: the IPv6
//! `transport.v6_aggregate_prefix_len` prefix (default /48) or the IPv4 /24
//! (6to4 `2002::/16` and NAT64 `64:ff9b::/96` sources count in the /24 of
//! their embedded IPv4 address). Without it one delegated /56 or /48
//! rotates through its /64s and takes whole pools (SR-58). Configured trunk
//! addresses ([`ConnLimiter::set_trusted_sources`]) skip the aggregate level;
//! their per-source caps still apply.
//!
//! It also holds accept-time admission state shared by the listeners: an
//! optional per-source accept token bucket
//! (`transport.accept_rate_per_source`), an aggregate accept bucket of 16
//! times that rate and burst, and caps on handshakes in progress per source
//! (`transport.max_handshakes_per_source`) and per aggregate.
//!
//! The critical sections are O(1), never span an `.await`, and run only on
//! accept, handshake end and close, so `std::sync::Mutex` is used. The
//! accept buckets have their own lock, and the trusted set its own
//! read-mostly lock; no path holds two of these locks at once.
//!
//! ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection), SC-7

// POAM: POA&M-454 — rotation across many aggregates is bounded only by the
// listener and node pools: about max_connections_per_listener /
// max_connections_per_v6_aggregate distinct /48s (10 at the defaults, 6
// under the Helm caps) fill one listener pool. There is no cross-aggregate
// or adaptive bound (e.g. a /32 level); the trunk reserve is POA&M-453
// (SC-5).

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use tracing::warn;
use uc_dos_protection::{MAX_TRUSTED_SOURCES, RateLimiter, RateLimiterConfig};

/// Distinct sources whose connection rejections are tracked between audit
/// flushes; rejections from further sources are summed without a key.
const MAX_REJECTED_SOURCES: usize = 4_096;

/// The aggregate accept bucket's rate and burst, as multiples of the
/// per-source values (SR-58).
pub const AGGREGATE_ACCEPT_FACTOR: u32 = 16;

/// Which cap a count belongs to. Tags the map key, since a /48 aggregate
/// key (`2001:db8:1::`) can equal a /64 source key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Level {
    /// The per-source key (IPv4 address or IPv6 `ipv6_prefix_len` prefix).
    Source,
    /// The aggregate key (IPv6 `v6_aggregate_prefix_len` prefix or IPv4 /24).
    Aggregate,
    /// A trusted WebSocket reverse proxy (exact address), for its
    /// pre-handshake cap (SR-59).
    Proxy,
}

#[derive(Debug, Default)]
struct Inner {
    /// Live connections per (level, key). An entry exists only while the
    /// key holds a connection, so the map is bounded by twice the
    /// connection pools.
    active: HashMap<(Level, IpAddr), u32>,
    /// Handshakes in progress per (level, key), plus trusted-proxy
    /// pre-handshake slots ([`Level::Proxy`]). An entry exists only while a
    /// handshake runs, and each runs under a pool permit, so the map is
    /// bounded by three times the connection pools.
    handshakes: HashMap<(Level, IpAddr), u32>,
    /// Rejections per (key, kind) since the last drain.
    rejected: HashMap<(IpAddr, Rejection), u64>,
    /// Rejections from keys past `MAX_REJECTED_SOURCES`.
    rejected_untracked: u64,
}

/// Why a stream connection (or its message) was rejected, for the
/// aggregated audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rejection {
    /// The source was at `max_connections_per_source`.
    PerSource,
    /// The source's IPv6 aggregate prefix or IPv4 /24 was at its aggregate
    /// cap (SR-58).
    PerAggregate,
    /// The stream carried invalid Content-Length framing (SI-10).
    Framing,
    /// The source was over `accept_rate_per_source`.
    AcceptRate,
    /// The source's aggregate was over its accept rate
    /// (`accept_rate_per_source` x [`AGGREGATE_ACCEPT_FACTOR`], SR-58).
    AggregateAcceptRate,
    /// The source was at `max_handshakes_per_source`.
    HandshakeBusy,
    /// The source's aggregate was at its handshake cap (SR-58).
    AggregateHandshakeBusy,
    /// The source is blocked by the per-source rate limiter; the accept
    /// was dropped before any handshake.
    AcceptBlocked,
    /// A trusted WebSocket proxy was at `ws_max_handshakes_per_proxy`
    /// (keyed on the proxy, SR-59).
    ProxyHandshakeBusy,
    /// A trusted WebSocket proxy sent no, or an unusable, client address
    /// (keyed on the proxy, SR-59).
    ProxyHeader,
}

/// Totals drained by [`ConnLimiter::drain_rejections`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DrainedTotals {
    /// Per-source rejections from sources past the tracking cap.
    pub untracked: u64,
    /// Accepts dropped because a listener pool was full.
    pub listener_full: u64,
    /// Accepts dropped because the node-wide pool was full.
    pub total_full: u64,
}

/// The accept buckets, under one lock so both are charged in one critical
/// section. `RateLimiter`s that never block, reused for their bounded
/// bucket maps, overflow buckets and idle sweep.
#[derive(Debug)]
struct AcceptBuckets {
    /// Keyed per source.
    source: RateLimiter,
    /// Keyed per aggregate; charged only for keys whose aggregate level
    /// is on.
    aggregate: RateLimiter,
}

/// Per-source and aggregate connection limiter shared by all stream
/// listeners.
#[derive(Debug)]
pub struct ConnLimiter {
    inner: Mutex<Inner>,
    /// Accepts dropped on a full listener pool since the last drain.
    listener_full: AtomicU64,
    /// Accepts dropped on the full node-wide pool since the last drain.
    total_full: AtomicU64,
    max_per_source: u32,
    v6_prefix_len: u8,
    /// IPv6 aggregate prefix length (never longer than `v6_prefix_len`).
    v6_aggregate_prefix_len: u8,
    /// Connections per IPv6 aggregate; 0 = off.
    v6_aggregate_cap: u32,
    /// Connections per IPv4 /24; 0 = off.
    v4_aggregate_cap: u32,
    /// Accept buckets; `None` when the accept rate is off.
    accept: Option<Mutex<AcceptBuckets>>,
    /// Aggregate accept rate per second (0 when the accept rate is off).
    aggregate_accept_rate: u32,
    /// Handshakes in progress allowed per source.
    max_handshakes_per_source: u32,
    /// Handshakes in progress allowed per aggregate.
    max_handshakes_per_aggregate: u32,
    /// Connections from one trusted WebSocket proxy allowed before their
    /// client is known (SR-59).
    max_handshakes_per_proxy: u32,
    /// Configured trunk addresses (canonical), exempt from the aggregate
    /// level. At most [`MAX_TRUSTED_SOURCES`] entries.
    trusted: RwLock<HashSet<IpAddr>>,
}

/// Holds one handshake slot for a source (and its aggregate); released on
/// drop (including on panic or task abort).
#[derive(Debug)]
pub struct HandshakeGuard {
    limiter: Arc<ConnLimiter>,
    key: IpAddr,
    /// Aggregate key also charged, if that level applied.
    aggregate: Option<IpAddr>,
}

/// Holds one pre-handshake slot of a trusted WebSocket proxy; released on
/// drop (including on panic or task abort).
#[derive(Debug)]
pub struct ProxyHandshakeGuard {
    limiter: Arc<ConnLimiter>,
    key: IpAddr,
}

/// Holds one connection slot for a source (and its aggregate); released on
/// drop (including on panic or task abort).
#[derive(Debug)]
pub struct ConnGuard {
    limiter: Arc<ConnLimiter>,
    key: IpAddr,
    /// Aggregate key also charged, if that level applied.
    aggregate: Option<IpAddr>,
}

/// Takes one unit of `key` in `map` if its count is below `cap`; returns
/// whether it did. One hash lookup.
fn take(map: &mut HashMap<(Level, IpAddr), u32>, key: (Level, IpAddr), cap: u32) -> bool {
    match map.entry(key) {
        Entry::Occupied(mut e) if *e.get() < cap => {
            *e.get_mut() += 1;
            true
        }
        Entry::Occupied(_) => false,
        Entry::Vacant(e) if cap > 0 => {
            e.insert(1);
            true
        }
        Entry::Vacant(_) => false,
    }
}

/// Returns one unit of `key` in `map`, removing the entry at zero. One
/// hash lookup.
fn release(map: &mut HashMap<(Level, IpAddr), u32>, key: (Level, IpAddr)) {
    if let Entry::Occupied(mut e) = map.entry(key) {
        if *e.get() <= 1 {
            e.remove();
        } else {
            *e.get_mut() -= 1;
        }
    }
}

/// The IPv4 address embedded in a 6to4 (`2002::/16`, RFC 3056) or NAT64
/// well-known-prefix (`64:ff9b::/96`, RFC 6052) address.
fn embedded_v4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = v6.segments();
    if s[0] == 0x2002 {
        return Some(Ipv4Addr::from((u32::from(s[1]) << 16) | u32::from(s[2])));
    }
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return Some(Ipv4Addr::from((u32::from(s[6]) << 16) | u32::from(s[7])));
    }
    None
}

impl ConnLimiter {
    /// Creates a limiter allowing `max_per_source` connections per source.
    /// Aggregate caps are off until [`Self::with_aggregate_caps`].
    pub fn new(max_per_source: u32, v6_prefix_len: u8) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            listener_full: AtomicU64::new(0),
            total_full: AtomicU64::new(0),
            max_per_source: max_per_source.max(1),
            v6_prefix_len,
            v6_aggregate_prefix_len: v6_prefix_len,
            v6_aggregate_cap: 0,
            v4_aggregate_cap: 0,
            accept: None,
            aggregate_accept_rate: 0,
            max_handshakes_per_source: u32::MAX,
            max_handshakes_per_aggregate: u32::MAX,
            max_handshakes_per_proxy: u32::MAX,
            trusted: RwLock::new(HashSet::new()),
        }
    }

    /// Also caps connections per IPv6 `v6_prefix`-bit aggregate (clamped to
    /// the per-source prefix) at `v6_cap`, and per IPv4 /24 at `v4_cap`.
    /// A cap of 0 turns that level off, including its accept bucket and
    /// handshake cap. A cap below the per-source cap is honoured.
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7
    // POAM: POA&M-455 — the caps are static per prefix: no shrinking under
    // attack and no per-prefix override for large sites (SC-5).
    #[must_use]
    pub fn with_aggregate_caps(mut self, v6_prefix: u8, v6_cap: u32, v4_cap: u32) -> Self {
        self.v6_aggregate_prefix_len = v6_prefix.min(self.v6_prefix_len);
        self.v6_aggregate_cap = v6_cap;
        self.v4_aggregate_cap = v4_cap;
        self
    }

    /// Adds the accept buckets: per source, `rate` new connections per
    /// second and `burst` at once; per aggregate,
    /// [`AGGREGATE_ACCEPT_FACTOR`] times both. At most `max_tracked` keys
    /// (at least 1) per bucket map get their own bucket; further keys share
    /// one overflow bucket of `4 *` that map's rate with its burst, so a
    /// key past the tracking cap cannot outpace its rate by more than four
    /// times. `rate` 0 leaves the buckets off.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    #[must_use]
    pub fn with_accept_rate(mut self, rate: u32, burst: u32, max_tracked: usize) -> Self {
        let bucket = |rate: u32, burst: u32| {
            let burst = burst.max(1);
            let config = RateLimiterConfig::new(rate, burst)
                .with_per_ip(true)
                // Aggregate keys are already masked to at most this length,
                // so re-keying them is a no-op.
                .with_ipv6_prefix_len(self.v6_prefix_len)
                .with_max_tracked_sources(max_tracked.max(1))
                .with_overflow(rate.saturating_mul(4), burst)
                // Never blocks: an over-rate accept is dropped, nothing more.
                .with_block_threshold(f64::INFINITY)
                .with_max_blocked_sources(0);
            RateLimiter::new(config)
        };
        let aggregate_rate = rate.saturating_mul(AGGREGATE_ACCEPT_FACTOR);
        self.accept = (rate > 0).then(|| {
            Mutex::new(AcceptBuckets {
                source: bucket(rate, burst),
                aggregate: bucket(
                    aggregate_rate,
                    burst.saturating_mul(AGGREGATE_ACCEPT_FACTOR),
                ),
            })
        });
        self.aggregate_accept_rate = if rate > 0 { aggregate_rate } else { 0 };
        self
    }

    /// Caps handshakes in progress per source at `per_source` (at least 1).
    #[must_use]
    pub fn with_handshake_cap(mut self, per_source: u32) -> Self {
        self.max_handshakes_per_source = per_source.max(1);
        self
    }

    /// Caps handshakes in progress per aggregate at `per_aggregate` (at
    /// least 1), for aggregates whose level is on (SR-58).
    ///
    /// ## NIST 800-53 Rev5: SC-5
    #[must_use]
    pub fn with_aggregate_handshake_cap(mut self, per_aggregate: u32) -> Self {
        self.max_handshakes_per_aggregate = per_aggregate.max(1);
        self
    }

    /// Caps the connections one trusted WebSocket proxy may hold before
    /// their client address is known (`transport.ws_max_handshakes_per_proxy`,
    /// at least 1; SR-59).
    ///
    /// ## NIST 800-53 Rev5: SC-5
    #[must_use]
    pub fn with_proxy_handshake_cap(mut self, per_proxy: u32) -> Self {
        self.max_handshakes_per_proxy = per_proxy.max(1);
        self
    }

    /// Replaces the configured trunk addresses that skip the aggregate
    /// level (SR-58). Stored in canonical form, at most
    /// [`MAX_TRUSTED_SOURCES`]; returns how many were kept. Connections
    /// already held keep releasing what they took.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    pub fn set_trusted_sources(&self, ips: impl IntoIterator<Item = IpAddr>) -> usize {
        let set: HashSet<IpAddr> = ips
            .into_iter()
            .map(|ip| ip.to_canonical())
            .take(MAX_TRUSTED_SOURCES)
            .collect();
        let kept = set.len();
        *self
            .trusted
            .write()
            .unwrap_or_else(|poisoned: PoisonError<_>| {
                warn!("Connection limiter trusted set poisoned; recovering");
                poisoned.into_inner()
            }) = set;
        kept
    }

    /// Whether `ip` is a configured trunk address (exempt from the
    /// aggregate level).
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.trusted
            .read()
            .unwrap_or_else(|poisoned: PoisonError<_>| {
                warn!("Connection limiter trusted set poisoned; recovering");
                poisoned.into_inner()
            })
            .contains(&ip)
    }

    /// Connections allowed per IPv6 aggregate (0 = off).
    pub fn v6_aggregate_cap(&self) -> u32 {
        self.v6_aggregate_cap
    }

    /// Connections allowed per IPv4 /24 (0 = off).
    pub fn v4_aggregate_cap(&self) -> u32 {
        self.v4_aggregate_cap
    }

    /// New connections allowed per aggregate per second (0 = off).
    pub fn aggregate_accept_rate(&self) -> u32 {
        self.aggregate_accept_rate
    }

    /// Handshakes in progress allowed per aggregate.
    pub fn max_handshakes_per_aggregate(&self) -> u32 {
        self.max_handshakes_per_aggregate
    }

    /// The aggregate key and connection cap for `ip`, or `None` when that
    /// family's aggregate level is off or `ip` is a configured trunk.
    /// v4-mapped, 6to4 and NAT64 addresses count in the IPv4 /24.
    fn aggregate_of(&self, ip: IpAddr) -> Option<(IpAddr, u32)> {
        let ip = ip.to_canonical();
        let v4 = match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(v6) => embedded_v4(v6),
        };
        let aggregate = match v4 {
            Some(v4) if self.v4_aggregate_cap > 0 => Some((
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & 0xFFFF_FF00)),
                self.v4_aggregate_cap,
            )),
            Some(_) => None,
            None if self.v6_aggregate_cap > 0 => Some((
                uc_dos_protection::source_key(ip, self.v6_aggregate_prefix_len),
                self.v6_aggregate_cap,
            )),
            None => None,
        };
        // NIST 800-53 Rev5: SC-5 — a co-tenant filling a trunk's /24 or
        // /48 must not lock the trunk out; its per-source caps still apply.
        aggregate.filter(|_| !self.is_trusted(ip))
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned: PoisonError<_>| {
                warn!("Connection limiter lock poisoned; recovering");
                poisoned.into_inner()
            })
    }

    fn lock_accept(accept: &Mutex<AcceptBuckets>) -> MutexGuard<'_, AcceptBuckets> {
        accept.lock().unwrap_or_else(|poisoned: PoisonError<_>| {
            warn!("Accept rate limiter lock poisoned; recovering");
            poisoned.into_inner()
        })
    }

    /// Takes a connection slot for `ip`, or `None` (counted for audit) when
    /// the source or its aggregate is over its accept rate or at its cap.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        self.try_admit(ip).ok()
    }

    /// Like [`Self::try_acquire`], but reports why a connection was
    /// refused. The source's accept bucket is charged first, then its
    /// aggregate's, in one critical section; a bucket reject takes no slot.
    /// A token spent on an accept that a later check (aggregate bucket,
    /// cap, pool, handshake) refuses is not refunded: such a source or
    /// aggregate is at a limit already.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    pub fn try_admit(self: &Arc<Self>, ip: IpAddr) -> Result<ConnGuard, Rejection> {
        let key = uc_dos_protection::source_key(ip, self.v6_prefix_len);
        let aggregate = self.aggregate_of(ip);
        if let Some(accept) = &self.accept {
            // The bucket lock is released before `inner` is taken.
            let rejected = {
                let mut buckets = Self::lock_accept(accept);
                if buckets.source.check(key).is_rejected() {
                    Some((key, Rejection::AcceptRate))
                } else {
                    aggregate
                        .filter(|(agg, _)| buckets.aggregate.check(*agg).is_rejected())
                        .map(|(agg, _)| (agg, Rejection::AggregateAcceptRate))
                }
            };
            if let Some((k, kind)) = rejected {
                Self::count(&mut self.lock(), k, kind);
                return Err(kind);
            }
        }
        self.take_slot(key, aggregate)
    }

    /// Takes a connection slot for source `key` and its aggregate, or
    /// counts a [`Rejection::PerSource`] / [`Rejection::PerAggregate`].
    /// The per-source cap is checked first; a rejection at either level
    /// takes nothing.
    fn take_slot(
        self: &Arc<Self>,
        key: IpAddr,
        aggregate: Option<(IpAddr, u32)>,
    ) -> Result<ConnGuard, Rejection> {
        let mut inner = self.lock();
        if !take(&mut inner.active, (Level::Source, key), self.max_per_source) {
            Self::count(&mut inner, key, Rejection::PerSource);
            return Err(Rejection::PerSource);
        }
        if let Some((agg, cap)) = aggregate
            && !take(&mut inner.active, (Level::Aggregate, agg), cap)
        {
            release(&mut inner.active, (Level::Source, key));
            Self::count(&mut inner, agg, Rejection::PerAggregate);
            return Err(Rejection::PerAggregate);
        }
        drop(inner);
        Ok(ConnGuard {
            limiter: Arc::clone(self),
            key,
            aggregate: aggregate.map(|(k, _)| k),
        })
    }

    /// Takes a handshake slot for `ip`, or `None` (counted for audit) when
    /// the source is at `max_handshakes_per_source` or its aggregate at its
    /// handshake cap. Hold the guard only for the handshake.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    pub fn try_begin_handshake(self: &Arc<Self>, ip: IpAddr) -> Option<HandshakeGuard> {
        self.try_handshake(ip).ok()
    }

    /// Like [`Self::try_begin_handshake`], but reports why
    /// ([`Rejection::HandshakeBusy`] or
    /// [`Rejection::AggregateHandshakeBusy`]). Both levels are taken in one
    /// critical section; a rejection at either takes nothing.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    pub fn try_handshake(self: &Arc<Self>, ip: IpAddr) -> Result<HandshakeGuard, Rejection> {
        let key = uc_dos_protection::source_key(ip, self.v6_prefix_len);
        let aggregate = self.aggregate_of(ip).map(|(k, _)| k);
        let mut inner = self.lock();
        if !take(
            &mut inner.handshakes,
            (Level::Source, key),
            self.max_handshakes_per_source,
        ) {
            Self::count(&mut inner, key, Rejection::HandshakeBusy);
            return Err(Rejection::HandshakeBusy);
        }
        if let Some(agg) = aggregate
            && !take(
                &mut inner.handshakes,
                (Level::Aggregate, agg),
                self.max_handshakes_per_aggregate,
            )
        {
            release(&mut inner.handshakes, (Level::Source, key));
            Self::count(&mut inner, agg, Rejection::AggregateHandshakeBusy);
            return Err(Rejection::AggregateHandshakeBusy);
        }
        drop(inner);
        Ok(HandshakeGuard {
            limiter: Arc::clone(self),
            key,
            aggregate,
        })
    }

    /// Takes one pre-handshake slot for trusted WebSocket proxy `proxy`
    /// (its exact canonical address), or `None` (counted as
    /// [`Rejection::ProxyHandshakeBusy`] under the proxy) when it already
    /// holds `max_handshakes_per_proxy`. Hold the guard until the client
    /// address is known and admitted, or the handshake ends. Entries live
    /// only while a slot is held, each under a pool permit, so the map stays
    /// bounded by the connection pools.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    pub fn try_proxy_handshake(self: &Arc<Self>, proxy: IpAddr) -> Option<ProxyHandshakeGuard> {
        let key = proxy.to_canonical();
        let mut inner = self.lock();
        if !take(
            &mut inner.handshakes,
            (Level::Proxy, key),
            self.max_handshakes_per_proxy,
        ) {
            Self::count(&mut inner, key, Rejection::ProxyHandshakeBusy);
            return None;
        }
        drop(inner);
        Some(ProxyHandshakeGuard {
            limiter: Arc::clone(self),
            key,
        })
    }

    /// Pre-handshake connections from one trusted proxy allowed.
    pub fn max_handshakes_per_proxy(&self) -> u32 {
        self.max_handshakes_per_proxy
    }

    /// Counts a connection from trusted proxy `proxy` refused because it
    /// sent no, or an unusable, client address; aggregated per flush under
    /// the proxy's address (`ws_proxy_header`).
    ///
    /// ## NIST 800-53 Rev5: AU-12, SC-7
    pub fn note_proxy_header(&self, proxy: IpAddr) {
        Self::count(
            &mut self.lock(),
            proxy.to_canonical(),
            Rejection::ProxyHeader,
        );
    }

    /// Counts an accept dropped because the source is blocked.
    ///
    /// ## NIST 800-53 Rev5: AU-12, SC-7
    pub fn note_accept_blocked(&self, ip: IpAddr) {
        let key = uc_dos_protection::source_key(ip, self.v6_prefix_len);
        Self::count(&mut self.lock(), key, Rejection::AcceptBlocked);
    }

    /// Accept-bucket maintenance: evicts idle buckets, then reports and
    /// resets `f(key, kind, count)` for accept-rate rejections
    /// ([`Rejection::AcceptRate`], [`Rejection::AggregateAcceptRate`]) not
    /// yet taken by [`Self::drain_rejections`]. Each rejection is reported
    /// once, by whichever call sees it first.
    ///
    /// ## NIST 800-53 Rev5: SC-5, AU-4
    pub fn sweep_accept(&self, mut f: impl FnMut(IpAddr, Rejection, u64)) {
        if let Some(accept) = &self.accept {
            let mut guard = Self::lock_accept(accept);
            let buckets = &mut *guard;
            // Rejections are counted in `Inner`; the buckets' own counters
            // are only reset here.
            for bucket in [&mut buckets.source, &mut buckets.aggregate] {
                let _ = bucket.sweep_with(|_| {});
                let _ = bucket.take_overflow_rejections();
            }
        }
        let mut inner = self.lock();
        inner.rejected.retain(|(key, kind), n| {
            if matches!(kind, Rejection::AcceptRate | Rejection::AggregateAcceptRate) {
                f(*key, *kind, *n);
                false
            } else {
                true
            }
        });
    }

    /// Adds one rejection for `(key, kind)` within the tracking cap.
    fn count(inner: &mut Inner, key: IpAddr, kind: Rejection) {
        if let Some(n) = inner.rejected.get_mut(&(key, kind)) {
            *n = n.saturating_add(1);
        } else if inner.rejected.len() < MAX_REJECTED_SOURCES {
            inner.rejected.insert((key, kind), 1);
        } else {
            inner.rejected_untracked = inner.rejected_untracked.saturating_add(1);
        }
    }

    /// Counts a stream framing rejection from `ip` for the audit aggregate.
    ///
    /// ## NIST 800-53 Rev5: AU-12, SI-10
    pub fn note_framing_error(&self, ip: IpAddr) {
        let key = uc_dos_protection::source_key(ip, self.v6_prefix_len);
        Self::count(&mut self.lock(), key, Rejection::Framing);
    }

    /// Counts an accept dropped because a listener pool was full.
    pub fn note_listener_full(&self) {
        self.listener_full.fetch_add(1, Ordering::Relaxed);
    }

    /// Counts an accept dropped because the node-wide pool was full.
    pub fn note_total_full(&self) {
        self.total_full.fetch_add(1, Ordering::Relaxed);
    }

    /// Reports and resets rejection counts: `f(key, kind, count)` per
    /// tracked (key, kind), and returns the untracked and pool totals.
    pub fn drain_rejections(&self, mut f: impl FnMut(IpAddr, Rejection, u64)) -> DrainedTotals {
        let mut inner = self.lock();
        for ((key, kind), n) in inner.rejected.drain() {
            f(key, kind, n);
        }
        DrainedTotals {
            untracked: std::mem::take(&mut inner.rejected_untracked),
            listener_full: self.listener_full.swap(0, Ordering::Relaxed),
            total_full: self.total_full.swap(0, Ordering::Relaxed),
        }
    }

    /// Live connections held by the source of `ip`.
    #[cfg(test)]
    pub fn active(&self, ip: IpAddr) -> u32 {
        let key = uc_dos_protection::source_key(ip, self.v6_prefix_len);
        self.lock()
            .active
            .get(&(Level::Source, key))
            .copied()
            .unwrap_or(0)
    }

    /// Live connections counted against the aggregate of `ip` (0 when the
    /// level does not apply to it).
    #[cfg(test)]
    pub fn aggregate_active(&self, ip: IpAddr) -> u32 {
        let Some((key, _)) = self.aggregate_of(ip) else {
            return 0;
        };
        self.lock()
            .active
            .get(&(Level::Aggregate, key))
            .copied()
            .unwrap_or(0)
    }

    /// Number of keys (sources and aggregates) holding at least one
    /// connection.
    #[cfg(test)]
    pub fn sources(&self) -> usize {
        self.lock().active.len()
    }
}

impl Drop for HandshakeGuard {
    fn drop(&mut self) {
        let mut inner = self.limiter.lock();
        release(&mut inner.handshakes, (Level::Source, self.key));
        if let Some(agg) = self.aggregate {
            release(&mut inner.handshakes, (Level::Aggregate, agg));
        }
    }
}

impl Drop for ProxyHandshakeGuard {
    fn drop(&mut self) {
        release(
            &mut self.limiter.lock().handshakes,
            (Level::Proxy, self.key),
        );
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut inner = self.limiter.lock();
        release(&mut inner.active, (Level::Source, self.key));
        if let Some(agg) = self.aggregate {
            release(&mut inner.active, (Level::Aggregate, agg));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn conn_limiter_caps_per_source_and_releases_on_drop() {
        let limiter = Arc::new(ConnLimiter::new(2, 64));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        let g1 = limiter.try_acquire(a).unwrap();
        let g2 = limiter.try_acquire(a).unwrap();
        assert!(limiter.try_acquire(a).is_none());
        // Another source is unaffected.
        let gb = limiter.try_acquire(b).unwrap();
        drop(g1);
        let g3 = limiter.try_acquire(a).unwrap();
        drop((g2, g3, gb));
        assert_eq!(limiter.sources(), 0);
        let mut seen = Vec::new();
        assert_eq!(
            limiter
                .drain_rejections(|k, _, n| seen.push((k, n)))
                .untracked,
            0
        );
        assert_eq!(seen, vec![(a, 1)]);
    }

    #[test]
    fn conn_limiter_keys_v6_by_prefix() {
        let limiter = Arc::new(ConnLimiter::new(1, 64));
        let a: IpAddr = "2001:db8:0:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:0:1::2".parse().unwrap();
        let c: IpAddr = "2001:db8:0:2::1".parse().unwrap();
        let _g = limiter.try_acquire(a).unwrap();
        assert!(limiter.try_acquire(b).is_none());
        assert!(limiter.try_acquire(c).is_some());
        // v4-mapped and plain v4 are the same source.
        let v4: IpAddr = "192.0.2.9".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.9".parse().unwrap();
        let _g4 = limiter.try_acquire(v4).unwrap();
        assert!(limiter.try_acquire(mapped).is_none());
        assert_eq!(limiter.active(mapped), 1);
    }

    // QA: the v4-mapped form counts against the v4 source.
    #[test]
    fn qa_conn_limiter_unmaps_v4_mapped() {
        let limiter = Arc::new(ConnLimiter::new(1, 64));
        let v4: IpAddr = "192.0.2.5".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.5".parse().unwrap();
        let _g = limiter.try_acquire(v4).unwrap();
        assert!(limiter.try_acquire(mapped).is_none());
    }

    // QA: every slot released removes the entry; rejections drain once.
    #[test]
    fn qa_conn_limiter_release_and_drain() {
        let limiter = Arc::new(ConnLimiter::new(2, 64));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let g1 = limiter.try_acquire(a).unwrap();
        let g2 = limiter.try_acquire(a).unwrap();
        for _ in 0..3 {
            assert!(limiter.try_acquire(a).is_none());
        }
        let mut seen = Vec::new();
        assert_eq!(
            limiter
                .drain_rejections(|k, _, n| seen.push((k, n)))
                .untracked,
            0
        );
        assert_eq!(seen, vec![(a, 3)]);
        seen.clear();
        assert_eq!(
            limiter
                .drain_rejections(|k, _, n| seen.push((k, n)))
                .untracked,
            0
        );
        assert_eq!(seen.len(), 0);
        drop(g1);
        assert_eq!(limiter.active(a), 1);
        let g3 = limiter.try_acquire(a).unwrap();
        drop(g2);
        drop(g3);
        assert_eq!(limiter.active(a), 0);
        assert_eq!(limiter.sources(), 0);
    }

    // QA: a zero cap is clamped to one (fail-secure, never unlimited).
    #[test]
    fn qa_conn_limiter_zero_cap_clamped() {
        let limiter = Arc::new(ConnLimiter::new(0, 64));
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let _g = limiter.try_acquire(a).unwrap();
        assert!(limiter.try_acquire(a).is_none());
    }
}

/// SR-56: per-source accept token bucket and per-source in-handshake cap.
///
/// ## NIST 800-53 Rev5: SC-5
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod sr56_accept_admission_tests {
    use super::*;

    fn rejections(limiter: &ConnLimiter) -> Vec<(IpAddr, Rejection, u64)> {
        let mut seen = Vec::new();
        let _ = limiter.drain_rejections(|k, kind, n| seen.push((k, kind, n)));
        seen.sort_by_key(|(k, kind, _)| (*k, format!("{kind:?}")));
        seen
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn accept_rate_limits_new_connections_per_source() {
        let limiter = Arc::new(ConnLimiter::new(100, 64).with_accept_rate(1, 3, 1_024));
        let a = ip("192.0.2.1");
        let b = ip("192.0.2.2");
        for i in 0..3 {
            assert!(limiter.try_acquire(a).is_some(), "burst accept {i}");
        }
        assert!(
            limiter.try_acquire(a).is_none(),
            "4th accept within a second must be refused by the bucket"
        );
        assert!(
            limiter.try_acquire(b).is_some(),
            "another source is unaffected"
        );
        assert_eq!(rejections(&limiter), vec![(a, Rejection::AcceptRate, 1)]);
    }

    #[test]
    fn accept_rate_reject_takes_no_slot() {
        let limiter = Arc::new(ConnLimiter::new(4, 64).with_accept_rate(1, 1, 1_024));
        let a = ip("192.0.2.1");
        let held = limiter.try_acquire(a).unwrap();
        assert!(limiter.try_acquire(a).is_none());
        assert_eq!(limiter.active(a), 1, "bucket reject must not take a slot");
        let c = ip("192.0.2.3");
        drop(limiter.try_acquire(c).unwrap());
        assert!(limiter.try_acquire(c).is_none());
        assert_eq!(limiter.active(c), 0);
        assert_eq!(limiter.sources(), 1, "no entry for the refused source");
        // A bucket reject is AcceptRate, never PerSource.
        assert_eq!(
            rejections(&limiter),
            vec![(a, Rejection::AcceptRate, 1), (c, Rejection::AcceptRate, 1)]
        );
        drop(held);
        assert_eq!(limiter.sources(), 0);
    }

    #[test]
    fn accept_rate_keys_by_prefix_and_unmaps_v4() {
        let limiter = Arc::new(ConnLimiter::new(100, 64).with_accept_rate(1, 1, 1_024));
        drop(limiter.try_acquire(ip("2001:db8:0:1::1")).unwrap());
        assert!(
            limiter.try_acquire(ip("2001:db8:0:1::2")).is_none(),
            "same /64 shares one bucket"
        );
        assert!(limiter.try_acquire(ip("2001:db8:0:2::1")).is_some());
        drop(limiter.try_acquire(ip("192.0.2.1")).unwrap());
        assert!(
            limiter.try_acquire(ip("::ffff:192.0.2.1")).is_none(),
            "v4-mapped shares the plain-v4 bucket"
        );
        let seen = rejections(&limiter);
        assert!(seen.contains(&(ip("2001:db8:0:1::"), Rejection::AcceptRate, 1)));
        assert!(seen.contains(&(ip("192.0.2.1"), Rejection::AcceptRate, 1)));
    }

    #[test]
    fn accept_rate_zero_disables() {
        let limiter = Arc::new(ConnLimiter::new(1, 64).with_accept_rate(0, 1, 1_024));
        let a = ip("192.0.2.1");
        for i in 0..10_000 {
            assert!(limiter.try_acquire(a).is_some(), "cycle {i}");
        }
        assert_eq!(rejections(&limiter), Vec::new());
    }

    #[test]
    fn accept_rate_refills() {
        let limiter = Arc::new(ConnLimiter::new(100, 64).with_accept_rate(20, 1, 1_024));
        let a = ip("192.0.2.1");
        drop(limiter.try_acquire(a).unwrap());
        assert!(limiter.try_acquire(a).is_none(), "burst of 1 is spent");
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            limiter.try_acquire(a).is_some(),
            "20/s refills a token within 100 ms"
        );
    }

    #[test]
    fn handshake_cap_per_source_and_release_on_drop() {
        let limiter = Arc::new(ConnLimiter::new(100, 64).with_handshake_cap(2));
        let a = ip("2001:db8:0:1::1");
        let a_same_prefix = ip("2001:db8:0:1::2");
        let b = ip("192.0.2.2");
        let h1: HandshakeGuard = limiter.try_begin_handshake(a).unwrap();
        let h2 = limiter.try_begin_handshake(a_same_prefix).unwrap();
        assert!(limiter.try_begin_handshake(a).is_none(), "third handshake");
        let hb = limiter.try_begin_handshake(b).unwrap();
        // Handshake slots are separate from connection slots.
        assert_eq!(limiter.active(a), 0);
        assert_eq!(
            rejections(&limiter),
            vec![(ip("2001:db8:0:1::"), Rejection::HandshakeBusy, 1)]
        );
        drop(h1);
        let h3 = limiter.try_begin_handshake(a).unwrap();
        drop((h2, h3, hb));
        // Every guard released: the source can start a full set again.
        let _x = limiter.try_begin_handshake(a).unwrap();
        let _y = limiter.try_begin_handshake(a).unwrap();
    }

    #[test]
    fn handshake_guard_releases_on_panic() {
        let limiter = Arc::new(ConnLimiter::new(100, 64).with_handshake_cap(1));
        let a = ip("192.0.2.1");
        let l = Arc::clone(&limiter);
        let r = std::thread::spawn(move || {
            let _g = l.try_begin_handshake(a).unwrap();
            // Unwind like a panicking handshake task.
            std::panic::resume_unwind(Box::new("handshake task panicked"));
        })
        .join();
        assert!(r.is_err());
        assert!(limiter.try_begin_handshake(a).is_some());
    }

    #[test]
    fn sweep_accept_evicts_idle_and_reports_rejections() {
        let limiter = Arc::new(ConnLimiter::new(100, 64).with_accept_rate(1, 1, 1_024));
        let a = ip("192.0.2.1");
        drop(limiter.try_acquire(a).unwrap());
        for _ in 0..3 {
            assert!(limiter.try_acquire(a).is_none());
        }
        let mut seen = Vec::new();
        limiter.sweep_accept(|k, _, n| seen.push((k, n)));
        assert_eq!(seen, vec![(a, 3)]);
        seen.clear();
        limiter.sweep_accept(|k, _, n| seen.push((k, n)));
        assert!(seen.is_empty(), "rejections are reported once");
    }

    // SR-56 (PERF-003): sources past the tracking cap share an overflow
    // bucket of 4 x the per-source rate with the per-source burst, not the
    // message limiter's overflow (1,000/s, burst 2,000).
    #[test]
    fn accept_overflow_uses_own_rate_and_burst() {
        let limiter = Arc::new(ConnLimiter::new(100, 64).with_accept_rate(1, 2, 1));
        // The only tracked bucket.
        drop(limiter.try_acquire(ip("192.0.2.1")).unwrap());
        // Untracked sources share the overflow burst of 2.
        drop(limiter.try_acquire(ip("192.0.2.2")).unwrap());
        drop(limiter.try_acquire(ip("192.0.2.3")).unwrap());
        assert!(
            limiter.try_acquire(ip("192.0.2.4")).is_none(),
            "overflow burst is accept_burst_per_source"
        );
        // 4/s refills one overflow token within 300 ms.
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(limiter.try_acquire(ip("192.0.2.5")).is_some());
    }

    // SR-59: the per-proxy pre-handshake cap counts per exact proxy
    // address, releases on drop and is audited under the proxy.
    #[test]
    fn proxy_handshake_cap_per_proxy_and_released() {
        let limiter = Arc::new(ConnLimiter::new(2, 64).with_proxy_handshake_cap(2));
        assert_eq!(limiter.max_handshakes_per_proxy(), 2);
        let p = ip("10.0.0.1");
        let g1 = limiter.try_proxy_handshake(p).unwrap();
        let g2 = limiter.try_proxy_handshake(ip("::ffff:10.0.0.1")).unwrap();
        assert!(limiter.try_proxy_handshake(p).is_none());
        // Another proxy is unaffected, and no per-source slot is held.
        let other = limiter.try_proxy_handshake(ip("10.0.0.2")).unwrap();
        assert_eq!(limiter.active(p), 0);
        drop(g1);
        let g3 = limiter.try_proxy_handshake(p).unwrap();
        limiter.note_proxy_header(p);
        drop((g2, g3, other));
        let mut seen = Vec::new();
        let _ = limiter.drain_rejections(|k, kind, n| seen.push((k, kind, n)));
        seen.sort_by_key(|(_, kind, _)| format!("{kind:?}"));
        assert_eq!(
            seen,
            vec![
                (p, Rejection::ProxyHandshakeBusy, 1),
                (p, Rejection::ProxyHeader, 1)
            ]
        );
        assert_eq!(limiter.lock().handshakes.len(), 0);
    }
}

/// SR-58 (POA&M-454/455): hierarchical connection caps. Besides the /64
/// per-source key, every connection also counts against an aggregate: the
/// IPv6 `v6_aggregate_prefix_len` prefix (default /48) or the IPv4 /24.
/// Compile-red until `ConnLimiter::with_aggregate_caps` and
/// `Rejection::PerAggregate` exist.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod sr58_aggregate_tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Drains the limiter and returns every (key, kind, count), sorted.
    fn drained(limiter: &ConnLimiter) -> Vec<(IpAddr, Rejection, u64)> {
        let mut seen = Vec::new();
        let _ = limiter.drain_rejections(|k, kind, n| seen.push((k, kind, n)));
        seen.sort_by_key(|(k, kind, _)| (*k, format!("{kind:?}")));
        seen
    }

    #[test]
    fn v6_aggregate_caps_many_64s_in_one_48() {
        let limiter = Arc::new(ConnLimiter::new(128, 64).with_aggregate_caps(48, 4, 1024));
        // Within the /48 cap.
        let held: Vec<_> = (1..=4u16)
            .map(|n| {
                limiter
                    .try_acquire(ip(&format!("2001:db8:1:{n:x}::1")))
                    .unwrap()
            })
            .collect();
        // Fifth distinct /64 in the same /48.
        assert!(limiter.try_acquire(ip("2001:db8:1:5::1")).is_none());
        // A /64 in another /48 is unaffected.
        let other = limiter.try_acquire(ip("2001:db8:2:1::1")).unwrap();
        assert_eq!(
            drained(&limiter),
            vec![(ip("2001:db8:1::"), Rejection::PerAggregate, 1)]
        );
        drop((held, other));
    }

    #[test]
    fn v4_24_caps_many_hosts() {
        let limiter = Arc::new(ConnLimiter::new(128, 64).with_aggregate_caps(48, 1024, 3));
        let g: Vec<_> = (1..=3u8)
            .map(|n| limiter.try_acquire(ip(&format!("192.0.2.{n}"))).unwrap())
            .collect();
        assert!(limiter.try_acquire(ip("192.0.2.4")).is_none());
        let other = limiter.try_acquire(ip("198.51.100.1")).unwrap();
        assert_eq!(
            drained(&limiter),
            vec![(ip("192.0.2.0"), Rejection::PerAggregate, 1)]
        );
        drop((g, other));
    }

    #[test]
    fn aggregate_reject_takes_no_per_source_slot() {
        let limiter = Arc::new(ConnLimiter::new(128, 64).with_aggregate_caps(48, 2, 2));
        let _a = limiter.try_acquire(ip("2001:db8:1:1::1")).unwrap();
        let _b = limiter.try_acquire(ip("2001:db8:1:2::1")).unwrap();
        let victim = ip("2001:db8:1:3::1");
        assert_eq!(limiter.active(victim), 0);
        for _ in 0..5 {
            assert!(limiter.try_acquire(victim).is_none());
        }
        assert_eq!(limiter.active(victim), 0, "no per-source slot leaked");
        // Same for IPv4.
        let _c = limiter.try_acquire(ip("192.0.2.1")).unwrap();
        let _d = limiter.try_acquire(ip("192.0.2.2")).unwrap();
        assert!(limiter.try_acquire(ip("192.0.2.3")).is_none());
        assert_eq!(limiter.active(ip("192.0.2.3")), 0);
    }

    #[test]
    fn per_source_cap_still_applies_below_aggregate() {
        let limiter = Arc::new(ConnLimiter::new(2, 64).with_aggregate_caps(48, 100, 100));
        let a = ip("2001:db8:1:1::1");
        let _g1 = limiter.try_acquire(a).unwrap();
        let _g2 = limiter.try_acquire(ip("2001:db8:1:1::2")).unwrap();
        assert!(limiter.try_acquire(a).is_none());
        // The per-source reject must not consume an aggregate slot: 98 more
        // /64s fit in the /48 (100 - 2).
        let more: Vec<_> = (2..=99u16)
            .map(|n| {
                limiter
                    .try_acquire(ip(&format!("2001:db8:1:{n:x}::1")))
                    .unwrap()
            })
            .collect();
        assert!(limiter.try_acquire(ip("2001:db8:1:ff::1")).is_none());
        assert_eq!(
            drained(&limiter),
            vec![
                (ip("2001:db8:1::"), Rejection::PerAggregate, 1),
                (ip("2001:db8:1:1::"), Rejection::PerSource, 1),
            ]
        );
        drop(more);
    }

    #[test]
    fn aggregate_released_on_drop() {
        let limiter = Arc::new(ConnLimiter::new(128, 64).with_aggregate_caps(48, 2, 2));
        let g1 = limiter.try_acquire(ip("2001:db8:1:1::1")).unwrap();
        let g2 = limiter.try_acquire(ip("2001:db8:1:2::1")).unwrap();
        let g3 = limiter.try_acquire(ip("192.0.2.1")).unwrap();
        let g4 = limiter.try_acquire(ip("192.0.2.2")).unwrap();
        assert!(limiter.try_acquire(ip("2001:db8:1:3::1")).is_none());
        assert!(limiter.try_acquire(ip("192.0.2.3")).is_none());
        drop(g1);
        drop(g3);
        // One slot back at each aggregate.
        let g5 = limiter.try_acquire(ip("2001:db8:1:3::1")).unwrap();
        let g6 = limiter.try_acquire(ip("192.0.2.3")).unwrap();
        drop((g2, g4, g5, g6));
        assert_eq!(limiter.sources(), 0, "every level released");
    }

    #[test]
    fn aggregate_released_on_panic() {
        let limiter = Arc::new(ConnLimiter::new(128, 64).with_aggregate_caps(48, 1, 1));
        let l = Arc::clone(&limiter);
        let r = std::thread::spawn(move || {
            let _g = l.try_acquire("2001:db8:1:1::1".parse().unwrap()).unwrap();
            let _h = l.try_acquire("192.0.2.1".parse().unwrap()).unwrap();
            // Unwind like a task that died holding the slots.
            std::panic::resume_unwind(Box::new("task died holding the slots"));
        })
        .join();
        assert!(r.is_err());
        assert_eq!(limiter.sources(), 0);
        assert!(limiter.try_acquire(ip("2001:db8:1:2::1")).is_some());
        assert!(limiter.try_acquire(ip("192.0.2.2")).is_some());
    }

    #[test]
    fn aggregate_zero_disables() {
        let limiter = Arc::new(ConnLimiter::new(128, 64).with_aggregate_caps(48, 0, 0));
        let v6: Vec<_> = (1..=100u16)
            .map(|n| {
                limiter
                    .try_acquire(ip(&format!("2001:db8:1:{n:x}::1")))
                    .unwrap()
            })
            .collect();
        let v4: Vec<_> = (1..=100u8)
            .map(|n| limiter.try_acquire(ip(&format!("192.0.2.{n}"))).unwrap())
            .collect();
        assert_eq!((v6.len(), v4.len()), (100, 100));
        assert_eq!(drained(&limiter), Vec::new());
        drop((v6, v4));
    }

    #[test]
    fn aggregate_levels_are_independent() {
        // v6 aggregate off, v4 /24 capped at 2.
        let limiter = Arc::new(ConnLimiter::new(128, 64).with_aggregate_caps(48, 0, 2));
        let _v6: Vec<_> = (1..=50u16)
            .map(|n| {
                limiter
                    .try_acquire(ip(&format!("2001:db8:1:{n:x}::1")))
                    .unwrap()
            })
            .collect();
        let _a = limiter.try_acquire(ip("192.0.2.1")).unwrap();
        let _b = limiter.try_acquire(ip("192.0.2.2")).unwrap();
        assert!(limiter.try_acquire(ip("192.0.2.3")).is_none());
    }

    #[test]
    fn aggregate_unmaps_v4_mapped() {
        let limiter = Arc::new(ConnLimiter::new(128, 64).with_aggregate_caps(48, 1024, 2));
        let _a = limiter.try_acquire(ip("::ffff:192.0.2.1")).unwrap();
        let _b = limiter.try_acquire(ip("192.0.2.2")).unwrap();
        assert!(limiter.try_acquire(ip("::ffff:192.0.2.3")).is_none());
        assert_eq!(
            drained(&limiter),
            vec![(ip("192.0.2.0"), Rejection::PerAggregate, 1)]
        );
    }

    #[test]
    fn v6_aggregate_prefix_is_configurable() {
        // /56 aggregate: two /64s per /56.
        let limiter = Arc::new(ConnLimiter::new(128, 64).with_aggregate_caps(56, 2, 1024));
        let _a = limiter.try_acquire(ip("2001:db8:1:100::1")).unwrap();
        let _b = limiter.try_acquire(ip("2001:db8:1:101::1")).unwrap();
        assert!(limiter.try_acquire(ip("2001:db8:1:1ff::1")).is_none());
        // Another /56 inside the same /48 is a different aggregate.
        assert!(limiter.try_acquire(ip("2001:db8:1:200::1")).is_some());
        assert_eq!(
            drained(&limiter),
            vec![(ip("2001:db8:1:100::"), Rejection::PerAggregate, 1)]
        );
    }

    /// SR-58 scenario: one IPv6 /56 (256 /64s) opening 128 connections per
    /// /64 under the decision-9 defaults (128 per /64, 1024 per /48, 1024
    /// per /24) gets exactly 1024 slots, not 32,768.
    #[test]
    fn slash56_cannot_fill_listener_pool() {
        let limiter = Arc::new(ConnLimiter::new(128, 64).with_aggregate_caps(48, 1024, 1024));
        let mut held = Vec::new();
        let mut rejected = 0u32;
        for sub in 0..=255u16 {
            let a = ip(&format!("2001:db8:1:{:x}::1", 0xab00 | sub));
            for _ in 0..128 {
                match limiter.try_acquire(a) {
                    Some(g) => held.push(g),
                    None => rejected += 1,
                }
            }
        }
        assert_eq!(held.len(), 1024);
        assert_eq!(rejected, 256 * 128 - 1024);
        drop(held);
        assert_eq!(limiter.sources(), 0);
    }
}

/// SR-58 fix round: trunk exemption (SEC-001), aggregate accept bucket and
/// handshake cap (SEC-002), stricter caps honoured (SEC-003), embedded-IPv4
/// mapping (SEC-004) and key edge cases (SEC-007).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod sr58_fix_round_tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn drained(limiter: &ConnLimiter) -> Vec<(IpAddr, Rejection, u64)> {
        let mut seen = Vec::new();
        let _ = limiter.drain_rejections(|k, kind, n| seen.push((k, kind, n)));
        seen.sort_by_key(|(k, kind, _)| (*k, format!("{kind:?}")));
        seen
    }

    /// SEC-001: a full /24 (and a full /48) still admits a configured trunk
    /// address, which takes no aggregate slot; its per-source cap applies.
    #[test]
    fn trunk_ip_skips_aggregate_level() {
        let limiter = Arc::new(
            ConnLimiter::new(2, 64)
                .with_aggregate_caps(48, 2, 2)
                .with_aggregate_handshake_cap(1),
        );
        let trunk = ip("192.0.2.200");
        let trunk6 = ip("2001:db8:1:ff::5");
        assert_eq!(limiter.set_trusted_sources([trunk, trunk6]), 2);
        let fill: Vec<_> = [
            "192.0.2.1",
            "192.0.2.2",
            "2001:db8:1:1::1",
            "2001:db8:1:2::1",
        ]
        .iter()
        .map(|s| limiter.try_acquire(ip(s)).unwrap())
        .collect();
        assert!(limiter.try_acquire(ip("192.0.2.3")).is_none(), "/24 full");
        assert!(
            limiter.try_acquire(ip("2001:db8:1:3::1")).is_none(),
            "/48 full"
        );
        // The trunk skips the /24 cap.
        let t1 = limiter.try_acquire(trunk).unwrap();
        let t2 = limiter.try_acquire(ip("::ffff:192.0.2.200")).unwrap();
        assert!(
            limiter.try_acquire(trunk).is_none(),
            "per-source cap still applies"
        );
        // The trunk skips the /48 cap.
        let t3 = limiter.try_acquire(trunk6).unwrap();
        assert_eq!(limiter.aggregate_active(ip("192.0.2.1")), 2);
        // The trunk's slots were never charged to the /24.
        assert_eq!(limiter.aggregate_active(trunk), 0);
        let h = limiter.try_begin_handshake(ip("192.0.2.1")).unwrap();
        assert!(limiter.try_begin_handshake(ip("192.0.2.2")).is_none());
        let ht = limiter.try_begin_handshake(trunk).unwrap();
        // Untrusting does not unbalance the counts of guards already held.
        limiter.set_trusted_sources([]);
        assert!(limiter.try_acquire(ip("192.0.2.201")).is_none());
        drop((t1, t2, t3, fill, h, ht));
        assert_eq!(limiter.sources(), 0);
        // The trunk's only refusal is its own per-source cap.
        assert_eq!(
            drained(&limiter),
            vec![
                (ip("192.0.2.0"), Rejection::AggregateHandshakeBusy, 1),
                (ip("192.0.2.0"), Rejection::PerAggregate, 2),
                (trunk, Rejection::PerSource, 1),
                (ip("2001:db8:1::"), Rejection::PerAggregate, 1),
            ]
        );
    }

    /// SEC-001: a trunk is also exempt from the aggregate accept bucket,
    /// not from its own.
    #[test]
    fn trunk_ip_skips_aggregate_accept_bucket() {
        let limiter = Arc::new(
            ConnLimiter::new(100, 64)
                .with_aggregate_caps(48, 1024, 1024)
                .with_accept_rate(1, 1, 1_024),
        );
        let trunk = ip("192.0.2.200");
        limiter.set_trusted_sources([trunk]);
        let held: Vec<_> = (1..=16u8)
            .map(|h| limiter.try_acquire(ip(&format!("192.0.2.{h}"))).unwrap())
            .collect();
        assert_eq!(
            limiter.try_admit(ip("192.0.2.17")).err(),
            Some(Rejection::AggregateAcceptRate)
        );
        assert!(limiter.try_acquire(trunk).is_some());
        assert_eq!(limiter.try_admit(trunk).err(), Some(Rejection::AcceptRate));
        drop(held);
    }

    /// SEC-002: one bucket per aggregate, 16 x the per-source rate and
    /// burst, shared by every source in it.
    #[test]
    fn aggregate_accept_rate_spans_sources() {
        let limiter = Arc::new(
            ConnLimiter::new(100, 64)
                .with_aggregate_caps(48, 1024, 1024)
                .with_accept_rate(1, 2, 4_096),
        );
        assert_eq!(limiter.aggregate_accept_rate(), 16);
        let mut admitted = 0;
        for n in 1..=40u16 {
            // Two accepts per /64 (its own burst), 40 /64s in one /48.
            for _ in 0..2 {
                if limiter
                    .try_acquire(ip(&format!("2001:db8:1:{n:x}::1")))
                    .is_some()
                {
                    admitted += 1;
                }
            }
        }
        assert_eq!(admitted, 32, "aggregate burst 16 x 2");
        assert_eq!(
            limiter.try_admit(ip("2001:db8:1:ff::1")).err(),
            Some(Rejection::AggregateAcceptRate)
        );
        // Another /48 has its own aggregate bucket.
        assert!(limiter.try_acquire(ip("2001:db8:2:1::1")).is_some());
        let seen = drained(&limiter);
        assert_eq!(
            seen,
            // 80 - 32 in the loop, plus the one above.
            vec![(ip("2001:db8:1::"), Rejection::AggregateAcceptRate, 49)]
        );
    }

    /// SEC-002: an aggregate accept-rate reject takes no slot at either
    /// level, and the level tag keeps a /48 key apart from an equal /64 key.
    #[test]
    fn aggregate_accept_reject_takes_no_slot() {
        let limiter = Arc::new(
            ConnLimiter::new(100, 64)
                .with_aggregate_caps(48, 1024, 1024)
                .with_accept_rate(1, 1, 1_024),
        );
        let held: Vec<_> = (1..=16u16)
            .map(|n| {
                limiter
                    .try_acquire(ip(&format!("2001:db8:1:{n:x}::1")))
                    .unwrap()
            })
            .collect();
        // `2001:db8:1::/64` has the same key as the /48 aggregate.
        let same_key = ip("2001:db8:1::9");
        assert_eq!(
            limiter.try_admit(same_key).err(),
            Some(Rejection::AggregateAcceptRate)
        );
        assert_eq!(limiter.active(same_key), 0);
        assert_eq!(limiter.aggregate_active(same_key), 16);
        drop(held);
        assert_eq!(limiter.sources(), 0);
        // Sweeping reports the aggregate kind with the aggregate key.
        let mut seen = Vec::new();
        limiter.sweep_accept(|k, kind, n| seen.push((k, kind, n)));
        assert_eq!(
            seen,
            vec![(ip("2001:db8:1::"), Rejection::AggregateAcceptRate, 1)]
        );
    }

    /// SEC-002: handshakes in progress are capped per aggregate across its
    /// sources, and released on drop.
    #[test]
    fn aggregate_handshake_cap_spans_sources() {
        let limiter = Arc::new(
            ConnLimiter::new(100, 64)
                .with_aggregate_caps(48, 1024, 1024)
                .with_handshake_cap(8)
                .with_aggregate_handshake_cap(3),
        );
        assert_eq!(limiter.max_handshakes_per_aggregate(), 3);
        let h: Vec<_> = (1..=3u16)
            .map(|n| {
                limiter
                    .try_begin_handshake(ip(&format!("2001:db8:1:{n:x}::1")))
                    .unwrap()
            })
            .collect();
        let victim = ip("2001:db8:1:4::1");
        assert_eq!(
            limiter.try_handshake(victim).err(),
            Some(Rejection::AggregateHandshakeBusy)
        );
        // The rejected source holds no per-source handshake: with the
        // aggregate cap raised by a release it gets in at once.
        assert!(limiter.try_begin_handshake(ip("2001:db8:2:1::1")).is_some());
        drop(h);
        let again: Vec<_> = (0..3)
            .map(|_| limiter.try_begin_handshake(victim).unwrap())
            .collect();
        assert_eq!(again.len(), 3);
        drop(again);
        assert_eq!(
            drained(&limiter),
            vec![(ip("2001:db8:1::"), Rejection::AggregateHandshakeBusy, 1)]
        );
    }

    /// SEC-004: 6to4 and NAT64 sources count in the /24 of their embedded
    /// IPv4 address, together with plain IPv4 hosts there.
    #[test]
    fn six_to_four_and_nat64_count_in_embedded_v4_24() {
        let limiter = Arc::new(ConnLimiter::new(128, 64).with_aggregate_caps(48, 1024, 3));
        // 2002:c000:0201:: is 6to4 for 192.0.2.1; 64:ff9b::c000:202 is
        // NAT64 for 192.0.2.2.
        let a = limiter.try_acquire(ip("2002:c000:201::1")).unwrap();
        let b = limiter.try_acquire(ip("64:ff9b::c000:202")).unwrap();
        let c = limiter.try_acquire(ip("192.0.2.3")).unwrap();
        assert_eq!(limiter.aggregate_active(ip("192.0.2.99")), 3);
        assert!(limiter.try_acquire(ip("2002:c000:2ff::1")).is_none());
        assert!(limiter.try_acquire(ip("64:ff9b::c000:2fe")).is_none());
        // Outside the /24, and outside 64:ff9b::/96, are separate aggregates.
        assert!(limiter.try_acquire(ip("2002:c000:301::1")).is_some());
        assert!(limiter.try_acquire(ip("64:ff9b:1::c000:203")).is_some());
        assert_eq!(
            drained(&limiter),
            vec![(ip("192.0.2.0"), Rejection::PerAggregate, 2)]
        );
        drop((a, b, c));
    }

    /// SEC-007: per-source prefix equal to the aggregate prefix: both
    /// levels use the same key, kept apart by the level tag.
    #[test]
    fn per_source_prefix_equal_to_aggregate_prefix() {
        let limiter = Arc::new(ConnLimiter::new(2, 48).with_aggregate_caps(48, 3, 3));
        let a = ip("2001:db8:1:1::1");
        let g1 = limiter.try_acquire(a).unwrap();
        let g2 = limiter.try_acquire(ip("2001:db8:1:2::1")).unwrap();
        assert_eq!(
            limiter.try_admit(ip("2001:db8:1:3::1")).err(),
            Some(Rejection::PerSource),
            "per-source /48 is at 2 before the aggregate at 3"
        );
        assert_eq!((limiter.active(a), limiter.aggregate_active(a)), (2, 2));
        assert_eq!(limiter.sources(), 2, "one entry per level");
        drop((g1, g2));
        assert_eq!(limiter.sources(), 0);
    }

    /// SEC-007: the /24 network address (`192.0.2.0`) is an ordinary host
    /// in its /24.
    #[test]
    fn v4_24_network_address_counts_with_other_hosts() {
        let limiter = Arc::new(ConnLimiter::new(128, 64).with_aggregate_caps(48, 1024, 2));
        let zero = limiter.try_acquire(ip("192.0.2.0")).unwrap();
        let one = limiter.try_acquire(ip("192.0.2.1")).unwrap();
        assert!(limiter.try_acquire(ip("192.0.2.255")).is_none());
        assert_eq!(limiter.active(ip("192.0.2.0")), 1);
        drop(zero);
        assert!(limiter.try_acquire(ip("192.0.2.255")).is_some());
        drop(one);
    }

    /// SEC-003: an aggregate cap below the per-source cap is honoured.
    #[test]
    fn aggregate_cap_below_per_source_honoured() {
        let limiter = Arc::new(ConnLimiter::new(128, 64).with_aggregate_caps(48, 1, 1));
        let _a = limiter.try_acquire(ip("192.0.2.1")).unwrap();
        assert_eq!(
            limiter.try_admit(ip("192.0.2.1")).err(),
            Some(Rejection::PerAggregate)
        );
        let _b = limiter.try_acquire(ip("2001:db8:1:1::1")).unwrap();
        assert_eq!(
            limiter.try_admit(ip("2001:db8:1:1::1")).err(),
            Some(Rejection::PerAggregate)
        );
    }
}
