//! Per-source stream connection cap.
//!
//! One source (an IPv4 address, or an IPv6 prefix of
//! `rate_limit.ipv6_prefix_len` bits) may hold at most
//! `transport.max_connections_per_source` accepted stream connections across
//! all TCP, TLS and WebSocket listeners. Without it one host can take the
//! whole listener pool with idle sockets.
//!
//! It also holds accept-time admission state shared by the listeners: an
//! optional per-source accept token bucket
//! (`transport.accept_rate_per_source`) and a per-source cap on handshakes
//! in progress (`transport.max_handshakes_per_source`).
//!
//! The critical sections are O(1), never span an `.await`, and run only on
//! accept, handshake end and close, so `std::sync::Mutex` is used. The
//! accept bucket has its own lock; no path holds both locks at once.
//!
//! ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection), SC-7

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use tracing::warn;
use uc_dos_protection::{RateLimiter, RateLimiterConfig};

/// Distinct sources whose connection rejections are tracked between audit
/// flushes; rejections from further sources are summed without a key.
const MAX_REJECTED_SOURCES: usize = 4_096;

#[derive(Debug, Default)]
struct Inner {
    /// Live connections per source key. An entry exists only while the
    /// source holds a connection, so the map is bounded by the connection
    /// pools.
    active: HashMap<IpAddr, u32>,
    /// Handshakes in progress per source key. An entry exists only while a
    /// handshake runs, and each runs under a connection slot, so the map is
    /// bounded by the connection pools.
    handshakes: HashMap<IpAddr, u32>,
    /// Rejections per (source key, kind) since the last drain.
    rejected: HashMap<(IpAddr, Rejection), u64>,
    /// Rejections from sources past `MAX_REJECTED_SOURCES`.
    rejected_untracked: u64,
}

/// Why a stream connection (or its message) was rejected, for the
/// aggregated audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rejection {
    /// The source was at `max_connections_per_source`.
    PerSource,
    /// The stream carried invalid Content-Length framing (SI-10).
    Framing,
    /// The source was over `accept_rate_per_source`.
    AcceptRate,
    /// The source was at `max_handshakes_per_source`.
    HandshakeBusy,
    /// The source is blocked by the per-source rate limiter; the accept
    /// was dropped before any handshake.
    AcceptBlocked,
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

/// Per-source connection limiter shared by all stream listeners.
#[derive(Debug)]
pub struct ConnLimiter {
    inner: Mutex<Inner>,
    /// Accepts dropped on a full listener pool since the last drain.
    listener_full: AtomicU64,
    /// Accepts dropped on the full node-wide pool since the last drain.
    total_full: AtomicU64,
    max_per_source: u32,
    v6_prefix_len: u8,
    /// Per-source accept bucket; `None` when the accept rate is off. A
    /// `RateLimiter` that never blocks, reused for its bounded bucket map,
    /// overflow bucket and idle sweep.
    accept: Option<Mutex<RateLimiter>>,
    /// Handshakes in progress allowed per source.
    max_handshakes_per_source: u32,
}

/// Holds one handshake slot for a source; released on drop (including on
/// panic or task abort).
#[derive(Debug)]
pub struct HandshakeGuard {
    limiter: Arc<ConnLimiter>,
    key: IpAddr,
}

/// Holds one connection slot for a source; released on drop (including on
/// panic or task abort).
#[derive(Debug)]
pub struct ConnGuard {
    limiter: Arc<ConnLimiter>,
    key: IpAddr,
}

impl ConnLimiter {
    /// Creates a limiter allowing `max_per_source` connections per source.
    pub fn new(max_per_source: u32, v6_prefix_len: u8) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            listener_full: AtomicU64::new(0),
            total_full: AtomicU64::new(0),
            max_per_source: max_per_source.max(1),
            v6_prefix_len,
            accept: None,
            max_handshakes_per_source: u32::MAX,
        }
    }

    /// Adds a per-source accept bucket: `rate` new connections per second,
    /// `burst` at once. At most `max_tracked` sources (at least 1) get their
    /// own bucket; further sources share one overflow bucket of
    /// `4 * rate` per second and `burst` at once, so a source past the
    /// tracking cap cannot outpace the per-source rate by more than four
    /// times. `rate` 0 leaves the bucket off.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    #[must_use]
    pub fn with_accept_rate(mut self, rate: u32, burst: u32, max_tracked: usize) -> Self {
        self.accept = (rate > 0).then(|| {
            let burst = burst.max(1);
            let config = RateLimiterConfig::new(rate, burst)
                .with_per_ip(true)
                .with_ipv6_prefix_len(self.v6_prefix_len)
                .with_max_tracked_sources(max_tracked.max(1))
                .with_overflow(rate.saturating_mul(4), burst)
                // Never blocks: an over-rate accept is dropped, nothing more.
                .with_block_threshold(f64::INFINITY)
                .with_max_blocked_sources(0);
            Mutex::new(RateLimiter::new(config))
        });
        self
    }

    /// Caps handshakes in progress per source at `per_source` (at least 1).
    #[must_use]
    pub fn with_handshake_cap(mut self, per_source: u32) -> Self {
        self.max_handshakes_per_source = per_source.max(1);
        self
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned: PoisonError<_>| {
                warn!("Connection limiter lock poisoned; recovering");
                poisoned.into_inner()
            })
    }

    fn lock_accept(accept: &Mutex<RateLimiter>) -> MutexGuard<'_, RateLimiter> {
        accept.lock().unwrap_or_else(|poisoned: PoisonError<_>| {
            warn!("Accept rate limiter lock poisoned; recovering");
            poisoned.into_inner()
        })
    }

    /// Takes a connection slot for `ip`, or `None` (counted for audit) when
    /// the source is over its accept rate or at its cap.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        self.try_admit(ip).ok()
    }

    /// Like [`Self::try_acquire`], but reports why a connection was refused
    /// ([`Rejection::AcceptRate`] or [`Rejection::PerSource`]). The accept
    /// bucket is charged first; a bucket reject takes no slot. A token
    /// spent on an accept that a later cap (per source, pool, handshake)
    /// refuses is not refunded: such a source is at a cap already.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    pub fn try_admit(self: &Arc<Self>, ip: IpAddr) -> Result<ConnGuard, Rejection> {
        let key = uc_dos_protection::source_key(ip, self.v6_prefix_len);
        if let Some(accept) = &self.accept {
            // The bucket lock is released before `inner` is taken.
            let rejected = Self::lock_accept(accept).check(key).is_rejected();
            if rejected {
                Self::count(&mut self.lock(), key, Rejection::AcceptRate);
                return Err(Rejection::AcceptRate);
            }
        }
        self.take_slot(key)
    }

    /// Takes a connection slot for `ip` without charging the accept
    /// bucket ([`Rejection::PerSource`] at the cap). For listeners whose
    /// accept address is not the client's, such as WebSocket behind a
    /// proxy, where one bucket would be shared by every client.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    pub fn try_admit_unmetered(self: &Arc<Self>, ip: IpAddr) -> Result<ConnGuard, Rejection> {
        self.take_slot(uc_dos_protection::source_key(ip, self.v6_prefix_len))
    }

    /// Takes a connection slot for source `key`, or counts a
    /// [`Rejection::PerSource`].
    fn take_slot(self: &Arc<Self>, key: IpAddr) -> Result<ConnGuard, Rejection> {
        let mut inner = self.lock();
        let count = inner.active.entry(key).or_insert(0);
        if *count >= self.max_per_source {
            Self::count(&mut inner, key, Rejection::PerSource);
            return Err(Rejection::PerSource);
        }
        *count += 1;
        drop(inner);
        Ok(ConnGuard {
            limiter: Arc::clone(self),
            key,
        })
    }

    /// Takes a handshake slot for `ip`, or `None` (counted for audit as
    /// [`Rejection::HandshakeBusy`]) when the source is at
    /// `max_handshakes_per_source`. Hold the guard only for the handshake.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    pub fn try_begin_handshake(self: &Arc<Self>, ip: IpAddr) -> Option<HandshakeGuard> {
        let key = uc_dos_protection::source_key(ip, self.v6_prefix_len);
        let mut inner = self.lock();
        let count = inner.handshakes.get(&key).copied().unwrap_or(0);
        if count >= self.max_handshakes_per_source {
            Self::count(&mut inner, key, Rejection::HandshakeBusy);
            return None;
        }
        inner.handshakes.insert(key, count.saturating_add(1));
        drop(inner);
        Some(HandshakeGuard {
            limiter: Arc::clone(self),
            key,
        })
    }

    /// Counts an accept dropped because the source is blocked.
    ///
    /// ## NIST 800-53 Rev5: AU-12, SC-7
    pub fn note_accept_blocked(&self, ip: IpAddr) {
        let key = uc_dos_protection::source_key(ip, self.v6_prefix_len);
        Self::count(&mut self.lock(), key, Rejection::AcceptBlocked);
    }

    /// Accept-bucket maintenance: evicts idle buckets, then reports and
    /// resets `f(key, count)` for accept-rate rejections not yet taken by
    /// [`Self::drain_rejections`]. Each rejection is reported once, by
    /// whichever call sees it first.
    ///
    /// ## NIST 800-53 Rev5: SC-5, AU-4
    pub fn sweep_accept(&self, mut f: impl FnMut(IpAddr, u64)) {
        if let Some(accept) = &self.accept {
            let mut bucket = Self::lock_accept(accept);
            // Rejections are counted in `Inner`; the bucket's own counters
            // are only reset here.
            let _ = bucket.sweep_with(|_| {});
            let _ = bucket.take_overflow_rejections();
        }
        let mut inner = self.lock();
        inner.rejected.retain(|(key, kind), n| {
            if *kind == Rejection::AcceptRate {
                f(*key, *n);
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
    /// tracked (source, kind), and returns the untracked and pool totals.
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
        self.lock().active.get(&key).copied().unwrap_or(0)
    }

    /// Number of sources holding at least one connection.
    #[cfg(test)]
    pub fn sources(&self) -> usize {
        self.lock().active.len()
    }
}

impl Drop for HandshakeGuard {
    fn drop(&mut self) {
        let mut inner = self.limiter.lock();
        if let Some(count) = inner.handshakes.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.handshakes.remove(&self.key);
            }
        }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut inner = self.limiter.lock();
        if let Some(count) = inner.active.get_mut(&self.key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                inner.active.remove(&self.key);
            }
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
        limiter.sweep_accept(|k, n| seen.push((k, n)));
        assert_eq!(seen, vec![(a, 3)]);
        seen.clear();
        limiter.sweep_accept(|k, n| seen.push((k, n)));
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

    // SR-56: the WebSocket path takes a connection slot without charging
    // the accept bucket; the per-source cap still applies.
    #[test]
    fn unmetered_admit_skips_bucket_keeps_cap() {
        let limiter = Arc::new(ConnLimiter::new(2, 64).with_accept_rate(1, 1, 1_024));
        let a = ip("192.0.2.1");
        let g1 = limiter.try_admit_unmetered(a).unwrap();
        let g2 = limiter.try_admit_unmetered(a).unwrap();
        assert_eq!(
            limiter.try_admit_unmetered(a).err(),
            Some(Rejection::PerSource)
        );
        drop((g1, g2));
        for _ in 0..10 {
            drop(limiter.try_admit_unmetered(a).unwrap());
        }
        // The bucket was never charged: a metered accept still passes.
        assert!(limiter.try_admit(a).is_ok());
    }
}
