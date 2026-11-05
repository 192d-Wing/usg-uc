//! Audit aggregation for STIR failures (verification and signing).
//!
//! An attacker can send any number of INVITEs with bad Identity headers.
//! One audit event is emitted per (trunk, reason) per window: the first
//! failure is emitted at once; later ones in the window are counted and the
//! count is carried on the next emitted event for that key, or by
//! [`FailureAggregator::flush`] once the window has closed, so a burst that
//! then stops is still fully accounted for.
//!
//! The key table is bounded ([`MAX_KEYS`]); when it is full of live keys a
//! new key's event is dropped and counted in [`FailureAggregator::dropped`].
//!
//! ## NIST 800-53 Rev5: AU-2, AU-4 (Audit Log Storage Capacity), AU-5, SC-5

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Most distinct (trunk, reason) keys tracked.
pub const MAX_KEYS: usize = 4096;
/// Longest gap between full-table sweeps: a full table of live keys is not
/// rescanned on every new key (SC-5).
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

struct Slot {
    window_start: Instant,
    suppressed: u64,
    /// Source IP of the latest failure for the key (AU-3).
    last_source_ip: Option<IpAddr>,
    /// Call-ID hash of the latest failure; the buffer is reused.
    last_call_id_hash: String,
}

/// Suppressed failures for one key whose window has closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Trunk id.
    pub trunk: String,
    /// Reason token.
    pub reason: &'static str,
    /// Failures suppressed since the last event for the key.
    pub count: u64,
    /// Source IP of the latest suppressed failure, if known.
    pub last_source_ip: Option<IpAddr>,
    /// Call-ID hash of the latest suppressed failure.
    pub last_call_id_hash: String,
}

/// The latest failure's context, kept on the slot so a flushed event can
/// still name a source (NIST 800-53 Rev5: AU-3).
#[derive(Debug, Clone, Copy, Default)]
pub struct Seen<'a> {
    /// Source IP of the failure.
    pub source_ip: Option<IpAddr>,
    /// Hashed Call-ID of the failure.
    pub call_id_hash: &'a str,
}

struct Table {
    /// reason -> trunk -> slot. Reasons are a small fixed set, so the
    /// outer map stays tiny and the inner one is looked up by `&str`
    /// without building an owned key.
    by_reason: HashMap<&'static str, HashMap<String, Slot>>,
    len: usize,
    last_sweep: Option<Instant>,
}

/// Rate limiter for audit events keyed by (trunk, reason).
pub struct FailureAggregator {
    window: Duration,
    slots: Mutex<Table>,
    dropped: AtomicU64,
}

impl std::fmt::Debug for FailureAggregator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FailureAggregator")
            .field("window", &self.window)
            .finish_non_exhaustive()
    }
}

impl FailureAggregator {
    /// Creates an aggregator with the given window (10 s in the daemon).
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            slots: Mutex::new(Table {
                by_reason: HashMap::new(),
                len: 0,
                last_sweep: None,
            }),
            dropped: AtomicU64::new(0),
        }
    }

    /// The aggregation window.
    #[must_use]
    pub const fn window(&self) -> Duration {
        self.window
    }

    /// Failures whose audit event was dropped because the key table was
    /// full of live keys (metric).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Records one failure at `now`. Returns `Some(count)` when an event
    /// should be emitted now, carrying `count` failures (this one plus any
    /// suppressed since the last event for the key).
    pub fn record(&self, trunk: &str, reason: &'static str, now: Instant) -> Option<u64> {
        self.record_seen(trunk, reason, now, Seen::default())
    }

    /// [`Self::record`], remembering `seen` as the key's latest failure.
    pub fn record_seen(
        &self,
        trunk: &str,
        reason: &'static str,
        now: Instant,
        seen: Seen<'_>,
    ) -> Option<u64> {
        let Ok(mut t) = self.slots.lock() else {
            return Some(1);
        };
        let window = self.window;
        if let Some(slot) = t.by_reason.get_mut(reason).and_then(|m| m.get_mut(trunk)) {
            slot.last_source_ip = seen.source_ip;
            slot.last_call_id_hash.clear();
            slot.last_call_id_hash.push_str(seen.call_id_hash);
            if now.duration_since(slot.window_start) < window {
                slot.suppressed = slot.suppressed.saturating_add(1);
                return None;
            }
            let count = slot.suppressed.saturating_add(1);
            slot.window_start = now;
            slot.suppressed = 0;
            return Some(count);
        }
        if t.len >= MAX_KEYS {
            let due = t
                .last_sweep
                .is_none_or(|s| now.duration_since(s) >= SWEEP_INTERVAL.min(window));
            if due {
                t.last_sweep = Some(now);
                // Keep keys that are live or still owe a flushed count.
                let mut len = 0;
                for m in t.by_reason.values_mut() {
                    m.retain(|_, s| {
                        now.duration_since(s.window_start) < window || s.suppressed > 0
                    });
                    len += m.len();
                }
                t.by_reason.retain(|_, m| !m.is_empty());
                t.len = len;
            }
            if t.len >= MAX_KEYS {
                // Still full: emitting unaggregated is the flood we are
                // preventing, so drop the event and count it.
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        t.by_reason.entry(reason).or_default().insert(
            trunk.to_owned(),
            Slot {
                window_start: now,
                suppressed: 0,
                last_source_ip: seen.source_ip,
                last_call_id_hash: seen.call_id_hash.to_owned(),
            },
        );
        t.len += 1;
        Some(1)
    }

    /// Takes the suppressed counts of every key whose window has closed by
    /// `now` (bounded by [`MAX_KEYS`]); the caller emits one event each.
    /// Idle keys with nothing pending are dropped.
    pub fn flush(&self, now: Instant) -> Vec<Pending> {
        let Ok(mut t) = self.slots.lock() else {
            return Vec::new();
        };
        let window = self.window;
        let mut out = Vec::new();
        let mut len = 0;
        for (reason, m) in &mut t.by_reason {
            m.retain(|trunk, s| {
                if now.duration_since(s.window_start) < window {
                    return true;
                }
                if s.suppressed > 0 {
                    out.push(Pending {
                        trunk: trunk.clone(),
                        reason,
                        count: s.suppressed,
                        last_source_ip: s.last_source_ip,
                        last_call_id_hash: std::mem::take(&mut s.last_call_id_hash),
                    });
                }
                false
            });
            len += m.len();
        }
        t.by_reason.retain(|_, m| !m.is_empty());
        t.len = len;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousand_failures_one_event_per_window() {
        let a = FailureAggregator::new(Duration::from_secs(10));
        let t0 = Instant::now();
        let emitted: u64 = (0..1000)
            .filter_map(|i| a.record("carrier", "bad-signature", t0 + Duration::from_millis(i)))
            .count() as u64;
        assert_eq!(emitted, 1);
        assert_eq!(
            a.record("carrier", "bad-signature", t0 + Duration::from_secs(11)),
            Some(1000)
        );
        assert_eq!(a.record("carrier", "expired-iat", t0), Some(1));
        assert_eq!(a.record("other", "bad-signature", t0), Some(1));
    }

    #[test]
    fn flush_reports_suppressed_after_window() {
        let a = FailureAggregator::new(Duration::from_secs(10));
        let t0 = Instant::now();
        assert_eq!(a.record("t", "bad-number", t0), Some(1));
        for i in 1..=5 {
            assert_eq!(
                a.record("t", "bad-number", t0 + Duration::from_millis(i)),
                None
            );
        }
        assert_eq!(a.record("u", "bad-number", t0), Some(1));
        // Window still open: nothing yet.
        assert_eq!(a.flush(t0 + Duration::from_secs(5)), Vec::new());
        let pending = a.flush(t0 + Duration::from_secs(11));
        assert_eq!(
            pending,
            vec![Pending {
                trunk: "t".into(),
                reason: "bad-number",
                count: 5,
                last_source_ip: None,
                last_call_id_hash: String::new(),
            }]
        );
        // Flushed and idle keys are gone; the next failure emits at once.
        assert_eq!(a.flush(t0 + Duration::from_secs(30)), Vec::new());
        assert_eq!(
            a.record("t", "bad-number", t0 + Duration::from_secs(31)),
            Some(1)
        );
    }

    #[test]
    fn full_table_drops_and_counts() {
        let a = FailureAggregator::new(Duration::from_secs(10));
        let t0 = Instant::now();
        for i in 0..MAX_KEYS {
            assert_eq!(a.record(&format!("t{i}"), "x", t0), Some(1));
        }
        assert_eq!(a.record("new", "x", t0), None);
        assert_eq!(a.dropped(), 1);
        // A full table of live keys is not rescanned per new key.
        assert_eq!(a.record("new2", "x", t0 + Duration::from_millis(1)), None);
        assert_eq!(a.dropped(), 2);
        // After the window the idle keys are reclaimed.
        assert_eq!(a.record("new", "x", t0 + Duration::from_secs(11)), Some(1));
    }

    /// NIST-013: a flushed event carries the latest suppressed failure's
    /// source IP and Call-ID hash.
    #[test]
    fn flush_carries_last_seen_source() {
        let a = FailureAggregator::new(Duration::from_secs(10));
        let t0 = Instant::now();
        let ip = |o: u8| Some(IpAddr::from([192, 0, 2, o]));
        let seen = |o: u8, h: &'static str| Seen {
            source_ip: ip(o),
            call_id_hash: h,
        };
        assert_eq!(
            a.record_seen("t", "bad-signature", t0, seen(1, "aa")),
            Some(1)
        );
        assert_eq!(a.record_seen("t", "bad-signature", t0, seen(2, "bb")), None);
        assert_eq!(a.record_seen("t", "bad-signature", t0, seen(3, "cc")), None);
        let p = a.flush(t0 + Duration::from_secs(11));
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].count, 2);
        assert_eq!(p[0].last_source_ip, ip(3));
        assert_eq!(p[0].last_call_id_hash, "cc");
    }
}
