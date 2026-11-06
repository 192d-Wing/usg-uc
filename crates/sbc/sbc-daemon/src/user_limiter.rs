//! Per-user SIP request limiter (`rate_limit.per_user_rps`).
//!
//! Replaces keying on the raw, unauthenticated From user: a spoofed
//! `From: victim` could drain the victim's bucket from anywhere, and the
//! previous limiter rejected every new key once its map was full.
//!
//! - Keys are an authenticated identity ([`UserKey::Auth`], a registered
//!   AOR whose binding matches the request's flow) or the source network
//!   plus the canonical From user ([`UserKey::Unauth`]; IPv4 /32, IPv6 /64).
//! - The bucket map is bounded at [`MAX_KEYS`]; unauthenticated keys may
//!   use at most [`MAX_UNAUTH_KEYS`] of it, so an unauthenticated flood
//!   cannot evict room for authenticated users.
//! - One source network may hold at most [`MAX_UNAUTH_USERS_PER_NET`]
//!   unauthenticated buckets; further From users from it share a single
//!   `(net, "*")` bucket, so rotating From users cannot fill the
//!   unauthenticated share.
//! - When full (after an idle sweep) a new key is allowed untracked and
//!   counted (`overflow`), never rejected: the per-IP transport limiter
//!   still bounds the flood.
//!
//! ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
//!
//! Authenticated keying depends on IA-2 (REGISTER authentication binding
//! the flow); this module does not itself implement IA-2/IA-8.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

/// Hard cap on tracked buckets.
pub const MAX_KEYS: usize = 65_536;
/// Cap on unauthenticated buckets (75% of [`MAX_KEYS`]).
pub const MAX_UNAUTH_KEYS: usize = MAX_KEYS / 4 * 3;
/// Unauthenticated buckets one source network may hold before its
/// further From users are folded into one shared bucket.
pub const MAX_UNAUTH_USERS_PER_NET: usize = 64;
/// User part of the shared per-network overflow bucket.
const FOLDED_USER: &str = "*";
/// Longest user part kept in a key (bytes).
const MAX_KEY_USER_LEN: usize = 64;
/// Minimum interval between full-map sweeps (bounds sweep cost under flood).
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// Minimum interval between overflow warnings.
const OVERFLOW_WARN_INTERVAL: Duration = Duration::from_secs(10);
/// Default burst multiplier (`rate_limit.burst_multiplier` default).
pub const DEFAULT_BURST_MULTIPLIER: f64 = 2.0;

/// Source network of an unauthenticated key: IPv4 /32, IPv6 /64
/// (v4-mapped addresses are unmapped first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourceNet(IpAddr);

impl SourceNet {
    /// The network `ip` belongs to.
    pub fn of(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            v4 @ IpAddr::V4(_) => Self(v4),
            IpAddr::V6(v6) => {
                let s = v6.segments();
                Self(IpAddr::V6(Ipv6Addr::new(
                    s[0], s[1], s[2], s[3], 0, 0, 0, 0,
                )))
            }
        }
    }
}

impl std::fmt::Display for SourceNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            IpAddr::V4(v4) => write!(f, "{v4}/32"),
            IpAddr::V6(v6) => write!(f, "{v6}/64"),
        }
    }
}

/// Limiter key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UserKey {
    /// Authenticated identity (registered AOR bound to the request flow).
    Auth(String),
    /// Unauthenticated: source network plus canonical From user.
    Unauth {
        /// Source network.
        net: SourceNet,
        /// Canonical From user, at most 64 bytes.
        user: String,
    },
}

impl UserKey {
    /// Unauthenticated key for `user` from `ip`. The user is canonicalised
    /// (`uc_types::DialedNumber`) and truncated to 64 bytes.
    pub fn unauth(ip: IpAddr, user: &str) -> Self {
        let mut user = uc_types::DialedNumber::parse(user).into_string();
        let mut end = user.len().min(MAX_KEY_USER_LEN);
        while !user.is_char_boundary(end) {
            end -= 1;
        }
        user.truncate(end);
        Self::Unauth {
            net: SourceNet::of(ip),
            user,
        }
    }

    /// Audit `limit_name`. Carries no raw unauthenticated user, so
    /// attacker-chosen strings never reach the audit record (AU-3).
    pub fn limit_name(&self) -> String {
        match self {
            Self::Auth(aor) => format!("per_user_rps:auth:{aor}"),
            Self::Unauth { net, .. } => format!("per_user_rps:unauth:{net}"),
        }
    }

    fn is_auth(&self) -> bool {
        matches!(self, Self::Auth(_))
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Outcome of [`UserLimiter::check`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserLimit {
    /// Within rate.
    Allow,
    /// Map full: allowed without tracking (counted as overflow).
    AllowUntracked,
    /// Over rate: answer 503 + Retry-After.
    Reject,
}

/// Bounded per-user token-bucket limiter.
#[derive(Debug)]
pub struct UserLimiter {
    rps: u32,
    burst: f64,
    buckets: HashMap<UserKey, Bucket>,
    unauth_keys: usize,
    /// Unauthenticated buckets per source network (entries bounded by
    /// `unauth_keys`).
    per_net: HashMap<SourceNet, usize>,
    last_sweep: Option<Instant>,
    last_overflow_warn: Option<Instant>,
    overflow: u64,
}

impl UserLimiter {
    /// `rps` requests per second, `burst` tokens of headroom per key.
    pub fn new(rps: u32, burst: u32) -> Self {
        Self {
            rps: rps.max(1),
            burst: f64::from(burst.max(1)),
            buckets: HashMap::new(),
            unauth_keys: 0,
            per_net: HashMap::new(),
            last_sweep: None,
            last_overflow_warn: None,
            overflow: 0,
        }
    }

    /// Per-key rate.
    pub fn rps(&self) -> u32 {
        self.rps
    }

    /// Keys allowed untracked because the map was full.
    pub fn overflow(&self) -> u64 {
        self.overflow
    }

    /// Number of tracked keys.
    pub fn tracked_keys(&self) -> usize {
        self.buckets.len()
    }

    fn idle_after(&self) -> Duration {
        Duration::from_secs_f64((2.0 * self.burst / f64::from(self.rps)).max(1.0))
    }

    fn has_room(&self, key: &UserKey) -> bool {
        self.buckets.len() < MAX_KEYS && (key.is_auth() || self.unauth_keys < MAX_UNAUTH_KEYS)
    }

    fn sweep(&mut self, now: Instant) {
        if self
            .last_sweep
            .is_some_and(|t| now.duration_since(t) < SWEEP_INTERVAL)
        {
            return;
        }
        self.last_sweep = Some(now);
        let idle = self.idle_after();
        self.buckets
            .retain(|_, b| now.duration_since(b.last) < idle);
        self.per_net.clear();
        for k in self.buckets.keys() {
            if let UserKey::Unauth { net, .. } = k {
                *self.per_net.entry(*net).or_insert(0) += 1;
            }
        }
        self.unauth_keys = self.per_net.values().sum();
    }

    /// The shared `(net, "*")` key when `key` is a new unauthenticated key
    /// from a network already at [`MAX_UNAUTH_USERS_PER_NET`].
    fn folded(&self, key: &UserKey) -> Option<UserKey> {
        let UserKey::Unauth { net, user } = key else {
            return None;
        };
        if user == FOLDED_USER
            || self.buckets.contains_key(key)
            || self.per_net.get(net).copied().unwrap_or(0) < MAX_UNAUTH_USERS_PER_NET
        {
            return None;
        }
        Some(UserKey::Unauth {
            net: *net,
            user: FOLDED_USER.to_string(),
        })
    }

    /// Consumes one token for `key`. Returns whether an overflow warning
    /// is due alongside the outcome (at most once every 10 s).
    pub fn check(&mut self, key: &UserKey) -> (UserLimit, bool) {
        let folded = self.folded(key);
        let key = folded.as_ref().unwrap_or(key);
        let now = Instant::now();
        if !self.buckets.contains_key(key) {
            if !self.has_room(key) {
                self.sweep(now);
            }
            if !self.has_room(key) {
                self.overflow += 1;
                let warn = self
                    .last_overflow_warn
                    .is_none_or(|t| now.duration_since(t) >= OVERFLOW_WARN_INTERVAL);
                if warn {
                    self.last_overflow_warn = Some(now);
                }
                return (UserLimit::AllowUntracked, warn);
            }
            if let UserKey::Unauth { net, .. } = key {
                self.unauth_keys += 1;
                *self.per_net.entry(*net).or_insert(0) += 1;
            }
            self.buckets.insert(
                key.clone(),
                Bucket {
                    tokens: self.burst,
                    last: now,
                },
            );
        }
        let (rps, burst) = (f64::from(self.rps), self.burst);
        let Some(b) = self.buckets.get_mut(key) else {
            return (UserLimit::Allow, false);
        };
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.tokens = elapsed.mul_add(rps, b.tokens).min(burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            (UserLimit::Allow, false)
        } else {
            (UserLimit::Reject, false)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn spoofed_from_other_net_does_not_drain_victim() {
        let mut l = UserLimiter::new(1, 1);
        let spoof = UserKey::unauth(v4(1), "victim");
        assert_eq!(l.check(&spoof).0, UserLimit::Allow);
        assert_eq!(l.check(&spoof).0, UserLimit::Reject);
        assert_eq!(
            l.check(&UserKey::Auth("sip:victim@d".into())).0,
            UserLimit::Allow
        );
        assert_eq!(
            l.check(&UserKey::unauth(v4(2), "victim")).0,
            UserLimit::Allow
        );
    }

    #[test]
    fn ipv6_keys_share_a_64() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(UserKey::unauth(a, "u"), UserKey::unauth(b, "u"));
        assert_ne!(UserKey::unauth(a, "u"), UserKey::unauth(c, "u"));
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(UserKey::unauth(mapped, "u"), UserKey::unauth(v4(1), "u"));
    }

    #[test]
    fn overflow_allows_untracked_and_counts() {
        let mut l = UserLimiter::new(1, 1);
        for i in 0..MAX_UNAUTH_KEYS {
            // Distinct networks: one network is capped per SEC-002.
            let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000_u32 + u32::try_from(i).unwrap()));
            let k = UserKey::unauth(ip, &format!("u{i}"));
            assert_eq!(l.check(&k).0, UserLimit::Allow);
        }
        let (out, warn) = l.check(&UserKey::unauth(v4(1), "new"));
        assert_eq!(out, UserLimit::AllowUntracked);
        assert!(warn);
        assert_eq!(l.overflow(), 1);
        // Warnings are rate limited.
        assert!(!l.check(&UserKey::unauth(v4(1), "new2")).1);
        // Authenticated users still have room.
        assert_eq!(
            l.check(&UserKey::Auth("sip:a@d".into())).0,
            UserLimit::Allow
        );
        assert_eq!(l.tracked_keys(), MAX_UNAUTH_KEYS + 1);
    }

    #[test]
    fn limit_name_has_no_unauth_user() {
        let k = UserKey::unauth(v4(1), "evil\r\nuser");
        assert_eq!(k.limit_name(), "per_user_rps:unauth:192.0.2.1/32");
        let long = UserKey::unauth(v4(1), &"a".repeat(200));
        assert!(matches!(long, UserKey::Unauth { ref user, .. } if user.len() == 64));
    }
    #[test]
    fn qa_unauth_key_canonicalises_user_and_scopes_v4_per_host() {
        assert_eq!(
            UserKey::unauth(v4(1), "555-1234"),
            UserKey::unauth(v4(1), "(555) 1234")
        );
        assert_eq!(
            UserKey::unauth(v4(1), "%35551234"),
            UserKey::unauth(v4(1), "5551234;phone-context=+1")
        );
        // Global and national forms are different keys (as_str keeps `+`).
        assert_ne!(
            UserKey::unauth(v4(1), "+1555"),
            UserKey::unauth(v4(1), "1555")
        );
        // IPv4 is /32: neighbouring hosts do not share a bucket.
        assert_ne!(UserKey::unauth(v4(1), "u"), UserKey::unauth(v4(2), "u"));
        assert_ne!(UserKey::unauth(v4(1), "u"), UserKey::Auth("u".into()));
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            UserKey::unauth(v6, "x").limit_name(),
            "per_user_rps:unauth:2001:db8::/64"
        );
        assert_eq!(
            UserKey::Auth("sip:a@d".into()).limit_name(),
            "per_user_rps:auth:sip:a@d"
        );
        // Oversize multi-byte user truncates on a char boundary.
        let k = UserKey::unauth(v4(1), &"\u{e9}".repeat(100));
        assert!(matches!(k, UserKey::Unauth { ref user, .. } if user.len() <= 64));
    }

    #[test]
    fn qa_full_map_allows_auth_untracked_and_keeps_limiting_tracked_keys() {
        let mut l = UserLimiter::new(1, 1);
        let first = UserKey::Auth("sip:first@d".into());
        assert_eq!(l.check(&first).0, UserLimit::Allow);
        for i in 1..MAX_KEYS {
            let k = UserKey::Auth(format!("sip:u{i}@d"));
            assert_eq!(l.check(&k).0, UserLimit::Allow);
        }
        assert_eq!(l.tracked_keys(), MAX_KEYS);
        // A new auth key is allowed untracked, never rejected.
        let (out, warn) = l.check(&UserKey::Auth("sip:late@d".into()));
        assert_eq!(out, UserLimit::AllowUntracked);
        assert!(warn);
        assert_eq!(
            l.check(&UserKey::unauth(v4(9), "late")).0,
            UserLimit::AllowUntracked
        );
        assert_eq!(l.overflow(), 2);
        // Untracked keys never gain a bucket.
        assert_eq!(l.tracked_keys(), MAX_KEYS);
        // An already tracked key is still rate limited when the map is full.
        assert_eq!(l.check(&first).0, UserLimit::Reject);
    }

    #[test]
    fn sec002_rotating_from_users_fold_into_one_bucket_per_net() {
        let mut l = UserLimiter::new(1, 1);
        for i in 0..MAX_UNAUTH_USERS_PER_NET {
            assert_eq!(
                l.check(&UserKey::unauth(v4(1), &format!("u{i}"))).0,
                UserLimit::Allow
            );
        }
        // Further users from the same /32 share one bucket and are limited.
        assert_eq!(l.check(&UserKey::unauth(v4(1), "x1")).0, UserLimit::Allow);
        assert_eq!(l.check(&UserKey::unauth(v4(1), "x2")).0, UserLimit::Reject);
        for i in 0..1000 {
            let (out, _) = l.check(&UserKey::unauth(v4(1), &format!("r{i}")));
            assert_eq!(out, UserLimit::Reject);
        }
        assert_eq!(l.tracked_keys(), MAX_UNAUTH_USERS_PER_NET + 1);
        assert_eq!(l.overflow(), 0);
        // Existing users of that net keep their own bucket; other nets
        // are unaffected.
        assert_eq!(l.check(&UserKey::unauth(v4(1), "u0")).0, UserLimit::Reject);
        assert_eq!(l.check(&UserKey::unauth(v4(2), "x1")).0, UserLimit::Allow);
    }

    #[test]
    fn qa_zero_rps_and_burst_are_clamped() {
        let mut l = UserLimiter::new(0, 0);
        assert_eq!(l.rps(), 1);
        let k = UserKey::unauth(v4(1), "u");
        assert_eq!(l.check(&k).0, UserLimit::Allow);
        assert_eq!(l.check(&k).0, UserLimit::Reject);
    }
}
