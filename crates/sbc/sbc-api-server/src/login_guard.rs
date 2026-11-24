//! Admin login guard: per-IP and account failure limits, argon2 slots.
//!
//! Every local-password login goes through [`LoginGuard::admit`] before the
//! argon2 verification runs:
//!
//! 1. Under one short mutex section, expired windows are dropped and the
//!    client-IP bucket and the account bucket are checked. A locked bucket
//!    is answered 429 without taking a verify slot.
//! 2. Still under the mutex, a verify slot is taken with `try_acquire` (no
//!    queue). With none free the login is answered 429 at once and nothing
//!    is counted. With a slot, one failure is **reserved** in both buckets.
//!    The reservation is made before hashing, so concurrent requests cannot
//!    all pass the check while their hashes are in flight.
//! 3. The caller moves the slot into the blocking verification; it is
//!    released when argon2 returns, even if the request is dropped.
//! 4. On success [`LoginGuard::on_success`] refunds the reservation and
//!    resets both consecutive-failure counts. Failures, panics and dropped
//!    requests keep it (fail closed).
//!
//! Windows are fixed: they open at the first failure and a locked bucket
//! stays locked until its window ends (time-bounded, self-releasing).
//!
//! The per-IP key is [`bucket_key`]: an IPv6 client counts per /64 (one
//! host usually controls a whole /64), an IPv4-mapped address as its IPv4.
//!
//! The account bucket is one counter for every local login, whatever
//! username is submitted: uc-auth has a single local account, and keying on
//! the submitted name would add a map to bound and an enumeration oracle.
//! If several local accounts are ever added, key it per account with one
//! overflow bucket for unknown names (as `sbc-daemon`'s `digest_throttle`
//! does).
//!
//! ## NIST 800-53 Rev5: AC-7 (Unsuccessful Logon Attempts), SC-5 (Denial-of-Service Protection)

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tracing::warn;

/// Failed logins one client IP may reserve per [`LOCKOUT_WINDOW`].
pub const IP_MAX_FAILURES: u32 = 5;

/// Failed local logins, from all sources together, per [`LOCKOUT_WINDOW`]
/// before every local login is locked.
pub const ACCOUNT_MAX_FAILURES: u32 = 10;

// One source can never lock the account on its own: tripping the account
// bucket takes at least two client IPs (IPv6: two /64s).
// POAM: POA&M-421 (AC-7) two or more sources can keep the local admin
// password login locked, one window after another; OIDC and API keys are
// not affected.
const _: () = assert!(ACCOUNT_MAX_FAILURES > IP_MAX_FAILURES);

/// Length of both failure windows (AC-7 b: time-bounded delay).
pub const LOCKOUT_WINDOW: Duration = Duration::from_mins(15);

/// Cap on per-IP entries. Beyond it new IPs share one overflow bucket
/// (POA&M-422).
pub const MAX_TRACKED_IPS: usize = 4096;

/// Most concurrent argon2 verifications. Worst-case memory is
/// `slots x m_cost` of the stored hash: 4 x 19 MiB (argon2 default
/// parameters) = 76 MiB, inside the 256 Mi sbc-api pod limit. For a stored
/// hash with a larger `m_cost`, [`verify_slots_for_m_cost`] lowers the
/// count. The 500m CPU limit means more slots would add no throughput.
// POAM: POA&M-422 (SC-5) the slot count is fixed at startup from the stored
// hash's m_cost; a single hash above VERIFY_MEMORY_BUDGET_KIB still exceeds
// the budget with one slot. Beyond MAX_TRACKED_IPS new IPs share one
// overflow bucket.
pub const MAX_CONCURRENT_VERIFY: usize = 4;

/// Memory budget for concurrent argon2 verifications, in KiB (96 MiB of the
/// 256 Mi pod limit).
pub const VERIFY_MEMORY_BUDGET_KIB: u64 = 96 * 1024;

/// Reads `m` (memory cost, KiB) from an argon2 PHC string such as
/// `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`. `None` if absent or
/// malformed.
#[must_use]
pub fn argon2_m_cost_kib(phc: &str) -> Option<u64> {
    phc.split('$')
        .flat_map(|field| field.split(','))
        .find_map(|kv| kv.strip_prefix("m="))
        .and_then(|m| m.parse::<u64>().ok())
}

/// Verify slots so that `slots x m_cost` stays within
/// [`VERIFY_MEMORY_BUDGET_KIB`]: `clamp(budget / m_cost, 1,
/// MAX_CONCURRENT_VERIFY)`. An unknown or zero `m_cost` (a hash argon2
/// cannot use, so verification fails without allocating) keeps the maximum.
#[must_use]
pub fn verify_slots_for_m_cost(m_cost_kib: Option<u64>) -> usize {
    m_cost_kib
        .and_then(|m| VERIFY_MEMORY_BUDGET_KIB.checked_div(m))
        .map_or(MAX_CONCURRENT_VERIFY, |n| {
            usize::try_from(n)
                .unwrap_or(usize::MAX)
                .clamp(1, MAX_CONCURRENT_VERIFY)
        })
}

/// Per-IP table key: IPv6 masked to its /64, IPv4-mapped IPv6 as IPv4,
/// IPv4 unchanged.
#[must_use]
pub fn bucket_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or_else(
            || IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
            IpAddr::V4,
        ),
    }
}

/// Tunables for [`LoginGuard`]. Production uses [`Default`] (the
/// constants above); tests shrink the tables.
#[derive(Debug, Clone)]
pub struct LoginGuardConfig {
    /// Concurrent argon2 verification slots.
    pub max_concurrent_verify: usize,
    /// Failures per client IP per window.
    pub ip_max_failures: u32,
    /// Failures across all sources per window.
    pub account_max_failures: u32,
    /// Fixed window length for both buckets.
    pub window: Duration,
    /// Per-IP table capacity.
    pub max_tracked_ips: usize,
}

impl Default for LoginGuardConfig {
    fn default() -> Self {
        Self {
            max_concurrent_verify: MAX_CONCURRENT_VERIFY,
            ip_max_failures: IP_MAX_FAILURES,
            account_max_failures: ACCOUNT_MAX_FAILURES,
            window: LOCKOUT_WINDOW,
            max_tracked_ips: MAX_TRACKED_IPS,
        }
    }
}

/// Outcome of [`LoginGuard::admit`].
#[derive(Debug)]
pub enum Admission {
    /// One failure is reserved; run the verification while holding the slot.
    Admitted(OwnedSemaphorePermit),
    /// The client IP or the account is locked; retry after this many
    /// seconds (rounded up, at least 1).
    Locked {
        /// Seconds until the longest relevant lock ends.
        retry_after_secs: u64,
    },
    /// Every verify slot is taken; nothing was counted.
    Busy,
}

/// One fixed failure window.
#[derive(Debug, Clone, Copy)]
struct Window {
    failures: u32,
    started: Instant,
}

impl Window {
    fn expired(&self, now: Instant, window: Duration) -> bool {
        now.saturating_duration_since(self.started) >= window
    }

    /// Seconds left in the window, rounded up, at least 1.
    fn retry_after_secs(&self, now: Instant, window: Duration) -> u64 {
        let left = window.saturating_sub(now.saturating_duration_since(self.started));
        (left.as_secs() + u64::from(left.subsec_nanos() > 0)).max(1)
    }
}

/// Which IP bucket a client maps to.
#[derive(Clone, Copy)]
enum IpSlot {
    /// Has (or will get) its own entry.
    Own,
    /// Table full of live entries: shares the overflow bucket.
    Overflow,
}

#[derive(Debug, Default)]
struct Tables {
    /// Per-IP windows. `std` `RandomState` is a keyed hasher, so client
    /// IPs cannot be chosen to collide (SC-5).
    ips: HashMap<IpAddr, Window>,
    /// Oldest `started` in `ips` (a lower bound; stale after removals),
    /// so a full table is scanned only when something can have expired.
    oldest: Option<Instant>,
    /// Shared by IPs that arrive while `ips` is full of live entries.
    overflow: Option<Window>,
    /// All local logins.
    account: Option<Window>,
}

/// Login failure limits and the argon2 slot pool. One per process.
// POAM: POA&M-420 (AC-7, SC-5) limits are per sbc-api replica and cleared
// on restart; with N replicas a client gets N x the per-window attempts.
#[derive(Debug)]
pub struct LoginGuard {
    cfg: LoginGuardConfig,
    slots: Arc<Semaphore>,
    tables: Mutex<Tables>,
}

impl Default for LoginGuard {
    fn default() -> Self {
        Self::new(LoginGuardConfig::default())
    }
}

impl LoginGuard {
    /// Builds a guard with empty tables and `cfg.max_concurrent_verify`
    /// slots.
    #[must_use]
    pub fn new(cfg: LoginGuardConfig) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(cfg.max_concurrent_verify)),
            cfg,
            tables: Mutex::new(Tables::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Tables> {
        self.tables.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Checks the locks, takes a verify slot and reserves one failure for
    /// `client_ip` and the account, or says why not. Never waits.
    pub fn admit(&self, client_ip: IpAddr) -> Admission {
        let key = bucket_key(client_ip);
        let now = Instant::now();
        let window = self.cfg.window;
        let mut t = self.lock();

        if t.account.is_some_and(|w| w.expired(now, window)) {
            t.account = None;
        }
        if t.overflow.is_some_and(|w| w.expired(now, window)) {
            t.overflow = None;
        }

        let slot = self.ip_slot(&mut t, key, now);
        let ip_window = match slot {
            IpSlot::Own => t.ips.get(&key).copied(),
            IpSlot::Overflow => t.overflow,
        };

        // AC-7: refuse while either bucket is locked, without counting.
        let ip_locked = ip_window.filter(|w| w.failures >= self.cfg.ip_max_failures);
        let account_locked = t
            .account
            .filter(|w| w.failures >= self.cfg.account_max_failures);
        if ip_locked.is_some() || account_locked.is_some() {
            let retry_after_secs = ip_locked
                .into_iter()
                .chain(account_locked)
                .map(|w| w.retry_after_secs(now, window))
                .max()
                .unwrap_or(1);
            return Admission::Locked { retry_after_secs };
        }

        // SC-5: bounded argon2 concurrency; overload is refused, not queued.
        // Taken under the mutex (try_acquire never blocks), so a failure is
        // reserved only together with a slot.
        let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() else {
            return Admission::Busy;
        };

        // Reserve before hashing.
        let ip_failures = match slot {
            IpSlot::Own => {
                let w = t.ips.entry(key).or_insert(Window {
                    failures: 0,
                    started: now,
                });
                w.failures += 1;
                let n = w.failures;
                if t.oldest.is_none_or(|o| now < o) {
                    t.oldest = Some(now);
                }
                n
            }
            IpSlot::Overflow => {
                let w = t.overflow.get_or_insert(Window {
                    failures: 0,
                    started: now,
                });
                w.failures += 1;
                w.failures
            }
        };
        let account = t.account.get_or_insert(Window {
            failures: 0,
            started: now,
        });
        account.failures += 1;
        let account_failures = account.failures;
        drop(t);

        if ip_failures == self.cfg.ip_max_failures {
            let scope = match slot {
                IpSlot::Own => "ip",
                IpSlot::Overflow => "ip-overflow",
            };
            warn!(%client_ip, scope, "admin login lockout engaged");
        }
        if account_failures == self.cfg.account_max_failures {
            warn!(%client_ip, scope = "account", "admin login lockout engaged");
        }
        Admission::Admitted(permit)
    }

    /// Picks the bucket for `ip`, dropping its own expired entry and, when
    /// the table is full, any expired entries. O(1) unless the table is
    /// full and something can have expired.
    fn ip_slot(&self, t: &mut Tables, ip: IpAddr, now: Instant) -> IpSlot {
        let window = self.cfg.window;
        match t.ips.get(&ip) {
            Some(w) if !w.expired(now, window) => return IpSlot::Own,
            Some(_) => {
                t.ips.remove(&ip);
                return IpSlot::Own;
            }
            None => {}
        }
        if t.ips.len() < self.cfg.max_tracked_ips {
            return IpSlot::Own;
        }
        if t.oldest
            .is_some_and(|o| now.saturating_duration_since(o) >= window)
        {
            let mut oldest = None;
            t.ips.retain(|_, w| {
                let keep = !w.expired(now, window);
                if keep && oldest.is_none_or(|o| w.started < o) {
                    oldest = Some(w.started);
                }
                keep
            });
            t.oldest = oldest;
        }
        if t.ips.len() < self.cfg.max_tracked_ips {
            IpSlot::Own
        } else {
            IpSlot::Overflow
        }
    }

    /// A verification for `client_ip` succeeded: refund its reservation and
    /// reset the consecutive-failure counts. The shared overflow bucket is
    /// left alone, so one success cannot clear other sources' failures.
    pub fn on_success(&self, client_ip: IpAddr) {
        let key = bucket_key(client_ip);
        let mut t = self.lock();
        t.ips.remove(&key);
        t.account = None;
    }

    /// Live failure count for the entry of `ip`'s [`bucket_key`] (`None` if
    /// untracked or expired). Overflow-routed IPs read `None`.
    #[cfg(test)]
    pub(crate) fn ip_failures(&self, ip: IpAddr) -> Option<u32> {
        let now = Instant::now();
        self.lock()
            .ips
            .get(&bucket_key(ip))
            .filter(|w| !w.expired(now, self.cfg.window))
            .map(|w| w.failures)
    }

    /// Live account failure count (0 when no window is open).
    #[cfg(test)]
    pub(crate) fn account_failures(&self) -> u32 {
        let now = Instant::now();
        self.lock()
            .account
            .filter(|w| !w.expired(now, self.cfg.window))
            .map_or(0, |w| w.failures)
    }

    /// Entries in the per-IP table (excludes the overflow bucket).
    #[cfg(test)]
    pub(crate) fn tracked_ips(&self) -> usize {
        self.lock().ips.len()
    }
}

#[cfg(test)]
// Test code: unwrap/expect/panic are the assertions.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{
        ACCOUNT_MAX_FAILURES, IP_MAX_FAILURES, LOCKOUT_WINDOW, LoginGuard, LoginGuardConfig,
        MAX_CONCURRENT_VERIFY, MAX_TRACKED_IPS, VERIFY_MEMORY_BUDGET_KIB, argon2_m_cost_kib,
        bucket_key, verify_slots_for_m_cost,
    };
    use crate::handlers::auth::{LoginRequest, LoginVerifier, login_with};
    use axum::http::{HeaderMap, StatusCode};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    const _: () = assert!(ACCOUNT_MAX_FAILURES > IP_MAX_FAILURES);

    /// Rejects every password; counts calls.
    #[derive(Default)]
    struct RejectAll(AtomicUsize);

    impl LoginVerifier for RejectAll {
        fn login(&self, _username: &str, _password: &str) -> Option<String> {
            self.0.fetch_add(1, Ordering::SeqCst);
            None
        }
        fn token_ttl_secs(&self) -> u64 {
            3600
        }
    }

    fn bad_login() -> LoginRequest {
        serde_json::from_value(serde_json::json!({
            "username": "admin",
            "password": format!("invalid-{}", std::process::id()),
        }))
        .unwrap()
    }

    fn nth_ip(n: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(0xC612_0000 + n)) // 198.18.0.0/15
    }

    async fn attempt(v: &Arc<RejectAll>, g: &LoginGuard, peer: IpAddr) -> StatusCode {
        login_with(v, g, &[], peer, &HeaderMap::new(), bad_login())
            .await
            .status()
    }

    /// Small table, account bucket out of the way.
    fn small_cfg() -> LoginGuardConfig {
        LoginGuardConfig {
            max_tracked_ips: 8,
            account_max_failures: 10_000,
            ..LoginGuardConfig::default()
        }
    }

    fn small_table() -> (LoginGuardConfig, LoginGuard) {
        (small_cfg(), LoginGuard::new(small_cfg()))
    }

    #[tokio::test]
    async fn qa_ip_table_is_bounded_and_overflows() {
        let v = Arc::new(RejectAll::default());
        let (cfg, guard) = small_table();
        let ip_max = usize::try_from(cfg.ip_max_failures).unwrap();

        let mut unauthorized = 0usize;
        let mut locked = 0usize;
        for n in 0..100 {
            match attempt(&v, &guard, nth_ip(n)).await {
                StatusCode::UNAUTHORIZED => unauthorized += 1,
                StatusCode::TOO_MANY_REQUESTS => locked += 1,
                other => panic!("unexpected status {other}"),
            }
        }
        assert!(guard.tracked_ips() <= 8, "tracked {}", guard.tracked_ips());
        // 8 own entries, then one shared overflow bucket with the IP limit.
        assert_eq!(unauthorized, 8 + ip_max);
        assert_eq!(locked, 100 - 8 - ip_max);
        assert_eq!(v.0.load(Ordering::SeqCst), 8 + ip_max);

        // A tracked IP keeps its own bucket; a new IP lands in the locked
        // overflow bucket.
        assert_eq!(guard.ip_failures(nth_ip(0)), Some(1));
        assert_eq!(
            attempt(&v, &guard, nth_ip(0)).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            attempt(&v, &guard, nth_ip(500)).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert!(guard.tracked_ips() <= 8);
    }

    #[tokio::test(start_paused = true)]
    async fn qa_expired_entries_evicted_when_full() {
        let v = Arc::new(RejectAll::default());
        let (cfg, guard) = small_table();
        for n in 0..8 {
            assert_eq!(
                attempt(&v, &guard, nth_ip(n)).await,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(guard.tracked_ips(), 8);

        tokio::time::advance(cfg.window + Duration::from_secs(1)).await;

        // Each new IP gets its own entry (a shared overflow bucket would
        // lock after ip_max_failures in total).
        for n in 100..108 {
            for _ in 0..cfg.ip_max_failures {
                assert_eq!(
                    attempt(&v, &guard, nth_ip(n)).await,
                    StatusCode::UNAUTHORIZED
                );
            }
            assert_eq!(guard.ip_failures(nth_ip(n)), Some(cfg.ip_max_failures));
        }
        assert!(guard.tracked_ips() <= 8);
        for n in 0..8 {
            assert_eq!(guard.ip_failures(nth_ip(n)), None, "expired entry evicted");
        }
    }

    #[test]
    fn account_threshold_exceeds_ip_threshold() {
        let c = LoginGuardConfig::default();
        assert!(c.account_max_failures > c.ip_max_failures);
        assert_eq!(c.ip_max_failures, IP_MAX_FAILURES);
        assert_eq!(c.account_max_failures, ACCOUNT_MAX_FAILURES);
        assert_eq!(c.window, LOCKOUT_WINDOW);
        assert_eq!(c.max_tracked_ips, MAX_TRACKED_IPS);
        assert_eq!(c.max_concurrent_verify, MAX_CONCURRENT_VERIFY);
        // Decided values (decisions.md).
        assert_eq!(IP_MAX_FAILURES, 5);
        assert_eq!(ACCOUNT_MAX_FAILURES, 10);
        assert_eq!(LOCKOUT_WINDOW, Duration::from_mins(15));
        assert_eq!(MAX_TRACKED_IPS, 4096);
        // Sizing: slots x argon2 default m_cost (19 MiB) stays well under
        // the 256 Mi pod limit.
        const { assert!(MAX_CONCURRENT_VERIFY >= 1) };
        const { assert!(MAX_CONCURRENT_VERIFY * 19 <= 96, "slots x 19 MiB") };
    }

    // ---- fix round 1 ------------------------------------------------------

    fn v6(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn bucket_key_masks_ipv6_to_64_and_unmaps_ipv4() {
        assert_eq!(
            bucket_key(v6("2001:db8:1:2:aaaa:bbbb:cccc:dddd")),
            v6("2001:db8:1:2::")
        );
        assert_eq!(bucket_key(v6("::ffff:192.0.2.1")), v6("192.0.2.1"));
        assert_eq!(bucket_key(v6("192.0.2.1")), v6("192.0.2.1"));
        assert_ne!(
            bucket_key(v6("2001:db8:1:2::1")),
            bucket_key(v6("2001:db8:1:3::1"))
        );
    }

    /// SEC-001: addresses from one IPv6 /64 share one IP bucket, so they
    /// cannot reach the account threshold on their own.
    #[tokio::test]
    async fn one_ipv6_64_cannot_lock_account() {
        let v = Arc::new(RejectAll::default());
        let guard = LoginGuard::default();
        let mut unauthorized = 0u32;
        for n in 1..=ACCOUNT_MAX_FAILURES {
            match attempt(&v, &guard, v6(&format!("2001:db8:1:2::{n:x}"))).await {
                StatusCode::UNAUTHORIZED => unauthorized += 1,
                StatusCode::TOO_MANY_REQUESTS => {}
                other => panic!("unexpected status {other}"),
            }
        }
        assert_eq!(unauthorized, IP_MAX_FAILURES);
        assert_eq!(guard.account_failures(), IP_MAX_FAILURES);
        assert_eq!(guard.tracked_ips(), 1);
        assert_eq!(
            attempt(&v, &guard, v6("2001:db8:1:3::1")).await,
            StatusCode::UNAUTHORIZED,
            "another /64 is not locked out"
        );
    }

    #[tokio::test]
    async fn ipv4_mapped_shares_ipv4_bucket() {
        let v = Arc::new(RejectAll::default());
        let guard = LoginGuard::default();
        for i in 0..IP_MAX_FAILURES {
            let peer = if i % 2 == 0 {
                v6("192.0.2.9")
            } else {
                v6("::ffff:192.0.2.9")
            };
            assert_eq!(attempt(&v, &guard, peer).await, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(
            attempt(&v, &guard, v6("::ffff:192.0.2.9")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(guard.ip_failures(v6("192.0.2.9")), Some(IP_MAX_FAILURES));
    }

    #[test]
    fn argon2_m_cost_parsed_from_phc() {
        let default_hash = uc_auth::hash_password("sizing-test").unwrap();
        assert_eq!(argon2_m_cost_kib(&default_hash), Some(19 * 1024));
        assert_eq!(
            argon2_m_cost_kib("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"),
            Some(65536)
        );
        assert_eq!(argon2_m_cost_kib("not-a-phc-hash"), None);
        assert_eq!(argon2_m_cost_kib("$argon2id$v=19$m=lots,t=2,p=1$x$y"), None);
        assert_eq!(argon2_m_cost_kib(""), None);
    }

    /// SEC-002 / PERF-001: slots x `m_cost` stays within the budget.
    #[test]
    fn verify_slots_sized_from_m_cost() {
        assert_eq!(verify_slots_for_m_cost(None), MAX_CONCURRENT_VERIFY);
        assert_eq!(verify_slots_for_m_cost(Some(0)), MAX_CONCURRENT_VERIFY);
        assert_eq!(verify_slots_for_m_cost(Some(19 * 1024)), 4);
        assert_eq!(verify_slots_for_m_cost(Some(32 * 1024)), 3);
        assert_eq!(verify_slots_for_m_cost(Some(48 * 1024)), 2);
        assert_eq!(verify_slots_for_m_cost(Some(64 * 1024)), 1);
        assert_eq!(verify_slots_for_m_cost(Some(256 * 1024)), 1, "never 0");
        assert_eq!(verify_slots_for_m_cost(Some(1)), MAX_CONCURRENT_VERIFY);
        for m in [1u64, 1024, 19 * 1024, 24 * 1024, 40 * 1024, 96 * 1024] {
            let slots = u64::try_from(verify_slots_for_m_cost(Some(m))).unwrap();
            assert!(slots * m <= VERIFY_MEMORY_BUDGET_KIB, "m={m}");
        }
    }
}
