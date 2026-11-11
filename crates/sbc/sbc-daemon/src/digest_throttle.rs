//! Per-username failure backoff for REGISTER digest (`[digest_auth]`).
//!
//! Online password guessing against one username is slowed down whatever
//! address the guesses come from (the per-source rate limit does not stop a
//! distributed attacker).
//!
//! - A username gets [`FREE_FAILURES`] wrong responses for free. Every
//!   further wrong response starts a backoff window: [`BASE_BACKOFF`],
//!   doubling per failure up to [`MAX_BACKOFF`]. While the window is open,
//!   REGISTERs for that username are not verified against its real secret.
//! - It is a backoff, not a lockout: the window always ends by itself, and
//!   attempts refused inside it do not count and do not extend it. An
//!   attacker therefore gets one guess per window and cannot keep an
//!   account closed for longer than [`MAX_BACKOFF`] per guess.
//! - Registered-source exemption: the caller lets the source that holds a
//!   live binding for the AOR through, so a registered phone keeps
//!   refreshing while its username is under attack. The source must be the
//!   binding's exact address and port; the same IP address on another port
//!   is not exempt. As a backstop the exemption has its own budget: after
//!   [`EXEMPT_FAILURES`] wrong responses through it inside one window it
//!   is gone until the next window opens. These failures do not extend the
//!   window either.
//! - Only usernames present in the credentials table get an entry. Every
//!   other username shares one bucket, so names from the wire cannot grow
//!   the table. The table is bounded at [`MAX_TRACKED_USERS`], which is the
//!   entry limit of the credentials table, so every known username fits.
//!   Entries of usernames removed by a reload can still fill it for up to
//!   [`FAILURE_MEMORY`]; a known username that then finds no room (after a
//!   sweep of idle entries) is counted in, and blocked by, one overflow
//!   bucket for known usernames (fail toward throttling). It is separate
//!   from the unknown-username bucket, so spraying invented names never
//!   closes a real account. Overflow is counted
//!   ([`METRIC_OVERFLOW`]). The overflow bucket is never cleared once
//!   created: its count only resets after [`FAILURE_MEMORY`] without an
//!   overflow failure.
//! - The caller answers a throttled request exactly like a wrong password
//!   (see `SipStack::verify_register_digest`), so the response shows
//!   neither that a throttle is active nor whether the username exists.
//!
//! ## Trade-off: targeted lockout of unregistered sources
//!
//! Slowing guesses down and keeping an account reachable pull against each
//! other. Once a username is at the longest window, one wrong response per
//! [`MAX_BACKOFF`] from anywhere keeps it closed to every source that does
//! not hold a binding: a phone that lost its registration (reboot, new
//! address, expiry) cannot register again while the attack lasts, and
//! neither can a new device of that user. Whoever can send from the
//! binding's exact address and port (an on-path attacker, or an off-path
//! UDP spoofer that also guesses the port) can use up the exemption
//! budget, which then closes the username to the phone for the rest of
//! that window; kept up, that lasts until the binding expires. A phone
//! whose NAT mapping moves to another port loses the exemption until it
//! registers again outside a window. This is inherent to
//! AC-7 without a second factor. It is visible, not silent: every trip is
//! audited (`digest:throttle_tripped`) and refused requests are counted
//! (`sbc_digest_verify_throttled_total`); alert on that counter.
//!
//! POAM: POA&M-316 - AC-7 residuals of this backoff:
//! - state is per node: a cluster of `n` nodes allows `n` times the
//!   guesses, and a failover starts from zero;
//! - the registered-source exemption: the binding is matched by exact
//!   source address and port, which UDP does not authenticate. A sender
//!   on the path, or an off-path spoofer that also guesses the port, gets
//!   [`EXEMPT_FAILURES`] extra guesses per window (blind, for the spoofer)
//!   and by spending that budget can keep a registered phone from
//!   refreshing until its binding expires. A phone whose NAT mapping
//!   changes port is not exempt until it re-registers outside a window;
//! - reset on success: a correct response outside a window forgets the
//!   username's failures, so a guesser that stays under [`FREE_FAILURES`]
//!   wrong responses between two successful registrations of the victim
//!   (e.g. 4 guesses per refresh interval) never opens a window;
//! - the thresholds ([`FREE_FAILURES`], [`BASE_BACKOFF`], [`MAX_BACKOFF`],
//!   [`FAILURE_MEMORY`], [`EXEMPT_FAILURES`]) are constants, not
//!   organization-defined configuration.
//!
//! ## NIST 800-53 Rev5: AC-7 (Unsuccessful Logon Attempts), IA-6, SC-5

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Wrong responses a username may give before backoff starts.
pub const FREE_FAILURES: u32 = 5;
/// First backoff window.
pub const BASE_BACKOFF: Duration = Duration::from_secs(1);
/// Longest backoff window.
pub const MAX_BACKOFF: Duration = Duration::from_mins(5);
/// A username without a failure for this long starts from zero again.
pub const FAILURE_MEMORY: Duration = Duration::from_mins(15);
/// Wrong responses the registered-source exemption allows inside one
/// backoff window before it is dropped for that window.
pub const EXEMPT_FAILURES: u32 = 3;
/// Hard cap on usernames tracked individually (SC-5): the entry limit of
/// the credentials table, so every known username fits. An entry exists
/// only after a wrong response for a known username and is about 100 bytes,
/// so the table grows with the usernames under attack, not with the wire.
pub const MAX_TRACKED_USERS: usize = crate::digest_credentials::MAX_ENTRIES;
/// Minimum interval between sweeps of a full table (bounds the sweep cost).
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// `sbc_digest_throttle_overflow_total`: failures of known usernames that
/// were counted in the overflow bucket because the table was full.
pub const METRIC_OVERFLOW: &str = "sbc_digest_throttle_overflow_total";

/// Failure state of one bucket.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Consecutive counted failures.
    failures: u32,
    /// Time of the last counted failure.
    last_failure: Instant,
    /// End of the open backoff window, if any.
    blocked_until: Option<Instant>,
    /// Wrong responses let through by the registered-source exemption
    /// since the window opened.
    exempt_failures: u32,
}

impl Bucket {
    fn new(now: Instant) -> Self {
        Self {
            failures: 0,
            last_failure: now,
            blocked_until: None,
            exempt_failures: 0,
        }
    }

    fn blocked(&self, now: Instant) -> bool {
        self.blocked_until.is_some_and(|until| now < until)
    }

    /// Nothing left to remember: no open window and no recent failure.
    fn idle(&self, now: Instant) -> bool {
        !self.blocked(now) && now.saturating_duration_since(self.last_failure) >= FAILURE_MEMORY
    }

    /// Counts a failure; returns the window it opened, if it opened one.
    fn fail(&mut self, now: Instant) -> Option<Duration> {
        if self.idle(now) {
            self.failures = 0;
        }
        self.failures = self.failures.saturating_add(1);
        self.last_failure = now;
        let over = self
            .failures
            .checked_sub(FREE_FAILURES)
            .filter(|o| *o > 0)?;
        let window = backoff_for(over);
        self.blocked_until = now.checked_add(window);
        // A new window comes with a new exemption budget.
        self.exempt_failures = 0;
        Some(window)
    }
}

/// Backoff after `over` failures past the free ones (`over >= 1`).
fn backoff_for(over: u32) -> Duration {
    let doublings = over.saturating_sub(1).min(31);
    BASE_BACKOFF
        .checked_mul(1u32 << doublings)
        .map_or(MAX_BACKOFF, |d| d.min(MAX_BACKOFF))
}

/// A backoff window that just opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tripped {
    /// Length of the window.
    pub backoff: Duration,
    /// Whether it is a bucket shared by several usernames (the one for
    /// unknown usernames, or the overflow one for known usernames).
    pub shared: bool,
}

/// The failure table. `&mut self`; the caller holds it behind a leaf lock
/// that is never held across `.await` or another lock.
#[derive(Debug)]
pub struct DigestThrottle {
    users: HashMap<Box<str>, Bucket>,
    /// Unknown usernames.
    shared: Option<Bucket>,
    /// Known usernames without an entry while `users` is full. Kept apart
    /// from `shared`: unknown-name spraying must not close real accounts.
    overflow_bucket: Option<Bucket>,
    max_users: usize,
    last_sweep: Option<Instant>,
    /// Failures of known usernames counted in `overflow_bucket`.
    overflow: u64,
}

impl Default for DigestThrottle {
    fn default() -> Self {
        Self::new(MAX_TRACKED_USERS)
    }
}

impl DigestThrottle {
    /// A table tracking at most `max_users` usernames (at least 1, at most
    /// [`MAX_TRACKED_USERS`]).
    #[must_use]
    pub fn new(max_users: usize) -> Self {
        Self {
            users: HashMap::new(),
            shared: None,
            overflow_bucket: None,
            max_users: max_users.clamp(1, MAX_TRACKED_USERS),
            last_sweep: None,
            overflow: 0,
        }
    }

    /// The bucket that decides for `username`: its own entry, else the
    /// overflow bucket (known) or the shared one (unknown).
    fn bucket(&self, username: &str, known: bool) -> Option<&Bucket> {
        if known {
            // A known username without an entry is never judged by the
            // unknown-username bucket, only by the overflow bucket, which
            // exists only after the table was full (SC-5: fail toward
            // throttling, not toward an untracked account).
            self.users.get(username).or(self.overflow_bucket.as_ref())
        } else {
            self.shared.as_ref()
        }
    }

    /// Whether `username` is inside a backoff window. `known` says whether
    /// the credentials table has the username; unknown ones use the shared
    /// bucket, known ones without an entry the overflow bucket.
    #[must_use]
    pub fn is_blocked(&self, username: &str, known: bool, now: Instant) -> bool {
        self.bucket(username, known).is_some_and(|b| b.blocked(now))
    }

    /// Whether the registered-source exemption still applies to `username`
    /// in the open window: fewer than [`EXEMPT_FAILURES`] wrong responses
    /// came through it since the window opened.
    #[cfg(test)]
    #[must_use]
    pub fn exemption_open(&self, username: &str, known: bool) -> bool {
        self.bucket(username, known)
            .is_none_or(|b| b.exempt_failures < EXEMPT_FAILURES)
    }

    fn bucket_mut(&mut self, username: &str, known: bool) -> Option<&mut Bucket> {
        if known {
            match self.users.get_mut(username) {
                Some(b) => Some(b),
                None => self.overflow_bucket.as_mut(),
            }
        } else {
            self.shared.as_mut()
        }
    }

    /// Takes one unit of the exemption budget of `username` for a request
    /// about to be verified through the registered-source exemption;
    /// `false` when the budget of this window is spent. Check and count
    /// are one step, so concurrent requests cannot overshoot the budget.
    /// The caller gives the unit back with [`Self::refund_exemption`]
    /// unless the request turns out to be a wrong response. A wrong
    /// response through the exemption does not extend the window.
    pub fn reserve_exemption(&mut self, username: &str, known: bool) -> bool {
        match self.bucket_mut(username, known) {
            Some(b) if b.exempt_failures >= EXEMPT_FAILURES => false,
            Some(b) => {
                b.exempt_failures = b.exempt_failures.saturating_add(1);
                true
            }
            // No bucket, no window: nothing to spend.
            None => true,
        }
    }

    /// Gives back a unit taken by [`Self::reserve_exemption`]: the request
    /// was not a wrong response.
    pub fn refund_exemption(&mut self, username: &str, known: bool) {
        if let Some(b) = self.bucket_mut(username, known) {
            b.exempt_failures = b.exempt_failures.saturating_sub(1);
        }
    }

    /// Counts a wrong response for `username`. Returns the window when this
    /// failure opened one. Not to be called for a request that was refused
    /// by [`Self::is_blocked`]: such attempts do not extend the window.
    pub fn record_failure(&mut self, username: &str, known: bool, now: Instant) -> Option<Tripped> {
        if known {
            if !self.users.contains_key(username) && self.users.len() >= self.max_users {
                self.sweep(now);
            }
            if let Some(b) = self.users.get_mut(username) {
                return b.fail(now).map(|backoff| Tripped {
                    backoff,
                    shared: false,
                });
            }
            if self.users.len() < self.max_users {
                let mut b = Bucket::new(now);
                let tripped = b.fail(now);
                self.users.insert(username.into(), b);
                return tripped.map(|backoff| Tripped {
                    backoff,
                    shared: false,
                });
            }
            // SC-5: full even after the sweep. Fail toward throttling, in
            // the overflow bucket (which `is_blocked` consults for every
            // known username without an entry), never toward an unbounded
            // table.
            self.overflow = self.overflow.saturating_add(1);
        }
        let slot = if known {
            &mut self.overflow_bucket
        } else {
            &mut self.shared
        };
        let b = slot.get_or_insert(Bucket::new(now));
        b.fail(now).map(|backoff| Tripped {
            backoff,
            shared: true,
        })
    }

    /// Forgets the failures of `username` after a successful
    /// authentication.
    ///
    /// POAM: POA&M-316 - reset on success: a guesser that stays under
    /// [`FREE_FAILURES`] wrong responses between two successful
    /// registrations of the user never opens a window.
    pub fn record_success(&mut self, username: &str) {
        self.users.remove(username);
    }

    /// Usernames tracked individually.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.users.len()
    }

    /// Failures of known usernames that were counted in the overflow
    /// bucket because the table was full ([`METRIC_OVERFLOW`]).
    #[must_use]
    pub fn overflow(&self) -> u64 {
        self.overflow
    }

    /// Drops idle entries; at most once per [`SWEEP_INTERVAL`].
    fn sweep(&mut self, now: Instant) {
        if self
            .last_sweep
            .is_some_and(|t| now.saturating_duration_since(t) < SWEEP_INTERVAL)
        {
            return;
        }
        self.last_sweep = Some(now);
        self.users.retain(|_, b| !b.idle(now));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    /// Fails `user` `n` times at `now`; returns the last result.
    fn fail_n(
        t: &mut DigestThrottle,
        user: &str,
        known: bool,
        n: u32,
        now: Instant,
    ) -> Option<Tripped> {
        let mut last = None;
        for _ in 0..n {
            last = t.record_failure(user, known, now);
        }
        last
    }

    #[test]
    fn free_failures_then_doubling_backoff_up_to_the_cap() {
        let mut t = DigestThrottle::default();
        let mut now = Instant::now();
        assert_eq!(fail_n(&mut t, "alice", true, FREE_FAILURES, now), None);
        assert!(!t.is_blocked("alice", true, now));

        let mut expected = BASE_BACKOFF;
        let mut windows = Vec::new();
        for _ in 0..12 {
            let tripped = t.record_failure("alice", true, now).expect("trips");
            assert!(!tripped.shared);
            assert_eq!(tripped.backoff, expected.min(MAX_BACKOFF));
            windows.push(tripped.backoff);
            // Blocked for the whole window, open again right at its end.
            assert!(t.is_blocked("alice", true, now));
            assert!(t.is_blocked(
                "alice",
                true,
                now + tripped.backoff.saturating_sub(Duration::from_millis(1))
            ));
            now += tripped.backoff;
            assert!(!t.is_blocked("alice", true, now));
            expected = expected.saturating_mul(2);
        }
        assert_eq!(windows.first(), Some(&secs(1)));
        assert_eq!(windows.last(), Some(&MAX_BACKOFF));
        assert!(windows.iter().all(|w| *w <= MAX_BACKOFF));
    }

    /// Not a lockout: the window ends by itself, and one guess per window
    /// is all an attacker gets.
    #[test]
    fn window_always_ends_and_never_exceeds_the_cap() {
        let mut t = DigestThrottle::default();
        let now = Instant::now();
        fail_n(&mut t, "alice", true, 1_000, now);
        assert!(t.is_blocked("alice", true, now));
        assert!(t.is_blocked("alice", true, now + MAX_BACKOFF.saturating_sub(secs(1))));
        assert!(!t.is_blocked("alice", true, now + MAX_BACKOFF));
    }

    #[test]
    fn success_and_idle_time_reset_the_count() {
        let mut t = DigestThrottle::default();
        let now = Instant::now();
        fail_n(&mut t, "alice", true, FREE_FAILURES + 3, now);
        assert!(t.is_blocked("alice", true, now));
        t.record_success("alice");
        assert!(!t.is_blocked("alice", true, now));
        assert_eq!(t.tracked(), 0);
        assert_eq!(fail_n(&mut t, "alice", true, FREE_FAILURES, now), None);

        // Failures older than the memory do not add up.
        let later = now + FAILURE_MEMORY;
        assert_eq!(fail_n(&mut t, "alice", true, FREE_FAILURES, later), None);
        assert_eq!(
            t.record_failure("alice", true, later).map(|x| x.backoff),
            Some(BASE_BACKOFF)
        );
    }

    /// Unknown usernames share one bucket and never get an entry; they do
    /// not block a known username, and a blocked known username does not
    /// block them.
    #[test]
    fn unknown_usernames_share_one_bucket() {
        let mut t = DigestThrottle::default();
        let now = Instant::now();
        for i in 0..FREE_FAILURES {
            assert_eq!(t.record_failure(&format!("ghost{i}"), false, now), None);
        }
        let tripped = t.record_failure("ghost-x", false, now).expect("trips");
        assert!(tripped.shared);
        assert_eq!(t.tracked(), 0, "wire usernames never grow the table");
        assert!(t.is_blocked("never-seen-before", false, now));
        assert!(!t.is_blocked("alice", true, now));
        // The same name, once it is in the credentials table, is its own.
        assert!(!t.is_blocked("ghost-x", true, now));

        fail_n(&mut t, "alice", true, FREE_FAILURES + 1, now + secs(400));
        assert!(t.is_blocked("alice", true, now + secs(400)));
        assert!(!t.is_blocked("ghost-x", false, now + secs(400)));
    }

    /// SEC-010: a known username that does not fit the table is still
    /// throttled, through the overflow bucket, and the unknown-username
    /// bucket is not involved in either direction.
    #[test]
    fn table_is_bounded_and_overflows_into_the_overflow_bucket() {
        let mut t = DigestThrottle::new(4);
        let now = Instant::now();
        for i in 0..4 {
            t.record_failure(&format!("u{i}"), true, now);
        }
        assert_eq!(t.tracked(), 4);
        // Full, nothing idle: further known users are counted together.
        for i in 4..(4 + FREE_FAILURES) {
            assert_eq!(t.record_failure(&format!("u{i}"), true, now), None);
        }
        let tripped = t.record_failure("u99", true, now).expect("shared trips");
        assert!(tripped.shared);
        assert_eq!(t.tracked(), 4);
        assert_eq!(t.overflow(), u64::from(FREE_FAILURES) + 1);
        // A tracked user is still counted on their own.
        assert!(!t.is_blocked("u0", true, now));
        // Every known username without an entry is throttled, whether it
        // failed before or not; unknown usernames are not.
        assert!(t.is_blocked("u99", true, now));
        assert!(t.is_blocked("u4", true, now));
        assert!(t.is_blocked("never-failed", true, now));
        assert!(!t.is_blocked("ghost", false, now));
        assert!(!t.is_blocked("u99", true, now + BASE_BACKOFF));
        // Unknown-name spraying does not close them either.
        fail_n(&mut t, "ghost", false, FREE_FAILURES + 1, now + secs(5));
        assert!(t.is_blocked("ghost", false, now + secs(5)));
        assert!(!t.is_blocked("never-failed", true, now + secs(5)));
        assert!(!t.is_blocked("u0", true, now + secs(5)));

        // Once the entries are idle a sweep makes room again.
        let later = now + FAILURE_MEMORY + secs(1);
        assert_eq!(t.record_failure("new", true, later), None);
        assert_eq!(t.tracked(), 1);

        assert_eq!(DigestThrottle::new(0).max_users, 1);
        assert_eq!(DigestThrottle::new(usize::MAX).max_users, MAX_TRACKED_USERS);
    }

    /// SEC-009: the registered-source exemption has a budget per window.
    /// Failures through it do not extend the window, and a new window
    /// brings a new budget.
    #[test]
    fn exemption_budget_is_per_window() {
        let mut t = DigestThrottle::default();
        let now = Instant::now();
        // No bucket, or no failure through the exemption yet: open.
        assert!(t.exemption_open("alice", true));
        fail_n(&mut t, "alice", true, FREE_FAILURES + 4, now);
        assert!(t.is_blocked("alice", true, now));
        let until = t.users.get("alice").and_then(|b| b.blocked_until);
        // A request that was no wrong response gives its unit back.
        assert!(t.reserve_exemption("alice", true));
        t.refund_exemption("alice", true);
        for i in 1..=EXEMPT_FAILURES {
            assert!(t.exemption_open("alice", true), "{i}");
            assert!(t.reserve_exemption("alice", true), "{i}");
        }
        assert!(!t.exemption_open("alice", true));
        // SEC-015: check and count are one step, so nothing gets past a
        // spent budget; the window did not move.
        assert!(!t.reserve_exemption("alice", true));
        assert!(!t.exemption_open("alice", true));
        let b = t.users.get("alice").copied().expect("entry");
        assert_eq!(b.blocked_until, until);
        assert_eq!(b.failures, FREE_FAILURES + 4);
        // Another user's budget is their own; an untracked one is a no-op.
        assert!(t.exemption_open("bob", true));
        assert!(t.reserve_exemption("bob", true));
        t.refund_exemption("bob", true);
        assert_eq!(t.tracked(), 1);

        // The next counted failure opens a new window with a new budget.
        let later = now + MAX_BACKOFF;
        assert!(!t.is_blocked("alice", true, later));
        assert!(t.record_failure("alice", true, later).is_some());
        assert!(t.exemption_open("alice", true));
    }

    #[test]
    fn backoff_arithmetic_saturates() {
        assert_eq!(backoff_for(1), secs(1));
        assert_eq!(backoff_for(2), secs(2));
        assert_eq!(backoff_for(9), secs(256));
        assert_eq!(backoff_for(10), MAX_BACKOFF);
        assert_eq!(backoff_for(u32::MAX), MAX_BACKOFF);
        let mut b = Bucket {
            failures: u32::MAX - 1,
            last_failure: Instant::now(),
            blocked_until: None,
            exempt_failures: 0,
        };
        let now = Instant::now();
        assert_eq!(b.fail(now), Some(MAX_BACKOFF));
        assert_eq!(b.fail(now), Some(MAX_BACKOFF));
        assert_eq!(b.failures, u32::MAX);
    }
}
