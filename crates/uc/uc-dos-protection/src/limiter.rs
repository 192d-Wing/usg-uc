//! Token bucket rate limiter.

use crate::key::{DEFAULT_IPV6_PREFIX_LEN, source_key};
use crate::{DEFAULT_BLOCK_DURATION_SECS, DEFAULT_BURST, DEFAULT_RPS};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Rate limit action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitAction {
    /// Allow the request.
    Allow,
    /// Throttle the request (delay it).
    Throttle {
        /// Suggested delay in milliseconds.
        delay_ms: u64,
    },
    /// Reject the request.
    Reject,
    /// Block the source.
    Block {
        /// Duration to block.
        duration_secs: u64,
    },
}

impl RateLimitAction {
    /// Returns whether this action allows the request.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow | Self::Throttle { .. })
    }

    /// Returns whether this action rejects the request.
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Reject | Self::Block { .. })
    }
}

/// Outcome of [`RateLimiter::check_outcome`]: the action plus whether this
/// call moved the source into the blocked state.
///
/// The transition flag lets callers emit a single state-change audit record
/// (AU-12) instead of one per dropped packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckOutcome {
    /// The action to take for this request.
    pub action: RateLimitAction,
    /// `true` only on the call that inserted the block.
    pub block_started: bool,
}

/// Default cap on simultaneously blocked sources.
pub const DEFAULT_MAX_BLOCKED_SOURCES: usize = 16_384;

/// Default cap on per-source token buckets.
pub const DEFAULT_MAX_TRACKED_SOURCES: usize = 65_536;

/// Default rate of the shared overflow bucket (requests per second).
pub const DEFAULT_OVERFLOW_RPS: u32 = 1_000;

/// Default burst of the shared overflow bucket.
pub const DEFAULT_OVERFLOW_BURST: u32 = 2_000;

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimiterConfig {
    /// Maximum requests per second.
    pub rps: u32,
    /// Burst size (max tokens).
    pub burst: u32,
    /// Block duration when threshold exceeded.
    pub block_duration_secs: u64,
    /// Threshold multiplier for blocking (e.g., 2.0 = block at 2x RPS).
    pub block_threshold_multiplier: f64,
    /// Whether to track per-IP or globally. A global limiter never blocks.
    pub per_ip: bool,
    /// IPv6 prefix length per-source state is keyed on (see
    /// [`crate::source_key`]).
    pub ipv6_prefix_len: u8,
    /// Cap on per-source token buckets. New sources past the cap share the
    /// overflow bucket.
    pub max_tracked_sources: usize,
    /// Cap on simultaneously blocked sources. Past it, offenders are
    /// rejected without being added to the block map.
    pub max_blocked_sources: usize,
    /// Rate of the shared overflow bucket.
    pub overflow_rps: u32,
    /// Burst of the shared overflow bucket.
    pub overflow_burst: u32,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            rps: DEFAULT_RPS,
            burst: DEFAULT_BURST,
            block_duration_secs: DEFAULT_BLOCK_DURATION_SECS,
            block_threshold_multiplier: 2.0,
            per_ip: true,
            ipv6_prefix_len: DEFAULT_IPV6_PREFIX_LEN,
            max_tracked_sources: DEFAULT_MAX_TRACKED_SOURCES,
            max_blocked_sources: DEFAULT_MAX_BLOCKED_SOURCES,
            overflow_rps: DEFAULT_OVERFLOW_RPS,
            overflow_burst: DEFAULT_OVERFLOW_BURST,
        }
    }
}

impl RateLimiterConfig {
    /// Creates a new configuration.
    pub fn new(rps: u32, burst: u32) -> Self {
        Self {
            rps,
            burst,
            ..Default::default()
        }
    }

    /// Sets the block duration.
    #[must_use]
    pub fn with_block_duration(mut self, secs: u64) -> Self {
        self.block_duration_secs = secs;
        self
    }

    /// Sets the block threshold multiplier.
    #[must_use]
    pub fn with_block_threshold(mut self, multiplier: f64) -> Self {
        self.block_threshold_multiplier = multiplier;
        self
    }

    /// Sets per-IP tracking.
    #[must_use]
    pub fn with_per_ip(mut self, per_ip: bool) -> Self {
        self.per_ip = per_ip;
        self
    }

    /// Sets the IPv6 keying prefix length.
    #[must_use]
    pub fn with_ipv6_prefix_len(mut self, len: u8) -> Self {
        self.ipv6_prefix_len = len;
        self
    }

    /// Sets the per-source bucket cap.
    #[must_use]
    pub fn with_max_tracked_sources(mut self, max: usize) -> Self {
        self.max_tracked_sources = max;
        self
    }

    /// Sets the blocked-source cap.
    #[must_use]
    pub fn with_max_blocked_sources(mut self, max: usize) -> Self {
        self.max_blocked_sources = max;
        self
    }

    /// Sets the overflow bucket rate and burst.
    #[must_use]
    pub fn with_overflow(mut self, rps: u32, burst: u32) -> Self {
        self.overflow_rps = rps;
        self.overflow_burst = burst;
        self
    }
}

/// Token bucket state.
#[derive(Debug)]
struct TokenBucket {
    /// Available tokens.
    tokens: f64,
    /// Last update time.
    last_update: Instant,
    /// Request count in current window.
    request_count: u32,
    /// Window start time.
    window_start: Instant,
    /// Rejections since the last [`RateLimiter::drain_rejections`].
    rejected: u32,
}

/// Cap on per-user token buckets ([`KeyedRateLimiter`]). Bounds memory
/// against identity-rotation floods.
const MAX_TRACKED_SOURCES: usize = 65_536;

/// A bucket idle this long is evicted under memory pressure (a quiet
/// returning source simply starts with a full bucket again).
const BUCKET_IDLE_TIMEOUT: Duration = Duration::from_mins(1);

/// Minimum spacing between idle-bucket sweeps, so a flood of new sources at
/// capacity cannot trigger an O(n) scan on every packet.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

impl TokenBucket {
    /// Creates a new token bucket.
    fn new(burst: u32) -> Self {
        let now = Instant::now();
        Self {
            tokens: burst as f64,
            last_update: now,
            request_count: 0,
            window_start: now,
            rejected: 0,
        }
    }

    /// Whether this bucket has seen no traffic for `idle`.
    fn is_idle(&self, idle: Duration) -> bool {
        self.last_update.elapsed() >= idle
    }

    /// Updates the token bucket and tries to consume a token.
    fn try_consume(&mut self, rps: u32, burst: u32) -> (bool, f64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update);

        // Add tokens based on elapsed time
        let tokens_to_add = elapsed.as_secs_f64() * rps as f64;
        self.tokens = (self.tokens + tokens_to_add).min(burst as f64);
        self.last_update = now;

        // Update request count (rolling window)
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.request_count = 0;
            self.window_start = now;
        }
        self.request_count = self.request_count.saturating_add(1);

        // Try to consume a token
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            (true, self.request_count as f64)
        } else {
            self.rejected = self.rejected.saturating_add(1);
            (false, self.request_count as f64)
        }
    }

    /// Returns the current token count.
    fn token_count(&self) -> f64 {
        self.tokens
    }
}

/// Block entry.
#[derive(Debug)]
struct BlockEntry {
    /// When the block expires.
    expires_at: Instant,
    /// Packets dropped while blocked since the last sweep (AU-12: sizes
    /// a blocked flood; a plain integer add on the hot path).
    dropped: u64,
}

impl BlockEntry {
    /// Creates a new block entry.
    fn new(duration: Duration) -> Self {
        Self {
            expires_at: Instant::now() + duration,
            dropped: 0,
        }
    }

    /// Returns whether the block has expired.
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Returns the remaining duration.
    fn remaining(&self) -> Duration {
        self.expires_at.saturating_duration_since(Instant::now())
    }
}

/// Token bucket rate limiter keyed by an opaque identity such as a SIP user
/// (`rate_limit.per_user_rps`), one bucket per key.
///
/// Unlike [`RateLimiter`] it has no block list: a user over its rate is
/// rejected for that request only, so a legitimate but chatty endpoint is
/// slowed, not locked out. The key map is bounded like the per-IP map.
#[derive(Debug)]
pub struct KeyedRateLimiter {
    config: RateLimiterConfig,
    buckets: HashMap<String, TokenBucket>,
    last_sweep: Instant,
}

impl KeyedRateLimiter {
    /// Creates a keyed limiter allowing `rps` requests per second with
    /// `burst` tokens of headroom per key.
    pub fn new(rps: u32, burst: u32) -> Self {
        Self {
            config: RateLimiterConfig::new(rps, burst),
            buckets: HashMap::new(),
            last_sweep: Instant::now(),
        }
    }

    /// Consumes one token for `key`, returning `Allow` or `Reject`.
    pub fn check(&mut self, key: &str) -> RateLimitAction {
        if !self.buckets.contains_key(key) && self.buckets.len() >= MAX_TRACKED_SOURCES {
            if self.last_sweep.elapsed() >= SWEEP_INTERVAL {
                self.buckets
                    .retain(|_, bucket| !bucket.is_idle(BUCKET_IDLE_TIMEOUT));
                self.last_sweep = Instant::now();
            }
            if self.buckets.len() >= MAX_TRACKED_SOURCES {
                return RateLimitAction::Reject;
            }
        }
        let bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(self.config.burst));
        if bucket.try_consume(self.config.rps, self.config.burst).0 {
            RateLimitAction::Allow
        } else {
            RateLimitAction::Reject
        }
    }

    /// Number of keys currently tracked.
    pub fn tracked_keys(&self) -> usize {
        self.buckets.len()
    }

    /// The configured per-key rate (requests per second).
    pub fn rps(&self) -> u32 {
        self.config.rps
    }
}

/// One report from [`RateLimiter::sweep_with`]; keys are [`source_key`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepEvent {
    /// Over-rate rejections from a tracked source since the last sweep.
    Rejected(IpAddr, u64),
    /// Packets dropped while the source was blocked since the last sweep.
    BlockedDrops(IpAddr, u64),
    /// The source's block expired and was removed.
    Unblocked(IpAddr),
}

/// Token bucket rate limiter.
///
/// Per-source mode (`per_ip`) keys state with [`source_key`], caps both the
/// bucket map and the block map, and sends new sources past the bucket cap to
/// one shared overflow bucket. Global mode (`!per_ip`) uses one bucket and
/// never blocks: a global rejection cannot be attributed to the source that
/// happened to trip it.
///
/// ## NIST 800-53 Rev5: SC-5, SC-5(2)
#[derive(Debug)]
pub struct RateLimiter {
    /// Configuration.
    config: RateLimiterConfig,
    /// Per-source token buckets, keyed by [`source_key`].
    buckets: HashMap<IpAddr, TokenBucket>,
    /// Global token bucket (if not per-IP).
    global_bucket: TokenBucket,
    /// Shared bucket for new sources once `buckets` is full.
    overflow_bucket: TokenBucket,
    /// Blocked sources, keyed by [`source_key`]. Bounded by
    /// `max_blocked_sources`.
    blocked: HashMap<IpAddr, BlockEntry>,
    /// Last time the per-IP bucket map was swept for idle entries.
    last_sweep: Instant,
    /// Last time a full block map was swept for expired entries.
    last_block_sweep: Instant,
    /// Global-bucket rejections since the last take.
    global_rejected: u64,
    /// Overflow-bucket rejections since the last take.
    overflow_rejected: u64,
}

impl RateLimiter {
    /// Creates a new rate limiter.
    pub fn new(config: RateLimiterConfig) -> Self {
        let global_bucket = TokenBucket::new(config.burst);
        let overflow_bucket = TokenBucket::new(config.overflow_burst);
        Self {
            config,
            buckets: HashMap::new(),
            global_bucket,
            overflow_bucket,
            blocked: HashMap::new(),
            last_sweep: Instant::now(),
            last_block_sweep: Instant::now(),
            global_rejected: 0,
            overflow_rejected: 0,
        }
    }

    /// Creates a rate limiter with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(RateLimiterConfig::default())
    }

    /// Returns the configuration.
    pub fn config(&self) -> &RateLimiterConfig {
        &self.config
    }

    /// The per-source key for `source` under this limiter's configuration.
    fn key(&self, source: IpAddr) -> IpAddr {
        source_key(source, self.config.ipv6_prefix_len)
    }

    /// Checks if a source is blocked.
    pub fn is_blocked(&self, source: IpAddr) -> bool {
        self.blocked
            .get(&self.key(source))
            .is_some_and(|entry| !entry.is_expired())
    }

    /// Returns the remaining block time for a source.
    pub fn block_remaining(&self, source: IpAddr) -> Option<Duration> {
        self.blocked.get(&self.key(source)).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.remaining())
            }
        })
    }

    /// Blocks a source. Returns `false` (and does not block) when the block
    /// map is at `max_blocked_sources` and the source is not already in it.
    // POAM: POA&M-90 — blocks are node-local and not replicated across the
    // cluster, so an attacker can rotate to a peer node (SC-5).
    pub fn block(&mut self, source: IpAddr, duration: Duration) -> bool {
        let key = self.key(source);
        if let Some(entry) = self.blocked.get_mut(&key) {
            // Re-block keeps the undrained drop count.
            entry.expires_at = Instant::now() + duration;
            return true;
        }
        if self.blocked.len() >= self.config.max_blocked_sources {
            // Make room from expired entries before giving up, at most once
            // per SWEEP_INTERVAL: a flood of new offenders against a full
            // map must not cost an O(n) scan per packet under the caller's
            // lock (CWE-407). Expiry is otherwise left to `sweep_with`.
            if self.last_block_sweep.elapsed() < SWEEP_INTERVAL {
                return false;
            }
            self.last_block_sweep = Instant::now();
            self.blocked.retain(|_, entry| !entry.is_expired());
            if self.blocked.len() >= self.config.max_blocked_sources {
                return false;
            }
        }
        self.blocked.insert(key, BlockEntry::new(duration));
        true
    }

    /// Unblocks a source.
    pub fn unblock(&mut self, source: IpAddr) {
        let key = self.key(source);
        self.blocked.remove(&key);
    }

    /// Checks a request and returns the action to take.
    pub fn check(&mut self, source: IpAddr) -> RateLimitAction {
        self.check_outcome(source).action
    }

    /// Checks a request, also reporting whether this call started a block.
    ///
    /// ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection)
    pub fn check_outcome(&mut self, source: IpAddr) -> CheckOutcome {
        let pass = |action| CheckOutcome {
            action,
            block_started: false,
        };

        // A global limiter never consults or populates the block list: the
        // source that trips a global flood is often an innocent trunk.
        if !self.config.per_ip {
            let (allowed, rate) = self
                .global_bucket
                .try_consume(self.config.rps, self.config.burst);
            if allowed {
                return pass(self.allow_or_throttle(rate));
            }
            self.global_rejected = self.global_rejected.saturating_add(1);
            return pass(RateLimitAction::Reject);
        }

        let key = self.key(source);

        // Check if blocked (normalized key: rotating within a /64 or
        // switching to the v4-mapped form does not dodge a block). An
        // expired entry is left for `sweep_with`, which reports its drop
        // count and the unblock.
        if let Some(entry) = self.blocked.get_mut(&key)
            && !entry.is_expired()
        {
            entry.dropped = entry.dropped.saturating_add(1);
            return pass(RateLimitAction::Block {
                duration_secs: entry.remaining().as_secs(),
            });
        }

        // Spoofed UDP source addresses can otherwise grow the per-IP map
        // without bound.
        if !self.buckets.contains_key(&key) && self.buckets.len() >= self.config.max_tracked_sources
        {
            // At capacity with a new source. Sweep idle buckets at most
            // once per second (a full retain on every packet would be an
            // O(n) scan per packet under the caller's lock during a flood).
            if self.last_sweep.elapsed() >= SWEEP_INTERVAL {
                self.buckets
                    .retain(|_, bucket| !bucket.is_idle(BUCKET_IDLE_TIMEOUT));
                self.last_sweep = Instant::now();
            }
            // Still full: charge the shared overflow bucket instead of
            // rejecting outright, so genuinely new sources keep a share of
            // service during a flood. The overflow bucket never blocks.
            // POAM: POA&M-91 — /48-scale IPv6 rotation is bounded only by
            // this bucket; no adaptive prefix aggregation (SC-5).
            if self.buckets.len() >= self.config.max_tracked_sources {
                let (allowed, _) = self
                    .overflow_bucket
                    .try_consume(self.config.overflow_rps, self.config.overflow_burst);
                if allowed {
                    return pass(RateLimitAction::Allow);
                }
                self.overflow_rejected = self.overflow_rejected.saturating_add(1);
                return pass(RateLimitAction::Reject);
            }
        }

        let (allowed, rate) = self
            .buckets
            .entry(key)
            .or_insert_with(|| TokenBucket::new(self.config.burst))
            .try_consume(self.config.rps, self.config.burst);

        if allowed {
            return pass(self.allow_or_throttle(rate));
        }

        // Check if we should block
        let block_threshold = self.config.rps as f64 * self.config.block_threshold_multiplier;
        if rate >= block_threshold {
            let duration = Duration::from_secs(self.config.block_duration_secs);
            if self.block(key, duration) {
                return CheckOutcome {
                    action: RateLimitAction::Block {
                        duration_secs: self.config.block_duration_secs,
                    },
                    block_started: true,
                };
            }
        }
        pass(RateLimitAction::Reject)
    }

    /// `Allow`, or `Throttle` once the source is over 80% of its rate.
    fn allow_or_throttle(&self, rate: f64) -> RateLimitAction {
        if rate > self.config.rps as f64 * 0.8 {
            // The calculation is always positive when rate > 80% of RPS
            #[allow(clippy::cast_sign_loss)]
            let delay_ms = ((self.config.rps as f64).mul_add(-0.8, rate) * 10.0) as u64;
            RateLimitAction::Throttle { delay_ms }
        } else {
            RateLimitAction::Allow
        }
    }

    /// Cleans up expired blocks and idle buckets.
    pub fn cleanup(&mut self) {
        let _ = self.cleanup_with(|_| {});
    }

    /// Removes expired blocks (calling `on_unblock` with each key) and idle
    /// buckets. Returns the number of blocks that ended.
    ///
    /// Call [`Self::drain_rejections`] first: an idle bucket swept here
    /// takes any undrained rejection count with it.
    pub fn cleanup_with(&mut self, mut on_unblock: impl FnMut(IpAddr)) -> usize {
        let mut ended = 0;
        self.blocked.retain(|key, entry| {
            if entry.is_expired() {
                on_unblock(*key);
                ended += 1;
                false
            } else {
                true
            }
        });
        self.buckets
            .retain(|_, bucket| !bucket.is_idle(BUCKET_IDLE_TIMEOUT));
        self.last_sweep = Instant::now();
        ended
    }

    /// One maintenance pass over both maps, reporting through `on_event`:
    /// per-source rejection counts and packets dropped while blocked
    /// (then reset), ended blocks, while evicting idle buckets and expired
    /// blocks in the same pass. Returns the number of blocks that ended.
    ///
    /// Replaces [`Self::drain_rejections`] + [`Self::cleanup_with`] (two
    /// full passes under the caller's lock).
    ///
    /// ## NIST 800-53 Rev5: SC-5, AU-4, AU-12 (aggregated audit)
    pub fn sweep_with(&mut self, mut on_event: impl FnMut(SweepEvent)) -> usize {
        let mut ended = 0;
        self.blocked.retain(|key, entry| {
            if entry.dropped > 0 {
                on_event(SweepEvent::BlockedDrops(*key, entry.dropped));
                entry.dropped = 0;
            }
            if entry.is_expired() {
                on_event(SweepEvent::Unblocked(*key));
                ended += 1;
                false
            } else {
                true
            }
        });
        self.buckets.retain(|key, bucket| {
            if bucket.rejected > 0 {
                on_event(SweepEvent::Rejected(*key, u64::from(bucket.rejected)));
                bucket.rejected = 0;
            }
            !bucket.is_idle(BUCKET_IDLE_TIMEOUT)
        });
        let now = Instant::now();
        self.last_sweep = now;
        self.last_block_sweep = now;
        ended
    }

    /// Reports and resets per-source rejection counts (`f(key, count)` for
    /// every bucket with at least one rejection since the last drain).
    ///
    /// ## NIST 800-53 Rev5: AU-4, AU-12 (aggregated audit)
    pub fn drain_rejections(&mut self, mut f: impl FnMut(IpAddr, u64)) {
        for (key, bucket) in &mut self.buckets {
            if bucket.rejected > 0 {
                f(*key, u64::from(bucket.rejected));
                bucket.rejected = 0;
            }
        }
    }

    /// Returns and resets the global-bucket rejection count.
    pub fn take_global_rejections(&mut self) -> u64 {
        std::mem::take(&mut self.global_rejected)
    }

    /// Returns and resets the overflow-bucket rejection count.
    pub fn take_overflow_rejections(&mut self) -> u64 {
        std::mem::take(&mut self.overflow_rejected)
    }

    /// Returns the number of tracked sources.
    pub fn tracked_sources(&self) -> usize {
        self.buckets.len()
    }

    /// Returns the number of blocked sources.
    pub fn blocked_sources(&self) -> usize {
        self.blocked.iter().filter(|(_, e)| !e.is_expired()).count()
    }

    /// Returns the current token count for a source.
    pub fn token_count(&self, source: IpAddr) -> Option<f64> {
        if self.config.per_ip {
            self.buckets
                .get(&self.key(source))
                .map(TokenBucket::token_count)
        } else {
            Some(self.global_bucket.token_count())
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyed_limiter_isolates_users_and_rejects_over_burst() {
        let mut limiter = KeyedRateLimiter::new(1, 2);
        assert_eq!(limiter.rps(), 1);
        assert!(limiter.check("alice").is_allowed());
        assert!(limiter.check("alice").is_allowed());
        // Third request within the same instant exceeds the 2-token burst.
        assert!(limiter.check("alice").is_rejected());
        // Another user has an untouched bucket.
        assert!(limiter.check("bob").is_allowed());
        assert_eq!(limiter.tracked_keys(), 2);
    }
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))
    }

    #[test]
    fn test_rate_limit_action() {
        assert!(RateLimitAction::Allow.is_allowed());
        assert!(RateLimitAction::Throttle { delay_ms: 100 }.is_allowed());
        assert!(RateLimitAction::Reject.is_rejected());
        assert!(RateLimitAction::Block { duration_secs: 60 }.is_rejected());
    }

    #[test]
    fn test_config_builder() {
        let config = RateLimiterConfig::new(50, 100)
            .with_block_duration(120)
            .with_block_threshold(3.0)
            .with_per_ip(false);

        assert_eq!(config.rps, 50);
        assert_eq!(config.burst, 100);
        assert_eq!(config.block_duration_secs, 120);
        assert!(!config.per_ip);
    }

    #[test]
    fn test_limiter_creation() {
        let limiter = RateLimiter::with_defaults();
        assert_eq!(limiter.config().rps, DEFAULT_RPS);
        assert_eq!(limiter.tracked_sources(), 0);
    }

    #[test]
    fn test_limiter_allow() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(100, 100));
        let ip = test_ip();

        // First request should be allowed
        let action = limiter.check(ip);
        assert!(action.is_allowed());
    }

    #[test]
    fn test_limiter_exhaust_tokens() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(10, 5));
        let ip = test_ip();

        // First 5 requests should be allowed (burst)
        for _ in 0..5 {
            let action = limiter.check(ip);
            assert!(action.is_allowed(), "Expected allowed, got {action:?}");
        }

        // Next request should be rejected (out of tokens)
        let action = limiter.check(ip);
        assert!(action.is_rejected(), "Expected rejected, got {action:?}");
    }

    #[test]
    fn test_limiter_blocking() {
        let mut limiter = RateLimiter::new(
            RateLimiterConfig::new(10, 5)
                .with_block_threshold(1.5)
                .with_block_duration(60),
        );
        let ip = test_ip();

        // Exhaust tokens and exceed threshold
        for _ in 0..20 {
            let _ = limiter.check(ip);
        }

        // Should be blocked now
        assert!(limiter.is_blocked(ip));
        assert!(limiter.block_remaining(ip).is_some());

        let action = limiter.check(ip);
        assert!(matches!(action, RateLimitAction::Block { .. }));
    }

    #[test]
    fn test_limiter_manual_block() {
        let mut limiter = RateLimiter::with_defaults();
        let ip = test_ip();

        limiter.block(ip, Duration::from_secs(30));
        assert!(limiter.is_blocked(ip));

        limiter.unblock(ip);
        assert!(!limiter.is_blocked(ip));
    }

    #[test]
    fn test_limiter_per_ip() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(10, 5).with_per_ip(true));

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Exhaust tokens for ip1
        for _ in 0..5 {
            limiter.check(ip1);
        }

        // ip2 should still have tokens
        let action = limiter.check(ip2);
        assert!(action.is_allowed());

        assert_eq!(limiter.tracked_sources(), 2);
    }

    #[test]
    fn test_limiter_global() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(10, 5).with_per_ip(false));

        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Exhaust global tokens from ip1
        for _ in 0..5 {
            limiter.check(ip1);
        }

        // ip2 should also be affected
        let action = limiter.check(ip2);
        assert!(action.is_rejected());
    }

    #[test]
    fn test_limiter_cleanup() {
        let mut limiter = RateLimiter::with_defaults();
        let ip = test_ip();

        // Add expired block (duration 0)
        limiter.block(ip, Duration::from_secs(0));

        // Cleanup should remove it
        limiter.cleanup();
        assert!(!limiter.is_blocked(ip));
    }

    #[test]
    fn test_token_count() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(100, 50));
        let ip = test_ip();

        // First check creates the bucket
        limiter.check(ip);

        // Should have tokens (less than burst after consuming one)
        let count = limiter.token_count(ip).unwrap();
        assert!(count < 50.0);
        assert!(count >= 48.0);
    }

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    #[test]
    fn global_limiter_never_blocks() {
        let mut limiter = RateLimiter::new(
            RateLimiterConfig::new(10, 5)
                .with_per_ip(false)
                .with_block_threshold(1.0),
        );
        for _ in 0..100 {
            let outcome = limiter.check_outcome(v4(1));
            assert!(!outcome.block_started);
            assert!(!matches!(outcome.action, RateLimitAction::Block { .. }));
        }
        assert_eq!(limiter.blocked_sources(), 0);
        assert!(!limiter.is_blocked(v4(1)));
        assert_eq!(limiter.take_global_rejections(), 95);
        assert_eq!(limiter.take_global_rejections(), 0);
    }

    #[test]
    fn block_started_emitted_once() {
        let mut limiter = RateLimiter::new(
            RateLimiterConfig::new(10, 5)
                .with_block_threshold(1.0)
                .with_block_duration(60),
        );
        let mut started = 0;
        for _ in 0..30 {
            if limiter.check_outcome(v4(1)).block_started {
                started += 1;
            }
        }
        assert_eq!(started, 1);
        assert!(matches!(
            limiter.check(v4(1)),
            RateLimitAction::Block { .. }
        ));
    }

    #[test]
    fn blocked_map_capped() {
        let mut limiter = RateLimiter::new(
            RateLimiterConfig::new(1, 1)
                .with_block_threshold(1.0)
                .with_max_blocked_sources(2),
        );
        for last in 1..=3 {
            for _ in 0..5 {
                let _ = limiter.check(v4(last));
            }
        }
        assert_eq!(limiter.blocked_sources(), 2);
        assert!(!limiter.is_blocked(v4(3)));
        assert_eq!(limiter.check(v4(3)), RateLimitAction::Reject);
        assert!(!limiter.block(v4(4), Duration::from_secs(10)));
    }

    #[test]
    fn cleanup_with_reports_expired_blocks_and_sweeps_idle_buckets() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(1, 1).with_block_duration(0));
        limiter.block(v4(1), Duration::ZERO);
        limiter.block(v4(2), Duration::from_secs(60));
        let mut ended = Vec::new();
        let n = limiter.cleanup_with(|k| ended.push(k));
        assert_eq!(n, 1);
        assert_eq!(ended, vec![v4(1)]);
        assert!(limiter.is_blocked(v4(2)));
        // A fresh bucket is not idle and survives the sweep.
        let _ = limiter.check(v4(3));
        let _ = limiter.cleanup_with(|_| {});
        assert_eq!(limiter.tracked_sources(), 1);
    }

    #[test]
    fn v6_rotation_within_64_shares_bucket() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(10, 3));
        for host in 1u16..=3 {
            let ip = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, host));
            assert!(limiter.check(ip).is_allowed());
        }
        let ip = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 9, 9, 9, 9));
        assert!(limiter.check(ip).is_rejected());
        assert_eq!(limiter.tracked_sources(), 1);
        // The v4-mapped form of a v4 source shares the v4 bucket.
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        let _ = limiter.check(mapped);
        assert!(limiter.token_count(v4(1)).is_some());
    }

    #[test]
    fn block_applies_to_whole_v6_prefix() {
        let mut limiter = RateLimiter::with_defaults();
        let a: IpAddr = "2001:db8:0:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:0:1::2".parse().unwrap();
        limiter.block(a, Duration::from_secs(30));
        assert!(limiter.is_blocked(b));
        assert!(matches!(limiter.check(b), RateLimitAction::Block { .. }));
    }

    #[test]
    fn overflow_uses_shared_bucket_not_reject() {
        let mut limiter = RateLimiter::new(
            RateLimiterConfig::new(100, 100)
                .with_max_tracked_sources(1)
                .with_overflow(1, 2)
                .with_block_threshold(1.0),
        );
        assert!(limiter.check(v4(1)).is_allowed());
        // New sources past the cap share the overflow burst of 2.
        assert!(limiter.check(v4(2)).is_allowed());
        assert!(limiter.check(v4(3)).is_allowed());
        for _ in 0..50 {
            let outcome = limiter.check_outcome(v4(4));
            assert_eq!(outcome.action, RateLimitAction::Reject);
            assert!(!outcome.block_started);
        }
        assert_eq!(limiter.tracked_sources(), 1);
        assert_eq!(limiter.blocked_sources(), 0);
        assert_eq!(limiter.take_overflow_rejections(), 50);
        // The tracked source is unaffected.
        assert!(limiter.check(v4(1)).is_allowed());
    }

    #[test]
    fn drain_rejections_reports_and_resets() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(1, 1).with_block_threshold(1e9));
        for _ in 0..11 {
            let _ = limiter.check(v4(1));
        }
        let _ = limiter.check(v4(2));
        let mut seen = Vec::new();
        limiter.drain_rejections(|k, n| seen.push((k, n)));
        assert_eq!(seen, vec![(v4(1), 10)]);
        seen.clear();
        limiter.drain_rejections(|k, n| seen.push((k, n)));
        assert_eq!(seen.len(), 0);
    }

    // QA: a global flood spread over many sources never blocks any of them,
    // and a source that arrives after the flood is rejected, never blocked.
    #[test]
    fn qa_global_flood_never_blocks_innocent_source() {
        let mut limiter = RateLimiter::new(
            RateLimiterConfig::new(5, 5)
                .with_per_ip(false)
                .with_block_threshold(1.0),
        );
        for i in 0..2_000u32 {
            let _ = limiter.check_outcome(v4((i % 250) as u8 + 1));
        }
        let outcome = limiter.check_outcome(v4(253));
        assert_eq!(outcome.action, RateLimitAction::Reject);
        assert!(!outcome.block_started);
        assert_eq!(limiter.blocked_sources(), 0);
        assert!(!limiter.is_blocked(v4(253)));
    }

    // QA: the blocked map stays at its cap under many offenders; existing
    // blocks are not evicted and later offenders are only rejected.
    #[test]
    fn qa_blocked_map_cap_holds_under_many_offenders() {
        let mut limiter = RateLimiter::new(
            RateLimiterConfig::new(1, 1)
                .with_block_threshold(1.0)
                .with_max_blocked_sources(3),
        );
        for last in 1..=200u8 {
            for _ in 0..5 {
                let outcome = limiter.check_outcome(v4(last));
                if last > 3 {
                    assert!(!outcome.block_started, "offender {last} blocked past cap");
                }
            }
        }
        assert_eq!(limiter.blocked_sources(), 3);
        for last in 1..=3 {
            assert!(limiter.is_blocked(v4(last)));
        }
    }

    // PERF-001: with the block map full of live blocks, new offenders
    // trigger at most one expiry scan per SWEEP_INTERVAL, not one per packet.
    #[test]
    fn full_block_map_sweeps_at_most_once_per_interval() {
        let mut limiter = RateLimiter::new(
            RateLimiterConfig::new(1, 1)
                .with_block_threshold(1.0)
                .with_max_blocked_sources(2),
        );
        assert!(limiter.block(v4(1), Duration::from_secs(300)));
        assert!(limiter.block(v4(2), Duration::from_secs(300)));
        // Age the sweep stamp so the first at-capacity attempt may scan.
        if let Some(aged) = Instant::now().checked_sub(SWEEP_INTERVAL) {
            limiter.last_block_sweep = aged;
        }
        assert!(!limiter.block(v4(3), Duration::from_secs(300)));
        let scanned_at = limiter.last_block_sweep;
        for last in 4..=200u8 {
            for _ in 0..3 {
                assert!(!limiter.check_outcome(v4(last)).block_started);
            }
        }
        assert_eq!(limiter.last_block_sweep, scanned_at, "rescanned within 1 s");
        assert_eq!(limiter.blocked_sources(), 2);
    }

    // SEC-003 / NIST-004: packets dropped while blocked are counted and
    // reported once by the sweep, together with the unblock.
    #[test]
    fn blocked_drops_are_reported_by_sweep() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(1, 1).with_block_threshold(1e9));
        assert!(limiter.block(v4(7), Duration::from_millis(30)));
        for _ in 0..25 {
            assert!(matches!(
                limiter.check(v4(7)),
                RateLimitAction::Block { .. }
            ));
        }
        for _ in 0..4 {
            let _ = limiter.check(v4(8));
        }
        let mut events = Vec::new();
        assert_eq!(limiter.sweep_with(|e| events.push(e)), 0);
        assert!(events.contains(&SweepEvent::BlockedDrops(v4(7), 25)));
        assert!(events.contains(&SweepEvent::Rejected(v4(8), 3)));
        assert_eq!(events.len(), 2);
        std::thread::sleep(Duration::from_millis(40));
        events.clear();
        assert_eq!(limiter.sweep_with(|e| events.push(e)), 1);
        assert_eq!(events, vec![SweepEvent::Unblocked(v4(7))]);
        assert_eq!(limiter.blocked_sources(), 0);
    }

    // QA: the v4-mapped form of a blocked v4 source is blocked too.
    #[test]
    fn qa_v4_mapped_cannot_dodge_v4_block() {
        let mut limiter = RateLimiter::with_defaults();
        limiter.block(v4(9), Duration::from_secs(30));
        let mapped: IpAddr = "::ffff:192.0.2.9".parse().unwrap();
        assert!(limiter.is_blocked(mapped));
        assert!(matches!(
            limiter.check(mapped),
            RateLimitAction::Block { .. }
        ));
    }

    // QA: different /64s are separate buckets.
    #[test]
    fn qa_distinct_v6_prefixes_are_distinct_sources() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(10, 1));
        let a: IpAddr = "2001:db8:0:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:0:2::1".parse().unwrap();
        assert!(limiter.check(a).is_allowed());
        assert!(limiter.check(b).is_allowed());
        assert_eq!(limiter.tracked_sources(), 2);
    }

    // QA: overflow traffic never creates a block, even far past the
    // block threshold, and never enters the tracked table.
    #[test]
    fn qa_overflow_bucket_never_blocks_under_flood() {
        let mut limiter = RateLimiter::new(
            RateLimiterConfig::new(100, 100)
                .with_max_tracked_sources(1)
                .with_overflow(1, 1)
                .with_block_threshold(1.0),
        );
        let _ = limiter.check(v4(1));
        for i in 0..5_000u32 {
            let outcome = limiter.check_outcome(v4((i % 200) as u8 + 2));
            assert!(!outcome.block_started);
            assert!(!matches!(outcome.action, RateLimitAction::Block { .. }));
        }
        assert_eq!(limiter.blocked_sources(), 0);
        assert_eq!(limiter.tracked_sources(), 1);
    }
}
