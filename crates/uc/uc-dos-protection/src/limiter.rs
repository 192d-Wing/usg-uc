//! Token bucket rate limiter.

use crate::key::{DEFAULT_IPV6_PREFIX_LEN, source_key};
use crate::{DEFAULT_BLOCK_DURATION_SECS, DEFAULT_BURST, DEFAULT_RPS};
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tracing::warn;

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
    /// Whether a source over `block_threshold_multiplier` x `rps` is moved
    /// to the block map. When `false` it is rejected per request only.
    /// Explicit [`RateLimiter::block`] calls are unaffected. Trusted
    /// sources are never auto-blocked, whatever this is set to.
    pub auto_block: bool,
    /// Rate of each trusted source's own bucket. `0` uses `rps`.
    pub trusted_rps: u32,
    /// Burst of each trusted source's own bucket. `0` uses `burst`.
    pub trusted_burst: u32,
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
            auto_block: true,
            trusted_rps: 0,
            trusted_burst: 0,
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

    /// Sets whether over-threshold sources are blocked or only rejected.
    #[must_use]
    pub fn with_auto_block(mut self, on: bool) -> Self {
        self.auto_block = on;
        self
    }

    /// Sets the rate and burst of each trusted source's bucket.
    #[must_use]
    pub fn with_trusted_bucket(mut self, rps: u32, burst: u32) -> Self {
        self.trusted_rps = rps;
        self.trusted_burst = burst;
        self
    }

    /// The trusted bucket rate in effect (`0` falls back to `rps`).
    fn effective_trusted_rps(&self) -> u32 {
        if self.trusted_rps == 0 {
            self.rps
        } else {
            self.trusted_rps
        }
    }

    /// The trusted bucket burst in effect (`0` falls back to `burst`).
    fn effective_trusted_burst(&self) -> u32 {
        if self.trusted_burst == 0 {
            self.burst
        } else {
            self.trusted_burst
        }
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

/// Cap on [`RateLimiter::set_trusted_sources`]; addresses past it are not
/// trusted. Bounds the trusted map and the cost of replacing it under the
/// caller's lock.
pub const MAX_TRUSTED_SOURCES: usize = 4_096;

/// Multiplicative word hasher (Fx-style) for the trusted map. Its keys are
/// operator-configured and capped at [`MAX_TRUSTED_SOURCES`]; attacker
/// addresses are only looked up, never inserted, so a keyed hasher buys
/// nothing on that map and SipHash costs every untrusted packet a lookup.
#[derive(Default)]
struct WordHasher(u64);

impl WordHasher {
    const SEED: u64 = 0x517c_c1b7_2722_0a95;

    fn mix(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(5) ^ word).wrapping_mul(Self::SEED);
    }
}

impl Hasher for WordHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let (words, rest) = bytes.as_chunks::<8>();
        for word in words {
            self.mix(u64::from_le_bytes(*word));
        }
        for &b in rest {
            self.mix(u64::from(b));
        }
    }

    fn write_u8(&mut self, n: u8) {
        self.mix(u64::from(n));
    }

    fn write_u32(&mut self, n: u32) {
        self.mix(u64::from(n));
    }

    fn write_u64(&mut self, n: u64) {
        self.mix(n);
    }

    fn write_u128(&mut self, n: u128) {
        #[allow(clippy::cast_possible_truncation)]
        self.mix(n as u64);
        self.mix((n >> 64) as u64);
    }

    fn write_usize(&mut self, n: usize) {
        self.mix(n as u64);
    }

    fn write_isize(&mut self, n: isize) {
        #[allow(clippy::cast_sign_loss)]
        self.mix(n as u64);
    }
}

/// A trusted source's bucket and any explicit [`RateLimiter::block`] of
/// its exact address.
#[derive(Debug)]
struct TrustedEntry {
    bucket: TokenBucket,
    block: Option<BlockEntry>,
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

/// One report from [`RateLimiter::sweep_with`]; keys are [`source_key`]s,
/// except [`SweepEvent::TrustedRejected`], which carries the exact address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepEvent {
    /// Over-rate rejections from a tracked source since the last sweep.
    Rejected(IpAddr, u64),
    /// Packets dropped while the source was blocked since the last sweep.
    BlockedDrops(IpAddr, u64),
    /// The source's block expired and was removed.
    Unblocked(IpAddr),
    /// Over-rate rejections from a trusted source since the last sweep.
    TrustedRejected(IpAddr, u64),
}

/// Token bucket rate limiter.
///
/// Per-source mode (`per_ip`) keys state with [`source_key`], caps both the
/// bucket map and the block map, and sends new sources past the bucket cap to
/// one shared overflow bucket. Global mode (`!per_ip`) uses one bucket and
/// never blocks: a global rejection cannot be attributed to the source that
/// happened to trip it.
///
/// Trusted sources ([`Self::set_trusted_sources`]) are matched on the exact
/// canonical address, not the /prefix key. Each has its own bucket, is
/// checked before the block map, and is never auto-blocked; only an
/// explicit [`Self::block`] of its exact address stops it.
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
    /// Trusted sources, keyed by exact canonical address. The key set is
    /// the trusted set; at most [`MAX_TRUSTED_SOURCES`] entries.
    trusted_buckets: HashMap<IpAddr, TrustedEntry, BuildHasherDefault<WordHasher>>,
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
            trusted_buckets: HashMap::default(),
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

    /// Checks if a source is blocked. A trusted source is blocked only by
    /// an explicit [`Self::block`] of its exact address, never by a block
    /// on its prefix.
    pub fn is_blocked(&self, source: IpAddr) -> bool {
        self.block_remaining(source).is_some()
    }

    /// Returns the remaining block time for a source (see
    /// [`Self::is_blocked`] for trusted sources).
    pub fn block_remaining(&self, source: IpAddr) -> Option<Duration> {
        if !self.trusted_buckets.is_empty()
            && let Some(entry) = self.trusted_buckets.get(&source.to_canonical())
        {
            return entry
                .block
                .as_ref()
                .filter(|block| !block.is_expired())
                .map(BlockEntry::remaining);
        }
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
    ///
    /// A trusted source is blocked on its exact address only (not its
    /// prefix) and does not count against `max_blocked_sources`.
    // POAM: POA&M-90 — blocks are node-local and not replicated across the
    // cluster, so an attacker can rotate to a peer node (SC-5).
    pub fn block(&mut self, source: IpAddr, duration: Duration) -> bool {
        if let Some(entry) = self.trusted_buckets.get_mut(&source.to_canonical()) {
            // Re-block keeps the undrained drop count.
            match &mut entry.block {
                Some(block) => block.expires_at = Instant::now() + duration,
                None => entry.block = Some(BlockEntry::new(duration)),
            }
            return true;
        }
        self.block_key(self.key(source), duration)
    }

    /// Adds `key` (already a [`source_key`]) to the block map. Auto-blocks
    /// come here directly: they never target a trusted address.
    fn block_key(&mut self, key: IpAddr, duration: Duration) -> bool {
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

    /// Unblocks a source. For a trusted source only its own explicit
    /// block is cleared; a block-map entry on its key (an explicit block
    /// made before it was trusted, or a neighbour's prefix block) is left
    /// in place. Such an entry is bypassed while the source is trusted
    /// and applies again once it is untrusted.
    pub fn unblock(&mut self, source: IpAddr) {
        if let Some(entry) = self.trusted_buckets.get_mut(&source.to_canonical()) {
            entry.block = None;
            return;
        }
        let key = self.key(source);
        self.blocked.remove(&key);
    }

    /// Replaces the trusted set. Addresses are canonicalised (IPv4-mapped
    /// folded to IPv4); state of addresses still trusted is kept, that of
    /// removed addresses dropped, except that a live explicit block moves
    /// to the block map under the address's [`source_key`] (so an IPv6
    /// exact-address block widens to its prefix). The move only extends
    /// an existing entry's expiry, never shortens it, and carries over the
    /// undrained drop count. Only the first [`MAX_TRUSTED_SOURCES`] distinct
    /// addresses (in iteration order) are trusted; returns how many were
    /// left out. Callers wanting a deterministic choice pass a sorted,
    /// already capped list.
    ///
    /// ## NIST 800-53 Rev5: SC-5 (configured peers)
    pub fn set_trusted_sources(&mut self, ips: impl IntoIterator<Item = IpAddr>) -> usize {
        let mut old = std::mem::take(&mut self.trusted_buckets);
        let burst = self.config.effective_trusted_burst();
        let mut skipped = 0;
        for ip in ips.into_iter().map(|ip| ip.to_canonical()) {
            if self.trusted_buckets.contains_key(&ip) {
                continue;
            }
            if self.trusted_buckets.len() >= MAX_TRUSTED_SOURCES {
                skipped += 1;
                continue;
            }
            let entry = old.remove(&ip).unwrap_or_else(|| TrustedEntry {
                bucket: TokenBucket::new(burst),
                block: None,
            });
            self.trusted_buckets.insert(ip, entry);
        }
        for (ip, entry) in old {
            if let Some(block) = entry.block.filter(|block| !block.is_expired()) {
                self.migrate_block(ip, &block);
            }
        }
        skipped
    }

    /// Moves the live explicit block of an untrusted `ip` to the block map.
    fn migrate_block(&mut self, ip: IpAddr, block: &BlockEntry) {
        let key = self.key(ip);
        if let Some(existing) = self.blocked.get_mut(&key) {
            existing.expires_at = existing.expires_at.max(block.expires_at);
            existing.dropped = existing.dropped.saturating_add(block.dropped);
            return;
        }
        if self.block_key(key, block.remaining()) {
            if let Some(entry) = self.blocked.get_mut(&key) {
                entry.expires_at = block.expires_at;
                entry.dropped = block.dropped;
            }
        } else {
            warn!(
                source = %ip,
                "Block map full; explicit block of an untrusted source not kept"
            );
        }
    }

    /// Whether `ip` (either IPv4 or IPv4-mapped form) is a trusted source.
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted_buckets.contains_key(&ip.to_canonical())
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

        // Trusted sources use their own bucket ahead of the block map and
        // are rejected, never auto-blocked. Only the emptiness test stays
        // inline: the lookup is out of line so the untrusted path keeps
        // its codegen when no trunk is configured.
        // NIST 800-53 Rev5: SC-5, SC-5(2) (per-peer capacity)
        if !self.trusted_buckets.is_empty()
            && let Some(action) = self.check_trusted(source)
        {
            return pass(action);
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

        // Check if we should block. With `auto_block` off (spoofable
        // transports) an over-threshold source is only rejected.
        let block_threshold = self.config.rps as f64 * self.config.block_threshold_multiplier;
        if self.config.auto_block && rate >= block_threshold {
            let duration = Duration::from_secs(self.config.block_duration_secs);
            if self.block_key(key, duration) {
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

    /// The action for a trusted `source`, or `None` when it is not
    /// trusted. An explicit block of its exact address wins; otherwise
    /// `Allow` or `Reject` from its own bucket.
    #[cold]
    #[inline(never)]
    fn check_trusted(&mut self, source: IpAddr) -> Option<RateLimitAction> {
        let (rps, burst) = (
            self.config.effective_trusted_rps(),
            self.config.effective_trusted_burst(),
        );
        let entry = self.trusted_buckets.get_mut(&source.to_canonical())?;
        if let Some(block) = entry.block.as_mut()
            && !block.is_expired()
        {
            block.dropped = block.dropped.saturating_add(1);
            return Some(RateLimitAction::Block {
                duration_secs: block.remaining().as_secs(),
            });
        }
        let (allowed, _) = entry.bucket.try_consume(rps, burst);
        Some(if allowed {
            RateLimitAction::Allow
        } else {
            RateLimitAction::Reject
        })
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
        // Trusted sources first. Ordering only helps within one sweep: a
        // caller that caps records across several sweeps must keep these
        // apart from per-source events (the SBC daemon does). Their
        // entries live as long as the source stays trusted.
        for (ip, entry) in &mut self.trusted_buckets {
            if entry.bucket.rejected > 0 {
                on_event(SweepEvent::TrustedRejected(
                    *ip,
                    u64::from(entry.bucket.rejected),
                ));
                entry.bucket.rejected = 0;
            }
            if let Some(block) = entry.block.as_mut() {
                if block.dropped > 0 {
                    on_event(SweepEvent::BlockedDrops(*ip, block.dropped));
                    block.dropped = 0;
                }
                if block.is_expired() {
                    on_event(SweepEvent::Unblocked(*ip));
                    ended += 1;
                    entry.block = None;
                }
            }
        }
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
    /// Trusted-source rejections are reported only by [`Self::sweep_with`].
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
            assert!(
                action.is_allowed(),
                "expected the request within the burst to be allowed"
            );
        }

        // Next request should be rejected (out of tokens)
        let action = limiter.check(ip);
        assert!(
            action.is_rejected(),
            "expected the request past the burst to be rejected"
        );
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

// SR-55: auto-block gate and trusted (configured trunk) sources. Written
// against the planned API (`with_auto_block`, `with_trusted_bucket`,
// `set_trusted_sources`, `is_trusted`, `SweepEvent::TrustedRejected`).
#[cfg(test)]
mod sr55_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn is_block(action: RateLimitAction) -> bool {
        matches!(action, RateLimitAction::Block { .. })
    }

    #[test]
    fn auto_block_off_rejects_without_blocking() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(10, 10).with_auto_block(false));
        let src = v4(1);
        let mut rejects = 0;
        for _ in 0..1_000 {
            let outcome = limiter.check_outcome(src);
            assert!(!outcome.block_started);
            assert!(
                !is_block(outcome.action),
                "auto-block disabled: no block expected"
            );
            if outcome.action == RateLimitAction::Reject {
                rejects += 1;
            }
        }
        assert!(rejects > 0);
        assert_eq!(limiter.blocked_sources(), 0);
        assert!(!limiter.is_blocked(src));
    }

    #[test]
    fn auto_block_off_explicit_block_still_applies() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(10, 10).with_auto_block(false));
        assert!(limiter.block(v4(2), Duration::from_secs(30)));
        assert!(limiter.is_blocked(v4(2)));
        assert!(is_block(limiter.check(v4(2))));
    }

    #[test]
    fn auto_block_default_unchanged() {
        let config = RateLimiterConfig::default();
        assert!(config.auto_block);
        assert_eq!((config.trusted_rps, config.trusted_burst), (0, 0));
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(10, 10));
        let mut started = 0;
        for _ in 0..1_000 {
            if limiter.check_outcome(v4(3)).block_started {
                started += 1;
            }
        }
        assert_eq!(started, 1);
        assert!(limiter.is_blocked(v4(3)));
    }

    #[test]
    fn trusted_source_never_blocked() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(50, 50));
        let t = v4(5);
        limiter.set_trusted_sources([t]);
        assert!(limiter.is_trusted(t));
        let mut rejects = 0;
        for i in 0..5_000 {
            let outcome = limiter.check_outcome(t);
            assert!(!outcome.block_started);
            assert!(
                !is_block(outcome.action),
                "trusted source must never be blocked (check {i})"
            );
            if i < 50 {
                assert!(outcome.action.is_allowed(), "check {i} within burst");
            } else if outcome.action == RateLimitAction::Reject {
                rejects += 1;
            }
        }
        assert!(rejects > 0, "trusted bucket never rejected");
        assert!(!limiter.is_blocked(t));
        assert_eq!(limiter.blocked_sources(), 0);
        // Trusted traffic does not create a per-source bucket.
        assert_eq!(limiter.tracked_sources(), 0);
    }

    #[test]
    fn trusted_ignores_prefix_block() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(1_000, 1_000));
        let trunk = ip("2001:db8::5");
        let neighbour = ip("2001:db8::66");
        limiter.set_trusted_sources([trunk]);
        for _ in 0..1_000 {
            let _ = limiter.check(neighbour);
        }
        assert!(limiter.is_blocked(neighbour), "/64 not blocked by flood");
        assert_eq!(limiter.check(trunk), RateLimitAction::Allow);
        assert!(!limiter.is_blocked(trunk));
        assert_eq!(limiter.block_remaining(trunk), None);
    }

    #[test]
    fn trusted_is_not_reported_blocked_under_prefix_block() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(1_000, 1_000));
        let trunk = ip("2001:db8::5");
        limiter.set_trusted_sources([trunk]);
        // An explicit block of a neighbour blocks the shared /64.
        assert!(limiter.block(ip("2001:db8::66"), Duration::from_secs(30)));
        assert!(limiter.is_blocked(ip("2001:db8::77")));
        assert!(!limiter.is_blocked(trunk));
        assert_eq!(limiter.block_remaining(trunk), None);
        // Untrusting it exposes the prefix block again.
        limiter.set_trusted_sources(std::iter::empty());
        assert!(limiter.is_blocked(trunk));
    }

    #[test]
    fn explicit_block_of_trusted_source_is_enforced() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(1_000, 1_000));
        let trunk = ip("2001:db8::5");
        let neighbour = ip("2001:db8::66");
        limiter.set_trusted_sources([trunk]);
        assert!(limiter.block(trunk, Duration::from_secs(30)));
        assert!(limiter.is_blocked(trunk));
        assert!(limiter.block_remaining(trunk).is_some());
        assert!(is_block(limiter.check(trunk)));
        // Exact address only: the trunk's /64 is not blocked.
        assert!(!limiter.is_blocked(neighbour));
        assert_eq!(limiter.check(neighbour), RateLimitAction::Allow);
        assert_eq!(
            limiter.blocked_sources(),
            0,
            "trusted block is not in the block map"
        );
        // Drops are reported like other blocks.
        let mut events = Vec::new();
        let _ = limiter.sweep_with(|e| events.push(e));
        assert!(
            events.contains(&SweepEvent::BlockedDrops(trunk, 1)),
            "{events:?}"
        );
        limiter.unblock(trunk);
        assert!(!limiter.is_blocked(trunk));
        assert_eq!(limiter.check(trunk), RateLimitAction::Allow);
    }

    #[test]
    fn explicit_block_of_trusted_source_survives_untrust() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(1_000, 1_000));
        let t = v4(40);
        limiter.set_trusted_sources([t]);
        assert!(limiter.block(t, Duration::from_secs(30)));
        let _ = limiter.set_trusted_sources(std::iter::empty());
        assert!(limiter.is_blocked(t));
        assert!(is_block(limiter.check(t)));
    }

    // SEC-007: the move on untrust extends, never shortens, an existing
    // block-map entry and carries over undrained drops.
    #[test]
    fn untrust_migration_extends_expiry_and_keeps_drops() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(1_000, 1_000));
        let (long, short) = (v4(44), v4(45));
        // Pre-trust blocks: `long` outlasts its later trusted block,
        // `short` is outlasted by it.
        assert!(limiter.block(long, Duration::from_secs(600)));
        assert!(limiter.block(short, Duration::from_secs(5)));
        limiter.set_trusted_sources([long, short]);
        assert!(limiter.block(long, Duration::from_secs(30)));
        assert!(limiter.block(short, Duration::from_secs(300)));
        for _ in 0..3 {
            assert!(is_block(limiter.check(short)));
        }
        let _ = limiter.set_trusted_sources(std::iter::empty());
        let long_left = limiter.block_remaining(long).unwrap();
        assert!(long_left > Duration::from_secs(500), "{long_left:?}");
        let short_left = limiter.block_remaining(short).unwrap();
        assert!(short_left > Duration::from_secs(200), "{short_left:?}");
        let mut events = Vec::new();
        let _ = limiter.sweep_with(|e| events.push(e));
        assert!(
            events.contains(&SweepEvent::BlockedDrops(short, 3)),
            "{events:?}"
        );
    }

    // SEC-007: an IPv6 exact-address block widens to the prefix on untrust.
    #[test]
    fn untrust_migration_widens_v6_block_to_prefix() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(1_000, 1_000));
        let trunk = ip("2001:db8::5");
        let neighbour = ip("2001:db8::66");
        limiter.set_trusted_sources([trunk]);
        assert!(limiter.block(trunk, Duration::from_secs(30)));
        assert!(!limiter.is_blocked(neighbour));
        let _ = limiter.set_trusted_sources(std::iter::empty());
        assert!(limiter.is_blocked(trunk));
        assert!(limiter.is_blocked(neighbour));
        assert_eq!(limiter.blocked_sources(), 1);
    }

    // SEC-008: unblocking a trusted source clears only its own block; a
    // pre-trust block-map entry is bypassed while trusted and applies
    // again on untrust.
    #[test]
    fn unblock_trusted_keeps_pre_trust_block() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(1_000, 1_000));
        let t = v4(46);
        assert!(limiter.block(t, Duration::from_secs(60)));
        limiter.set_trusted_sources([t]);
        assert_eq!(limiter.check(t), RateLimitAction::Allow);
        assert!(limiter.block(t, Duration::from_secs(30)));
        assert!(is_block(limiter.check(t)));
        limiter.unblock(t);
        assert_eq!(limiter.check(t), RateLimitAction::Allow);
        assert_eq!(limiter.blocked_sources(), 1, "pre-trust entry removed");
        let _ = limiter.set_trusted_sources(std::iter::empty());
        assert!(limiter.is_blocked(t));
        assert!(is_block(limiter.check(t)));
        limiter.unblock(t);
        assert!(!limiter.is_blocked(t));
    }

    #[test]
    fn trusted_block_expiry_reports_unblocked() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(1_000, 1_000));
        let t = v4(41);
        limiter.set_trusted_sources([t]);
        assert!(limiter.block(t, Duration::ZERO));
        let mut events = Vec::new();
        assert_eq!(limiter.sweep_with(|e| events.push(e)), 1);
        assert!(events.contains(&SweepEvent::Unblocked(t)), "{events:?}");
        assert_eq!(limiter.check(t), RateLimitAction::Allow);
    }

    #[test]
    fn sweep_reports_trusted_rejections_first() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(1, 1).with_trusted_bucket(1, 1));
        let t = v4(42);
        limiter.set_trusted_sources([t]);
        for _ in 0..10 {
            let _ = limiter.check(t);
            let _ = limiter.check(v4(43));
        }
        let mut events = Vec::new();
        let _ = limiter.sweep_with(|e| events.push(e));
        assert!(
            matches!(events.first(), Some(SweepEvent::TrustedRejected(ip, _)) if *ip == t),
            "{events:?}"
        );
        assert!(events.len() > 1, "{events:?}");
    }

    #[test]
    fn trusted_set_capped() {
        let mut limiter = RateLimiter::new(RateLimiterConfig::new(10, 10));
        let ips: Vec<IpAddr> = (0..MAX_TRUSTED_SOURCES as u32 + 10)
            .map(|n| IpAddr::V4(Ipv4Addr::from(0x0A00_0000 | n)))
            .collect();
        let skipped = limiter.set_trusted_sources(ips.iter().copied().chain(ips.iter().copied()));
        assert_eq!(skipped, 20);
        assert_eq!(limiter.trusted_buckets.len(), MAX_TRUSTED_SOURCES);
        assert!(limiter.is_trusted(ips[0]));
        assert!(!limiter.is_trusted(ips[MAX_TRUSTED_SOURCES]));
    }

    #[test]
    fn trusted_neighbour_not_trusted() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(1_000, 1_000));
        let trunk = ip("2001:db8::5");
        let neighbour = ip("2001:db8::66");
        limiter.set_trusted_sources([trunk]);
        assert!(!limiter.is_trusted(neighbour));
        let _ = limiter.check(trunk);
        assert_eq!(limiter.tracked_sources(), 0);
        let _ = limiter.check(neighbour);
        assert_eq!(limiter.tracked_sources(), 1);
        // The neighbour's bucket is the shared /64 one.
        assert!(limiter.token_count(ip("2001:db8::1")).is_some());
    }

    #[test]
    fn trusted_matches_v4_mapped() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(5, 5));
        limiter.set_trusted_sources([v4(1)]);
        assert!(limiter.is_trusted(ip("::ffff:192.0.2.1")));
        limiter.set_trusted_sources([ip("::ffff:192.0.2.7")]);
        assert!(limiter.is_trusted(v4(7)));
        assert!(!limiter.is_trusted(v4(1)));
    }

    #[test]
    fn trusted_set_replace_drops_old() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(50, 50));
        let (a, b) = (v4(10), v4(11));
        limiter.set_trusted_sources([a]);
        let _ = limiter.check(a);
        assert_eq!(limiter.trusted_buckets.len(), 1);
        limiter.set_trusted_sources([b]);
        let _ = limiter.check(b);
        assert!(!limiter.is_trusted(a));
        assert!(limiter.is_trusted(b));
        assert_eq!(limiter.trusted_buckets.len(), 1);
        assert!(limiter.trusted_buckets.contains_key(&b));
        assert_eq!(limiter.tracked_sources(), 0);
        let _ = limiter.check(a);
        assert_eq!(
            limiter.tracked_sources(),
            1,
            "a not back on the normal bucket"
        );
    }

    #[test]
    fn sweep_reports_trusted_rejections() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(1, 1));
        let t = v4(20);
        limiter.set_trusted_sources([t]);
        for _ in 0..10 {
            let _ = limiter.check(t);
        }
        let mut events = Vec::new();
        let _ = limiter.sweep_with(|e| events.push(e));
        let trusted: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, SweepEvent::TrustedRejected(..)))
            .collect();
        assert_eq!(trusted.len(), 1, "{events:?}");
        let SweepEvent::TrustedRejected(src, n) = *trusted[0] else {
            unreachable!()
        };
        assert_eq!(src, t);
        assert!(n >= 1);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, SweepEvent::Rejected(k, _) if *k == t)),
            "{events:?}"
        );
        events.clear();
        let _ = limiter.sweep_with(|e| events.push(e));
        assert!(events.is_empty(), "count not reset: {events:?}");
    }

    #[test]
    fn trusted_bucket_not_evicted_by_idle_sweep() {
        let mut limiter =
            RateLimiter::new(RateLimiterConfig::new(10, 10).with_trusted_bucket(50, 50));
        let t = v4(30);
        limiter.set_trusted_sources([t]);
        let _ = limiter.check(t);
        let idle = Instant::now().checked_sub(BUCKET_IDLE_TIMEOUT * 2).unwrap();
        limiter
            .trusted_buckets
            .get_mut(&t)
            .unwrap()
            .bucket
            .last_update = idle;
        let _ = limiter.sweep_with(|_| {});
        limiter.cleanup();
        assert!(
            limiter.trusted_buckets.contains_key(&t),
            "trusted bucket evicted"
        );
        limiter.set_trusted_sources(std::iter::empty());
        assert!(limiter.trusted_buckets.is_empty());
        assert!(!limiter.is_trusted(t));
    }
}
