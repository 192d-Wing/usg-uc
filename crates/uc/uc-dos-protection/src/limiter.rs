//! Token bucket rate limiter.

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
    /// Whether to track per-IP or globally.
    pub per_ip: bool,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            rps: DEFAULT_RPS,
            burst: DEFAULT_BURST,
            block_duration_secs: DEFAULT_BLOCK_DURATION_SECS,
            block_threshold_multiplier: 2.0,
            per_ip: true,
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
    pub fn with_block_duration(mut self, secs: u64) -> Self {
        self.block_duration_secs = secs;
        self
    }

    /// Sets the block threshold multiplier.
    pub fn with_block_threshold(mut self, multiplier: f64) -> Self {
        self.block_threshold_multiplier = multiplier;
        self
    }

    /// Sets per-IP tracking.
    pub fn with_per_ip(mut self, per_ip: bool) -> Self {
        self.per_ip = per_ip;
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
}

impl TokenBucket {
    /// Creates a new token bucket.
    fn new(burst: u32) -> Self {
        let now = Instant::now();
        Self {
            tokens: burst as f64,
            last_update: now,
            request_count: 0,
            window_start: now,
        }
    }

    /// Updates the token bucket and tries to consume a token.
    fn try_consume(&mut self, config: &RateLimiterConfig) -> (bool, f64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update);

        // Add tokens based on elapsed time
        let tokens_to_add = elapsed.as_secs_f64() * config.rps as f64;
        self.tokens = (self.tokens + tokens_to_add).min(config.burst as f64);
        self.last_update = now;

        // Update request count (rolling window)
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.request_count = 0;
            self.window_start = now;
        }
        self.request_count += 1;

        // Try to consume a token
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            (true, self.request_count as f64)
        } else {
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
}

impl BlockEntry {
    /// Creates a new block entry.
    fn new(duration: Duration) -> Self {
        Self {
            expires_at: Instant::now() + duration,
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

/// Token bucket rate limiter.
#[derive(Debug)]
pub struct RateLimiter {
    /// Configuration.
    config: RateLimiterConfig,
    /// Per-IP token buckets.
    buckets: HashMap<IpAddr, TokenBucket>,
    /// Global token bucket (if not per-IP).
    global_bucket: TokenBucket,
    /// Blocked sources.
    blocked: HashMap<IpAddr, BlockEntry>,
}

impl RateLimiter {
    /// Creates a new rate limiter.
    pub fn new(config: RateLimiterConfig) -> Self {
        let global_bucket = TokenBucket::new(config.burst);
        Self {
            config,
            buckets: HashMap::new(),
            global_bucket,
            blocked: HashMap::new(),
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

    /// Checks if a source is blocked.
    pub fn is_blocked(&self, source: IpAddr) -> bool {
        if let Some(entry) = self.blocked.get(&source) {
            !entry.is_expired()
        } else {
            false
        }
    }

    /// Returns the remaining block time for a source.
    pub fn block_remaining(&self, source: IpAddr) -> Option<Duration> {
        self.blocked.get(&source).and_then(|entry| {
            if entry.is_expired() {
                None
            } else {
                Some(entry.remaining())
            }
        })
    }

    /// Blocks a source.
    pub fn block(&mut self, source: IpAddr, duration: Duration) {
        self.blocked.insert(source, BlockEntry::new(duration));
    }

    /// Unblocks a source.
    pub fn unblock(&mut self, source: IpAddr) {
        self.blocked.remove(&source);
    }

    /// Checks a request and returns the action to take.
    pub fn check(&mut self, source: IpAddr) -> RateLimitAction {
        // Check if blocked
        if let Some(entry) = self.blocked.get(&source) {
            if entry.is_expired() {
                // Clean up expired block
                self.blocked.remove(&source);
            } else {
                return RateLimitAction::Block {
                    duration_secs: entry.remaining().as_secs(),
                };
            }
        }

        // Get or create bucket
        let (allowed, rate) = if self.config.per_ip {
            let bucket = self
                .buckets
                .entry(source)
                .or_insert_with(|| TokenBucket::new(self.config.burst));
            bucket.try_consume(&self.config)
        } else {
            self.global_bucket.try_consume(&self.config)
        };

        if allowed {
            // Check if we should warn/throttle
            if rate > self.config.rps as f64 * 0.8 {
                // Over 80% of limit, suggest throttling
                let delay_ms = ((self.config.rps as f64).mul_add(-0.8, rate) * 10.0) as u64;
                RateLimitAction::Throttle { delay_ms }
            } else {
                RateLimitAction::Allow
            }
        } else {
            // Check if we should block
            let block_threshold = self.config.rps as f64 * self.config.block_threshold_multiplier;
            if rate >= block_threshold {
                self.block(source, Duration::from_secs(self.config.block_duration_secs));
                RateLimitAction::Block {
                    duration_secs: self.config.block_duration_secs,
                }
            } else {
                RateLimitAction::Reject
            }
        }
    }

    /// Cleans up expired entries.
    pub fn cleanup(&mut self) {
        // Remove expired blocks
        self.blocked.retain(|_, entry| !entry.is_expired());

        // Optionally clean up old buckets (not implemented to avoid removing
        // buckets for legitimate but temporarily quiet sources)
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
            self.buckets.get(&source).map(TokenBucket::token_count)
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
            assert!(action.is_allowed(), "Expected allowed, got {:?}", action);
        }

        // Next request should be rejected (out of tokens)
        let action = limiter.check(ip);
        assert!(action.is_rejected(), "Expected rejected, got {:?}", action);
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
}
