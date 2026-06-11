//! Call-level TDoS counters.
//!
//! The packet-level limiters in `sbc-daemon`'s server loop shed floods
//! before parsing; this layer limits *call attempts* — INVITEs per second
//! per source, REGISTERs per second per source, and concurrent calls per
//! callee — which is where TDoS against a hotline or operator DID shows
//! up even at modest packet rates.
//!
//! ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection)

use std::collections::HashMap;
use std::net::IpAddr;
use uc_dos_protection::{RateLimitAction, RateLimiter, RateLimiterConfig};

/// Configuration for the call-level limiter, derived from
/// [`crate::config::TdosConfig`].
#[derive(Debug, Clone)]
pub struct CallLimiterConfig {
    /// Maximum INVITE attempts per second per source IP (0 = disabled).
    pub per_source_cps: u32,
    /// Burst allowance for the INVITE bucket.
    pub per_source_burst: u32,
    /// Maximum REGISTERs per second per source IP (0 = disabled).
    pub register_per_source_rps: u32,
    /// Burst allowance for the REGISTER bucket.
    pub register_burst: u32,
    /// Block duration applied on sustained abuse, in seconds.
    pub block_duration_secs: u64,
    /// Maximum concurrent calls per callee (0 = unlimited).
    pub per_callee_max_concurrent: u32,
}

impl From<&crate::config::TdosConfig> for CallLimiterConfig {
    fn from(config: &crate::config::TdosConfig) -> Self {
        Self {
            per_source_cps: config.per_source_cps,
            per_source_burst: config.per_source_burst,
            register_per_source_rps: config.register_per_source_rps,
            register_burst: config.register_burst,
            block_duration_secs: config.block_duration_secs,
            per_callee_max_concurrent: config.per_callee_max_concurrent,
        }
    }
}

/// Call-level rate limiter and concurrency tracker.
#[derive(Debug)]
pub struct CallLimiter {
    config: CallLimiterConfig,
    /// Per-source INVITE token buckets (None when disabled).
    invite_limiter: Option<RateLimiter>,
    /// Per-source REGISTER token buckets (None when disabled).
    register_limiter: Option<RateLimiter>,
    /// Concurrent call count per callee number.
    concurrent_by_callee: HashMap<String, u32>,
}

impl CallLimiter {
    /// Creates a limiter from configuration.
    pub fn new(config: CallLimiterConfig) -> Self {
        let invite_limiter = (config.per_source_cps > 0).then(|| {
            RateLimiter::new(
                RateLimiterConfig::new(config.per_source_cps, config.per_source_burst)
                    .with_block_duration(config.block_duration_secs)
                    .with_per_ip(true),
            )
        });
        let register_limiter = (config.register_per_source_rps > 0).then(|| {
            RateLimiter::new(
                RateLimiterConfig::new(config.register_per_source_rps, config.register_burst)
                    .with_block_duration(config.block_duration_secs)
                    .with_per_ip(true),
            )
        });
        Self {
            config,
            invite_limiter,
            register_limiter,
            concurrent_by_callee: HashMap::new(),
        }
    }

    /// Checks an INVITE attempt from a source.
    pub fn check_invite(&mut self, source: IpAddr) -> RateLimitAction {
        self.invite_limiter
            .as_mut()
            .map_or(RateLimitAction::Allow, |limiter| limiter.check(source))
    }

    /// Checks a REGISTER attempt from a source.
    pub fn check_register(&mut self, source: IpAddr) -> RateLimitAction {
        self.register_limiter
            .as_mut()
            .map_or(RateLimitAction::Allow, |limiter| limiter.check(source))
    }

    /// Whether a new call to `callee` would exceed the concurrency cap.
    pub fn callee_at_capacity(&self, callee: &str) -> bool {
        if self.config.per_callee_max_concurrent == 0 {
            return false;
        }
        self.concurrent_by_callee
            .get(callee)
            .is_some_and(|count| *count >= self.config.per_callee_max_concurrent)
    }

    /// Records a call to `callee` becoming active.
    pub fn call_started(&mut self, callee: &str) {
        *self
            .concurrent_by_callee
            .entry(callee.to_string())
            .or_insert(0) += 1;
    }

    /// Records a call to `callee` ending.
    pub fn call_ended(&mut self, callee: &str) {
        if let Some(count) = self.concurrent_by_callee.get_mut(callee) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.concurrent_by_callee.remove(callee);
            }
        }
    }

    /// Current concurrent call count for a callee.
    pub fn concurrent_calls(&self, callee: &str) -> u32 {
        self.concurrent_by_callee.get(callee).copied().unwrap_or(0)
    }

    /// Removes expired rate-limit blocks.
    pub fn cleanup(&mut self) {
        if let Some(ref mut limiter) = self.invite_limiter {
            limiter.cleanup();
        }
        if let Some(ref mut limiter) = self.register_limiter {
            limiter.cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    fn config(cps: u32, burst: u32, max_concurrent: u32) -> CallLimiterConfig {
        CallLimiterConfig {
            per_source_cps: cps,
            per_source_burst: burst,
            register_per_source_rps: cps,
            register_burst: burst,
            block_duration_secs: 60,
            per_callee_max_concurrent: max_concurrent,
        }
    }

    #[test]
    fn test_invite_rate_limit() {
        let mut limiter = CallLimiter::new(config(10, 3, 0));

        for _ in 0..3 {
            assert!(limiter.check_invite(ip()).is_allowed());
        }
        assert!(limiter.check_invite(ip()).is_rejected());
    }

    #[test]
    fn test_disabled_when_zero() {
        let mut limiter = CallLimiter::new(config(0, 0, 0));
        for _ in 0..100 {
            assert!(limiter.check_invite(ip()).is_allowed());
            assert!(limiter.check_register(ip()).is_allowed());
        }
    }

    #[test]
    fn test_concurrency_cap() {
        let mut limiter = CallLimiter::new(config(0, 0, 2));

        assert!(!limiter.callee_at_capacity("1000"));
        limiter.call_started("1000");
        limiter.call_started("1000");
        assert!(limiter.callee_at_capacity("1000"));
        assert!(!limiter.callee_at_capacity("2000"));

        limiter.call_ended("1000");
        assert!(!limiter.callee_at_capacity("1000"));
        assert_eq!(limiter.concurrent_calls("1000"), 1);
    }

    #[test]
    fn test_call_ended_underflow_safe() {
        let mut limiter = CallLimiter::new(config(0, 0, 1));
        limiter.call_ended("never-started");
        assert_eq!(limiter.concurrent_calls("never-started"), 0);
    }
}
