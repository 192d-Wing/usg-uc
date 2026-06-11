//! The VPS screening engine.

use crate::blocklist::Blocklist;
use crate::call_limiter::{CallLimiter, CallLimiterConfig};
use crate::config::{
    ScreeningMode, VpsConfig, VpsDefaultAction, VpsRuleAction, VpsRuleConfig,
};
use crate::context::{CallAttempt, CallDirection};
use crate::error::{VpsError, VpsResult};
use crate::verdict::{VerdictSource, VpsVerdict};
use chrono::{Datelike, Timelike};
use std::net::IpAddr;
use std::time::Duration;
use tracing::warn;
use uc_dos_protection::RateLimitAction;
use uc_policy::condition::{RequestContext, StringMatch};
use uc_policy::engine::PolicyEngineConfig;
use uc_policy::rule::RulePriority;
use uc_policy::{Condition, PolicyAction, PolicyEngine, PolicyRule};

/// Screening statistics, by outcome.
#[derive(Debug, Clone, Copy, Default)]
pub struct VpsStats {
    /// Total call attempts screened.
    pub screened: u64,
    /// Attempts allowed.
    pub allowed: u64,
    /// Attempts rejected by the blocklist.
    pub rejected_blocklist: u64,
    /// Attempts rejected/dropped by the call rate limit.
    pub rejected_rate: u64,
    /// Attempts rejected by the per-callee concurrency cap.
    pub rejected_concurrency: u64,
    /// Attempts rejected by STIR/SHAKEN screening.
    pub rejected_stir_shaken: u64,
    /// Attempts rejected by a policy rule or default-deny.
    pub rejected_policy: u64,
}

/// The Voice Protection System engine.
///
/// One instance per daemon; callers serialize access (the SIP stack holds
/// it behind a mutex). All checks are in-memory and non-blocking.
#[derive(Debug)]
pub struct VpsEngine {
    config: VpsConfig,
    policy: PolicyEngine,
    limiter: CallLimiter,
    blocklist: Blocklist,
    stats: VpsStats,
}

impl VpsEngine {
    /// Builds an engine from configuration. Fails on an invalid config
    /// (duplicate rule IDs, bad status codes, malformed blocked IPs).
    pub fn new(config: &VpsConfig) -> VpsResult<Self> {
        config
            .validate()
            .map_err(VpsError::invalid_config)?;

        let default_action = match config.default_action {
            VpsDefaultAction::Allow => PolicyAction::Allow,
            VpsDefaultAction::Deny => {
                PolicyAction::deny(crate::DEFAULT_DENY_STATUS, "Forbidden by voice protection policy")
            }
        };
        let mut policy = PolicyEngine::new(PolicyEngineConfig {
            default_action,
            ..PolicyEngineConfig::default()
        });
        for rule in &config.rules {
            policy.add_global_rule(Self::compile_rule(rule))?;
        }

        let mut blocklist = Blocklist::new();
        for source in &config.blocked_sources {
            if let Ok(ip) = source.parse::<IpAddr>() {
                blocklist.block_source(ip, None);
            }
        }
        for prefix in &config.blocked_caller_prefixes {
            blocklist.block_caller_prefix(prefix.clone(), None);
        }

        Ok(Self {
            limiter: CallLimiter::new(CallLimiterConfig::from(&config.tdos)),
            config: config.clone(),
            policy,
            blocklist,
            stats: VpsStats::default(),
        })
    }

    /// Compiles a declarative rule into a `uc-policy` rule.
    fn compile_rule(rule: &VpsRuleConfig) -> PolicyRule {
        let mut conditions = Vec::new();
        if let Some(ref prefix) = rule.caller_prefix {
            conditions.push(Condition::CallerId(StringMatch::Prefix(prefix.clone())));
        }
        if let Some(ref prefix) = rule.callee_prefix {
            conditions.push(Condition::CalledNumber(StringMatch::Prefix(prefix.clone())));
        }
        if let Some(ref source) = rule.source_ip {
            conditions.push(Condition::SourceIp(source.clone()));
        }
        if let (Some(start), Some(end)) = (rule.time_start_hour, rule.time_end_hour) {
            if start <= end {
                conditions.push(Condition::TimeOfDay {
                    start_hour: start,
                    end_hour: end,
                });
            } else {
                // Window wraps midnight (e.g. 18..6).
                conditions.push(Condition::Any(vec![
                    Condition::TimeOfDay {
                        start_hour: start,
                        end_hour: 23,
                    },
                    Condition::TimeOfDay {
                        start_hour: 0,
                        end_hour: end,
                    },
                ]));
            }
        }
        if let Some(ref days) = rule.days {
            conditions.push(Condition::DayOfWeek { days: days.clone() });
        }
        let condition = match conditions.len() {
            0 => Condition::Always,
            1 => conditions.remove(0),
            _ => Condition::All(conditions),
        };

        let action = match rule.action {
            VpsRuleAction::Allow => PolicyAction::Allow,
            VpsRuleAction::Deny => PolicyAction::deny(rule.status_code, rule.reason.clone()),
        };

        PolicyRule::new(rule.id.clone(), rule.description.clone(), condition, action)
            .with_priority(RulePriority::custom(rule.priority))
    }

    /// Screens a call attempt. See the crate docs for evaluation order.
    pub fn screen_call(&mut self, attempt: &CallAttempt) -> VpsVerdict {
        if !self.config.enabled {
            return VpsVerdict::allow(VerdictSource::Disabled);
        }
        self.stats.screened += 1;

        // 1. Blocklist.
        if let Some(source) = attempt.source_ip
            && self.blocklist.is_source_blocked(source)
        {
            self.stats.rejected_blocklist += 1;
            return VpsVerdict::drop_silently(VerdictSource::Blocklist);
        }
        if let Some(ref caller) = attempt.caller
            && let Some(prefix) = self.blocklist.caller_block_match(caller)
        {
            self.stats.rejected_blocklist += 1;
            return VpsVerdict::reject(
                VerdictSource::Blocklist,
                crate::DEFAULT_DENY_STATUS,
                "Caller blocked by voice protection policy",
            )
            .with_rule(format!("blocklist:{prefix}"));
        }

        // 2. Per-source call-attempt rate limit.
        if let Some(source) = attempt.source_ip {
            match self.limiter.check_invite(source) {
                RateLimitAction::Allow | RateLimitAction::Throttle { .. } => {}
                RateLimitAction::Reject => {
                    self.stats.rejected_rate += 1;
                    return VpsVerdict::reject(
                        VerdictSource::CallRateLimit,
                        crate::RATE_LIMIT_STATUS,
                        "Call rate exceeded",
                    );
                }
                RateLimitAction::Block { .. } => {
                    // Sustained abuse: answering a spoofed flood is
                    // amplification, so say nothing.
                    self.stats.rejected_rate += 1;
                    return VpsVerdict::drop_silently(VerdictSource::CallRateLimit);
                }
            }
        }

        // 3. Per-callee concurrency cap.
        if let Some(ref callee) = attempt.callee
            && self.limiter.callee_at_capacity(callee)
        {
            self.stats.rejected_concurrency += 1;
            return VpsVerdict::reject(
                VerdictSource::ConcurrencyCap,
                crate::CONCURRENCY_CAP_STATUS,
                "Destination at capacity",
            );
        }

        // 4. STIR/SHAKEN screening (inbound trunk calls only).
        if let Some(verdict) = self.screen_stir_shaken(attempt) {
            self.stats.rejected_stir_shaken += 1;
            return verdict;
        }

        // 5/6. Declarative policy rules, then the default action.
        let decision = self.policy.evaluate(&Self::request_context(attempt));
        if decision.is_allowed() {
            self.stats.allowed += 1;
            let source = if decision.matched_rule_id().is_some() {
                VerdictSource::PolicyRule
            } else {
                VerdictSource::Default
            };
            let verdict = VpsVerdict::allow(source);
            match decision.matched_rule_id() {
                Some(rule) => verdict.with_rule(rule),
                None => verdict,
            }
        } else {
            self.stats.rejected_policy += 1;
            let (status_code, reason) = match decision.action() {
                PolicyAction::Deny {
                    status_code,
                    reason,
                } => (*status_code, reason.clone()),
                _ => (
                    crate::DEFAULT_DENY_STATUS,
                    "Forbidden by voice protection policy".to_string(),
                ),
            };
            let source = if decision.matched_rule_id().is_some() {
                VerdictSource::PolicyRule
            } else {
                VerdictSource::Default
            };
            let verdict = VpsVerdict::reject(source, status_code, reason);
            match decision.matched_rule_id() {
                Some(rule) => verdict.with_rule(rule),
                None => verdict,
            }
        }
    }

    /// STIR/SHAKEN screening; returns a reject verdict on violation.
    fn screen_stir_shaken(&self, attempt: &CallAttempt) -> Option<VpsVerdict> {
        let ss = &self.config.stir_shaken;
        if ss.mode == ScreeningMode::Off || attempt.direction != CallDirection::Inbound {
            return None;
        }

        let violation = attempt.stir_shaken.attestation().map_or(
            matches!(attempt.stir_shaken, crate::context::StirShakenStatus::Failed)
                || ss.require_identity_header,
            |level| level < ss.minimum_attestation,
        );
        if !violation {
            return None;
        }

        if ss.mode == ScreeningMode::LogOnly {
            warn!(
                caller = attempt.caller.as_deref().unwrap_or("unknown"),
                status = ?attempt.stir_shaken,
                "STIR/SHAKEN screening violation (log-only)"
            );
            return None;
        }

        Some(VpsVerdict::reject(
            VerdictSource::StirShaken,
            crate::STIR_SHAKEN_FAILED_STATUS,
            "Bad Identity Info",
        ))
    }

    /// Screens a REGISTER attempt from a source.
    pub fn screen_register(&mut self, source: IpAddr) -> VpsVerdict {
        if !self.config.enabled {
            return VpsVerdict::allow(VerdictSource::Disabled);
        }
        if self.blocklist.is_source_blocked(source) {
            return VpsVerdict::drop_silently(VerdictSource::Blocklist);
        }
        match self.limiter.check_register(source) {
            RateLimitAction::Allow | RateLimitAction::Throttle { .. } => {
                VpsVerdict::allow(VerdictSource::Default)
            }
            RateLimitAction::Reject => VpsVerdict::reject(
                VerdictSource::CallRateLimit,
                crate::RATE_LIMIT_STATUS,
                "Registration rate exceeded",
            ),
            RateLimitAction::Block { .. } => {
                VpsVerdict::drop_silently(VerdictSource::CallRateLimit)
            }
        }
    }

    /// Records a screened call becoming active (concurrency accounting).
    pub fn call_started(&mut self, callee: &str) {
        self.limiter.call_started(callee);
    }

    /// Records a call ending (concurrency accounting).
    pub fn call_ended(&mut self, callee: &str) {
        self.limiter.call_ended(callee);
    }

    /// Installs a timed (or permanent) source block. The surface the
    /// phase-3 `VpsPolicySync` service drives.
    pub fn block_source(&mut self, source: IpAddr, duration: Option<Duration>) {
        self.blocklist.block_source(source, duration);
    }

    /// Removes a source block.
    pub fn unblock_source(&mut self, source: IpAddr) {
        self.blocklist.unblock_source(source);
    }

    /// Installs a timed (or permanent) caller-prefix block.
    pub fn block_caller_prefix(&mut self, prefix: impl Into<String>, duration: Option<Duration>) {
        self.blocklist.block_caller_prefix(prefix, duration);
    }

    /// Removes a caller-prefix block.
    pub fn unblock_caller_prefix(&mut self, prefix: &str) {
        self.blocklist.unblock_caller_prefix(prefix);
    }

    /// Screening statistics.
    pub fn stats(&self) -> &VpsStats {
        &self.stats
    }

    /// Removes expired blocklist and rate-limit entries. Call
    /// periodically (e.g. from the daemon's housekeeping tick).
    pub fn cleanup(&mut self) {
        self.blocklist.cleanup();
        self.limiter.cleanup();
    }

    /// Builds a `uc-policy` request context from a call attempt, stamping
    /// the local wall-clock for time-based conditions.
    fn request_context(attempt: &CallAttempt) -> RequestContext {
        let now = chrono::Local::now();
        let mut ctx = RequestContext::new()
            .with_method("INVITE")
            .with_current_hour(now.hour() as u8)
            .with_current_day(now.weekday().num_days_from_sunday() as u8);
        if let Some(source) = attempt.source_ip {
            ctx = ctx.with_source_ip(source.to_string());
        }
        if let Some(ref caller) = attempt.caller {
            ctx = ctx.with_caller_id(caller.clone());
        }
        if let Some(ref callee) = attempt.callee {
            ctx = ctx.with_called_number(callee.clone());
        }
        if let Some(ref uri) = attempt.from_uri {
            ctx = ctx.with_from_uri(uri.clone());
        }
        if let Some(ref uri) = attempt.to_uri {
            ctx = ctx.with_to_uri(uri.clone());
        }
        if let Some(ref uri) = attempt.request_uri {
            ctx = ctx.with_request_uri(uri.clone());
        }
        ctx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{StirShakenScreeningConfig, TdosConfig, VpsRuleConfig};
    use crate::context::StirShakenStatus;
    use crate::verdict::VpsAction;
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn enabled_config() -> VpsConfig {
        VpsConfig {
            enabled: true,
            tdos: TdosConfig {
                per_source_cps: 0,
                register_per_source_rps: 0,
                ..TdosConfig::default()
            },
            ..VpsConfig::default()
        }
    }

    fn attempt(source: IpAddr) -> CallAttempt {
        CallAttempt::new(source)
            .with_caller("+12135551000")
            .with_callee("+12135552000")
    }

    #[test]
    fn test_disabled_allows_everything() {
        let mut engine = VpsEngine::new(&VpsConfig::default()).unwrap();
        let verdict = engine.screen_call(&attempt(ip(1)));
        assert!(verdict.is_allowed());
        assert_eq!(verdict.source(), VerdictSource::Disabled);
        assert_eq!(engine.stats().screened, 0);
    }

    #[test]
    fn test_default_allow() {
        let mut engine = VpsEngine::new(&enabled_config()).unwrap();
        let verdict = engine.screen_call(&attempt(ip(1)));
        assert!(verdict.is_allowed());
        assert_eq!(verdict.source(), VerdictSource::Default);
        assert_eq!(engine.stats().allowed, 1);
    }

    #[test]
    fn test_default_deny() {
        let config = VpsConfig {
            default_action: crate::config::VpsDefaultAction::Deny,
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        let verdict = engine.screen_call(&attempt(ip(1)));
        assert!(!verdict.is_allowed());
        assert_eq!(verdict.source(), VerdictSource::Default);
    }

    #[test]
    fn test_blocked_source_dropped_silently() {
        let config = VpsConfig {
            blocked_sources: vec!["10.0.0.9".to_string()],
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        let verdict = engine.screen_call(&attempt(ip(9)));
        assert_eq!(*verdict.action(), VpsAction::Drop);
        assert_eq!(verdict.source(), VerdictSource::Blocklist);
    }

    #[test]
    fn test_blocked_caller_prefix() {
        let config = VpsConfig {
            blocked_caller_prefixes: vec!["+1900".to_string()],
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        let verdict =
            engine.screen_call(&attempt(ip(1)).with_caller("+19005551234"));
        assert!(!verdict.is_allowed());
        assert_eq!(verdict.matched_rule(), Some("blocklist:+1900"));
    }

    #[test]
    fn test_call_rate_limit() {
        let config = VpsConfig {
            tdos: TdosConfig {
                per_source_cps: 2,
                per_source_burst: 2,
                ..TdosConfig::default()
            },
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        assert!(engine.screen_call(&attempt(ip(1))).is_allowed());
        assert!(engine.screen_call(&attempt(ip(1))).is_allowed());
        let verdict = engine.screen_call(&attempt(ip(1)));
        assert!(!verdict.is_allowed());
        assert_eq!(verdict.source(), VerdictSource::CallRateLimit);
        // A different source is unaffected.
        assert!(engine.screen_call(&attempt(ip(2))).is_allowed());
    }

    #[test]
    fn test_concurrency_cap() {
        let config = VpsConfig {
            tdos: TdosConfig {
                per_source_cps: 0,
                per_callee_max_concurrent: 1,
                ..TdosConfig::default()
            },
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        assert!(engine.screen_call(&attempt(ip(1))).is_allowed());
        engine.call_started("+12135552000");

        let verdict = engine.screen_call(&attempt(ip(2)));
        assert!(!verdict.is_allowed());
        assert_eq!(verdict.source(), VerdictSource::ConcurrencyCap);

        engine.call_ended("+12135552000");
        assert!(engine.screen_call(&attempt(ip(3))).is_allowed());
    }

    #[test]
    fn test_policy_rule_deny() {
        let config = VpsConfig {
            rules: vec![VpsRuleConfig {
                id: "block-premium".to_string(),
                callee_prefix: Some("1900".to_string()),
                ..VpsRuleConfig::default()
            }],
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();

        let verdict = engine.screen_call(
            &attempt(ip(1)).with_callee("19005551234"),
        );
        assert!(!verdict.is_allowed());
        assert_eq!(verdict.source(), VerdictSource::PolicyRule);
        assert_eq!(verdict.matched_rule(), Some("block-premium"));

        // Non-matching callee allowed.
        assert!(engine.screen_call(&attempt(ip(1))).is_allowed());
    }

    #[test]
    fn test_stir_shaken_enforce() {
        let config = VpsConfig {
            stir_shaken: StirShakenScreeningConfig {
                mode: ScreeningMode::Enforce,
                minimum_attestation: crate::config::AttestationLevel::B,
                require_identity_header: false,
            },
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();

        // Failed verification on an inbound call → 438.
        let verdict = engine.screen_call(
            &attempt(ip(1))
                .with_direction(CallDirection::Inbound)
                .with_stir_shaken(StirShakenStatus::Failed),
        );
        assert!(!verdict.is_allowed());
        assert_eq!(verdict.source(), VerdictSource::StirShaken);

        // Attestation below minimum → 438.
        let verdict = engine.screen_call(
            &attempt(ip(1))
                .with_direction(CallDirection::Inbound)
                .with_stir_shaken(StirShakenStatus::VerifiedC),
        );
        assert!(!verdict.is_allowed());

        // Attestation at minimum → allowed.
        assert!(engine
            .screen_call(
                &attempt(ip(1))
                    .with_direction(CallDirection::Inbound)
                    .with_stir_shaken(StirShakenStatus::VerifiedB),
            )
            .is_allowed());

        // Missing Identity header allowed unless required.
        assert!(engine
            .screen_call(&attempt(ip(1)).with_direction(CallDirection::Inbound))
            .is_allowed());

        // Internal calls never screened.
        assert!(engine
            .screen_call(
                &attempt(ip(1))
                    .with_direction(CallDirection::Internal)
                    .with_stir_shaken(StirShakenStatus::Failed),
            )
            .is_allowed());
    }

    #[test]
    fn test_stir_shaken_log_only_never_rejects() {
        let config = VpsConfig {
            stir_shaken: StirShakenScreeningConfig {
                mode: ScreeningMode::LogOnly,
                minimum_attestation: crate::config::AttestationLevel::A,
                require_identity_header: true,
            },
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        assert!(engine
            .screen_call(
                &attempt(ip(1))
                    .with_direction(CallDirection::Inbound)
                    .with_stir_shaken(StirShakenStatus::Failed),
            )
            .is_allowed());
    }

    #[test]
    fn test_screen_register() {
        let config = VpsConfig {
            tdos: TdosConfig {
                register_per_source_rps: 2,
                register_burst: 2,
                ..TdosConfig::default()
            },
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        assert!(engine.screen_register(ip(1)).is_allowed());
        assert!(engine.screen_register(ip(1)).is_allowed());
        assert!(!engine.screen_register(ip(1)).is_allowed());
    }

    #[test]
    fn test_dynamic_block_api() {
        let mut engine = VpsEngine::new(&enabled_config()).unwrap();
        assert!(engine.screen_call(&attempt(ip(1))).is_allowed());

        engine.block_source(ip(1), Some(Duration::from_mins(1)));
        assert_eq!(
            *engine.screen_call(&attempt(ip(1))).action(),
            VpsAction::Drop
        );

        engine.unblock_source(ip(1));
        assert!(engine.screen_call(&attempt(ip(1))).is_allowed());
    }

    #[test]
    fn test_invalid_config_rejected() {
        let config = VpsConfig {
            blocked_sources: vec!["bogus".to_string()],
            ..enabled_config()
        };
        assert!(VpsEngine::new(&config).is_err());
    }
}
