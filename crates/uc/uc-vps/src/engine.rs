//! The VPS screening engine.

use crate::blocklist::Blocklist;
use crate::call_limiter::{CallLimiter, CallLimiterConfig};
use crate::config::{ScreeningMode, VpsConfig, VpsDefaultAction, VpsRuleAction, VpsRuleConfig};
use crate::context::{CallAttempt, CallDirection};
use crate::emergency::EmergencyNumbers;
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
    /// Emergency calls let through without screening.
    pub emergency_bypassed: u64,
}

/// The Voice Protection System engine.
///
/// One instance per daemon; callers serialize access (the SIP stack holds
/// it behind a mutex). All checks are in-memory and non-blocking.
#[derive(Debug)]
pub struct VpsEngine {
    config: VpsConfig,
    emergency: EmergencyNumbers,
    policy: PolicyEngine,
    limiter: CallLimiter,
    blocklist: Blocklist,
    stats: VpsStats,
}

impl VpsEngine {
    /// Builds an engine from configuration. Fails on an invalid config
    /// (duplicate rule IDs, bad status codes, malformed blocked IPs).
    pub fn new(config: &VpsConfig) -> VpsResult<Self> {
        config.validate().map_err(VpsError::invalid_config)?;

        let default_action = match config.default_action {
            VpsDefaultAction::Allow => PolicyAction::Allow,
            VpsDefaultAction::Deny => PolicyAction::deny(
                crate::DEFAULT_DENY_STATUS,
                "Forbidden by voice protection policy",
            ),
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
            emergency: EmergencyNumbers::new(&config.emergency_numbers),
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
            // NIST 800-53 Rev5: AC-3, SI-10 — prefixes are canonicalised at
            // load and compared against the canonical caller/callee.
            conditions.push(Condition::CallerId(StringMatch::Prefix(
                uc_types::canonical_prefix(prefix),
            )));
        }
        if let Some(ref prefix) = rule.callee_prefix {
            conditions.push(Condition::CalledNumber(StringMatch::Prefix(
                uc_types::canonical_prefix(prefix),
            )));
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

    /// Whether `dialed` (a Request-URI, or its user part) is a configured
    /// emergency number. Evaluated whether or not the VPS is enabled, so
    /// the SIP stack can apply the same classification to its own
    /// capacity limits. Allocation-free.
    ///
    /// ## 47 CFR 9.16; NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
    pub fn is_emergency(&self, dialed: &str) -> bool {
        self.emergency.matches(dialed)
    }

    /// Canonicalises the attempt's caller and callee once
    /// (`uc_types::DialedNumber` screening keys), so the blocklist, policy
    /// prefixes, emergency check and per-callee cap all compare the same
    /// form. Idempotent on already-canonical input.
    ///
    /// ## NIST 800-53 Rev5: SI-10 (Information Input Validation), AC-3
    fn canonical_attempt(attempt: &CallAttempt) -> CallAttempt {
        let mut canon = attempt.clone();
        canon.callee = attempt
            .callee
            .as_deref()
            .map(crate::emergency::screening_key);
        canon.caller = attempt
            .caller
            .as_deref()
            .map(crate::emergency::screening_key);
        canon
    }

    /// Screens a call attempt. See the crate docs for evaluation order.
    /// Caller and callee are compared in canonical form.
    pub fn screen_call(&mut self, attempt: &CallAttempt) -> VpsVerdict {
        let canon = Self::canonical_attempt(attempt);
        self.screen_canonical(&canon)
    }

    /// [`Self::screen_call`] on an attempt already canonicalised.
    fn screen_canonical(&mut self, attempt: &CallAttempt) -> VpsVerdict {
        if !self.config.enabled {
            return VpsVerdict::allow(VerdictSource::Disabled);
        }
        self.stats.screened += 1;

        // 0. Operator source-IP blocks apply to every call, emergency
        // included: an operator who blocked an abusive source must be able
        // to stop it dialing 911 too.
        if let Some(source) = attempt.source_ip
            && self.blocklist.is_source_blocked(source)
        {
            self.stats.rejected_blocklist += 1;
            return VpsVerdict::drop_silently(VerdictSource::Blocklist);
        }

        // 1. Emergency numbers are not screened out by number/caller
        // policy: caller blocklist, rate limit, per-callee cap, STIR/SHAKEN
        // and deny rules would all block a 911 call (47 CFR 9.16). The SIP
        // stack still enforces ACLs, authentication, the transport flood
        // limiter and the bounded emergency reserve, and audits the bypass.
        if let Some(ref callee) = attempt.callee
            && self.is_emergency(callee)
        {
            self.stats.emergency_bypassed += 1;
            self.stats.allowed += 1;
            return VpsVerdict::allow(VerdictSource::EmergencyBypass);
        }

        // 1b. Caller-prefix blocklist.
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
            matches!(
                attempt.stir_shaken,
                crate::context::StirShakenStatus::Failed
            ) || ss.require_identity_header,
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

    /// Screens a call attempt and, when it is allowed, reserves a
    /// per-callee concurrency slot in the same step, so the cap check and
    /// the increment cannot be split by another caller.
    ///
    /// Returns the verdict and the callee key that was reserved. A key is
    /// reserved only when the call is allowed, carries a callee and
    /// `per_callee_max_concurrent` is non-zero; the caller must pass that
    /// key to [`Self::call_ended`] exactly once when the call goes away.
    ///
    /// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
    ///
    /// The reserved key is the canonical screening key of the callee, so
    /// `+15551234567` and `1 (555) 123-4567` share one slot.
    pub fn screen_and_reserve(&mut self, attempt: &CallAttempt) -> (VpsVerdict, Option<String>) {
        let attempt = &Self::canonical_attempt(attempt);
        let verdict = self.screen_canonical(attempt);
        // An emergency call takes no slot, so held emergency calls never
        // fill the cap against further ones.
        if !verdict.is_allowed()
            || verdict.source() == VerdictSource::EmergencyBypass
            || !self.config.enabled
            || self.limiter.per_callee_max_concurrent() == 0
        {
            return (verdict, None);
        }
        // POAM: POA&M-81 — `per_callee_max_concurrent` is counted per node and is NOT
        // divided by `cluster.admission` (a cap of 1 cannot be split); an
        // N-node cluster admits up to N x cap per callee. Accepted risk.
        let reserved = attempt.callee.clone();
        if let Some(ref callee) = reserved {
            self.limiter.call_started(callee);
        }
        (verdict, reserved)
    }

    /// Current concurrent call count for a callee.
    /// `callee` is canonicalised (idempotent on a reserved key).
    pub fn callee_concurrent_calls(&self, callee: &str) -> u32 {
        self.limiter
            .concurrent_calls(&crate::emergency::screening_key(callee))
    }

    /// Records a screened call becoming active (concurrency accounting).
    /// `callee` is canonicalised.
    pub fn call_started(&mut self, callee: &str) {
        self.limiter
            .call_started(&crate::emergency::screening_key(callee));
    }

    /// Records a call ending (concurrency accounting). `callee` is
    /// canonicalised, so the key returned by [`Self::screen_and_reserve`]
    /// and the dialed form release the same slot.
    pub fn call_ended(&mut self, callee: &str) {
        self.limiter
            .call_ended(&crate::emergency::screening_key(callee));
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
        let verdict = engine.screen_call(&attempt(ip(1)).with_caller("+19005551234"));
        assert!(!verdict.is_allowed());
        assert_eq!(verdict.matched_rule(), Some("blocklist:1900"));
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
    fn test_screen_and_reserve_caps_concurrency() {
        let config = VpsConfig {
            tdos: TdosConfig {
                per_source_cps: 0,
                per_callee_max_concurrent: 2,
                ..TdosConfig::default()
            },
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        let (v1, k1) = engine.screen_and_reserve(&attempt(ip(1)));
        let (v2, k2) = engine.screen_and_reserve(&attempt(ip(2)));
        assert!(v1.is_allowed() && v2.is_allowed());
        assert_eq!(k1.as_deref(), Some("12135552000"));
        assert!(k2.is_some());
        assert_eq!(engine.callee_concurrent_calls("+12135552000"), 2);

        // The third concurrent call is rejected and reserves nothing.
        let (v3, k3) = engine.screen_and_reserve(&attempt(ip(3)));
        assert_eq!(v3.source(), VerdictSource::ConcurrencyCap);
        assert!(k3.is_none());
        assert_eq!(engine.callee_concurrent_calls("+12135552000"), 2);

        engine.call_ended("+12135552000");
        let (v4, k4) = engine.screen_and_reserve(&attempt(ip(4)));
        assert!(v4.is_allowed());
        assert!(k4.is_some());
    }

    #[test]
    fn test_screen_and_reserve_without_cap_reserves_nothing() {
        let mut engine = VpsEngine::new(&enabled_config()).unwrap();
        let (verdict, key) = engine.screen_and_reserve(&attempt(ip(1)));
        assert!(verdict.is_allowed());
        assert!(key.is_none());
        assert_eq!(engine.callee_concurrent_calls("+12135552000"), 0);

        let mut disabled = VpsEngine::new(&VpsConfig::default()).unwrap();
        let (verdict, key) = disabled.screen_and_reserve(&attempt(ip(1)));
        assert!(verdict.is_allowed());
        assert!(key.is_none());
    }

    #[test]
    fn canonical_callee_deny_catches_formatting_variants() {
        let config = VpsConfig {
            rules: vec![VpsRuleConfig {
                id: "block-premium".to_string(),
                callee_prefix: Some("1900".to_string()),
                ..VpsRuleConfig::default()
            }],
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        for callee in [
            "+19005551234",
            "1-900-555-1234",
            "%2B19005551234",
            "sip:1(900)5551234@h",
        ] {
            let v = engine.screen_call(&attempt(ip(1)).with_callee(callee));
            assert!(!v.is_allowed(), "{callee}");
        }
        assert!(
            engine
                .screen_call(&attempt(ip(1)).with_callee("+12135551234"))
                .is_allowed()
        );
    }

    #[test]
    fn canonical_caller_blocklist_and_runtime_block() {
        let config = VpsConfig {
            blocked_caller_prefixes: vec!["+1555".to_string()],
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        for caller in ["15551234567", "1-555-123-4567"] {
            let v = engine.screen_call(&attempt(ip(1)).with_caller(caller));
            assert_eq!(v.source(), VerdictSource::Blocklist, "{caller}");
        }
        engine.block_caller_prefix("+1-900", None);
        let v = engine.screen_call(&attempt(ip(1)).with_caller("19005550000"));
        assert_eq!(v.source(), VerdictSource::Blocklist);
    }

    #[test]
    fn qa_deny_emergency_and_cap_alternate_forms() {
        let config = VpsConfig {
            rules: vec![VpsRuleConfig {
                id: "deny-9".to_string(),
                callee_prefix: Some("9".to_string()),
                ..VpsRuleConfig::default()
            }],
            tdos: TdosConfig {
                per_source_cps: 0,
                per_callee_max_concurrent: 1,
                ..TdosConfig::default()
            },
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        // Emergency forms bypass the deny rule.
        for callee in [
            "911",
            "9-1-1",
            "(911)",
            "+911",
            "%39%31%31",
            "sip:911;phone-context=+1@h",
        ] {
            let v = engine.screen_call(&attempt(ip(1)).with_callee(callee));
            assert_eq!(v.source(), VerdictSource::EmergencyBypass, "{callee}");
        }
        // Near-emergency and phone-context variants are denied.
        for callee in ["9111", "9-1-1-1", "95551234;phone-context=+1", "%2B9 555"] {
            let v = engine.screen_call(&attempt(ip(1)).with_callee(callee));
            assert!(!v.is_allowed(), "{callee}");
        }
        // Opaque callee: screening key is the raw user, compared as a
        // string prefix (fails closed for a deny rule).
        assert!(
            !engine
                .screen_call(&attempt(ip(1)).with_callee("9alice"))
                .is_allowed()
        );
        assert!(
            engine
                .screen_call(&attempt(ip(1)).with_callee("alice9"))
                .is_allowed()
        );
        // Per-callee cap: escaped and URI forms share one key.
        let (v1, k1) = engine.screen_and_reserve(&attempt(ip(1)).with_callee("%2B15551234567"));
        assert!(v1.is_allowed());
        assert_eq!(k1.as_deref(), Some("15551234567"));
        for other in [
            "sip:+1-555-123-4567@h;user=phone",
            "1.555.123.4567",
            "15551234567;x=1",
        ] {
            let (v, k) = engine.screen_and_reserve(&attempt(ip(2)).with_callee(other));
            assert_eq!(v.source(), VerdictSource::ConcurrencyCap, "{other}");
            assert!(k.is_none(), "{other}");
        }
        assert_eq!(engine.callee_concurrent_calls("(555) 123-4567"), 0);
        assert_eq!(engine.callee_concurrent_calls("1 555 123 4567"), 1);
        engine.call_ended("+1 (555) 123-4567");
        assert_eq!(engine.callee_concurrent_calls("15551234567"), 0);
    }

    #[test]
    fn qa_caller_blocklist_unblock_is_canonical() {
        let mut engine = VpsEngine::new(&enabled_config()).unwrap();
        engine.block_caller_prefix("%2B1 (555)", None);
        for caller in ["+15550001111", "1-555-000-1111", "sip:15550001111@h"] {
            let v = engine.screen_call(&attempt(ip(1)).with_caller(caller));
            assert_eq!(v.source(), VerdictSource::Blocklist, "{caller}");
        }
        assert!(
            engine
                .screen_call(&attempt(ip(1)).with_caller("+12025550100"))
                .is_allowed()
        );
        engine.unblock_caller_prefix("+1-555");
        assert!(
            engine
                .screen_call(&attempt(ip(1)).with_caller("+15550001111"))
                .is_allowed()
        );
    }

    #[test]
    fn canonical_callee_cap_shares_one_slot() {
        let config = VpsConfig {
            tdos: TdosConfig {
                per_source_cps: 0,
                per_callee_max_concurrent: 1,
                ..TdosConfig::default()
            },
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        let (v1, k1) = engine.screen_and_reserve(&attempt(ip(1)).with_callee("+15551234567"));
        assert!(v1.is_allowed());
        let (v2, _) = engine.screen_and_reserve(&attempt(ip(2)).with_callee("1 (555) 123-4567"));
        assert_eq!(v2.source(), VerdictSource::ConcurrencyCap);
        engine.call_ended(k1.as_deref().unwrap());
        assert_eq!(engine.callee_concurrent_calls("+1-555-123-4567"), 0);
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

        let verdict = engine.screen_call(&attempt(ip(1)).with_callee("19005551234"));
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
        assert!(
            engine
                .screen_call(
                    &attempt(ip(1))
                        .with_direction(CallDirection::Inbound)
                        .with_stir_shaken(StirShakenStatus::VerifiedB),
                )
                .is_allowed()
        );

        // Missing Identity header allowed unless required.
        assert!(
            engine
                .screen_call(&attempt(ip(1)).with_direction(CallDirection::Inbound))
                .is_allowed()
        );

        // Internal calls never screened.
        assert!(
            engine
                .screen_call(
                    &attempt(ip(1))
                        .with_direction(CallDirection::Internal)
                        .with_stir_shaken(StirShakenStatus::Failed),
                )
                .is_allowed()
        );
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
        assert!(
            engine
                .screen_call(
                    &attempt(ip(1))
                        .with_direction(CallDirection::Inbound)
                        .with_stir_shaken(StirShakenStatus::Failed),
                )
                .is_allowed()
        );
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

    fn emergency(source: IpAddr, callee: &str) -> CallAttempt {
        CallAttempt::new(source)
            .with_caller("+12135551000")
            .with_callee(callee)
    }

    #[test]
    fn emergency_match_is_exact_after_separator_strip() {
        let engine = VpsEngine::new(&enabled_config()).unwrap();
        for dialed in [
            "911",
            "933",
            "112",
            "+911",
            "9-1-1",
            "(911)",
            "sip:911@pbx.example.com",
            "tel:911",
            "911;phone-context=+1",
            "sip:911;user=phone@pbx.example.com",
        ] {
            assert!(engine.is_emergency(dialed), "{dialed}");
        }
        for dialed in [
            "9111",
            "+1911",
            "91",
            "",
            "988",
            "sip:pbx.example.com",
            "911a",
        ] {
            assert!(!engine.is_emergency(dialed), "{dialed}");
        }
        let none = VpsEngine::new(&VpsConfig {
            emergency_numbers: Vec::new(),
            ..enabled_config()
        })
        .unwrap();
        assert!(!none.is_emergency("911"));
        // Classification works with the VPS disabled (the SIP stack uses it
        // for its own capacity limits).
        assert!(
            VpsEngine::new(&VpsConfig::default())
                .unwrap()
                .is_emergency("911")
        );
    }

    #[test]
    fn emergency_bypasses_full_per_callee_cap_without_reserving() {
        let config = VpsConfig {
            tdos: TdosConfig {
                per_source_cps: 0,
                per_callee_max_concurrent: 1,
                ..TdosConfig::default()
            },
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        // The cap for 911 is already full.
        engine.call_started("911");
        assert!(engine.limiter.callee_at_capacity("911"));
        let (v, key) = engine.screen_and_reserve(&emergency(ip(1), "911"));
        assert!(v.is_allowed());
        assert_eq!(v.source(), VerdictSource::EmergencyBypass);
        assert!(key.is_none(), "an emergency call takes no slot");
        assert_eq!(engine.callee_concurrent_calls("911"), 1);
        assert_eq!(engine.stats().emergency_bypassed, 1);
        // A non-emergency callee is still capped.
        engine.call_started("+12135552000");
        let (v, _) = engine.screen_and_reserve(&attempt(ip(2)));
        assert_eq!(v.source(), VerdictSource::ConcurrencyCap);
    }

    #[test]
    fn emergency_bypasses_rate_limit_blocklist_and_deny_rules() {
        let config = VpsConfig {
            tdos: TdosConfig {
                per_source_cps: 1,
                per_source_burst: 1,
                ..TdosConfig::default()
            },
            default_action: VpsDefaultAction::Deny,
            blocked_caller_prefixes: vec!["+1213".to_string()],
            rules: vec![VpsRuleConfig {
                id: "deny-911".to_string(),
                callee_prefix: Some("9".to_string()),
                action: VpsRuleAction::Deny,
                ..VpsRuleConfig::default()
            }],
            stir_shaken: StirShakenScreeningConfig {
                mode: ScreeningMode::Enforce,
                require_identity_header: true,
                ..StirShakenScreeningConfig::default()
            },
            ..enabled_config()
        };
        let mut engine = VpsEngine::new(&config).unwrap();
        for _ in 0..5 {
            let attempt = emergency(ip(9), "911")
                .with_caller("+12135550100")
                .with_direction(CallDirection::Inbound);
            let v = engine.screen_call(&attempt);
            assert!(v.is_allowed());
            assert_eq!(v.source(), VerdictSource::EmergencyBypass);
        }
        // The same caller dialing anything else is still rejected.
        assert!(
            !engine
                .screen_call(&attempt(ip(9)).with_caller("+12135550100"))
                .is_allowed()
        );
        assert_eq!(engine.stats().emergency_bypassed, 5);
    }

    #[test]
    fn operator_source_block_still_rejects_emergency_calls() {
        // Decision 7: operator source-IP blocks are not bypassed.
        let mut engine = VpsEngine::new(&enabled_config()).unwrap();
        engine.block_source(ip(9), None);
        let v = engine.screen_call(&emergency(ip(9), "911"));
        assert_eq!(*v.action(), VpsAction::Drop);
        assert_eq!(v.source(), VerdictSource::Blocklist);
        assert_eq!(engine.stats().emergency_bypassed, 0);
        // Another source dialing 911 is still bypassed.
        assert!(engine.screen_call(&emergency(ip(10), "911")).is_allowed());
    }

    #[test]
    fn emergency_numbers_validated() {
        let bad = |list: &[&str]| VpsConfig {
            emergency_numbers: list.iter().map(|s| (*s).to_string()).collect(),
            ..VpsConfig::default()
        };
        assert!(bad(&["911", "*99#", "+112"]).validate().is_ok());
        assert!(bad(&[]).validate().is_ok());
        for list in [&[""][..], &["91 1"], &["911@x"], &["+"], &["9;1"]] {
            assert!(bad(list).validate().is_err(), "{list:?}");
        }
        assert!(
            bad(&["1234567890123456789012345678901234"])
                .validate()
                .is_err()
        );
        let many: Vec<String> = (0..33).map(|i| i.to_string()).collect();
        assert!(
            VpsConfig {
                emergency_numbers: many,
                ..VpsConfig::default()
            }
            .validate()
            .is_err()
        );
        assert_eq!(
            VpsConfig::default().emergency_numbers,
            vec!["911", "933", "112"]
        );
        let parsed: VpsConfig = toml::from_str("enabled = true").unwrap();
        assert_eq!(parsed.emergency_numbers, vec!["911", "933", "112"]);
    }
}
