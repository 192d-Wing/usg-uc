//! VPS configuration schema.
//!
//! Deserialized from the `[vps]` section of the SBC configuration file.
//! All fields default such that an absent or empty section yields a
//! disabled, permissive VPS.

use serde::{Deserialize, Serialize};

/// Root VPS configuration (`[vps]` section).
///
/// ## NIST 800-53 Rev5: CM-2 (Baseline Configuration)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct VpsConfig {
    /// Master enable. When false, `screen_call` always allows.
    pub enabled: bool,

    /// Call-level TDoS thresholds.
    pub tdos: TdosConfig,

    /// STIR/SHAKEN screening for inbound trunk calls.
    pub stir_shaken: StirShakenScreeningConfig,

    /// Declarative call-screening rules (evaluated in priority order;
    /// first match wins).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<VpsRuleConfig>,

    /// Action when no rule matches.
    pub default_action: VpsDefaultAction,

    /// Statically configured blocked source IPs (no expiry).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blocked_sources: Vec<String>,

    /// Statically configured blocked caller-number prefixes (no expiry).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub blocked_caller_prefixes: Vec<String>,
}

impl VpsConfig {
    /// Validates the configuration, returning a human-readable reason on
    /// failure. Intended to be called at config-load time so an invalid
    /// VPS section fails startup rather than silently degrading.
    pub fn validate(&self) -> Result<(), String> {
        let mut seen = std::collections::HashSet::new();
        for rule in &self.rules {
            if rule.id.is_empty() {
                return Err("rule with empty id".to_string());
            }
            if !seen.insert(rule.id.as_str()) {
                return Err(format!("duplicate rule id: {}", rule.id));
            }
            if !(400..700).contains(&rule.status_code) {
                return Err(format!(
                    "rule {}: status_code {} outside 400-699",
                    rule.id, rule.status_code
                ));
            }
            if let Some(h) = rule.time_start_hour
                && h > 23
            {
                return Err(format!("rule {}: time_start_hour {h} > 23", rule.id));
            }
            if let Some(h) = rule.time_end_hour
                && h > 23
            {
                return Err(format!("rule {}: time_end_hour {h} > 23", rule.id));
            }
            if rule.time_start_hour.is_some() != rule.time_end_hour.is_some() {
                return Err(format!(
                    "rule {}: time_start_hour and time_end_hour must be set together",
                    rule.id
                ));
            }
            if let Some(ref days) = rule.days
                && days.iter().any(|d| *d > 6)
            {
                return Err(format!("rule {}: day of week > 6", rule.id));
            }
        }
        for source in &self.blocked_sources {
            if source.parse::<std::net::IpAddr>().is_err() {
                return Err(format!("blocked_sources: invalid IP address {source}"));
            }
        }
        if self.tdos.per_source_cps > 0 && self.tdos.per_source_burst < self.tdos.per_source_cps {
            return Err("tdos: per_source_burst must be >= per_source_cps".to_string());
        }
        Ok(())
    }
}

/// Call-level TDoS thresholds (`[vps.tdos]`).
///
/// ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TdosConfig {
    /// Maximum INVITE call attempts per second per source IP.
    /// 0 disables call-rate limiting.
    pub per_source_cps: u32,

    /// Burst allowance for the per-source call-rate bucket.
    pub per_source_burst: u32,

    /// Maximum REGISTER requests per second per source IP.
    /// 0 disables registration-rate limiting.
    pub register_per_source_rps: u32,

    /// Burst allowance for the per-source registration bucket.
    pub register_burst: u32,

    /// How long a source is blocked after sustained abuse, in seconds.
    pub block_duration_secs: u64,

    /// Maximum concurrent calls to any single callee (DID). 0 = unlimited.
    /// Enforcement requires `call_started`/`call_ended` accounting.
    pub per_callee_max_concurrent: u32,
}

impl Default for TdosConfig {
    fn default() -> Self {
        Self {
            per_source_cps: 5,
            per_source_burst: 10,
            register_per_source_rps: 10,
            register_burst: 20,
            block_duration_secs: 300,
            per_callee_max_concurrent: 0,
        }
    }
}

/// STIR/SHAKEN screening mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ScreeningMode {
    /// No STIR/SHAKEN screening.
    #[default]
    Off,
    /// Evaluate and log, but never reject (staged rollout).
    LogOnly,
    /// Reject calls failing verification or below the minimum attestation.
    Enforce,
}

/// Minimum STIR/SHAKEN attestation level (RFC 8588).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum AttestationLevel {
    /// Gateway attestation (weakest).
    #[default]
    C,
    /// Partial attestation.
    B,
    /// Full attestation (strongest).
    A,
}

/// STIR/SHAKEN screening configuration (`[vps.stir_shaken]`).
///
/// Applies only to calls with `CallDirection::Inbound` (trunk-originated);
/// internal calls never carry carrier attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct StirShakenScreeningConfig {
    /// Screening mode.
    pub mode: ScreeningMode,

    /// Minimum acceptable attestation level when an Identity header is
    /// present and verified.
    pub minimum_attestation: AttestationLevel,

    /// Whether a missing Identity header is itself a violation (in
    /// `enforce` mode). Off by default: many carriers still do not sign.
    pub require_identity_header: bool,
}

/// Action a declarative rule takes on match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum VpsRuleAction {
    /// Allow the call (terminal; later rules are not evaluated).
    Allow,
    /// Deny the call with `status_code`/`reason`.
    #[default]
    Deny,
}

/// Default action when no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum VpsDefaultAction {
    /// Allow unmatched calls.
    #[default]
    Allow,
    /// Deny unmatched calls with 403.
    Deny,
}

/// A declarative call-screening rule (`[[vps.rules]]`).
///
/// All specified conditions must match (AND). Omitted conditions match
/// anything. A time window where `time_start_hour > time_end_hour` wraps
/// midnight (e.g. 18..6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VpsRuleConfig {
    /// Unique rule identifier (stamped into logs and CDRs).
    pub id: String,

    /// Human-readable description.
    pub description: String,

    /// Action on match.
    pub action: VpsRuleAction,

    /// SIP status code for `deny` (400-699).
    pub status_code: u16,

    /// SIP reason phrase for `deny`.
    pub reason: String,

    /// Evaluation priority; lower values are evaluated first.
    pub priority: u32,

    /// Match caller number by prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_prefix: Option<String>,

    /// Match callee number by prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callee_prefix: Option<String>,

    /// Match source IP (substring/wildcard per `uc-policy` semantics).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,

    /// Time window start hour (0-23, local time). Set with `time_end_hour`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_start_hour: Option<u8>,

    /// Time window end hour (0-23, local time, inclusive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_end_hour: Option<u8>,

    /// Days of week the rule applies (0 = Sunday .. 6 = Saturday).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days: Option<Vec<u8>>,
}

impl Default for VpsRuleConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            description: String::new(),
            action: VpsRuleAction::Deny,
            status_code: crate::DEFAULT_DENY_STATUS,
            reason: "Forbidden by voice protection policy".to_string(),
            priority: 1000,
            caller_prefix: None,
            callee_prefix: None,
            source_ip: None,
            time_start_hour: None,
            time_end_hour: None,
            days: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_disabled() {
        let config = VpsConfig::default();
        assert!(!config.enabled);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_toml_round_trip() {
        let toml_str = r#"
            enabled = true
            default_action = "deny"

            [tdos]
            per_source_cps = 3
            per_source_burst = 6

            [stir_shaken]
            mode = "enforce"
            minimum_attestation = "B"

            [[rules]]
            id = "block-premium"
            callee_prefix = "1900"
            action = "deny"
            status_code = 403
        "#;
        let config: VpsConfig = toml::from_str(toml_str).unwrap();
        assert!(config.enabled);
        assert_eq!(config.default_action, VpsDefaultAction::Deny);
        assert_eq!(config.tdos.per_source_cps, 3);
        assert_eq!(config.stir_shaken.mode, ScreeningMode::Enforce);
        assert_eq!(config.stir_shaken.minimum_attestation, AttestationLevel::B);
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].callee_prefix.as_deref(), Some("1900"));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_duplicate_rule_id() {
        let config = VpsConfig {
            rules: vec![
                VpsRuleConfig {
                    id: "r1".to_string(),
                    ..Default::default()
                },
                VpsRuleConfig {
                    id: "r1".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_bad_status_code() {
        let config = VpsConfig {
            rules: vec![VpsRuleConfig {
                id: "r1".to_string(),
                status_code: 200,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_bad_blocked_source() {
        let config = VpsConfig {
            blocked_sources: vec!["not-an-ip".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_unpaired_time_window() {
        let config = VpsConfig {
            rules: vec![VpsRuleConfig {
                id: "r1".to_string(),
                time_start_hour: Some(9),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_attestation_ordering() {
        assert!(AttestationLevel::A > AttestationLevel::B);
        assert!(AttestationLevel::B > AttestationLevel::C);
    }
}
