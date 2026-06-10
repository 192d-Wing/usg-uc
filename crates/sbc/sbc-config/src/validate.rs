//! Configuration validation.
//!
//! ## NIST 800-53 Rev5: CM-6 (Configuration Settings)
//!
//! Validates configuration settings for correctness and CNSA 2.0 compliance.
//!
//! Stringly-typed enum fields (trunk strategies, dial plan directions, header
//! manipulation actions, ...) are validated against the exact value sets the
//! daemon parses in `sbc-daemon/src/sip_stack.rs`. The daemon's `match`
//! statements have catch-all defaults, so an unknown value would otherwise be
//! silently misinterpreted instead of rejected.

use crate::error::{ConfigError, ConfigResult};
use crate::schema::SbcConfig;
use std::collections::HashSet;
use uc_types::protocol::{CnsaCurve, CnsaHash, CnsaSrtpProfile};

/// Trunk group selection strategies accepted by the daemon
/// (`init_router_from_config`); anything else silently falls back to
/// `priority`.
const VALID_STRATEGIES: &[&str] = &[
    "priority",
    "round_robin",
    "weighted_random",
    "least_connections",
    "best_success_rate",
];

/// Trunk transport protocols accepted by the daemon; anything else silently
/// falls back to `udp`.
const VALID_TRUNK_PROTOCOLS: &[&str] = &["udp", "tcp", "tls"];

/// Call/rule directions accepted by the daemon; anything else silently falls
/// back to `outbound` (dial plans) or `both` (header manipulation).
const VALID_DIRECTIONS: &[&str] = &["inbound", "outbound", "both"];

/// Dial plan pattern types accepted by the daemon; anything else silently
/// falls back to `prefix`.
const VALID_PATTERN_TYPES: &[&str] = &["exact", "prefix", "wildcard", "any"];

/// Dial plan destination types accepted by the daemon; anything else silently
/// falls back to `trunk_group`.
const VALID_DESTINATION_TYPES: &[&str] = &["trunk_group", "registered_user", "static_uri"];

/// Number transform types accepted by the daemon; anything else silently
/// falls back to `none`.
const VALID_TRANSFORM_TYPES: &[&str] = &["none", "strip_prefix", "add_prefix", "replace_prefix"];

/// Header manipulation actions accepted by the daemon
/// (`parse_manipulation_action`); anything else silently falls back to `set`.
const VALID_MANIPULATION_ACTIONS: &[&str] =
    &["add", "set", "remove", "replace", "prepend", "append"];

/// Validates the entire configuration.
///
/// ## NIST 800-53 Rev5: CM-6 (Configuration Settings)
///
/// ## Errors
///
/// Returns an error if validation fails.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn validate_config(config: &SbcConfig) -> ConfigResult<()> {
    validate_general(&config.general)?;
    validate_transport(&config.transport)?;
    validate_media(&config.media)?;
    validate_security(&config.security)?;
    validate_stir_shaken(&config.stir_shaken)?;
    validate_rate_limit(&config.rate_limit)?;
    validate_zones(&config.zones)?;
    validate_trunk_groups(config)?;
    validate_routing(config)?;
    validate_header_manipulation(config)?;
    validate_topology_hiding(config)?;

    Ok(())
}

fn validate_general(config: &crate::schema::GeneralConfig) -> ConfigResult<()> {
    if config.instance_name.is_empty() {
        return Err(ConfigError::Validation {
            message: "instance_name cannot be empty".to_string(),
        });
    }

    if config.max_calls == 0 {
        return Err(ConfigError::Validation {
            message: "max_calls must be greater than 0".to_string(),
        });
    }

    Ok(())
}

fn validate_transport(config: &crate::schema::TransportConfig) -> ConfigResult<()> {
    // Must have at least one listen address
    let total_listeners = config.udp_listen.len()
        + config.tcp_listen.len()
        + config.tls_listen.len()
        + config.ws_listen.len()
        + config.wss_listen.len();

    if total_listeners == 0 {
        return Err(ConfigError::Validation {
            message: "at least one listen address must be configured".to_string(),
        });
    }

    // Validate timeouts
    if config.tcp_timeout_secs == 0 {
        return Err(ConfigError::Validation {
            message: "tcp_timeout_secs must be greater than 0".to_string(),
        });
    }

    Ok(())
}

fn validate_media(config: &crate::schema::MediaConfig) -> ConfigResult<()> {
    // Validate port range. This also guarantees the range provides at least
    // two ports (an RTP/RTCP pair): `min < max` implies `max - min + 1 >= 2`.
    if config.rtp_port_min >= config.rtp_port_max {
        return Err(ConfigError::Validation {
            message: format!(
                "rtp_port_min ({}) must be less than rtp_port_max ({}); the range must \
                 provide at least 2 ports",
                config.rtp_port_min, config.rtp_port_max
            ),
        });
    }

    if config.rtp_port_min < 1024 {
        return Err(ConfigError::Validation {
            message: "rtp_port_min should be >= 1024 (non-privileged)".to_string(),
        });
    }

    // Must have at least one codec
    if config.codecs.is_empty() {
        return Err(ConfigError::Validation {
            message: "at least one codec must be configured".to_string(),
        });
    }

    // CNSA 2.0: Validate SRTP profile
    validate_cnsa_srtp(&config.srtp);

    // CNSA 2.0: Validate DTLS fingerprint hash
    validate_cnsa_hash(config.dtls.fingerprint_hash);

    Ok(())
}

fn validate_security(config: &crate::schema::SecurityConfig) -> ConfigResult<()> {
    // CNSA 2.0: Validate curve
    validate_cnsa_curve(config.curve);

    // TLS material must be configured as a pair.
    //
    // NOTE (relaxed rule): requiring cert/key whenever transport.tls_listen
    // or transport.wss_listen is non-empty would reject `SbcConfig::default()`
    // and every shipped deploy config (all declare a TLS listener with no
    // operator-provided certificate; the daemon bootstraps self-signed
    // material instead). We therefore only enforce that the paths are set
    // together.
    match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(ConfigError::Validation {
                message: "security.tls_cert_path and security.tls_key_path must be set together"
                    .to_string(),
            });
        }
        _ => {}
    }

    // CNSA 2.0: Validate TLS version
    match config.min_tls_version.as_str() {
        "1.3" => Ok(()),
        "1.2" => {
            // TLS 1.2 is allowed but 1.3 is preferred
            Ok(())
        }
        _ => Err(ConfigError::CnsaViolation {
            message: "minimum TLS version must be 1.2 or 1.3".to_string(),
        }),
    }
}

fn validate_stir_shaken(config: &crate::schema::StirShakenConfig) -> ConfigResult<()> {
    // If signing is enabled, certificate and key must be provided
    if config.signing_enabled {
        if config.certificate_path.is_none() {
            return Err(ConfigError::Validation {
                message: "STIR/SHAKEN signing requires certificate_path".to_string(),
            });
        }

        if config.private_key_path.is_none() {
            return Err(ConfigError::Validation {
                message: "STIR/SHAKEN signing requires private_key_path".to_string(),
            });
        }

        if config.certificate_url.is_none() {
            return Err(ConfigError::Validation {
                message: "STIR/SHAKEN signing requires certificate_url".to_string(),
            });
        }
    }

    // NOTE (relaxed rule): `verification_enabled = true` without
    // `ca_bundle_path` is NOT rejected. The shipped deploy config
    // (deploy/config/config.toml) explicitly enables verification without a
    // CA bundle, and the daemon has no verification code path today.
    // Tighten this once verification is implemented.

    // Validate attestation level
    match config.default_attestation.as_str() {
        "A" | "B" | "C" => Ok(()),
        _ => Err(ConfigError::Validation {
            message: "default_attestation must be A, B, or C".to_string(),
        }),
    }
}

fn validate_rate_limit(config: &crate::schema::RateLimitConfig) -> ConfigResult<()> {
    if config.enabled {
        if config.global_rps == 0 {
            return Err(ConfigError::Validation {
                message: "global_rps must be greater than 0 when rate limiting is enabled"
                    .to_string(),
            });
        }

        if config.burst_multiplier < 1.0 {
            return Err(ConfigError::Validation {
                message: "burst_multiplier must be >= 1.0".to_string(),
            });
        }
    }

    Ok(())
}

fn validate_zones(zones: &[crate::schema::ZoneConfig]) -> ConfigResult<()> {
    let mut seen = HashSet::new();

    for zone in zones {
        if zone.name.is_empty() {
            return Err(ConfigError::Validation {
                message: "zones: zone name cannot be empty".to_string(),
            });
        }

        if !seen.insert(zone.name.as_str()) {
            return Err(ConfigError::Validation {
                message: format!("zones: duplicate zone name '{}'", zone.name),
            });
        }

        if zone.signaling_interface.is_empty() {
            return Err(ConfigError::Validation {
                message: format!("zone '{}': signaling_interface cannot be empty", zone.name),
            });
        }

        if zone.media_interface.is_empty() {
            return Err(ConfigError::Validation {
                message: format!("zone '{}': media_interface cannot be empty", zone.name),
            });
        }
    }

    Ok(())
}

fn validate_trunk_groups(config: &SbcConfig) -> ConfigResult<()> {
    let mut seen_groups = HashSet::new();

    for group in &config.trunk_groups {
        if group.id.is_empty() {
            return Err(ConfigError::Validation {
                message: "trunk_groups: group id cannot be empty".to_string(),
            });
        }

        if !seen_groups.insert(group.id.as_str()) {
            return Err(ConfigError::Validation {
                message: format!("trunk_groups: duplicate trunk group id '{}'", group.id),
            });
        }

        if !VALID_STRATEGIES.contains(&group.strategy.as_str()) {
            return Err(ConfigError::Validation {
                message: format!(
                    "trunk group '{}': unknown strategy '{}' (expected one of: {})",
                    group.id,
                    group.strategy,
                    VALID_STRATEGIES.join(", ")
                ),
            });
        }

        // Cross-check the zone reference only when zones are configured;
        // with no [[zones]] sections, zones may be implicit.
        if let Some(zone) = group.zone.as_deref()
            && !config.zones.is_empty()
            && !config.zones.iter().any(|z| z.name == zone)
        {
            return Err(ConfigError::Validation {
                message: format!(
                    "trunk group '{}': zone '{zone}' does not match any [[zones]] name",
                    group.id
                ),
            });
        }

        validate_trunks(group)?;
    }

    Ok(())
}

fn validate_trunks(group: &crate::schema::TrunkGroupConfig) -> ConfigResult<()> {
    let mut seen_trunks = HashSet::new();

    for trunk in &group.trunks {
        if trunk.id.is_empty() {
            return Err(ConfigError::Validation {
                message: format!("trunk group '{}': trunk id cannot be empty", group.id),
            });
        }

        if !seen_trunks.insert(trunk.id.as_str()) {
            return Err(ConfigError::Validation {
                message: format!(
                    "trunk group '{}': duplicate trunk id '{}'",
                    group.id, trunk.id
                ),
            });
        }

        if trunk.host.is_empty() {
            return Err(ConfigError::Validation {
                message: format!(
                    "trunk '{}' (group '{}'): host cannot be empty",
                    trunk.id, group.id
                ),
            });
        }

        if !is_valid_host(&trunk.host) {
            return Err(ConfigError::Validation {
                message: format!(
                    "trunk '{}' (group '{}'): host '{}' contains invalid characters \
                     (allowed: letters, digits, '.', ':', '-', '[', ']')",
                    trunk.id,
                    group.id,
                    trunk.host.escape_default()
                ),
            });
        }

        if trunk.port == 0 {
            return Err(ConfigError::Validation {
                message: format!(
                    "trunk '{}' (group '{}'): port cannot be 0",
                    trunk.id, group.id
                ),
            });
        }

        if !VALID_TRUNK_PROTOCOLS.contains(&trunk.protocol.as_str()) {
            return Err(ConfigError::Validation {
                message: format!(
                    "trunk '{}' (group '{}'): unknown protocol '{}' (expected one of: {})",
                    trunk.id,
                    group.id,
                    trunk.protocol,
                    VALID_TRUNK_PROTOCOLS.join(", ")
                ),
            });
        }
    }

    Ok(())
}

fn validate_routing(config: &SbcConfig) -> ConfigResult<()> {
    let group_ids: HashSet<&str> = config
        .trunk_groups
        .iter()
        .map(|g| g.id.as_str())
        .collect();
    // Cross-check trunk group references only when trunk groups are
    // configured; with none, references may be resolved elsewhere.
    let have_groups = !config.trunk_groups.is_empty();

    if let Some(routing) = &config.routing
        && have_groups
        && !group_ids.contains(routing.default_trunk_group.as_str())
    {
        return Err(ConfigError::Validation {
            message: format!(
                "routing.default_trunk_group '{}' does not match any [[trunk_groups]] id",
                routing.default_trunk_group
            ),
        });
    }

    for plan in &config.dial_plans {
        for entry in &plan.entries {
            validate_dial_plan_entry(&plan.id, entry, &group_ids, have_groups)?;
        }
    }

    Ok(())
}

fn validate_dial_plan_entry(
    plan_id: &str,
    entry: &crate::schema::DialPlanEntryConfig,
    group_ids: &HashSet<&str>,
    have_groups: bool,
) -> ConfigResult<()> {
    if !VALID_DIRECTIONS.contains(&entry.direction.as_str()) {
        return Err(ConfigError::Validation {
            message: format!(
                "dial plan '{plan_id}': unknown direction '{}' (expected one of: {})",
                entry.direction,
                VALID_DIRECTIONS.join(", ")
            ),
        });
    }

    if !VALID_PATTERN_TYPES.contains(&entry.pattern_type.as_str()) {
        return Err(ConfigError::Validation {
            message: format!(
                "dial plan '{plan_id}': unknown pattern_type '{}' (expected one of: {})",
                entry.pattern_type,
                VALID_PATTERN_TYPES.join(", ")
            ),
        });
    }

    if !VALID_DESTINATION_TYPES.contains(&entry.destination_type.as_str()) {
        return Err(ConfigError::Validation {
            message: format!(
                "dial plan '{plan_id}': unknown destination_type '{}' (expected one of: {})",
                entry.destination_type,
                VALID_DESTINATION_TYPES.join(", ")
            ),
        });
    }

    if !VALID_TRANSFORM_TYPES.contains(&entry.transform_type.as_str()) {
        return Err(ConfigError::Validation {
            message: format!(
                "dial plan '{plan_id}': unknown transform_type '{}' (expected one of: {})",
                entry.transform_type,
                VALID_TRANSFORM_TYPES.join(", ")
            ),
        });
    }

    if let Some(dest) = entry.static_destination.as_deref()
        && has_ascii_control(dest)
    {
        return Err(ConfigError::Validation {
            message: format!(
                "dial plan '{plan_id}': static_destination '{}' contains ASCII control \
                 characters",
                dest.escape_default()
            ),
        });
    }

    if entry.destination_type == "trunk_group"
        && have_groups
        && !group_ids.contains(entry.trunk_group.as_str())
    {
        return Err(ConfigError::Validation {
            message: format!(
                "dial plan '{plan_id}': trunk_group '{}' does not match any [[trunk_groups]] id",
                entry.trunk_group
            ),
        });
    }

    Ok(())
}

fn validate_header_manipulation(config: &SbcConfig) -> ConfigResult<()> {
    let Some(manip) = &config.header_manipulation else {
        return Ok(());
    };

    for rule in &manip.global_rules {
        validate_manipulation_rule(&rule.name, &rule.action, &rule.header, &rule.value)?;

        if !VALID_DIRECTIONS.contains(&rule.direction.as_str()) {
            return Err(ConfigError::Validation {
                message: format!(
                    "header manipulation rule '{}': unknown direction '{}' (expected one of: {})",
                    rule.name,
                    rule.direction,
                    VALID_DIRECTIONS.join(", ")
                ),
            });
        }
    }

    for rule in &manip.trunk_rules {
        validate_manipulation_rule(&rule.name, &rule.action, &rule.header, &rule.value)?;
    }

    Ok(())
}

fn validate_manipulation_rule(
    name: &str,
    action: &str,
    header: &str,
    value: &str,
) -> ConfigResult<()> {
    if !VALID_MANIPULATION_ACTIONS.contains(&action) {
        return Err(ConfigError::Validation {
            message: format!(
                "header manipulation rule '{name}': unknown action '{action}' \
                 (expected one of: {})",
                VALID_MANIPULATION_ACTIONS.join(", ")
            ),
        });
    }

    if !is_rfc3261_token(header) {
        return Err(ConfigError::Validation {
            message: format!(
                "header manipulation rule '{name}': header name '{}' is not a valid \
                 RFC 3261 token (allowed: alphanumeric and -.!%*_+`'~)",
                header.escape_default()
            ),
        });
    }

    if has_ascii_control(value) {
        return Err(ConfigError::Validation {
            message: format!(
                "header manipulation rule '{name}': value '{}' contains ASCII control \
                 characters (CRLF injection)",
                value.escape_default()
            ),
        });
    }

    Ok(())
}

fn validate_topology_hiding(config: &SbcConfig) -> ConfigResult<()> {
    if let Some(topo) = &config.topology_hiding
        && has_ascii_control(&topo.external_host)
    {
        return Err(ConfigError::Validation {
            message: format!(
                "topology_hiding.external_host '{}' contains ASCII control characters",
                topo.external_host.escape_default()
            ),
        });
    }

    Ok(())
}

/// Returns `true` if `s` is a non-empty RFC 3261 token
/// (alphanumeric plus ``-.!%*_+`'~``).
fn is_rfc3261_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
                )
        })
}

/// Returns `true` if `s` contains any ASCII control character
/// (0x00-0x1F or 0x7F), including CR and LF.
fn has_ascii_control(s: &str) -> bool {
    s.bytes().any(|b| b.is_ascii_control())
}

/// Returns `true` if `s` is a plausible host: a non-empty string of
/// letters, digits, `.`, `:`, `-`, `[`, `]` (IPv6 literals allowed).
fn is_valid_host(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-' | b'[' | b']'))
}

/// Validates CNSA 2.0 SRTP profile compliance.
///
/// The match is exhaustive: adding a non-CNSA variant to
/// [`CnsaSrtpProfile`] fails to compile here, forcing an explicit
/// compliance decision.
const fn validate_cnsa_srtp(config: &crate::schema::SrtpConfig) {
    match config.profile {
        CnsaSrtpProfile::AeadAes256Gcm => (),
    }
}

/// Validates CNSA 2.0 hash algorithm compliance.
///
/// The match is exhaustive: adding a non-CNSA variant to [`CnsaHash`]
/// fails to compile here, forcing an explicit compliance decision.
const fn validate_cnsa_hash(hash: CnsaHash) {
    match hash {
        CnsaHash::Sha384 | CnsaHash::Sha512 => (),
    }
}

/// Validates CNSA 2.0 elliptic curve compliance.
///
/// The match is exhaustive: adding a non-CNSA variant to [`CnsaCurve`]
/// fails to compile here, forcing an explicit compliance decision.
const fn validate_cnsa_curve(curve: CnsaCurve) {
    match curve {
        CnsaCurve::P384 | CnsaCurve::P521 => (),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::field_reassign_with_default
)]
mod tests {
    use super::*;
    use crate::schema::{
        DialPlanConfig, DialPlanEntryConfig, HeaderManipulationConfig, ManipulationRuleConfig,
        RoutingConfig, TopologyHidingConfig, TrunkConfigSchema, TrunkGroupConfig,
        TrunkManipulationRuleConfig, ZoneConfig,
    };

    fn zone(name: &str) -> ZoneConfig {
        ZoneConfig {
            name: name.to_string(),
            signaling_interface: "eth0".to_string(),
            media_interface: "eth1".to_string(),
            external_ip: None,
        }
    }

    fn trunk(id: &str) -> TrunkConfigSchema {
        TrunkConfigSchema {
            id: id.to_string(),
            host: "sip.example.com".to_string(),
            ..Default::default()
        }
    }

    fn trunk_group(id: &str) -> TrunkGroupConfig {
        TrunkGroupConfig {
            id: id.to_string(),
            name: id.to_string(),
            strategy: "priority".to_string(),
            trunks: vec![trunk("t1")],
            zone: None,
        }
    }

    fn global_rule() -> ManipulationRuleConfig {
        ManipulationRuleConfig {
            name: "rule-1".to_string(),
            direction: "both".to_string(),
            action: "set".to_string(),
            header: "User-Agent".to_string(),
            value: "USG-SBC/1.0".to_string(),
        }
    }

    fn trunk_rule() -> TrunkManipulationRuleConfig {
        TrunkManipulationRuleConfig {
            trunk_id: "t1".to_string(),
            name: "trunk-rule-1".to_string(),
            action: "remove".to_string(),
            header: "X-Internal-ID".to_string(),
            value: String::new(),
        }
    }

    fn assert_rejected(config: &SbcConfig, needle: &str) {
        let err = validate_config(config).expect_err("config should be rejected");
        let msg = err.to_string();
        assert!(msg.contains(needle), "error '{msg}' should mention '{needle}'");
    }

    #[test]
    fn test_valid_default_config() {
        let config = SbcConfig::default();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_empty_instance_name() {
        let mut config = SbcConfig::default();
        config.general.instance_name = String::new();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_invalid_port_range() {
        let mut config = SbcConfig::default();
        config.media.rtp_port_min = 50000;
        config.media.rtp_port_max = 40000;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_single_port_rtp_range_rejected() {
        // The range must provide at least 2 ports (RTP/RTCP pair).
        let mut config = SbcConfig::default();
        config.media.rtp_port_min = 20000;
        config.media.rtp_port_max = 20000;
        assert_rejected(&config, "rtp_port_min");
    }

    #[test]
    fn test_no_codecs() {
        let mut config = SbcConfig::default();
        config.media.codecs.clear();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_stir_shaken_signing_without_cert() {
        let mut config = SbcConfig::default();
        config.stir_shaken.signing_enabled = true;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_invalid_tls_version() {
        let mut config = SbcConfig::default();
        config.security.min_tls_version = "1.0".to_string();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_security_cert_without_key() {
        let mut config = SbcConfig::default();
        config.security.tls_cert_path = Some("/etc/sbc/tls.crt".into());
        assert_rejected(&config, "security.tls_cert_path");

        config.security.tls_key_path = Some("/etc/sbc/tls.key".into());
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_security_key_without_cert() {
        let mut config = SbcConfig::default();
        config.security.tls_key_path = Some("/etc/sbc/tls.key".into());
        assert_rejected(&config, "security.tls_key_path");
    }

    #[test]
    fn test_zones_valid() {
        let mut config = SbcConfig::default();
        config.zones = vec![zone("inside"), zone("outside")];
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_zone_empty_name_rejected() {
        let mut config = SbcConfig::default();
        config.zones = vec![zone("")];
        assert_rejected(&config, "zone name cannot be empty");
    }

    #[test]
    fn test_zone_duplicate_name_rejected() {
        let mut config = SbcConfig::default();
        config.zones = vec![zone("inside"), zone("inside")];
        assert_rejected(&config, "duplicate zone name 'inside'");
    }

    #[test]
    fn test_zone_empty_signaling_interface_rejected() {
        let mut config = SbcConfig::default();
        let mut z = zone("inside");
        z.signaling_interface = String::new();
        config.zones = vec![z];
        assert_rejected(&config, "signaling_interface cannot be empty");
    }

    #[test]
    fn test_zone_empty_media_interface_rejected() {
        let mut config = SbcConfig::default();
        let mut z = zone("inside");
        z.media_interface = String::new();
        config.zones = vec![z];
        assert_rejected(&config, "media_interface cannot be empty");
    }

    // ── Trunk groups ───────────────────────────────────────────────

    #[test]
    fn test_trunk_group_valid() {
        let mut config = SbcConfig::default();
        config.trunk_groups = vec![trunk_group("tg1")];
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_trunk_group_empty_id_rejected() {
        let mut config = SbcConfig::default();
        config.trunk_groups = vec![trunk_group("")];
        assert_rejected(&config, "group id cannot be empty");
    }

    #[test]
    fn test_trunk_group_duplicate_id_rejected() {
        let mut config = SbcConfig::default();
        config.trunk_groups = vec![trunk_group("tg1"), trunk_group("tg1")];
        assert_rejected(&config, "duplicate trunk group id 'tg1'");
    }

    #[test]
    fn test_trunk_group_strategies() {
        let mut config = SbcConfig::default();
        for strategy in super::VALID_STRATEGIES {
            let mut group = trunk_group("tg1");
            group.strategy = (*strategy).to_string();
            config.trunk_groups = vec![group];
            assert!(validate_config(&config).is_ok(), "strategy {strategy}");
        }

        // Daemon matching is case-sensitive: "Round_Robin" would silently
        // fall back to priority, so it must be rejected.
        for strategy in ["roundrobin", "Round_Robin", "fastest", ""] {
            let mut group = trunk_group("tg1");
            group.strategy = strategy.to_string();
            config.trunk_groups = vec![group];
            assert_rejected(&config, "unknown strategy");
        }
    }

    #[test]
    fn test_trunk_empty_id_rejected() {
        let mut config = SbcConfig::default();
        let mut group = trunk_group("tg1");
        group.trunks = vec![trunk("")];
        config.trunk_groups = vec![group];
        assert_rejected(&config, "trunk id cannot be empty");
    }

    #[test]
    fn test_trunk_duplicate_id_within_group_rejected() {
        let mut config = SbcConfig::default();
        let mut group = trunk_group("tg1");
        group.trunks = vec![trunk("t1"), trunk("t1")];
        config.trunk_groups = vec![group];
        assert_rejected(&config, "duplicate trunk id 't1'");
    }

    #[test]
    fn test_trunk_empty_host_rejected() {
        let mut config = SbcConfig::default();
        let mut group = trunk_group("tg1");
        group.trunks[0].host = String::new();
        config.trunk_groups = vec![group];
        assert_rejected(&config, "host cannot be empty");
    }

    #[test]
    fn test_trunk_host_charset() {
        let mut config = SbcConfig::default();

        // IPv6 literal and IPv4/hostname forms are accepted.
        for host in ["[2001:db8::1]", "2001:db8::1", "192.0.2.10", "sip-1.example.com"] {
            let mut group = trunk_group("tg1");
            group.trunks[0].host = host.to_string();
            config.trunk_groups = vec![group];
            assert!(validate_config(&config).is_ok(), "host {host}");
        }

        for host in ["evil\r\nhost", "host with space", "host;param", "host_under"] {
            let mut group = trunk_group("tg1");
            group.trunks[0].host = host.to_string();
            config.trunk_groups = vec![group];
            assert_rejected(&config, "invalid characters");
        }
    }

    #[test]
    fn test_trunk_port_zero_rejected() {
        let mut config = SbcConfig::default();
        let mut group = trunk_group("tg1");
        group.trunks[0].port = 0;
        config.trunk_groups = vec![group];
        assert_rejected(&config, "port cannot be 0");
    }

    #[test]
    fn test_trunk_protocols() {
        let mut config = SbcConfig::default();
        for protocol in super::VALID_TRUNK_PROTOCOLS {
            let mut group = trunk_group("tg1");
            group.trunks[0].protocol = (*protocol).to_string();
            config.trunk_groups = vec![group];
            assert!(validate_config(&config).is_ok(), "protocol {protocol}");
        }

        // Daemon matching is case-sensitive: "UDP" would silently fall back
        // to udp, but "TLS" would too -- a security downgrade. Reject all.
        for protocol in ["sctp", "UDP", "TLS", ""] {
            let mut group = trunk_group("tg1");
            group.trunks[0].protocol = protocol.to_string();
            config.trunk_groups = vec![group];
            assert_rejected(&config, "unknown protocol");
        }
    }

    #[test]
    fn test_trunk_group_zone_reference() {
        let mut config = SbcConfig::default();
        let mut group = trunk_group("tg1");
        group.zone = Some("outside".to_string());

        // No zones configured: cross-check is skipped (zones may be implicit).
        config.trunk_groups = vec![group.clone()];
        assert!(validate_config(&config).is_ok());

        // Zones configured and reference resolves: ok.
        config.zones = vec![zone("inside"), zone("outside")];
        assert!(validate_config(&config).is_ok());

        // Zones configured and reference dangles: rejected.
        group.zone = Some("dmz".to_string());
        config.trunk_groups = vec![group];
        assert_rejected(&config, "zone 'dmz' does not match");
    }

    // ── Routing / dial plans ───────────────────────────────────────

    fn config_with_entry(entry: DialPlanEntryConfig) -> SbcConfig {
        let mut config = SbcConfig::default();
        config.dial_plans = vec![DialPlanConfig {
            id: "main".to_string(),
            name: "Main".to_string(),
            active: true,
            entries: vec![entry],
        }];
        config
    }

    #[test]
    fn test_dial_plan_entry_valid_enums() {
        for direction in super::VALID_DIRECTIONS {
            for pattern_type in super::VALID_PATTERN_TYPES {
                let entry = DialPlanEntryConfig {
                    direction: (*direction).to_string(),
                    pattern_type: (*pattern_type).to_string(),
                    ..Default::default()
                };
                assert!(validate_config(&config_with_entry(entry)).is_ok());
            }
        }
    }

    #[test]
    fn test_dial_plan_invalid_direction_rejected() {
        let entry = DialPlanEntryConfig {
            direction: "Inbound".to_string(),
            ..Default::default()
        };
        assert_rejected(&config_with_entry(entry), "unknown direction 'Inbound'");
    }

    #[test]
    fn test_dial_plan_invalid_pattern_type_rejected() {
        let entry = DialPlanEntryConfig {
            pattern_type: "regex".to_string(),
            ..Default::default()
        };
        assert_rejected(&config_with_entry(entry), "unknown pattern_type 'regex'");
    }

    #[test]
    fn test_dial_plan_invalid_destination_type_rejected() {
        let entry = DialPlanEntryConfig {
            destination_type: "voicemail".to_string(),
            ..Default::default()
        };
        assert_rejected(
            &config_with_entry(entry),
            "unknown destination_type 'voicemail'",
        );
    }

    #[test]
    fn test_dial_plan_invalid_transform_type_rejected() {
        let entry = DialPlanEntryConfig {
            transform_type: "strip-prefix".to_string(),
            ..Default::default()
        };
        assert_rejected(
            &config_with_entry(entry),
            "unknown transform_type 'strip-prefix'",
        );
    }

    #[test]
    fn test_dial_plan_static_destination_crlf_rejected() {
        let entry = DialPlanEntryConfig {
            destination_type: "static_uri".to_string(),
            static_destination: Some("sip:a@b\r\nVia: evil".to_string()),
            ..Default::default()
        };
        assert_rejected(&config_with_entry(entry), "static_destination");
    }

    #[test]
    fn test_dial_plan_trunk_group_reference() {
        // No trunk groups configured: cross-check skipped.
        let entry = DialPlanEntryConfig {
            trunk_group: "anywhere".to_string(),
            ..Default::default()
        };
        assert!(validate_config(&config_with_entry(entry.clone())).is_ok());

        // Trunk groups configured and reference dangles: rejected.
        let mut config = config_with_entry(entry);
        config.trunk_groups = vec![trunk_group("tg1")];
        assert_rejected(&config, "trunk_group 'anywhere' does not match");

        // Resolving reference: ok.
        config.dial_plans[0].entries[0].trunk_group = "tg1".to_string();
        assert!(validate_config(&config).is_ok());

        // Non-trunk_group destinations do not use the trunk_group field.
        config.dial_plans[0].entries[0].trunk_group = String::new();
        config.dial_plans[0].entries[0].destination_type = "registered_user".to_string();
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_routing_default_trunk_group_reference() {
        let mut config = SbcConfig::default();
        config.routing = Some(RoutingConfig::default()); // default_trunk_group = "default"

        // No trunk groups configured: cross-check skipped.
        assert!(validate_config(&config).is_ok());

        // Trunk groups configured and reference dangles: rejected.
        config.trunk_groups = vec![trunk_group("tg1")];
        assert_rejected(&config, "routing.default_trunk_group 'default'");

        // Resolving reference: ok.
        if let Some(routing) = config.routing.as_mut() {
            routing.default_trunk_group = "tg1".to_string();
        }
        assert!(validate_config(&config).is_ok());
    }

    // ── Header manipulation ────────────────────────────────────────

    fn config_with_global_rule(rule: ManipulationRuleConfig) -> SbcConfig {
        let mut config = SbcConfig::default();
        config.header_manipulation = Some(HeaderManipulationConfig {
            global_rules: vec![rule],
            trunk_rules: Vec::new(),
        });
        config
    }

    #[test]
    fn test_header_manipulation_valid() {
        for action in super::VALID_MANIPULATION_ACTIONS {
            let mut rule = global_rule();
            rule.action = (*action).to_string();
            assert!(
                validate_config(&config_with_global_rule(rule)).is_ok(),
                "action {action}"
            );
        }

        let mut config = SbcConfig::default();
        config.header_manipulation = Some(HeaderManipulationConfig {
            global_rules: Vec::new(),
            trunk_rules: vec![trunk_rule()],
        });
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn test_header_manipulation_invalid_action_rejected() {
        let mut rule = global_rule();
        rule.action = "delete".to_string();
        assert_rejected(&config_with_global_rule(rule), "unknown action 'delete'");

        let mut config = SbcConfig::default();
        let mut t_rule = trunk_rule();
        t_rule.action = "Set".to_string();
        config.header_manipulation = Some(HeaderManipulationConfig {
            global_rules: Vec::new(),
            trunk_rules: vec![t_rule],
        });
        assert_rejected(&config, "unknown action 'Set'");
    }

    #[test]
    fn test_header_manipulation_invalid_direction_rejected() {
        let mut rule = global_rule();
        rule.direction = "egress".to_string();
        assert_rejected(&config_with_global_rule(rule), "unknown direction 'egress'");
    }

    #[test]
    fn test_header_manipulation_invalid_header_name_rejected() {
        for header in ["", "X Header", "X-Header:", "Via\r\nEvil", "héader"] {
            let mut rule = global_rule();
            rule.header = header.to_string();
            assert_rejected(&config_with_global_rule(rule), "RFC 3261 token");
        }

        // Token specials are allowed.
        let mut rule = global_rule();
        rule.header = "X-Custom.Hdr!%*_+`'~-1".to_string();
        assert!(validate_config(&config_with_global_rule(rule)).is_ok());
    }

    #[test]
    fn test_header_manipulation_value_crlf_rejected() {
        let mut rule = global_rule();
        rule.value = "ok\r\nVia: injected".to_string();
        assert_rejected(&config_with_global_rule(rule), "control characters");

        let mut config = SbcConfig::default();
        let mut t_rule = trunk_rule();
        t_rule.action = "set".to_string();
        t_rule.value = "bad\u{0}value".to_string();
        config.header_manipulation = Some(HeaderManipulationConfig {
            global_rules: Vec::new(),
            trunk_rules: vec![t_rule],
        });
        assert_rejected(&config, "control characters");
    }

    // ── Topology hiding ────────────────────────────────────────────

    #[test]
    fn test_topology_hiding_external_host_control_chars_rejected() {
        let mut config = SbcConfig::default();
        config.topology_hiding = Some(TopologyHidingConfig {
            enabled: true,
            mode: "full".to_string(),
            external_host: "sbc.example.com\r\nVia: evil".to_string(),
            external_port: 5060,
            obfuscate_call_id: false,
        });
        assert_rejected(&config, "topology_hiding.external_host");

        if let Some(topo) = config.topology_hiding.as_mut() {
            topo.external_host = "sbc.example.com".to_string();
        }
        assert!(validate_config(&config).is_ok());
    }

    // ── STIR/SHAKEN ────────────────────────────────────────────────

}

/// Tests that the shipped deploy configurations still validate.
///
/// Fixtures are extracted from:
/// - `deploy/config/config.toml`
/// - `deploy/microk8s/sbc-configmap.yaml` (`data."config.toml"`)
/// - `deploy/k8s-local/sbc-configmap.yaml` (`data."config.toml"`)
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod deploy_config_tests {
    /// `deploy/config/config.toml` (comments stripped).
    const DEPLOY_CONFIG_TOML: &str = r#"
[general]
instance_name = "sbc-01"
max_calls = 10000
max_registrations = 50000

[transport]
udp_listen = ["[::]:5060"]
tcp_listen = ["[::]:5060"]
tls_listen = ["[::]:5061"]
ws_listen = []
wss_listen = []
tcp_timeout_secs = 30
tcp_idle_timeout_secs = 300

[api]
listen_addr = "0.0.0.0:8443"

[media]
default_mode = "Relay"
codecs = ["Opus", "G722", "G711Ulaw", "G711Alaw"]
rtp_port_min = 16384
rtp_port_max = 32768

[media.srtp]
required = true
profile = "AeadAes256Gcm"

[media.dtls]
fingerprint_hash = "Sha384"

[security]
curve = "P384"
min_tls_version = "1.3"
require_mtls = false

[stir_shaken]
signing_enabled = false
verification_enabled = true
default_attestation = "B"
max_passport_age_secs = 60

[rate_limit]
enabled = true
global_rps = 10000
per_ip_rps = 100
per_user_rps = 50
burst_multiplier = 2.0

[logging]
level = "info"
format = "json"
output = "stdout"
audit_enabled = true
"#;

    /// `deploy/microk8s/sbc-configmap.yaml` embedded `config.toml`
    /// (comments stripped).
    const MICROK8S_CONFIG_TOML: &str = r#"
[general]
instance_name = "sbc-microk8s"
max_calls = 5000
max_registrations = 10000
default_internal_zone = "inside"

[[zones]]
name = "inside"
signaling_interface = "net1"
media_interface = "net1"

[[zones]]
name = "outside"
signaling_interface = "net2"
media_interface = "net2"
external_ip = "stun"

[[zones]]
name = "oobm"
signaling_interface = "net3"
media_interface = "net3"

[transport]
udp_listen = ["0.0.0.0:5060"]
tcp_listen = ["0.0.0.0:5060"]
tls_listen = ["0.0.0.0:5061"]
stun_refresh_interval_secs = 300

[api]
listen_addr = "0.0.0.0:80"
insecure_http = "any"

[media]
default_mode = "Relay"
codecs = ["G711Ulaw", "G711Alaw", "G722"]
rtp_port_min = 16384
rtp_port_max = 20000

[media.srtp]
required = false

[rate_limit]
enabled = true
global_rps = 50000
per_ip_rps = 10000

[logging]
level = "info"
format = "json"
output = "stdout"
"#;

    /// `deploy/k8s-local/sbc-configmap.yaml` embedded `config.toml`
    /// (comments stripped).
    const K8S_LOCAL_CONFIG_TOML: &str = r#"
[general]
instance_name = "sbc-k8s"
max_calls = 5000
max_registrations = 10000
default_internal_zone = "inside"

[[zones]]
name = "inside"
signaling_interface = "net1"
media_interface = "net1"

[[zones]]
name = "outside"
signaling_interface = "net2"
media_interface = "net2"
external_ip = "stun"

[[zones]]
name = "oobm"
signaling_interface = "net3"
media_interface = "net3"

[transport]
udp_listen = ["0.0.0.0:5060"]
tcp_listen = ["0.0.0.0:5060"]
tls_listen = ["0.0.0.0:5061"]
stun_refresh_interval_secs = 300

[api]
listen_addr = "0.0.0.0:8443"

[media]
default_mode = "Relay"
codecs = ["G711Ulaw", "G711Alaw", "G722"]
rtp_port_min = 16384
rtp_port_max = 20000

[media.srtp]
required = false

[rate_limit]
enabled = true
global_rps = 50000
per_ip_rps = 10000

[logging]
level = "info"
format = "json"
output = "stdout"
"#;

    #[test]
    fn test_deploy_config_toml_validates() {
        let config = crate::load_from_str(DEPLOY_CONFIG_TOML).expect("deploy/config/config.toml");
        assert_eq!(config.general.instance_name, "sbc-01");
    }

    #[test]
    fn test_microk8s_configmap_validates() {
        let config =
            crate::load_from_str(MICROK8S_CONFIG_TOML).expect("deploy/microk8s/sbc-configmap.yaml");
        assert_eq!(config.general.instance_name, "sbc-microk8s");
        assert_eq!(config.zones.len(), 3);
    }

    #[test]
    fn test_k8s_local_configmap_validates() {
        let config = crate::load_from_str(K8S_LOCAL_CONFIG_TOML)
            .expect("deploy/k8s-local/sbc-configmap.yaml");
        assert_eq!(config.general.instance_name, "sbc-k8s");
        assert_eq!(config.zones.len(), 3);
    }
}
