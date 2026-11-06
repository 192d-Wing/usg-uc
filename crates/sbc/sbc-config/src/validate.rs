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

/// Bounds for `trunk_groups[].trunks[].options_ping_interval_secs`. The
/// monitor never pings faster than every 5 s.
const MIN_OPTIONS_PING_INTERVAL_SECS: u32 = 5;
const MAX_OPTIONS_PING_INTERVAL_SECS: u32 = 3600;

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
    validate_logging(&config.logging)?;
    validate_stir_shaken(config)?;
    validate_rate_limit(&config.rate_limit)?;
    validate_vps(config)?;
    validate_zones(&config.zones)?;
    validate_trunk_groups(config)?;
    validate_trunk_tls(config)?;
    validate_routing(config)?;
    validate_header_manipulation(config)?;
    validate_topology_hiding(config)?;
    validate_cdr(&config.cdr)?;
    #[cfg(feature = "cluster")]
    validate_cluster_admission(config)?;
    if let Some(grpc) = &config.grpc {
        validate_grpc(grpc)?;
    }

    Ok(())
}

/// `cluster.admission`: under `split = "divide"` every divided cap must
/// give each of `expected_nodes` at least one slot, and `expected_nodes`
/// is only accepted where it is enforced.
///
/// ## NIST 800-53 Rev5: CM-6, SC-5, CP-2(2)
#[cfg(feature = "cluster")]
fn validate_cluster_admission(config: &SbcConfig) -> ConfigResult<()> {
    use crate::schema::AdmissionSplit;
    let Some(cluster) = &config.cluster else {
        return Ok(());
    };
    let adm = &cluster.admission;
    match adm.split {
        AdmissionSplit::PerNode => {
            if adm.expected_nodes != 1 {
                return Err(ConfigError::Validation {
                    message:
                        "cluster.admission.expected_nodes is only used with split = \"divide\""
                            .to_string(),
                });
            }
            return Ok(());
        }
        AdmissionSplit::Divide => {}
    }
    if !cluster.enabled {
        return Err(ConfigError::Validation {
            message: "cluster.admission.split = \"divide\" requires cluster.enabled".to_string(),
        });
    }
    let n = adm.expected_nodes;
    if !(1..=uc_cluster::MAX_EXPECTED_NODES).contains(&n) {
        return Err(ConfigError::Validation {
            message: format!(
                "cluster.admission.expected_nodes must be 1-{}",
                uc_cluster::MAX_EXPECTED_NODES
            ),
        });
    }
    let too_small = |what: &str, cap: u32| -> ConfigResult<()> {
        if cap < n {
            return Err(ConfigError::Validation {
                message: format!(
                    "{what} ({cap}) is below cluster.admission.expected_nodes ({n}) with split = \"divide\""
                ),
            });
        }
        Ok(())
    };
    too_small("general.max_calls", config.general.max_calls)?;
    too_small(
        "general.max_registrations",
        config.general.max_registrations,
    )?;
    for group in &config.trunk_groups {
        for trunk in &group.trunks {
            too_small(&format!("trunk '{}' max_calls", trunk.id), trunk.max_calls)?;
        }
    }
    Ok(())
}

/// Most entries accepted in `grpc.allowed_client_names`.
pub const MAX_GRPC_ALLOWED_CLIENT_NAMES: usize = 64;

/// Longest entry in `grpc.allowed_client_names` (DNS name limit; URIs and
/// CNs are capped the same).
pub const MAX_GRPC_CLIENT_NAME_LEN: usize = 253;

/// `grpc.allowed_client_names` is only enforced under `require_mtls`, so a
/// list without it is rejected rather than silently ignored.
///
/// ## NIST 800-53 Rev5: CM-6, AC-3, IA-3
fn validate_grpc(config: &crate::schema::GrpcConfig) -> ConfigResult<()> {
    let err = |message: String| Err(ConfigError::Validation { message });
    if config.allowed_client_names.is_empty() {
        return Ok(());
    }
    if !config.require_mtls {
        return err(
            "grpc.allowed_client_names is only enforced with grpc.require_mtls = true".to_string(),
        );
    }
    if config.allowed_client_names.len() > MAX_GRPC_ALLOWED_CLIENT_NAMES {
        return err(format!(
            "grpc.allowed_client_names has more than {MAX_GRPC_ALLOWED_CLIENT_NAMES} entries"
        ));
    }
    for name in &config.allowed_client_names {
        let printable = name.bytes().all(|b| (0x21..=0x7e).contains(&b));
        if name.is_empty() || name.len() > MAX_GRPC_CLIENT_NAME_LEN || !printable {
            return err(format!(
                "grpc.allowed_client_names entry {name:?} must be 1..={MAX_GRPC_CLIENT_NAME_LEN} \
                 printable ASCII characters without spaces"
            ));
        }
    }
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

    // The emergency reserve is enforced by admission control; an
    // out-of-range value is rejected, not ignored.
    //
    // ## 47 CFR 9.16; NIST 800-53 Rev5: CM-6, SC-5
    if let Some(reserve) = config.emergency_reserve_calls
        && !(1..=config.max_calls).contains(&reserve)
    {
        return Err(ConfigError::Validation {
            message: format!(
                "emergency_reserve_calls must be 1-{} (max_calls)",
                config.max_calls
            ),
        });
    }

    if config.max_registrations == 0 {
        return Err(ConfigError::Validation {
            message: "max_registrations must be greater than 0".to_string(),
        });
    }

    if !(1..=crate::schema::MAX_TRUNK_RETRY_AFTER_SECS).contains(&config.trunk_retry_after_max_secs)
    {
        return Err(ConfigError::Validation {
            message: format!(
                "trunk_retry_after_max_secs must be 1-{}",
                crate::schema::MAX_TRUNK_RETRY_AFTER_SECS
            ),
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

    // The WebSocket transport (RFC 7118) does not terminate TLS itself, so a
    // `wss_listen` entry would silently be plain WS. Refuse it rather than
    // advertise security that is not there.
    if !config.wss_listen.is_empty() {
        return Err(ConfigError::Validation {
            message: "transport.wss_listen is not supported by this build: the WebSocket \
                      transport does not terminate TLS. Terminate TLS at a reverse proxy and \
                      use transport.ws_listen, or use transport.tls_listen."
                .to_string(),
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

    validate_media_enforced(config)?;

    // CNSA 2.0: Validate SRTP profile
    validate_cnsa_srtp(&config.srtp);

    // CNSA 2.0: Validate DTLS fingerprint hash
    validate_cnsa_hash(config.dtls.fingerprint_hash);

    Ok(())
}

/// Rejects media keys this build accepts in the schema but does not act on.
///
/// The live call path always anchors media (`Relay`): there is no media
/// bypass, so `PassThrough`/`SignalingOnly` and per-realm overrides would be
/// silently ignored. There is no SDP codec filtering or transcoding, so a
/// non-default codec list would be ignored too.
///
/// ## NIST 800-53 Rev5: CM-6 (Configuration Settings), CM-7 (Least Functionality)
fn validate_media_enforced(config: &crate::schema::MediaConfig) -> ConfigResult<()> {
    use uc_types::media::MediaMode;

    if config.default_mode != MediaMode::Relay {
        return Err(ConfigError::Validation {
            message: format!(
                "media.default_mode = {:?} is not supported by this build (media is always \
                 relayed; there is no media bypass); remove it or set it to \"Relay\"",
                config.default_mode
            ),
        });
    }

    if !config.realm_modes.is_empty() {
        let mut realms: Vec<&str> = config.realm_modes.keys().map(String::as_str).collect();
        realms.sort_unstable();
        return Err(ConfigError::Validation {
            message: format!(
                "media.realm_modes is not supported by this build (per-realm media modes need \
                 media bypass); remove the entries for: {}",
                realms.join(", ")
            ),
        });
    }

    // Order-insensitive: the list is not used for SDP negotiation, so only
    // its contents matter for "is this the default".
    let mut configured = config.codecs.clone();
    let mut default = crate::schema::MediaConfig::default().codecs;
    configured.sort_unstable_by_key(|c| format!("{c:?}"));
    default.sort_unstable_by_key(|c| format!("{c:?}"));
    if configured != default {
        return Err(ConfigError::Validation {
            message: "media.codecs is not enforced by this build (no SDP codec filtering or \
                      transcoding); remove it or set it to the default list \
                      [\"Opus\", \"G722\", \"G711Ulaw\", \"G711Alaw\"]"
                .to_string(),
        });
    }

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
    // operator-provided certificate; the daemon skips binding those
    // listeners and logs a warning). We therefore only enforce that the
    // paths are set together.
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
        "1.3" | "1.2" => {}
        _ => {
            return Err(ConfigError::CnsaViolation {
                message: "minimum TLS version must be 1.2 or 1.3".to_string(),
            });
        }
    }

    // Mutual TLS needs server credentials and a CA to verify clients against.
    if config.require_mtls {
        if config.tls_cert_path.is_none() {
            return Err(ConfigError::Validation {
                message: "security.require_mtls needs security.tls_cert_path / tls_key_path"
                    .to_string(),
            });
        }
        if config.tls_ca_path.is_none() {
            return Err(ConfigError::Validation {
                message: "security.require_mtls needs security.tls_ca_path (PEM bundle of \
                          CAs that issue client certificates)"
                    .to_string(),
            });
        }
    }

    Ok(())
}

fn validate_logging(config: &crate::schema::LoggingConfig) -> ConfigResult<()> {
    match config.level.to_ascii_lowercase().as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => {}
        other => {
            return Err(ConfigError::Validation {
                message: format!(
                    "logging.level must be trace, debug, info, warn or error (got {other:?})"
                ),
            });
        }
    }
    match config.format.to_ascii_lowercase().as_str() {
        "json" | "text" => {}
        other => {
            return Err(ConfigError::Validation {
                message: format!("logging.format must be json or text (got {other:?})"),
            });
        }
    }
    if config.output.trim().is_empty() {
        return Err(ConfigError::Validation {
            message: "logging.output must be stdout, stderr or a file path".to_string(),
        });
    }
    Ok(())
}

/// `[stir_shaken]` and per-trunk `stir_shaken` validation.
///
/// ## NIST 800-53 Rev5: CM-6 (Configuration Settings), SC-13, SC-17, IA-9
fn validate_stir_shaken(config: &SbcConfig) -> ConfigResult<()> {
    use crate::schema::StirAlgorithm;
    let err = |message: String| Err(ConfigError::Validation { message });
    let (ss, _deprecated) = config
        .stir_shaken
        .normalized()
        .map_err(|message| ConfigError::Validation { message })?;

    // CNSA-EXCEPTION: ATIS-1000074 mandates ES256 for ppt=shaken. ES384
    // (bilateral) is reserved and not implemented, so it is rejected rather
    // than silently signing with ES256.
    if ss.algorithm == StirAlgorithm::Es384 {
        return err(
            "stir_shaken.algorithm = \"ES384\" is not supported in this release (SHAKEN requires ES256)"
                .to_string(),
        );
    }

    // An accepted-but-unimplemented key source is rejected even with
    // signing off, so enabling signing later cannot surprise (CM-6).
    if ss.signing.key_source == crate::schema::StirKeySource::Pkcs11 {
        return err("stir_shaken.signing.key_source = \"pkcs11\" is not supported yet".into());
    }
    if ss.signing_enabled {
        validate_stir_signing(&ss.signing)?;
    }
    validate_stir_verification(&ss)?;
    validate_stir_attestation(&ss.attestation)?;

    // Per-trunk switches are enforced or rejected, never silently ignored.
    for g in &config.trunk_groups {
        for t in &g.trunks {
            if t.stir_shaken.sign && !ss.signing_enabled {
                return err(format!(
                    "trunk {}: stir_shaken.sign requires stir_shaken.signing_enabled",
                    t.id
                ));
            }
            if t.stir_shaken.verify && !ss.verification_enabled {
                return err(format!(
                    "trunk {}: stir_shaken.verify requires stir_shaken.verification_enabled",
                    t.id
                ));
            }
        }
    }
    Ok(())
}

fn validate_stir_signing(sig: &crate::schema::StirSigningConfig) -> ConfigResult<()> {
    use crate::schema::StirKeySource;
    let err = |message: String| Err(ConfigError::Validation { message });
    {
        if sig.key_source == StirKeySource::Pkcs11 {
            return err("stir_shaken.signing.key_source = \"pkcs11\" is not supported yet".into());
        }
        if sig.private_key_path.is_none() {
            return err("STIR/SHAKEN signing requires signing.private_key_path".to_string());
        }
        if sig.certificate_path.is_none() {
            return err("STIR/SHAKEN signing requires signing.certificate_path".to_string());
        }
        match sig.certificate_url.as_deref() {
            None => return err("STIR/SHAKEN signing requires signing.certificate_url".to_string()),
            Some(u) if !is_https_url(u) => {
                return err("stir_shaken.signing.certificate_url must be an https:// URL".into());
            }
            Some(_) => {}
        }
    }
    Ok(())
}

fn validate_stir_verification(ss: &crate::schema::StirShakenConfig) -> ConfigResult<()> {
    let err = |message: String| Err(ConfigError::Validation { message });
    let v = &ss.verification;
    if ss.verification_enabled && v.trust_anchors_path.is_none() {
        return err(
            "stir_shaken.verification_enabled requires verification.trust_anchors_path".to_string(),
        );
    }
    let bounded = |name: &str, val: u64, lo: u64, hi: u64| -> ConfigResult<()> {
        if (lo..=hi).contains(&val) {
            Ok(())
        } else {
            err(format!(
                "stir_shaken.verification.{name} must be {lo}..={hi}"
            ))
        }
    };
    bounded("cert_fetch_timeout_ms", v.cert_fetch_timeout_ms, 100, 5000)?;
    bounded(
        "cert_cache_entries",
        v.cert_cache_entries as u64,
        1,
        100_000,
    )?;
    bounded("cert_cache_ttl_secs", v.cert_cache_ttl_secs, 60, 86_400)?;
    bounded(
        "negative_cache_ttl_secs",
        v.negative_cache_ttl_secs,
        1,
        3600,
    )?;
    bounded("max_cert_bytes", v.max_cert_bytes as u64, 1024, 65_536)?;
    bounded(
        "max_concurrent_fetches",
        v.max_concurrent_fetches as u64,
        1,
        1024,
    )?;
    bounded(
        "trust_anchor_refresh_secs",
        v.trust_anchor_refresh_secs,
        60,
        604_800,
    )?;
    bounded("max_passport_age_secs", v.max_passport_age_secs, 10, 300)?;
    if v.x5u_allow_hosts.len() > 256
        || v.x5u_allow_hosts
            .iter()
            .any(|h| h.is_empty() || h.len() > 253 || h.contains(['/', ':', '@', ' ']))
    {
        return err(
            "stir_shaken.verification.x5u_allow_hosts entries must be bare host names (max 256)"
                .into(),
        );
    }
    Ok(())
}

fn validate_stir_attestation(a: &crate::schema::StirAttestationConfig) -> ConfigResult<()> {
    let err = |message: String| Err(ConfigError::Validation { message });
    if a.owned_numbers.len() > 10_000 || a.rules.len() > 1024 {
        return err("stir_shaken.attestation: at most 10000 owned_numbers and 1024 rules".into());
    }
    for n in &a.owned_numbers {
        let digits = n.strip_suffix('*').unwrap_or(n);
        let digits = digits.strip_prefix('+').unwrap_or(digits);
        if digits.is_empty() || digits.len() > 32 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return err(format!(
                "stir_shaken.attestation.owned_numbers entry {n:?} must be digits with an optional trailing *"
            ));
        }
    }
    for r in &a.rules {
        if let Some(p) = &r.orig_prefix
            && (p.is_empty() || p.len() > 32 || !p.bytes().all(|b| b.is_ascii_digit()))
        {
            return err("stir_shaken.attestation.rules orig_prefix must be digits".into());
        }
    }
    Ok(())
}

fn is_https_url(u: &str) -> bool {
    u.get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case("https://"))
        && u.len() > 8
        && u.len() <= 1024
        && !u.bytes().any(|b| b.is_ascii_control() || b == b' ')
}

fn validate_vps(config: &SbcConfig) -> ConfigResult<()> {
    if let Some(ref vps) = config.vps {
        vps.validate().map_err(|message| ConfigError::Validation {
            message: format!("vps: {message}"),
        })?;
    }
    Ok(())
}

fn validate_rate_limit(config: &crate::schema::RateLimitConfig) -> ConfigResult<()> {
    if config.enabled {
        if config.global_rps == 0 {
            return Err(ConfigError::Validation {
                message: "global_rps must be greater than 0 when rate limiting is enabled"
                    .to_string(),
            });
        }

        if !config.burst_multiplier.is_finite() || config.burst_multiplier < 1.0 {
            return Err(ConfigError::Validation {
                message: "burst_multiplier must be a finite number >= 1.0".to_string(),
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

        // NIST 800-53 Rev5: SC-8, CM-6 — a TLS-only group (its own flag or the
        // global `security.require_tls_trunks`) without a TLS trunk would
        // reject every call; refuse the config instead (POA&M-48).
        if (group.require_tls || config.security.require_tls_trunks)
            && !group.trunks.iter().any(|t| t.protocol == "tls")
        {
            let why = if group.require_tls {
                "require_tls = true"
            } else {
                "security.require_tls_trunks = true"
            };
            return Err(ConfigError::Validation {
                message: format!(
                    "trunk group '{}': {why} but the group has no trunk with protocol = \"tls\"",
                    group.id
                ),
            });
        }
    }

    Ok(())
}

/// Outbound TLS to trunks: trust anchors, verified name, client cert.
/// Every key is enforced by the egress flow layer or rejected here.
///
/// ## NIST 800-53 Rev5: SC-8, SC-23 (Session Authenticity), IA-3, CM-6
fn validate_trunk_tls(config: &SbcConfig) -> ConfigResult<()> {
    let mut any_tls = false;
    for group in &config.trunk_groups {
        for trunk in &group.trunks {
            let is_tls = trunk.protocol == "tls";
            any_tls |= is_tls;
            let what = |key: &str, why: &str| ConfigError::Validation {
                message: format!("trunk '{}' (group '{}'): {key} {why}", trunk.id, group.id),
            };
            // RFC 3261 §8.1.1.8, §18.2.2, §20.42: the Via sent-by and
            // Contact on a TCP/TLS leg name the SBC's listener of that
            // transport, where the trunk sends in-dialog requests and
            // late responses. Without one the SBC would advertise a port
            // nothing listens on.
            let listener_missing = match trunk.protocol.as_str() {
                "tls" => config.transport.tls_listen.is_empty(),
                "tcp" => config.transport.tcp_listen.is_empty(),
                _ => false,
            };
            if listener_missing {
                return Err(what(
                    "protocol",
                    &format!(
                        "= \"{}\" needs a transport.{}_listen address",
                        trunk.protocol, trunk.protocol
                    ),
                ));
            }
            if let Some(name) = &trunk.tls_server_name {
                if !is_tls {
                    return Err(what("tls_server_name", "requires protocol = \"tls\""));
                }
                // A DNS name (RFC 6125) or IP literal; never a SIP header value.
                if name.is_empty()
                    || name.len() > 253
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
                    // Must also be what rustls will verify against: rejects
                    // "host:5061", "::::" and other non-name/non-IP shapes.
                    || rustls_pki_types::ServerName::try_from(name.as_str()).is_err()
                {
                    return Err(what(
                        "tls_server_name",
                        "must be a DNS name or IP address (letters, digits, '.', '-', ':')",
                    ));
                }
            }
            if trunk.tls_client_cert {
                if !is_tls {
                    return Err(what("tls_client_cert", "requires protocol = \"tls\""));
                }
                if config.security.tls_cert_path.is_none() {
                    return Err(what(
                        "tls_client_cert",
                        "needs security.tls_cert_path / tls_key_path",
                    ));
                }
            }
        }
    }
    match (&config.security.trunk_tls_ca_path, any_tls) {
        (None, true) => Err(ConfigError::Validation {
            message: "a trunk uses protocol = \"tls\" but security.trunk_tls_ca_path is not set \
                      (PEM bundle of CAs that issue trunk server certificates)"
                .to_string(),
        }),
        (Some(p), _) if !p.is_absolute() => Err(ConfigError::Validation {
            message: "security.trunk_tls_ca_path must be an absolute path".to_string(),
        }),
        // A CA with no TLS trunk in this file is allowed: trunks also arrive
        // through the gRPC TrunkSync / management API (the Helm deployment
        // defines none in the config file), and a TLS trunk added that way
        // needs these anchors to connect at all.
        _ => Ok(()),
    }
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

        // max_calls = 0 would make the trunk permanently "at capacity";
        // max_failures = 0 would put it into cooldown on every failure.
        // These keys are enforced by routing, so out-of-range values are
        // rejected rather than accepted and ignored.
        //
        // ## NIST 800-53 Rev5: CM-6 (Configuration Settings), SC-5
        if trunk.max_calls == 0 {
            return Err(ConfigError::Validation {
                message: format!(
                    "trunk '{}' (group '{}'): max_calls must be greater than 0",
                    trunk.id, group.id
                ),
            });
        }
        if let Some(reserve) = trunk.emergency_reserve_calls
            && !(1..=trunk.max_calls).contains(&reserve)
        {
            return Err(ConfigError::Validation {
                message: format!(
                    "trunk '{}' (group '{}'): emergency_reserve_calls must be 1-{} (max_calls)",
                    trunk.id, group.id, trunk.max_calls
                ),
            });
        }
        if trunk.max_failures == 0 {
            return Err(ConfigError::Validation {
                message: format!(
                    "trunk '{}' (group '{}'): max_failures must be greater than 0",
                    trunk.id, group.id
                ),
            });
        }

        // The OPTIONS monitor clamps to >= 5 s; reject values it would
        // silently change rather than ignore them.
        if trunk.options_ping_enabled
            && !(MIN_OPTIONS_PING_INTERVAL_SECS..=MAX_OPTIONS_PING_INTERVAL_SECS)
                .contains(&trunk.options_ping_interval_secs)
        {
            return Err(ConfigError::Validation {
                message: format!(
                    "trunk '{}' (group '{}'): options_ping_interval_secs must be between {} and {}",
                    trunk.id,
                    group.id,
                    MIN_OPTIONS_PING_INTERVAL_SECS,
                    MAX_OPTIONS_PING_INTERVAL_SECS
                ),
            });
        }
    }

    Ok(())
}

fn validate_routing(config: &SbcConfig) -> ConfigResult<()> {
    let group_ids: HashSet<&str> = config.trunk_groups.iter().map(|g| g.id.as_str()).collect();
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
/// Validates `[cdr]`.
///
/// ## NIST 800-53 Rev5: AU-4 (Audit Log Storage Capacity), AU-5, SI-12, SC-5
fn validate_cdr(config: &crate::schema::CdrConfig) -> ConfigResult<()> {
    use crate::schema::CdrPiiMode;
    let err = |message: String| Err(ConfigError::Validation { message });
    if !config.enabled {
        return Ok(());
    }
    if !config.directory.is_absolute() {
        return err(format!(
            "cdr.directory must be an absolute path (got {})",
            config.directory.display()
        ));
    }
    if let Some(id) = &config.node_id {
        let ok = !id.is_empty()
            && id.len() <= 64
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !ok {
            return err("cdr.node_id must be 1-64 characters of [A-Za-z0-9._-]".to_string());
        }
    }
    if !(1..=4096).contains(&config.rotate_size_mb) {
        return err(format!(
            "cdr.rotate_size_mb must be 1..=4096 (got {})",
            config.rotate_size_mb
        ));
    }
    match config.rotate_interval_secs() {
        Some(0) => {}
        Some(s) if (300..=86_400).contains(&s) => {}
        _ => {
            return err(format!(
                "cdr.rotate_interval must be \"0\" or 5m..=24h (got {:?})",
                config.rotate_interval
            ));
        }
    }
    if config.fsync_interval_ms > 60_000 {
        return err(format!(
            "cdr.fsync_interval_ms must be 0..=60000 (got {})",
            config.fsync_interval_ms
        ));
    }
    if !(64..=1_000_000).contains(&config.queue_capacity) {
        return err(format!(
            "cdr.queue_capacity must be 64..=1000000 (got {})",
            config.queue_capacity
        ));
    }
    if config.ring_capacity > 200_000 {
        return err(format!(
            "cdr.ring_capacity must be 0..=200000 (got {})",
            config.ring_capacity
        ));
    }
    match (config.pii, &config.pii_hash_key_file) {
        (CdrPiiMode::Hash, None) => {
            return err("cdr.pii = \"hash\" requires cdr.pii_hash_key_file".to_string());
        }
        (CdrPiiMode::Hash, Some(p)) if !p.is_absolute() => {
            return err("cdr.pii_hash_key_file must be an absolute path".to_string());
        }
        (CdrPiiMode::Full | CdrPiiMode::MaskCaller, Some(_)) => {
            // Accepted keys must be enforced or rejected, never ignored.
            return err("cdr.pii_hash_key_file is only valid with cdr.pii = \"hash\"".to_string());
        }
        _ => {}
    }
    if config.retention_files == 0 && config.retention_days == 0 {
        // AU-4/AU-11: one bound is required so CDRs cannot fill the volume
        // unchecked (STIG: retention >= 1).
        return err(
            "cdr.retention_files and cdr.retention_days cannot both be 0 (unlimited); \
             size retention_files * rotate_size_mb to the CDR volume"
                .to_string(),
        );
    }
    validate_cdr_syslog(&config.syslog)
}

/// `[cdr.syslog]` keys are validated even when syslog is disabled: accepted
/// keys must be enforced or rejected, never silently ignored.
///
/// ## NIST 800-53 Rev5: CM-6 (Configuration Settings)
fn validate_cdr_syslog(syslog: &crate::schema::CdrSyslogConfig) -> ConfigResult<()> {
    let err = |message: String| Err(ConfigError::Validation { message });
    let config = syslog;
    {
        let Some(rest) = config.target.strip_prefix("tls://") else {
            // RFC 5425: CDRs carry PII; TLS is mandatory off-host.
            return err("cdr.syslog.target must be tls://host:port (RFC 5425)".to_string());
        };
        let valid = rest.rsplit_once(':').is_some_and(|(host, port)| {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            !host.is_empty()
                && !has_ascii_control(host)
                && !host.contains('/')
                && port.parse::<u16>().is_ok_and(|p| p != 0)
        });
        if !valid {
            return err(format!(
                "cdr.syslog.target must be tls://host:port (got {:?})",
                config.target
            ));
        }
        if config.facility > 23 {
            return err("cdr.syslog.facility must be 0..=23".to_string());
        }
        if config.ca_path.as_ref().is_some_and(|p| !p.is_absolute()) {
            return err("cdr.syslog.ca_path must be an absolute path".to_string());
        }
    }
    Ok(())
}

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
    use uc_types::media::MediaMode;

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
            require_tls: false,
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
        assert!(
            msg.contains(needle),
            "error '{msg}' should mention '{needle}'"
        );
    }

    #[test]
    fn wss_listen_is_rejected_as_unsupported() {
        let mut config = SbcConfig::default();
        config.transport.wss_listen = vec!["0.0.0.0:7443".parse().unwrap()];
        let err = validate_config(&config).unwrap_err().to_string();
        assert!(err.contains("wss_listen"), "{err}");
        config.transport.wss_listen.clear();
        config.transport.ws_listen = vec!["0.0.0.0:7080".parse().unwrap()];
        assert!(
            validate_config(&config).is_ok(),
            "plain ws_listen is supported"
        );
    }

    #[test]
    fn require_mtls_needs_certificate_and_client_ca() {
        let mut config = SbcConfig::default();
        config.security.require_mtls = true;
        assert!(
            validate_config(&config)
                .unwrap_err()
                .to_string()
                .contains("tls_cert_path")
        );
        config.security.tls_cert_path = Some("/etc/sbc/tls.crt".into());
        config.security.tls_key_path = Some("/etc/sbc/tls.key".into());
        assert!(
            validate_config(&config)
                .unwrap_err()
                .to_string()
                .contains("tls_ca_path")
        );
        config.security.tls_ca_path = Some("/etc/sbc/clients-ca.pem".into());
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn logging_fields_are_validated() {
        let mut config = SbcConfig::default();
        config.logging.format = "yaml".to_string();
        assert!(
            validate_config(&config)
                .unwrap_err()
                .to_string()
                .contains("logging.format")
        );
        config.logging.format = "text".to_string();
        config.logging.level = "loud".to_string();
        assert!(
            validate_config(&config)
                .unwrap_err()
                .to_string()
                .contains("logging.level")
        );
        config.logging.level = "warn".to_string();
        config.logging.output = " ".to_string();
        assert!(
            validate_config(&config)
                .unwrap_err()
                .to_string()
                .contains("logging.output")
        );
        config.logging.output = "/var/log/sbc/sbc.log".to_string();
        assert!(validate_config(&config).is_ok());
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

    fn stir_signing_ok() -> SbcConfig {
        let mut config = SbcConfig::default();
        let s = &mut config.stir_shaken;
        s.signing_enabled = true;
        s.signing.private_key_path = Some("/etc/sbc/sti.key".into());
        s.signing.certificate_path = Some("/etc/sbc/sti.pem".into());
        s.signing.certificate_url = Some("https://cert.example.invalid/sti.pem".into());
        config
    }

    #[test]
    fn stir_defaults_are_off_and_valid() {
        let config = SbcConfig::default();
        assert!(!config.stir_shaken.verification_enabled);
        assert!(!config.stir_shaken.signing_enabled);
        assert_eq!(
            config.stir_shaken.attestation.default,
            crate::schema::StirAttestation::C
        );
        validate_config(&config).unwrap();
    }

    #[test]
    fn stir_signing_rules() {
        validate_config(&stir_signing_ok()).unwrap();
        let mut c = stir_signing_ok();
        c.stir_shaken.signing.certificate_url = Some("http://cert.example.invalid/a".into());
        assert_rejected(&c, "https");
        let mut c = stir_signing_ok();
        c.stir_shaken.signing.key_source = crate::schema::StirKeySource::Pkcs11;
        assert_rejected(&c, "pkcs11");
        let mut c = stir_signing_ok();
        c.stir_shaken.algorithm = crate::schema::StirAlgorithm::Es384;
        assert_rejected(&c, "ES384");
    }

    #[test]
    fn stir_verification_rules() {
        let mut c = SbcConfig::default();
        c.stir_shaken.verification_enabled = true;
        assert_rejected(&c, "trust_anchors_path");
        c.stir_shaken.verification.trust_anchors_path = Some("/etc/sbc/sti-cr".into());
        validate_config(&c).unwrap();
        c.stir_shaken.verification.cert_fetch_timeout_ms = 50;
        assert_rejected(&c, "cert_fetch_timeout_ms");
        c.stir_shaken.verification.cert_fetch_timeout_ms = 1500;
        c.stir_shaken.verification.cert_cache_entries = 0;
        assert_rejected(&c, "cert_cache_entries");
        c.stir_shaken.verification.cert_cache_entries = 100_001;
        assert_rejected(&c, "cert_cache_entries");
        c.stir_shaken.verification.cert_cache_entries = 10;
        c.stir_shaken.verification.x5u_allow_hosts = vec!["https://x".into()];
        assert_rejected(&c, "x5u_allow_hosts");
    }

    #[test]
    fn stir_trunk_switch_requires_global() {
        let mut c = SbcConfig::default();
        c.trunk_groups.push(crate::schema::TrunkGroupConfig {
            id: "g".into(),
            name: String::new(),
            strategy: "priority".into(),
            trunks: vec![TrunkConfigSchema {
                id: "t1".into(),
                host: "192.0.2.1".into(),
                stir_shaken: crate::schema::TrunkStirConfig {
                    sign: true,
                    ..Default::default()
                },
                ..Default::default()
            }],
            zone: None,
            require_tls: false,
        });
        assert_rejected(&c, "signing_enabled");
    }

    #[test]
    fn stir_deprecated_aliases() {
        let toml_src = r#"
[stir_shaken]
signing_enabled = true
certificate_path = "/etc/sbc/sti.pem"
private_key_path = "/etc/sbc/sti.key"
certificate_url = "https://cert.example.invalid/sti.pem"
default_attestation = "B"
max_passport_age_secs = 30
"#;
        let c: SbcConfig = toml::from_str(toml_src).unwrap();
        let (n, used) = c.stir_shaken.normalized().unwrap();
        assert_eq!(used.len(), 5);
        assert_eq!(
            n.signing.certificate_path.as_deref(),
            Some(std::path::Path::new("/etc/sbc/sti.pem"))
        );
        assert_eq!(n.attestation.default, crate::schema::StirAttestation::B);
        assert_eq!(n.verification.max_passport_age_secs, 30);
        validate_config(&c).unwrap();

        let mut bad = c.clone();
        bad.stir_shaken.signing.certificate_path = Some("/other".into());
        assert_rejected(&bad, "conflicts");
        let mut bad = c;
        bad.stir_shaken.default_attestation = Some("Z".into());
        assert_rejected(&bad, "default_attestation");
    }

    fn stir_verify_ok() -> SbcConfig {
        let mut c = SbcConfig::default();
        c.stir_shaken.verification_enabled = true;
        c.stir_shaken.verification.trust_anchors_path = Some("/etc/sbc/sti-cr".into());
        c
    }

    /// QA: every numeric bound, both edges, one key at a time.
    #[test]
    fn qa_stir_every_verification_bound() {
        type Set = fn(&mut crate::schema::StirVerificationConfig, u64);
        let cases: &[(&str, Set, u64, u64)] = &[
            (
                "cert_fetch_timeout_ms",
                |v, x| v.cert_fetch_timeout_ms = x,
                100,
                5000,
            ),
            (
                "cert_cache_entries",
                |v, x| v.cert_cache_entries = usize::try_from(x).unwrap(),
                1,
                100_000,
            ),
            (
                "cert_cache_ttl_secs",
                |v, x| v.cert_cache_ttl_secs = x,
                60,
                86_400,
            ),
            (
                "negative_cache_ttl_secs",
                |v, x| v.negative_cache_ttl_secs = x,
                1,
                3600,
            ),
            (
                "max_cert_bytes",
                |v, x| v.max_cert_bytes = usize::try_from(x).unwrap(),
                1024,
                65_536,
            ),
            (
                "max_concurrent_fetches",
                |v, x| v.max_concurrent_fetches = usize::try_from(x).unwrap(),
                1,
                1024,
            ),
            (
                "trust_anchor_refresh_secs",
                |v, x| v.trust_anchor_refresh_secs = x,
                60,
                604_800,
            ),
            (
                "max_passport_age_secs",
                |v, x| v.max_passport_age_secs = x,
                10,
                300,
            ),
        ];
        for &(name, set, lo, hi) in cases {
            for ok in [lo, hi] {
                let mut c = stir_verify_ok();
                set(&mut c.stir_shaken.verification, ok);
                assert!(validate_config(&c).is_ok(), "{name}={ok}");
            }
            for bad in [lo - 1, hi + 1] {
                let mut c = stir_verify_ok();
                set(&mut c.stir_shaken.verification, bad);
                assert_rejected(&c, name);
            }
        }
        // Bounds apply even when verification is off (no silent acceptance).
        let mut c = SbcConfig::default();
        c.stir_shaken.verification.cert_fetch_timeout_ms = 0;
        assert_rejected(&c, "cert_fetch_timeout_ms");
    }

    #[test]
    fn qa_stir_allow_hosts_and_attestation_syntax() {
        for bad in ["", "a b", "h:443", "u@h", "h/p"] {
            let mut c = stir_verify_ok();
            c.stir_shaken.verification.x5u_allow_hosts = vec![bad.into()];
            assert_rejected(&c, "x5u_allow_hosts");
        }
        let mut c = stir_verify_ok();
        c.stir_shaken.verification.x5u_allow_hosts = vec!["cert.example.com".into()];
        validate_config(&c).unwrap();
        c.stir_shaken.verification.x5u_allow_hosts = vec!["h".into(); 257];
        assert_rejected(&c, "x5u_allow_hosts");

        for good in ["+1202555*", "1202555", "1*"] {
            let mut c = SbcConfig::default();
            c.stir_shaken.attestation.owned_numbers = vec![good.into()];
            assert!(validate_config(&c).is_ok(), "{good}");
        }
        for bad in ["", "*", "+", "12a", "1*2", &"1".repeat(33)] {
            let mut c = SbcConfig::default();
            c.stir_shaken.attestation.owned_numbers = vec![bad.to_string()];
            assert_rejected(&c, "owned_numbers");
        }
        let toml_src = r#"
[stir_shaken.attestation]
default = "A"
[[stir_shaken.attestation.rules]]
orig_prefix = "12x"
attest = "A"
"#;
        let c: SbcConfig = toml::from_str(toml_src).unwrap();
        assert_rejected(&c, "orig_prefix");
        assert!(
            toml::from_str::<SbcConfig>("[stir_shaken.attestation]\ndefault = \"D\"\n").is_err(),
            "attestation.default is a typed enum"
        );
    }

    #[test]
    fn qa_stir_trunk_verify_requires_global_and_unknown_trunk_key() {
        let toml_src = r#"
[[trunk_groups]]
id = "g"
strategy = "priority"
[[trunk_groups.trunks]]
id = "t1"
host = "192.0.2.1"
stir_shaken = { verify = true }
"#;
        let c: SbcConfig = toml::from_str(toml_src).unwrap();
        assert_rejected(&c, "verification_enabled");
        // deny_unknown_fields on the per-trunk table.
        let typo = toml_src.replace("verify = true", "verfy = true");
        assert!(toml::from_str::<SbcConfig>(&typo).is_err());
    }

    #[test]
    fn qa_stir_failure_policy_and_algorithm_strings() {
        for (s, want) in [
            (
                "pass-through",
                crate::schema::StirFailurePolicy::PassThrough,
            ),
            ("mark", crate::schema::StirFailurePolicy::Mark),
            ("reject", crate::schema::StirFailurePolicy::Reject),
        ] {
            let c: SbcConfig = toml::from_str(&format!(
                "[stir_shaken.verification]\nfailure_policy = \"{s}\"\n"
            ))
            .unwrap();
            assert_eq!(c.stir_shaken.verification.failure_policy, want);
        }
        assert!(
            toml::from_str::<SbcConfig>("[stir_shaken.verification]\nfailure_policy = \"drop\"\n")
                .is_err()
        );
        let c: SbcConfig = toml::from_str("[stir_shaken]\nalgorithm = \"ES384\"\n").unwrap();
        assert_rejected(&c, "ES384");
        let c: SbcConfig =
            toml::from_str("[stir_shaken.signing]\nkey_source = \"pkcs11\"\n").unwrap();
        // NIST-008: pkcs11 is rejected even with signing off.
        assert_rejected(&c, "pkcs11");
    }

    #[test]
    fn qa_stir_ca_bundle_alias_and_conflicts() {
        let toml_src = r#"
[stir_shaken]
verification_enabled = true
ca_bundle_path = "/etc/sbc/sti-cr"
"#;
        let c: SbcConfig = toml::from_str(toml_src).unwrap();
        let (n, used) = c.stir_shaken.normalized().unwrap();
        assert_eq!(used, vec!["ca_bundle_path"]);
        assert_eq!(
            n.verification.trust_anchors_path.as_deref(),
            Some(std::path::Path::new("/etc/sbc/sti-cr"))
        );
        validate_config(&c).unwrap();
        // Same value under both: accepted, not a conflict.
        let mut same = c.clone();
        same.stir_shaken.verification.trust_anchors_path = Some("/etc/sbc/sti-cr".into());
        validate_config(&same).unwrap();
        let mut bad = c;
        bad.stir_shaken.verification.trust_anchors_path = Some("/other".into());
        assert_rejected(&bad, "ca_bundle_path");
    }

    /// QA: the deprecated top-level `max_passport_age_secs` silently wins
    /// over a different nested value; every other alias reports a conflict.
    #[test]
    fn qa_stir_max_age_alias_conflict_is_reported() {
        let toml_src = "
[stir_shaken]
max_passport_age_secs = 30
[stir_shaken.verification]
max_passport_age_secs = 120
";
        let c: SbcConfig = toml::from_str(toml_src).unwrap();
        assert!(c.stir_shaken.normalized().is_err());
        // Alias alone, or agreeing with the nested key, still folds.
        let c: SbcConfig = toml::from_str("[stir_shaken]\nmax_passport_age_secs = 30\n").unwrap();
        let (n, used) = c.stir_shaken.normalized().unwrap();
        assert_eq!(n.verification.max_passport_age_secs, 30);
        assert_eq!(used, vec!["max_passport_age_secs"]);
        let c: SbcConfig = toml::from_str(
            "[stir_shaken]\nmax_passport_age_secs = 30\n[stir_shaken.verification]\nmax_passport_age_secs = 30\n",
        )
        .unwrap();
        assert!(c.stir_shaken.normalized().is_ok());
        let c: SbcConfig = toml::from_str(
            "[stir_shaken]\ndefault_attestation = \"A\"\n[stir_shaken.attestation]\ndefault = \"B\"\n",
        )
        .unwrap();
        assert!(c.stir_shaken.normalized().is_err());
    }

    /// `[stir_shaken]` and its nested tables reject unknown keys; the
    /// deprecated flat aliases are still accepted.
    #[test]
    fn stir_unknown_keys_rejected() {
        for src in [
            "[stir_shaken]\nsigning_enabeld = true\n",
            "[stir_shaken.signing]\nprivate_key = \"/k\"\n",
            "[stir_shaken.attestation]\ndefualt = \"A\"\n",
            "[stir_shaken.verification]\nmax_age = 30\n",
        ] {
            assert!(toml::from_str::<SbcConfig>(src).is_err(), "{src}");
        }
        let ok = "[stir_shaken]\ncertificate_path = \"/c\"\nprivate_key_path = \"/k\"\n\
                  certificate_url = \"https://x/c\"\nca_bundle_path = \"/a\"\n\
                  default_attestation = \"B\"\nmax_passport_age_secs = 30\n";
        assert!(toml::from_str::<SbcConfig>(ok).is_ok());
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
        for host in [
            "[2001:db8::1]",
            "2001:db8::1",
            "192.0.2.10",
            "sip-1.example.com",
        ] {
            let mut group = trunk_group("tg1");
            group.trunks[0].host = host.to_string();
            config.trunk_groups = vec![group];
            assert!(validate_config(&config).is_ok(), "host {host}");
        }

        for host in [
            "evil\r\nhost",
            "host with space",
            "host;param",
            "host_under",
        ] {
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
            config.security.trunk_tls_ca_path =
                (*protocol == "tls").then(|| "/etc/sbc/trunk-ca.pem".into());
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

    #[test]
    fn test_repo_deploy_configs_validate() {
        for rel in ["deploy/config/config.toml", "deploy/test/sbc-test.toml"] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../..")
                .join(rel);
            let text = std::fs::read_to_string(&path).expect(rel);
            let config = crate::load_from_str(&text).expect(rel);
            let result = validate_config(&config);
            assert!(result.is_ok(), "{rel} must validate: {result:?}");
        }
    }

    #[test]
    fn test_media_default_mode_must_be_relay() {
        for mode in [MediaMode::PassThrough, MediaMode::SignalingOnly] {
            let mut config = SbcConfig::default();
            config.media.default_mode = mode;
            assert_rejected(&config, "media.default_mode");
        }
    }

    #[test]
    fn test_media_realm_modes_rejected() {
        let mut config = SbcConfig::default();
        config
            .media
            .realm_modes
            .insert("external".to_string(), MediaMode::Relay);
        assert_rejected(&config, "media.realm_modes");
        assert_rejected(&config, "external");
    }

    #[test]
    fn test_media_codecs_must_equal_default_set() {
        use uc_types::codec::CodecId;

        let mut config = SbcConfig::default();
        config.media.codecs.reverse();
        validate_config(&config).expect("reordered default codecs are accepted");

        config.media.codecs = vec![CodecId::G711Ulaw, CodecId::G711Alaw, CodecId::G722];
        assert_rejected(&config, "media.codecs");

        config.media.codecs = vec![
            CodecId::Opus,
            CodecId::G722,
            CodecId::G711Ulaw,
            CodecId::G711Alaw,
            CodecId::G711Alaw,
        ];
        assert_rejected(&config, "media.codecs");
    }

    #[test]
    fn test_trunk_limits_must_be_positive() {
        let mut config = SbcConfig::default();
        let mut group = trunk_group("tg");
        group.trunks[0].max_calls = 0;
        config.trunk_groups = vec![group];
        assert_rejected(&config, "max_calls");

        let mut group = trunk_group("tg");
        group.trunks[0].max_failures = 0;
        config.trunk_groups = vec![group];
        assert_rejected(&config, "max_failures");
    }

    #[test]
    fn emergency_reserve_calls_default_and_bounds() {
        let mut config = SbcConfig::default();
        assert_eq!(config.general.emergency_reserve_calls, None);
        assert_eq!(config.general.effective_emergency_reserve_calls(), 1000);
        config.general.max_calls = 5;
        assert_eq!(config.general.effective_emergency_reserve_calls(), 1);
        for ok in [1, 5] {
            config.general.emergency_reserve_calls = Some(ok);
            assert!(super::validate_config(&config).is_ok(), "{ok}");
            assert_eq!(config.general.effective_emergency_reserve_calls(), ok);
        }
        for bad in [0, 6, u32::MAX] {
            config.general.emergency_reserve_calls = Some(bad);
            assert_rejected(&config, "emergency_reserve_calls");
        }
        config.general.emergency_reserve_calls = None;

        let mut group = trunk_group("tg");
        group.trunks[0].max_calls = 20;
        assert_eq!(group.trunks[0].effective_emergency_reserve_calls(), 2);
        group.trunks[0].emergency_reserve_calls = Some(20);
        config.trunk_groups = vec![group.clone()];
        assert!(super::validate_config(&config).is_ok());
        for bad in [0, 21] {
            group.trunks[0].emergency_reserve_calls = Some(bad);
            config.trunk_groups = vec![group.clone()];
            assert_rejected(&config, "emergency_reserve_calls");
        }

        let parsed =
            crate::load_from_str("[general]\nmax_calls = 100\nemergency_reserve_calls = 7\n")
                .unwrap();
        assert_eq!(parsed.general.effective_emergency_reserve_calls(), 7);
    }

    #[test]
    fn test_trunk_options_ping_interval_bounds() {
        let mut config = SbcConfig::default();
        let mut group = trunk_group("tg");
        group.trunks[0].options_ping_enabled = true;
        group.trunks[0].options_ping_interval_secs = 30;
        config.trunk_groups = vec![group.clone()];
        validate_config(&config).expect("30 s ping interval is valid");

        for bad in [0, 4, 3601] {
            group.trunks[0].options_ping_interval_secs = bad;
            config.trunk_groups = vec![group.clone()];
            assert_rejected(&config, "options_ping_interval_secs");
        }

        // Not checked while pinging is off.
        group.trunks[0].options_ping_enabled = false;
        group.trunks[0].options_ping_interval_secs = 0;
        config.trunk_groups = vec![group];
        validate_config(&config).expect("interval ignored when disabled");
    }

    #[test]
    fn cdr_defaults_valid() {
        let config = SbcConfig::default();
        assert!(config.cdr.enabled);
        assert!(validate_config(&config).is_ok());
        assert_eq!(config.cdr.rotate_interval_secs(), Some(3600));
    }

    #[test]
    fn cdr_relative_directory_rejected() {
        let mut config = SbcConfig::default();
        config.cdr.directory = "cdr".into();
        assert_rejected(&config, "cdr.directory");
        config.cdr.enabled = false;
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn cdr_pii_hash_requires_key_file() {
        use crate::schema::CdrPiiMode;
        let mut config = SbcConfig::default();
        config.cdr.pii = CdrPiiMode::Hash;
        assert_rejected(&config, "pii_hash_key_file");
        config.cdr.pii_hash_key_file = Some("key".into());
        assert_rejected(&config, "absolute");
        config.cdr.pii_hash_key_file = Some("/etc/usg-sbc/cdr.key".into());
        assert!(validate_config(&config).is_ok());
        config.cdr.pii = CdrPiiMode::Full;
        assert_rejected(&config, "only valid with");
    }

    #[test]
    fn cdr_unlimited_retention_rejected() {
        let mut c = SbcConfig::default();
        c.cdr.retention_files = 0;
        c.cdr.retention_days = 0;
        assert_rejected(&c, "cannot both be 0");
        c.cdr.retention_days = 1;
        assert!(validate_config(&c).is_ok());
    }

    #[test]
    fn cdr_syslog_keys_validated_while_disabled() {
        let base = SbcConfig::default();
        assert!(!base.cdr.syslog.enabled);
        let mut c = base.clone();
        c.cdr.syslog.target = "udp://collector:514".to_string();
        assert_rejected(&c, "cdr.syslog.target");
        let mut c = base.clone();
        c.cdr.syslog.facility = 24;
        assert_rejected(&c, "facility");
        let mut c = base;
        c.cdr.syslog.ca_path = Some("ca.pem".into());
        assert_rejected(&c, "ca_path");
    }

    #[test]
    fn cdr_ranges_enforced() {
        let base = SbcConfig::default();
        let mut c = base.clone();
        c.cdr.rotate_size_mb = 0;
        assert_rejected(&c, "rotate_size_mb");
        let mut c = base.clone();
        c.cdr.rotate_size_mb = 5000;
        assert_rejected(&c, "rotate_size_mb");
        for bad in ["1m", "25h", "abc", "", "-5m", "1d"] {
            let mut c = base.clone();
            c.cdr.rotate_interval = bad.to_string();
            assert_rejected(&c, "rotate_interval");
        }
        for good in ["0", "5m", "300", "24h", "3600s"] {
            let mut c = base.clone();
            c.cdr.rotate_interval = good.to_string();
            assert!(validate_config(&c).is_ok(), "{good}");
        }
        let mut c = base.clone();
        c.cdr.queue_capacity = 10;
        assert_rejected(&c, "queue_capacity");
        let mut c = base.clone();
        c.cdr.ring_capacity = 200_001;
        assert_rejected(&c, "ring_capacity");
        let mut c = base.clone();
        c.cdr.fsync_interval_ms = 60_001;
        assert_rejected(&c, "fsync_interval_ms");
        let mut c = base;
        c.cdr.node_id = Some("../etc".into());
        assert_rejected(&c, "node_id");
    }

    #[test]
    fn cdr_syslog_requires_tls() {
        let mut config = SbcConfig::default();
        config.cdr.syslog.enabled = true;
        assert!(validate_config(&config).is_ok());
        config.cdr.syslog.target = "udp://collector:514".into();
        assert_rejected(&config, "tls://");
        config.cdr.syslog.target = "tls://collector".into();
        assert_rejected(&config, "tls://");
        config.cdr.syslog.target = "tls://[2001:db8::1]:6514".into();
        assert!(validate_config(&config).is_ok());
        config.cdr.syslog.facility = 24;
        assert_rejected(&config, "facility");
    }
    // NIST 800-53 Rev5: SC-8, SC-23 — outbound trunk TLS keys are enforced
    // or rejected, never ignored.
    // RFC-001 (RFC 3261 §18.2.2, §20.42): a TCP/TLS trunk needs a listener
    // of that transport, or the Via/Contact would name a dead port.
    #[test]
    fn stream_trunk_requires_matching_listener() {
        for (proto, port) in [("tls", 5061), ("tcp", 5060)] {
            let mut c = SbcConfig::default();
            let mut g = trunk_group("g1");
            g.trunks[0].protocol = proto.to_string();
            g.trunks[0].port = port;
            c.trunk_groups = vec![g];
            if proto == "tls" {
                c.security.trunk_tls_ca_path = Some("/etc/sbc/trunk-ca.pem".into());
            }
            super::validate_config(&c).unwrap();
            if proto == "tls" {
                c.transport.tls_listen.clear();
            } else {
                c.transport.tcp_listen.clear();
            }
            let err = super::validate_config(&c).unwrap_err().to_string();
            assert!(err.contains(&format!("transport.{proto}_listen")), "{err}");
        }
        // A UDP trunk needs no stream listener.
        let mut c = SbcConfig::default();
        c.transport.tcp_listen.clear();
        c.transport.tls_listen.clear();
        c.trunk_groups = vec![trunk_group("g1")];
        super::validate_config(&c).unwrap();
    }

    #[test]
    fn trunk_tls_keys_validated() {
        let tls_cfg = || {
            let mut c = SbcConfig::default();
            let mut g = trunk_group("g1");
            g.trunks[0].protocol = "tls".to_string();
            g.trunks[0].port = 5061;
            c.trunk_groups = vec![g];
            c
        };
        // A TLS trunk needs trunk trust anchors.
        let c = tls_cfg();
        let err = super::validate_config(&c).unwrap_err().to_string();
        assert!(err.contains("trunk_tls_ca_path"), "{err}");
        let mut c = tls_cfg();
        c.security.trunk_tls_ca_path = Some("trunks.pem".into());
        assert!(
            super::validate_config(&c).is_err(),
            "relative path rejected"
        );
        c.security.trunk_tls_ca_path = Some("/etc/sbc/trunk-ca.pem".into());
        super::validate_config(&c).unwrap();

        // Server name: TLS only, no header metacharacters.
        c.trunk_groups[0].trunks[0].tls_server_name = Some("sip.example.net".to_string());
        super::validate_config(&c).unwrap();
        c.trunk_groups[0].trunks[0].tls_server_name = Some("bad\r\nVia: x".to_string());
        assert!(super::validate_config(&c).is_err());
        c.trunk_groups[0].trunks[0].tls_server_name = None;

        // mTLS to the trunk needs the SBC certificate.
        c.trunk_groups[0].trunks[0].tls_client_cert = true;
        assert!(super::validate_config(&c).is_err());
        c.security.tls_cert_path = Some("/etc/sbc/cert.pem".into());
        c.security.tls_key_path = Some("/etc/sbc/key.pem".into());
        super::validate_config(&c).unwrap();

        // TLS-only keys on a UDP trunk are rejected, as is an unused CA.
        let mut c = SbcConfig::default();
        c.trunk_groups = vec![trunk_group("g1")];
        c.trunk_groups[0].trunks[0].tls_server_name = Some("sip.example.net".to_string());
        assert!(super::validate_config(&c).is_err());
        c.trunk_groups[0].trunks[0].tls_server_name = None;
        c.trunk_groups[0].trunks[0].tls_client_cert = true;
        assert!(super::validate_config(&c).is_err());
        c.trunk_groups[0].trunks[0].tls_client_cert = false;
        c.security.trunk_tls_ca_path = Some("/etc/sbc/trunk-ca.pem".into());
        // An unused CA is allowed (trunks may arrive via TrunkSync).
        super::validate_config(&c).unwrap();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod qa_trunk_tls_edges {
    use crate::schema::{SbcConfig, TrunkConfigSchema, TrunkGroupConfig};

    fn group(id: &str, proto: &str) -> TrunkGroupConfig {
        TrunkGroupConfig {
            id: id.to_string(),
            name: id.to_string(),
            strategy: "priority".to_string(),
            trunks: vec![TrunkConfigSchema {
                id: format!("{id}-t"),
                host: "sip.example.net".to_string(),
                port: if proto == "tls" { 5061 } else { 5060 },
                protocol: proto.to_string(),
                ..TrunkConfigSchema::default()
            }],
            zone: None,
            require_tls: false,
        }
    }

    fn cfg(groups: Vec<TrunkGroupConfig>, ca: Option<&str>) -> SbcConfig {
        let mut c = SbcConfig {
            trunk_groups: groups,
            ..SbcConfig::default()
        };
        c.security.trunk_tls_ca_path = ca.map(Into::into);
        c
    }

    fn err(c: &SbcConfig) -> String {
        super::validate_config(c).unwrap_err().to_string()
    }

    // POA&M-48 (SC-8): require_tls validation.
    #[test]
    fn require_tls_group_needs_a_tls_trunk() {
        let ca = Some("/etc/sbc/trunk-ca.pem");
        let mut g = group("a", "udp");
        g.require_tls = true;
        assert!(err(&cfg(vec![g.clone()], ca)).contains("require_tls"));
        g.trunks.clear();
        assert!(err(&cfg(vec![g.clone()], ca)).contains("require_tls"));
        // Mixed group is fine.
        let mut g = group("a", "udp");
        g.require_tls = true;
        g.trunks.extend(group("b", "tls").trunks);
        super::validate_config(&cfg(vec![g], ca)).unwrap();
    }

    #[test]
    fn global_require_tls_trunks_applies_to_every_group() {
        let ca = Some("/etc/sbc/trunk-ca.pem");
        let mut c = cfg(vec![group("a", "tls"), group("b", "tcp")], ca);
        super::validate_config(&c).unwrap();
        c.security.require_tls_trunks = true;
        assert!(err(&c).contains("security.require_tls_trunks"));
        c.trunk_groups.truncate(1);
        super::validate_config(&c).unwrap();
    }

    #[test]
    fn require_tls_absent_key_defaults_false() {
        let c = crate::load_from_str(
            "[[trunk_groups]]\nid = \"g\"\n[[trunk_groups.trunks]]\nid = \"t\"\nhost = \"sip.example.net\"\n",
        )
        .unwrap();
        assert!(!c.trunk_groups[0].require_tls);
        assert!(!c.security.require_tls_trunks);
    }

    #[test]
    fn tls_trunk_in_a_later_group_still_needs_ca() {
        let c = cfg(vec![group("a", "udp"), group("b", "tls")], None);
        assert!(err(&c).contains("trunk_tls_ca_path"));
        let c = cfg(
            vec![group("a", "udp"), group("b", "tls")],
            Some("/etc/sbc/trunk-ca.pem"),
        );
        super::validate_config(&c).unwrap();
    }

    #[test]
    fn trunk_ca_path_empty_or_relative_rejected() {
        for p in ["", "trunk-ca.pem", "./trunk-ca.pem", "../etc/ca.pem"] {
            let c = cfg(vec![group("a", "tls")], Some(p));
            assert!(err(&c).contains("absolute"), "{p:?}");
        }
    }

    #[test]
    fn trunk_ca_without_tls_trunk_in_file_is_allowed() {
        // TLS trunks may arrive later via TrunkSync; the CA must be loadable
        // up front. It must still be absolute.
        let c = cfg(vec![group("a", "tcp")], Some("/etc/sbc/trunk-ca.pem"));
        super::validate_config(&c).unwrap();
        let c = cfg(Vec::new(), Some("/etc/sbc/trunk-ca.pem"));
        super::validate_config(&c).unwrap();
        let c = cfg(Vec::new(), Some("trunk-ca.pem"));
        assert!(err(&c).contains("absolute"));
    }

    #[test]
    fn tls_server_name_shapes() {
        // 253 octets in labels of at most 63 (RFC 1035 §2.3.4).
        let max_name = format!("{0}.{0}.{0}.{1}", "a".repeat(63), "a".repeat(61));
        assert_eq!(max_name.len(), 253);
        for ok in ["sip.example.net", "192.0.2.10", "2001:db8::1", &max_name] {
            let mut c = cfg(vec![group("a", "tls")], Some("/etc/sbc/trunk-ca.pem"));
            c.trunk_groups[0].trunks[0].tls_server_name = Some(ok.to_string());
            assert!(super::validate_config(&c).is_ok(), "{ok:?} rejected");
        }
        for bad in [
            "",
            &"a".repeat(254),
            "sip example.net",
            "sip_example.net",
            "sip.example.net\r\n",
            "sip.example.net;transport=udp",
            "*.example.net",
            "sip.example.net/",
            "host:5061",
            "::::",
            "sip..example.net",
            &"a".repeat(64),
        ] {
            let mut c = cfg(vec![group("a", "tls")], Some("/etc/sbc/trunk-ca.pem"));
            c.trunk_groups[0].trunks[0].tls_server_name = Some(bad.to_string());
            assert!(super::validate_config(&c).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn tls_keys_rejected_on_tcp_trunk() {
        let mut c = cfg(vec![group("a", "tcp")], None);
        c.trunk_groups[0].trunks[0].tls_server_name = Some("sip.example.net".to_string());
        assert!(err(&c).contains("requires protocol"));
        let mut c = cfg(vec![group("a", "tcp")], None);
        c.trunk_groups[0].trunks[0].tls_client_cert = true;
        assert!(err(&c).contains("requires protocol"));
    }

    #[test]
    fn tls_client_cert_needs_cert_and_key_pair() {
        let mut c = cfg(vec![group("a", "tls")], Some("/etc/sbc/trunk-ca.pem"));
        c.trunk_groups[0].trunks[0].tls_client_cert = true;
        c.security.tls_cert_path = Some("/etc/sbc/cert.pem".into());
        assert!(super::validate_config(&c).is_err(), "cert without key");
        c.security.tls_cert_path = None;
        c.security.tls_key_path = Some("/etc/sbc/key.pem".into());
        assert!(super::validate_config(&c).is_err(), "key without cert");
    }
}

/// Tests that the shipped deploy configurations still validate.
///
/// Fixtures are extracted from:
/// - `deploy/config/config.toml`
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
verification_enabled = false

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

[cdr]
enabled = true
format = "jsonl"
directory = "/var/lib/usg-sbc/cdr"
rotate_size_mb = 100
rotate_interval = "1h"
retention_files = 168
retention_days = 90
fsync_interval_ms = 1000
queue_capacity = 8192
ring_capacity = 10000
hash_chain = true
record_unanswered = "all"
record_auth_challenges = false
pii = "full"
on_failure = "continue"

[cdr.syslog]
enabled = false
target = "tls://collector.example.net:6514"
facility = 16
"#;

    #[test]
    fn test_deploy_config_toml_validates() {
        let config = crate::load_from_str(DEPLOY_CONFIG_TOML).expect("deploy/config/config.toml");
        assert_eq!(config.general.instance_name, "sbc-01");
        super::validate_config(&config).expect("deploy/config/config.toml must validate");
    }

    #[test]
    fn trunk_retry_after_max_secs_bounds() {
        let mut config = crate::SbcConfig::default();
        assert_eq!(config.general.trunk_retry_after_max_secs, 300);
        for ok in [1, 300, 3600] {
            config.general.trunk_retry_after_max_secs = ok;
            assert!(super::validate_config(&config).is_ok(), "{ok}");
        }
        for bad in [0, 3601, u32::MAX] {
            config.general.trunk_retry_after_max_secs = bad;
            assert!(super::validate_config(&config).is_err(), "{bad}");
        }
    }

    #[test]
    fn emergency_numbers_parse_default_and_reject_invalid() {
        let config = crate::load_from_str("[vps]\nenabled = true\n").unwrap();
        assert_eq!(
            config.vps.as_ref().unwrap().emergency_numbers,
            vec!["911", "933", "112"]
        );
        let config = crate::load_from_str(
            "[general]\ntrunk_retry_after_max_secs = 60\n[vps]\nemergency_numbers = [\"911\", \"+999\"]\n",
        )
        .unwrap();
        assert_eq!(config.general.trunk_retry_after_max_secs, 60);
        assert_eq!(
            config.vps.as_ref().unwrap().emergency_numbers,
            vec!["911", "+999"]
        );
        assert!(super::validate_config(&config).is_ok());
        let mut bad = config;
        bad.vps.as_mut().unwrap().emergency_numbers = vec!["9-1-1".to_string()];
        assert!(super::validate_config(&bad).is_err());
        assert!(crate::load_from_str("[general]\ntrunk_retry_after_max_secs = 0\n").is_err());
    }
}

#[cfg(all(test, feature = "cluster"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod cluster_admission_tests {
    use super::*;
    use crate::schema::{
        AdmissionSplit, ClusterConfig, TrunkConfigSchema, TrunkGroupConfig, cluster_share,
    };

    fn divided(n: u32) -> SbcConfig {
        let mut config = SbcConfig::default();
        let mut cluster = ClusterConfig {
            enabled: true,
            ..ClusterConfig::default()
        };
        cluster.admission.split = AdmissionSplit::Divide;
        cluster.admission.expected_nodes = n;
        config.cluster = Some(cluster);
        config
    }

    fn rejected(config: &SbcConfig, needle: &str) {
        let msg = validate_config(config).expect_err("rejected").to_string();
        assert!(msg.contains(needle), "'{msg}' should mention '{needle}'");
    }

    #[test]
    fn share_arithmetic() {
        assert_eq!(cluster_share(100, 0), 100);
        assert_eq!(cluster_share(100, 1), 100);
        assert_eq!(cluster_share(100, 3), 33);
        assert_eq!(cluster_share(2, 3), 1);
        assert_eq!(cluster_share(u32::MAX, 64), u32::MAX / 64);
    }

    #[test]
    fn per_node_default_keeps_configured_caps() {
        let config = SbcConfig::default();
        validate_config(&config).unwrap();
        assert_eq!(config.admission_divisor(), 1);
        assert_eq!(config.effective_max_calls(), config.general.max_calls);
        assert_eq!(
            config.effective_max_registrations(),
            config.general.max_registrations
        );
        let mut c = divided(1);
        c.cluster.as_mut().unwrap().admission.split = AdmissionSplit::PerNode;
        validate_config(&c).unwrap();
        assert_eq!(c.admission_divisor(), 1);
    }

    #[test]
    fn divide_splits_caps_but_not_emergency_reserve() {
        let mut config = divided(3);
        config.general.max_calls = 1000;
        config.general.max_registrations = 3000;
        validate_config(&config).unwrap();
        assert_eq!(config.effective_max_calls(), 333);
        assert_eq!(config.effective_max_registrations(), 1000);
        // 47 CFR 9.16: the reserve stays per node, sized from the configured cap.
        assert_eq!(config.general.effective_emergency_reserve_calls(), 100);
    }

    #[test]
    fn divide_rejects_bad_values() {
        rejected(&divided(0), "expected_nodes must be 1-64");
        rejected(&divided(65), "expected_nodes must be 1-64");
        let mut c = divided(3);
        c.general.max_calls = 2;
        rejected(&c, "general.max_calls");
        let mut c = divided(3);
        c.general.max_registrations = 2;
        rejected(&c, "general.max_registrations");
        let mut c = divided(3);
        c.trunk_groups.push(TrunkGroupConfig {
            id: "g".to_string(),
            require_tls: false,
            name: "g".to_string(),
            strategy: "priority".to_string(),
            trunks: vec![TrunkConfigSchema {
                id: "t1".to_string(),
                host: "sip.example.com".to_string(),
                max_calls: 2,
                ..Default::default()
            }],
            zone: None,
        });
        rejected(&c, "trunk 't1' max_calls");
        let mut c = divided(3);
        c.cluster.as_mut().unwrap().enabled = false;
        rejected(&c, "requires cluster.enabled");
        let mut c = divided(3);
        c.cluster.as_mut().unwrap().admission.split = AdmissionSplit::PerNode;
        rejected(&c, "only used with split");
    }

    #[test]
    fn toml_round_trip() {
        let parsed = crate::load_from_str(
            "[cluster]\nenabled = true\n[cluster.admission]\nsplit = \"divide\"\nexpected_nodes = 4\n",
        )
        .unwrap();
        assert_eq!(parsed.admission_divisor(), 4);
        assert_eq!(parsed.effective_max_calls(), 2500);
    }

    #[test]
    fn qa_share_boundaries() {
        // N = 1 identity, exact and uneven division, cap == N gives 1.
        for cap in [0, 1, 7, 1000, u32::MAX] {
            assert_eq!(cluster_share(cap, 1), cap);
        }
        assert_eq!(cluster_share(1000, 4), 250);
        assert_eq!(cluster_share(1001, 4), 250);
        assert_eq!(cluster_share(1003, 4), 250);
        assert_eq!(cluster_share(64, 64), 1);
        assert_eq!(cluster_share(127, 64), 1);
        assert_eq!(cluster_share(128, 64), 2);
        // Floor never exceeds the cluster total.
        for n in 1..=64u32 {
            for cap in [n, n + 1, 2 * n - 1, 999, 50_000] {
                let s = cluster_share(cap, n);
                assert!(s >= 1 && u64::from(s) * u64::from(n) <= u64::from(cap.max(n)));
            }
        }
    }

    #[test]
    fn misspelled_admission_key_rejected() {
        // NIST 800-53 Rev5: CM-6 — NIST-001.
        let err = crate::load_from_str(
            "[cluster]\nenabled = true\n[cluster.admission]\nsplit = \"divide\"\nexpected_node = 3\n",
        );
        assert!(err.is_err());
    }

    #[test]
    fn qa_divide_one_node_is_identity_and_accepted() {
        let config = divided(1);
        validate_config(&config).unwrap();
        assert_eq!(config.admission_divisor(), 1);
        assert_eq!(config.effective_max_calls(), config.general.max_calls);
        assert_eq!(
            config.effective_max_registrations(),
            config.general.max_registrations
        );
    }

    #[test]
    fn qa_divide_cap_equal_to_n_accepted_below_rejected() {
        let mut c = divided(64);
        c.general.max_calls = 64;
        c.general.max_registrations = 64;
        validate_config(&c).unwrap();
        assert_eq!(c.effective_max_calls(), 1);
        assert_eq!(c.effective_max_registrations(), 1);
        c.general.max_calls = 63;
        rejected(&c, "general.max_calls (63)");
        let mut c = divided(4);
        c.general.max_registrations = 3;
        rejected(&c, "general.max_registrations (3)");
    }

    #[test]
    fn qa_divide_trunk_cap_equal_to_n_accepted() {
        let mut c = divided(3);
        c.trunk_groups.push(TrunkGroupConfig {
            id: "g".to_string(),
            require_tls: false,
            name: "g".to_string(),
            strategy: "priority".to_string(),
            trunks: vec![
                TrunkConfigSchema {
                    id: "ok".to_string(),
                    host: "sip.example.com".to_string(),
                    max_calls: 3,
                    ..Default::default()
                },
                TrunkConfigSchema {
                    id: "small".to_string(),
                    host: "sip2.example.com".to_string(),
                    max_calls: 2,
                    ..Default::default()
                },
            ],
            zone: None,
        });
        rejected(&c, "trunk 'small' max_calls");
        c.trunk_groups[0].trunks.pop();
        validate_config(&c).unwrap();
    }

    #[test]
    fn qa_per_node_caps_below_n_irrelevant() {
        // per_node with expected_nodes = 1 does not apply the cap >= N rule.
        let mut c = divided(1);
        c.cluster.as_mut().unwrap().admission.split = AdmissionSplit::PerNode;
        c.general.max_calls = 1;
        c.general.max_registrations = 1;
        validate_config(&c).unwrap();
        // per_node under a disabled cluster is fine too.
        c.cluster.as_mut().unwrap().enabled = false;
        validate_config(&c).unwrap();
    }

    #[test]
    fn qa_toml_backward_compat_and_rejections() {
        // Existing [cluster] without an admission table: per_node, divisor 1.
        let parsed = crate::load_from_str("[cluster]\nenabled = true\n").unwrap();
        let adm = &parsed.cluster.as_ref().unwrap().admission;
        assert_eq!(adm.split, AdmissionSplit::PerNode);
        assert_eq!(adm.expected_nodes, 1);
        assert_eq!(parsed.admission_divisor(), 1);
        assert_eq!(parsed.effective_max_calls(), parsed.general.max_calls);
        // No [cluster] at all.
        let parsed = crate::load_from_str("").unwrap();
        assert_eq!(parsed.admission_divisor(), 1);
        // Explicit per_node.
        let parsed = crate::load_from_str(
            "[cluster]\nenabled = true\n[cluster.admission]\nsplit = \"per_node\"\n",
        )
        .unwrap();
        assert_eq!(parsed.admission_divisor(), 1);
        // Rejections through the loader.
        for bad in [
            "[cluster]\nenabled = true\n[cluster.admission]\nsplit = \"bogus\"\n",
            "[cluster]\nenabled = true\n[cluster.admission]\nsplit = \"divide\"\nexpected_nodes = 0\n",
            "[cluster]\nenabled = true\n[cluster.admission]\nsplit = \"divide\"\nexpected_nodes = 65\n",
            "[cluster]\nenabled = true\n[cluster.admission]\nexpected_nodes = 3\n",
            "[cluster]\nenabled = false\n[cluster.admission]\nsplit = \"divide\"\nexpected_nodes = 2\n",
            "[cluster]\nenabled = true\n[cluster.admission]\nsplit = \"divide\"\nexpected_nodes = -1\n",
            "[general]\nmax_registrations = 3\n[cluster]\nenabled = true\n[cluster.admission]\nsplit = \"divide\"\nexpected_nodes = 4\n",
        ] {
            assert!(crate::load_from_str(bad).is_err(), "accepted: {bad}");
        }
    }
}
