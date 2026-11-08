//! Trunk-group transport policy checks on JSONB trunk-group bodies.
//!
//! Shared by the REST API servers (request validation) and the daemon's
//! `TrunkSync` path (parsing) so both read `require_tls` and the trunk
//! `protocol`/`transport` field the same way.
//!
//! ## NIST 800-53 Rev5: SC-8 (POA&M-48), CM-6, SI-10 (Information Input Validation)

use serde_json::Value;

/// Warning returned when a `require_tls` group has no trunk yet.
pub const WARN_REQUIRE_TLS_EMPTY: &str =
    "require_tls group has no TLS trunk; calls will be rejected";

/// Transport of a trunk in a JSONB trunk-group body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrunkTransport {
    /// `udp` (also the default when the field is absent).
    Udp,
    /// `tcp`.
    Tcp,
    /// `tls`.
    Tls,
}

/// Why a trunk-group body is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrunkPolicyError {
    /// Malformed field (HTTP 400).
    Invalid(String),
    /// Well-formed but violates the `require_tls` policy (HTTP 422).
    Policy(String),
}

impl std::fmt::Display for TrunkPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(m) | Self::Policy(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for TrunkPolicyError {}

/// Reads a trunk's transport from `protocol`, else `transport`.
///
/// `transport` is the dashboard field. Absent means UDP (rows written before this field was
/// honoured). Accepted values, ASCII case-insensitive and untrimmed:
/// `udp`, `tcp`, `tls`.
///
/// # Errors
/// A non-string or unknown value. Callers must never map it to UDP.
pub fn trunk_transport(trunk: &Value) -> Result<TrunkTransport, String> {
    let field = trunk
        .get("protocol")
        .filter(|v| !v.is_null())
        .or_else(|| trunk.get("transport").filter(|v| !v.is_null()));
    let Some(v) = field else {
        return Ok(TrunkTransport::Udp);
    };
    let Some(s) = v.as_str() else {
        return Err("trunk protocol/transport must be a string".to_string());
    };
    if s.eq_ignore_ascii_case("udp") {
        Ok(TrunkTransport::Udp)
    } else if s.eq_ignore_ascii_case("tcp") {
        Ok(TrunkTransport::Tcp)
    } else if s.eq_ignore_ascii_case("tls") {
        Ok(TrunkTransport::Tls)
    } else {
        Err("trunk protocol/transport must be one of udp, tcp, tls".to_string())
    }
}

impl TrunkTransport {
    /// Default port when the trunk body has none (RFC 3261 §19.1.2:
    /// 5061 for TLS, 5060 otherwise).
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Tls => 5061,
            Self::Udp | Self::Tcp => 5060,
        }
    }
}

/// Reads a trunk's `port`. Absent or `null` means the transport's default
/// port ([`TrunkTransport::default_port`]).
///
/// # Errors
/// A non-integer value or one outside `1..=65535`. Callers skip the trunk;
/// a port is never truncated.
pub fn trunk_port(trunk: &Value, transport: TrunkTransport) -> Result<u16, String> {
    match trunk.get("port") {
        None | Some(Value::Null) => Ok(transport.default_port()),
        Some(v) => v
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .ok_or_else(|| "trunk port must be an integer in 1..=65535".to_string()),
    }
}

/// Reads the group `require_tls` flag. Absent or `null` means `false`.
///
/// # Errors
/// Any non-bool value. The daemon treats that as `true` (fail closed).
pub fn group_require_tls(group: &Value) -> Result<bool, String> {
    match group.get("require_tls") {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err("require_tls must be a boolean".to_string()),
    }
}

/// Reads a trunk's `allow_md5_digest` UAC digest policy (POA&M-255).
///
/// Absent or `null` means unset (`None`): MD5 is answered only when the
/// REGISTER transport is TLS (`proto_sip::resolve_allow_md5`).
///
/// # Errors
/// Any non-bool value (a string `"true"` is refused, never coerced). Callers
/// that cannot reject the body treat it as `Some(false)` (fail closed).
///
/// ## NIST 800-53 Rev5: IA-5(1), SC-13, CM-6, SI-10
pub fn trunk_allow_md5_digest(trunk: &Value) -> Result<Option<bool>, String> {
    match trunk.get("allow_md5_digest") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err("trunk allow_md5_digest must be a boolean".to_string()),
    }
}

/// [`trunk_allow_md5_digest`] for consumers of already-stored bodies: an
/// invalid value refuses MD5 (`Some(false)`, fail closed) and is returned as
/// the second element so the caller can log it.
#[must_use]
pub fn trunk_allow_md5_digest_or_refuse(trunk: &Value) -> (Option<bool>, Option<String>) {
    match trunk_allow_md5_digest(trunk) {
        Ok(policy) => (policy, None),
        Err(e) => (Some(false), Some(e)),
    }
}

/// Validates the transport policy of a trunk-group body as it would be
/// stored. Returns warnings to pass back to the client.
///
/// - `require_tls` not a bool, a trunk protocol outside {udp,tcp,tls}, a
///   trunk port outside `1..=65535`, or a non-bool trunk `allow_md5_digest`:
///   [`TrunkPolicyError::Invalid`].
/// - `require_tls` with at least one trunk and none TLS:
///   [`TrunkPolicyError::Policy`].
/// - `require_tls` with no trunks: accepted with [`WARN_REQUIRE_TLS_EMPTY`]
///   (groups are created first and trunks added after).
///
/// # Errors
/// As above.
pub fn validate_trunk_group_json(group: &Value) -> Result<Vec<String>, TrunkPolicyError> {
    let require_tls = group_require_tls(group).map_err(TrunkPolicyError::Invalid)?;
    let trunks: &[Value] = match group.get("trunks") {
        None | Some(Value::Null) => &[],
        Some(Value::Array(a)) => a,
        Some(_) => {
            return Err(TrunkPolicyError::Invalid(
                "trunks must be an array".to_string(),
            ));
        }
    };
    let mut any_tls = false;
    for t in trunks {
        let transport = trunk_transport(t).map_err(TrunkPolicyError::Invalid)?;
        trunk_port(t, transport).map_err(TrunkPolicyError::Invalid)?;
        trunk_allow_md5_digest(t).map_err(TrunkPolicyError::Invalid)?;
        any_tls |= transport == TrunkTransport::Tls;
    }
    if !require_tls {
        return Ok(Vec::new());
    }
    if trunks.is_empty() {
        return Ok(vec![WARN_REQUIRE_TLS_EMPTY.to_string()]);
    }
    if !any_tls {
        return Err(TrunkPolicyError::Policy(
            "require_tls group must contain at least one trunk with protocol \"tls\"".to_string(),
        ));
    }
    Ok(Vec::new())
}

/// Transport-policy change between two versions of a trunk group, for the
/// config-change audit record.
///
/// `None` input = absent (created or deleted). Returns `None` when neither
/// `require_tls` nor any trunk's transport changed.
///
/// Format: `require_tls=<old>-><new> trunk_protocols=[id:old->new, ...]`,
/// with `-` for an absent trunk and `invalid` for an unparsable protocol.
/// Trunk ids are admin-supplied; they are escaped (`escape_default`) so the
/// record cannot be split.
///
/// ## NIST 800-53 Rev5: AU-3 (Content of Audit Records), CM-3, SC-8
#[must_use]
pub fn transport_policy_diff(old: Option<&Value>, new: Option<&Value>) -> Option<String> {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;

    let flag = |g: Option<&Value>| g.is_some_and(|g| group_require_tls(g).unwrap_or(true));
    let protocols = |g: Option<&Value>| -> BTreeMap<String, &'static str> {
        g.and_then(|g| g.get("trunks"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|t| {
                        let id = t.get("id").and_then(Value::as_str).unwrap_or_default();
                        let p = match trunk_transport(t) {
                            Ok(TrunkTransport::Udp) => "udp",
                            Ok(TrunkTransport::Tcp) => "tcp",
                            Ok(TrunkTransport::Tls) => "tls",
                            Err(_) => "invalid",
                        };
                        (id.escape_default().to_string(), p)
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let (old_flag, new_flag) = (flag(old), flag(new));
    let (old_p, new_p) = (protocols(old), protocols(new));
    let mut changed = String::new();
    for id in old_p
        .keys()
        .chain(new_p.keys().filter(|k| !old_p.contains_key(*k)))
    {
        let (a, b) = (
            old_p.get(id).copied().unwrap_or("-"),
            new_p.get(id).copied().unwrap_or("-"),
        );
        if a != b {
            if !changed.is_empty() {
                changed.push_str(", ");
            }
            let _ = write!(changed, "{id}:{a}->{b}");
        }
    }
    if old_flag == new_flag && changed.is_empty() {
        return None;
    }
    Some(format!(
        "require_tls={old_flag}->{new_flag} trunk_protocols=[{changed}]"
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn transport_parsing() {
        assert_eq!(trunk_transport(&json!({})), Ok(TrunkTransport::Udp));
        assert_eq!(
            trunk_transport(&json!({"transport": "TLS"})),
            Ok(TrunkTransport::Tls)
        );
        assert_eq!(
            trunk_transport(&json!({"protocol": "tcp", "transport": "tls"})),
            Ok(TrunkTransport::Tcp)
        );
        assert!(trunk_transport(&json!({"protocol": "TLS "})).is_err());
        assert!(trunk_transport(&json!({"protocol": "sctp"})).is_err());
        assert!(trunk_transport(&json!({"protocol": 1})).is_err());
    }

    #[test]
    fn policy_diff() {
        let g = json!({"require_tls": false, "trunks": [{"id": "a", "protocol": "udp"}]});
        assert_eq!(transport_policy_diff(Some(&g), Some(&g)), None);
        let g2 = json!({"require_tls": true, "trunks": [
            {"id": "a", "protocol": "tls"}, {"id": "b\n", "protocol": "tcp"}]});
        assert_eq!(
            transport_policy_diff(Some(&g), Some(&g2)).unwrap(),
            "require_tls=false->true trunk_protocols=[a:udp->tls, b\\n:-->tcp]"
        );
        assert_eq!(
            transport_policy_diff(Some(&g2), None).unwrap(),
            "require_tls=true->false trunk_protocols=[a:tls->-, b\\n:tcp->-]"
        );
        // Unrelated edits (host, name) are not reported.
        let g3 = json!({"require_tls": false, "name": "x",
            "trunks": [{"id": "a", "protocol": "udp", "host": "h"}]});
        assert_eq!(transport_policy_diff(Some(&g), Some(&g3)), None);
    }

    #[test]
    fn port_parsing() {
        assert_eq!(trunk_port(&json!({}), TrunkTransport::Tls), Ok(5061));
        assert_eq!(trunk_port(&json!({}), TrunkTransport::Udp), Ok(5060));
        assert_eq!(
            trunk_port(&json!({"port": null}), TrunkTransport::Tcp),
            Ok(5060)
        );
        assert_eq!(
            trunk_port(&json!({"port": 5080}), TrunkTransport::Tls),
            Ok(5080)
        );
        for bad in [json!(70000), json!(0), json!(-1), json!("5060"), json!(1.5)] {
            assert!(
                trunk_port(&json!({ "port": bad }), TrunkTransport::Udp).is_err(),
                "{bad}"
            );
        }
        assert!(matches!(
            validate_trunk_group_json(&json!({"trunks": [{"port": 65536}]})),
            Err(TrunkPolicyError::Invalid(_))
        ));
    }

    #[test]
    fn require_tls_parsing() {
        assert_eq!(group_require_tls(&json!({})), Ok(false));
        assert_eq!(group_require_tls(&json!({"require_tls": true})), Ok(true));
        assert!(group_require_tls(&json!({"require_tls": "true"})).is_err());
    }

    #[test]
    fn group_validation() {
        let udp = json!({"id": "a", "transport": "udp"});
        let tls = json!({"id": "b", "transport": "tls"});
        let none: Vec<String> = Vec::new();
        assert_eq!(
            validate_trunk_group_json(&json!({"trunks": [udp]})).unwrap(),
            none
        );
        assert!(matches!(
            validate_trunk_group_json(&json!({"require_tls": true, "trunks": [udp]})),
            Err(TrunkPolicyError::Policy(_))
        ));
        assert_eq!(
            validate_trunk_group_json(&json!({"require_tls": true, "trunks": [udp, tls]})).unwrap(),
            none
        );
        assert_eq!(
            validate_trunk_group_json(&json!({"require_tls": true})).unwrap(),
            vec![WARN_REQUIRE_TLS_EMPTY.to_string()]
        );
        assert!(matches!(
            validate_trunk_group_json(&json!({"require_tls": 1})),
            Err(TrunkPolicyError::Invalid(_))
        ));
        assert!(matches!(
            validate_trunk_group_json(&json!({"trunks": [{"protocol": "x"}]})),
            Err(TrunkPolicyError::Invalid(_))
        ));
    }

    #[test]
    fn allow_md5_digest_parsing() {
        assert_eq!(trunk_allow_md5_digest(&json!({})), Ok(None));
        assert_eq!(
            trunk_allow_md5_digest(&json!({"allow_md5_digest": null})),
            Ok(None)
        );
        assert_eq!(
            trunk_allow_md5_digest(&json!({"allow_md5_digest": true})),
            Ok(Some(true))
        );
        assert_eq!(
            trunk_allow_md5_digest(&json!({"allow_md5_digest": false})),
            Ok(Some(false))
        );
        for bad in [json!("true"), json!(1), json!("yes")] {
            let t = json!({ "allow_md5_digest": bad });
            assert!(trunk_allow_md5_digest(&t).is_err(), "{bad}");
            assert!(matches!(
                validate_trunk_group_json(&json!({ "trunks": [t.clone()] })),
                Err(TrunkPolicyError::Invalid(_))
            ));
            let (policy, err) = trunk_allow_md5_digest_or_refuse(&t);
            assert_eq!(policy, Some(false));
            assert!(err.is_some());
        }
        // Explicit opt-in on a cleartext trunk is accepted without a warning
        // (warnings are 422 on central-config-api); the daemon logs it.
        assert_eq!(
            validate_trunk_group_json(
                &json!({"trunks": [{"transport": "udp", "allow_md5_digest": true}]})
            )
            .unwrap(),
            Vec::<String>::new()
        );
    }
}
