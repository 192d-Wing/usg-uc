//! Attestation policy (RFC 8588 §4, ATIS-1000074 §5.2.3).
//!
//! Decided from configuration, never from request content alone:
//!
//! 1. explicit rules, first match wins;
//! 2. authenticated caller presenting an owned number that is provisioned
//!    for its own registration (`tn_assigned`): **A**;
//! 3. any other authenticated caller: **B**;
//! 4. otherwise the configured default (**C** unless changed).
//!
//! ## NIST 800-53 Rev5: IA-9 (Service Identification and Authentication)

use proto_stir_shaken::{Attestation, TelephoneNumber};

/// One rule; every `Some` field must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestRule {
    /// Ingress trunk group.
    pub source_trunk: Option<String>,
    /// Ingress zone.
    pub source_realm: Option<String>,
    /// Caller authenticated.
    pub authenticated: Option<bool>,
    /// Calling-number prefix (digits).
    pub orig_prefix: Option<String>,
    /// Result.
    pub attest: Attestation,
}

/// Inputs to a decision.
#[derive(Debug, Clone, Copy)]
pub struct AttestCtx<'a> {
    /// Ingress trunk group (None for registered endpoints).
    pub source_trunk: Option<&'a str>,
    /// Ingress zone.
    pub source_realm: Option<&'a str>,
    /// The caller is an authenticated registered endpoint.
    pub authenticated: bool,
    /// `orig` is the number provisioned for the caller's own registration
    /// (AOR), not merely a number the SBC operator owns.
    pub tn_assigned: bool,
    /// Canonical calling number that will be signed.
    pub orig: &'a TelephoneNumber,
}

/// The policy.
#[derive(Debug, Clone)]
pub struct AttestationPolicy {
    default: Attestation,
    /// Owned-number prefixes (digits; a trailing `*` in config is stripped,
    /// an entry without `*` must match exactly).
    owned: Vec<(String, bool)>,
    rules: Vec<AttestRule>,
}

impl AttestationPolicy {
    /// Builds a policy. `owned_numbers` entries are digits with an optional
    /// leading `+` and trailing `*` (prefix match).
    #[must_use]
    pub fn new(default: Attestation, owned_numbers: &[String], rules: Vec<AttestRule>) -> Self {
        let owned = owned_numbers
            .iter()
            .map(|n| {
                let n = n.strip_prefix('+').unwrap_or(n);
                n.strip_suffix('*')
                    .map_or_else(|| (n.to_owned(), false), |p| (p.to_owned(), true))
            })
            .collect();
        Self {
            default,
            owned,
            rules,
        }
    }

    fn owns(&self, tn: &str) -> bool {
        self.owned.iter().any(|(p, prefix)| {
            if *prefix {
                tn.starts_with(p.as_str())
            } else {
                tn == p
            }
        })
    }

    /// Decides the attestation level.
    #[must_use]
    pub fn decide(&self, ctx: &AttestCtx<'_>) -> Attestation {
        let tn = ctx.orig.as_str();
        for r in &self.rules {
            let m = r
                .source_trunk
                .as_deref()
                .is_none_or(|t| ctx.source_trunk == Some(t))
                && r.source_realm
                    .as_deref()
                    .is_none_or(|z| ctx.source_realm == Some(z))
                && r.authenticated.is_none_or(|a| a == ctx.authenticated)
                && r.orig_prefix.as_deref().is_none_or(|p| tn.starts_with(p));
            if m {
                return r.attest;
            }
        }
        if ctx.authenticated {
            return if ctx.tn_assigned && self.owns(tn) {
                Attestation::Full
            } else {
                Attestation::Partial
            };
        }
        self.default
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto_stir_shaken::canonicalize_tn;

    #[test]
    fn matrix() {
        let p = AttestationPolicy::new(
            Attestation::Gateway,
            &["+1202555*".to_string(), "13015550100".to_string()],
            vec![AttestRule {
                source_trunk: Some("pbx".into()),
                orig_prefix: Some("1703".into()),
                attest: Attestation::Partial,
                source_realm: None,
                authenticated: None,
            }],
        );
        let tn = |s: &str| canonicalize_tn(s).unwrap();
        let d = |trunk: Option<&str>, auth: bool, n: &str| {
            p.decide(&AttestCtx {
                source_trunk: trunk,
                source_realm: None,
                authenticated: auth,
                tn_assigned: true,
                orig: &tn(n),
            })
        };
        assert_eq!(d(None, true, "12025550100"), Attestation::Full);
        assert_eq!(d(None, true, "13015550100"), Attestation::Full);
        assert_eq!(d(None, true, "13015550101"), Attestation::Partial);
        assert_eq!(d(None, false, "12025550100"), Attestation::Gateway);
        assert_eq!(d(Some("pbx"), false, "17035550100"), Attestation::Partial);
        assert_eq!(
            d(Some("carrier"), false, "17035550100"),
            Attestation::Gateway
        );
        // SEC-001: an owned number not provisioned for the caller's own
        // registration is never A.
        let unassigned = p.decide(&AttestCtx {
            source_trunk: None,
            source_realm: None,
            authenticated: true,
            tn_assigned: false,
            orig: &tn("12025550100"),
        });
        assert_eq!(unassigned, Attestation::Partial);
    }
}
