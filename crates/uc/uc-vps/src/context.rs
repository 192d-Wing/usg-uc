//! Call-attempt context handed to the VPS engine.
//!
//! Deliberately transport-agnostic: the engine sees normalized call
//! attributes, not SIP messages, so the same engine can later run in a
//! standalone inline-proxy deployment.

use std::net::IpAddr;

/// Direction of a call attempt relative to the SBC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CallDirection {
    /// Originated by an upstream trunk (carrier side).
    Inbound,
    /// Originated by a registered local user toward a trunk.
    Outbound,
    /// Between two local users.
    Internal,
    /// Direction could not be determined.
    #[default]
    Unknown,
}

/// STIR/SHAKEN verification outcome for the attempt (RFC 8224/8588).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StirShakenStatus {
    /// No Identity header was present.
    #[default]
    NotPresent,
    /// Verified with full (A) attestation.
    VerifiedA,
    /// Verified with partial (B) attestation.
    VerifiedB,
    /// Verified with gateway (C) attestation.
    VerifiedC,
    /// An Identity header was present but verification failed.
    Failed,
}

impl StirShakenStatus {
    /// Returns the verified attestation level, if any.
    pub fn attestation(&self) -> Option<crate::config::AttestationLevel> {
        match self {
            Self::VerifiedA => Some(crate::config::AttestationLevel::A),
            Self::VerifiedB => Some(crate::config::AttestationLevel::B),
            Self::VerifiedC => Some(crate::config::AttestationLevel::C),
            Self::NotPresent | Self::Failed => None,
        }
    }
}

/// A normalized call attempt for screening.
#[derive(Debug, Clone, Default)]
pub struct CallAttempt {
    /// Source IP the attempt arrived from.
    pub source_ip: Option<IpAddr>,
    /// Caller number / From user part.
    pub caller: Option<String>,
    /// Callee number / Request-URI user part.
    pub callee: Option<String>,
    /// Full From URI.
    pub from_uri: Option<String>,
    /// Full To URI.
    pub to_uri: Option<String>,
    /// Full Request-URI.
    pub request_uri: Option<String>,
    /// Call direction.
    pub direction: CallDirection,
    /// STIR/SHAKEN verification outcome.
    pub stir_shaken: StirShakenStatus,
}

impl CallAttempt {
    /// Creates a new attempt from a source IP.
    pub fn new(source_ip: IpAddr) -> Self {
        Self {
            source_ip: Some(source_ip),
            ..Self::default()
        }
    }

    /// Sets the caller number.
    #[must_use]
    pub fn with_caller(mut self, caller: impl Into<String>) -> Self {
        self.caller = Some(caller.into());
        self
    }

    /// Sets the callee number.
    #[must_use]
    pub fn with_callee(mut self, callee: impl Into<String>) -> Self {
        self.callee = Some(callee.into());
        self
    }

    /// Sets the From URI (and derives the caller number if unset).
    #[must_use]
    pub fn with_from_uri(mut self, uri: impl Into<String>) -> Self {
        let uri = uri.into();
        if self.caller.is_none() {
            self.caller = uri_user(&uri).map(ToString::to_string);
        }
        self.from_uri = Some(uri);
        self
    }

    /// Sets the To URI.
    #[must_use]
    pub fn with_to_uri(mut self, uri: impl Into<String>) -> Self {
        self.to_uri = Some(uri.into());
        self
    }

    /// Sets the Request-URI.
    #[must_use]
    pub fn with_request_uri(mut self, uri: impl Into<String>) -> Self {
        self.request_uri = Some(uri.into());
        self
    }

    /// Sets the call direction.
    #[must_use]
    pub fn with_direction(mut self, direction: CallDirection) -> Self {
        self.direction = direction;
        self
    }

    /// Sets the STIR/SHAKEN status.
    #[must_use]
    pub fn with_stir_shaken(mut self, status: StirShakenStatus) -> Self {
        self.stir_shaken = status;
        self
    }
}

/// Strips a leading `scheme:` from `uri`, comparing the scheme ASCII
/// case-insensitively (RFC 3261 §19.1.4: `SIP:` and `sip:` are the same
/// scheme). Returns the remainder and whether the scheme was `tel`.
fn strip_scheme(uri: &str) -> (&str, bool) {
    for (scheme, is_tel) in [("sips:", false), ("sip:", false), ("tel:", true)] {
        if let Some(head) = uri.get(..scheme.len())
            && head.eq_ignore_ascii_case(scheme)
        {
            return (&uri[scheme.len()..], is_tel);
        }
    }
    (uri, false)
}

/// Extracts the user part from a SIP URI string
/// (`"sip:alice@example.com"` → `"alice"`). Returns `None` if there is no
/// user part.
///
/// The scheme is matched case-insensitively, so `SIP:` and `Tel:` callers are screened like their lower-case forms (POA&M-531).
///
/// ## NIST 800-53 Rev5: SI-10 (Information Input Validation), AC-3
pub fn uri_user(uri: &str) -> Option<&str> {
    let uri = uri.trim();
    let (rest, is_tel) = strip_scheme(uri);
    let user = rest.split('@').next()?;
    // Strip URI parameters from a tel: or user-only form.
    let user = user.split(';').next().unwrap_or(user);
    if user.is_empty() || (!rest.contains('@') && !is_tel) {
        return None;
    }
    Some(user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_uri_user() {
        assert_eq!(uri_user("sip:alice@example.com"), Some("alice"));
        assert_eq!(
            uri_user("sips:+15551234567@host:5061"),
            Some("+15551234567")
        );
        assert_eq!(uri_user("tel:+15551234567"), Some("+15551234567"));
        assert_eq!(uri_user("sip:example.com"), None);
        assert_eq!(uri_user("sip:bob;p=x@host"), Some("bob"));
        // POA&M-531: schemes are case-insensitive (RFC 3261 §19.1.4).
        assert_eq!(uri_user("SIP:+19005551234@host"), Some("+19005551234"));
        assert_eq!(uri_user("SipS:alice@host"), Some("alice"));
        assert_eq!(uri_user("TEL:+15551234567;x=y"), Some("+15551234567"));
        assert_eq!(uri_user(" sip:alice@host"), Some("alice"));
        assert_eq!(uri_user("SIP:example.com"), None);
        // Multi-byte input near the scheme boundary must not panic.
        assert_eq!(uri_user("s\u{e9}:x"), None);
    }

    #[test]
    fn test_attempt_builder_derives_caller() {
        let attempt = CallAttempt::new(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .with_from_uri("sip:+12135551000@trunk.example.com")
            .with_callee("911");
        assert_eq!(attempt.caller.as_deref(), Some("+12135551000"));
        assert_eq!(attempt.callee.as_deref(), Some("911"));
    }

    #[test]
    fn test_stir_shaken_attestation() {
        use crate::config::AttestationLevel;
        assert_eq!(
            StirShakenStatus::VerifiedA.attestation(),
            Some(AttestationLevel::A)
        );
        assert_eq!(StirShakenStatus::Failed.attestation(), None);
        assert_eq!(StirShakenStatus::NotPresent.attestation(), None);
    }
}
