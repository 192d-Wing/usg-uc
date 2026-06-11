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

/// Extracts the user part from a SIP URI string
/// (`"sip:alice@example.com"` → `"alice"`). Returns `None` if there is no
/// user part.
pub fn uri_user(uri: &str) -> Option<&str> {
    let rest = uri
        .strip_prefix("sips:")
        .or_else(|| uri.strip_prefix("sip:"))
        .or_else(|| uri.strip_prefix("tel:"))
        .unwrap_or(uri);
    let user = rest.split('@').next()?;
    // Strip URI parameters from a tel: or user-only form.
    let user = user.split(';').next().unwrap_or(user);
    if user.is_empty() || (!rest.contains('@') && !uri.starts_with("tel:")) {
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
        assert_eq!(uri_user("sips:+15551234567@host:5061"), Some("+15551234567"));
        assert_eq!(uri_user("tel:+15551234567"), Some("+15551234567"));
        assert_eq!(uri_user("sip:example.com"), None);
        assert_eq!(uri_user("sip:bob;p=x@host"), Some("bob"));
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
