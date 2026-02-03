//! STIR/SHAKEN attestation levels.
//!
//! ## RFC 8588 - `PASSporT` Extension for Signature-based Handling of Asserted information
//!
//! Defines the attestation levels used in STIR/SHAKEN caller ID authentication.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// STIR/SHAKEN attestation level per RFC 8588.
///
/// Indicates the service provider's level of knowledge about the calling party.
///
/// ## NIST 800-53 Rev5: IA-9 (Service Identification and Authentication)
///
/// Attestation levels are part of the authenticated caller identity framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AttestationLevel {
    /// Full Attestation (Level A).
    ///
    /// The service provider:
    /// - Has authenticated the calling party
    /// - Verified they are authorized to use the calling number
    /// - The call originates from their network
    ///
    /// This is the highest level of trust.
    #[cfg_attr(feature = "serde", serde(rename = "A"))]
    Full,

    /// Partial Attestation (Level B).
    ///
    /// The service provider:
    /// - Has authenticated the calling party
    /// - The call originates from their network
    /// - But cannot verify authorization for the specific number
    ///
    /// Common for enterprise PBX scenarios.
    #[cfg_attr(feature = "serde", serde(rename = "B"))]
    Partial,

    /// Gateway Attestation (Level C).
    ///
    /// The service provider:
    /// - Received the call from a trusted source
    /// - But cannot authenticate the originator
    /// - The calling number source is unknown
    ///
    /// Common for calls entering from foreign networks.
    #[cfg_attr(feature = "serde", serde(rename = "C"))]
    Gateway,
}

impl AttestationLevel {
    /// Returns the single-character code per RFC 8588.
    #[must_use]
    pub const fn as_code(&self) -> char {
        match self {
            Self::Full => 'A',
            Self::Partial => 'B',
            Self::Gateway => 'C',
        }
    }

    /// Parses from single-character code.
    ///
    /// Returns `None` for invalid codes.
    #[must_use]
    pub const fn from_code(code: char) -> Option<Self> {
        match code.to_ascii_uppercase() {
            'A' => Some(Self::Full),
            'B' => Some(Self::Partial),
            'C' => Some(Self::Gateway),
            _ => None,
        }
    }

    /// Returns a human-readable description.
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Full => "Full attestation: Caller authenticated and authorized for number",
            Self::Partial => {
                "Partial attestation: Caller authenticated but number authorization unverified"
            }
            Self::Gateway => {
                "Gateway attestation: Call received from trusted source, originator unknown"
            }
        }
    }

    /// Returns true if this is considered high trust (A or B).
    #[must_use]
    pub const fn is_high_trust(&self) -> bool {
        matches!(self, Self::Full | Self::Partial)
    }
}

impl std::fmt::Display for AttestationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_code())
    }
}

impl std::str::FromStr for AttestationLevel {
    type Err = AttestationParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 1 {
            return Err(AttestationParseError::InvalidLength);
        }

        s.chars()
            .next()
            .and_then(Self::from_code)
            .ok_or(AttestationParseError::InvalidCode)
    }
}

/// Error parsing attestation level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationParseError {
    /// Input was not a single character.
    InvalidLength,
    /// Character was not A, B, or C.
    InvalidCode,
}

impl std::fmt::Display for AttestationParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "attestation level must be a single character"),
            Self::InvalidCode => write!(f, "attestation level must be A, B, or C"),
        }
    }
}

impl std::error::Error for AttestationParseError {}

/// STIR/SHAKEN verification result.
///
/// Represents the outcome of verifying an incoming call's Identity header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum VerificationResult {
    /// Verification succeeded with the given attestation level.
    Valid(AttestationLevel),

    /// No Identity header was present.
    NoIdentity,

    /// Identity header present but verification failed.
    Failed(VerificationFailureReason),
}

impl VerificationResult {
    /// Returns true if verification succeeded.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }

    /// Returns the attestation level if verification succeeded.
    #[must_use]
    pub const fn attestation(&self) -> Option<AttestationLevel> {
        match self {
            Self::Valid(level) => Some(*level),
            _ => None,
        }
    }
}

/// Reason for STIR/SHAKEN verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum VerificationFailureReason {
    /// PASSporT signature verification failed.
    SignatureInvalid,

    /// PASSporT has expired (iat too old).
    Expired,

    /// Certificate could not be fetched.
    CertificateFetchFailed,

    /// Certificate chain validation failed.
    CertificateInvalid,

    /// Originating number does not match PASSporT.
    OriginMismatch,

    /// PASSporT format is invalid.
    MalformedPassport,

    /// Unsupported algorithm (non-CNSA 2.0 compliant).
    UnsupportedAlgorithm,
}

impl std::fmt::Display for VerificationFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureInvalid => write!(f, "signature verification failed"),
            Self::Expired => write!(f, "passport expired"),
            Self::CertificateFetchFailed => write!(f, "certificate fetch failed"),
            Self::CertificateInvalid => write!(f, "certificate validation failed"),
            Self::OriginMismatch => write!(f, "originating number mismatch"),
            Self::MalformedPassport => write!(f, "malformed passport"),
            Self::UnsupportedAlgorithm => write!(f, "unsupported algorithm"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_codes() {
        assert_eq!(AttestationLevel::Full.as_code(), 'A');
        assert_eq!(AttestationLevel::Partial.as_code(), 'B');
        assert_eq!(AttestationLevel::Gateway.as_code(), 'C');
    }

    #[test]
    fn test_attestation_from_code() {
        assert_eq!(
            AttestationLevel::from_code('A'),
            Some(AttestationLevel::Full)
        );
        assert_eq!(
            AttestationLevel::from_code('a'),
            Some(AttestationLevel::Full)
        );
        assert_eq!(
            AttestationLevel::from_code('B'),
            Some(AttestationLevel::Partial)
        );
        assert_eq!(
            AttestationLevel::from_code('C'),
            Some(AttestationLevel::Gateway)
        );
        assert_eq!(AttestationLevel::from_code('D'), None);
    }

    #[test]
    fn test_attestation_ordering() {
        // Ord is by enum variant order (A < B < C alphabetically)
        // This is useful for sorting, not trust comparison
        // Use is_high_trust() for trust-based comparisons
        assert!(AttestationLevel::Full < AttestationLevel::Partial);
        assert!(AttestationLevel::Partial < AttestationLevel::Gateway);
    }

    #[test]
    fn test_attestation_parse() {
        assert_eq!(
            "A".parse::<AttestationLevel>().ok(),
            Some(AttestationLevel::Full)
        );
        assert_eq!(
            "B".parse::<AttestationLevel>().ok(),
            Some(AttestationLevel::Partial)
        );
        assert!("AB".parse::<AttestationLevel>().is_err());
        assert!("X".parse::<AttestationLevel>().is_err());
    }

    #[test]
    fn test_verification_result() {
        let valid = VerificationResult::Valid(AttestationLevel::Full);
        assert!(valid.is_valid());
        assert_eq!(valid.attestation(), Some(AttestationLevel::Full));

        let failed = VerificationResult::Failed(VerificationFailureReason::Expired);
        assert!(!failed.is_valid());
        assert_eq!(failed.attestation(), None);
    }
}
