//! STIR/SHAKEN error types.
//!
//! ## NIST 800-53 Rev5: SI-11 (Error Handling)
//!
//! Errors carry fixed reason text; attacker-supplied bytes are never echoed.

use std::fmt;

/// STIR/SHAKEN result type.
pub type StirShakenResult<T> = Result<T, StirShakenError>;

/// STIR/SHAKEN errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StirShakenError {
    /// The Identity header or PASSporT is syntactically invalid.
    Malformed {
        /// Fixed reason.
        reason: &'static str,
    },
    /// The `info` parameter is missing or not an acceptable URI.
    BadInfo {
        /// Fixed reason.
        reason: &'static str,
    },
    /// Algorithm not supported for this `ppt`.
    UnsupportedAlgorithm,
    /// A required claim is missing or invalid.
    InvalidClaim {
        /// Claim name.
        claim: &'static str,
    },
    /// Invalid telephone number.
    InvalidPhoneNumber,
    /// Signing failed (key unusable).
    SigningFailed,
}

impl fmt::Display for StirShakenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { reason } => write!(f, "malformed identity: {reason}"),
            Self::BadInfo { reason } => write!(f, "bad identity info: {reason}"),
            Self::UnsupportedAlgorithm => {
                write!(f, "unsupported algorithm (ES256 required for ppt=shaken)")
            }
            Self::InvalidClaim { claim } => write!(f, "invalid claim '{claim}'"),
            Self::InvalidPhoneNumber => write!(f, "invalid telephone number"),
            Self::SigningFailed => write!(f, "signing failed"),
        }
    }
}

impl std::error::Error for StirShakenError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_fixed_text() {
        let e = StirShakenError::InvalidClaim { claim: "iat" };
        assert_eq!(e.to_string(), "invalid claim 'iat'");
        assert!(
            StirShakenError::UnsupportedAlgorithm
                .to_string()
                .contains("ES256")
        );
    }
}
