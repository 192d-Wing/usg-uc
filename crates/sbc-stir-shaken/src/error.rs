//! STIR/SHAKEN error types.

use std::fmt;

/// STIR/SHAKEN result type.
pub type StirShakenResult<T> = Result<T, StirShakenError>;

/// STIR/SHAKEN errors.
#[derive(Debug)]
pub enum StirShakenError {
    /// Invalid PASSporT format.
    InvalidPASSporT {
        /// Reason.
        reason: String,
    },
    /// Invalid algorithm.
    InvalidAlgorithm {
        /// Requested algorithm.
        algorithm: String,
    },
    /// Signature verification failed.
    SignatureVerificationFailed {
        /// Reason.
        reason: String,
    },
    /// Certificate error.
    CertificateError {
        /// Reason.
        reason: String,
    },
    /// PASSporT expired.
    Expired {
        /// Age in seconds.
        age_seconds: u64,
        /// Maximum allowed age.
        max_age: u64,
    },
    /// Invalid phone number.
    InvalidPhoneNumber {
        /// Number.
        number: String,
        /// Reason.
        reason: String,
    },
    /// Invalid claim.
    InvalidClaim {
        /// Claim name.
        claim: String,
        /// Reason.
        reason: String,
    },
    /// Missing required field.
    MissingField {
        /// Field name.
        field: String,
    },
    /// Attestation level error.
    AttestationError {
        /// Reason.
        reason: String,
    },
    /// Crypto error.
    CryptoError {
        /// Error message.
        message: String,
    },
    /// Encoding error.
    EncodingError {
        /// Error message.
        message: String,
    },
    /// Network error fetching certificate.
    NetworkError {
        /// URL.
        url: String,
        /// Error message.
        message: String,
    },
}

impl fmt::Display for StirShakenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPASSporT { reason } => {
                write!(f, "Invalid PASSporT: {}", reason)
            }
            Self::InvalidAlgorithm { algorithm } => {
                write!(
                    f,
                    "Invalid algorithm '{}' (only ES384 is supported for CNSA 2.0)",
                    algorithm
                )
            }
            Self::SignatureVerificationFailed { reason } => {
                write!(f, "Signature verification failed: {}", reason)
            }
            Self::CertificateError { reason } => {
                write!(f, "Certificate error: {}", reason)
            }
            Self::Expired { age_seconds, max_age } => {
                write!(
                    f,
                    "PASSporT expired: age {}s exceeds maximum {}s",
                    age_seconds, max_age
                )
            }
            Self::InvalidPhoneNumber { number, reason } => {
                write!(f, "Invalid phone number '{}': {}", number, reason)
            }
            Self::InvalidClaim { claim, reason } => {
                write!(f, "Invalid claim '{}': {}", claim, reason)
            }
            Self::MissingField { field } => {
                write!(f, "Missing required field: {}", field)
            }
            Self::AttestationError { reason } => {
                write!(f, "Attestation error: {}", reason)
            }
            Self::CryptoError { message } => {
                write!(f, "Crypto error: {}", message)
            }
            Self::EncodingError { message } => {
                write!(f, "Encoding error: {}", message)
            }
            Self::NetworkError { url, message } => {
                write!(f, "Network error fetching '{}': {}", url, message)
            }
        }
    }
}

impl std::error::Error for StirShakenError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let error = StirShakenError::InvalidAlgorithm {
            algorithm: "ES256".to_string(),
        };
        assert!(error.to_string().contains("ES256"));
        assert!(error.to_string().contains("CNSA 2.0"));
    }

    #[test]
    fn test_expired_error() {
        let error = StirShakenError::Expired {
            age_seconds: 120,
            max_age: 60,
        };
        assert!(error.to_string().contains("120"));
        assert!(error.to_string().contains("60"));
    }
}
