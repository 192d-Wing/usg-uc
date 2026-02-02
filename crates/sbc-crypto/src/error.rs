//! Cryptographic error types.
//!
//! ## NIST 800-53 Rev5: SI-11 (Error Handling)
//!
//! Error messages are designed to provide sufficient diagnostic information
//! without leaking sensitive cryptographic details that could aid attackers.

use sbc_types::error::CryptoError as TypesCryptoError;
use thiserror::Error;

/// Result type for cryptographic operations.
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Cryptographic operation error.
///
/// These errors intentionally provide limited detail to prevent
/// information leakage that could aid cryptographic attacks.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Key generation failed.
    #[error("key generation failed")]
    KeyGenerationFailed,

    /// AEAD encryption (seal) operation failed.
    #[error("encryption failed")]
    SealFailed,

    /// AEAD decryption (open) operation failed.
    ///
    /// This may indicate tampering or use of wrong key.
    #[error("decryption failed")]
    OpenFailed,

    /// Digital signature generation failed.
    #[error("signing failed")]
    SigningFailed,

    /// Digital signature verification failed.
    #[error("verification failed")]
    VerificationFailed,

    /// Key derivation failed.
    #[error("key derivation failed")]
    KeyDerivationFailed,

    /// Invalid key material provided.
    #[error("invalid key material")]
    InvalidKeyMaterial,

    /// Invalid nonce length.
    #[error("invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected nonce length.
        expected: usize,
        /// Actual nonce length.
        actual: usize,
    },

    /// Random number generation failed.
    #[error("random generation failed")]
    RandomFailed,

    /// CNSA 2.0 algorithm violation.
    ///
    /// An attempt was made to use a non-compliant algorithm.
    #[error("CNSA 2.0 violation: {0}")]
    CnsaViolation(String),
}

impl From<CryptoError> for TypesCryptoError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::KeyGenerationFailed => TypesCryptoError::KeyGenerationFailed,
            CryptoError::SealFailed => TypesCryptoError::EncryptionFailed,
            CryptoError::OpenFailed => TypesCryptoError::DecryptionFailed,
            CryptoError::SigningFailed => TypesCryptoError::SignatureFailed,
            CryptoError::VerificationFailed => TypesCryptoError::VerificationFailed,
            CryptoError::KeyDerivationFailed => TypesCryptoError::KeyDerivationFailed,
            CryptoError::InvalidKeyMaterial | CryptoError::InvalidNonceLength { .. } => {
                TypesCryptoError::InvalidKeyMaterial
            }
            CryptoError::RandomFailed => TypesCryptoError::KeyGenerationFailed,
            CryptoError::CnsaViolation(_) => TypesCryptoError::CnsaViolation,
        }
    }
}
