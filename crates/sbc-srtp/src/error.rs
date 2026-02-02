//! SRTP error types.

use thiserror::Error;

/// Result type for SRTP operations.
pub type SrtpResult<T> = Result<T, SrtpError>;

/// SRTP errors.
#[derive(Debug, Error)]
pub enum SrtpError {
    /// Invalid key material.
    #[error("invalid key material: {reason}")]
    InvalidKey {
        /// Error description.
        reason: String,
    },

    /// Key derivation failed.
    #[error("key derivation failed: {reason}")]
    KeyDerivationFailed {
        /// Error description.
        reason: String,
    },

    /// Encryption failed.
    #[error("encryption failed: {reason}")]
    EncryptionFailed {
        /// Error description.
        reason: String,
    },

    /// Decryption failed.
    #[error("decryption failed: {reason}")]
    DecryptionFailed {
        /// Error description.
        reason: String,
    },

    /// Authentication failed.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Replay attack detected.
    #[error("replay attack detected: packet index {index}")]
    ReplayDetected {
        /// The replayed packet index.
        index: u64,
    },

    /// Packet index overflow.
    #[error("packet index overflow")]
    IndexOverflow,

    /// Invalid packet.
    #[error("invalid SRTP packet: {reason}")]
    InvalidPacket {
        /// Error description.
        reason: String,
    },

    /// Context not initialized.
    #[error("SRTP context not initialized")]
    NotInitialized,
}
