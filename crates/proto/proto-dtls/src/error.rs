//! DTLS error types.

use thiserror::Error;

/// Result type for DTLS operations.
pub type DtlsResult<T> = Result<T, DtlsError>;

/// DTLS errors.
#[derive(Debug, Error)]
pub enum DtlsError {
    /// Handshake failed.
    #[error("DTLS handshake failed: {reason}")]
    HandshakeFailed {
        /// Error description.
        reason: String,
    },

    /// Certificate error.
    #[error("certificate error: {reason}")]
    CertificateError {
        /// Error description.
        reason: String,
    },

    /// Certificate fingerprint mismatch.
    #[error("certificate fingerprint mismatch: expected {expected}, got {actual}")]
    FingerprintMismatch {
        /// Expected fingerprint.
        expected: String,
        /// Actual fingerprint.
        actual: String,
    },

    /// Connection not established.
    #[error("DTLS connection not established")]
    NotConnected,

    /// Connection already closed.
    #[error("DTLS connection already closed")]
    AlreadyClosed,

    /// Send failed.
    #[error("send failed: {reason}")]
    SendFailed {
        /// Error description.
        reason: String,
    },

    /// Receive failed.
    #[error("receive failed: {reason}")]
    ReceiveFailed {
        /// Error description.
        reason: String,
    },

    /// Invalid configuration.
    #[error("invalid configuration: {reason}")]
    InvalidConfig {
        /// Error description.
        reason: String,
    },

    /// SRTP keying material export failed.
    #[error("SRTP key export failed: {reason}")]
    SrtpKeyExportFailed {
        /// Error description.
        reason: String,
    },

    /// Timeout.
    #[error("operation timed out")]
    Timeout,

    /// IO error.
    #[error("I/O error: {reason}")]
    Io {
        /// Error description.
        reason: String,
    },

    /// Record layer error.
    #[error("record error: {reason}")]
    RecordError {
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

    /// Replay attack detected.
    #[error("replay attack detected")]
    ReplayDetected,

    /// Key derivation failed.
    #[error("key derivation failed: {reason}")]
    KeyDerivationFailed {
        /// Error description.
        reason: String,
    },

    /// Unsupported cipher suite.
    #[error("unsupported cipher suite: {0}")]
    UnsupportedCipherSuite(u16),

    /// Alert received.
    #[error("alert received: {level:?} {description:?}")]
    AlertReceived {
        /// Alert level.
        level: u8,
        /// Alert description.
        description: u8,
    },
}

impl From<std::io::Error> for DtlsError {
    fn from(err: std::io::Error) -> Self {
        Self::Io {
            reason: err.to_string(),
        }
    }
}
