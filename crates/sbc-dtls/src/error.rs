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
}

impl From<std::io::Error> for DtlsError {
    fn from(err: std::io::Error) -> Self {
        Self::Io {
            reason: err.to_string(),
        }
    }
}
