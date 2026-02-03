//! Transport error types.

use uc_types::address::SbcSocketAddr;
use thiserror::Error;

/// Result type for transport operations.
pub type TransportResult<T> = Result<T, TransportError>;

/// Transport errors.
///
/// ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality and Integrity)
#[derive(Debug, Error)]
pub enum TransportError {
    /// Failed to bind to address.
    #[error("failed to bind to {address}: {reason}")]
    BindFailed {
        /// Address that failed to bind.
        address: SbcSocketAddr,
        /// Error description.
        reason: String,
    },

    /// Failed to connect to remote.
    #[error("failed to connect to {address}: {reason}")]
    ConnectFailed {
        /// Remote address.
        address: SbcSocketAddr,
        /// Error description.
        reason: String,
    },

    /// Send operation failed.
    #[error("send failed to {address}: {reason}")]
    SendFailed {
        /// Destination address.
        address: SbcSocketAddr,
        /// Error description.
        reason: String,
    },

    /// Receive operation failed.
    #[error("receive failed: {reason}")]
    ReceiveFailed {
        /// Error description.
        reason: String,
    },

    /// Connection closed.
    #[error("connection closed")]
    ConnectionClosed,

    /// Message too large.
    #[error("message size {size} exceeds maximum {max_size}")]
    MessageTooLarge {
        /// Actual message size.
        size: usize,
        /// Maximum allowed size.
        max_size: usize,
    },

    /// TLS handshake failed.
    #[error("TLS handshake failed: {reason}")]
    TlsHandshakeFailed {
        /// Error description.
        reason: String,
    },

    /// TLS certificate error.
    #[error("TLS certificate error: {reason}")]
    TlsCertificateError {
        /// Error description.
        reason: String,
    },

    /// Invalid address.
    #[error("invalid address: {reason}")]
    InvalidAddress {
        /// Error description.
        reason: String,
    },

    /// Transport not connected.
    #[error("transport not connected")]
    NotConnected,

    /// Transport already closed.
    #[error("transport already closed")]
    AlreadyClosed,

    /// IO error.
    #[error("I/O error: {reason}")]
    Io {
        /// Error description.
        reason: String,
    },

    /// Timeout.
    #[error("operation timed out")]
    Timeout,
}

impl From<std::io::Error> for TransportError {
    fn from(err: std::io::Error) -> Self {
        Self::Io {
            reason: err.to_string(),
        }
    }
}
