//! Transport error types.

use thiserror::Error;
use uc_types::address::SbcSocketAddr;

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

/// SR-22 tests for `TransportError::AcceptFailed`. Compile-red until the
/// variant and `is_resource_exhausted` exist.
#[cfg(test)]
mod sr22_accept_error_tests {
    use super::*;

    // NIST 800-53 Rev5: SC-5
    #[test]
    fn accept_failed_carries_resource_flag() {
        const TIMEOUT_EXHAUSTED: bool = TransportError::Timeout.is_resource_exhausted();
        assert!(!TIMEOUT_EXHAUSTED, "is_resource_exhausted is a const fn");
        let exhausted = TransportError::AcceptFailed {
            reason: "Too many open files".into(),
            resource_exhausted: true,
        };
        assert!(exhausted.is_resource_exhausted());
        let transient = TransportError::AcceptFailed {
            reason: "Software caused connection abort".into(),
            resource_exhausted: false,
        };
        assert!(!transient.is_resource_exhausted());
        let addr = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 5060);
        let others = [
            TransportError::BindFailed {
                address: addr,
                reason: String::new(),
            },
            TransportError::ConnectFailed {
                address: addr,
                reason: String::new(),
            },
            TransportError::SendFailed {
                address: addr,
                reason: String::new(),
            },
            TransportError::ReceiveFailed {
                reason: "accept failed: Too many open files".into(),
            },
            TransportError::ConnectionClosed,
            TransportError::MessageTooLarge {
                size: 2,
                max_size: 1,
            },
            TransportError::TlsHandshakeFailed {
                reason: String::new(),
            },
            TransportError::TlsCertificateError {
                reason: String::new(),
            },
            TransportError::InvalidAddress {
                reason: String::new(),
            },
            TransportError::NotConnected,
            TransportError::AlreadyClosed,
            TransportError::Io {
                reason: "Too many open files".into(),
            },
            TransportError::Timeout,
        ];
        for e in &others {
            assert!(
                !e.is_resource_exhausted(),
                "{e:?} must not be resource-exhausted"
            );
        }
    }
}
