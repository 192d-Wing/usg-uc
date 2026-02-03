//! SDP error types.

use thiserror::Error;

/// Result type for SDP operations.
pub type SdpResult<T> = Result<T, SdpError>;

/// SDP errors.
#[derive(Debug, Error)]
pub enum SdpError {
    /// Failed to parse SDP.
    #[error("failed to parse SDP: {reason}")]
    ParseError {
        /// Error description.
        reason: String,
    },

    /// Invalid line format.
    #[error("invalid line at position {line}: {reason}")]
    InvalidLine {
        /// Line number (1-indexed).
        line: usize,
        /// Error description.
        reason: String,
    },

    /// Missing required field.
    #[error("missing required field: {field}")]
    MissingField {
        /// Field name.
        field: String,
    },

    /// Invalid attribute.
    #[error("invalid attribute '{name}': {reason}")]
    InvalidAttribute {
        /// Attribute name.
        name: String,
        /// Error description.
        reason: String,
    },

    /// Invalid media description.
    #[error("invalid media description: {reason}")]
    InvalidMedia {
        /// Error description.
        reason: String,
    },

    /// Invalid connection data.
    #[error("invalid connection data: {reason}")]
    InvalidConnection {
        /// Error description.
        reason: String,
    },

    /// Unsupported version.
    #[error("unsupported SDP version: {version}")]
    UnsupportedVersion {
        /// The version number.
        version: u8,
    },

    /// Invalid media modification per RFC 3264 §8.4.
    #[error("invalid media modification: {reason}")]
    InvalidModification {
        /// Error description.
        reason: String,
    },
}
