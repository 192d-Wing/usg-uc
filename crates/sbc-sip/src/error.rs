//! SIP error types.

use thiserror::Error;

/// Result type for SIP operations.
pub type SipResult<T> = Result<T, SipError>;

/// SIP errors.
#[derive(Debug, Error)]
pub enum SipError {
    /// Failed to parse SIP message.
    #[error("failed to parse SIP message: {reason}")]
    ParseError {
        /// Error description.
        reason: String,
    },

    /// Invalid SIP method.
    #[error("invalid SIP method: {method}")]
    InvalidMethod {
        /// The invalid method.
        method: String,
    },

    /// Invalid SIP URI.
    #[error("invalid SIP URI: {reason}")]
    InvalidUri {
        /// Error description.
        reason: String,
    },

    /// Invalid header.
    #[error("invalid header '{name}': {reason}")]
    InvalidHeader {
        /// Header name.
        name: String,
        /// Error description.
        reason: String,
    },

    /// Missing required header.
    #[error("missing required header: {name}")]
    MissingHeader {
        /// Header name.
        name: String,
    },

    /// Invalid status code.
    #[error("invalid status code: {code}")]
    InvalidStatusCode {
        /// The invalid code.
        code: u16,
    },

    /// Message too large.
    #[error("message size {size} exceeds maximum {max_size}")]
    MessageTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max_size: usize,
    },

    /// Invalid Content-Length.
    #[error("Content-Length mismatch: header says {header}, body is {actual}")]
    ContentLengthMismatch {
        /// Content-Length header value.
        header: usize,
        /// Actual body length.
        actual: usize,
    },

    /// Encoding error.
    #[error("encoding error: {reason}")]
    EncodingError {
        /// Error description.
        reason: String,
    },
}
