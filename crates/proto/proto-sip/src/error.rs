//! SIP error types.

use thiserror::Error;

/// Result type for SIP operations.
pub type SipResult<T> = Result<T, SipError>;

/// SIP errors.
///
/// Marked `#[non_exhaustive]`: new variants are added as the parser is
/// hardened, and callers must keep a catch-all arm.
#[derive(Debug, Error)]
#[non_exhaustive]
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

    /// A single-valued header appeared more than once (RFC 3261 §7.3.1,
    /// §20; RFC 4475 §3.1.2.x).
    #[error("duplicate single-valued header: {name}")]
    DuplicateHeader {
        /// Header name (canonical form).
        name: String,
    },

    /// A parser resource limit was exceeded.
    ///
    /// NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection).
    #[error("{what} exceeds limit {limit}")]
    LimitExceeded {
        /// What was limited (static, never attacker data).
        what: &'static str,
        /// The configured limit.
        limit: usize,
    },

    /// Content-Length header value is malformed (RFC 3261 §20.14).
    #[error("invalid Content-Length: {reason}")]
    InvalidContentLength {
        /// Static reason (never attacker data).
        reason: &'static str,
    },
}

impl SipError {
    /// Returns true if this error was caused by a malformed or abusive
    /// message from the peer, i.e. a case where RFC 3261 §8.2.2 / §16.3
    /// permit a 400 (Bad Request) response.
    ///
    /// NIST 800-53 Rev5: SI-10 (Information Input Validation), SI-11
    /// (Error Handling).
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::ParseError { .. }
                | Self::InvalidMethod { .. }
                | Self::InvalidUri { .. }
                | Self::InvalidHeader { .. }
                | Self::MissingHeader { .. }
                | Self::InvalidStatusCode { .. }
                | Self::MessageTooLarge { .. }
                | Self::ContentLengthMismatch { .. }
                | Self::DuplicateHeader { .. }
                | Self::LimitExceeded { .. }
                | Self::InvalidContentLength { .. }
        )
    }
}

/// Truncates attacker-controlled text before it is placed in an error
/// reason (reasons reach logs).
///
/// NIST 800-53 Rev5: SI-11 (Error Handling) - bound echoed input.
pub(crate) fn truncate_for_log(s: &str) -> String {
    const MAX: usize = 64;
    if s.len() <= MAX {
        return s.escape_debug().to_string();
    }
    let mut end = MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", s[..end].escape_debug())
}
