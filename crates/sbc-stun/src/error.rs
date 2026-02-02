//! STUN error types.

use thiserror::Error;

/// Result type for STUN operations.
pub type StunResult<T> = Result<T, StunError>;

/// STUN errors.
#[derive(Debug, Error)]
pub enum StunError {
    /// Invalid STUN message format.
    #[error("invalid message: {reason}")]
    InvalidMessage {
        /// Error description.
        reason: String,
    },

    /// Message too short.
    #[error("message too short: need {need} bytes, got {got}")]
    MessageTooShort {
        /// Required bytes.
        need: usize,
        /// Actual bytes.
        got: usize,
    },

    /// Invalid magic cookie.
    #[error("invalid magic cookie: expected 0x2112A442, got {got:#010x}")]
    InvalidMagicCookie {
        /// Received cookie value.
        got: u32,
    },

    /// Invalid attribute.
    #[error("invalid attribute: {reason}")]
    InvalidAttribute {
        /// Error description.
        reason: String,
    },

    /// Unknown attribute type (comprehension-required).
    #[error("unknown comprehension-required attribute: {attr_type:#06x}")]
    UnknownRequiredAttribute {
        /// Attribute type.
        attr_type: u16,
    },

    /// Message integrity verification failed.
    #[error("message integrity verification failed")]
    IntegrityFailed,

    /// Fingerprint verification failed.
    #[error("fingerprint verification failed")]
    FingerprintFailed,

    /// STUN error response received.
    #[error("STUN error {code}: {reason}")]
    ErrorResponse {
        /// Error code.
        code: u16,
        /// Error reason.
        reason: String,
    },

    /// Request timed out.
    #[error("request timed out")]
    Timeout,

    /// Network error.
    #[error("network error: {reason}")]
    NetworkError {
        /// Error description.
        reason: String,
    },
}

/// STUN error codes per RFC 5389.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunErrorCode {
    /// 300: Try Alternate.
    TryAlternate = 300,
    /// 400: Bad Request.
    BadRequest = 400,
    /// 401: Unauthorized.
    Unauthorized = 401,
    /// 403: Forbidden.
    Forbidden = 403,
    /// 420: Unknown Attribute.
    UnknownAttribute = 420,
    /// 438: Stale Nonce.
    StaleNonce = 438,
    /// 500: Server Error.
    ServerError = 500,
}

impl StunErrorCode {
    /// Returns the error code value.
    pub fn code(&self) -> u16 {
        *self as u16
    }

    /// Returns the default reason phrase.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::TryAlternate => "Try Alternate",
            Self::BadRequest => "Bad Request",
            Self::Unauthorized => "Unauthorized",
            Self::Forbidden => "Forbidden",
            Self::UnknownAttribute => "Unknown Attribute",
            Self::StaleNonce => "Stale Nonce",
            Self::ServerError => "Server Error",
        }
    }

    /// Creates from numeric code.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            300 => Some(Self::TryAlternate),
            400 => Some(Self::BadRequest),
            401 => Some(Self::Unauthorized),
            403 => Some(Self::Forbidden),
            420 => Some(Self::UnknownAttribute),
            438 => Some(Self::StaleNonce),
            500 => Some(Self::ServerError),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(StunErrorCode::BadRequest.code(), 400);
        assert_eq!(StunErrorCode::Unauthorized.code(), 401);
        assert_eq!(StunErrorCode::from_code(401), Some(StunErrorCode::Unauthorized));
        assert_eq!(StunErrorCode::from_code(999), None);
    }

    #[test]
    fn test_error_display() {
        let err = StunError::InvalidMagicCookie { got: 0x12345678 };
        let msg = format!("{err}");
        assert!(msg.contains("magic cookie"));
    }
}
