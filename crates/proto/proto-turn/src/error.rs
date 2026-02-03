//! TURN error types.

use thiserror::Error;

/// Result type for TURN operations.
pub type TurnResult<T> = Result<T, TurnError>;

/// TURN errors.
#[derive(Debug, Error)]
pub enum TurnError {
    /// Allocation failed.
    #[error("allocation failed: {reason}")]
    AllocationFailed {
        /// Error description.
        reason: String,
    },

    /// No allocation exists.
    #[error("no allocation exists for this 5-tuple")]
    NoAllocation,

    /// Allocation already exists.
    #[error("allocation already exists")]
    AllocationExists,

    /// Allocation expired.
    #[error("allocation has expired")]
    AllocationExpired,

    /// Permission denied.
    #[error("permission denied for peer {peer}")]
    PermissionDenied {
        /// Peer address.
        peer: std::net::SocketAddr,
    },

    /// Invalid channel number.
    #[error("invalid channel number: {channel}")]
    InvalidChannel {
        /// Channel number.
        channel: u16,
    },

    /// Channel binding failed.
    #[error("channel binding failed: {reason}")]
    ChannelBindFailed {
        /// Error description.
        reason: String,
    },

    /// Invalid channel data.
    #[error("invalid channel data: {reason}")]
    InvalidChannelData {
        /// Error description.
        reason: String,
    },

    /// STUN error.
    #[error("STUN error: {0}")]
    Stun(#[from] proto_stun::StunError),

    /// Authentication failed.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Quota exceeded.
    #[error("allocation quota exceeded")]
    QuotaExceeded,

    /// Invalid request.
    #[error("invalid request: {reason}")]
    InvalidRequest {
        /// Error description.
        reason: String,
    },

    /// Buffer too small.
    #[error("buffer too small: needed {needed} bytes, available {available}")]
    BufferTooSmall {
        /// Bytes needed.
        needed: usize,
        /// Bytes available.
        available: usize,
    },

    /// Data too large.
    #[error("data too large: {size} bytes exceeds maximum {max}")]
    DataTooLarge {
        /// Actual size.
        size: usize,
        /// Maximum allowed.
        max: usize,
    },
}

/// TURN error codes per RFC 5766.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnErrorCode {
    /// 403: Forbidden.
    Forbidden = 403,
    /// 437: Allocation Mismatch.
    AllocationMismatch = 437,
    /// 438: Stale Nonce.
    StaleNonce = 438,
    /// 440: Address Family not Supported.
    AddressFamilyNotSupported = 440,
    /// 441: Wrong Credentials.
    WrongCredentials = 441,
    /// 442: Unsupported Transport Protocol.
    UnsupportedTransport = 442,
    /// 486: Allocation Quota Reached.
    AllocationQuotaReached = 486,
    /// 508: Insufficient Capacity.
    InsufficientCapacity = 508,
}

impl TurnErrorCode {
    /// Returns the error code value.
    pub fn code(&self) -> u16 {
        *self as u16
    }

    /// Returns the default reason phrase.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Forbidden => "Forbidden",
            Self::AllocationMismatch => "Allocation Mismatch",
            Self::StaleNonce => "Stale Nonce",
            Self::AddressFamilyNotSupported => "Address Family not Supported",
            Self::WrongCredentials => "Wrong Credentials",
            Self::UnsupportedTransport => "Unsupported Transport Protocol",
            Self::AllocationQuotaReached => "Allocation Quota Reached",
            Self::InsufficientCapacity => "Insufficient Capacity",
        }
    }

    /// Creates from numeric code.
    pub fn from_code(code: u16) -> Option<Self> {
        match code {
            403 => Some(Self::Forbidden),
            437 => Some(Self::AllocationMismatch),
            438 => Some(Self::StaleNonce),
            440 => Some(Self::AddressFamilyNotSupported),
            441 => Some(Self::WrongCredentials),
            442 => Some(Self::UnsupportedTransport),
            486 => Some(Self::AllocationQuotaReached),
            508 => Some(Self::InsufficientCapacity),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(TurnErrorCode::AllocationMismatch.code(), 437);
        assert_eq!(TurnErrorCode::from_code(486), Some(TurnErrorCode::AllocationQuotaReached));
        assert_eq!(TurnErrorCode::from_code(999), None);
    }
}
