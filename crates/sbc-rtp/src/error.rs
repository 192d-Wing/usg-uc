//! RTP error types.

use thiserror::Error;

/// Result type for RTP operations.
pub type RtpResult<T> = Result<T, RtpError>;

/// RTP errors.
#[derive(Debug, Error)]
pub enum RtpError {
    /// Packet too short.
    #[error("packet too short: need at least {need} bytes, got {got}")]
    PacketTooShort {
        /// Minimum required bytes.
        need: usize,
        /// Actual bytes received.
        got: usize,
    },

    /// Invalid RTP version.
    #[error("invalid RTP version: {version}, expected 2")]
    InvalidVersion {
        /// The invalid version.
        version: u8,
    },

    /// Invalid padding.
    #[error("invalid padding: {reason}")]
    InvalidPadding {
        /// Error description.
        reason: String,
    },

    /// Invalid extension.
    #[error("invalid extension header: {reason}")]
    InvalidExtension {
        /// Error description.
        reason: String,
    },

    /// Invalid RTCP packet.
    #[error("invalid RTCP packet: {reason}")]
    InvalidRtcp {
        /// Error description.
        reason: String,
    },

    /// Sequence number discontinuity.
    #[error("sequence discontinuity: expected {expected}, got {actual}")]
    SequenceDiscontinuity {
        /// Expected sequence number.
        expected: u16,
        /// Actual sequence number.
        actual: u16,
    },

    /// SSRC collision.
    #[error("SSRC collision detected: {ssrc}")]
    SsrcCollision {
        /// The colliding SSRC.
        ssrc: u32,
    },
}
