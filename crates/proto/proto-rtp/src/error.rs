//! RTP error types.

use thiserror::Error;

/// Result type for RTP operations.
pub type RtpResult<T> = Result<T, RtpError>;

/// RTP errors.
///
/// String fields use `&'static str` to avoid heap allocation on error paths.
/// Dynamic values (padding size, RTCP version) get dedicated variants with
/// structured fields instead of `format!()`.
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

    /// Invalid padding (static reason).
    #[error("invalid padding: {reason}")]
    InvalidPadding {
        /// Error description.
        reason: &'static str,
    },

    /// Invalid padding size (structured).
    #[error("invalid padding size: {padding_size}")]
    InvalidPaddingSize {
        /// The invalid padding size byte.
        padding_size: usize,
    },

    /// Invalid extension header.
    #[error("invalid extension header: {reason}")]
    InvalidExtension {
        /// Error description.
        reason: &'static str,
    },

    /// Invalid RTCP packet (static reason).
    #[error("invalid RTCP packet: {reason}")]
    InvalidRtcp {
        /// Error description.
        reason: &'static str,
    },

    /// Invalid RTCP version.
    #[error("invalid RTCP version: {version}")]
    InvalidRtcpVersion {
        /// The invalid version.
        version: u8,
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
