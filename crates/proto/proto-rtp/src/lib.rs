//! RTP and RTCP protocol handling for real-time media.
//!
//! This crate implements the Real-time Transport Protocol (RTP) and
//! RTP Control Protocol (RTCP) for media streaming.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//!
//! ## RFC Compliance
//!
//! - **RFC 3550**: RTP: A Transport Protocol for Real-Time Applications
//! - **RFC 3551**: RTP Profile for Audio and Video Conferences
//! - **RFC 5761**: Multiplexing RTP and RTCP on a Single Port
//!
//! ## Features
//!
//! - RTP packet parsing and generation
//! - RTCP packet handling (SR, RR, SDES, BYE, APP)
//! - Sequence number tracking
//! - Jitter calculation
//! - SSRC management

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
// TODO: Fix these warnings in a dedicated cleanup pass
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::branches_sharing_code)]

pub mod error;
pub mod packet;
pub mod rtcp;
pub mod sequence;

pub use error::{RtpError, RtpResult};
pub use packet::{RtpHeader, RtpPacket};
pub use rtcp::{RtcpPacket, RtcpType};
pub use sequence::SequenceTracker;

/// RTP version (always 2 per RFC 3550).
pub const RTP_VERSION: u8 = 2;

/// Minimum RTP header size in bytes.
pub const RTP_HEADER_MIN_SIZE: usize = 12;

/// Maximum RTP packet size (for UDP transport).
pub const MAX_RTP_PACKET_SIZE: usize = 1500;

/// Standard audio payload types per RFC 3551.
pub mod payload_types {
    /// PCMU (G.711 mu-law).
    pub const PCMU: u8 = 0;
    /// GSM.
    pub const GSM: u8 = 3;
    /// G723.
    pub const G723: u8 = 4;
    /// DVI4 8kHz.
    pub const DVI4_8000: u8 = 5;
    /// DVI4 16kHz.
    pub const DVI4_16000: u8 = 6;
    /// LPC.
    pub const LPC: u8 = 7;
    /// PCMA (G.711 a-law).
    pub const PCMA: u8 = 8;
    /// G722.
    pub const G722: u8 = 9;
    /// L16 stereo.
    pub const L16_STEREO: u8 = 10;
    /// L16 mono.
    pub const L16_MONO: u8 = 11;
    /// QCELP.
    pub const QCELP: u8 = 12;
    /// CN (Comfort Noise).
    pub const CN: u8 = 13;
    /// G728.
    pub const G728: u8 = 15;
    /// G729.
    pub const G729: u8 = 18;
    /// Dynamic range start.
    pub const DYNAMIC_START: u8 = 96;
    /// Dynamic range end.
    pub const DYNAMIC_END: u8 = 127;

    /// Returns true if this is a dynamic payload type.
    #[must_use]
    pub const fn is_dynamic(pt: u8) -> bool {
        pt >= DYNAMIC_START && pt <= DYNAMIC_END
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(RTP_VERSION, 2);
        assert_eq!(RTP_HEADER_MIN_SIZE, 12);
    }

    #[test]
    fn test_payload_types() {
        assert!(!payload_types::is_dynamic(0));
        assert!(payload_types::is_dynamic(96));
        assert!(payload_types::is_dynamic(127));
    }
}
