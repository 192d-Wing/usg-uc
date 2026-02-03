//! SDP parsing and manipulation for media negotiation.
//!
//! This crate provides Session Description Protocol (SDP) parsing and
//! generation for negotiating media parameters in VoIP sessions.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity (DTLS fingerprints)
//! - **SC-13**: Cryptographic Protection (crypto attributes)
//!
//! ## RFC Compliance
//!
//! - **RFC 4566**: SDP: Session Description Protocol
//! - **RFC 3264**: An Offer/Answer Model with SDP
//! - **RFC 5245**: ICE candidates in SDP
//! - **RFC 4572**: Fingerprint attribute for DTLS
//!
//! ## Example SDP
//!
//! ```text
//! v=0
//! o=- 123456 1 IN IP6 ::1
//! s=-
//! t=0 0
//! m=audio 49170 RTP/SAVP 0
//! a=rtpmap:0 PCMU/8000
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod attribute;
pub mod error;
pub mod media;
pub mod offer_answer;
pub mod session;

pub use attribute::{Attribute, AttributeName, Direction};
pub use error::{SdpError, SdpResult};
pub use media::{MediaDescription, MediaType, TransportProtocol};
pub use offer_answer::{
    compute_answer_direction, disable_media_stream, enable_media_stream, generate_answer,
    hold_media_stream, resume_media_stream, validate_answer, HoldType, LocalCapabilities,
    LocalMediaCapability, MediaModification, MediaModificationType, MediaModificationValidator,
    MediaNegotiationResult, NegotiationResult,
};
pub use session::{Origin, RepeatTimes, SessionDescription, TimeValue, Timing};

/// SDP protocol version (always 0 per RFC 4566).
pub const SDP_VERSION: u8 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(SDP_VERSION, 0);
    }
}
