//! Back-to-back user agent core implementation.
//!
//! This crate implements the B2BUA (Back-to-Back User Agent) pattern for
//! SIP call handling, providing call control and media anchoring.
//!
//! ## RFC Compliance
//!
//! - **RFC 3261**: SIP Core
//! - **RFC 7092**: B2BUA Taxonomy
//! - **RFC 5853**: SBC Requirements
//!
//! ## B2BUA Types (RFC 7092)
//!
//! - **Signaling-only**: Modifies signaling, media flows directly
//! - **Media-relay**: Anchors media, forwards RTP packets
//! - **Media-aware**: Can inspect/modify media content
//! - **Media-termination**: Terminates and re-originates media
//!
//! ## Architecture
//!
//! ```text
//!   A-Leg (UAC)                  B2BUA                    B-Leg (UAS)
//!  ┌─────────┐              ┌───────────┐              ┌─────────┐
//!  │  Alice  │──INVITE────▶│   Call    │──INVITE────▶│   Bob   │
//!  │         │◀────200─────│  Control  │◀────200─────│         │
//!  │         │─────ACK────▶│           │─────ACK────▶│         │
//!  └─────────┘              └───────────┘              └─────────┘
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
// TODO: Fix these warnings in a dedicated cleanup pass
#![allow(clippy::unreadable_literal)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::use_self)]
// Allow unwrap/panic in tests
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::panic))]

pub mod call;
pub mod error;
pub mod leg;
pub mod mode;
pub mod sdp_rewrite;

pub use call::{Call, CallConfig, CallId, CallState};
pub use error::{B2buaError, B2buaResult};
pub use leg::{CallLeg, LegConfig, LegRole, LegState};
pub use mode::{
    CodecNegotiationMode, MediaAddress, MediaHandling, MediaRelayConfig, MediaTerminationConfig,
    ModeCharacteristics, ModeConfig, SdpModification, SdpRewriteContext, TopologyHiding,
    TopologyHidingConfig,
};
pub use sdp_rewrite::{extract_media_address, is_connection_hold, is_hold_sdp, SdpRewriter, SdpRewriteResult};

/// B2BUA operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum B2buaMode {
    /// Signaling-only B2BUA.
    ///
    /// Media flows directly between endpoints.
    /// B2BUA only modifies SIP signaling.
    SignalingOnly,

    /// Media-relay B2BUA (default).
    ///
    /// Media flows through the B2BUA.
    /// RTP packets are relayed without modification.
    #[default]
    MediaRelay,

    /// Media-aware B2BUA.
    ///
    /// Can inspect and modify media content.
    /// Supports recording, transcoding, etc.
    MediaAware,

    /// Media-termination B2BUA.
    ///
    /// Terminates media on each leg.
    /// Full media control including transcoding.
    MediaTermination,
}

impl std::fmt::Display for B2buaMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignalingOnly => write!(f, "signaling-only"),
            Self::MediaRelay => write!(f, "media-relay"),
            Self::MediaAware => write!(f, "media-aware"),
            Self::MediaTermination => write!(f, "media-termination"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_b2bua_mode_default() {
        assert_eq!(B2buaMode::default(), B2buaMode::MediaRelay);
    }

    #[test]
    fn test_b2bua_mode_display() {
        assert_eq!(B2buaMode::SignalingOnly.to_string(), "signaling-only");
        assert_eq!(B2buaMode::MediaRelay.to_string(), "media-relay");
        assert_eq!(B2buaMode::MediaAware.to_string(), "media-aware");
        assert_eq!(B2buaMode::MediaTermination.to_string(), "media-termination");
    }
}
