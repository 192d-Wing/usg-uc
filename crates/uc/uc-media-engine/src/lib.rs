//! Media session orchestration.
//!
//! This crate tracks per-call media session and stream state, selects the
//! media mode, and negotiates codecs for the SBC. It does not touch RTP
//! packets: RTP/RTCP relay, SRTP and transcoding live in `sbc-media-core`
//! (built on `proto-rtp`, `proto-srtp` and `uc-codecs`).
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity (orchestration
//!   only: records whether SRTP is required for a session; performs no
//!   cryptography itself)
//! - **SI-10**: Information Input Validation (remote codec offers are
//!   negotiated through `uc_codecs::CodecRegistry::negotiate`; not wired
//!   in sbc-daemon; POA&M-142)
//!
//! ## Media Modes
//!
//! The SBC supports two media handling modes:
//!
//! - **Relay (B2BUA)**: media is anchored on the SBC (transcoding, where
//!   needed, is performed by `sbc-media-core`)
//! - **Pass-through**: Direct media forwarding between endpoints
//!
//! ## Features
//!
//! - Media session and stream state machines
//! - Media mode selection (Relay / Pass-through)
//! - Codec negotiation (delegated to `uc-codecs`)
//! - Packet and byte counters per stream

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
// Clippy style preferences for protocol implementation code
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
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::panic))]

pub mod error;
pub mod session;
pub mod stream;

pub use error::{MediaError, MediaResult};
pub use session::{MediaMode, MediaSession, MediaSessionConfig};
pub use stream::{MediaStream, StreamDirection, StreamState};

/// Default jitter buffer size in packets.
pub const DEFAULT_JITTER_BUFFER_SIZE: usize = 50;

/// Default packet timeout in milliseconds.
pub const DEFAULT_PACKET_TIMEOUT_MS: u64 = 5000;

/// Maximum supported streams per session.
pub const MAX_STREAMS_PER_SESSION: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        const _: () = {
            assert!(DEFAULT_JITTER_BUFFER_SIZE > 0);
            assert!(DEFAULT_PACKET_TIMEOUT_MS > 0);
        };
    }
}
