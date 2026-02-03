//! # WebRTC Gateway for USG SBC
//!
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::unused_async)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::unused_self)]
#![allow(clippy::significant_drop_tightening)]
//!
//! This crate provides WebRTC gateway functionality for the USG Session Border Controller,
//! enabling SIP-to-WebRTC interworking for browser-based communication.
//!
//! ## Features
//!
//! - **SIP-to-WebRTC Bridging**: Convert SIP calls to WebRTC sessions
//! - **SDP Munging**: Transform SDP for WebRTC compatibility
//! - **ICE Trickling**: Support for incremental ICE candidate exchange
//! - **SRTP Interworking**: SDES-to-DTLS-SRTP key conversion
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **SC-13**: Cryptographic Protection (DTLS-SRTP)
//! - **SC-23**: Session Authenticity
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    WebRTC Gateway                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │  Session    │    SDP      │    ICE      │    Media         │
//! │  Manager    │   Munger    │  Trickler   │   Bridge         │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod config;
pub mod error;
pub mod gateway;
pub mod sdp_munge;
pub mod session;
pub mod trickle;

pub use config::WebRtcConfig;
pub use error::{WebRtcError, WebRtcResult};
pub use gateway::WebRtcGateway;
pub use sdp_munge::{SdpMunger, WebRtcSdpMode};
pub use session::{WebRtcSession, WebRtcSessionState};
pub use trickle::{TrickleCandidate, TrickleIce};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exports() {
        let _ = WebRtcConfig::default();
    }
}
