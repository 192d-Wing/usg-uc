//! # T.38 Fax Relay Protocol (RFC 4612)
//!
//! This crate implements T.38 real-time fax relay for the USG Session Border Controller,
//! enabling fax transmission over IP networks with error correction.
//!
//! ## WARNING: not interoperable (POA&M-204)
//!
//! The UDPTL and IFP wire encodings in this crate are **project-specific**.
//! They are NOT the ITU-T T.38 ASN.1 PER encoding and will not interoperate
//! with standards-conformant T.38 gateways or endpoints. RFC 4612 covers only
//! the MIME registration. This crate is not a dependency of any shipped binary.
//!
//! The SBC relays UDPTL opaquely and does not use this crate: T.38 SDP is
//! handled by `proto-sdp::t38` and the switchover by `sbc-daemon`
//! (POA&M-290; redundancy/FEC/buffer residuals POA&M-292).
//!
//! ## Features
//!
//! - **UDPTL Transport**: UDPTL-style transport with redundancy (non-standard encoding)
//! - **Error Correction**: redundancy modelled on ITU-T T.38 (FEC is a stub; non-interoperable encoding, POA&M-204)
//! - **Audio-to-T.38 Gateway**: Transition from audio fax to T.38
//! - **T.30 Signal Handling**: Fax signal detection and processing
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **AU-2**: Audit Events (fax transmission logging)
//!
//! ## Protocol Overview
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                    T.38 Fax Gateway                      │
//! ├──────────────────────────────────────────────────────────┤
//! │  T.30 Signal   │   IFP Packet    │    UDPTL/TCP          │
//! │  Detection     │   Encoder       │    Transport          │
//! └──────────────────────────────────────────────────────────┘
//! ```

#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::unused_async)]

// POAM: POA&M-204 -- UDPTL/IFP wire encoding is not ITU-T T.38 ASN.1 PER; not interoperable

pub mod config;
pub mod error;
pub mod ifp;
pub mod session;
pub mod signal;
pub mod udptl;

pub use config::T38Config;
pub use error::{T38Error, T38Result};
pub use ifp::{DataType, IfpPacket};
pub use session::{T38Session, T38SessionState};
pub use signal::{FaxPhase, T30Signal};
pub use udptl::{UdptlPacket, UdptlTransport};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exports() {
        let _ = T38Config::default();
    }
}
