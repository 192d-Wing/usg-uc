//! # T.38 Fax Relay Protocol (RFC 4612)
//!
//! This crate implements T.38 real-time fax relay for the USG Session Border Controller,
//! enabling fax transmission over IP networks with error correction.
//!
//! ## Features
//!
//! - **UDPTL Transport**: UDP Transport Layer for T.38 with redundancy
//! - **Error Correction**: FEC and redundancy modes per ITU-T T.38
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
