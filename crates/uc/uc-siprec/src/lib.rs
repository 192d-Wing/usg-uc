//! SIPREC call recording support per RFC 7865/7866.
//!
//! This crate implements Session Recording Protocol (SIPREC) for
//! recording SIP sessions on enterprise SBC deployments.
//!
//! ## RFC Compliance
//!
//! - **RFC 7865**: Session Initiation Protocol (SIP) Recording Metadata
//! - **RFC 7866**: Session Recording Protocol (SIPREC)
//! - **RFC 6341**: Use Cases and Requirements for SIP-Based Media Recording
//!
//! ## Architecture
//!
//! ```text
//! +-------+          +-----+          +-------+        +-----+
//! | Alice |          | SBC |          |  Bob  |        |  SRS |
//! +-------+          +-----+          +-------+        +-----+
//!     |   INVITE       |                  |               |
//!     |--------------->|  INVITE          |               |
//!     |                |----------------->|               |
//!     |   200 OK       |  200 OK          |               |
//!     |<---------------|<-----------------|               |
//!     |   ACK          |  ACK             |               |
//!     |--------------->|----------------->|               |
//!     |                |                  |               |
//!     |   Media <----->|<---------------->| Media         |
//!     |                |                  |               |
//!     |                |  INVITE (SIPREC) |               |
//!     |                |--------------------------------->|
//!     |                |  200 OK          |               |
//!     |                |<---------------------------------|
//!     |                |  Forked Media ------------------>|
//! ```
//!
//! ## Terminology
//!
//! - **SRC**: Session Recording Client (the SBC)
//! - **SRS**: Session Recording Server (recording device)
//! - **CS**: Communication Session (the call being recorded)
//! - **RS**: Recording Session (SIPREC session to SRS)
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-4**: Audit Storage Capacity (recording storage)
//! - **AU-9**: Protection of Audit Information
//! - **SC-8**: Transmission Confidentiality and Integrity (POA&M-304)
//! - **SI-10 / SI-15**: metadata escaping, rejection and caps (`xml`, `metadata`);
//!   SRS answer validation (`rs_answer`)
//!
//! ## Scope
//!
//! This crate is the library half of the SRC: the RFC 7865 serializer, a pure
//! RFC 7866 RS INVITE body builder whose SDP offer is SRTP-only (SDES
//! `AEAD_AES_256_GCM`, RFC 4568 / RFC 7714) and the RS answer validator.
//! `sbc-daemon` originates the recording session and forks media with it
//! (POA&M-300 origination, -302 and -306 closed). The unwired scaffolding
//! (`forking`, `session`, `config`) was removed (POA&M-309, CM-7); the SBC
//! schema for recording lives in `sbc-config` (`[recording]`).
//! Still open: POA&M-300 (RS liveness), -301 (remote media nodes, RTCP),
//! -303 (recording indication), -304 (NAPTR/SRV, ML-KEM), -305 (metadata
//! updates), -307 (cluster) and -308 (inbound SRS requests).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod metadata;
pub mod rs_answer;
pub mod src_request;
pub mod xml;

pub use error::{SiprecError, SiprecResult};
pub use metadata::{
    MediaStream, Participant, ParticipantRole, RecordingMetadata, SessionMetadata, StreamDirection,
};
pub use rs_answer::{RsAnswerStream, has_recordpref_never, parse_rs_answer};
pub use src_request::{RsInviteParts, SdesKey, SrcHeaders, build_rs_offer};

#[cfg(test)]
mod tests {
    #[test]
    fn test_crate_loads() {
        // Placeholder test - crate compiles if this runs
    }
}
