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
//! - **SI-10 / SI-15**: metadata escaping, rejection and caps (`xml`, `metadata`)
//!
//! ## Phase 1 scope
//!
//! Library-level conformance only: the RFC 7865 serializer and a pure RFC 7866
//! RS INVITE body builder. Nothing in the SBC consumes this crate yet.
//! POA&M-300..309 track the SRC wiring, media forking, config, recording
//! indication, SRS transport security, snapshots, audit/CDR, cluster, inbound
//! SRS requests, and the remaining scaffolding (`forking`, `session`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod config;
pub mod error;
pub mod forking;
pub mod metadata;
pub mod session;
pub mod src_request;
pub mod xml;

pub use config::{RecordingConfig, RecordingMode, RecordingTrigger, SrsEndpoint};
pub use error::{SiprecError, SiprecResult};
pub use forking::{ForkingMode, MediaForker, StreamFork};
pub use metadata::{
    MediaStream, Participant, ParticipantRole, RecordingMetadata, SessionMetadata, StreamDirection,
};
pub use session::{
    RecordingSession, RecordingSessionState, SessionRecordingClient, SessionRecordingEvent,
};
pub use src_request::{RsInviteParts, SrcHeaders, build_rs_offer};

#[cfg(test)]
mod tests {
    #[test]
    fn test_crate_loads() {
        // Placeholder test - crate compiles if this runs
    }
}
