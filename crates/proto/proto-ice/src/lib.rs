//! ICE protocol for NAT traversal.
//!
//! This crate implements Interactive Connectivity Establishment (ICE) per
//! RFC 8445 for NAT traversal in VoIP communications.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-7**: Boundary Protection (NAT traversal)
//! - **SC-8**: Transmission Confidentiality and Integrity
//!
//! ## RFC Compliance
//!
//! - **RFC 8445**: ICE Protocol
//! - **RFC 8839**: SDP for ICE
//! - **RFC 5245**: ICE (legacy, superseded by 8445)
//!
//! ## ICE Flow
//!
//! 1. Gather local candidates (host, server-reflexive, relay)
//! 2. Exchange candidates via SDP offer/answer
//! 3. Pair local and remote candidates
//! 4. Perform connectivity checks on candidate pairs
//! 5. Select best working pair for media
//!
//! ## Features
//!
//! - Candidate gathering (host, srflx, relay)
//! - Candidate pair formation and prioritization
//! - Connectivity check state machine
//! - ICE agent (controlling/controlled modes)

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

pub mod agent;
pub mod candidate;
pub mod checklist;
pub mod connectivity;
pub mod consent;
pub mod error;

pub use agent::{IceAgent, IceCredentials, IceRole};
pub use candidate::{Candidate, CandidateType, TransportProtocol};
pub use checklist::{CandidatePair, CheckList, PairState};
pub use connectivity::{CheckResult, ConnectivityCheck, ConnectivityChecker, IceStunServer, TriggeredCheckInfo};
pub use consent::{ConsentKeepaliveAction, ConsentKeepaliveManager, ConsentState, ConsentTracker, KeepaliveTracker};
pub use error::{IceError, IceResult};

/// Default ICE timeout in seconds.
pub const DEFAULT_TIMEOUT: u64 = 30;

/// Default connectivity check interval in milliseconds.
pub const DEFAULT_TA: u64 = 50;

/// ICE foundation characters.
pub const FOUNDATION_CHARS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

/// Type preference values per RFC 8445 Section 5.1.2.2
pub mod type_preference {
    /// Host candidate preference (highest).
    pub const HOST: u32 = 126;
    /// Peer reflexive preference.
    pub const PEER_REFLEXIVE: u32 = 110;
    /// Server reflexive preference.
    pub const SERVER_REFLEXIVE: u32 = 100;
    /// Relay candidate preference (lowest).
    pub const RELAY: u32 = 0;
}

/// ICE component IDs.
pub mod component {
    /// RTP component.
    pub const RTP: u16 = 1;
    /// RTCP component.
    pub const RTCP: u16 = 2;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_preferences() {
        // Host should have highest preference
        assert!(type_preference::HOST > type_preference::SERVER_REFLEXIVE);
        assert!(type_preference::SERVER_REFLEXIVE > type_preference::RELAY);
    }

    #[test]
    fn test_components() {
        assert_eq!(component::RTP, 1);
        assert_eq!(component::RTCP, 2);
    }
}
