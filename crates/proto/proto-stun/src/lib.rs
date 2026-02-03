//! STUN protocol for NAT discovery.
//!
//! This crate implements Session Traversal Utilities for NAT (STUN) per
//! RFC 5389 and RFC 8489 for discovering public IP addresses and NAT types.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-7**: Boundary Protection (NAT discovery)
//! - **SC-8**: Transmission Confidentiality and Integrity (message integrity)
//!
//! ## RFC Compliance
//!
//! - **RFC 5389**: STUN Protocol
//! - **RFC 8489**: STUN (updated)
//! - **RFC 5245**: ICE (uses STUN)
//! - **RFC 8445**: ICE (updated)
//!
//! ## CNSA 2.0 Compliance
//!
//! Message integrity uses HMAC-SHA384 for CNSA 2.0 compliance when
//! long-term credentials are used. Short-term credentials use
//! HMAC-SHA256 for ICE compatibility (required by RFC 8445).
//!
//! ## Features
//!
//! - STUN message parsing and generation
//! - Binding request/response handling
//! - STUN attributes (XOR-MAPPED-ADDRESS, etc.)
//! - Message integrity and fingerprint

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

pub mod attribute;
pub mod client;
pub mod error;
pub mod message;

pub use attribute::{StunAttribute, XorMappedAddress};
pub use client::StunClient;
pub use error::{StunError, StunResult};
pub use message::{StunClass, StunMessage, StunMessageType, StunMethod};

/// STUN magic cookie (RFC 5389).
pub const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN header size in bytes.
pub const HEADER_SIZE: usize = 20;

/// STUN fingerprint XOR value.
pub const FINGERPRINT_XOR: u32 = 0x5354554E;

/// Default STUN port.
pub const DEFAULT_PORT: u16 = 3478;

/// Default STUNS (TLS) port.
pub const DEFAULT_TLS_PORT: u16 = 5349;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MAGIC_COOKIE, 0x2112A442);
        assert_eq!(HEADER_SIZE, 20);
        assert_eq!(DEFAULT_PORT, 3478);
    }
}
