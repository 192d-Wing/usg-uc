//! TURN relay protocol for media traversal.
//!
//! This crate implements Traversal Using Relays around NAT (TURN) per
//! RFC 5766 and RFC 8656 for relaying media when direct connectivity
//! is not possible.
//!
//! ## RFC Compliance
//!
//! - **RFC 5766**: TURN Protocol
//! - **RFC 8656**: TURN (updated)
//! - **RFC 6156**: TURN IPv6
//!
//! ## TURN Flow
//!
//! 1. Client sends Allocate request to TURN server
//! 2. Server allocates relayed transport address
//! 3. Client creates permissions for peer addresses
//! 4. Media flows through the relay
//!
//! ## Features
//!
//! - TURN allocation management
//! - Permission and channel binding
//! - Relayed address allocation
//! - ChannelData for efficient relay

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

pub mod allocation;
pub mod attribute;
pub mod channel;
pub mod error;

pub use allocation::{Allocation, AllocationState};
pub use attribute::TurnAttribute;
pub use channel::ChannelData;
pub use error::{TurnError, TurnResult};

/// Default TURN port (same as STUN).
pub const DEFAULT_PORT: u16 = 3478;

/// Default TURNS (TLS) port.
pub const DEFAULT_TLS_PORT: u16 = 5349;

/// Default allocation lifetime in seconds.
pub const DEFAULT_LIFETIME: u32 = 600;

/// Maximum allocation lifetime in seconds (10 minutes).
pub const MAX_LIFETIME: u32 = 3600;

/// Minimum channel number (0x4000).
pub const MIN_CHANNEL_NUMBER: u16 = 0x4000;

/// Maximum channel number (0x7FFE).
pub const MAX_CHANNEL_NUMBER: u16 = 0x7FFE;

/// Channel data header size.
pub const CHANNEL_DATA_HEADER_SIZE: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_PORT, 3478);
        assert_eq!(DEFAULT_LIFETIME, 600);
        assert!(MIN_CHANNEL_NUMBER < MAX_CHANNEL_NUMBER);
    }
}
