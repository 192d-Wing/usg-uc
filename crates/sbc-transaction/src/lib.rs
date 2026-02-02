//! SIP transaction layer state machine.
//!
//! This crate implements the SIP transaction layer finite state machine
//! per RFC 3261 for reliable message delivery and retransmission handling.
//!
//! ## RFC Compliance
//!
//! - **RFC 3261**: SIP Transaction Layer (Sections 17.1, 17.2)
//!
//! ## Transaction Types
//!
//! - **Client INVITE Transaction**: For outgoing INVITE requests
//! - **Client Non-INVITE Transaction**: For outgoing non-INVITE requests
//! - **Server INVITE Transaction**: For incoming INVITE requests
//! - **Server Non-INVITE Transaction**: For incoming non-INVITE requests
//!
//! ## Features
//!
//! - Transaction state machine per RFC 3261
//! - Timer management (T1, T2, Timer A-K)
//! - Retransmission handling
//! - Transaction matching

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

pub mod client;
pub mod error;
pub mod server;
pub mod timer;

pub use client::{ClientInviteTransaction, ClientNonInviteTransaction};
pub use error::{TransactionError, TransactionResult};
pub use server::{ServerInviteTransaction, ServerNonInviteTransaction};
pub use timer::TimerConfig;

use std::time::Duration;

/// Default T1 timer value (500ms per RFC 3261).
pub const DEFAULT_T1: Duration = Duration::from_millis(500);

/// Default T2 timer value (4s per RFC 3261).
pub const DEFAULT_T2: Duration = Duration::from_secs(4);

/// Default T4 timer value (5s per RFC 3261).
pub const DEFAULT_T4: Duration = Duration::from_secs(5);

/// Timer A initial value (T1 for unreliable transport).
pub const TIMER_A_INITIAL: Duration = DEFAULT_T1;

/// Timer B value (64*T1).
pub const TIMER_B: Duration = Duration::from_millis(32000);

/// Timer D value (32s for unreliable, 0 for reliable).
pub const TIMER_D_UNRELIABLE: Duration = Duration::from_secs(32);

/// Timer E initial value (T1).
pub const TIMER_E_INITIAL: Duration = DEFAULT_T1;

/// Timer F value (64*T1).
pub const TIMER_F: Duration = Duration::from_millis(32000);

/// Timer G initial value (T1).
pub const TIMER_G_INITIAL: Duration = DEFAULT_T1;

/// Timer H value (64*T1).
pub const TIMER_H: Duration = Duration::from_millis(32000);

/// Timer I value (T4 for unreliable, 0 for reliable).
pub const TIMER_I_UNRELIABLE: Duration = DEFAULT_T4;

/// Timer J value (64*T1 for unreliable, 0 for reliable).
pub const TIMER_J_UNRELIABLE: Duration = Duration::from_millis(32000);

/// Timer K value (T4 for unreliable, 0 for reliable).
pub const TIMER_K_UNRELIABLE: Duration = DEFAULT_T4;

/// Transaction key for matching transactions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionKey {
    /// Branch parameter from Via header.
    pub branch: String,
    /// CSeq method.
    pub method: String,
    /// Whether this is a server transaction.
    pub is_server: bool,
}

impl TransactionKey {
    /// Creates a new transaction key.
    pub fn new(branch: impl Into<String>, method: impl Into<String>, is_server: bool) -> Self {
        Self {
            branch: branch.into(),
            method: method.into(),
            is_server,
        }
    }

    /// Creates a client transaction key.
    pub fn client(branch: impl Into<String>, method: impl Into<String>) -> Self {
        Self::new(branch, method, false)
    }

    /// Creates a server transaction key.
    pub fn server(branch: impl Into<String>, method: impl Into<String>) -> Self {
        Self::new(branch, method, true)
    }
}

impl std::fmt::Display for TransactionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let side = if self.is_server { "server" } else { "client" };
        write!(f, "{}:{}:{}", side, self.method, self.branch)
    }
}

/// Transport type for timer calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    /// Reliable transport (TCP, TLS, WebSocket).
    Reliable,
    /// Unreliable transport (UDP).
    Unreliable,
}

impl TransportType {
    /// Returns true if this is a reliable transport.
    pub fn is_reliable(&self) -> bool {
        *self == Self::Reliable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_key() {
        let key = TransactionKey::client("z9hG4bK776asdhds", "INVITE");
        assert!(!key.is_server);
        assert_eq!(key.method, "INVITE");

        let server_key = TransactionKey::server("z9hG4bK776asdhds", "INVITE");
        assert!(server_key.is_server);
    }

    #[test]
    fn test_timer_constants() {
        assert_eq!(DEFAULT_T1, Duration::from_millis(500));
        assert_eq!(DEFAULT_T2, Duration::from_secs(4));
        assert_eq!(TIMER_B, Duration::from_millis(32000));
    }

    #[test]
    fn test_transport_type() {
        assert!(TransportType::Reliable.is_reliable());
        assert!(!TransportType::Unreliable.is_reliable());
    }
}
