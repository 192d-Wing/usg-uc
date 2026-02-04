//! SIP transaction layer state machine.
//!
//! This crate implements the SIP transaction layer finite state machine
//! per RFC 3261 for reliable message delivery and retransmission handling.
//!
//! ## RFC Compliance
//!
//! - **RFC 3261**: SIP Transaction Layer (Sections 17.1, 17.2)
//! - **RFC 3262**: Reliable Provisional Responses (100rel, PRACK)
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
//!
//! ## Power of 10 Compliance
//!
//! This crate follows NASA's "Power of 10" rules for safety-critical code:
//! - Rule 1: Simple control flow (no goto, setjmp/longjmp)
//! - Rule 2: Fixed upper bounds on loops (timer intervals bounded)
//! - Rule 3: No dynamic memory after init (pre-allocated state machines)
//! - Rule 4: Functions ≤60 lines (modular design)
//! - Rule 5: ≥2 assertions per function (state invariants)
//! - Rule 6: Minimal variable scope
//! - Rule 7: Check return values
//! - Rule 8: Limited preprocessor (Rust doesn't have one)
//! - Rule 9: Limited pointer use (Rust ownership)
//! - Rule 10: Compile with all warnings, use static analysis

#![forbid(unsafe_code)]
#![deny(warnings)]
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

pub mod client;
pub mod error;
pub mod prack;
pub mod server;
pub mod timer;

pub use client::{ClientInviteTransaction, ClientNonInviteTransaction};
pub use error::{TransactionError, TransactionResult};
pub use prack::{
    ClientReliableProvisionalTracker, EXTENSION_100REL, RAck, ReliableProvisionalState,
    ReliableProvisionalTracker, requires_100rel, supports_100rel,
};
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
///
/// Per RFC 3261 Section 17.1.3, transactions are matched by:
/// - Via branch parameter (MUST start with "z9hG4bK" for RFC 3261 compliance)
/// - CSeq method
/// - For server transactions: sent-by value from Via header
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

    /// Returns true if the branch is RFC 3261 compliant (starts with magic cookie).
    pub fn is_rfc3261_branch(&self) -> bool {
        self.branch.starts_with(RFC3261_BRANCH_MAGIC)
    }
}

/// RFC 3261 branch parameter magic cookie.
///
/// Per RFC 3261 Section 8.1.1.7, the branch parameter MUST start with
/// this magic cookie to indicate RFC 3261 compliance.
pub const RFC3261_BRANCH_MAGIC: &str = "z9hG4bK";

/// CSeq validation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSeqValidation {
    /// CSeq is valid for this transaction.
    Valid,
    /// CSeq is a retransmission (same sequence number).
    Retransmission,
    /// CSeq sequence number is too low (out of order).
    TooLow,
    /// CSeq method doesn't match transaction.
    MethodMismatch,
}

/// CSeq tracker for transaction-level validation.
///
/// Per RFC 3261 Section 17.1.3, the transaction layer must track CSeq
/// to distinguish retransmissions from new requests.
#[derive(Debug, Clone)]
pub struct CSeqTracker {
    /// The expected CSeq sequence number for this transaction.
    sequence: u32,
    /// The CSeq method.
    method: String,
}

impl CSeqTracker {
    /// Creates a new CSeq tracker.
    pub fn new(sequence: u32, method: impl Into<String>) -> Self {
        Self {
            sequence,
            method: method.into(),
        }
    }

    /// Returns the current sequence number.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Returns the method.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Validates an incoming CSeq against this tracker.
    ///
    /// Per RFC 3261 Section 17.1.3:
    /// - Same sequence + method = retransmission
    /// - Higher sequence + same method = new request (for in-dialog)
    /// - Lower sequence = out of order (reject)
    /// - Different method = mismatch (different transaction)
    pub fn validate(&self, incoming_seq: u32, incoming_method: &str) -> CSeqValidation {
        if incoming_method != self.method {
            return CSeqValidation::MethodMismatch;
        }

        match incoming_seq.cmp(&self.sequence) {
            std::cmp::Ordering::Equal => CSeqValidation::Retransmission,
            std::cmp::Ordering::Greater => CSeqValidation::Valid,
            std::cmp::Ordering::Less => CSeqValidation::TooLow,
        }
    }

    /// Validates that a response matches this transaction's CSeq.
    ///
    /// Responses must have the exact same CSeq as the request.
    pub fn validate_response(&self, response_seq: u32, response_method: &str) -> CSeqValidation {
        if response_method != self.method {
            return CSeqValidation::MethodMismatch;
        }

        if response_seq == self.sequence {
            CSeqValidation::Valid
        } else {
            CSeqValidation::TooLow
        }
    }

    /// Updates the sequence number (for in-dialog requests).
    pub fn update_sequence(&mut self, new_seq: u32) {
        if new_seq > self.sequence {
            self.sequence = new_seq;
        }
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
    fn test_transaction_key_rfc3261_branch() {
        let rfc3261_key = TransactionKey::client("z9hG4bK776asdhds", "INVITE");
        assert!(rfc3261_key.is_rfc3261_branch());

        let legacy_key = TransactionKey::client("1234567890", "INVITE");
        assert!(!legacy_key.is_rfc3261_branch());
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

    #[test]
    fn test_cseq_tracker_creation() {
        let tracker = CSeqTracker::new(100, "INVITE");
        assert_eq!(tracker.sequence(), 100);
        assert_eq!(tracker.method(), "INVITE");
    }

    #[test]
    fn test_cseq_tracker_validate_retransmission() {
        let tracker = CSeqTracker::new(100, "INVITE");

        // Same sequence = retransmission
        let result = tracker.validate(100, "INVITE");
        assert_eq!(result, CSeqValidation::Retransmission);
    }

    #[test]
    fn test_cseq_tracker_validate_new_request() {
        let tracker = CSeqTracker::new(100, "INVITE");

        // Higher sequence = new request
        let result = tracker.validate(101, "INVITE");
        assert_eq!(result, CSeqValidation::Valid);
    }

    #[test]
    fn test_cseq_tracker_validate_out_of_order() {
        let tracker = CSeqTracker::new(100, "INVITE");

        // Lower sequence = out of order
        let result = tracker.validate(99, "INVITE");
        assert_eq!(result, CSeqValidation::TooLow);
    }

    #[test]
    fn test_cseq_tracker_validate_method_mismatch() {
        let tracker = CSeqTracker::new(100, "INVITE");

        // Different method = mismatch
        let result = tracker.validate(100, "BYE");
        assert_eq!(result, CSeqValidation::MethodMismatch);
    }

    #[test]
    fn test_cseq_tracker_validate_response() {
        let tracker = CSeqTracker::new(100, "INVITE");

        // Response must match exactly
        assert_eq!(
            tracker.validate_response(100, "INVITE"),
            CSeqValidation::Valid
        );
        assert_eq!(
            tracker.validate_response(99, "INVITE"),
            CSeqValidation::TooLow
        );
        assert_eq!(
            tracker.validate_response(101, "INVITE"),
            CSeqValidation::TooLow
        );
        assert_eq!(
            tracker.validate_response(100, "BYE"),
            CSeqValidation::MethodMismatch
        );
    }

    #[test]
    fn test_cseq_tracker_update_sequence() {
        let mut tracker = CSeqTracker::new(100, "INVITE");

        // Update to higher value
        tracker.update_sequence(105);
        assert_eq!(tracker.sequence(), 105);

        // Should not update to lower value
        tracker.update_sequence(102);
        assert_eq!(tracker.sequence(), 105);
    }
}
