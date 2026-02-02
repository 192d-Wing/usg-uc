//! SIP dialog state management.
//!
//! This crate manages SIP dialog lifecycle including creation, modification,
//! and termination of call sessions per RFC 3261.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-2**: Event Logging (dialog state changes)
//! - **SC-10**: Network Disconnect (session termination)
//!
//! ## RFC Compliance
//!
//! - **RFC 3261**: SIP Dialogs (Section 12)
//! - **RFC 3515**: REFER Method
//! - **RFC 4028**: Session Timers
//!
//! ## Dialog Lifecycle
//!
//! 1. **Early**: Dialog created from provisional response (1xx)
//! 2. **Confirmed**: Dialog established from final 2xx response
//! 3. **Terminated**: Dialog ended by BYE or error
//!
//! ## Features
//!
//! - Dialog ID management (Call-ID, local tag, remote tag)
//! - CSeq sequence tracking
//! - Route set management
//! - Session timer support

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

pub mod dialog;
pub mod error;
pub mod session_timer;

pub use dialog::{Dialog, DialogId, DialogState};
pub use error::{DialogError, DialogResult};
pub use session_timer::SessionTimer;

/// Default session expires value (1800 seconds per RFC 4028).
pub const DEFAULT_SESSION_EXPIRES: u32 = 1800;

/// Minimum session expires value (90 seconds per RFC 4028).
pub const MIN_SESSION_EXPIRES: u32 = 90;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_timer_defaults() {
        assert!(DEFAULT_SESSION_EXPIRES >= MIN_SESSION_EXPIRES);
    }
}
