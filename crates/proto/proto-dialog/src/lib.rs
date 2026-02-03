//! SIP dialog state management.
//!
//! This crate manages SIP dialog lifecycle including creation, modification,
//! and termination of call sessions per RFC 3261.
//!
//! ## RFC Compliance
//!
//! - **RFC 3261**: SIP Dialogs (Section 12)
//! - **RFC 3515**: REFER Method
//! - **RFC 4028**: Session Timers
//! - **RFC 6665**: SIP-Specific Event Notification (SUBSCRIBE/NOTIFY)
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
//!
//! ## Power of 10 Compliance
//!
//! This crate follows NASA's "Power of 10" rules for safety-critical code:
//! - Rule 1: Simple control flow (no goto, setjmp/longjmp)
//! - Rule 2: Fixed upper bounds on loops
//! - Rule 3: No dynamic memory after init (dialog state pre-allocated)
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
pub mod forking;
pub mod refer;
pub mod session_timer;
pub mod subscription;

pub use dialog::{Dialog, DialogId, DialogRole, DialogState};
pub use error::{DialogError, DialogResult};
pub use forking::{ForkKey, ForkedDialogSet};
pub use refer::{
    format_refer_to, parse_refer_to, ReferHandler, ReferRequest, ReferStatus,
    ReferSubscriptionState,
};
pub use session_timer::{
    format_min_se, format_session_expires, handle_422_response, negotiate_session_timer,
    parse_min_se, parse_session_expires, RefresherRole, SessionTimer, SessionTimerNegotiation,
};
pub use subscription::{
    format_allow_events, is_event_package_registered, parse_allow_events, validate_event_package,
    EventPackage, EventPackageRegistry, EventPackageValidation, Notifier, Subscription,
    SubscriptionState, SubscriptionStateHeader, TerminationReason, DEFAULT_SUBSCRIPTION_EXPIRES,
    IANA_REGISTERED_EVENT_PACKAGES, MIN_SUBSCRIPTION_EXPIRES,
};

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
