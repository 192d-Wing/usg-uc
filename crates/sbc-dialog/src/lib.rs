//! SIP dialog state management for SBC.
//!
//! This crate re-exports the generic `proto-dialog` crate with
//! SBC-specific extensions if needed in the future.
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

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

// Re-export everything from proto-dialog
pub use proto_dialog::*;
