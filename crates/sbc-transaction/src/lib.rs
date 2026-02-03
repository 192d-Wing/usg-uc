//! SIP transaction layer state machine for SBC.
//!
//! This crate re-exports the generic `proto-transaction` crate with
//! SBC-specific extensions if needed in the future.
//!
//! ## RFC Compliance
//!
//! - **RFC 3261**: SIP Transaction Layer (Sections 17.1, 17.2)
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **AU-2**: Event Logging (transaction state changes)

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

// Re-export everything from proto-transaction
pub use proto_transaction::*;
