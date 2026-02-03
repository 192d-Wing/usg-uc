//! Back-to-back user agent implementation for SBC.
//!
//! This crate re-exports the generic `proto-b2bua` crate with
//! SBC-specific extensions if needed in the future.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-7**: Boundary Protection
//! - **SC-8**: Transmission Confidentiality and Integrity
//!
//! ## RFC Compliance
//!
//! - **RFC 3261**: SIP Core
//! - **RFC 7092**: B2BUA Taxonomy
//! - **RFC 5853**: SBC Requirements

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

// Re-export everything from proto-b2bua
pub use proto_b2bua::*;
