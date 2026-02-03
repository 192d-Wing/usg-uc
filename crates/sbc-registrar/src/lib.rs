//! SIP registration and location service for SBC.
//!
//! This crate re-exports the generic `proto-registrar` crate with
//! SBC-specific extensions if needed in the future.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **IA-2**: Identification and Authentication (Organizational Users)
//! - **IA-4**: Identifier Management
//! - **IA-5**: Authenticator Management
//!
//! ## RFC Compliance
//!
//! - **RFC 3261**: SIP Core (Section 10 - Registrations)
//! - **RFC 5626**: SIP Outbound
//! - **RFC 5627**: GRUU (Globally Routable UA URI)

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]

// Re-export everything from proto-registrar
pub use proto_registrar::*;
