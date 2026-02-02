//! SIP registration and location service.
//!
//! This crate handles SIP REGISTER requests and maintains the location
//! database for endpoint discovery and routing.
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
//!
//! ## Operation Modes
//!
//! - **B2BUA Registrar**: Terminates registrations, manages bindings locally
//! - **Proxy Mode**: Forwards registrations to upstream registrar
//!
//! ## Features
//!
//! - Contact binding management with expiration
//! - Multiple contact bindings per AOR
//! - Location service for routing
//! - Outbound support (RFC 5626)

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

pub mod binding;
pub mod error;
pub mod location;
pub mod registrar;

pub use binding::{Binding, BindingState};
pub use error::{RegistrarError, RegistrarResult};
pub use location::LocationService;
pub use registrar::{Registrar, RegistrarConfig, RegistrarMode};

/// Default registration expiration in seconds (RFC 3261 recommends 3600).
pub const DEFAULT_EXPIRES: u32 = 3600;

/// Minimum registration expiration in seconds.
pub const MIN_EXPIRES: u32 = 60;

/// Maximum registration expiration in seconds.
pub const MAX_EXPIRES: u32 = 86400; // 24 hours

/// Maximum contacts per AOR.
pub const MAX_CONTACTS_PER_AOR: usize = 10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expires_constants() {
        assert!(MIN_EXPIRES < DEFAULT_EXPIRES);
        assert!(DEFAULT_EXPIRES < MAX_EXPIRES);
    }
}
