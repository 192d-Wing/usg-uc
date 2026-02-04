//! # Authentication, Authorization, and Accounting for USG SBC
//!
#![allow(clippy::doc_markdown)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::type_complexity)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unused_async)]
#![allow(clippy::missing_const_for_fn)]
#![allow(dead_code)]
//!
//! This crate provides AAA (Authentication, Authorization, Accounting) integration
//! for the USG Session Border Controller, supporting:
//!
//! - **RADIUS**: Remote Authentication Dial-In User Service (RFC 2865, RFC 2866)
//! - **Diameter**: 3GPP Cx/Dx for IMS (RFC 6733, TS 29.228/229)
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **IA-2**: Identification and Authentication
//! - **IA-8**: Identification and Authentication (Non-Organizational Users)
//! - **AU-3**: Content of Audit Records
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      AAA Provider                            │
//! ├─────────────────────────────────────────────────────────────┤
//! │     RADIUS      │     Diameter     │      Local            │
//! │    (UDP/TCP)    │      (SCTP)      │    (In-Memory)        │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod config;
pub mod diameter;
pub mod error;
pub mod provider;
pub mod radius;

pub use config::{AaaConfig, DiameterConfig, RadiusConfig};
pub use diameter::DiameterClient;
pub use error::{AaaError, AaaResult};
pub use provider::{AaaProvider, AccountingRecord, AuthRequest, AuthResponse};
pub use radius::RadiusClient;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exports() {
        let _ = AaaConfig::default();
    }
}
