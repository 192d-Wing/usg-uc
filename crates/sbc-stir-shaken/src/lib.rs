//! STIR/SHAKEN caller ID verification and attestation.
//!
//! This crate implements STIR (Secure Telephone Identity Revisited) and
//! SHAKEN (Signature-based Handling of Asserted information using toKENs)
//! for caller ID authentication and robocall prevention.
//!
//! ## RFC Compliance
//!
//! - **RFC 8224**: Authenticated Identity Management in SIP
//! - **RFC 8225**: PASSporT: Personal Assertion Token
//! - **RFC 8226**: Secure Telephone Identity Credentials
//!
//! ## CNSA 2.0 Compliance
//!
//! This implementation uses ES384 (ECDSA with P-384 and SHA-384) for
//! PASSporT signatures, meeting CNSA 2.0 requirements. ES256 is NOT supported.
//!
//! ## Attestation Levels
//!
//! - **A (Full)**: Full attestation - caller is authorized
//! - **B (Partial)**: Partial attestation - caller authenticated, not verified
//! - **C (Gateway)**: Gateway attestation - no authentication

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

pub mod error;
pub mod identity;
pub mod passport;
pub mod verification;

pub use error::{StirShakenError, StirShakenResult};
pub use identity::{Identity, IdentityHeader};
pub use passport::{Attestation, OrigId, PASSporT, PASSporTClaims, PASSporTHeader};
pub use verification::{VerificationResult, VerificationStatus, Verifier};

/// PASSporT media type.
pub const PASSPORT_MEDIA_TYPE: &str = "passport";

/// PASSporT algorithm (CNSA 2.0 compliant).
pub const PASSPORT_ALGORITHM: &str = "ES384";

/// PASSporT type.
pub const PASSPORT_TYPE: &str = "passport";

/// Identity header name.
pub const IDENTITY_HEADER: &str = "Identity";

/// Maximum PASSporT age in seconds (default 60).
pub const MAX_PASSPORT_AGE: u64 = 60;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(PASSPORT_ALGORITHM, "ES384");
        assert_eq!(PASSPORT_TYPE, "passport");
    }
}
