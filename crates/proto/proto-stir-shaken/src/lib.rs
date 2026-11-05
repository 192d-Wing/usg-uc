//! STIR/SHAKEN caller ID verification and attestation.
//!
//! This crate implements STIR (Secure Telephone Identity Revisited) and
//! SHAKEN (Signature-based Handling of Asserted information using toKENs)
//! for caller ID authentication and robocall prevention.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **IA-9**: Service Identification and Authentication
//! - **SI-10**: Information Input Validation (strict Identity/PASSporT decode)
//! - **SC-23**: Session Authenticity (signed `orig`/`dest`/`iat` binding)
//!
//! ## RFC Compliance
//!
//! - **RFC 8224**: Authenticated Identity Management in SIP
//! - **RFC 8225**: PASSporT: Personal Assertion Token
//! - **RFC 8226**: Secure Telephone Identity Credentials
//!
//! - **RFC 8588**: PASSporT Extension for SHAKEN
//! - **ATIS-1000074**: SHAKEN framework (verstat, x5u)
//!
//! ## CNSA 2.0 Compliance
//!
//! SHAKEN mandates ES256 (ECDSA P-256 / SHA-256), which CNSA 2.0 does not
//! permit. This crate contains no cryptography: signing and verification are
//! injected through [`Signer`] and [`VerifyingKey`]. The ES256 implementation
//! lives in `uc_crypto::interop::ecdsa_p256` behind the `stir-shaken-es256`
//! feature (CNSA-EXCEPTION: ATIS-1000074). ES384 is accepted for bilateral,
//! non-SHAKEN profiles only; `ppt=shaken` with any `alg` other than ES256 is
//! rejected to prevent algorithm confusion.
//!
//! ## Layering
//!
//! Pure and synchronous. Certificate fetch, chain validation and caching are
//! in `uc-sti`.
//!
//! ## Attestation Levels
//!
//! - **A (Full)**: Full attestation - caller is authorized
//! - **B (Partial)**: Partial attestation - caller authenticated, not verified
//! - **C (Gateway)**: Gateway attestation - no authentication

#![forbid(unsafe_code)]
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

pub mod canon;
pub mod error;
pub mod identity;
pub mod jws;
pub mod passport;
pub mod verification;

pub use canon::{TelephoneNumber, canonicalize_tn};
pub use error::{StirShakenError, StirShakenResult};
pub use identity::IdentityHeader;
pub use passport::{
    Alg, Attestation, DecodedPassport, PASSporT, PPT_DIV, PPT_SHAKEN, PassportClaims,
    PassportHeader, Signer,
};
pub use verification::{
    CallContext, FailureReason, KeyResolver, PreparedIdentity, TnAuthEntry, TnAuthScope,
    VerificationResult, VerifiedKey, Verifier, VerifyingKey, Verstat,
};

/// Identity header name.
pub const IDENTITY_HEADER: &str = "Identity";
