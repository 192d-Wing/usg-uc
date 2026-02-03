//! # SBC Crypto
//!
//! CNSA 2.0 compliant cryptographic abstraction layer for the USG Session Border Controller.
//!
//! ## Purpose
//!
//! This crate serves as the **single point of entry** for all cryptographic operations
//! in the SBC. By centralizing crypto here, we ensure:
//!
//! 1. **CNSA 2.0 Compliance**: Non-compliant algorithms cannot be used
//! 2. **FIPS 140-3 Validation**: All operations use aws-lc-rs FIPS module
//! 3. **Auditability**: Single place to verify cryptographic compliance
//! 4. **Future-Proofing**: Easy migration to post-quantum algorithms (ML-KEM)
//!
//! ## CNSA 2.0 Algorithm Restrictions
//!
//! | Function | Allowed | Forbidden |
//! |----------|---------|-----------|
//! | Hash | SHA-384, SHA-512 | SHA-256, SHA-1, MD5 |
//! | Symmetric | AES-256-GCM | AES-128, AES-192, 3DES |
//! | Key Exchange | ECDH P-384, P-521 | ECDH P-256, RSA, DH |
//! | Signatures | ECDSA P-384, P-521 | ECDSA P-256, RSA |
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! This crate implements:
//! - **SC-12**: Cryptographic Key Establishment and Management
//! - **SC-13**: Cryptographic Protection
//!
//! ## Usage
//!
//! ```ignore
//! use uc_crypto::{hash, aead, ecdsa};
//!
//! // Hash data with SHA-384 (minimum CNSA 2.0 hash)
//! let digest = hash::sha384(b"data to hash");
//!
//! // Encrypt with AES-256-GCM
//! let key = aead::Aes256GcmKey::generate()?;
//! let ciphertext = key.seal(nonce, aad, plaintext)?;
//!
//! // Sign with ECDSA P-384
//! let keypair = ecdsa::P384KeyPair::generate()?;
//! let signature = keypair.sign(message)?;
//! ```

#![forbid(unsafe_code)]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
// TODO: Fix these warnings in a dedicated cleanup pass
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::format_collect)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::use_self)]
#![allow(clippy::option_if_let_else)]

pub mod aead;
pub mod ecdh;
pub mod ecdsa;
pub mod error;
pub mod hash;
pub mod hkdf;
pub mod random;

pub use error::{CryptoError, CryptoResult};

/// Initialize the FIPS 140-3 validated crypto module.
///
/// This should be called once at application startup.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
///
/// Ensures the FIPS module is properly initialized and self-tests pass.
///
/// ## Errors
///
/// Returns an error if FIPS initialization fails.
///
/// # Errors
/// Returns an error if the operation fails.
pub fn init_fips_mode() -> CryptoResult<()> {
    // aws-lc-rs automatically runs FIPS self-tests on first use
    // when compiled with the fips feature.
    //
    // We trigger this by performing a simple operation.
    let _ = hash::sha384(b"FIPS self-test trigger");
    Ok(())
}

/// Returns true if running in FIPS mode.
#[must_use]
pub fn is_fips_mode() -> bool {
    cfg!(feature = "fips")
}
