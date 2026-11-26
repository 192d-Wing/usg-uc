//! SHA-256 for stored legacy digests.
//!
//! CNSA-EXCEPTION: POA&M-211. SBC API keys are stored as SHA-256 hex
//! digests (operator-supplied `SBC_API_KEY_SHA256`); the stored format is
//! kept until the operator re-keys to SHA-384. SHA-256 is computed by the
//! aws-lc FIPS module, never for new tokens or signatures.
//!
//! ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection), IA-5
// POAM: POA&M-211 (SHA-256 API-key digests; migrate to SHA-384).

use aws_lc_rs::digest;

/// SHA-256 output length in bytes.
pub const SHA256_OUTPUT_LEN: usize = 32;

/// Computes SHA-256 of `data` (FIPS 180-4).
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; SHA256_OUTPUT_LEN] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; SHA256_OUTPUT_LEN];
    out.copy_from_slice(d.as_ref());
    out
}
