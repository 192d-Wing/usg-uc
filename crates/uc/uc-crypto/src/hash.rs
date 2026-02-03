//! CNSA 2.0 compliant hash functions.
//!
//! ## CNSA 2.0 Requirements
//!
//! - **Allowed**: SHA-384, SHA-512
//! - **Forbidden**: SHA-256, SHA-1, MD5
//!
//! This module only exposes SHA-384 and SHA-512. SHA-256 is intentionally
//! not provided to enforce CNSA 2.0 compliance.
//!
//! ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)

use aws_lc_rs::digest;
use aws_lc_rs::hmac;

/// SHA-384 digest length in bytes.
pub const SHA384_OUTPUT_LEN: usize = 48;

/// SHA-512 digest length in bytes.
pub const SHA512_OUTPUT_LEN: usize = 64;

/// Computes SHA-384 hash of the input data.
///
/// SHA-384 is the minimum hash algorithm permitted by CNSA 2.0.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
///
/// ## Example
///
/// ```
/// use uc_crypto::hash::sha384;
///
/// let digest = sha384(b"hello world");
/// assert_eq!(digest.len(), 48);
/// ```
#[must_use]
pub fn sha384(data: &[u8]) -> [u8; SHA384_OUTPUT_LEN] {
    let digest_value = digest::digest(&digest::SHA384, data);
    let mut output = [0u8; SHA384_OUTPUT_LEN];
    output.copy_from_slice(digest_value.as_ref());
    output
}

/// Computes SHA-512 hash of the input data.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
///
/// ## Example
///
/// ```
/// use uc_crypto::hash::sha512;
///
/// let digest = sha512(b"hello world");
/// assert_eq!(digest.len(), 64);
/// ```
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; SHA512_OUTPUT_LEN] {
    let digest_value = digest::digest(&digest::SHA512, data);
    let mut output = [0u8; SHA512_OUTPUT_LEN];
    output.copy_from_slice(digest_value.as_ref());
    output
}

/// Incremental SHA-384 hasher.
///
/// Use this for hashing data in chunks.
///
/// ## Example
///
/// ```
/// use uc_crypto::hash::Sha384;
///
/// let mut hasher = Sha384::new();
/// hasher.update(b"hello ");
/// hasher.update(b"world");
/// let digest = hasher.finish();
/// ```
pub struct Sha384 {
    context: digest::Context,
}

impl Sha384 {
    /// Creates a new SHA-384 hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            context: digest::Context::new(&digest::SHA384),
        }
    }

    /// Updates the hasher with additional data.
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// Finalizes the hash and returns the digest.
    ///
    /// Consumes the hasher.
    #[must_use]
    pub fn finish(self) -> [u8; SHA384_OUTPUT_LEN] {
        let digest_value = self.context.finish();
        let mut output = [0u8; SHA384_OUTPUT_LEN];
        output.copy_from_slice(digest_value.as_ref());
        output
    }
}

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

/// Incremental SHA-512 hasher.
///
/// Use this for hashing data in chunks.
pub struct Sha512 {
    context: digest::Context,
}

impl Sha512 {
    /// Creates a new SHA-512 hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            context: digest::Context::new(&digest::SHA512),
        }
    }

    /// Updates the hasher with additional data.
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// Finalizes the hash and returns the digest.
    ///
    /// Consumes the hasher.
    #[must_use]
    pub fn finish(self) -> [u8; SHA512_OUTPUT_LEN] {
        let digest_value = self.context.finish();
        let mut output = [0u8; SHA512_OUTPUT_LEN];
        output.copy_from_slice(digest_value.as_ref());
        output
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes HMAC-SHA384.
///
/// HMAC-SHA384 is the minimum HMAC algorithm permitted by CNSA 2.0.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
///
/// ## Example
///
/// ```
/// use uc_crypto::hash::hmac_sha384;
///
/// let mac = hmac_sha384(b"secret key", b"message");
/// assert_eq!(mac.len(), 48);
/// ```
#[must_use]
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; SHA384_OUTPUT_LEN] {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA384, key);
    let tag = hmac::sign(&signing_key, data);
    let mut output = [0u8; SHA384_OUTPUT_LEN];
    output.copy_from_slice(tag.as_ref());
    output
}

/// Computes HMAC-SHA512.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
///
/// ## Example
///
/// ```
/// use uc_crypto::hash::hmac_sha512;
///
/// let mac = hmac_sha512(b"secret key", b"message");
/// assert_eq!(mac.len(), 64);
/// ```
#[must_use]
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; SHA512_OUTPUT_LEN] {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA512, key);
    let tag = hmac::sign(&signing_key, data);
    let mut output = [0u8; SHA512_OUTPUT_LEN];
    output.copy_from_slice(tag.as_ref());
    output
}

/// Verifies HMAC-SHA384.
///
/// Returns `true` if the provided tag matches the computed HMAC.
///
/// ## Example
///
/// ```
/// use uc_crypto::hash::{hmac_sha384, verify_hmac_sha384};
///
/// let mac = hmac_sha384(b"key", b"message");
/// assert!(verify_hmac_sha384(b"key", b"message", &mac));
/// ```
#[must_use]
pub fn verify_hmac_sha384(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA384, key);
    hmac::verify(&signing_key, data, tag).is_ok()
}

/// Verifies HMAC-SHA512.
///
/// Returns `true` if the provided tag matches the computed HMAC.
#[must_use]
pub fn verify_hmac_sha512(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    let signing_key = hmac::Key::new(hmac::HMAC_SHA512, key);
    hmac::verify(&signing_key, data, tag).is_ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // Test vectors from NIST CAVP

    #[test]
    fn test_sha384_empty() {
        let digest = sha384(b"");
        // Known SHA-384 of empty string
        let expected = [
            0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1,
            0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf,
            0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a,
            0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha512_empty() {
        let digest = sha512(b"");
        // Known SHA-512 of empty string
        let expected = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha384_incremental() {
        let mut hasher = Sha384::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let incremental = hasher.finish();

        let one_shot = sha384(b"hello world");
        assert_eq!(incremental, one_shot);
    }

    #[test]
    fn test_sha512_incremental() {
        let mut hasher = Sha512::new();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let incremental = hasher.finish();

        let one_shot = sha512(b"hello world");
        assert_eq!(incremental, one_shot);
    }

    #[test]
    fn test_hmac_sha384() {
        let mac = hmac_sha384(b"key", b"message");
        assert_eq!(mac.len(), 48);
        // Verify
        assert!(verify_hmac_sha384(b"key", b"message", &mac));
        // Wrong key should fail
        assert!(!verify_hmac_sha384(b"wrong", b"message", &mac));
    }

    #[test]
    fn test_hmac_sha512() {
        let mac = hmac_sha512(b"key", b"message");
        assert_eq!(mac.len(), 64);
        assert!(verify_hmac_sha512(b"key", b"message", &mac));
    }
}
