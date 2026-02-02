//! CNSA 2.0 compliant HKDF key derivation.
//!
//! ## CNSA 2.0 Requirements
//!
//! HKDF must use SHA-384 or SHA-512 as the underlying hash function.
//! SHA-256 based HKDF is **forbidden**.
//!
//! ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment)

use crate::error::{CryptoError, CryptoResult};
use aws_lc_rs::hkdf::{self, Prk, Salt, HKDF_SHA384, HKDF_SHA512};

/// HKDF-SHA384 output key material.
pub struct HkdfSha384Output {
    prk: Prk,
}

impl HkdfSha384Output {
    /// Extracts a pseudo-random key from input key material.
    ///
    /// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment)
    ///
    /// ## Arguments
    ///
    /// * `salt` - Optional salt value. If None, uses a zero-filled salt.
    /// * `ikm` - Input key material.
    #[must_use]
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let salt_obj = match salt {
            Some(s) => Salt::new(HKDF_SHA384, s),
            None => Salt::new(HKDF_SHA384, &[]),
        };
        let prk = salt_obj.extract(ikm);
        Self { prk }
    }

    /// Expands the PRK into output key material.
    ///
    /// ## Arguments
    ///
    /// * `info` - Context and application-specific information.
    /// * `output` - Buffer to fill with derived key material.
    ///
    /// ## Errors
    ///
    /// Returns an error if the output length is too large.
    pub fn expand(&self, info: &[&[u8]], output: &mut [u8]) -> CryptoResult<()> {
        let okm = self
            .prk
            .expand(info, HkdfLen(output.len()))
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        okm.fill(output)
            .map_err(|_| CryptoError::KeyDerivationFailed)
    }

    /// Convenience method to extract and expand in one step.
    ///
    /// ## Arguments
    ///
    /// * `salt` - Optional salt value.
    /// * `ikm` - Input key material.
    /// * `info` - Context and application-specific information.
    /// * `output` - Buffer to fill with derived key material.
    ///
    /// ## Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive(salt: Option<&[u8]>, ikm: &[u8], info: &[&[u8]], output: &mut [u8]) -> CryptoResult<()> {
        let extracted = Self::extract(salt, ikm);
        extracted.expand(info, output)
    }
}

/// HKDF-SHA512 output key material.
pub struct HkdfSha512Output {
    prk: Prk,
}

impl HkdfSha512Output {
    /// Extracts a pseudo-random key from input key material.
    ///
    /// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment)
    #[must_use]
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        let salt_obj = match salt {
            Some(s) => Salt::new(HKDF_SHA512, s),
            None => Salt::new(HKDF_SHA512, &[]),
        };
        let prk = salt_obj.extract(ikm);
        Self { prk }
    }

    /// Expands the PRK into output key material.
    ///
    /// ## Errors
    ///
    /// Returns an error if the output length is too large.
    pub fn expand(&self, info: &[&[u8]], output: &mut [u8]) -> CryptoResult<()> {
        let okm = self
            .prk
            .expand(info, HkdfLen(output.len()))
            .map_err(|_| CryptoError::KeyDerivationFailed)?;

        okm.fill(output)
            .map_err(|_| CryptoError::KeyDerivationFailed)
    }

    /// Convenience method to extract and expand in one step.
    ///
    /// ## Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive(salt: Option<&[u8]>, ikm: &[u8], info: &[&[u8]], output: &mut [u8]) -> CryptoResult<()> {
        let extracted = Self::extract(salt, ikm);
        extracted.expand(info, output)
    }
}

/// Helper struct for specifying HKDF output length.
struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derives key material using HKDF-SHA384.
///
/// This is a convenience function for one-shot key derivation.
///
/// ## Arguments
///
/// * `salt` - Optional salt value.
/// * `ikm` - Input key material.
/// * `info` - Context and application-specific information.
/// * `output` - Buffer to fill with derived key material.
///
/// ## Errors
///
/// Returns an error if key derivation fails.
///
/// ## Example
///
/// ```
/// use sbc_crypto::hkdf::hkdf_sha384;
///
/// let ikm = b"input key material";
/// let salt = b"salt";
/// let info = b"context info";
/// let mut output = [0u8; 32];
///
/// hkdf_sha384(Some(salt), ikm, &[info], &mut output).expect("HKDF failed");
/// ```
pub fn hkdf_sha384(salt: Option<&[u8]>, ikm: &[u8], info: &[&[u8]], output: &mut [u8]) -> CryptoResult<()> {
    HkdfSha384Output::derive(salt, ikm, info, output)
}

/// Derives key material using HKDF-SHA512.
///
/// This is a convenience function for one-shot key derivation.
///
/// ## Errors
///
/// Returns an error if key derivation fails.
pub fn hkdf_sha512(salt: Option<&[u8]>, ikm: &[u8], info: &[&[u8]], output: &mut [u8]) -> CryptoResult<()> {
    HkdfSha512Output::derive(salt, ikm, info, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha384_basic() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let mut output = [0u8; 32];

        hkdf_sha384(Some(salt), ikm, &[info], &mut output).unwrap();

        // Output should not be all zeros
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_hkdf_sha512_basic() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";
        let mut output = [0u8; 64];

        hkdf_sha512(Some(salt), ikm, &[info], &mut output).unwrap();

        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        hkdf_sha384(Some(salt), ikm, &[info], &mut output1).unwrap();
        hkdf_sha384(Some(salt), ikm, &[info], &mut output2).unwrap();

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_hkdf_different_info_different_output() {
        let ikm = b"input key material";
        let salt = b"salt";

        let mut output1 = [0u8; 32];
        let mut output2 = [0u8; 32];

        hkdf_sha384(Some(salt), ikm, &[b"info1"], &mut output1).unwrap();
        hkdf_sha384(Some(salt), ikm, &[b"info2"], &mut output2).unwrap();

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_hkdf_no_salt() {
        let ikm = b"input key material";
        let info = b"info";
        let mut output = [0u8; 32];

        // Should work without salt
        hkdf_sha384(None, ikm, &[info], &mut output).unwrap();
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_hkdf_multiple_info() {
        let ikm = b"input key material";
        let salt = b"salt";
        let mut output = [0u8; 32];

        // Multiple info segments
        hkdf_sha384(Some(salt), ikm, &[b"part1", b"part2"], &mut output).unwrap();
        assert_ne!(output, [0u8; 32]);
    }
}
