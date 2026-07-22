//! AES-256 in Counter (CTR) mode.
//!
//! ## CNSA 2.0 Compliance
//!
//! AES-256 only (no AES-128/192). Provided specifically for the RFC 3711 SRTP
//! key-derivation function, whose PRF is AES in counter mode — SRTP requires it
//! for interoperability with other endpoints (libsrtp, pion, browsers). FIPS
//! 140-3 validated via aws-lc-rs when the `fips` feature is enabled.

use aws_lc_rs::cipher::{AES_256, EncryptingKey, EncryptionContext, UnboundCipherKey};
use aws_lc_rs::iv::FixedLength;

use crate::error::{CryptoError, CryptoResult};

/// AES-256 key length in bytes.
pub const AES_256_KEY_LEN: usize = 32;

/// Applies the AES-256-CTR keystream to `in_out` in place.
///
/// Starts from the 16-byte initial counter block `iv`. Encryption and
/// decryption are the same operation (XOR with the keystream); pass a
/// zero-filled buffer to obtain the raw keystream (as the SRTP KDF does).
///
/// # Errors
/// [`CryptoError::InvalidKeyMaterial`] if `key` is not 32 bytes;
/// [`CryptoError::KeyDerivationFailed`] if the cipher operation fails.
pub fn aes256_ctr(key: &[u8], iv: &[u8; 16], in_out: &mut [u8]) -> CryptoResult<()> {
    if key.len() != AES_256_KEY_LEN {
        return Err(CryptoError::InvalidKeyMaterial);
    }
    let unbound =
        UnboundCipherKey::new(&AES_256, key).map_err(|_| CryptoError::InvalidKeyMaterial)?;
    let encrypting = EncryptingKey::ctr(unbound).map_err(|_| CryptoError::KeyDerivationFailed)?;
    let context = EncryptionContext::Iv128(FixedLength::from(*iv));
    encrypting
        .less_safe_encrypt(in_out, context)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(())
}

// `aes256_ctr` is exercised as a known-answer by proto-srtp's
// `kdf_matches_reference_srtp_vector` (it runs through this function and must
// equal pion/libsrtp's AES-CM output) and end-to-end by the srtp-audio gate.
// A standalone unit test here would only add hard-coded key material that trips
// CodeQL's crypto-value scan for no extra coverage.
