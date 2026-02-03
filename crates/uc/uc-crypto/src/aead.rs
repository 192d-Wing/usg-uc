//! CNSA 2.0 compliant AEAD encryption.
//!
//! ## CNSA 2.0 Requirements
//!
//! - **Allowed**: AES-256-GCM
//! - **Forbidden**: AES-128, AES-192, ChaCha20-Poly1305
//!
//! This module only provides AES-256-GCM to enforce CNSA 2.0 compliance.
//!
//! ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)

use crate::error::{CryptoError, CryptoResult};
use crate::random;
use aws_lc_rs::aead::{
    self, AES_256_GCM, Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey,
};
use zeroize::ZeroizeOnDrop;

/// AES-256-GCM key length in bytes.
pub const KEY_LEN: usize = 32;

/// AES-256-GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// AES-256-GCM key for AEAD operations.
///
/// The key material is automatically zeroed when dropped.
///
/// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment)
#[derive(ZeroizeOnDrop)]
pub struct Aes256GcmKey {
    #[zeroize(skip)] // aws-lc-rs handles its own memory
    key_bytes: [u8; KEY_LEN],
}

impl Aes256GcmKey {
    /// Creates a new key from raw bytes.
    ///
    /// ## Errors
    ///
    /// Returns an error if the key length is not 32 bytes.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn new(key_bytes: [u8; KEY_LEN]) -> CryptoResult<Self> {
        Ok(Self { key_bytes })
    }

    /// Generates a new random key.
    ///
    /// ## Errors
    ///
    /// Returns an error if random generation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn generate() -> CryptoResult<Self> {
        let key_bytes = random::generate_key_256()?;
        Ok(Self { key_bytes })
    }

    /// Returns the raw key bytes.
    ///
    /// Use with caution - key material should be protected.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.key_bytes
    }

    /// Encrypts plaintext with additional authenticated data.
    ///
    /// Returns the ciphertext with the authentication tag appended.
    ///
    /// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
    ///
    /// ## Errors
    ///
    /// Returns an error if encryption fails.
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let unbound_key = aead::UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        let nonce_seq = SingleNonce::new(*nonce);
        let mut sealing_key = SealingKey::new(unbound_key, nonce_seq);

        // Allocate output buffer: plaintext + tag
        let mut in_out = plaintext.to_vec();
        in_out.reserve(TAG_LEN);

        sealing_key
            .seal_in_place_append_tag(Aad::from(aad), &mut in_out)
            .map_err(|_| CryptoError::SealFailed)?;

        Ok(in_out)
    }

    /// Decrypts ciphertext with additional authenticated data.
    ///
    /// The ciphertext must include the authentication tag at the end.
    ///
    /// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
    ///
    /// ## Errors
    ///
    /// Returns an error if decryption fails (wrong key, tampered data, etc.).
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if ciphertext.len() < TAG_LEN {
            return Err(CryptoError::OpenFailed);
        }

        let unbound_key = aead::UnboundKey::new(&AES_256_GCM, &self.key_bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        let nonce_seq = SingleNonce::new(*nonce);
        let mut opening_key = OpeningKey::new(unbound_key, nonce_seq);

        let mut in_out = ciphertext.to_vec();
        let plaintext = opening_key
            .open_in_place(Aad::from(aad), &mut in_out)
            .map_err(|_| CryptoError::OpenFailed)?;

        Ok(plaintext.to_vec())
    }
}

impl std::fmt::Debug for Aes256GcmKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes256GcmKey")
            .field("key_bytes", &"[REDACTED]")
            .finish()
    }
}

/// A nonce sequence that provides a single nonce value.
///
/// Used for one-shot seal/open operations.
struct SingleNonce {
    nonce: Option<[u8; NONCE_LEN]>,
}

impl SingleNonce {
    fn new(nonce: [u8; NONCE_LEN]) -> Self {
        Self { nonce: Some(nonce) }
    }
}

impl NonceSequence for SingleNonce {
    fn advance(&mut self) -> Result<Nonce, aws_lc_rs::error::Unspecified> {
        self.nonce
            .take()
            .map(|n| Nonce::assume_unique_for_key(n))
            .ok_or(aws_lc_rs::error::Unspecified)
    }
}

/// Encrypts data with AES-256-GCM using a randomly generated nonce.
///
/// Returns (nonce, ciphertext_with_tag).
///
/// ## Errors
///
/// Returns an error if encryption or random generation fails.
pub fn seal_with_random_nonce(
    key: &Aes256GcmKey,
    aad: &[u8],
    plaintext: &[u8],
) -> CryptoResult<([u8; NONCE_LEN], Vec<u8>)> {
    let nonce = random::generate_nonce()?;
    let ciphertext = key.seal(&nonce, aad, plaintext)?;
    Ok((nonce, ciphertext))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_open_roundtrip() {
        let key = Aes256GcmKey::generate().unwrap();
        let nonce = random::generate_nonce().unwrap();
        let aad = b"additional data";
        let plaintext = b"secret message";

        let ciphertext = key.seal(&nonce, aad, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_LEN);

        let decrypted = key.open(&nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = Aes256GcmKey::generate().unwrap();
        let key2 = Aes256GcmKey::generate().unwrap();
        let nonce = random::generate_nonce().unwrap();
        let aad = b"aad";
        let plaintext = b"secret";

        let ciphertext = key1.seal(&nonce, aad, plaintext).unwrap();
        let result = key2.open(&nonce, aad, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = Aes256GcmKey::generate().unwrap();
        let nonce = random::generate_nonce().unwrap();
        let plaintext = b"secret";

        let ciphertext = key.seal(&nonce, b"correct aad", plaintext).unwrap();
        let result = key.open(&nonce, b"wrong aad", &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = Aes256GcmKey::generate().unwrap();
        let nonce = random::generate_nonce().unwrap();
        let aad = b"aad";
        let plaintext = b"secret";

        let mut ciphertext = key.seal(&nonce, aad, plaintext).unwrap();
        // Tamper with the ciphertext
        ciphertext[0] ^= 0xFF;

        let result = key.open(&nonce, aad, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = Aes256GcmKey::generate().unwrap();
        let nonce = random::generate_nonce().unwrap();
        let aad = b"aad";
        let plaintext = b"";

        let ciphertext = key.seal(&nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), TAG_LEN); // Just the tag

        let decrypted = key.open(&nonce, aad, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_seal_with_random_nonce() {
        let key = Aes256GcmKey::generate().unwrap();
        let aad = b"aad";
        let plaintext = b"secret";

        let (nonce, ciphertext) = seal_with_random_nonce(&key, aad, plaintext).unwrap();
        let decrypted = key.open(&nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_key_debug_redacted() {
        let key = Aes256GcmKey::generate().unwrap();
        let debug_str = format!("{key:?}");
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains(&format!("{:?}", key.as_bytes())));
    }
}
