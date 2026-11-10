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
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AES-256-GCM key length in bytes.
pub const KEY_LEN: usize = 32;

/// AES-256-GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// AES-256-GCM key for AEAD operations.
///
/// ## Key material lifecycle
///
/// - The 32-byte key array owned by this struct is wiped when the key is
///   dropped (`ZeroizeOnDrop`).
/// - Each `seal`/`open` builds a short-lived aws-lc AES key schedule from
///   these bytes. aws-lc wipes it (`EVP_AEAD_CTX_cleanup` ->
///   `OPENSSL_cleanse`) when it is freed at the end of the call; Rust cannot
///   reach it.
/// - Not covered: the caller's copy of the array passed to [`Self::new`]
///   (`[u8; 32]` is `Copy`; zeroize it yourself), and stack copies the
///   compiler may leave when the key is moved.
///
/// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment), SC-4, SI-16
// NIST 800-53 Rev5: SC-12, SC-4 (POA&M-160 closed: key array wiped on drop).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Aes256GcmKey {
    key_bytes: [u8; KEY_LEN],
}

impl Aes256GcmKey {
    /// Creates a new key from raw bytes.
    ///
    /// The array is copied in; the caller still owns (and should zeroize)
    /// its own copy.
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
        let mut key_bytes = random::generate_key_256()?;
        let key = Self { key_bytes };
        // `[u8; 32]` is `Copy`: wipe the local so only `key` holds it.
        key_bytes.zeroize();
        Ok(key)
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
    /// The ciphertext must include the authentication tag at the end. The
    /// returned plaintext is owned by the caller, who is responsible for
    /// wiping it if it is sensitive (e.g. wrap it in `zeroize::Zeroizing`).
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

        // NIST 800-53 Rev5: SC-4 (POA&M-161 closed): decrypt in place and hand back the same buffer; the
        // former `plaintext.to_vec()` left an unwiped plaintext copy behind.
        let mut in_out = ciphertext.to_vec();
        let Ok(plaintext_len) = opening_key
            .open_in_place(Aad::from(aad), &mut in_out)
            .map(|p| p.len())
        else {
            in_out.zeroize();
            return Err(CryptoError::OpenFailed);
        };
        in_out.truncate(plaintext_len);
        Ok(in_out)
    }
}

impl std::fmt::Debug for Aes256GcmKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Aes256GcmKey")
            .field("key_bytes", &"[REDACTED]")
            .finish()
    }
}

/// AES-256-GCM key with a pre-expanded key schedule for repeated use.
///
/// Unlike [`Aes256GcmKey`], which creates a new `UnboundKey` (AES key schedule)
/// on every `seal`/`open` call, this type expands the key schedule once at
/// construction and reuses it across all subsequent operations. This saves
/// ~100ns per packet on the SRTP hot path.
///
/// Uses `LessSafeKey` from aws-lc-rs, which requires the caller to manage
/// nonce uniqueness (appropriate for SRTP where nonces are derived from
/// packet index + SSRC).
///
/// The expanded key lives inside an opaque aws-lc `EVP_AEAD_CTX`; aws-lc
/// cleanses it when this value is dropped. Rust code cannot wipe it.
pub struct CachedAeadKey {
    inner: aead::LessSafeKey,
}

impl CachedAeadKey {
    /// Creates a new cached AEAD key from raw key bytes.
    ///
    /// The AES key schedule is expanded once here and reused for all
    /// subsequent `seal`/`open` calls.
    ///
    /// # Errors
    /// Returns an error if the key bytes are invalid.
    pub fn new(key_bytes: &[u8; KEY_LEN]) -> CryptoResult<Self> {
        let unbound_key = aead::UnboundKey::new(&AES_256_GCM, key_bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        Ok(Self {
            inner: aead::LessSafeKey::new(unbound_key),
        })
    }

    /// Encrypts plaintext with additional authenticated data.
    ///
    /// Returns the ciphertext with the authentication tag appended.
    ///
    /// # Errors
    /// Returns an error if encryption fails.
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let mut in_out = plaintext.to_vec();
        in_out.reserve(TAG_LEN);

        self.inner
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| CryptoError::SealFailed)?;

        Ok(in_out)
    }

    /// Decrypts ciphertext with additional authenticated data.
    ///
    /// The ciphertext must include the authentication tag at the end.
    ///
    /// # Errors
    /// Returns an error if decryption or authentication fails.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> CryptoResult<Vec<u8>> {
        if ciphertext.len() < TAG_LEN {
            return Err(CryptoError::OpenFailed);
        }

        let nonce = Nonce::assume_unique_for_key(*nonce);
        let mut in_out = ciphertext.to_vec();
        let Ok(plaintext_len) = self
            .inner
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map(|p| p.len())
        else {
            // NIST 800-53 Rev5: SC-4 (POA&M-161 closed): wipe the working buffer on failure as well.
            in_out.zeroize();
            return Err(CryptoError::OpenFailed);
        };

        // Truncate in-place instead of copying: open_in_place returns
        // a subslice of in_out (ciphertext minus the 16-byte auth tag).
        in_out.truncate(plaintext_len);
        Ok(in_out)
    }

    /// Encrypts plaintext into a caller-provided buffer, avoiding allocation.
    ///
    /// The buffer is cleared, filled with plaintext, and sealed in-place.
    /// On return it contains `ciphertext || auth_tag`.
    ///
    /// # Errors
    /// Returns an error if encryption fails.
    pub fn seal_into(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        buf: &mut Vec<u8>,
    ) -> CryptoResult<()> {
        buf.clear();
        buf.extend_from_slice(plaintext);
        buf.reserve(TAG_LEN);

        let nonce = Nonce::assume_unique_for_key(*nonce);
        self.inner
            .seal_in_place_append_tag(nonce, Aad::from(aad), buf)
            .map_err(|_| CryptoError::SealFailed)?;
        Ok(())
    }

    /// Encrypts `in_out` in place and returns the detached authentication tag.
    ///
    /// No heap allocation: the ciphertext overwrites the plaintext (same
    /// length) and the 16-byte tag is returned by value, for the caller to
    /// place where its wire format needs it. This is the per-packet path for
    /// fixed-buffer SRTP senders (RFC 7714 §8.2: ciphertext then tag).
    ///
    /// The caller is responsible for nonce uniqueness under this key
    /// (RFC 7714 §8.4 / NIST SP 800-38D §8: a repeated nonce breaks both
    /// confidentiality and authenticity).
    ///
    /// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection), SC-5 (no
    /// per-packet allocation)
    ///
    /// # Errors
    /// Returns an error if encryption fails. The contents of `in_out` are
    /// then unspecified and must not be sent.
    pub fn seal_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        in_out: &mut [u8],
    ) -> CryptoResult<[u8; TAG_LEN]> {
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let tag = self
            .inner
            .seal_in_place_separate_tag(nonce, Aad::from(aad), in_out)
            .map_err(|_| CryptoError::SealFailed)?;
        // AES-256-GCM always yields a 16-byte tag; fail closed rather than
        // truncate or pad if the backend ever reports another length.
        <[u8; TAG_LEN]>::try_from(tag.as_ref()).map_err(|_| CryptoError::SealFailed)
    }

    /// Decrypts ciphertext into a caller-provided buffer, avoiding allocation.
    ///
    /// The buffer is cleared and filled with ciphertext, then decrypted
    /// in-place. On return it contains the plaintext (tag stripped). The
    /// caller owns `buf` and is responsible for wiping it.
    ///
    /// # Errors
    /// Returns an error if decryption or authentication fails.
    pub fn open_into(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        buf: &mut Vec<u8>,
    ) -> CryptoResult<()> {
        if ciphertext.len() < TAG_LEN {
            return Err(CryptoError::OpenFailed);
        }

        buf.clear();
        buf.extend_from_slice(ciphertext);

        let nonce = Nonce::assume_unique_for_key(*nonce);
        let plaintext_len = self
            .inner
            .open_in_place(nonce, Aad::from(aad), buf)
            .map_err(|_| CryptoError::OpenFailed)?
            .len();

        buf.truncate(plaintext_len);
        Ok(())
    }
}

impl std::fmt::Debug for CachedAeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedAeadKey")
            .field("algorithm", &"AES-256-GCM")
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
        assert_eq!(decrypted, [] as [u8; 0]);
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

    // POA&M-160 (closed): the derive set must cover the key array. `Zeroize` and
    // `ZeroizeOnDrop` are derived over the same fields, so wiping through
    // `Zeroize` proves the drop path reaches `key_bytes`.
    #[test]
    fn test_key_zeroize_wipes_key_bytes() {
        fn assert_zod<T: ZeroizeOnDrop>() {}
        assert_zod::<Aes256GcmKey>();

        let mut key = Aes256GcmKey::new([0xA5; KEY_LEN]).unwrap();
        assert_eq!(key.as_bytes(), &[0xA5; KEY_LEN]);
        key.zeroize();
        assert_eq!(key.as_bytes(), &[0u8; KEY_LEN]);
    }

    #[test]
    fn test_open_returns_single_buffer() {
        let key = Aes256GcmKey::generate().unwrap();
        let nonce = random::generate_nonce().unwrap();
        let ct = key.seal(&nonce, b"", b"0123456789").unwrap();
        let pt = key.open(&nonce, b"", &ct).unwrap();
        assert_eq!(pt, b"0123456789");
        // Returned vec is the in-place working buffer (no second copy).
        assert!(pt.capacity() >= ct.len());
    }

    #[test]
    fn test_cached_open_roundtrip_and_failure() {
        let ck = CachedAeadKey::new(Aes256GcmKey::generate().unwrap().as_bytes()).unwrap();
        let nonce = random::generate_nonce().unwrap();
        let mut ct = ck.seal(&nonce, b"a", b"secret").unwrap();
        let pt = ck.open(&nonce, b"a", &ct).unwrap();
        assert_eq!(pt, b"secret");
        assert!(pt.capacity() >= ct.len());
        ct[0] ^= 1;
        assert!(ck.open(&nonce, b"a", &ct).is_err());
    }

    // Known answer: NIST GCM test case 16 (AES-256, 60-byte plaintext,
    // 20-byte AAD) from the McGrew/Viega GCM specification.
    #[test]
    fn test_seal_in_place_known_answer() {
        fn hex(s: &str) -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        }
        let key: [u8; KEY_LEN] =
            hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
                .try_into()
                .unwrap();
        let nonce: [u8; NONCE_LEN] = hex("cafebabefacedbaddecaf888").try_into().unwrap();
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let mut buf = hex(concat!(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
            "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
        ));
        let expected_ct = hex(concat!(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
        ));
        let expected_tag = hex("76fc6ece0f4e1768cddf8853bb2d551b");

        let ck = CachedAeadKey::new(&key).unwrap();
        let tag = ck.seal_in_place(&nonce, &aad, &mut buf).unwrap();
        assert_eq!(buf, expected_ct);
        assert_eq!(tag.as_slice(), expected_tag.as_slice());
    }

    // `seal_in_place` must be byte-identical to `seal` (ciphertext || tag)
    // for every length across several AES block boundaries, including empty.
    #[test]
    fn test_seal_in_place_equals_seal_over_lengths() {
        let ck = CachedAeadKey::new(&[0x42; KEY_LEN]).unwrap();
        for len in 0..=300usize {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
            let aad: Vec<u8> = (0..(len % 73)).map(|i| i as u8).collect();
            let mut nonce = [0u8; NONCE_LEN];
            nonce[..8].copy_from_slice(&(len as u64).to_be_bytes());

            let expected = ck.seal(&nonce, &aad, &plaintext).unwrap();

            let mut in_out = plaintext.clone();
            let tag = ck.seal_in_place(&nonce, &aad, &mut in_out).unwrap();
            assert_eq!(in_out.len(), len);
            assert_eq!(&expected[..len], in_out.as_slice(), "ciphertext, len {len}");
            assert_eq!(&expected[len..], tag.as_slice(), "tag, len {len}");

            // And the detached form opens with the existing `open`.
            in_out.extend_from_slice(&tag);
            assert_eq!(ck.open(&nonce, &aad, &in_out).unwrap(), plaintext);
        }
    }

    #[test]
    fn test_seal_in_place_tag_binds_aad_and_nonce() {
        let ck = CachedAeadKey::new(&[0x11; KEY_LEN]).unwrap();
        let nonce = [7u8; NONCE_LEN];
        let mut buf = *b"payload bytes";
        let tag = ck.seal_in_place(&nonce, b"hdr", &mut buf).unwrap();
        let mut wire = buf.to_vec();
        wire.extend_from_slice(&tag);
        assert!(ck.open(&nonce, b"hdX", &wire).is_err());
        assert!(ck.open(&[8u8; NONCE_LEN], b"hdr", &wire).is_err());
        assert_eq!(ck.open(&nonce, b"hdr", &wire).unwrap(), b"payload bytes");
    }

    #[test]
    fn test_open_tag_failure_paths() {
        let key = Aes256GcmKey::generate().unwrap();
        let nonce = random::generate_nonce().unwrap();
        let ct = key.seal(&nonce, b"aad", b"secret plaintext").unwrap();
        // Shorter than the tag: rejected before any decryption.
        assert!(key.open(&nonce, b"aad", &ct[..TAG_LEN - 1]).is_err());
        assert!(key.open(&nonce, b"aad", &[]).is_err());
        // Tag-only (empty body, wrong tag) and flipped tag byte fail closed.
        assert!(key.open(&nonce, b"aad", &[0u8; TAG_LEN]).is_err());
        let mut bad = ct.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(key.open(&nonce, b"aad", &bad).is_err());
        // Wrong nonce fails.
        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 1;
        assert!(key.open(&wrong_nonce, b"aad", &ct).is_err());
        // Key remains usable after failures (failure wipe touches only the temp buffer).
        assert_eq!(key.open(&nonce, b"aad", &ct).unwrap(), b"secret plaintext");
    }

    #[test]
    fn test_key_debug_redacted() {
        let key = Aes256GcmKey::generate().unwrap();
        let debug_str = format!("{key:?}");
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains(&format!("{:?}", key.as_bytes())));
    }
}
