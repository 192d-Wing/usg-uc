//! CNSA 2.0 compliant AEAD encryption.
//!
//! ## CNSA 2.0 Requirements
//!
//! - **Allowed**: AES-256-GCM
//! - **Forbidden**: AES-128, AES-192, ChaCha20-Poly1305
//!
//! This module only provides AES-256-GCM to enforce CNSA 2.0 compliance.
//!
//! ## FIPS 140-3 approved services (IG C.H)
//!
//! - [`RandomNonceKey`]: seal with a module-generated IV (approved). Use it
//!   for data at rest.
//! - [`Aes256GcmKey`]: open only (approved).
//! - [`CachedAeadKey`]: seal with a caller-built IV for RFC 7714 SRTP; not an
//!   approved service (POA&M-400). Its open is approved.
//! - TLS 1.2 record seal: [`crate::tls12::Tls12GcmSealer`] (approved).
//!
//! ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)

use crate::error::{CryptoError, CryptoResult};
use crate::random;
use aws_lc_rs::aead::{
    self, AES_256_GCM, Aad, BoundKey, Nonce, NonceSequence, OpeningKey, RandomizedNonceKey,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AES-256-GCM key length in bytes.
pub const KEY_LEN: usize = 32;

/// AES-256-GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length in bytes.
pub const TAG_LEN: usize = 16;

/// AES-256-GCM opening key (DTLS read side and blobs sealed elsewhere).
///
/// Open-only: AES-GCM seal with a caller-built IV is not an approved FIPS
/// 140-3 service (IG C.H). Seal data at rest with [`RandomNonceKey`].
///
/// ## Key material lifecycle
///
/// - The 32-byte key array owned by this struct is wiped when the key is
///   dropped (`ZeroizeOnDrop`).
/// - Each `open` builds a short-lived aws-lc AES key schedule from
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

/// AES-256-GCM key whose seal IV is generated inside the FIPS module.
///
/// The approved internal-IV service (SP 800-38D §8.2.2, FIPS 140-3 IG C.H):
/// aws-lc draws the 96-bit IV from its DRBG and returns it. Use this for
/// data at rest. Output is plain AES-256-GCM, so blobs open with
/// [`Aes256GcmKey`] and caller-IV blobs open here.
///
/// The key schedule is expanded once into an aws-lc `EVP_AEAD_CTX`, which
/// aws-lc cleanses on drop; no Rust copy of the key is kept. Not `Clone`.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection), SC-12, SC-28
pub struct RandomNonceKey {
    inner: RandomizedNonceKey,
}

impl RandomNonceKey {
    /// Creates a key from raw bytes. The caller still owns (and should
    /// zeroize) its copy.
    ///
    /// # Errors
    /// Returns an error if the module rejects the key.
    pub fn new(key_bytes: &[u8; KEY_LEN]) -> CryptoResult<Self> {
        let inner = RandomizedNonceKey::new(&AES_256_GCM, key_bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        Ok(Self { inner })
    }

    /// Generates a new random key.
    ///
    /// # Errors
    /// Returns an error if random generation or key setup fails.
    pub fn generate() -> CryptoResult<Self> {
        let mut key_bytes = random::generate_key_256()?;
        let key = Self::new(&key_bytes);
        key_bytes.zeroize();
        key
    }

    /// Encrypts `plaintext`; the module generates the IV.
    ///
    /// Returns `(nonce, ciphertext || tag)`.
    ///
    /// # Errors
    /// Returns an error if encryption fails.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> CryptoResult<([u8; NONCE_LEN], Vec<u8>)> {
        let mut in_out = Vec::with_capacity(plaintext.len() + TAG_LEN);
        in_out.extend_from_slice(plaintext);
        let Ok(nonce) = self
            .inner
            .seal_in_place_append_tag(Aad::from(aad), &mut in_out)
        else {
            in_out.zeroize();
            return Err(CryptoError::SealFailed);
        };
        Ok((*nonce.as_ref(), in_out))
    }

    /// Decrypts `ciphertext || tag`, including blobs sealed with a
    /// caller-built IV. The working buffer is wiped on failure; the
    /// returned plaintext is the caller's to wipe.
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
        let mut in_out = ciphertext.to_vec();
        let Ok(plaintext_len) = self
            .inner
            .open_in_place(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                &mut in_out,
            )
            .map(|p| p.len())
        else {
            in_out.zeroize();
            return Err(CryptoError::OpenFailed);
        };
        in_out.truncate(plaintext_len);
        Ok(in_out)
    }
}

impl std::fmt::Debug for RandomNonceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RandomNonceKey")
            .field("algorithm", &"AES-256-GCM")
            .field("key", &"[REDACTED]")
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
/// RFC 7714 SRTP only; for data at rest use [`RandomNonceKey`].
///
/// Uses `LessSafeKey` from aws-lc-rs, which requires the caller to manage
/// nonce uniqueness (RFC 7714 §8.1: IV derived from SSRC, ROC, SEQ and the
/// salt). Seal with a caller-built IV is not an approved FIPS 140-3 service
/// (IG C.H); open is approved.
///
/// The expanded key lives inside an opaque aws-lc `EVP_AEAD_CTX`; aws-lc
/// cleanses it when this value is dropped. Rust code cannot wipe it.
// POAM: POA&M-400 (SRTP/SRTCP seal: external IV, no approved aws-lc service fits RFC 7714).
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
    /// Not an approved FIPS 140-3 service (caller-built IV; POA&M-400).
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
    /// Not an approved FIPS 140-3 service (caller-built IV; POA&M-400).
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
    /// Not an approved FIPS 140-3 service (caller-built IV; POA&M-400).
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Caller-IV seal for test vectors (same bytes the removed
    /// `Aes256GcmKey::seal` produced).
    fn seal(key: &Aes256GcmKey, nonce: &[u8; NONCE_LEN], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        CachedAeadKey::new(key.as_bytes())
            .unwrap()
            .seal(nonce, aad, pt)
            .unwrap()
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let key = Aes256GcmKey::generate().unwrap();
        let nonce = random::generate_nonce().unwrap();
        let aad = b"additional data";
        let plaintext = b"secret message";

        let ciphertext = seal(&key, &nonce, aad, plaintext);
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

        let ciphertext = seal(&key1, &nonce, aad, plaintext);
        let result = key2.open(&nonce, aad, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_aad_fails() {
        let key = Aes256GcmKey::generate().unwrap();
        let nonce = random::generate_nonce().unwrap();
        let plaintext = b"secret";

        let ciphertext = seal(&key, &nonce, b"correct aad", plaintext);
        let result = key.open(&nonce, b"wrong aad", &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = Aes256GcmKey::generate().unwrap();
        let nonce = random::generate_nonce().unwrap();
        let aad = b"aad";
        let plaintext = b"secret";

        let mut ciphertext = seal(&key, &nonce, aad, plaintext);
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

        let ciphertext = seal(&key, &nonce, aad, plaintext);
        assert_eq!(ciphertext.len(), TAG_LEN); // Just the tag

        let decrypted = key.open(&nonce, aad, &ciphertext).unwrap();
        assert_eq!(decrypted, [] as [u8; 0]);
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
        let ct = seal(&key, &nonce, b"", b"0123456789");
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
            let nonce = random::generate_nonce().unwrap();

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
        let nonce = random::generate_nonce().unwrap();
        let mut other_nonce = nonce;
        other_nonce[0] ^= 1;
        let mut buf = *b"payload bytes";
        let tag = ck.seal_in_place(&nonce, b"hdr", &mut buf).unwrap();
        let mut wire = buf.to_vec();
        wire.extend_from_slice(&tag);
        assert!(ck.open(&nonce, b"hdX", &wire).is_err());
        assert!(ck.open(&other_nonce, b"hdr", &wire).is_err());
        assert_eq!(ck.open(&nonce, b"hdr", &wire).unwrap(), b"payload bytes");
    }

    #[test]
    fn test_open_tag_failure_paths() {
        let key = Aes256GcmKey::generate().unwrap();
        let nonce = random::generate_nonce().unwrap();
        let ct = seal(&key, &nonce, b"aad", b"secret plaintext");
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

// SR-15: removed caller-nonce seal on the general-purpose key. These doctests
// fail if `Aes256GcmKey::seal` or `seal_with_random_nonce` comes back.
/// ```compile_fail
/// use uc_crypto::aead::Aes256GcmKey;
/// let key = Aes256GcmKey::generate().unwrap();
/// let nonce = uc_crypto::random::generate_nonce().unwrap();
/// let _ = key.seal(&nonce, b"aad", b"plaintext");
/// ```
///
/// ```compile_fail
/// use uc_crypto::aead::{seal_with_random_nonce, Aes256GcmKey};
/// let key = Aes256GcmKey::generate().unwrap();
/// let _ = seal_with_random_nonce(&key, b"aad", b"plaintext");
/// ```
///
/// The opener and the internal-IV key stay available (compile check only):
///
/// ```no_run
/// use uc_crypto::aead::{Aes256GcmKey, RandomNonceKey};
/// let bytes = uc_crypto::random::generate_key_256().unwrap();
/// let sealer = RandomNonceKey::new(&bytes).unwrap();
/// let opener = Aes256GcmKey::new(bytes).unwrap();
/// let (nonce, ct) = sealer.seal(b"aad", b"plaintext").unwrap();
/// assert_eq!(opener.open(&nonce, b"aad", &ct).unwrap(), b"plaintext");
/// ```
#[cfg(doctest)]
mod sr15_no_caller_nonce_seal_on_aes256gcmkey {}

/// SR-15: `RandomNonceKey`, the module-internal-IV AES-256-GCM service
/// (plan section 4). Random runtime keys only.
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod random_nonce_key_tests {
    use super::*;
    use std::collections::HashSet;
    use zeroize::Zeroizing;

    /// Fails to compile if `$type` implements `$trait` (see
    /// `proto-dtls/tests/secret_hygiene.rs`).
    macro_rules! assert_not_impl {
        ($type:ty: $trait:path) => {
            const _: fn() = || {
                trait AmbiguousIfImpl<A> {
                    fn some_item() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                #[allow(dead_code)]
                struct Invalid;
                impl<T: ?Sized + $trait> AmbiguousIfImpl<Invalid> for T {}
                let _ = <$type as AmbiguousIfImpl<_>>::some_item;
            };
        };
    }

    assert_not_impl!(RandomNonceKey: Clone);
    assert_not_impl!(RandomNonceKey: Copy);

    fn random_key_bytes() -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(random::generate_key_256().unwrap())
    }

    #[test]
    fn random_nonce_key_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RandomNonceKey>();
    }

    #[test]
    fn random_nonce_seal_open_roundtrip() {
        let key = RandomNonceKey::generate().unwrap();
        for pt in [&b""[..], b"x", b"secret message", &[0x5a; 300][..]] {
            let (nonce, ct) = key.seal(b"aad", pt).unwrap();
            assert_eq!(ct.len(), pt.len() + TAG_LEN);
            if !pt.is_empty() {
                assert_ne!(&ct[..pt.len()], pt);
            }
            assert_eq!(key.open(&nonce, b"aad", &ct).unwrap(), pt);
        }
        // From caller bytes as well as `generate`.
        let key = RandomNonceKey::new(&random_key_bytes()).unwrap();
        let (nonce, ct) = key.seal(b"", b"pt").unwrap();
        assert_eq!(key.open(&nonce, b"", &ct).unwrap(), b"pt");
    }

    #[test]
    fn random_nonce_wrong_aad_or_key_fails() {
        let a = RandomNonceKey::generate().unwrap();
        let b = RandomNonceKey::generate().unwrap();
        let (nonce, ct) = a.seal(b"correct aad", b"secret").unwrap();
        assert!(a.open(&nonce, b"wrong aad", &ct).is_err());
        assert!(a.open(&nonce, b"", &ct).is_err());
        assert!(b.open(&nonce, b"correct aad", &ct).is_err());
        let mut other = nonce;
        other[NONCE_LEN - 1] ^= 1;
        assert!(a.open(&other, b"correct aad", &ct).is_err());
        assert_eq!(a.open(&nonce, b"correct aad", &ct).unwrap(), b"secret");
    }

    #[test]
    fn random_nonce_tamper_and_short_fail() {
        let key = RandomNonceKey::generate().unwrap();
        let (nonce, ct) = key.seal(b"aad", b"secret plaintext").unwrap();
        // Every single-byte flip (body and tag) fails closed.
        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 0x01;
            assert!(key.open(&nonce, b"aad", &bad).is_err(), "flip at {i}");
        }
        // Shorter than a tag, empty, tag-only, truncated tag.
        assert!(key.open(&nonce, b"aad", &ct[..TAG_LEN - 1]).is_err());
        assert!(key.open(&nonce, b"aad", &[]).is_err());
        assert!(key.open(&nonce, b"aad", &[0u8; TAG_LEN]).is_err());
        assert!(key.open(&nonce, b"aad", &ct[..ct.len() - 1]).is_err());
        // Failures leave the key usable.
        assert_eq!(key.open(&nonce, b"aad", &ct).unwrap(), b"secret plaintext");
    }

    #[test]
    fn random_nonce_nonces_distinct() {
        let key = RandomNonceKey::generate().unwrap();
        let mut seen = HashSet::with_capacity(1024);
        for _ in 0..1024 {
            let (nonce, _) = key.seal(b"aad", b"same plaintext").unwrap();
            assert!(seen.insert(nonce), "module repeated an IV");
        }
        assert_eq!(seen.len(), 1024);
    }

    /// Rolling upgrade: a blob sealed by the new key opens with the
    /// pre-change opener (`Aes256GcmKey`) and with `CachedAeadKey`, and is
    /// byte-identical to a caller-nonce seal under the returned IV.
    #[test]
    fn random_nonce_blob_opens_with_aes256gcmkey() {
        let bytes = random_key_bytes();
        let sealer = RandomNonceKey::new(&bytes).unwrap();
        let opener = Aes256GcmKey::new(*bytes).unwrap();
        let cached = CachedAeadKey::new(&bytes).unwrap();
        let (nonce, ct) = sealer.seal(b"row-aad", b"ha1 value").unwrap();
        assert_eq!(opener.open(&nonce, b"row-aad", &ct).unwrap(), b"ha1 value");
        assert_eq!(cached.open(&nonce, b"row-aad", &ct).unwrap(), b"ha1 value");
        assert_eq!(cached.seal(&nonce, b"row-aad", b"ha1 value").unwrap(), ct);
    }

    /// Old rows: a caller-nonce (pre-SR-15) blob opens with `RandomNonceKey`.
    #[test]
    fn caller_nonce_blob_opens_with_random_nonce_key() {
        let bytes = random_key_bytes();
        let legacy = CachedAeadKey::new(&bytes).unwrap();
        let key = RandomNonceKey::new(&bytes).unwrap();
        let nonce = random::generate_nonce().unwrap();
        let ct = legacy.seal(&nonce, b"row-aad", b"ha1 value").unwrap();
        assert_eq!(key.open(&nonce, b"row-aad", &ct).unwrap(), b"ha1 value");
        let mut bad = ct;
        bad[0] ^= 1;
        assert!(key.open(&nonce, b"row-aad", &bad).is_err());
    }

    #[test]
    fn random_nonce_key_debug_redacted() {
        let bytes = random_key_bytes();
        let key = RandomNonceKey::new(&bytes).unwrap();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        for s in [format!("{key:?}"), format!("{key:#?}")] {
            assert!(s.contains("RandomNonceKey"), "{s}");
            assert!(s.contains("AES-256-GCM"), "{s}");
            assert!(!s.contains(&format!("{:?}", *bytes)), "{s}");
            assert!(!s.to_ascii_lowercase().contains(&hex), "{s}");
        }
    }
}
