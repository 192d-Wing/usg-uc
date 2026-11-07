//! CNSA 2.0 compliant ECDSA digital signatures.
//!
//! ## CNSA 2.0 Requirements
//!
//! - **Allowed**: ECDSA with P-384 (ES384), ECDSA with P-521 (ES512)
//! - **Forbidden**: ECDSA with P-256 (ES256), RSA signatures
//!
//! This module only provides P-384 ECDSA to enforce CNSA 2.0 compliance.
//!
//! ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)

use crate::error::{CryptoError, CryptoResult};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING,
    ECDSA_P521_SHA512_ASN1_SIGNING, EcdsaKeyPair, EcdsaSigningAlgorithm, KeyPair,
    UnparsedPublicKey,
};
use zeroize::Zeroizing;

/// P-384 ECDSA key pair for signing operations.
///
/// ## Key material lifecycle
///
/// - The PKCS#8 DER copy owned by this struct is held in
///   [`Zeroizing`] and wiped on drop.
/// - The parsed key (`EcdsaKeyPair`) is an opaque aws-lc `EVP_PKEY`; aws-lc
///   clears the private scalar when it is freed (`EC_KEY_free` ->
///   `BN_clear_free`). Rust code cannot wipe it.
/// - Not covered: the caller's input slice to [`Self::from_pkcs8`], and
///   copies the caller makes from [`Self::pkcs8_bytes`].
///
/// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment), SC-4, SI-16
// NIST 800-53 Rev5: SC-12, SC-4 (POA&M-162 closed: PKCS#8 bytes held in `Zeroizing`).
pub struct P384KeyPair {
    inner: EcdsaKeyPair,
    pkcs8_bytes: Zeroizing<Vec<u8>>,
}

impl P384KeyPair {
    /// Generates a new P-384 key pair.
    ///
    /// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment)
    ///
    /// ## Errors
    ///
    /// Returns an error if key generation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn generate() -> CryptoResult<Self> {
        let rng = SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;

        let inner = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_bytes.as_ref())
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        // aws-lc-rs `pkcs8::Document` zeroizes its own buffer on drop.
        Ok(Self {
            inner,
            pkcs8_bytes: Zeroizing::new(pkcs8_bytes.as_ref().to_vec()),
        })
    }

    /// Creates a key pair from PKCS#8 encoded private key.
    ///
    /// ## Errors
    ///
    /// Returns an error if the key material is invalid.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn from_pkcs8(pkcs8_bytes: &[u8]) -> CryptoResult<Self> {
        let inner = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        Ok(Self {
            inner,
            pkcs8_bytes: Zeroizing::new(pkcs8_bytes.to_vec()),
        })
    }

    /// Signs a message using ECDSA P-384 with SHA-384.
    ///
    /// Returns the signature in ASN.1 DER format.
    ///
    /// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
    ///
    /// ## Errors
    ///
    /// Returns an error if signing fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn sign(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
        let rng = SystemRandom::new();
        let signature = self
            .inner
            .sign(&rng, message)
            .map_err(|_| CryptoError::SigningFailed)?;
        Ok(signature.as_ref().to_vec())
    }

    /// Returns the public key in uncompressed point format.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        self.inner.public_key().as_ref()
    }

    /// Returns the PKCS#8 encoded private key.
    ///
    /// **WARNING**: Handle with care - this is sensitive key material.
    #[must_use]
    pub fn pkcs8_bytes(&self) -> &[u8] {
        &self.pkcs8_bytes
    }
}

impl std::fmt::Debug for P384KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P384KeyPair")
            .field("public_key", &hex_encode(self.public_key_bytes()))
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

/// Elliptic curve of an EC private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcCurve {
    /// NIST P-256 (not permitted by CNSA 1.0 or this repo's policy).
    P256,
    /// NIST P-384 (the CNSA 1.0 ECDSA curve; transitional under CNSA 2.0).
    P384,
    /// NIST P-521 (not a CNSA curve; accepted by repo policy, `CnsaCurve`).
    P521,
}

impl std::fmt::Display for EcCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        })
    }
}

/// Identifies the curve of a DER private key (PKCS#8 or SEC1).
///
/// Returns `None` for non-EC keys (e.g. RSA), unsupported curves, or
/// malformed input. Used to enforce the configured CNSA curve on loaded
/// keys; P-256 is recognised only so it can be rejected.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
// NIST 800-53 Rev5: SC-13 (library half of POA&M-166: key curve check at load).
#[must_use]
pub fn ec_private_key_curve(der: &[u8]) -> Option<EcCurve> {
    const CANDIDATES: [(EcCurve, &EcdsaSigningAlgorithm); 3] = [
        (EcCurve::P384, &ECDSA_P384_SHA384_ASN1_SIGNING),
        (EcCurve::P521, &ECDSA_P521_SHA512_ASN1_SIGNING),
        (EcCurve::P256, &ECDSA_P256_SHA256_ASN1_SIGNING),
    ];
    CANDIDATES.iter().find_map(|(curve, alg)| {
        (EcdsaKeyPair::from_pkcs8(alg, der).is_ok()
            || EcdsaKeyPair::from_private_key_der(alg, der).is_ok())
        .then_some(*curve)
    })
}

/// Verifies a P-384 ECDSA signature.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
///
/// ## Arguments
///
/// * `public_key` - The signer's public key in uncompressed point format.
/// * `message` - The signed message.
/// * `signature` - The signature in ASN.1 DER format.
///
/// ## Errors
///
/// Returns an error if verification fails (invalid signature, wrong key, etc.).
///
/// # Errors
/// Returns an error if the operation fails.
pub fn verify_p384(public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<()> {
    let public_key = UnparsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, public_key);
    public_key
        .verify(message, signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

/// P-384 public key for verification only.
pub struct P384PublicKey {
    bytes: Vec<u8>,
}

impl P384PublicKey {
    /// Creates a public key from uncompressed point bytes.
    ///
    /// ## Errors
    ///
    /// Returns an error if the public key is invalid.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        // Basic validation: P-384 uncompressed public key is 97 bytes (0x04 || x || y)
        if bytes.len() != 97 || bytes[0] != 0x04 {
            return Err(CryptoError::InvalidKeyMaterial);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    /// Verifies a signature against this public key.
    ///
    /// ## Errors
    ///
    /// Returns an error if verification fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> CryptoResult<()> {
        verify_p384(&self.bytes, message, signature)
    }

    /// Returns the public key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for P384PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P384PublicKey")
            .field("bytes", &hex_encode(&self.bytes))
            .finish()
    }
}

/// Helper to encode bytes as hex for debug output.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_and_sign_verify() {
        let keypair = P384KeyPair::generate().unwrap();
        let message = b"test message";

        let signature = keypair.sign(message).unwrap();

        // Verify with the public key
        verify_p384(keypair.public_key_bytes(), message, &signature).unwrap();
    }

    #[test]
    fn test_wrong_message_fails() {
        let keypair = P384KeyPair::generate().unwrap();
        let message = b"test message";
        let wrong_message = b"wrong message";

        let signature = keypair.sign(message).unwrap();

        let result = verify_p384(keypair.public_key_bytes(), wrong_message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = P384KeyPair::generate().unwrap();
        let keypair2 = P384KeyPair::generate().unwrap();
        let message = b"test message";

        let signature = keypair1.sign(message).unwrap();

        let result = verify_p384(keypair2.public_key_bytes(), message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_signature_fails() {
        let keypair = P384KeyPair::generate().unwrap();
        let message = b"test message";

        let mut signature = keypair.sign(message).unwrap();
        // Tamper with the signature
        if let Some(byte) = signature.last_mut() {
            *byte ^= 0xFF;
        }

        let result = verify_p384(keypair.public_key_bytes(), message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_pkcs8_roundtrip() {
        let keypair1 = P384KeyPair::generate().unwrap();
        let message = b"test message";
        let signature = keypair1.sign(message).unwrap();

        // Recreate from PKCS#8
        let keypair2 = P384KeyPair::from_pkcs8(keypair1.pkcs8_bytes()).unwrap();

        // Public keys should match
        assert_eq!(keypair1.public_key_bytes(), keypair2.public_key_bytes());

        // Signature should still verify
        verify_p384(keypair2.public_key_bytes(), message, &signature).unwrap();
    }

    #[test]
    fn test_public_key_from_bytes() {
        let keypair = P384KeyPair::generate().unwrap();
        let pubkey = P384PublicKey::from_bytes(keypair.public_key_bytes()).unwrap();

        let message = b"test message";
        let signature = keypair.sign(message).unwrap();

        pubkey.verify(message, &signature).unwrap();
    }

    // POA&M-162 (closed): the PKCS#8 copy is `Zeroizing`, so its drop wipes it.
    #[test]
    fn test_pkcs8_bytes_zeroizing() {
        use zeroize::{Zeroize, ZeroizeOnDrop};
        fn assert_zod<T: ZeroizeOnDrop>(_: &T) {}

        let keypair = P384KeyPair::generate().unwrap();
        assert_zod(&keypair.pkcs8_bytes);
        let P384KeyPair {
            pkcs8_bytes: mut der,
            ..
        } = keypair;
        assert!(der.iter().any(|b| *b != 0));
        der.zeroize();
        assert!(der.is_empty());
    }

    #[test]
    fn test_ec_private_key_curve() {
        let rng = SystemRandom::new();
        for (alg, want) in [
            (&ECDSA_P256_SHA256_ASN1_SIGNING, EcCurve::P256),
            (&ECDSA_P384_SHA384_ASN1_SIGNING, EcCurve::P384),
            (&ECDSA_P521_SHA512_ASN1_SIGNING, EcCurve::P521),
        ] {
            let doc = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
            assert_eq!(ec_private_key_curve(doc.as_ref()), Some(want));
        }
        assert_eq!(ec_private_key_curve(b""), None);
        assert_eq!(ec_private_key_curve(&[0x30, 0x82, 0xff, 0xff, 0x02]), None);
    }

    #[test]
    fn test_ec_private_key_curve_rejects_non_ec_and_accepts_sec1() {
        use aws_lc_rs::encoding::AsDer;
        // RSA PKCS#8 must not be classified as any EC curve.
        let rsa = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let rsa_der = rsa.as_der().unwrap();
        assert_eq!(ec_private_key_curve(rsa_der.as_ref()), None);
        // Ed25519 PKCS#8 is not an ECDSA curve either.
        let rng = SystemRandom::new();
        let ed = aws_lc_rs::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        assert_eq!(ec_private_key_curve(ed.as_ref()), None);
        // SEC1 ("EC PRIVATE KEY") encoding of a P-384 key is recognised.
        let kp = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_ASN1_SIGNING).unwrap();
        let sec1 = kp.private_key().as_der().unwrap();
        assert_eq!(ec_private_key_curve(sec1.as_ref()), Some(EcCurve::P384));
        // Truncated PKCS#8 is rejected.
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng).unwrap();
        let bytes = doc.as_ref();
        assert_eq!(ec_private_key_curve(&bytes[..bytes.len() / 2]), None);
    }

    #[test]
    fn test_key_debug_redacted() {
        let keypair = P384KeyPair::generate().unwrap();
        let debug_str = format!("{keypair:?}");
        assert!(debug_str.contains("REDACTED"));
    }
}
