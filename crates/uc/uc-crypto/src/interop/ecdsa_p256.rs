//! ECDSA P-256 / SHA-256 (JWS `ES256`) for STIR/SHAKEN interop.
//!
//! CNSA-EXCEPTION: ATIS-1000074 mandates ES256 for SHAKEN PASSporTs.
//!
//! Signatures use the fixed-width JWS encoding (RFC 7518 §3.4): the 64-byte
//! concatenation `R || S`, not ASN.1 DER.
//!
//! ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection), IA-9

use crate::error::{CryptoError, CryptoResult};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};

/// Length of an ES256 JWS signature (`R || S`).
pub const SIGNATURE_LEN: usize = 64;

/// Length of an uncompressed P-256 public point (`0x04 || X || Y`).
pub const PUBLIC_KEY_LEN: usize = 65;

/// P-256 signing key for ES256 PASSporTs.
///
/// The private scalar lives inside aws-lc and is zeroized by it on drop; this
/// type keeps no copy of the PKCS#8 bytes.
///
/// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment)
pub struct P256SigningKey {
    inner: EcdsaKeyPair,
}

impl P256SigningKey {
    /// Generates a fresh key pair and returns it with its PKCS#8 encoding.
    ///
    /// Intended for tests and tooling; production keys are STI-CA issued.
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    pub fn generate_pkcs8() -> CryptoResult<zeroize::Zeroizing<Vec<u8>>> {
        let rng = SystemRandom::new();
        let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;
        Ok(zeroize::Zeroizing::new(doc.as_ref().to_vec()))
    }

    /// Loads a key from a PKCS#8 v1/v2 DER document.
    ///
    /// # Errors
    /// Returns [`CryptoError::InvalidKeyMaterial`] if the document is not a
    /// P-256 EC private key.
    pub fn from_pkcs8(pkcs8: &[u8]) -> CryptoResult<Self> {
        let inner = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
        Ok(Self { inner })
    }

    /// Signs `message` with ES256 and returns the 64-byte `R || S` signature.
    ///
    /// # Errors
    /// Returns [`CryptoError::SigningFailed`] if aws-lc rejects the operation.
    pub fn sign(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
        let rng = SystemRandom::new();
        let sig = self
            .inner
            .sign(&rng, message)
            .map_err(|_| CryptoError::SigningFailed)?;
        Ok(sig.as_ref().to_vec())
    }

    /// Returns the public key as an uncompressed point.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        self.inner.public_key().as_ref()
    }
}

impl std::fmt::Debug for P256SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P256SigningKey")
            .field("private_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Verifies an ES256 (`R || S`) signature against an uncompressed P-256 point.
///
/// # Errors
/// Returns [`CryptoError::VerificationFailed`] on any failure, including a
/// malformed key or a signature of the wrong length.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> CryptoResult<()> {
    if public_key.len() != PUBLIC_KEY_LEN || signature.len() != SIGNATURE_LEN {
        return Err(CryptoError::VerificationFailed);
    }
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
        .verify(message, signature)
        .map_err(|_| CryptoError::VerificationFailed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let pkcs8 = P256SigningKey::generate_pkcs8().unwrap();
        let key = P256SigningKey::from_pkcs8(&pkcs8).unwrap();
        let sig = key.sign(b"hello").unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        verify(key.public_key_bytes(), b"hello", &sig).unwrap();
        assert!(verify(key.public_key_bytes(), b"hellp", &sig).is_err());
    }

    #[test]
    fn rejects_bad_lengths_and_tamper() {
        let pkcs8 = P256SigningKey::generate_pkcs8().unwrap();
        let key = P256SigningKey::from_pkcs8(&pkcs8).unwrap();
        let mut sig = key.sign(b"m").unwrap();
        assert!(verify(key.public_key_bytes(), b"m", &sig[..63]).is_err());
        assert!(verify(&key.public_key_bytes()[..64], b"m", &sig).is_err());
        sig[10] ^= 1;
        assert!(verify(key.public_key_bytes(), b"m", &sig).is_err());
    }

    #[test]
    fn rejects_p384_key() {
        let p384 = crate::ecdsa::P384KeyPair::generate().unwrap();
        assert!(P256SigningKey::from_pkcs8(p384.pkcs8_bytes()).is_err());
    }

    /// RFC 7515 Appendix A.3 ES256 example (public key + JWS signing input +
    /// signature), a known-good vector independent of aws-lc's own signer.
    #[test]
    fn rfc7515_a3_vector() {
        fn b64(s: &str) -> Vec<u8> {
            crate::interop::test_b64url(s)
        }
        let x = b64("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU");
        let y = b64("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0");
        let mut pk = vec![4u8];
        pk.extend_from_slice(&x);
        pk.extend_from_slice(&y);
        let input = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
        let sig = b64(
            "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q",
        );
        verify(&pk, input.as_bytes(), &sig).unwrap();
    }
}
