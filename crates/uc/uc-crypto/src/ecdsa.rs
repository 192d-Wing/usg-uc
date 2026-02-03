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
    ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use zeroize::ZeroizeOnDrop;

/// P-384 ECDSA key pair for signing operations.
///
/// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment)
#[derive(ZeroizeOnDrop)]
pub struct P384KeyPair {
    #[zeroize(skip)]
    inner: EcdsaKeyPair,
    #[zeroize(skip)]
    pkcs8_bytes: Vec<u8>,
}

impl P384KeyPair {
    /// Generates a new P-384 key pair.
    ///
    /// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment)
    ///
    /// ## Errors
    ///
    /// Returns an error if key generation fails.
    pub fn generate() -> CryptoResult<Self> {
        let rng = SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;

        let inner = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_bytes.as_ref())
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        Ok(Self {
            inner,
            pkcs8_bytes: pkcs8_bytes.as_ref().to_vec(),
        })
    }

    /// Creates a key pair from PKCS#8 encoded private key.
    ///
    /// ## Errors
    ///
    /// Returns an error if the key material is invalid.
    pub fn from_pkcs8(pkcs8_bytes: &[u8]) -> CryptoResult<Self> {
        let inner = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, pkcs8_bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;

        Ok(Self {
            inner,
            pkcs8_bytes: pkcs8_bytes.to_vec(),
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

    #[test]
    fn test_key_debug_redacted() {
        let keypair = P384KeyPair::generate().unwrap();
        let debug_str = format!("{keypair:?}");
        assert!(debug_str.contains("REDACTED"));
    }
}
