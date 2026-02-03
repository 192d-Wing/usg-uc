//! CNSA 2.0 compliant ECDH key exchange.
//!
//! ## CNSA 2.0 Requirements
//!
//! - **Allowed**: ECDH with P-384, ECDH with P-521
//! - **Forbidden**: ECDH with P-256, traditional DH, RSA key exchange
//!
//! This module only provides P-384 ECDH to enforce CNSA 2.0 compliance.
//!
//! ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment)

use crate::error::{CryptoError, CryptoResult};
use aws_lc_rs::agreement::{self, ECDH_P384, EphemeralPrivateKey, UnparsedPublicKey};
use aws_lc_rs::rand::SystemRandom;
use zeroize::Zeroize;

/// P-384 ECDH ephemeral key pair for key exchange.
///
/// This key pair is designed for single-use key exchange operations.
/// The private key is automatically zeroed when dropped.
///
/// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment)
pub struct P384EphemeralKeyPair {
    private_key: EphemeralPrivateKey,
    public_key_bytes: Vec<u8>,
}

impl P384EphemeralKeyPair {
    /// Generates a new P-384 ephemeral key pair.
    ///
    /// ## Errors
    ///
    /// Returns an error if key generation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn generate() -> CryptoResult<Self> {
        let rng = SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&ECDH_P384, &rng)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;

        let public_key_bytes = private_key
            .compute_public_key()
            .map_err(|_| CryptoError::KeyGenerationFailed)?
            .as_ref()
            .to_vec();

        Ok(Self {
            private_key,
            public_key_bytes,
        })
    }

    /// Returns the public key in uncompressed point format.
    ///
    /// This should be sent to the peer for key agreement.
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }

    /// Performs ECDH key agreement with a peer's public key.
    ///
    /// Consumes this key pair (ephemeral keys should only be used once).
    ///
    /// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment)
    ///
    /// ## Arguments
    ///
    /// * `peer_public_key` - The peer's public key in uncompressed point format.
    ///
    /// ## Returns
    ///
    /// The shared secret, which should be passed through a KDF before use.
    ///
    /// ## Errors
    ///
    /// Returns an error if key agreement fails (invalid peer key, etc.).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn agree(self, peer_public_key: &[u8]) -> CryptoResult<SharedSecret> {
        let peer_key = UnparsedPublicKey::new(&ECDH_P384, peer_public_key);

        agreement::agree_ephemeral(
            self.private_key,
            &peer_key,
            CryptoError::KeyDerivationFailed,
            |key_material: &[u8]| {
                Ok(SharedSecret {
                    bytes: key_material.to_vec(),
                })
            },
        )
        .map_err(|_| CryptoError::KeyDerivationFailed)
    }
}

impl std::fmt::Debug for P384EphemeralKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P384EphemeralKeyPair")
            .field("public_key", &hex_encode(&self.public_key_bytes))
            .field("private_key", &"[EPHEMERAL]")
            .finish()
    }
}

/// Shared secret from ECDH key agreement.
///
/// The secret is automatically zeroed when dropped.
///
/// **WARNING**: This raw shared secret should NEVER be used directly as a key.
/// Always pass it through a KDF (like HKDF) first.
pub struct SharedSecret {
    bytes: Vec<u8>,
}

impl SharedSecret {
    /// Returns the raw shared secret bytes.
    ///
    /// **WARNING**: This should be passed through a KDF before use.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derives key material using HKDF-SHA384.
    ///
    /// This is the recommended way to use the shared secret.
    ///
    /// ## Arguments
    ///
    /// * `salt` - Optional salt for HKDF.
    /// * `info` - Context-specific information.
    /// * `output` - Buffer to fill with derived key material.
    ///
    /// ## Errors
    ///
    /// Returns an error if key derivation fails.
    pub fn derive_key(
        &self,
        salt: Option<&[u8]>,
        info: &[&[u8]],
        output: &mut [u8],
    ) -> CryptoResult<()> {
        crate::hkdf::hkdf_sha384(salt, &self.bytes, info, output)
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Performs a complete ECDH key exchange and derives a symmetric key.
///
/// This is a convenience function that:
/// 1. Performs ECDH key agreement
/// 2. Derives key material using HKDF-SHA384
///
/// ## Arguments
///
/// * `our_keypair` - Our ephemeral key pair.
/// * `peer_public_key` - The peer's public key.
/// * `salt` - Optional salt for HKDF.
/// * `info` - Context-specific information.
/// * `output` - Buffer to fill with derived key material.
///
/// ## Errors
///
/// Returns an error if key agreement or derivation fails.
pub fn ecdh_derive_key(
    our_keypair: P384EphemeralKeyPair,
    peer_public_key: &[u8],
    salt: Option<&[u8]>,
    info: &[&[u8]],
    output: &mut [u8],
) -> CryptoResult<()> {
    let shared_secret = our_keypair.agree(peer_public_key)?;
    shared_secret.derive_key(salt, info, output)
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
    fn test_key_agreement() {
        // Simulate two parties
        let alice = P384EphemeralKeyPair::generate().unwrap();
        let bob = P384EphemeralKeyPair::generate().unwrap();

        // Exchange public keys and compute shared secrets
        let alice_public = alice.public_key_bytes().to_vec();
        let bob_public = bob.public_key_bytes().to_vec();

        let alice_secret = alice.agree(&bob_public).unwrap();
        let bob_secret = bob.agree(&alice_public).unwrap();

        // Both should derive the same shared secret
        assert_eq!(alice_secret.as_bytes(), bob_secret.as_bytes());
    }

    #[test]
    fn test_derived_keys_match() {
        let alice = P384EphemeralKeyPair::generate().unwrap();
        let bob = P384EphemeralKeyPair::generate().unwrap();

        let alice_public = alice.public_key_bytes().to_vec();
        let bob_public = bob.public_key_bytes().to_vec();

        let alice_secret = alice.agree(&bob_public).unwrap();
        let bob_secret = bob.agree(&alice_public).unwrap();

        let salt = b"salt";
        let info = b"key derivation";

        let mut alice_key = [0u8; 32];
        let mut bob_key = [0u8; 32];

        alice_secret
            .derive_key(Some(salt), &[info], &mut alice_key)
            .unwrap();
        bob_secret
            .derive_key(Some(salt), &[info], &mut bob_key)
            .unwrap();

        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn test_invalid_peer_key_fails() {
        let alice = P384EphemeralKeyPair::generate().unwrap();
        let invalid_key = vec![0u8; 97]; // Invalid point

        let result = alice.agree(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_curve_key_fails() {
        let alice = P384EphemeralKeyPair::generate().unwrap();
        // P-256 public key (65 bytes instead of 97 for P-384)
        let wrong_curve_key = vec![0x04; 65];

        let result = alice.agree(&wrong_curve_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_ecdh_derive_key() {
        let alice = P384EphemeralKeyPair::generate().unwrap();
        let bob = P384EphemeralKeyPair::generate().unwrap();

        let alice_public = alice.public_key_bytes().to_vec();
        let bob_public = bob.public_key_bytes().to_vec();

        let salt = b"salt";
        let info = b"info";

        let mut alice_key = [0u8; 32];
        let mut bob_key = [0u8; 32];

        ecdh_derive_key(alice, &bob_public, Some(salt), &[info], &mut alice_key).unwrap();
        ecdh_derive_key(bob, &alice_public, Some(salt), &[info], &mut bob_key).unwrap();

        assert_eq!(alice_key, bob_key);
    }

    #[test]
    fn test_shared_secret_debug_redacted() {
        let alice = P384EphemeralKeyPair::generate().unwrap();
        let bob = P384EphemeralKeyPair::generate().unwrap();
        let bob_public = bob.public_key_bytes().to_vec();

        let secret = alice.agree(&bob_public).unwrap();
        let debug_str = format!("{secret:?}");
        assert!(debug_str.contains("REDACTED"));
    }
}
