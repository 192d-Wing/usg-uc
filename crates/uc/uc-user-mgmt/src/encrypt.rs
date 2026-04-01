//! Transparent AES-256-GCM encryption of HA1 digest credentials.
//!
//! Wraps any [`UserStore`] backend to encrypt `digest_ha1` values before
//! writing and decrypt after reading, providing defense-in-depth against
//! database compromise.
//!
//! ## Storage Format
//!
//! Encrypted HA1 is stored as `base64(nonce[12] || ciphertext || tag[16])`.
//! Plaintext HA1 (64-char hex) is detected on read for backward compatibility.

use base64::prelude::*;
use uc_crypto::aead::{self, Aes256GcmKey, NONCE_LEN};

use crate::error::UserMgmtError;
use crate::model::User;
use crate::store::{self, UserStore};

/// Additional authenticated data used for domain binding.
const AAD: &[u8] = b"digest_ha1";

/// A [`UserStore`] decorator that transparently encrypts/decrypts `digest_ha1`.
///
/// If no encryption key is configured, all operations pass through unchanged
/// (backward compatible).
pub struct EncryptedUserStore<S: UserStore> {
    inner: S,
    key: Option<Aes256GcmKey>,
}

impl<S: UserStore> EncryptedUserStore<S> {
    /// Wrap a store with optional HA1 encryption.
    ///
    /// Pass `None` for the key to disable encryption (passthrough mode).
    pub fn new(inner: S, key: Option<Aes256GcmKey>) -> Self {
        Self { inner, key }
    }

    /// Wrap a store with HA1 encryption using a hex-encoded key string.
    ///
    /// The key must be exactly 64 hex characters (32 bytes).
    /// Returns `Err` if the key is invalid.
    pub fn with_hex_key(
        inner: S,
        hex_key: &str,
    ) -> std::result::Result<Self, crate::error::UserMgmtError> {
        let key = parse_hex_key(hex_key)?;
        Ok(Self {
            inner,
            key: Some(key),
        })
    }

    /// Returns a reference to the inner store.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Returns `true` if HA1 encryption is enabled (a key is configured).
    pub fn is_encrypted(&self) -> bool {
        self.key.is_some()
    }

    /// Encrypt an HA1 value if a key is configured.
    fn encrypt_ha1(&self, ha1: &str) -> store::Result<String> {
        let Some(ref key) = self.key else {
            return Ok(ha1.to_owned());
        };

        let (nonce, ciphertext) = aead::seal_with_random_nonce(key, AAD, ha1.as_bytes())
            .map_err(|e| UserMgmtError::StorageError(format!("HA1 encryption failed: {e}")))?;

        // Encode as base64(nonce || ciphertext_with_tag)
        let mut blob = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        Ok(BASE64_STANDARD.encode(&blob))
    }

    /// Decrypt an HA1 value if it appears encrypted.
    ///
    /// Plaintext HA1 (64-char lowercase hex) passes through unchanged,
    /// enabling transparent migration from unencrypted databases.
    fn decrypt_ha1(&self, stored: &str) -> store::Result<String> {
        let Some(ref key) = self.key else {
            return Ok(stored.to_owned());
        };

        // Plaintext HA1 is always exactly 64 lowercase hex characters.
        if is_plaintext_ha1(stored) {
            return Ok(stored.to_owned());
        }

        let blob = BASE64_STANDARD
            .decode(stored)
            .map_err(|e| UserMgmtError::StorageError(format!("HA1 base64 decode failed: {e}")))?;

        if blob.len() < NONCE_LEN {
            return Err(UserMgmtError::StorageError(
                "encrypted HA1 too short".to_owned(),
            ));
        }

        let nonce: [u8; NONCE_LEN] = blob[..NONCE_LEN]
            .try_into()
            .map_err(|_| UserMgmtError::StorageError("invalid nonce length".to_owned()))?;

        let plaintext = key
            .open(&nonce, AAD, &blob[NONCE_LEN..])
            .map_err(|e| UserMgmtError::StorageError(format!("HA1 decryption failed: {e}")))?;

        String::from_utf8(plaintext)
            .map_err(|e| UserMgmtError::StorageError(format!("HA1 not valid UTF-8: {e}")))
    }

    /// Encrypt the `digest_ha1` field of a user in place for storage.
    fn encrypt_user_ha1(&self, user: &mut User) -> store::Result<()> {
        if let Some(ref ha1) = user.digest_ha1 {
            user.digest_ha1 = Some(self.encrypt_ha1(ha1)?);
        }
        Ok(())
    }

    /// Decrypt the `digest_ha1` field of a user in place after retrieval.
    fn decrypt_user_ha1(&self, user: &mut User) -> store::Result<()> {
        if let Some(ref ha1) = user.digest_ha1 {
            user.digest_ha1 = Some(self.decrypt_ha1(ha1)?);
        }
        Ok(())
    }
}

/// Parse a hex-encoded AES-256-GCM key (64 hex chars = 32 bytes).
pub fn parse_hex_key(
    hex_key: &str,
) -> std::result::Result<Aes256GcmKey, crate::error::UserMgmtError> {
    let bytes = hex::decode(hex_key).map_err(|e| {
        crate::error::UserMgmtError::StorageError(format!("invalid hex encryption key: {e}"))
    })?;
    if bytes.len() != 32 {
        return Err(crate::error::UserMgmtError::StorageError(format!(
            "encryption key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Aes256GcmKey::new(key_bytes).map_err(|e| {
        crate::error::UserMgmtError::StorageError(format!("invalid AES-256-GCM key: {e}"))
    })
}

/// Returns `true` if the value looks like a plaintext SHA-256 HA1 hex string.
fn is_plaintext_ha1(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

impl<S: UserStore> UserStore for EncryptedUserStore<S> {
    async fn create_user(&self, mut user: User) -> store::Result<User> {
        self.encrypt_user_ha1(&mut user)?;
        let mut created = self.inner.create_user(user).await?;
        self.decrypt_user_ha1(&mut created)?;
        Ok(created)
    }

    async fn get_user(&self, id: &str) -> store::Result<User> {
        let mut user = self.inner.get_user(id).await?;
        self.decrypt_user_ha1(&mut user)?;
        Ok(user)
    }

    async fn get_user_by_username(&self, username: &str) -> store::Result<User> {
        let mut user = self.inner.get_user_by_username(username).await?;
        self.decrypt_user_ha1(&mut user)?;
        Ok(user)
    }

    async fn get_user_by_certificate_dn(&self, dn: &str) -> store::Result<User> {
        let mut user = self.inner.get_user_by_certificate_dn(dn).await?;
        self.decrypt_user_ha1(&mut user)?;
        Ok(user)
    }

    async fn list_users(
        &self,
        filter: &crate::model::UserFilter,
    ) -> store::Result<Vec<User>> {
        let mut users = self.inner.list_users(filter).await?;
        for user in &mut users {
            self.decrypt_user_ha1(user)?;
        }
        Ok(users)
    }

    async fn update_user(&self, mut user: User) -> store::Result<User> {
        self.encrypt_user_ha1(&mut user)?;
        let mut updated = self.inner.update_user(user).await?;
        self.decrypt_user_ha1(&mut updated)?;
        Ok(updated)
    }

    async fn delete_user(&self, id: &str) -> store::Result<()> {
        self.inner.delete_user(id).await
    }

    async fn authenticate_digest(
        &self,
        username: &str,
        realm: &str,
    ) -> store::Result<Option<String>> {
        let ha1 = self.inner.authenticate_digest(username, realm).await?;
        match ha1 {
            Some(stored) => Ok(Some(self.decrypt_ha1(&stored)?)),
            None => Ok(None),
        }
    }

    async fn authenticate_certificate(
        &self,
        dn: &str,
        san: &str,
    ) -> store::Result<Option<User>> {
        let user = self.inner.authenticate_certificate(dn, san).await?;
        match user {
            Some(mut u) => {
                self.decrypt_user_ha1(&mut u)?;
                Ok(Some(u))
            }
            None => Ok(None),
        }
    }

    async fn count_users(&self) -> store::Result<usize> {
        self.inner.count_users().await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_is_plaintext_ha1() {
        // Valid 64-char hex
        let ha1 = "a".repeat(64);
        assert!(is_plaintext_ha1(&ha1));

        // Mixed case hex
        let ha1 = "aAbBcCdDeEfF00112233445566778899aAbBcCdDeEfF00112233445566778899";
        assert!(is_plaintext_ha1(ha1));

        // Too short
        assert!(!is_plaintext_ha1("abcdef"));

        // Non-hex chars
        let bad = "g".repeat(64);
        assert!(!is_plaintext_ha1(&bad));

        // Base64-encoded encrypted value (longer than 64)
        assert!(!is_plaintext_ha1("dGhpcyBpcyBhIGJhc2U2NCBlbmNvZGVkIHN0cmluZyB0aGF0IGlzIGxvbmdlciB0aGFuIDY0IGNoYXJz"));
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = Aes256GcmKey::generate().unwrap();
        // Use a dummy inner store — we only test encrypt/decrypt helpers
        let store = EncryptedUserStore {
            inner: DummyStore,
            key: Some(key),
        };

        let original = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let encrypted = store.encrypt_ha1(original).unwrap();

        // Encrypted value should not be the same as original
        assert_ne!(encrypted, original);
        // Encrypted value should not be 64 hex chars (it's base64)
        assert!(!is_plaintext_ha1(&encrypted));

        let decrypted = store.decrypt_ha1(&encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_passthrough_without_key() {
        let store = EncryptedUserStore {
            inner: DummyStore,
            key: None,
        };

        let original = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let result = store.encrypt_ha1(original).unwrap();
        assert_eq!(result, original);

        let result = store.decrypt_ha1(original).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_decrypt_plaintext_ha1_passthrough() {
        let key = Aes256GcmKey::generate().unwrap();
        let store = EncryptedUserStore {
            inner: DummyStore,
            key: Some(key),
        };

        // Plaintext HA1 should pass through even when key is set
        let plaintext_ha1 =
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let result = store.decrypt_ha1(plaintext_ha1).unwrap();
        assert_eq!(result, plaintext_ha1);
    }

    /// Minimal dummy store for unit-testing encrypt/decrypt helpers.
    struct DummyStore;

    impl UserStore for DummyStore {
        async fn create_user(&self, _: User) -> store::Result<User> {
            unimplemented!()
        }
        async fn get_user(&self, _: &str) -> store::Result<User> {
            unimplemented!()
        }
        async fn get_user_by_username(&self, _: &str) -> store::Result<User> {
            unimplemented!()
        }
        async fn get_user_by_certificate_dn(&self, _: &str) -> store::Result<User> {
            unimplemented!()
        }
        async fn list_users(
            &self,
            _: &crate::model::UserFilter,
        ) -> store::Result<Vec<User>> {
            unimplemented!()
        }
        async fn update_user(&self, _: User) -> store::Result<User> {
            unimplemented!()
        }
        async fn delete_user(&self, _: &str) -> store::Result<()> {
            unimplemented!()
        }
        async fn authenticate_digest(
            &self,
            _: &str,
            _: &str,
        ) -> store::Result<Option<String>> {
            unimplemented!()
        }
        async fn authenticate_certificate(
            &self,
            _: &str,
            _: &str,
        ) -> store::Result<Option<User>> {
            unimplemented!()
        }
        async fn count_users(&self) -> store::Result<usize> {
            unimplemented!()
        }
    }
}
