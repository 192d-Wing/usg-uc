//! Secure credential storage for digest authentication.
//!
//! Uses platform keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service)
//! when available, with AES-256-GCM encrypted file fallback for headless environments.
//!
//! This module is only available when the `digest-auth` feature is enabled.

use crate::{AppError, AppResult};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// Service name for keyring entries.
const SERVICE_NAME: &str = "usg-sip-client";

/// Encrypted credentials file name.
const CREDENTIALS_FILE: &str = "credentials.enc";

/// Backend used for credential storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackend {
    /// Platform keyring (macOS Keychain, Windows Credential Manager, etc.).
    Keyring,
    /// AES-256-GCM encrypted file (fallback).
    EncryptedFile,
}

impl std::fmt::Display for StorageBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keyring => write!(f, "Platform Keyring"),
            Self::EncryptedFile => write!(f, "Encrypted File"),
        }
    }
}

/// Secure credential storage manager.
///
/// Automatically detects the best available storage backend:
/// 1. Platform keyring (preferred)
/// 2. AES-256-GCM encrypted file (fallback)
pub struct CredentialStore {
    backend: StorageBackend,
    /// Config directory for encrypted file fallback.
    config_dir: PathBuf,
    /// Encryption key for file backend (derived on first use).
    #[cfg(feature = "digest-auth")]
    encryption_key: Option<uc_crypto::aead::Aes256GcmKey>,
}

impl CredentialStore {
    /// Creates a new credential store, auto-detecting the available backend.
    ///
    /// Tries platform keyring first, falls back to encrypted file.
    pub fn new(config_dir: PathBuf) -> AppResult<Self> {
        let backend = Self::detect_backend();
        info!(backend = %backend, "Credential store initialized");

        Ok(Self {
            backend,
            config_dir,
            #[cfg(feature = "digest-auth")]
            encryption_key: None,
        })
    }

    /// Detects the best available storage backend.
    fn detect_backend() -> StorageBackend {
        // Try keyring first
        #[cfg(feature = "digest-auth")]
        {
            // Test if keyring is accessible by trying to create an entry
            match keyring::Entry::new(SERVICE_NAME, "__probe__") {
                Ok(entry) => {
                    // Try to access it (will fail with NoEntry, but that's OK)
                    match entry.get_password() {
                        Ok(_) | Err(keyring::Error::NoEntry) => {
                            debug!("Platform keyring is available");
                            return StorageBackend::Keyring;
                        }
                        Err(e) => {
                            warn!(error = %e, "Platform keyring not accessible, using encrypted file fallback");
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Platform keyring not available, using encrypted file fallback");
                }
            }
        }

        StorageBackend::EncryptedFile
    }

    /// Returns which backend is being used.
    pub const fn backend(&self) -> StorageBackend {
        self.backend
    }

    /// Stores a password for an account.
    pub fn store_password(&mut self, account_id: &str, password: &str) -> AppResult<()> {
        match self.backend {
            StorageBackend::Keyring => self.store_keyring(account_id, password),
            StorageBackend::EncryptedFile => self.store_encrypted_file(account_id, password),
        }
    }

    /// Retrieves a password for an account.
    pub fn get_password(&mut self, account_id: &str) -> AppResult<Option<Zeroizing<String>>> {
        match self.backend {
            StorageBackend::Keyring => self.get_keyring(account_id),
            StorageBackend::EncryptedFile => self.get_encrypted_file(account_id),
        }
    }

    /// Deletes a password for an account.
    pub fn delete_password(&mut self, account_id: &str) -> AppResult<()> {
        match self.backend {
            StorageBackend::Keyring => self.delete_keyring(account_id),
            StorageBackend::EncryptedFile => self.delete_encrypted_file(account_id),
        }
    }

    // ========== Keyring Backend ==========

    #[cfg(feature = "digest-auth")]
    #[allow(clippy::unused_self)]
    fn store_keyring(&self, account_id: &str, password: &str) -> AppResult<()> {
        let entry = keyring::Entry::new(SERVICE_NAME, account_id)
            .map_err(|e| AppError::Settings(format!("Failed to create keyring entry: {e}")))?;

        entry
            .set_password(password)
            .map_err(|e| AppError::Settings(format!("Failed to store password in keyring: {e}")))?;

        debug!(account_id = %account_id, "Password stored in keyring");
        Ok(())
    }

    #[cfg(not(feature = "digest-auth"))]
    fn store_keyring(&self, _account_id: &str, _password: &str) -> AppResult<()> {
        Err(AppError::Settings(
            "Keyring storage not available".to_string(),
        ))
    }

    #[cfg(feature = "digest-auth")]
    #[allow(clippy::unused_self)]
    fn get_keyring(&self, account_id: &str) -> AppResult<Option<Zeroizing<String>>> {
        let entry = keyring::Entry::new(SERVICE_NAME, account_id)
            .map_err(|e| AppError::Settings(format!("Failed to create keyring entry: {e}")))?;

        match entry.get_password() {
            Ok(password) => {
                debug!(account_id = %account_id, "Password retrieved from keyring");
                Ok(Some(Zeroizing::new(password)))
            }
            Err(keyring::Error::NoEntry) => {
                debug!(account_id = %account_id, "No password found in keyring");
                Ok(None)
            }
            Err(e) => Err(AppError::Settings(format!(
                "Failed to get password from keyring: {e}"
            ))),
        }
    }

    #[cfg(not(feature = "digest-auth"))]
    fn get_keyring(&self, _account_id: &str) -> AppResult<Option<Zeroizing<String>>> {
        Err(AppError::Settings(
            "Keyring storage not available".to_string(),
        ))
    }

    #[cfg(feature = "digest-auth")]
    #[allow(clippy::unused_self)]
    fn delete_keyring(&self, account_id: &str) -> AppResult<()> {
        let entry = keyring::Entry::new(SERVICE_NAME, account_id)
            .map_err(|e| AppError::Settings(format!("Failed to create keyring entry: {e}")))?;

        match entry.delete_credential() {
            Ok(()) => {
                debug!(account_id = %account_id, "Password deleted from keyring");
                Ok(())
            }
            Err(keyring::Error::NoEntry) => {
                debug!(account_id = %account_id, "No password to delete in keyring");
                Ok(())
            }
            Err(e) => Err(AppError::Settings(format!(
                "Failed to delete password from keyring: {e}"
            ))),
        }
    }

    #[cfg(not(feature = "digest-auth"))]
    fn delete_keyring(&self, _account_id: &str) -> AppResult<()> {
        Err(AppError::Settings(
            "Keyring storage not available".to_string(),
        ))
    }

    // ========== Encrypted File Backend ==========

    /// Gets or derives the encryption key for the file backend.
    #[cfg(feature = "digest-auth")]
    fn get_or_derive_key(&mut self) -> AppResult<&uc_crypto::aead::Aes256GcmKey> {
        if self.encryption_key.is_none() {
            // Derive key from machine-specific data
            // We use: hostname + username + config dir path as the input key material
            let hostname = hostname::get()
                .map_or_else(|_| "unknown".to_string(), |h| h.to_string_lossy().to_string());
            let username = whoami::username();
            let config_path = self.config_dir.to_string_lossy();

            let ikm = format!("{hostname}:{username}:{config_path}");
            let salt = b"usg-sip-client-credential-store-v1";
            let info = b"aes-256-gcm-key";

            let mut key_bytes = [0u8; 32];
            uc_crypto::hkdf::hkdf_sha384(Some(salt), ikm.as_bytes(), &[info], &mut key_bytes)
                .map_err(|e| AppError::Settings(format!("Failed to derive encryption key: {e}")))?;

            let key = uc_crypto::aead::Aes256GcmKey::new(key_bytes)
                .map_err(|e| AppError::Settings(format!("Failed to create encryption key: {e}")))?;

            self.encryption_key = Some(key);
        }

        // Safe because we just set it
        self
            .encryption_key
            .as_ref()
            .ok_or_else(|| AppError::Settings("Encryption key not initialized".to_string()))
    }

    /// Gets the path to the encrypted credentials file.
    fn credentials_file_path(&self) -> PathBuf {
        self.config_dir.join(CREDENTIALS_FILE)
    }

    /// Loads the credentials map from the encrypted file.
    #[cfg(feature = "digest-auth")]
    fn load_credentials_map(&mut self) -> AppResult<HashMap<String, String>> {
        let path = self.credentials_file_path();

        if !path.exists() {
            return Ok(HashMap::new());
        }

        let encrypted_data = fs::read(&path)?;

        if encrypted_data.len() < 12 {
            // Nonce is 12 bytes
            return Err(AppError::Settings("Corrupted credentials file".to_string()));
        }

        // First 12 bytes are the nonce
        let nonce: [u8; 12] = encrypted_data[..12]
            .try_into()
            .map_err(|_| AppError::Settings("Invalid nonce length".to_string()))?;
        let ciphertext = &encrypted_data[12..];

        let key = self.get_or_derive_key()?;
        let plaintext = key
            .open(&nonce, b"credentials", ciphertext)
            .map_err(|e| AppError::Settings(format!("Failed to decrypt credentials: {e}")))?;

        let json_str = String::from_utf8(plaintext)
            .map_err(|e| AppError::Settings(format!("Invalid credentials data: {e}")))?;

        let map: HashMap<String, String> = serde_json::from_str(&json_str)
            .map_err(|e| AppError::Settings(format!("Failed to parse credentials: {e}")))?;

        Ok(map)
    }

    /// Saves the credentials map to the encrypted file.
    #[cfg(feature = "digest-auth")]
    fn save_credentials_map(&mut self, map: &HashMap<String, String>) -> AppResult<()> {
        let path = self.credentials_file_path();

        // Serialize to JSON
        let json_str = serde_json::to_string(map)
            .map_err(|e| AppError::Settings(format!("Failed to serialize credentials: {e}")))?;

        // Generate random nonce
        let nonce = uc_crypto::random::generate_nonce()
            .map_err(|e| AppError::Settings(format!("Failed to generate nonce: {e}")))?;

        // Encrypt
        let key = self.get_or_derive_key()?;
        let ciphertext = key
            .seal(&nonce, b"credentials", json_str.as_bytes())
            .map_err(|e| AppError::Settings(format!("Failed to encrypt credentials: {e}")))?;

        // Write nonce + ciphertext
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);

        // Write atomically via temp file
        let temp_path = path.with_extension("enc.tmp");
        fs::write(&temp_path, &output)?;
        fs::rename(&temp_path, &path)?;

        debug!(path = ?path, "Credentials saved to encrypted file");
        Ok(())
    }

    #[cfg(feature = "digest-auth")]
    fn store_encrypted_file(&mut self, account_id: &str, password: &str) -> AppResult<()> {
        let mut map = self.load_credentials_map()?;
        map.insert(account_id.to_string(), password.to_string());
        self.save_credentials_map(&map)?;
        debug!(account_id = %account_id, "Password stored in encrypted file");
        Ok(())
    }

    #[cfg(not(feature = "digest-auth"))]
    fn store_encrypted_file(&mut self, _account_id: &str, _password: &str) -> AppResult<()> {
        Err(AppError::Settings(
            "Encrypted file storage not available".to_string(),
        ))
    }

    #[cfg(feature = "digest-auth")]
    fn get_encrypted_file(&mut self, account_id: &str) -> AppResult<Option<Zeroizing<String>>> {
        let map = self.load_credentials_map()?;
        Ok(map.get(account_id).map_or_else(
            || {
                debug!(account_id = %account_id, "No password found in encrypted file");
                None
            },
            |password| {
                debug!(account_id = %account_id, "Password retrieved from encrypted file");
                Some(Zeroizing::new(password.clone()))
            },
        ))
    }

    #[cfg(not(feature = "digest-auth"))]
    fn get_encrypted_file(&mut self, _account_id: &str) -> AppResult<Option<Zeroizing<String>>> {
        Err(AppError::Settings(
            "Encrypted file storage not available".to_string(),
        ))
    }

    #[cfg(feature = "digest-auth")]
    fn delete_encrypted_file(&mut self, account_id: &str) -> AppResult<()> {
        let mut map = self.load_credentials_map()?;
        if map.remove(account_id).is_some() {
            self.save_credentials_map(&map)?;
            debug!(account_id = %account_id, "Password deleted from encrypted file");
        } else {
            debug!(account_id = %account_id, "No password to delete in encrypted file");
        }
        Ok(())
    }

    #[cfg(not(feature = "digest-auth"))]
    fn delete_encrypted_file(&mut self, _account_id: &str) -> AppResult<()> {
        Err(AppError::Settings(
            "Encrypted file storage not available".to_string(),
        ))
    }
}

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStore")
            .field("backend", &self.backend)
            .field("config_dir", &self.config_dir)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_storage_backend_display() {
        assert_eq!(StorageBackend::Keyring.to_string(), "Platform Keyring");
        assert_eq!(StorageBackend::EncryptedFile.to_string(), "Encrypted File");
    }

    #[test]
    fn test_credential_store_new() {
        let dir = tempdir().unwrap();
        let store = CredentialStore::new(dir.path().to_path_buf()).unwrap();
        // Backend should be detected (either Keyring or EncryptedFile)
        assert!(
            store.backend() == StorageBackend::Keyring
                || store.backend() == StorageBackend::EncryptedFile
        );
    }

    #[cfg(feature = "digest-auth")]
    #[test]
    fn test_encrypted_file_roundtrip() {
        let dir = tempdir().unwrap();
        let mut store = CredentialStore {
            backend: StorageBackend::EncryptedFile,
            config_dir: dir.path().to_path_buf(),
            encryption_key: None,
        };

        // Store
        store
            .store_encrypted_file("test-account", "secret-password")
            .unwrap();

        // Retrieve
        let retrieved = store.get_encrypted_file("test-account").unwrap();
        assert_eq!(
            retrieved.map(|p| p.as_str().to_string()),
            Some("secret-password".to_string())
        );

        // Delete
        store.delete_encrypted_file("test-account").unwrap();

        // Should be gone
        let retrieved = store.get_encrypted_file("test-account").unwrap();
        assert!(retrieved.is_none());
    }

    #[cfg(feature = "digest-auth")]
    #[test]
    fn test_encrypted_file_multiple_accounts() {
        let dir = tempdir().unwrap();
        let mut store = CredentialStore {
            backend: StorageBackend::EncryptedFile,
            config_dir: dir.path().to_path_buf(),
            encryption_key: None,
        };

        store.store_encrypted_file("account1", "password1").unwrap();
        store.store_encrypted_file("account2", "password2").unwrap();

        assert_eq!(
            store
                .get_encrypted_file("account1")
                .unwrap()
                .map(|p| p.as_str().to_string()),
            Some("password1".to_string())
        );
        assert_eq!(
            store
                .get_encrypted_file("account2")
                .unwrap()
                .map(|p| p.as_str().to_string()),
            Some("password2".to_string())
        );

        // Delete one, other should remain
        store.delete_encrypted_file("account1").unwrap();
        assert!(store.get_encrypted_file("account1").unwrap().is_none());
        assert_eq!(
            store
                .get_encrypted_file("account2")
                .unwrap()
                .map(|p| p.as_str().to_string()),
            Some("password2".to_string())
        );
    }
}
