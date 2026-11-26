//! Secure credential storage (digest passwords, OIDC refresh tokens).
//!
//! Secrets are persisted only in the platform keyring (macOS Keychain,
//! Windows Credential Manager, Linux Secret Service). There is no file
//! fallback: when no keyring is available (Android, iOS, or a desktop whose
//! keyring probe fails, such as headless Linux) the store reports
//! [`StorageBackend::Unavailable`] and persists nothing, so the secret lives
//! in memory only and the user signs in again on the next launch.
//!
//! Earlier releases wrote an AES-256-GCM `credentials.enc` file under a key
//! derived only from public values (hostname, username, config path). That
//! file is never read; it is deleted whenever a store is initialised.
//!
//! This module is available when the `digest-auth` or `oidc` feature is enabled.

// NIST 800-53 Rev5: IA-5(1), IA-5(6), SC-28 (authenticators are stored only
// in an OS-protected keystore; never in a file with a derivable key)

use crate::{AppError, AppResult};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// Service name for keyring entries.
#[cfg(all(
    any(feature = "digest-auth", feature = "oidc"),
    any(windows, target_os = "macos", target_os = "linux")
))]
const SERVICE_NAME: &str = "usg-sip-client";

/// Files left by the removed encrypted-file backend (SR-47). Their key is
/// derivable from public values, so they are deleted, never decrypted.
const LEGACY_CREDENTIAL_FILES: [&str; 2] = ["credentials.enc", "credentials.enc.tmp"];

/// Backend used for credential storage.
// NIST 800-53 Rev5: IA-5(1), IA-5(6), SC-28
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackend {
    /// Platform keyring (macOS Keychain, Windows Credential Manager, etc.).
    Keyring,
    /// No OS keystore is usable: nothing is persisted. Stores succeed
    /// without writing anything and reads return `None`.
    Unavailable,
}

impl std::fmt::Display for StorageBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keyring => write!(f, "Platform Keyring"),
            Self::Unavailable => write!(f, "Unavailable"),
        }
    }
}

/// Secure credential storage manager.
///
/// Uses the platform keyring when it is available, otherwise
/// [`StorageBackend::Unavailable`] (no persistence). On every initialisation
/// it deletes any legacy `credentials.enc` / `credentials.enc.tmp` in the
/// config directory without reading them.
// NIST 800-53 Rev5: IA-5(1), IA-5(6), SC-28
pub struct CredentialStore {
    backend: StorageBackend,
    /// Config directory (kept for diagnostics; legacy cleanup runs at construction).
    config_dir: PathBuf,
}

impl CredentialStore {
    /// Creates a new credential store, auto-detecting the available backend.
    ///
    /// Removes legacy credential files from `config_dir` first (best
    /// effort; never fails), then uses the platform keyring if it is
    /// accessible, otherwise [`StorageBackend::Unavailable`].
    pub fn new(config_dir: PathBuf) -> AppResult<Self> {
        Self::remove_legacy_files(&config_dir);
        let backend = Self::detect_backend();
        info!(backend = %backend, "Credential store initialized");

        Ok(Self {
            backend,
            config_dir,
        })
    }

    /// Test seam: a store initialised as if the platform keyring were absent
    /// or its probe had failed, without touching the OS keychain.
    ///
    /// Runs the same legacy-file cleanup as [`Self::new`]. Compiled into unit
    /// tests only; release builds do not contain it.
    // NIST 800-53 Rev5: CM-7 (least functionality).
    #[cfg(test)]
    pub(crate) fn without_keyring(config_dir: PathBuf) -> Self {
        Self::remove_legacy_files(&config_dir);
        Self {
            backend: StorageBackend::Unavailable,
            config_dir,
        }
    }

    /// Best-effort removal of the files written by the removed
    /// encrypted-file backend.
    ///
    /// `remove_file` acts on the path itself: a symlink is unlinked and its
    /// target is left alone. A missing file is the normal case; any other
    /// error (a directory of that name, permissions) is logged and ignored.
    /// The log carries only the path and the I/O error, never file content.
    // NIST 800-53 Rev5: SC-28, IA-5(6) (the weakly keyed legacy file is unlinked, never read; unlink is not media sanitisation, see POA&M-372)
    fn remove_legacy_files(config_dir: &Path) {
        for name in LEGACY_CREDENTIAL_FILES {
            let path = config_dir.join(name);
            match fs::remove_file(&path) {
                Ok(()) => warn!(
                    path = %path.display(),
                    "Removed legacy credential file; stored secrets must be re-entered and should be rotated"
                ),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => warn!(
                    path = %path.display(),
                    error = %e,
                    "Could not remove legacy credential file"
                ),
            }
        }
    }

    /// Detects the best available storage backend.
    fn detect_backend() -> StorageBackend {
        // The keyring dependency only exists on desktop platforms (see
        // Cargo.toml target tables). Everywhere else, and on a desktop whose
        // keyring probe fails, nothing is persisted.
        #[cfg(all(
            any(feature = "digest-auth", feature = "oidc"),
            any(windows, target_os = "macos", target_os = "linux")
        ))]
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
                            warn!(error = %e, "Platform keyring not accessible; credentials will not be persisted");
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Platform keyring not available; credentials will not be persisted");
                }
            }
        }

        // POAM: POA&M-372 -- no iOS Keychain / Android Keystore provider;
        // mobile and keyring-less desktop builds do not persist digest
        // passwords or OIDC refresh tokens (the user signs in each launch).
        #[cfg(not(all(
            any(feature = "digest-auth", feature = "oidc"),
            any(windows, target_os = "macos", target_os = "linux")
        )))]
        info!("No platform keystore on this target; credentials will not be persisted");

        StorageBackend::Unavailable
    }

    /// Returns which backend is being used.
    pub const fn backend(&self) -> StorageBackend {
        self.backend
    }

    /// Stores a password for an account.
    ///
    /// With [`StorageBackend::Unavailable`] this writes nothing and returns
    /// `Ok(())`; callers that need to know use [`Self::backend`].
    pub fn store_password(&mut self, account_id: &str, password: &str) -> AppResult<()> {
        match self.backend {
            StorageBackend::Keyring => self.store_keyring(account_id, password),
            // POAM: POA&M-372 -- no OS keystore: secret is not persisted.
            StorageBackend::Unavailable => {
                debug!(account_id = %account_id, "No credential backend; password not persisted");
                Ok(())
            }
        }
    }

    /// Retrieves a password for an account.
    ///
    /// With [`StorageBackend::Unavailable`] this returns `Ok(None)` without
    /// touching the filesystem.
    pub fn get_password(&mut self, account_id: &str) -> AppResult<Option<Zeroizing<String>>> {
        match self.backend {
            StorageBackend::Keyring => self.get_keyring(account_id),
            StorageBackend::Unavailable => Ok(None),
        }
    }

    /// Deletes a password for an account.
    ///
    /// With [`StorageBackend::Unavailable`] there is nothing to delete.
    pub fn delete_password(&mut self, account_id: &str) -> AppResult<()> {
        match self.backend {
            StorageBackend::Keyring => self.delete_keyring(account_id),
            StorageBackend::Unavailable => Ok(()),
        }
    }

    // ========== Keyring Backend ==========

    #[cfg(all(
        any(feature = "digest-auth", feature = "oidc"),
        any(windows, target_os = "macos", target_os = "linux")
    ))]
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

    #[cfg(not(all(
        any(feature = "digest-auth", feature = "oidc"),
        any(windows, target_os = "macos", target_os = "linux")
    )))]
    #[allow(clippy::unused_self)]
    fn store_keyring(&self, _account_id: &str, _password: &str) -> AppResult<()> {
        Err(AppError::Settings(
            "Keyring storage not available".to_string(),
        ))
    }

    #[cfg(all(
        any(feature = "digest-auth", feature = "oidc"),
        any(windows, target_os = "macos", target_os = "linux")
    ))]
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

    #[cfg(not(all(
        any(feature = "digest-auth", feature = "oidc"),
        any(windows, target_os = "macos", target_os = "linux")
    )))]
    #[allow(clippy::unused_self)]
    fn get_keyring(&self, _account_id: &str) -> AppResult<Option<Zeroizing<String>>> {
        Err(AppError::Settings(
            "Keyring storage not available".to_string(),
        ))
    }

    #[cfg(all(
        any(feature = "digest-auth", feature = "oidc"),
        any(windows, target_os = "macos", target_os = "linux")
    ))]
    #[allow(clippy::unused_self)]
    fn delete_keyring(&self, account_id: &str) -> AppResult<()> {
        delete_keyring_entry(account_id)
    }

    #[cfg(not(all(
        any(feature = "digest-auth", feature = "oidc"),
        any(windows, target_os = "macos", target_os = "linux")
    )))]
    #[allow(clippy::unused_self)]
    fn delete_keyring(&self, _account_id: &str) -> AppResult<()> {
        Err(AppError::Settings(
            "Keyring storage not available".to_string(),
        ))
    }
}

/// Deletes the keyring entry for `account_id` directly, without a
/// [`CredentialStore`].
///
/// Used for best-effort deletion (sign-out, password removal) when the
/// keyring probe failed at start-up and no store was kept: a secret stored
/// by an earlier session may still be in the keyring. A missing entry is
/// `Ok(())`; any other keyring error is returned.
// NIST 800-53 Rev5: IA-5(6) (a stored authenticator is removed on request
// even when the keyring probe failed at start-up)
#[cfg(all(
    any(feature = "digest-auth", feature = "oidc"),
    any(windows, target_os = "macos", target_os = "linux")
))]
pub(crate) fn delete_keyring_entry(account_id: &str) -> AppResult<()> {
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

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStore")
            .field("backend", &self.backend)
            .field("config_dir", &self.config_dir)
            .finish()
    }
}

/// Fixtures that reproduce the pre-SR-47 `credentials.enc` format, so tests
/// can prove a legacy file is never decrypted and is removed on init.
///
/// The derivation is copied here on purpose: the production code must no
/// longer contain it.
#[cfg(test)]
#[cfg(any(feature = "digest-auth", feature = "oidc"))]
pub(crate) mod legacy_fixture {
    use std::collections::HashMap;

    /// A random per-run test secret, so no credential literal is compiled
    /// into the tests.
    pub fn test_secret() -> String {
        use std::fmt::Write as _;
        uc_crypto::random::generate_random::<16>()
            .unwrap()
            .iter()
            .fold(String::with_capacity(32), |mut out, b| {
                let _ = write!(out, "{b:02x}");
                out
            })
    }
    use std::path::{Path, PathBuf};

    /// Legacy encrypted credentials file name.
    pub const LEGACY_FILE: &str = "credentials.enc";
    /// Legacy temp file left by an interrupted atomic write.
    pub const LEGACY_TMP_FILE: &str = "credentials.enc.tmp";

    const AAD: &[u8] = b"credentials";

    /// Old key: `HKDF-SHA384`(salt = fixed constant,
    /// ikm = `"hostname:username:config_dir"`, info = "aes-256-gcm-key").
    /// Every input is public or guessable (SR-47).
    fn legacy_key(config_dir: &Path) -> uc_crypto::aead::RandomNonceKey {
        let hostname = hostname::get().map_or_else(
            |_| "unknown".to_string(),
            |h| h.to_string_lossy().to_string(),
        );
        let username = whoami::username();
        let ikm = format!("{hostname}:{username}:{}", config_dir.to_string_lossy());
        let mut key_bytes = [0u8; 32];
        uc_crypto::hkdf::hkdf_sha384(
            Some(b"usg-sip-client-credential-store-v1"),
            ikm.as_bytes(),
            &[b"aes-256-gcm-key"],
            &mut key_bytes,
        )
        .unwrap();
        let key = uc_crypto::aead::RandomNonceKey::new(&key_bytes).unwrap();
        zeroize::Zeroize::zeroize(&mut key_bytes);
        key
    }

    /// Writes `<config_dir>/credentials.enc` as the old code would have:
    /// `nonce(12) || AES-256-GCM(JSON map)` with AAD `b"credentials"`.
    pub fn write_legacy_credentials(config_dir: &Path, entries: &[(&str, &str)]) -> PathBuf {
        let map: HashMap<String, String> = entries
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let json = serde_json::to_string(&map).unwrap();
        let (nonce, ciphertext) = legacy_key(config_dir).seal(AAD, json.as_bytes()).unwrap();
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ciphertext);
        let path = config_dir.join(LEGACY_FILE);
        std::fs::write(&path, out).unwrap();
        path
    }

    /// Decrypts a legacy file with the old derivation (fixture self-check).
    pub fn read_legacy_credentials(config_dir: &Path) -> HashMap<String, String> {
        let data = std::fs::read(config_dir.join(LEGACY_FILE)).unwrap();
        let nonce: [u8; 12] = data[..12].try_into().unwrap();
        let plaintext = legacy_key(config_dir)
            .open(&nonce, AAD, &data[12..])
            .unwrap();
        serde_json::from_slice(&plaintext).unwrap()
    }

    /// Names of every entry in `dir` (sorted), for "nothing on disk" checks.
    pub fn dir_entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_storage_backend_display() {
        assert_eq!(StorageBackend::Keyring.to_string(), "Platform Keyring");
    }

    #[test]
    fn test_credential_store_new() {
        let dir = tempdir().unwrap();
        let store = CredentialStore::new(dir.path().to_path_buf()).unwrap();
        // SR-47: either the platform keyring, or no persistence at all.
        // There is no file backend.
        let backend = store.backend();
        assert!(
            backend == StorageBackend::Keyring || backend.to_string() == "Unavailable",
            "unexpected credential backend: {backend}"
        );
    }

    /// SR-47 contract: a store with no keyring reports the `Unavailable`
    /// backend (Display "Unavailable").
    #[test]
    fn no_keyring_backend_reports_unavailable() {
        let dir = tempdir().unwrap();
        let store = CredentialStore::without_keyring(dir.path().to_path_buf());
        assert_eq!(store.backend().to_string(), "Unavailable");
    }
}

/// SR-47: with no platform keyring, secrets are never persisted and the
/// legacy weakly keyed `credentials.enc` is neither read nor kept.
// NIST 800-53 Rev5: IA-5(1), IA-5(6), SC-28 (tests: no secret persisted without an OS keystore; legacy file removed, never read)
#[cfg(test)]
#[cfg(any(feature = "digest-auth", feature = "oidc"))]
mod no_keyring_tests {
    use super::legacy_fixture::{
        LEGACY_FILE, LEGACY_TMP_FILE, dir_entries, read_legacy_credentials, test_secret,
        write_legacy_credentials,
    };
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn store_password_without_keyring_is_ok_and_writes_nothing() {
        let dir = tempdir().unwrap();
        let mut store = CredentialStore::without_keyring(dir.path().to_path_buf());

        store.store_password("acct", &test_secret()).unwrap();

        assert!(
            dir_entries(dir.path()).is_empty(),
            "no keyring: config dir must stay empty, found {:?}",
            dir_entries(dir.path())
        );
    }

    #[test]
    fn get_after_store_without_keyring_returns_none() {
        let dir = tempdir().unwrap();
        let mut store = CredentialStore::without_keyring(dir.path().to_path_buf());

        store.store_password("acct", &test_secret()).unwrap();
        let got = store.get_password("acct").unwrap();

        assert!(got.is_none(), "no keyring: secret must not be persisted");
    }

    #[test]
    fn delete_without_keyring_is_ok_and_writes_nothing() {
        let dir = tempdir().unwrap();
        let mut store = CredentialStore::without_keyring(dir.path().to_path_buf());

        store.delete_password("acct").unwrap();

        assert_eq!(dir_entries(dir.path()), Vec::<String>::new());
    }

    /// Guards the fixture: the legacy file really is a valid ciphertext under
    /// the old derivation, so a `None` from `get_password` below means
    /// "never read", not "failed to decrypt".
    #[test]
    fn legacy_fixture_is_valid_old_format() {
        let dir = tempdir().unwrap();
        write_legacy_credentials(dir.path(), &[("acct", "legacy-secret")]);
        let map = read_legacy_credentials(dir.path());
        assert_eq!(map.get("acct").map(String::as_str), Some("legacy-secret"));
    }

    #[test]
    fn get_without_keyring_ignores_valid_legacy_ciphertext() {
        let dir = tempdir().unwrap();
        write_legacy_credentials(dir.path(), &[("acct", "legacy-secret")]);

        let mut store = CredentialStore::without_keyring(dir.path().to_path_buf());
        let got = store.get_password("acct").unwrap();

        assert!(
            got.is_none(),
            "legacy credentials.enc must never be decrypted"
        );
    }

    #[test]
    fn init_without_keyring_deletes_legacy_file() {
        let dir = tempdir().unwrap();
        let legacy = write_legacy_credentials(dir.path(), &[("acct", "legacy-secret")]);

        let _store = CredentialStore::without_keyring(dir.path().to_path_buf());

        assert!(
            !legacy.exists(),
            "legacy credentials.enc must be deleted on store init"
        );
    }

    #[test]
    fn init_without_keyring_deletes_legacy_tmp_file() {
        let dir = tempdir().unwrap();
        let tmp = dir.path().join(LEGACY_TMP_FILE);
        std::fs::write(&tmp, b"partial legacy write").unwrap();

        let _store = CredentialStore::without_keyring(dir.path().to_path_buf());

        assert!(
            !tmp.exists(),
            "legacy credentials.enc.tmp must be deleted on store init"
        );
    }

    /// Cleanup runs on every initialisation, not only when the keyring is
    /// missing: a desktop that once fell back still has the file.
    #[test]
    fn init_with_detected_backend_deletes_legacy_files() {
        let dir = tempdir().unwrap();
        let legacy = write_legacy_credentials(dir.path(), &[("acct", "legacy-secret")]);
        let tmp = dir.path().join(LEGACY_TMP_FILE);
        std::fs::write(&tmp, b"partial legacy write").unwrap();

        let _store = CredentialStore::new(dir.path().to_path_buf()).unwrap();

        assert!(!legacy.exists(), "credentials.enc must be deleted by new()");
        assert!(
            !tmp.exists(),
            "credentials.enc.tmp must be deleted by new()"
        );
    }

    /// A corrupt or truncated legacy file is not an error: it is removed and
    /// `get` reports nothing stored.
    #[test]
    fn corrupt_legacy_file_is_deleted_and_get_returns_none() {
        let dir = tempdir().unwrap();
        let legacy = dir.path().join(LEGACY_FILE);
        std::fs::write(&legacy, b"short").unwrap();

        let mut store = CredentialStore::without_keyring(dir.path().to_path_buf());
        let got = store.get_password("acct").unwrap();

        assert!(got.is_none());
        assert!(!legacy.exists());
    }

    /// Best-effort cleanup: a directory squatting on the legacy name must not
    /// make init or `get` fail.
    #[test]
    fn legacy_name_as_directory_does_not_fail() {
        let dir = tempdir().unwrap();
        std::fs::create_dir(dir.path().join(LEGACY_FILE)).unwrap();

        let mut store = CredentialStore::without_keyring(dir.path().to_path_buf());
        let got = store.get_password("acct").unwrap();
        assert!(got.is_none());
        store.store_password("acct", &test_secret()).unwrap();
    }

    /// Deleting a legacy symlink unlinks the link only; the target outside
    /// `config_dir` is untouched.
    #[cfg(unix)]
    #[test]
    fn legacy_symlink_is_unlinked_and_target_kept() {
        let dir = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let target = outside.path().join("victim.txt");
        std::fs::write(&target, b"do not delete").unwrap();
        let link = dir.path().join(LEGACY_FILE);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let _store = CredentialStore::without_keyring(dir.path().to_path_buf());

        assert!(
            std::fs::symlink_metadata(&link).is_err(),
            "legacy symlink must be unlinked"
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"do not delete");
    }
}
