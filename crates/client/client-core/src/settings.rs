//! Settings persistence for the SIP soft client.
//!
//! Stores user preferences and account configuration in TOML format.
//! Uses platform-specific directories (`%APPDATA%` on Windows).

use crate::{AppError, AppResult};
use client_types::{AudioConfig, ServerCertVerificationMode, SipAccount};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Application settings stored in TOML format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Application version (for migration purposes).
    #[serde(default = "default_version")]
    pub version: String,

    /// General application settings.
    #[serde(default)]
    pub general: GeneralSettings,

    /// Audio settings.
    #[serde(default)]
    pub audio: AudioConfig,

    /// SIP accounts (by account ID).
    #[serde(default)]
    pub accounts: HashMap<String, SipAccount>,

    /// Network settings.
    #[serde(default)]
    pub network: NetworkSettings,

    /// UI preferences.
    #[serde(default)]
    pub ui: UiSettings,

    /// Certificate filter settings.
    #[serde(default)]
    pub certificates: CertificateFilterSettings,
}

fn default_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// General application settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct GeneralSettings {
    /// Start minimized to system tray.
    #[serde(default)]
    pub start_minimized: bool,

    /// Minimize to tray instead of closing.
    #[serde(default = "default_true")]
    pub minimize_to_tray: bool,

    /// Auto-start with Windows.
    #[serde(default)]
    pub auto_start: bool,

    /// Check for updates on startup.
    #[serde(default = "default_true")]
    pub check_updates: bool,

    /// Enable debug logging.
    #[serde(default)]
    pub debug_logging: bool,

    /// Default account ID to use.
    #[serde(default)]
    pub default_account: Option<String>,

    /// Enable auto-answer for incoming calls.
    #[serde(default)]
    pub auto_answer_enabled: bool,

    /// Delay in seconds before auto-answering (0 = immediate).
    #[serde(default = "default_auto_answer_delay")]
    pub auto_answer_delay_secs: u32,
}

const fn default_auto_answer_delay() -> u32 {
    3
}

impl Default for GeneralSettings {
    fn default() -> Self {
        Self {
            start_minimized: false,
            minimize_to_tray: true,
            auto_start: false,
            check_updates: true,
            debug_logging: false,
            default_account: None,
            auto_answer_enabled: false,
            auto_answer_delay_secs: default_auto_answer_delay(),
        }
    }
}

/// Network settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// STUN server URI (e.g., "stun:stun.example.com:3478").
    #[serde(default)]
    pub stun_server: Option<String>,

    /// TURN server URI (e.g., "turn:turn.example.com:3478").
    #[serde(default)]
    pub turn_server: Option<String>,

    /// TURN username (if using long-term credentials).
    #[serde(default)]
    pub turn_username: Option<String>,

    /// Local port range start for RTP.
    #[serde(default = "default_rtp_port_start")]
    pub rtp_port_start: u16,

    /// Local port range end for RTP.
    #[serde(default = "default_rtp_port_end")]
    pub rtp_port_end: u16,

    /// Enable ICE.
    #[serde(default = "default_true")]
    pub enable_ice: bool,

    /// ICE nomination mode (aggressive vs regular).
    #[serde(default)]
    pub aggressive_nomination: bool,

    /// Server certificate verification mode.
    ///
    /// Controls how the client verifies TLS server certificates:
    /// - `System` (default): Uses the OS trusted CA store
    /// - `Custom`: Uses a custom CA certificate file
    /// - `Insecure`: Disables verification (development only)
    #[serde(default)]
    pub server_cert_verification: ServerCertVerificationMode,
}

const fn default_rtp_port_start() -> u16 {
    16384
}

const fn default_rtp_port_end() -> u16 {
    32767
}

const fn default_true() -> bool {
    true
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            stun_server: None,
            turn_server: None,
            turn_username: None,
            rtp_port_start: default_rtp_port_start(),
            rtp_port_end: default_rtp_port_end(),
            enable_ice: true,
            aggressive_nomination: false,
            server_cert_verification: ServerCertVerificationMode::default(),
        }
    }
}

/// UI preferences.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct UiSettings {
    /// Window width.
    #[serde(default = "default_window_width")]
    pub window_width: u32,

    /// Window height.
    #[serde(default = "default_window_height")]
    pub window_height: u32,

    /// Window X position (None = center).
    #[serde(default)]
    pub window_x: Option<i32>,

    /// Window Y position (None = center).
    #[serde(default)]
    pub window_y: Option<i32>,

    /// Dark mode.
    #[serde(default = "default_true")]
    pub dark_mode: bool,

    /// Show call duration in call view.
    #[serde(default = "default_true")]
    pub show_call_duration: bool,

    /// Confirm before hanging up.
    #[serde(default)]
    pub confirm_hangup: bool,

    /// Sort contacts alphabetically.
    #[serde(default = "default_true")]
    pub sort_contacts_alpha: bool,

    /// Classification level (unclassified, cui, confidential, secret, top-secret, top-secret-sci).
    #[serde(default = "default_classification")]
    pub classification_level: String,

    /// SCI caveats (e.g., SI, TK, G, HCS).
    #[serde(default)]
    pub classification_caveats: Vec<String>,

    /// Dissemination controls (e.g., NOFORN, RELTO, ORCON).
    #[serde(default)]
    pub classification_dissem: Vec<String>,
}

fn default_classification() -> String {
    "unclassified".to_string()
}

const fn default_window_width() -> u32 {
    400
}

const fn default_window_height() -> u32 {
    600
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            window_width: default_window_width(),
            window_height: default_window_height(),
            window_x: None,
            window_y: None,
            dark_mode: true,
            show_call_duration: true,
            confirm_hangup: false,
            sort_contacts_alpha: true,
            classification_level: default_classification(),
            classification_caveats: Vec::new(),
            classification_dissem: Vec::new(),
        }
    }
}

/// Certificate filter settings for controlling which certificates are displayed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct CertificateFilterSettings {
    /// Only show certificates from these trusted CA issuers.
    /// If empty, all certificates are shown.
    /// Matches against issuer CN (Common Name).
    #[serde(default = "default_trusted_issuers")]
    pub trusted_issuers: Vec<String>,

    /// Only show certificates with Smart Card Logon EKU (1.3.6.1.4.1.311.20.2.2).
    #[serde(default = "default_true")]
    pub require_smart_card_logon_eku: bool,

    /// Only show certificates with Client Authentication EKU (1.3.6.1.5.5.7.3.2).
    #[serde(default = "default_true")]
    pub require_client_auth_eku: bool,

    /// Hide expired certificates.
    #[serde(default = "default_true")]
    pub hide_expired: bool,

    /// Only show certificates from YubiKey/smart cards (not software certs).
    #[serde(default)]
    pub smart_card_only: bool,

    /// Exclude certificates where the subject CN is numeric-only.
    /// This filters out Card Authentication certificates (e.g., "CN=33952358")
    /// which are not user identity certificates.
    #[serde(default = "default_true")]
    pub exclude_numeric_cn: bool,
}

/// Default list of trusted DOD CA issuers.
fn default_trusted_issuers() -> Vec<String> {
    vec![
        // DOD Root CAs
        "DOD ROOT CA 3".to_string(),
        "DOD ROOT CA 4".to_string(),
        "DOD ROOT CA 5".to_string(),
        "DOD ROOT CA 6".to_string(),
        // DOD Intermediate CAs (ID/CAC)
        "DOD ID CA-59".to_string(),
        "DOD ID CA-62".to_string(),
        "DOD ID CA-63".to_string(),
        "DOD ID CA-64".to_string(),
        "DOD ID CA-65".to_string(),
        "DOD ID CA-66".to_string(),
        "DOD ID CA-67".to_string(),
        "DOD ID CA-68".to_string(),
        "DOD ID CA-69".to_string(),
        "DOD ID CA-70".to_string(),
        "DOD ID CA-71".to_string(),
        "DOD ID CA-72".to_string(),
        "DOD ID CA-73".to_string(),
        // DOD SW (Software) CAs
        "DOD ID SW CA-59".to_string(),
        "DOD ID SW CA-60".to_string(),
        "DOD ID SW CA-61".to_string(),
        "DOD ID SW CA-62".to_string(),
        "DOD ID SW CA-63".to_string(),
        "DOD ID SW CA-64".to_string(),
        "DOD ID SW CA-65".to_string(),
        "DOD ID SW CA-66".to_string(),
        "DOD ID SW CA-67".to_string(),
        "DOD ID SW CA-68".to_string(),
        "DOD ID SW CA-69".to_string(),
        "DOD ID SW CA-70".to_string(),
        "DOD ID SW CA-71".to_string(),
        // DOD Email CAs
        "DOD EMAIL CA-59".to_string(),
        "DOD EMAIL CA-62".to_string(),
        "DOD EMAIL CA-63".to_string(),
        "DOD EMAIL CA-64".to_string(),
        "DOD EMAIL CA-65".to_string(),
        "DOD EMAIL CA-66".to_string(),
        "DOD EMAIL CA-67".to_string(),
        "DOD EMAIL CA-68".to_string(),
        "DOD EMAIL CA-69".to_string(),
        "DOD EMAIL CA-70".to_string(),
        "DOD EMAIL CA-71".to_string(),
        // DOD DERILITY CAs (from your YubiKey)
        "DOD DERILITY CA-1".to_string(),
        "DOD DERILITY CA-2".to_string(),
        "DOD DERILITY CA-3".to_string(),
        "DOD DERILITY CA-4".to_string(),
        // ECA (External Certificate Authority)
        "ECA Root CA 4".to_string(),
        "ECA Subordinate CA 4A".to_string(),
        // Federal PKI
        "Federal Bridge CA G4".to_string(),
        "Federal Common Policy CA G2".to_string(),
    ]
}

impl Default for CertificateFilterSettings {
    fn default() -> Self {
        Self {
            trusted_issuers: default_trusted_issuers(),
            require_smart_card_logon_eku: true,
            require_client_auth_eku: true,
            hide_expired: true,
            smart_card_only: false,
            exclude_numeric_cn: true,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: default_version(),
            general: GeneralSettings::default(),
            audio: AudioConfig::default(),
            accounts: HashMap::new(),
            network: NetworkSettings::default(),
            ui: UiSettings::default(),
            certificates: CertificateFilterSettings::default(),
        }
    }
}

/// Settings manager for loading and saving configuration.
pub struct SettingsManager {
    /// Current settings.
    settings: Settings,
    /// Path to settings file.
    settings_path: PathBuf,
    /// Whether settings have been modified since last save.
    dirty: bool,
    /// Secure credential storage (when digest-auth feature is enabled).
    #[cfg(feature = "digest-auth")]
    credential_store: Option<crate::credential_store::CredentialStore>,
}

impl SettingsManager {
    /// Creates a new settings manager, loading from disk if available.
    pub fn new() -> AppResult<Self> {
        let settings_path = Self::settings_file_path()?;

        #[cfg(feature = "digest-auth")]
        let config_dir = settings_path
            .parent()
            .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);

        let settings = if settings_path.exists() {
            Self::load_from_file(&settings_path)?
        } else {
            info!("No settings file found, using defaults");
            Settings::default()
        };

        #[cfg(feature = "digest-auth")]
        let credential_store = match crate::credential_store::CredentialStore::new(config_dir) {
            Ok(store) => {
                info!(backend = %store.backend(), "Credential store initialized");
                Some(store)
            }
            Err(e) => {
                warn!(error = %e, "Failed to initialize credential store");
                None
            }
        };

        Ok(Self {
            settings,
            settings_path,
            dirty: false,
            #[cfg(feature = "digest-auth")]
            credential_store,
        })
    }

    /// Creates a settings manager with a custom path (for testing).
    pub fn with_path(path: PathBuf) -> AppResult<Self> {
        #[cfg(feature = "digest-auth")]
        let config_dir = path
            .parent()
            .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);

        let settings = if path.exists() {
            Self::load_from_file(&path)?
        } else {
            Settings::default()
        };

        #[cfg(feature = "digest-auth")]
        let credential_store = crate::credential_store::CredentialStore::new(config_dir).ok();

        Ok(Self {
            settings,
            settings_path: path,
            dirty: false,
            #[cfg(feature = "digest-auth")]
            credential_store,
        })
    }

    /// Gets the platform-specific settings file path.
    fn settings_file_path() -> AppResult<PathBuf> {
        let proj_dirs = ProjectDirs::from("com", "usg", "sip-client").ok_or_else(|| {
            AppError::Settings("Could not determine config directory".to_string())
        })?;

        let config_dir = proj_dirs.config_dir();

        // Create directory if it doesn't exist
        if !config_dir.exists() {
            fs::create_dir_all(config_dir)?;
            debug!(path = ?config_dir, "Created config directory");
        }

        Ok(config_dir.join("settings.toml"))
    }

    /// Loads settings from a TOML file.
    fn load_from_file(path: &std::path::Path) -> AppResult<Settings> {
        let content = fs::read_to_string(path)?;
        let settings: Settings = toml::from_str(&content)
            .map_err(|e| AppError::Serialization(format!("Failed to parse settings: {e}")))?;

        info!(path = ?path, "Loaded settings");
        Ok(settings)
    }

    /// Gets the current settings.
    pub const fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Gets mutable access to settings (marks as dirty).
    #[allow(clippy::missing_const_for_fn)]
    pub fn settings_mut(&mut self) -> &mut Settings {
        self.dirty = true;
        &mut self.settings
    }

    /// Returns whether settings have unsaved changes.
    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Saves settings to disk.
    pub fn save(&mut self) -> AppResult<()> {
        let content = toml::to_string_pretty(&self.settings)
            .map_err(|e| AppError::Serialization(format!("Failed to serialize settings: {e}")))?;

        // Write to temp file first, then rename (atomic on most filesystems)
        let temp_path = self.settings_path.with_extension("toml.tmp");
        fs::write(&temp_path, &content)?;
        fs::rename(&temp_path, &self.settings_path)?;

        self.dirty = false;
        info!(path = ?self.settings_path, "Saved settings");
        Ok(())
    }

    /// Saves settings if modified.
    pub fn save_if_dirty(&mut self) -> AppResult<()> {
        if self.dirty { self.save() } else { Ok(()) }
    }

    /// Gets the settings file path.
    pub fn path(&self) -> &std::path::Path {
        &self.settings_path
    }

    /// Adds or updates a SIP account.
    pub fn set_account(&mut self, account: SipAccount) {
        self.dirty = true;
        self.settings.accounts.insert(account.id.clone(), account);
    }

    /// Removes a SIP account.
    pub fn remove_account(&mut self, account_id: &str) -> Option<SipAccount> {
        self.dirty = true;
        self.settings.accounts.remove(account_id)
    }

    /// Gets an account by ID.
    pub fn get_account(&self, account_id: &str) -> Option<&SipAccount> {
        self.settings.accounts.get(account_id)
    }

    /// Gets all accounts.
    pub fn accounts(&self) -> impl Iterator<Item = &SipAccount> {
        self.settings.accounts.values()
    }

    /// Gets the default account.
    pub fn default_account(&self) -> Option<&SipAccount> {
        self.settings
            .general
            .default_account
            .as_ref()
            .and_then(|id| self.settings.accounts.get(id))
    }

    /// Sets the default account.
    pub fn set_default_account(&mut self, account_id: Option<String>) {
        self.dirty = true;
        self.settings.general.default_account = account_id;
    }

    /// Resets settings to defaults.
    pub fn reset(&mut self) {
        self.settings = Settings::default();
        self.dirty = true;
        warn!("Settings reset to defaults");
    }

    // ========== Credential Storage Methods ==========

    /// Stores a digest password for an account in secure credential storage.
    ///
    /// This stores the password in platform keyring (macOS Keychain, Windows
    /// Credential Manager) or an encrypted file as fallback.
    ///
    /// Returns `Ok(true)` if the password was stored, `Ok(false)` if credential
    /// storage is not available.
    #[cfg(feature = "digest-auth")]
    pub fn store_digest_password(&mut self, account_id: &str, password: &str) -> AppResult<bool> {
        if let Some(ref mut store) = self.credential_store {
            store.store_password(account_id, password)?;
            info!(account_id = %account_id, "Digest password stored in credential storage");
            Ok(true)
        } else {
            warn!("Credential storage not available");
            Ok(false)
        }
    }

    /// Retrieves a digest password for an account from secure credential storage.
    ///
    /// Returns `None` if no password is stored or credential storage is not available.
    #[cfg(feature = "digest-auth")]
    pub fn get_digest_password(
        &mut self,
        account_id: &str,
    ) -> AppResult<Option<zeroize::Zeroizing<String>>> {
        self.credential_store
            .as_mut()
            .map_or_else(|| Ok(None), |store| store.get_password(account_id))
    }

    /// Deletes a digest password for an account from secure credential storage.
    #[cfg(feature = "digest-auth")]
    pub fn delete_digest_password(&mut self, account_id: &str) -> AppResult<()> {
        if let Some(ref mut store) = self.credential_store {
            store.delete_password(account_id)?;
            info!(account_id = %account_id, "Digest password deleted from credential storage");
        }
        Ok(())
    }

    /// Loads persisted passwords for all accounts that have `password_persisted` set.
    ///
    /// Call this after loading settings to populate passwords from credential storage.
    #[cfg(feature = "digest-auth")]
    pub fn load_persisted_passwords(&mut self) -> AppResult<()> {
        // First, collect account IDs that need password loading
        let accounts_needing_passwords: Vec<String> = self
            .settings
            .accounts
            .iter()
            .filter_map(|(id, account)| {
                account.digest_credentials.as_ref().and_then(|creds| {
                    if creds.password_persisted && creds.password.is_empty() {
                        Some(id.clone())
                    } else {
                        None
                    }
                })
            })
            .collect();

        // Now load passwords from credential store
        let Some(store) = self.credential_store.as_mut() else {
            return Ok(());
        };

        for account_id in accounts_needing_passwords {
            if let Ok(Some(password)) = store.get_password(&account_id)
                && let Some(account) = self.settings.accounts.get_mut(&account_id)
                && let Some(ref mut creds) = account.digest_credentials
            {
                creds.password = password;
                debug!(account_id = %account_id, "Loaded persisted password");
            }
        }

        Ok(())
    }

    /// Persists passwords for all accounts that have non-empty passwords.
    ///
    /// Call this after modifying account credentials to save them to credential storage.
    #[cfg(feature = "digest-auth")]
    pub fn persist_account_passwords(&mut self) -> AppResult<()> {
        use zeroize::Zeroize;

        let mut accounts_to_persist: Vec<(String, String)> = self
            .settings
            .accounts
            .iter()
            .filter_map(|(id, account)| {
                account.digest_credentials.as_ref().and_then(|creds| {
                    if creds.password.is_empty() {
                        None
                    } else {
                        Some((id.clone(), creds.password.to_string()))
                    }
                })
            })
            .collect();

        for (account_id, password) in &accounts_to_persist {
            if self.store_digest_password(account_id, password)?
                && let Some(account) = self.settings.accounts.get_mut(account_id)
                && let Some(ref mut creds) = account.digest_credentials
            {
                creds.password_persisted = true;
            }
        }

        // Zeroize plaintext passwords from temporary vector
        for (_, password) in &mut accounts_to_persist {
            password.zeroize();
        }

        Ok(())
    }

    /// Returns information about the credential storage backend being used.
    #[cfg(feature = "digest-auth")]
    pub fn credential_storage_backend(&self) -> Option<crate::credential_store::StorageBackend> {
        self.credential_store
            .as_ref()
            .map(crate::credential_store::CredentialStore::backend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_types::CertificateConfig;
    use tempfile::tempdir;

    fn test_account() -> SipAccount {
        SipAccount {
            id: "test".to_string(),
            display_name: "Test User".to_string(),
            sip_uri: "sip:test@example.com".to_string(),
            registrar_uri: "sips:192.168.1.1:5061".to_string(),
            outbound_proxy: None,
            transport: client_types::TransportPreference::TlsOnly,
            register_expiry: 3600,
            stun_server: None,
            turn_config: None,
            enabled: true,
            certificate_config: CertificateConfig::default(),
            caller_id: None,
            #[cfg(feature = "digest-auth")]
            digest_credentials: None,
        }
    }

    #[test]
    fn test_settings_default() {
        let settings = Settings::default();

        assert!(!settings.general.start_minimized);
        assert!(settings.general.minimize_to_tray);
        assert!(settings.ui.dark_mode);
        assert_eq!(settings.network.rtp_port_start, 16384);
    }

    #[test]
    fn test_settings_manager_new_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.toml");

        let manager = SettingsManager::with_path(path).unwrap();

        assert!(!manager.is_dirty());
        assert!(manager.settings().accounts.is_empty());
    }

    #[test]
    fn test_settings_manager_save_load() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.toml");

        // Create and save
        {
            let mut manager = SettingsManager::with_path(path.clone()).unwrap();
            manager.set_account(test_account());
            manager.settings_mut().general.start_minimized = true;
            manager.save().unwrap();
        }

        // Load and verify
        {
            let manager = SettingsManager::with_path(path).unwrap();
            assert!(manager.get_account("test").is_some());
            assert!(manager.settings().general.start_minimized);
        }
    }

    #[test]
    fn test_account_management() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("settings.toml");
        let mut manager = SettingsManager::with_path(path).unwrap();

        // Add account
        manager.set_account(test_account());
        assert!(manager.is_dirty());
        assert!(manager.get_account("test").is_some());

        // Set default
        manager.set_default_account(Some("test".to_string()));
        assert!(manager.default_account().is_some());

        // Remove account
        let removed = manager.remove_account("test");
        assert!(removed.is_some());
        assert!(manager.get_account("test").is_none());
    }

    #[test]
    fn test_settings_serialization() {
        let settings = Settings::default();
        let toml_str = toml::to_string_pretty(&settings).unwrap();

        assert!(toml_str.contains("[general]"));
        assert!(toml_str.contains("[audio]"));
        assert!(toml_str.contains("[network]"));
        assert!(toml_str.contains("[ui]"));
    }
}
