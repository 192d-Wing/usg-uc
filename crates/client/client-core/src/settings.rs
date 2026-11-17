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

    /// OIDC provisioning session (service domain + keychain flag). The
    /// refresh token itself lives in the OS keychain, never in this file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisioning: Option<ProvisioningSettings>,
}

fn default_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Non-secret slice of the OIDC sign-in session persisted across launches.
///
/// Mirrors `client_provisioning::PersistedProvisioning`; kept as a local
/// type so `client-core` does not depend on the provisioning crate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvisioningSettings {
    /// Service domain entered at sign-in (e.g. `sbc.oopl.dev.mil`).
    #[serde(default)]
    pub service_domain: String,
    /// Whether a refresh token for `service_domain` is stored in the OS
    /// keychain (enables silent resume on next launch).
    #[serde(default)]
    pub refresh_token_persisted: bool,
    /// Optional extra CA PEM path used for discovery/IdP TLS trust (the
    /// internal CA), mirrored from the sign-in form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra_ca_cert_file: Option<String>,
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

    /// Offer a "continue anyway" warning when the service presents a TLS
    /// certificate chain this device does not trust (private-CA lab
    /// networks). When false, untrusted certificates are rejected outright
    /// with no override prompt. Release builds ignore this flag: the
    /// override does not exist there, so the prompt is never offered.
    #[serde(default = "default_true")]
    pub allow_untrusted_cert_warning: bool,
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
            allow_untrusted_cert_warning: true,
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
            provisioning: None,
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
    #[cfg(any(feature = "digest-auth", feature = "oidc"))]
    credential_store: Option<crate::credential_store::CredentialStore>,
}

impl SettingsManager {
    /// Creates a new settings manager, loading from disk if available.
    pub fn new() -> AppResult<Self> {
        let settings_path = Self::settings_file_path()?;

        #[cfg(any(feature = "digest-auth", feature = "oidc"))]
        let config_dir = settings_path
            .parent()
            .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);

        let settings = if settings_path.exists() {
            Self::load_from_file(&settings_path)?
        } else {
            info!("No settings file found, using defaults");
            Settings::default()
        };

        #[cfg(any(feature = "digest-auth", feature = "oidc"))]
        let credential_store = match crate::credential_store::CredentialStore::new(config_dir) {
            Ok(store) => Self::usable_credential_store(store),
            Err(e) => {
                warn!(error = %e, "Failed to initialize credential store");
                None
            }
        };

        Ok(Self {
            settings,
            settings_path,
            dirty: false,
            #[cfg(any(feature = "digest-auth", feature = "oidc"))]
            credential_store,
        })
    }

    /// Creates a settings manager with a custom path (for testing).
    pub fn with_path(path: PathBuf) -> AppResult<Self> {
        #[cfg(any(feature = "digest-auth", feature = "oidc"))]
        let config_dir = path
            .parent()
            .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);

        let settings = if path.exists() {
            Self::load_from_file(&path)?
        } else {
            Settings::default()
        };

        #[cfg(any(feature = "digest-auth", feature = "oidc"))]
        let credential_store = crate::credential_store::CredentialStore::new(config_dir)
            .ok()
            .and_then(Self::usable_credential_store);

        Ok(Self {
            settings,
            settings_path: path,
            dirty: false,
            #[cfg(any(feature = "digest-auth", feature = "oidc"))]
            credential_store,
        })
    }

    /// Default settings at `path` with no credential store attached.
    ///
    /// Unlike [`Self::with_path`], this never probes the OS keychain, so
    /// tests built with `digest-auth` / `oidc` stay hermetic.
    #[cfg(test)]
    pub(crate) fn without_credential_store(path: PathBuf) -> Self {
        Self {
            settings: Settings::default(),
            settings_path: path,
            dirty: false,
            #[cfg(any(feature = "digest-auth", feature = "oidc"))]
            credential_store: None,
        }
    }

    /// Test seam: [`Self::with_path`] with the platform keyring forced
    /// unavailable (as on Android/iOS, or a desktop whose keyring probe
    /// fails), without touching the OS keychain.
    // NIST 800-53 Rev5: CM-7 (least functionality).
    #[cfg(all(test, any(feature = "digest-auth", feature = "oidc")))]
    pub(crate) fn with_path_without_keyring(path: PathBuf) -> AppResult<Self> {
        let config_dir = path
            .parent()
            .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);

        let settings = if path.exists() {
            Self::load_from_file(&path)?
        } else {
            Settings::default()
        };

        let credential_store = Self::usable_credential_store(
            crate::credential_store::CredentialStore::without_keyring(config_dir),
        );

        Ok(Self {
            settings,
            settings_path: path,
            dirty: false,
            credential_store,
        })
    }

    /// Keeps a store only if it can persist secrets.
    ///
    /// A store whose backend is [`StorageBackend::Unavailable`] is dropped
    /// (after `CredentialStore::new` has already removed any legacy
    /// credential file), so the `None` branches below report "not
    /// persisted": `store_*` return `Ok(false)` and `get_*` return `None`.
    ///
    /// [`StorageBackend::Unavailable`]: crate::credential_store::StorageBackend::Unavailable
    // NIST 800-53 Rev5: IA-5(1), IA-5(6), SC-28
    #[cfg(any(feature = "digest-auth", feature = "oidc"))]
    fn usable_credential_store(
        store: crate::credential_store::CredentialStore,
    ) -> Option<crate::credential_store::CredentialStore> {
        match store.backend() {
            crate::credential_store::StorageBackend::Keyring => {
                info!(backend = %store.backend(), "Credential store initialized");
                Some(store)
            }
            // POAM: POA&M-372 -- no iOS Keychain / Android Keystore provider;
            // mobile and keyring-less desktop builds do not persist digest
            // passwords or OIDC refresh tokens.
            crate::credential_store::StorageBackend::Unavailable => {
                warn!("No platform keyring; credentials will be kept in memory only");
                None
            }
        }
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
    /// This stores the password in the platform keyring (macOS Keychain,
    /// Windows Credential Manager, Linux Secret Service). There is no file
    /// fallback.
    ///
    /// Returns `Ok(true)` if the password was stored, `Ok(false)` if no
    /// platform keyring is available (Android, iOS, or a desktop whose
    /// keyring probe failed); the password then stays in memory only.
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
    ///
    /// Without a usable store this still attempts a direct keyring delete on
    /// desktop targets (see [`Self::delete_without_store`]); an error is
    /// returned rather than reporting a silent success.
    #[cfg(feature = "digest-auth")]
    pub fn delete_digest_password(&mut self, account_id: &str) -> AppResult<()> {
        if let Some(ref mut store) = self.credential_store {
            store.delete_password(account_id)?;
        } else {
            Self::delete_without_store(account_id)?;
        }
        info!(account_id = %account_id, "Digest password deleted from credential storage");
        Ok(())
    }

    /// Best-effort delete when no credential store was kept.
    ///
    /// On desktop the keyring probe may have failed transiently at start-up
    /// while a secret from an earlier session is still in the keyring, so
    /// the entry is deleted directly (a missing entry is success). On other
    /// targets nothing was ever persisted.
    // NIST 800-53 Rev5: IA-5(6) (sign-out and password removal are not
    // silently skipped when the keyring probe failed)
    #[cfg(any(feature = "digest-auth", feature = "oidc"))]
    fn delete_without_store(key: &str) -> AppResult<()> {
        #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
        {
            crate::credential_store::delete_keyring_entry(key).inspect_err(|e| {
                warn!(error = %e, "Keyring delete without a credential store failed");
            })
        }
        // POAM: POA&M-372 -- no OS keystore on this target: nothing to delete.
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        {
            let _ = key;
            debug!("No platform keystore on this target; nothing to delete");
            Ok(())
        }
    }

    /// Loads persisted passwords for all accounts that have `password_persisted` set.
    ///
    /// Call this after loading settings to populate passwords from credential storage.
    ///
    /// A `password_persisted = true` carried over from an older build is
    /// cleared (and the settings marked dirty) when there is no usable
    /// keyring or the keyring holds no entry for the account. A keyring
    /// read error leaves the flag unchanged.
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
        for account_id in accounts_needing_passwords {
            // `Some(password)` loads it; `None` means nothing is stored
            // (no keyring, or no entry), so the flag is stale. A read error
            // may be transient and keeps the flag.
            let loaded = match self.credential_store.as_mut() {
                // POAM: POA&M-372 -- no OS keystore: nothing was persisted.
                None => None,
                Some(store) => match store.get_password(&account_id) {
                    Ok(password) => password,
                    Err(e) => {
                        warn!(account_id = %account_id, error = %e, "Failed to load persisted password");
                        continue;
                    }
                },
            };
            let Some(creds) = self
                .settings
                .accounts
                .get_mut(&account_id)
                .and_then(|account| account.digest_credentials.as_mut())
            else {
                continue;
            };
            if let Some(password) = loaded {
                creds.password = password;
                debug!(account_id = %account_id, "Loaded persisted password");
            } else {
                creds.password_persisted = false;
                self.dirty = true;
                warn!(
                    account_id = %account_id,
                    "Digest password marked persisted but not in secure storage; flag cleared"
                );
            }
        }

        Ok(())
    }

    /// Persists passwords for all accounts that have non-empty passwords.
    ///
    /// Call this after modifying account credentials to save them to credential storage.
    ///
    /// Returns the number of passwords actually stored. `Ok(0)` with a
    /// non-empty password means no platform keyring is available
    /// (POA&M-372): the password stays in memory only.
    #[cfg(feature = "digest-auth")]
    pub fn persist_account_passwords(&mut self) -> AppResult<usize> {
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

        let mut persisted = 0;
        let mut result = Ok(());
        for (account_id, password) in &accounts_to_persist {
            match self.store_digest_password(account_id, password) {
                Ok(true) => {
                    persisted += 1;
                    if let Some(account) = self.settings.accounts.get_mut(account_id)
                        && let Some(ref mut creds) = account.digest_credentials
                    {
                        creds.password_persisted = true;
                    }
                }
                Ok(false) => {}
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }

        // Zeroize plaintext passwords from temporary vector
        for (_, password) in &mut accounts_to_persist {
            password.zeroize();
        }

        result.map(|()| persisted)
    }

    /// Returns information about the credential storage backend being used.
    #[cfg(feature = "digest-auth")]
    pub fn credential_storage_backend(&self) -> Option<crate::credential_store::StorageBackend> {
        self.credential_store
            .as_ref()
            .map(crate::credential_store::CredentialStore::backend)
    }

    // ========== OIDC refresh-token persistence (feature = "oidc") ==========
    //
    // The refresh token enables silent resume across launches (design doc:
    // "Persisted across restarts (OS keystore)"). It is keyed per service
    // domain under the shared `usg-sip-client` keyring service, in a
    // namespace distinct from digest passwords.

    /// Keychain account key for a service domain's refresh token.
    #[cfg(feature = "oidc")]
    fn refresh_token_key(service_domain: &str) -> String {
        format!("oidc-refresh:{service_domain}")
    }

    /// Stores the OIDC refresh token for `service_domain` in the OS keychain.
    ///
    /// Returns `Ok(true)` when stored, `Ok(false)` when no platform keyring is
    /// available (Android, iOS, or a desktop whose keyring probe failed). The
    /// token is then not persisted anywhere and the caller should fall back
    /// to browser sign-in next launch.
    #[cfg(feature = "oidc")]
    pub fn store_refresh_token(&mut self, service_domain: &str, token: &str) -> AppResult<bool> {
        let key = Self::refresh_token_key(service_domain);
        if let Some(ref mut store) = self.credential_store {
            store.store_password(&key, token)?;
            info!(service_domain = %service_domain, "OIDC refresh token stored");
            Ok(true)
        } else {
            warn!("Credential storage not available; refresh token not persisted");
            Ok(false)
        }
    }

    /// Retrieves the OIDC refresh token for `service_domain` from the OS
    /// keychain, if one was persisted.
    #[cfg(feature = "oidc")]
    pub fn get_refresh_token(
        &mut self,
        service_domain: &str,
    ) -> AppResult<Option<zeroize::Zeroizing<String>>> {
        let key = Self::refresh_token_key(service_domain);
        self.credential_store
            .as_mut()
            .map_or_else(|| Ok(None), |store| store.get_password(&key))
    }

    /// Deletes the OIDC refresh token for `service_domain` (sign-out).
    #[cfg(feature = "oidc")]
    pub fn delete_refresh_token(&mut self, service_domain: &str) -> AppResult<()> {
        let key = Self::refresh_token_key(service_domain);
        if let Some(ref mut store) = self.credential_store {
            store.delete_password(&key)?;
        } else {
            Self::delete_without_store(&key)?;
        }
        info!(service_domain = %service_domain, "OIDC refresh token deleted");
        Ok(())
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
            auth_mode: client_types::SipAuthMode::Mtls,
            bearer_token: None,
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

    /// SR-47: with no platform keyring, `SettingsManager` never persists a
    /// secret and reports `Ok(false)`; a legacy `credentials.enc` is ignored
    /// and removed.
    // NIST 800-53 Rev5: IA-5(1), IA-5(6), SC-28 (tests: no secret persisted without an OS keystore; legacy file removed, never read)
    #[cfg(any(feature = "digest-auth", feature = "oidc"))]
    mod no_keyring {
        use super::*;
        use crate::credential_store::legacy_fixture::{
            LEGACY_FILE, dir_entries, write_legacy_credentials,
        };

        fn manager_in(dir: &std::path::Path) -> SettingsManager {
            SettingsManager::with_path_without_keyring(dir.join("settings.toml")).unwrap()
        }

        #[cfg(feature = "digest-auth")]
        #[test]
        fn store_digest_password_without_keyring_returns_false() {
            let dir = tempdir().unwrap();
            let mut manager = manager_in(dir.path());

            let stored = manager
                .store_digest_password("test", "secret-password")
                .unwrap();

            assert!(
                !stored,
                "no keyring: store_digest_password must be Ok(false)"
            );
            assert!(manager.get_digest_password("test").unwrap().is_none());
            assert!(
                dir_entries(dir.path()).is_empty(),
                "no keyring: nothing written, found {:?}",
                dir_entries(dir.path())
            );
        }

        #[cfg(feature = "digest-auth")]
        #[test]
        fn credential_storage_backend_is_none_without_keyring() {
            let dir = tempdir().unwrap();
            let manager = manager_in(dir.path());
            assert!(manager.credential_storage_backend().is_none());
        }

        #[cfg(feature = "digest-auth")]
        #[test]
        fn persist_account_passwords_without_keyring_does_not_mark_persisted() {
            let dir = tempdir().unwrap();
            let mut manager = manager_in(dir.path());
            let mut account = test_account();
            account.digest_credentials = Some(client_types::DigestAuthCredentials {
                username: "alice".to_string(),
                password: zeroize::Zeroizing::new("secret-password".to_string()),
                password_persisted: false,
                allow_md5_digest: None,
                md5_policy_version: client_types::account::DIGEST_MD5_POLICY_VERSION,
            });
            manager.set_account(account);

            assert_eq!(manager.persist_account_passwords().unwrap(), 0);

            let creds = manager
                .get_account("test")
                .and_then(|a| a.digest_credentials.as_ref())
                .unwrap();
            assert!(!creds.password_persisted);
            assert_eq!(dir_entries(dir.path()), Vec::<String>::new());
        }

        /// SEC-002: a `password_persisted = true` written by a pre-SR-47
        /// build (file backend) is cleared on load when there is no keyring.
        #[cfg(feature = "digest-auth")]
        #[test]
        fn load_persisted_passwords_clears_stale_flag_without_keyring() {
            let dir = tempdir().unwrap();
            let mut manager = manager_in(dir.path());
            let mut account = test_account();
            account.digest_credentials = Some(client_types::DigestAuthCredentials {
                username: "alice".to_string(),
                password: zeroize::Zeroizing::new(String::new()),
                password_persisted: true,
                allow_md5_digest: None,
                md5_policy_version: client_types::account::DIGEST_MD5_POLICY_VERSION,
            });
            manager.set_account(account);
            manager.save().unwrap();
            assert!(!manager.is_dirty());

            manager.load_persisted_passwords().unwrap();

            let creds = manager
                .get_account("test")
                .and_then(|a| a.digest_credentials.as_ref())
                .unwrap();
            assert!(!creds.password_persisted, "stale flag must be cleared");
            assert!(creds.password.is_empty());
            assert!(manager.is_dirty(), "cleared flag must be saved");
        }

        #[cfg(feature = "digest-auth")]
        #[test]
        fn get_digest_password_ignores_and_removes_legacy_file() {
            let dir = tempdir().unwrap();
            let legacy = write_legacy_credentials(dir.path(), &[("test", "legacy-secret")]);

            let mut manager = manager_in(dir.path());

            assert!(manager.get_digest_password("test").unwrap().is_none());
            assert!(!legacy.exists(), "legacy {LEGACY_FILE} must be deleted");
        }

        #[cfg(feature = "oidc")]
        #[test]
        fn store_refresh_token_without_keyring_returns_false() {
            let dir = tempdir().unwrap();
            let mut manager = manager_in(dir.path());

            let stored = manager
                .store_refresh_token("example.com", "refresh-token")
                .unwrap();

            assert!(!stored, "no keyring: store_refresh_token must be Ok(false)");
            assert!(manager.get_refresh_token("example.com").unwrap().is_none());
            assert!(
                dir_entries(dir.path()).is_empty(),
                "no keyring: nothing written, found {:?}",
                dir_entries(dir.path())
            );
        }

        #[cfg(feature = "oidc")]
        #[test]
        fn get_refresh_token_ignores_and_removes_legacy_file() {
            let dir = tempdir().unwrap();
            let legacy = write_legacy_credentials(
                dir.path(),
                &[("oidc-refresh:example.com", "legacy-refresh-token")],
            );

            let mut manager = manager_in(dir.path());

            assert!(manager.get_refresh_token("example.com").unwrap().is_none());
            assert!(!legacy.exists(), "legacy {LEGACY_FILE} must be deleted");
        }
    }
}
