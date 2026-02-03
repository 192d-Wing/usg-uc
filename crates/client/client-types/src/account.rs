//! SIP account configuration types.
//!
//! Authentication is exclusively via smart card (CAC/PIV/SIPR token)
//! using mutual TLS client certificates. Password-based digest auth
//! is NOT supported for CNSA 2.0 compliance.

use serde::{Deserialize, Serialize};

/// SIP account configuration.
///
/// Note: Authentication uses smart card client certificates via mutual TLS.
/// No password-based authentication is supported.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SipAccount {
    /// Unique account identifier.
    pub id: String,
    /// Display name for outgoing calls.
    pub display_name: String,
    /// SIP URI (e.g., "sips:user@domain.com").
    pub sip_uri: String,
    /// Registrar URI (e.g., "sips:registrar.domain.com").
    pub registrar_uri: String,
    /// Outbound proxy URI (optional).
    pub outbound_proxy: Option<String>,
    /// Transport preference (TLS only for CNSA 2.0).
    pub transport: TransportPreference,
    /// Registration expiry in seconds.
    pub register_expiry: u32,
    /// STUN server URI (optional).
    pub stun_server: Option<String>,
    /// TURN server configuration (optional).
    pub turn_config: Option<TurnConfig>,
    /// Whether this account is enabled.
    pub enabled: bool,
    /// Smart card certificate configuration.
    pub certificate_config: CertificateConfig,
}

impl Default for SipAccount {
    fn default() -> Self {
        Self {
            id: String::new(),
            display_name: String::new(),
            sip_uri: String::new(),
            registrar_uri: String::new(),
            outbound_proxy: None,
            transport: TransportPreference::TlsOnly,
            register_expiry: 3600,
            stun_server: None,
            turn_config: None,
            enabled: true,
            certificate_config: CertificateConfig::default(),
        }
    }
}

impl SipAccount {
    /// Creates a new SIP account with required fields.
    pub fn new(
        id: impl Into<String>,
        display_name: impl Into<String>,
        sip_uri: impl Into<String>,
        registrar_uri: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            display_name: display_name.into(),
            sip_uri: sip_uri.into(),
            registrar_uri: registrar_uri.into(),
            ..Default::default()
        }
    }

    /// Extracts the domain from the SIP URI.
    pub fn domain(&self) -> Option<&str> {
        // Parse "sip:user@domain" or "sips:user@domain"
        self.sip_uri
            .strip_prefix("sip:")
            .or_else(|| self.sip_uri.strip_prefix("sips:"))
            .and_then(|rest| rest.split('@').nth(1))
            .map(|s| s.split(':').next().unwrap_or(s))
    }

    /// Extracts the user part from the SIP URI.
    pub fn user(&self) -> Option<&str> {
        self.sip_uri
            .strip_prefix("sip:")
            .or_else(|| self.sip_uri.strip_prefix("sips:"))
            .and_then(|rest| rest.split('@').next())
    }
}

/// Transport preference for SIP signaling.
///
/// For CNSA 2.0 compliance, only TLS 1.3 is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TransportPreference {
    /// TLS 1.3 only (CNSA 2.0 compliant, required).
    #[default]
    TlsOnly,
}

impl std::fmt::Display for TransportPreference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TlsOnly => write!(f, "TLS 1.3 (CNSA 2.0)"),
        }
    }
}

/// TURN server configuration.
///
/// Note: TURN authentication also uses client certificates, not passwords.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnConfig {
    /// TURN server URI (e.g., "turns:turn.example.com:5349").
    pub uri: String,
    /// Whether to use TLS (TURNS) - always true for CNSA 2.0.
    pub use_tls: bool,
}

impl TurnConfig {
    /// Creates a new TURN configuration.
    pub fn new(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            use_tls: true,
        }
    }
}

/// Smart card certificate configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertificateConfig {
    /// Certificate selection mode.
    pub selection_mode: CertificateSelectionMode,
    /// Specific certificate thumbprint to use (if `SpecificCertificate` mode).
    pub certificate_thumbprint: Option<String>,
    /// Certificate store name (default: "MY" for personal certificates).
    pub store_name: String,
    /// Key usage filter (e.g., "Digital Signature", "Client Authentication").
    pub required_key_usage: Option<String>,
}

impl CertificateConfig {
    /// Creates a new certificate configuration with defaults.
    pub fn new() -> Self {
        Self {
            selection_mode: CertificateSelectionMode::PromptUser,
            certificate_thumbprint: None,
            store_name: "MY".to_string(),
            required_key_usage: Some("Client Authentication".to_string()),
        }
    }

    /// Uses a specific certificate by thumbprint.
    pub fn with_thumbprint(mut self, thumbprint: impl Into<String>) -> Self {
        self.selection_mode = CertificateSelectionMode::SpecificCertificate;
        self.certificate_thumbprint = Some(thumbprint.into());
        self
    }
}

/// Certificate selection mode for smart card authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CertificateSelectionMode {
    /// Prompt user to select a certificate from available smart cards.
    #[default]
    PromptUser,
    /// Use a specific certificate identified by thumbprint.
    SpecificCertificate,
    /// Automatically select the first valid CAC/PIV certificate.
    AutoSelect,
}

impl std::fmt::Display for CertificateSelectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PromptUser => write!(f, "Prompt for Selection"),
            Self::SpecificCertificate => write!(f, "Use Specific Certificate"),
            Self::AutoSelect => write!(f, "Auto-Select"),
        }
    }
}

/// Information about an available smart card certificate.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// Certificate thumbprint (SHA-256 hash).
    pub thumbprint: String,
    /// Subject common name (CN).
    pub subject_cn: String,
    /// Subject distinguished name.
    pub subject_dn: String,
    /// Issuer common name.
    pub issuer_cn: String,
    /// Certificate not valid before.
    pub not_before: String,
    /// Certificate not valid after.
    pub not_after: String,
    /// Whether the certificate is currently valid.
    pub is_valid: bool,
    /// Smart card reader name (if from smart card).
    pub reader_name: Option<String>,
    /// Key algorithm (e.g., "ECDSA P-384").
    pub key_algorithm: String,
}

impl std::fmt::Display for CertificateInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.subject_cn, self.issuer_cn)
    }
}

/// Registration state for an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState {
    /// Not registered.
    Unregistered,
    /// Waiting for smart card PIN entry.
    WaitingForPin,
    /// Registration in progress.
    Registering,
    /// Successfully registered.
    Registered,
    /// Registration refresh pending.
    RefreshPending,
    /// Registration failed.
    Failed,
    /// Smart card not present.
    SmartCardNotPresent,
    /// Certificate expired or invalid.
    CertificateInvalid,
}

impl std::fmt::Display for RegistrationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unregistered => write!(f, "Unregistered"),
            Self::WaitingForPin => write!(f, "Enter PIN..."),
            Self::Registering => write!(f, "Registering..."),
            Self::Registered => write!(f, "Registered"),
            Self::RefreshPending => write!(f, "Refreshing..."),
            Self::Failed => write!(f, "Failed"),
            Self::SmartCardNotPresent => write!(f, "Insert Smart Card"),
            Self::CertificateInvalid => write!(f, "Certificate Invalid"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sip_account_domain() {
        let account = SipAccount::new(
            "test",
            "Test User",
            "sips:alice@example.com",
            "sips:registrar.example.com",
        );

        assert_eq!(account.domain(), Some("example.com"));
        assert_eq!(account.user(), Some("alice"));
    }

    #[test]
    fn test_sip_account_domain_with_port() {
        let account = SipAccount::new(
            "test",
            "Test User",
            "sips:alice@example.com:5061",
            "sips:registrar.example.com",
        );

        assert_eq!(account.domain(), Some("example.com"));
    }

    #[test]
    fn test_certificate_config_default() {
        let config = CertificateConfig::new();
        assert_eq!(config.selection_mode, CertificateSelectionMode::PromptUser);
        assert_eq!(config.store_name, "MY");
    }

    #[test]
    fn test_certificate_config_with_thumbprint() {
        let config = CertificateConfig::new().with_thumbprint("ABC123");
        assert_eq!(
            config.selection_mode,
            CertificateSelectionMode::SpecificCertificate
        );
        assert_eq!(config.certificate_thumbprint, Some("ABC123".to_string()));
    }

    #[test]
    fn test_registration_state_smart_card_states() {
        assert_eq!(
            RegistrationState::SmartCardNotPresent.to_string(),
            "Insert Smart Card"
        );
        assert_eq!(RegistrationState::WaitingForPin.to_string(), "Enter PIN...");
    }
}
