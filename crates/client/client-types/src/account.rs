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

/// Server certificate verification mode for TLS connections.
///
/// This controls how the client verifies server certificates during the TLS handshake.
/// For production use, `System` or `Custom` mode should always be used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ServerCertVerificationMode {
    /// Accept all certificates without validation (DEVELOPMENT ONLY).
    ///
    /// **WARNING**: This mode bypasses all server certificate validation and should
    /// ONLY be used for local development with self-signed certificates. Never use
    /// this mode in production or with sensitive data.
    Insecure,

    /// Use the operating system's trusted CA store (default).
    ///
    /// On Windows: Windows Certificate Store (ROOT store).
    /// On macOS: Keychain.
    /// On Linux: /etc/ssl/certs or distribution-specific locations.
    ///
    /// This is the recommended mode for most deployments.
    #[default]
    System,

    /// Use custom trusted CA certificates from a file.
    ///
    /// For environments with private CAs (e.g., government networks, enterprise PKI).
    /// The CA file should be in PEM format containing one or more CA certificates.
    Custom {
        /// Path to the CA certificate file (PEM format).
        ca_file_path: String,
    },
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

impl std::fmt::Display for ServerCertVerificationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Insecure => write!(f, "Insecure (Development Only)"),
            Self::System => write!(f, "System CA Store"),
            Self::Custom { .. } => write!(f, "Custom CA File"),
        }
    }
}

impl ServerCertVerificationMode {
    /// Returns all available modes for UI selection.
    pub fn all_modes() -> &'static [(&'static str, &'static str)] {
        &[
            ("System", "Use the operating system's trusted CA store"),
            ("Custom", "Use a custom CA certificate file"),
            ("Insecure", "Accept all certificates (DEVELOPMENT ONLY)"),
        ]
    }

    /// Returns the display label for this mode.
    pub fn label(&self) -> &str {
        match self {
            Self::System => "System CA Store",
            Self::Custom { .. } => "Custom CA File",
            Self::Insecure => "Insecure (Dev Only)",
        }
    }

    /// Returns whether this is the insecure mode.
    pub fn is_insecure(&self) -> bool {
        matches!(self, Self::Insecure)
    }

    /// Returns the custom CA file path if in Custom mode.
    pub fn custom_ca_path(&self) -> Option<&str> {
        match self {
            Self::Custom { ca_file_path } => Some(ca_file_path),
            _ => None,
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

    #[test]
    fn test_server_cert_verification_mode_default() {
        let mode = ServerCertVerificationMode::default();
        assert_eq!(mode, ServerCertVerificationMode::System);
    }

    #[test]
    fn test_server_cert_verification_mode_display() {
        assert_eq!(
            ServerCertVerificationMode::Insecure.to_string(),
            "Insecure (Development Only)"
        );
        assert_eq!(
            ServerCertVerificationMode::System.to_string(),
            "System CA Store"
        );
        assert_eq!(
            ServerCertVerificationMode::Custom {
                ca_file_path: "/path/to/ca.pem".to_string()
            }
            .to_string(),
            "Custom CA File"
        );
    }

    #[test]
    fn test_server_cert_verification_mode_is_insecure() {
        assert!(ServerCertVerificationMode::Insecure.is_insecure());
        assert!(!ServerCertVerificationMode::System.is_insecure());
        assert!(!ServerCertVerificationMode::Custom {
            ca_file_path: "/path".to_string()
        }
        .is_insecure());
    }

    #[test]
    fn test_server_cert_verification_mode_custom_ca_path() {
        assert_eq!(ServerCertVerificationMode::System.custom_ca_path(), None);
        assert_eq!(ServerCertVerificationMode::Insecure.custom_ca_path(), None);
        assert_eq!(
            ServerCertVerificationMode::Custom {
                ca_file_path: "/etc/pki/ca.pem".to_string()
            }
            .custom_ca_path(),
            Some("/etc/pki/ca.pem")
        );
    }

    #[test]
    fn test_server_cert_verification_mode_labels() {
        assert_eq!(ServerCertVerificationMode::System.label(), "System CA Store");
        assert_eq!(
            ServerCertVerificationMode::Insecure.label(),
            "Insecure (Dev Only)"
        );
        assert_eq!(
            ServerCertVerificationMode::Custom {
                ca_file_path: "/path".to_string()
            }
            .label(),
            "Custom CA File"
        );
    }

    #[test]
    fn test_server_cert_verification_mode_all_modes() {
        let modes = ServerCertVerificationMode::all_modes();
        assert_eq!(modes.len(), 3);
        assert!(modes.iter().any(|(name, _)| *name == "System"));
        assert!(modes.iter().any(|(name, _)| *name == "Custom"));
        assert!(modes.iter().any(|(name, _)| *name == "Insecure"));
    }
}
