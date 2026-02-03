//! Configuration schema definitions.
//!
//! ## NIST 800-53 Rev5: CM-6 (Configuration Settings)

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use uc_types::codec::CodecId;
use uc_types::media::MediaMode;
use uc_types::protocol::{CnsaCurve, CnsaHash, CnsaSrtpProfile};

/// Root SBC configuration.
///
/// ## NIST 800-53 Rev5: CM-2 (Baseline Configuration)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct SbcConfig {
    /// General settings.
    pub general: GeneralConfig,

    /// Transport layer settings.
    pub transport: TransportConfig,

    /// Media processing settings.
    pub media: MediaConfig,

    /// Security settings.
    pub security: SecurityConfig,

    /// STIR/SHAKEN settings.
    pub stir_shaken: StirShakenConfig,

    /// Rate limiting settings.
    pub rate_limit: RateLimitConfig,

    /// Logging settings.
    pub logging: LoggingConfig,
}


/// General SBC settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Instance name for identification.
    pub instance_name: String,

    /// Cluster ID if running in a cluster.
    pub cluster_id: Option<String>,

    /// Maximum concurrent calls.
    pub max_calls: u32,

    /// Maximum concurrent registrations.
    pub max_registrations: u32,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            instance_name: "sbc-01".to_string(),
            cluster_id: None,
            max_calls: 10000,
            max_registrations: 50000,
        }
    }
}

/// Transport layer configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    /// UDP listen addresses.
    pub udp_listen: Vec<SocketAddr>,

    /// TCP listen addresses.
    pub tcp_listen: Vec<SocketAddr>,

    /// TLS listen addresses.
    pub tls_listen: Vec<SocketAddr>,

    /// WebSocket listen addresses.
    pub ws_listen: Vec<SocketAddr>,

    /// Secure WebSocket listen addresses.
    pub wss_listen: Vec<SocketAddr>,

    /// TCP connection timeout in seconds.
    pub tcp_timeout_secs: u64,

    /// TCP idle timeout in seconds.
    pub tcp_idle_timeout_secs: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        // Use unwrap for hardcoded valid addresses in Default impl
        #[allow(clippy::unwrap_used)]
        let udp = "[::]:5060".parse().unwrap();
        #[allow(clippy::unwrap_used)]
        let tcp = "[::]:5060".parse().unwrap();
        #[allow(clippy::unwrap_used)]
        let tls = "[::]:5061".parse().unwrap();

        Self {
            udp_listen: vec![udp],
            tcp_listen: vec![tcp],
            tls_listen: vec![tls],
            ws_listen: Vec::new(),
            wss_listen: Vec::new(),
            tcp_timeout_secs: 30,
            tcp_idle_timeout_secs: 300,
        }
    }
}

/// Media processing configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MediaConfig {
    /// Default media mode for calls.
    pub default_mode: MediaMode,

    /// Per-realm media mode overrides.
    pub realm_modes: HashMap<String, MediaMode>,

    /// Enabled codecs in priority order.
    pub codecs: Vec<CodecId>,

    /// RTP port range start.
    pub rtp_port_min: u16,

    /// RTP port range end.
    pub rtp_port_max: u16,

    /// SRTP configuration.
    pub srtp: SrtpConfig,

    /// DTLS configuration for DTLS-SRTP.
    pub dtls: DtlsConfig,
}

impl Default for MediaConfig {
    fn default() -> Self {
        Self {
            default_mode: MediaMode::Relay,
            realm_modes: HashMap::new(),
            codecs: vec![
                CodecId::Opus,
                CodecId::G722,
                CodecId::G711Ulaw,
                CodecId::G711Alaw,
            ],
            rtp_port_min: 16384,
            rtp_port_max: 32768,
            srtp: SrtpConfig::default(),
            dtls: DtlsConfig::default(),
        }
    }
}

/// SRTP configuration.
///
/// ## CNSA 2.0 Compliance
///
/// Only `AEAD_AES_256_GCM` is permitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SrtpConfig {
    /// Require SRTP for all calls.
    pub required: bool,

    /// SRTP profile (CNSA 2.0: only AES-256-GCM).
    pub profile: CnsaSrtpProfile,
}

impl Default for SrtpConfig {
    fn default() -> Self {
        Self {
            required: true,
            profile: CnsaSrtpProfile::AeadAes256Gcm,
        }
    }
}

/// DTLS configuration for DTLS-SRTP key exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DtlsConfig {
    /// Path to DTLS certificate (P-384).
    pub cert_path: Option<PathBuf>,

    /// Path to DTLS private key (P-384).
    pub key_path: Option<PathBuf>,

    /// Hash algorithm for SDP fingerprint.
    pub fingerprint_hash: CnsaHash,
}

impl Default for DtlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            fingerprint_hash: CnsaHash::Sha384,
        }
    }
}

/// Security configuration.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Path to TLS certificate (P-384).
    pub tls_cert_path: Option<PathBuf>,

    /// Path to TLS private key (P-384).
    pub tls_key_path: Option<PathBuf>,

    /// Elliptic curve for key generation (CNSA 2.0).
    pub curve: CnsaCurve,

    /// Minimum TLS version (CNSA 2.0: TLS 1.3 preferred).
    pub min_tls_version: String,

    /// Require mutual TLS for SIP.
    pub require_mtls: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            tls_cert_path: None,
            tls_key_path: None,
            curve: CnsaCurve::P384,
            min_tls_version: "1.3".to_string(),
            require_mtls: false,
        }
    }
}

/// STIR/SHAKEN configuration.
///
/// ## NIST 800-53 Rev5: IA-9 (Service Identification)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StirShakenConfig {
    /// Enable STIR/SHAKEN signing for outbound calls.
    pub signing_enabled: bool,

    /// Enable STIR/SHAKEN verification for inbound calls.
    pub verification_enabled: bool,

    /// Path to STI certificate (P-384).
    pub certificate_path: Option<PathBuf>,

    /// Path to STI private key (P-384).
    pub private_key_path: Option<PathBuf>,

    /// Certificate URL for x5u header.
    pub certificate_url: Option<String>,

    /// Default attestation level for signing.
    pub default_attestation: String,

    /// Maximum `PASSporT` age in seconds.
    pub max_passport_age_secs: u64,

    /// CA bundle path for certificate verification.
    pub ca_bundle_path: Option<PathBuf>,
}

impl Default for StirShakenConfig {
    fn default() -> Self {
        Self {
            signing_enabled: false,
            verification_enabled: true,
            certificate_path: None,
            private_key_path: None,
            certificate_url: None,
            default_attestation: "B".to_string(),
            max_passport_age_secs: 60,
            ca_bundle_path: None,
        }
    }
}

/// Rate limiting configuration.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial of Service Protection)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RateLimitConfig {
    /// Enable rate limiting.
    pub enabled: bool,

    /// Global requests per second limit.
    pub global_rps: u32,

    /// Per-IP requests per second limit.
    pub per_ip_rps: u32,

    /// Per-user requests per second limit.
    pub per_user_rps: u32,

    /// Burst allowance multiplier.
    pub burst_multiplier: f32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global_rps: 10000,
            per_ip_rps: 100,
            per_user_rps: 50,
            burst_multiplier: 2.0,
        }
    }
}

/// Logging configuration.
///
/// ## NIST 800-53 Rev5: AU-2 (Event Logging)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error).
    pub level: String,

    /// Output format (json, text).
    pub format: String,

    /// Output destination (stdout, file path).
    pub output: String,

    /// Enable audit logging.
    pub audit_enabled: bool,

    /// Audit log output path.
    pub audit_path: Option<PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            format: "json".to_string(),
            output: "stdout".to_string(),
            audit_enabled: true,
            audit_path: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SbcConfig::default();
        assert_eq!(config.media.default_mode, MediaMode::Relay);
        assert!(config.media.srtp.required);
        assert_eq!(config.security.curve, CnsaCurve::P384);
    }

    #[test]
    fn test_config_serialization() {
        let config = SbcConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("instance_name"));
    }

    #[test]
    fn test_config_deserialization() {
        let toml_str = r#"
            [general]
            instance_name = "test-sbc"
            max_calls = 5000

            [media]
            default_mode = "PassThrough"
        "#;

        let config: SbcConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.general.instance_name, "test-sbc");
        assert_eq!(config.general.max_calls, 5000);
        assert_eq!(config.media.default_mode, MediaMode::PassThrough);
    }
}
