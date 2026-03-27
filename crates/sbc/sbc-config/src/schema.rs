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

// Re-export cluster config types (feature-gated)
#[cfg(feature = "cluster")]
pub use uc_cluster::{
    ClusterConfig, FailoverConfig, FailoverStrategy, HeartbeatConfig, NodeRole, ReplicationConfig,
};
#[cfg(feature = "cluster")]
pub use uc_discovery::{
    DiscoveryConfig, DiscoveryMethod, DnsConfig, GossipConfig, KubernetesConfig,
};
#[cfg(feature = "cluster")]
pub use uc_storage::{PostgresConfig, RedisConfig, StorageBackendType, StorageConfig};

#[cfg(feature = "aaa")]
pub use uc_aaa::{AaaConfig, AaaProviderType, RadiusConfig};

#[cfg(feature = "snmp")]
pub use uc_snmp::SnmpConfig;

#[cfg(feature = "syslog")]
pub use uc_syslog::SyslogConfig;

#[cfg(feature = "telemetry")]
pub use uc_telemetry::TelemetryConfig;

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

    /// Cluster settings for high availability.
    ///
    /// ## NIST 800-53 Rev5: SC-24 (Fail in Known State)
    #[cfg(feature = "cluster")]
    pub cluster: Option<ClusterConfig>,

    /// Storage backend settings.
    ///
    /// ## NIST 800-53 Rev5: CP-9 (System Backup)
    #[cfg(feature = "cluster")]
    pub storage: Option<StorageConfig>,

    /// AAA (Authentication, Authorization, Accounting) settings.
    ///
    /// ## NIST 800-53 Rev5: AC-2 (Account Management)
    #[cfg(feature = "aaa")]
    pub aaa: Option<AaaConfig>,

    /// Monitoring settings.
    ///
    /// ## NIST 800-53 Rev5: AU-6 (Audit Record Review)
    pub monitoring: Option<MonitoringConfig>,

    /// OpenTelemetry distributed tracing configuration.
    ///
    /// ## NIST 800-53 Rev5: AU-2 (Audit Events)
    #[cfg(feature = "telemetry")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telemetry: Option<TelemetryConfig>,

    /// gRPC API server configuration.
    ///
    /// When enabled, provides enterprise-level management via gRPC.
    ///
    /// ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc: Option<GrpcConfig>,

    /// Call routing configuration.
    ///
    /// ## NIST 800-53 Rev5: AC-4 (Information Flow Enforcement)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<RoutingConfig>,

    /// Dial plan definitions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dial_plans: Vec<DialPlanConfig>,

    /// Trunk group definitions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trunk_groups: Vec<TrunkGroupConfig>,

    /// SIP header manipulation rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_manipulation: Option<HeaderManipulationConfig>,

    /// Topology hiding settings.
    ///
    /// ## NIST 800-53 Rev5: SC-7 (Boundary Protection)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topology_hiding: Option<TopologyHidingConfig>,
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

/// Monitoring configuration.
///
/// ## NIST 800-53 Rev5: AU-6 (Audit Record Review)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitoringConfig {
    /// Enable SNMP trap sending.
    #[cfg(feature = "snmp")]
    pub snmp: Option<SnmpConfig>,

    /// Enable syslog forwarding.
    #[cfg(feature = "syslog")]
    pub syslog: Option<SyslogConfig>,

    /// Prometheus metrics endpoint bind address.
    pub metrics_bind: Option<SocketAddr>,

    /// Enable detailed per-call metrics.
    pub per_call_metrics: bool,

    /// Metrics scrape interval in seconds.
    pub scrape_interval_secs: u64,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            #[cfg(feature = "snmp")]
            snmp: None,
            #[cfg(feature = "syslog")]
            syslog: None,
            metrics_bind: None,
            per_call_metrics: false,
            scrape_interval_secs: 15,
        }
    }
}

/// gRPC API server configuration.
///
/// Configures the gRPC management API for enterprise control plane operations.
///
/// ## NIST 800-53 Rev5 Controls
///
/// - **SC-8**: Transmission Confidentiality (TLS support)
/// - **SC-13**: Cryptographic Protection (CNSA 2.0 compliant TLS)
/// - **IA-3**: Device Identification (mTLS support)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GrpcConfig {
    /// Enable the gRPC API server.
    pub enabled: bool,

    /// Listen address for the gRPC server.
    pub listen_addr: SocketAddr,

    /// Path to TLS certificate (PEM format, P-384 ECDSA).
    pub tls_cert_path: Option<PathBuf>,

    /// Path to TLS private key (PEM format, P-384 ECDSA).
    pub tls_key_path: Option<PathBuf>,

    /// Path to CA certificate for client verification (mTLS).
    pub tls_ca_path: Option<PathBuf>,

    /// Require mutual TLS (client certificate authentication).
    pub require_mtls: bool,

    /// Maximum concurrent gRPC connections.
    pub max_connections: u32,

    /// Request timeout in seconds.
    pub request_timeout_secs: u64,

    /// Enable gRPC reflection for debugging tools like grpcurl.
    pub enable_reflection: bool,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        // Use unwrap for hardcoded valid address in Default impl
        #[allow(clippy::unwrap_used)]
        let listen_addr = "0.0.0.0:9090".parse().unwrap();

        Self {
            enabled: false,
            listen_addr,
            tls_cert_path: None,
            tls_key_path: None,
            tls_ca_path: None,
            require_mtls: false,
            max_connections: 1000,
            request_timeout_secs: 30,
            enable_reflection: true,
        }
    }
}

// ── Routing Configuration ──────────────────────────────────────────

/// Call routing configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingConfig {
    /// Enable dial plan-based routing.
    pub use_dial_plan: bool,
    /// Maximum failover attempts per call.
    pub max_failover_attempts: u32,
    /// Default trunk group for unmatched calls.
    pub default_trunk_group: String,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            use_dial_plan: true,
            max_failover_attempts: 3,
            default_trunk_group: "default".to_string(),
        }
    }
}

/// Dial plan configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DialPlanConfig {
    /// Unique dial plan ID.
    pub id: String,
    /// Display name.
    #[serde(default)]
    pub name: String,
    /// Whether this dial plan is active.
    #[serde(default = "default_true")]
    pub active: bool,
    /// Dial plan entries.
    #[serde(default)]
    pub entries: Vec<DialPlanEntryConfig>,
}

/// A single dial plan entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DialPlanEntryConfig {
    /// Call direction: "inbound", "outbound", or "both".
    pub direction: String,
    /// Pattern type: "exact", "prefix", "wildcard", "any".
    pub pattern_type: String,
    /// Pattern value (the string to match against).
    pub pattern_value: String,
    /// Domain pattern to match (e.g., "uc.mil", "*.mil").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_pattern: Option<String>,
    /// Source trunk filter (only match calls from this trunk ID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_trunk: Option<String>,
    /// Trunk group to route to.
    #[serde(default)]
    pub trunk_group: String,
    /// Destination type: "`trunk_group`" (default), "`registered_user`", "`static_uri`".
    #[serde(default = "default_trunk_group_type")]
    pub destination_type: String,
    /// Static destination URI (when `destination_type` = "`static_uri`").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub static_destination: Option<String>,
    /// Number transform type: "none", "`strip_prefix`", "`add_prefix`", "`replace_prefix`".
    #[serde(default = "default_none_str")]
    pub transform_type: String,
    /// Transform value (meaning depends on `transform_type`).
    #[serde(default)]
    pub transform_value: String,
    /// Priority (lower = higher priority).
    #[serde(default = "default_priority")]
    pub priority: u32,
}

impl Default for DialPlanEntryConfig {
    fn default() -> Self {
        Self {
            direction: "outbound".to_string(),
            pattern_type: "prefix".to_string(),
            pattern_value: String::new(),
            domain_pattern: None,
            source_trunk: None,
            trunk_group: String::new(),
            destination_type: "trunk_group".to_string(),
            static_destination: None,
            transform_type: "none".to_string(),
            transform_value: String::new(),
            priority: 100,
        }
    }
}

/// Trunk group configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrunkGroupConfig {
    /// Unique trunk group ID.
    pub id: String,
    /// Display name.
    #[serde(default)]
    pub name: String,
    /// Selection strategy: "priority", "`round_robin`", "`weighted_random`",
    /// "`least_connections`", "`best_success_rate`".
    #[serde(default = "default_priority_str")]
    pub strategy: String,
    /// Trunks in this group.
    #[serde(default)]
    pub trunks: Vec<TrunkConfigSchema>,
}

/// Individual trunk configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TrunkConfigSchema {
    /// Unique trunk ID.
    pub id: String,
    /// SIP host (IP or hostname).
    pub host: String,
    /// SIP port.
    pub port: u16,
    /// Transport protocol: "udp", "tcp", "tls".
    pub protocol: String,
    /// Selection priority (lower = preferred).
    pub priority: u32,
    /// Weight for weighted selection.
    pub weight: u32,
    /// Maximum concurrent calls.
    pub max_calls: u32,
    /// Cooldown period after failures (seconds).
    pub cooldown_secs: u32,
    /// Maximum consecutive failures before cooldown.
    pub max_failures: u32,
}

impl Default for TrunkConfigSchema {
    fn default() -> Self {
        Self {
            id: String::new(),
            host: String::new(),
            port: 5060,
            protocol: "udp".to_string(),
            priority: 1,
            weight: 100,
            max_calls: 100,
            cooldown_secs: 30,
            max_failures: 5,
        }
    }
}

// ── Header Manipulation Configuration ─────────────────────────────

/// SIP header manipulation configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HeaderManipulationConfig {
    /// Global manipulation rules (applied to all calls).
    #[serde(default)]
    pub global_rules: Vec<ManipulationRuleConfig>,
    /// Per-trunk manipulation rules.
    #[serde(default)]
    pub trunk_rules: Vec<TrunkManipulationRuleConfig>,
}

/// A header manipulation rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManipulationRuleConfig {
    /// Rule name.
    pub name: String,
    /// Direction: "inbound", "outbound", "both".
    #[serde(default = "default_both_str")]
    pub direction: String,
    /// Action: "add", "set", "remove", "replace", "prepend", "append".
    pub action: String,
    /// Header name to act on.
    pub header: String,
    /// Value (for add/set/replace/prepend/append).
    #[serde(default)]
    pub value: String,
}

/// Per-trunk manipulation rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrunkManipulationRuleConfig {
    /// Trunk ID this rule applies to.
    pub trunk_id: String,
    /// Rule name.
    pub name: String,
    /// Action.
    pub action: String,
    /// Header name.
    pub header: String,
    /// Value.
    #[serde(default)]
    pub value: String,
}

// ── Topology Hiding Configuration ─────────────────────────────────

/// Topology hiding configuration.
///
/// ## NIST 800-53 Rev5: SC-7 (Boundary Protection)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TopologyHidingConfig {
    /// Whether topology hiding is enabled.
    pub enabled: bool,
    /// Hiding mode: "none", "`signaling_only`", "full".
    pub mode: String,
    /// External hostname to present.
    pub external_host: String,
    /// External port to present.
    pub external_port: u16,
    /// Whether to obfuscate SIP Call-ID headers.
    pub obfuscate_call_id: bool,
}

impl Default for TopologyHidingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "none".to_string(),
            external_host: String::new(),
            external_port: 5060,
            obfuscate_call_id: false,
        }
    }
}

// ── Config helper functions ───────────────────────────────────────

const fn default_true() -> bool {
    true
}

const fn default_priority() -> u32 {
    100
}

fn default_none_str() -> String {
    "none".to_string()
}

fn default_trunk_group_type() -> String {
    "trunk_group".to_string()
}

fn default_priority_str() -> String {
    "priority".to_string()
}

fn default_both_str() -> String {
    "both".to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
        let toml_str = toml::to_string(&config).expect("serialize config");
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

        let config: SbcConfig = toml::from_str(toml_str).expect("parse config");
        assert_eq!(config.general.instance_name, "test-sbc");
        assert_eq!(config.general.max_calls, 5000);
        assert_eq!(config.media.default_mode, MediaMode::PassThrough);
    }

    #[test]
    fn test_monitoring_config_defaults() {
        let monitoring = MonitoringConfig::default();
        assert!(monitoring.metrics_bind.is_none());
        assert!(!monitoring.per_call_metrics);
        assert_eq!(monitoring.scrape_interval_secs, 15);
    }

    #[test]
    fn test_routing_config_parse() {
        let toml_str = r#"
            [general]
            instance_name = "sbc-routing-test"

            [routing]
            use_dial_plan = true
            max_failover_attempts = 3
            default_trunk_group = "us-domestic"

            [[dial_plans]]
            id = "main"
            name = "Main Plan"
            active = true

                [[dial_plans.entries]]
                direction = "outbound"
                pattern_type = "prefix"
                pattern_value = "+1"
                trunk_group = "us-domestic"
                transform_type = "strip_prefix"
                transform_value = "2"
                priority = 10

                [[dial_plans.entries]]
                direction = "inbound"
                pattern_type = "prefix"
                pattern_value = "+1555"
                destination_type = "registered_user"
                transform_type = "strip_prefix"
                transform_value = "5"
                priority = 5
                domain_pattern = "uc.mil"
                source_trunk = "bulkvs-1"

                [[dial_plans.entries]]
                direction = "both"
                pattern_type = "exact"
                pattern_value = "911"
                trunk_group = "emergency"
                priority = 1

            [[trunk_groups]]
            id = "us-domestic"
            name = "US Domestic"
            strategy = "least_connections"

                [[trunk_groups.trunks]]
                id = "bulkvs-1"
                host = "sip.bulkvs.com"
                port = 5060
                protocol = "udp"
                priority = 1
                max_calls = 200

                [[trunk_groups.trunks]]
                id = "bulkvs-2"
                host = "sip2.bulkvs.com"
                port = 5060
                protocol = "udp"
                priority = 2

            [[trunk_groups]]
            id = "emergency"
            name = "E911"
            strategy = "priority"

                [[trunk_groups.trunks]]
                id = "e911-1"
                host = "e911.example.com"
                port = 5060

            [header_manipulation]
                [[header_manipulation.global_rules]]
                name = "strip-internal"
                direction = "outbound"
                action = "remove"
                header = "X-Internal-ID"

                [[header_manipulation.trunk_rules]]
                trunk_id = "bulkvs-1"
                name = "set-ua"
                action = "set"
                header = "User-Agent"
                value = "USG-SBC/1.0"

            [topology_hiding]
            enabled = true
            mode = "full"
            external_host = "sbc.uc.mil"
            external_port = 5060
            obfuscate_call_id = true
        "#;

        let config: SbcConfig = toml::from_str(toml_str).expect("parse routing config");

        // Routing
        let routing = config.routing.unwrap();
        assert!(routing.use_dial_plan);
        assert_eq!(routing.max_failover_attempts, 3);
        assert_eq!(routing.default_trunk_group, "us-domestic");

        // Dial plans
        assert_eq!(config.dial_plans.len(), 1);
        let plan = &config.dial_plans[0];
        assert_eq!(plan.id, "main");
        assert!(plan.active);
        assert_eq!(plan.entries.len(), 3);

        // Outbound entry
        assert_eq!(plan.entries[0].direction, "outbound");
        assert_eq!(plan.entries[0].pattern_type, "prefix");
        assert_eq!(plan.entries[0].pattern_value, "+1");
        assert_eq!(plan.entries[0].transform_type, "strip_prefix");

        // Inbound entry with domain + source trunk
        assert_eq!(plan.entries[1].direction, "inbound");
        assert_eq!(plan.entries[1].destination_type, "registered_user");
        assert_eq!(plan.entries[1].domain_pattern.as_deref(), Some("uc.mil"));
        assert_eq!(plan.entries[1].source_trunk.as_deref(), Some("bulkvs-1"));

        // Emergency
        assert_eq!(plan.entries[2].direction, "both");
        assert_eq!(plan.entries[2].pattern_type, "exact");
        assert_eq!(plan.entries[2].priority, 1);

        // Trunk groups
        assert_eq!(config.trunk_groups.len(), 2);
        assert_eq!(config.trunk_groups[0].id, "us-domestic");
        assert_eq!(config.trunk_groups[0].strategy, "least_connections");
        assert_eq!(config.trunk_groups[0].trunks.len(), 2);
        assert_eq!(config.trunk_groups[0].trunks[0].host, "sip.bulkvs.com");

        // Header manipulation
        let manip = config.header_manipulation.unwrap();
        assert_eq!(manip.global_rules.len(), 1);
        assert_eq!(manip.global_rules[0].action, "remove");
        assert_eq!(manip.trunk_rules.len(), 1);
        assert_eq!(manip.trunk_rules[0].trunk_id, "bulkvs-1");

        // Topology hiding
        let topo = config.topology_hiding.unwrap();
        assert!(topo.enabled);
        assert_eq!(topo.mode, "full");
        assert_eq!(topo.external_host, "sbc.uc.mil");
        assert!(topo.obfuscate_call_id);
    }
}
