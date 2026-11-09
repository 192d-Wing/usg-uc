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
    AdmissionSplit, ClusterAdmissionConfig, ClusterConfig, FailoverConfig, FailoverStrategy,
    HeartbeatConfig, NodeRole, ReplicationConfig,
};
#[cfg(feature = "cluster")]
pub use uc_discovery::{
    DiscoveryConfig, DiscoveryMethod, DnsConfig, GossipConfig, KubernetesConfig,
};
#[cfg(feature = "cluster")]
pub use uc_storage::{
    PostgresConfig, PostgresSslMode, RedisConfig, StorageBackendType, StorageConfig,
};

/// `[cluster]` as accepted by the SBC: the `uc_cluster` settings plus the
/// SBC-owned `[cluster.auth]` table.
///
/// Derefs to [`ClusterConfig`], so `cluster.enabled`, `cluster.admission`
/// etc. read as before.
///
/// `Deserialize` is hand-written instead of `#[serde(flatten)]`: flatten
/// routes the inner struct through serde's buffered map deserializer, which
/// loses `deny_unknown_fields` diagnostics on nested tables such as
/// `[cluster.admission]` (CM-6: a typo must fail the load).
///
/// The `Deserialize` impl buffers the section as a `toml::Table`, so it only
/// works with TOML-backed deserializers (the config loader's format).
///
/// ## NIST 800-53 Rev5: CM-6 (Configuration Settings)
// IA-3, SC-23: prerequisite only, no peer transport (POA&M-241).
#[cfg(feature = "cluster")]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SbcClusterConfig {
    /// `uc_cluster` settings (`[cluster]` minus `auth`).
    pub inner: ClusterConfig,
    /// Peer authentication key (`[cluster.auth]`); required when
    /// `cluster.enabled` (POA&M-241).
    pub auth: Option<ClusterAuthConfig>,
}

#[cfg(feature = "cluster")]
impl From<ClusterConfig> for SbcClusterConfig {
    fn from(inner: ClusterConfig) -> Self {
        Self { inner, auth: None }
    }
}

#[cfg(feature = "cluster")]
impl std::ops::Deref for SbcClusterConfig {
    type Target = ClusterConfig;

    fn deref(&self) -> &ClusterConfig {
        &self.inner
    }
}

#[cfg(feature = "cluster")]
impl std::ops::DerefMut for SbcClusterConfig {
    fn deref_mut(&mut self) -> &mut ClusterConfig {
        &mut self.inner
    }
}

#[cfg(feature = "cluster")]
impl Serialize for SbcClusterConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Out<'a> {
            #[serde(flatten)]
            inner: &'a ClusterConfig,
            #[serde(skip_serializing_if = "Option::is_none")]
            auth: Option<&'a ClusterAuthConfig>,
        }
        Out {
            inner: &self.inner,
            auth: self.auth.as_ref(),
        }
        .serialize(serializer)
    }
}

#[cfg(feature = "cluster")]
impl<'de> Deserialize<'de> for SbcClusterConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let mut table = toml::Table::deserialize(deserializer)?;
        let auth = table
            .remove("auth")
            .map(|v| {
                v.try_into::<ClusterAuthConfig>()
                    .map_err(|e| D::Error::custom(format!("cluster.auth: {e}")))
            })
            .transpose()?;
        let inner = toml::Value::Table(table)
            .try_into::<ClusterConfig>()
            .map_err(|e| D::Error::custom(format!("cluster: {e}")))?;
        Ok(Self { inner, auth })
    }
}

/// `[cluster.auth]`: pre-shared HMAC key used to authenticate cluster peer
/// messages (`uc_cluster::PeerAuthenticator`).
///
/// The key file is read by the daemon at startup, not at validation time,
/// so a config can be validated off-box. It must hold at least
/// `uc_cluster::auth::MIN_KEY_LEN` bytes of random key material, be owned
/// by the SBC user and mode 0600, and be identical on every node.
///
/// ## NIST 800-53 Rev5: CM-6, SC-12 (Cryptographic Key Establishment)
// IA-3, SC-23: prerequisite only, no peer transport (POA&M-241).
#[cfg(feature = "cluster")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterAuthConfig {
    /// Path to the raw key material.
    pub key_file: PathBuf,
    /// Key identifier carried in every envelope (key rotation).
    pub key_id: u32,
}

#[cfg(feature = "aaa")]
pub use uc_aaa::{AaaConfig, AaaProviderType, RadiusConfig};

#[cfg(feature = "snmp")]
pub use uc_snmp::SnmpConfig;

pub use uc_vps::VpsConfig;

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

    /// Voice Protection System (call-level screening) settings.
    ///
    /// ## NIST 800-53 Rev5: AC-3 (Access Enforcement), SC-5 (Denial of Service Protection)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vps: Option<VpsConfig>,

    /// Logging settings.
    pub logging: LoggingConfig,

    /// Cluster settings for high availability.
    ///
    /// ## NIST 800-53 Rev5: SC-24 (Fail in Known State)
    #[cfg(feature = "cluster")]
    pub cluster: Option<SbcClusterConfig>,

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

    /// Monitoring settings. Not implemented: any `[monitoring]` table is
    /// rejected at config load (see [`MonitoringConfig`]).
    ///
    /// ## NIST 800-53 Rev5: CM-6, CM-7 (POA&M-191)
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

    /// Zone definitions for network interface binding.
    ///
    /// Each zone maps named interfaces to signaling and media roles.
    /// Trunks and internal registrations reference zones by name.
    ///
    /// ## NIST 800-53 Rev5: SC-7 (Boundary Protection)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<ZoneConfig>,

    /// Phone provisioning server configuration.
    ///
    /// When set, the daemon serves per-phone XML / cfg files at
    /// `/provision/{filename}` and embeds the configured host in
    /// vendor-specific provisioning fields (e.g. TEO `update_server`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioning: Option<ProvisioningConfig>,

    /// Call Detail Record pipeline settings.
    ///
    /// ## NIST 800-53 Rev5: AU-2 (Event Logging), AU-12 (Audit Record Generation)
    pub cdr: CdrConfig,
}

/// CDR file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CdrFormatConfig {
    /// JSON lines (carries the hash chain).
    #[default]
    Jsonl,
    /// Fixed-column CSV (RFC 4180).
    Csv,
}

/// Which unanswered call attempts produce a CDR.
///
/// ## NIST 800-53 Rev5: AU-2 (organisation-defined event set)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CdrRecordUnanswered {
    /// Every INVITE that reaches admission, including admission, policy and
    /// no-route rejects and trunk 4xx/5xx/6xx.
    #[default]
    All,
    /// Only attempts that were routed to a B-leg.
    Routed,
    /// Answered calls only.
    None,
}

/// How caller/callee numbers are stored in CDRs.
///
/// ## NIST 800-53 Rev5: SI-12 (Information Management and Retention)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CdrPiiMode {
    /// Store numbers as received.
    #[default]
    Full,
    /// Mask caller numbers except the last four characters.
    MaskCaller,
    /// Replace numbers with HMAC-SHA-384 (key from `pii_hash_key_file`).
    Hash,
}

/// Call handling when the CDR writer has failed.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures), AU-5(4)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CdrOnFailure {
    /// Keep admitting calls; drop and count CDRs, report health degraded.
    #[default]
    Continue,
    /// Reject new non-emergency INVITEs while the writer is dead.
    /// Emergency calls are always admitted.
    RejectNewCalls,
}

/// CDR syslog forwarding (RFC 5424 over TLS, RFC 5425).
///
/// ## NIST 800-53 Rev5: AU-9(2) (Store on Separate Physical Systems), SC-8
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CdrSyslogConfig {
    /// Forward CDRs to a syslog collector.
    pub enabled: bool,
    /// Collector as `tls://host:port`. Only TLS is accepted.
    pub target: String,
    /// PEM CA bundle that issues the collector's certificate. Empty uses the
    /// daemon's configured trust store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_path: Option<PathBuf>,
    /// Syslog facility, 0..=23 (16 = local0).
    pub facility: u8,
}

impl Default for CdrSyslogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            target: "tls://collector:6514".to_string(),
            ca_path: None,
            facility: 16,
        }
    }
}

/// Call Detail Record settings (`[cdr]`).
///
/// ## NIST 800-53 Rev5: AU-2, AU-4 (Storage Capacity), AU-9, AU-11 (Retention), SI-12
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CdrConfig {
    /// Produce CDRs.
    pub enabled: bool,
    /// File format.
    pub format: CdrFormatConfig,
    /// Absolute directory for CDR files (created 0750 if missing).
    pub directory: PathBuf,
    /// Node id stamped on records and file names. Unset uses
    /// `general.instance_name` (when it is a valid node id), then `$HOSTNAME`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Rotate a file at this size, 1..=4096 MiB.
    pub rotate_size_mb: u32,
    /// Rotate a non-empty file after this long (`"0"` = size only;
    /// otherwise 5m..=24h). Units: s, m, h.
    pub rotate_interval: String,
    /// Closed files to keep (0 = unlimited).
    pub retention_files: u32,
    /// Days to keep closed files (0 = unlimited).
    pub retention_days: u32,
    /// fsync at most this often (0 = after every record), 0..=60000 ms.
    pub fsync_interval_ms: u32,
    /// Writer queue capacity, `64..=1_000_000`.
    pub queue_capacity: usize,
    /// Recent CDRs held in memory for the API, `0..=200_000`.
    pub ring_capacity: usize,
    /// SHA-384 hash chain over records.
    pub hash_chain: bool,
    /// Which unanswered attempts produce a CDR.
    pub record_unanswered: CdrRecordUnanswered,
    /// Produce CDRs for INVITEs answered with a 401/407 challenge.
    pub record_auth_challenges: bool,
    /// Number storage policy.
    pub pii: CdrPiiMode,
    /// HMAC-SHA-384 key file (at least 48 bytes); required when `pii = "hash"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pii_hash_key_file: Option<PathBuf>,
    /// Call handling when the CDR writer fails.
    pub on_failure: CdrOnFailure,
    /// Syslog forwarding.
    pub syslog: CdrSyslogConfig,
}

impl Default for CdrConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            format: CdrFormatConfig::Jsonl,
            directory: PathBuf::from("/var/lib/usg-sbc/cdr"),
            node_id: None,
            rotate_size_mb: 100,
            rotate_interval: "1h".to_string(),
            retention_files: 168,
            retention_days: 90,
            fsync_interval_ms: 1000,
            queue_capacity: 8192,
            ring_capacity: 10_000,
            hash_chain: true,
            record_unanswered: CdrRecordUnanswered::All,
            record_auth_challenges: false,
            pii: CdrPiiMode::Full,
            pii_hash_key_file: None,
            on_failure: CdrOnFailure::Continue,
            syslog: CdrSyslogConfig::default(),
        }
    }
}

impl CdrConfig {
    /// Parses `rotate_interval` into seconds (`0` = size-only rotation).
    /// Accepts a bare number of seconds or a number with an `s`, `m` or `h`
    /// suffix. `None` when malformed.
    #[must_use]
    pub fn rotate_interval_secs(&self) -> Option<u64> {
        parse_duration_secs(&self.rotate_interval)
    }
}

/// Parses `"90"`, `"30s"`, `"5m"`, `"1h"` into seconds.
#[must_use]
pub fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = match s.as_bytes().last()? {
        b's' => (s.get(..s.len() - 1)?, 1),
        b'm' => (s.get(..s.len() - 1)?, 60),
        b'h' => (s.get(..s.len() - 1)?, 3600),
        b'0'..=b'9' => (s, 1),
        _ => return None,
    };
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    num.parse::<u64>().ok()?.checked_mul(mult)
}

/// Phone provisioning settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisioningConfig {
    /// Public hostname or IP that phones use to reach the SBC.
    ///
    /// Embedded into vendor configs as the next-fetch URL. Should resolve
    /// (or route) from the phone VLAN to the SBC's inside-zone interface.
    pub host: String,

    /// Port the daemon exposes provisioning on. Defaults to 80.
    #[serde(default = "default_provisioning_port")]
    pub port: u16,
}

const fn default_provisioning_port() -> u16 {
    80
}

/// Network zone configuration.
///
/// Zones bind signaling and media to named network interfaces.
/// Each trunk group and the internal registration realm references a zone.
///
/// ## NIST 800-53 Rev5: SC-7 (Boundary Protection)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneConfig {
    /// Zone name (referenced by trunk groups and internal registrations).
    pub name: String,
    /// Signaling interface name (e.g., "eth0"). Resolved to IP at startup.
    pub signaling_interface: String,
    /// Media interface name (e.g., "eth1"). Resolved to IP at startup.
    pub media_interface: String,
    /// External/public IP for NAT traversal. Supports:
    /// - Literal IP: `"203.0.113.10"`
    /// - Interface name: `"eth2"` (resolved at startup)
    /// - STUN: `"stun"` or `"stun:server:port"` (auto-discovered)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ip: Option<String>,
}

/// Default `general.trunk_retry_after_max_secs`.
pub const DEFAULT_TRUNK_RETRY_AFTER_MAX_SECS: u32 = 300;

/// Largest accepted `general.trunk_retry_after_max_secs`.
pub const MAX_TRUNK_RETRY_AFTER_SECS: u32 = 3600;

/// Default emergency headroom above a `max_calls` limit: 10% of it,
/// at least 1. Used when `emergency_reserve_calls` is not set.
///
/// ## 47 CFR 9.16; NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
#[must_use]
pub const fn default_emergency_reserve(max_calls: u32) -> u32 {
    let tenth = max_calls / 10;
    if tenth == 0 { 1 } else { tenth }
}

/// One node's share of a cluster-wide cap: `cap / divisor`, rounded
/// down, at least 1 (a divisor of 0 or 1 returns `cap`).
///
/// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
#[must_use]
pub const fn cluster_share(cap: u32, divisor: u32) -> u32 {
    if divisor <= 1 {
        return cap;
    }
    let share = cap / divisor;
    if share == 0 { 1 } else { share }
}

impl SbcConfig {
    /// Divisor this node applies to cluster-divided caps
    /// (`cluster.admission`): `expected_nodes` under `split = "divide"`,
    /// otherwise 1.
    ///
    /// The emergency reserve, VPS `per_callee_max_concurrent` and rate
    /// limits are never divided.
    ///
    /// ## NIST 800-53 Rev5: SC-5, CP-2(2) (Capacity Planning)
    #[must_use]
    pub fn admission_divisor(&self) -> u32 {
        #[cfg(feature = "cluster")]
        {
            self.cluster.as_ref().map_or(1, |c| c.admission.divisor())
        }
        #[cfg(not(feature = "cluster"))]
        {
            1
        }
    }

    /// `general.max_calls` enforced on this node (cluster share).
    #[must_use]
    pub fn effective_max_calls(&self) -> u32 {
        cluster_share(self.general.max_calls, self.admission_divisor())
    }

    /// `general.max_registrations` enforced on this node (cluster share).
    #[must_use]
    pub fn effective_max_registrations(&self) -> u32 {
        cluster_share(self.general.max_registrations, self.admission_divisor())
    }
}

/// General SBC settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Instance name for identification.
    pub instance_name: String,

    /// Cluster ID if running in a cluster.
    pub cluster_id: Option<String>,

    /// Maximum concurrent calls on this node. A normal INVITE over the limit
    /// gets 503 with no `Retry-After` (emergency calls may use
    /// `emergency_reserve_calls` beyond it, and a refused emergency caller
    /// may redial at once).
    pub max_calls: u32,

    /// Extra concurrent calls above `max_calls` that only emergency calls
    /// (`vps.emergency_numbers`) may use. A normal call is refused (503)
    /// at `max_calls`; an emergency call is refused (503) only at
    /// `max_calls + emergency_reserve_calls`, so held calls cannot block
    /// 911 while an emergency flood stays bounded. Defaults to 10% of
    /// `max_calls` (at least 1); must be 1..=`max_calls` when set.
    ///
    /// ## 47 CFR 9.16; NIST 800-53 Rev5: SC-5
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emergency_reserve_calls: Option<u32>,

    /// Maximum concurrent registrations.
    pub max_registrations: u32,

    /// Upper bound, in seconds, on a trunk's `Retry-After` honoured as its
    /// cooldown after a 503 (RFC 3261 §21.5.4), so a hostile or buggy peer
    /// cannot take a trunk out indefinitely. Range 1-3600, default 300. A
    /// missing, invalid or zero `Retry-After` uses the trunk's
    /// `cooldown_secs`.
    ///
    /// ## NIST 800-53 Rev5: SC-5, CP-8
    pub trunk_retry_after_max_secs: u32,

    /// Default zone for internal registrations (phones, softclients).
    /// Must reference a defined zone name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_internal_zone: Option<String>,
}

impl GeneralConfig {
    /// Emergency headroom above `max_calls` in effect (configured or
    /// the 10% default).
    #[must_use]
    pub fn effective_emergency_reserve_calls(&self) -> u32 {
        self.emergency_reserve_calls
            .unwrap_or_else(|| default_emergency_reserve(self.max_calls))
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            instance_name: "sbc-01".to_string(),
            cluster_id: None,
            max_calls: 10000,
            emergency_reserve_calls: None,
            max_registrations: 50000,
            trunk_retry_after_max_secs: DEFAULT_TRUNK_RETRY_AFTER_MAX_SECS,
            default_internal_zone: None,
        }
    }
}

/// Transport layer configuration.
///
/// Supports dual-interface deployment where signaling (SIP) and media (RTP)
/// are bound to separate network interfaces for security isolation.
///
/// ## NIST 800-53 Rev5: SC-7 (Boundary Protection)
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

    /// Idle timeout in seconds for accepted stream connections (TCP, TLS,
    /// WebSocket) once they have delivered a SIP message. Valid 30..=3600.
    ///
    /// ## NIST 800-53 Rev5: SC-10 (Network Disconnect)
    pub tcp_idle_timeout_secs: u64,

    /// Connection pool size of each stream listener (TCP, TLS, WS), so a
    /// flood on one listener cannot starve another. Valid 1..=1,000,000.
    ///
    /// ## NIST 800-53 Rev5: SC-5
    pub max_connections_per_listener: u32,

    /// Ceiling on accepted stream connections across all listeners (fd
    /// budget). Valid 1..=4,000,000.
    pub max_connections_total: u32,

    /// Concurrent stream connections allowed from one source (IPv4 address
    /// or IPv6 `rate_limit.ipv6_prefix_len` prefix), across all listeners.
    /// An enterprise NAT funnelling many TLS phones may need more. Valid
    /// 1..=`max_connections_per_listener`.
    ///
    /// ## NIST 800-53 Rev5: SC-5, SC-7
    pub max_connections_per_source: u32,

    /// TLS / WebSocket handshake deadline in seconds. Valid 1..=60.
    pub handshake_timeout_secs: u64,

    /// Deadline in seconds for a new stream connection to deliver its first
    /// accepted SIP message; until then CRLF keep-alives do not count as
    /// activity. Valid 1..=`tcp_idle_timeout_secs`.
    ///
    /// ## NIST 800-53 Rev5: SC-10
    pub first_message_timeout_secs: u64,

    /// Refuse WebSocket upgrades that do not offer the `sip` subprotocol
    /// (RFC 7118 §4 MUST). When false, an upgrade with no
    /// `Sec-WebSocket-Protocol` header is admitted.
    pub ws_require_sip_subprotocol: bool,

    /// External/public IP address for SIP Contact and SDP.
    /// Used when behind NAT. If unset, auto-detected from outgoing socket.
    pub external_ip: Option<String>,

    /// Signaling interface IP for SIP traffic.
    /// When set, SIP transports bind to this address.
    pub signaling_ip: Option<String>,

    /// Media interface IP for RTP/SRTP traffic.
    /// When set, RTP ports bind to this address instead of 0.0.0.0.
    pub media_ip: Option<String>,

    /// REST API listen address (default: 0.0.0.0:8080).
    pub api_listen: Option<SocketAddr>,

    /// REST API HTTPS listen address. When set together with
    /// `security.tls_cert_path` / `security.tls_key_path`, the API server
    /// runs HTTP and HTTPS listeners side-by-side.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_tls_listen: Option<SocketAddr>,

    /// STUN refresh interval in seconds for external IP re-resolution (default: 300).
    pub stun_refresh_interval_secs: Option<u64>,
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
            max_connections_per_listener: 10_000,
            max_connections_total: 20_000,
            max_connections_per_source: 128,
            handshake_timeout_secs: 10,
            first_message_timeout_secs: 30,
            ws_require_sip_subprotocol: true,
            external_ip: None,
            signaling_ip: None,
            media_ip: None,
            api_listen: None,
            api_tls_listen: None,
            stun_refresh_interval_secs: None,
        }
    }
}

/// Media processing configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MediaConfig {
    /// Default media mode for calls. Only `Relay` is accepted: the call path
    /// always anchors media (validation rejects other values).
    pub default_mode: MediaMode,

    /// Per-realm media mode overrides. Not supported (needs media bypass);
    /// validation rejects a non-empty map.
    pub realm_modes: HashMap<String, MediaMode>,

    /// Enabled codecs. Not enforced (no SDP codec filtering or
    /// transcoding); validation accepts only the default set, in any order.
    pub codecs: Vec<CodecId>,

    /// RTP port range start.
    pub rtp_port_min: u16,

    /// RTP port range end.
    pub rtp_port_max: u16,

    /// SRTP configuration.
    pub srtp: SrtpConfig,

    /// DTLS configuration for DTLS-SRTP.
    pub dtls: DtlsConfig,

    /// T.38 fax relay (`m=image udptl t38`) policy.
    pub t38: T38Config,
}

/// `T38FaxUdpEC` error-correction modes an operator may allow
/// (ITU-T T.38 Annex D spelling).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum T38EcMode {
    /// `t38UDPRedundancy`.
    #[serde(rename = "t38UDPRedundancy")]
    Redundancy,
    /// `t38UDPFEC`.
    #[serde(rename = "t38UDPFEC")]
    Fec,
    /// `t38UDPNoEC` (also what an absent `T38FaxUdpEC` means).
    #[serde(rename = "t38UDPNoEC")]
    NoEc,
}

/// T.38 fax relay policy (`[media.t38]`).
///
/// The SBC anchors and relays UDPTL opaquely on the call's existing media
/// ports after an audio <-> T.38 re-INVITE switchover; it never decodes
/// UDPTL/IFP (POA&M-290).
///
/// ## NIST 800-53 Rev5: CM-6, CM-7 (fail-closed default), SC-5 (caps), SC-8
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct T38Config {
    /// Accept `m=image` T.38 streams. Default `false`: image offers get 488.
    pub enabled: bool,
    /// Acknowledge that UDPTL is cleartext. Must be `true` to enable T.38
    /// when `media.srtp.required = true` (POA&M-291).
    pub allow_cleartext: bool,
    /// Cap for `T38MaxBitRate` in bit/s (2400..=33600); higher values are
    /// clamped down before forwarding.
    pub max_bit_rate: u32,
    /// Cap for `T38FaxMaxDatagram` in octets (64..=1472).
    pub max_datagram: u16,
    /// Cap for `T38FaxMaxBuffer` in octets (64..=65535).
    pub max_buffer: u32,
    /// Allowed `T38FaxUdpEC` modes (non-empty, no duplicates).
    pub allowed_ec: Vec<T38EcMode>,
}

impl Default for T38Config {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_cleartext: false,
            max_bit_rate: 14_400,
            max_datagram: 1400,
            max_buffer: 4096,
            allowed_ec: vec![T38EcMode::Redundancy, T38EcMode::Fec, T38EcMode::NoEc],
        }
    }
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
            t38: T38Config::default(),
        }
    }
}

/// How the SBC handles SRTP-secured media.
///
/// - `Passthrough`: the media relay forwards SRTP/DTLS opaquely; the endpoints
///   perform DTLS-SRTP directly with each other (the SBC never sees plaintext).
///   This is the default and works with the transparent relay today.
/// - `Terminate`: the SBC is a DTLS endpoint on each leg — it completes the
///   DTLS-SRTP handshake, decrypts inbound media, and re-encrypts for the far
///   leg. Required for transcoding, recording, or lawful intercept, and lets
///   the SBC bridge legs with mismatched crypto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SrtpMode {
    /// Relay SRTP/DTLS opaquely; endpoints secure media end-to-end.
    #[default]
    Passthrough,
    /// Terminate DTLS-SRTP at the SBC (decrypt + re-encrypt per leg).
    Terminate,
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

    /// Whether the SBC terminates DTLS-SRTP or relays it opaquely.
    pub mode: SrtpMode,
}

impl Default for SrtpConfig {
    fn default() -> Self {
        Self {
            required: true,
            profile: CnsaSrtpProfile::AeadAes256Gcm,
            mode: SrtpMode::Passthrough,
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

    /// Path to the fingerprint file published by the Go DTLS terminator
    /// sidecar. In the sidecar architecture the sidecar owns the DTLS cert +
    /// key and drives the handshake; the SBC reads this file at startup to get
    /// the fingerprint for the SDP `a=fingerprint`. Preferred over
    /// `cert_path`/`key_path` when set.
    pub fingerprint_file: Option<PathBuf>,

    /// Path to the Go DTLS terminator sidecar's Unix domain socket. The relay
    /// opens one connection per terminated leg to drive the DTLS handshake and
    /// pump records. Required (together with `fingerprint_file`) for the
    /// sidecar termination path when `srtp.mode = terminate`.
    pub sidecar_socket: Option<PathBuf>,

    /// Hash algorithm for SDP fingerprint.
    pub fingerprint_hash: CnsaHash,
}

impl Default for DtlsConfig {
    fn default() -> Self {
        Self {
            cert_path: None,
            key_path: None,
            fingerprint_file: None,
            sidecar_socket: None,
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

    /// Minimum TLS version for SIP-over-TLS listeners: "1.3" (CNSA 2.0
    /// default) or "1.2" (also accepts TLS 1.2 clients).
    pub min_tls_version: String,

    /// Require mutual TLS for SIP: TLS clients must present a certificate
    /// chaining to `tls_ca_path`.
    pub require_mtls: bool,

    /// PEM bundle of CA certificates trusted for client certificates.
    /// Required when `require_mtls` is set.
    pub tls_ca_path: Option<PathBuf>,

    /// PEM bundle of CA certificates trusted for SIP trunk **server**
    /// certificates (outbound TLS to `protocol = "tls"` trunks). Kept
    /// separate from `tls_ca_path` so a client-issuing CA cannot
    /// impersonate a trunk. Required when any trunk uses TLS; there is no
    /// implicit public-root fallback.
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-23 (Session Authenticity)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trunk_tls_ca_path: Option<PathBuf>,

    /// Global TLS-only egress: every trunk group behaves as if it had
    /// `require_tls = true` (a group cannot opt out). Applies to config-file
    /// and API-synced groups alike. Signaling only; does not imply SRTP.
    ///
    /// ## NIST 800-53 Rev5: SC-8 (POA&M-48)
    pub require_tls_trunks: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            tls_cert_path: None,
            tls_key_path: None,
            curve: CnsaCurve::P384,
            min_tls_version: "1.3".to_string(),
            require_mtls: false,
            tls_ca_path: None,
            trunk_tls_ca_path: None,
            require_tls_trunks: false,
        }
    }
}

/// STIR/SHAKEN configuration (`[stir_shaken]`).
///
/// Breaking change (schema for 0.10): `verification_enabled` now defaults to
/// `false` (it previously defaulted to `true` and verified nothing), the
/// signing/verification settings are nested, and `default_attestation` is a
/// typed A/B/C that defaults to `C`. The flat v0.9 keys
/// (`certificate_path`, `private_key_path`, `certificate_url`,
/// `ca_bundle_path`, `default_attestation`, `max_passport_age_secs`) are
/// accepted as deprecated aliases for one release; see
/// [`StirShakenConfig::normalized`].
///
/// ## NIST 800-53 Rev5: IA-9 (Service Identification), CM-6 (secure defaults)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// NIST 800-53 Rev5: CM-6 (a misspelt key is an error, never silently ignored)
#[serde(default, deny_unknown_fields)]
pub struct StirShakenConfig {
    /// Sign outbound INVITEs on trunks with `stir_shaken.sign = true`.
    pub signing_enabled: bool,

    /// Verify inbound Identity on trunks with `stir_shaken.verify = true`.
    /// Requires `verification.trust_anchors_path`.
    pub verification_enabled: bool,

    /// `PASSporT` algorithm. `ES256` is mandatory for SHAKEN interop
    /// (CNSA-EXCEPTION: ATIS-1000074). `ES384` is reserved for bilateral
    /// profiles and rejected by validation in this release.
    pub algorithm: StirAlgorithm,

    /// Signing (authentication service) settings.
    pub signing: StirSigningConfig,

    /// Attestation policy.
    pub attestation: StirAttestationConfig,

    /// Verification service settings.
    pub verification: StirVerificationConfig,

    /// Deprecated alias for `signing.certificate_path`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_path: Option<PathBuf>,
    /// Deprecated alias for `signing.private_key_path`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_path: Option<PathBuf>,
    /// Deprecated alias for `signing.certificate_url`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_url: Option<String>,
    /// Deprecated alias for `attestation.default`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_attestation: Option<String>,
    /// Deprecated alias for `verification.max_passport_age_secs`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_passport_age_secs: Option<u64>,
    /// Deprecated alias for `verification.trust_anchors_path`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_bundle_path: Option<PathBuf>,
}

impl Default for StirShakenConfig {
    fn default() -> Self {
        Self {
            signing_enabled: false,
            verification_enabled: false,
            algorithm: StirAlgorithm::Es256,
            signing: StirSigningConfig::default(),
            attestation: StirAttestationConfig::default(),
            verification: StirVerificationConfig::default(),
            certificate_path: None,
            private_key_path: None,
            certificate_url: None,
            default_attestation: None,
            max_passport_age_secs: None,
            ca_bundle_path: None,
        }
    }
}

impl StirShakenConfig {
    /// Folds the deprecated flat keys into the nested structure and returns
    /// the result plus the deprecated keys that were used (for a startup
    /// warning).
    ///
    /// # Errors
    /// A deprecated key and its replacement are both set to different
    /// values, or `default_attestation` is not A/B/C.
    pub fn normalized(&self) -> Result<(Self, Vec<&'static str>), String> {
        fn fold<T: Clone + PartialEq>(
            old: Option<&T>,
            new: &mut Option<T>,
            key: &'static str,
            used: &mut Vec<&'static str>,
        ) -> Result<(), String> {
            if let Some(o) = old {
                used.push(key);
                match new {
                    Some(n) if n != o => {
                        return Err(format!(
                            "stir_shaken.{key} (deprecated) conflicts with its nested replacement"
                        ));
                    }
                    _ => *new = Some(o.clone()),
                }
            }
            Ok(())
        }
        let mut out = self.clone();
        let mut used = Vec::new();
        fold(
            self.certificate_path.as_ref(),
            &mut out.signing.certificate_path,
            "certificate_path",
            &mut used,
        )?;
        fold(
            self.private_key_path.as_ref(),
            &mut out.signing.private_key_path,
            "private_key_path",
            &mut used,
        )?;
        fold(
            self.certificate_url.as_ref(),
            &mut out.signing.certificate_url,
            "certificate_url",
            &mut used,
        )?;
        fold(
            self.ca_bundle_path.as_ref(),
            &mut out.verification.trust_anchors_path,
            "ca_bundle_path",
            &mut used,
        )?;
        // Nested non-Option keys count as set when they differ from their
        // default, so an alias that disagrees with them is a conflict too.
        let attest = match self.default_attestation.as_deref() {
            None => None,
            Some("A") => Some(StirAttestation::A),
            Some("B") => Some(StirAttestation::B),
            Some("C") => Some(StirAttestation::C),
            Some(_) => return Err("stir_shaken.default_attestation must be A, B, or C".into()),
        };
        let mut nested_attest = (out.attestation.default
            != StirAttestationConfig::default().default)
            .then_some(out.attestation.default);
        fold(
            attest.as_ref(),
            &mut nested_attest,
            "default_attestation",
            &mut used,
        )?;
        if let Some(a) = nested_attest {
            out.attestation.default = a;
        }
        let default_age = StirVerificationConfig::default().max_passport_age_secs;
        let mut nested_age = (out.verification.max_passport_age_secs != default_age)
            .then_some(out.verification.max_passport_age_secs);
        fold(
            self.max_passport_age_secs.as_ref(),
            &mut nested_age,
            "max_passport_age_secs",
            &mut used,
        )?;
        if let Some(age) = nested_age {
            out.verification.max_passport_age_secs = age;
        }
        out.certificate_path = None;
        out.private_key_path = None;
        out.certificate_url = None;
        out.ca_bundle_path = None;
        out.default_attestation = None;
        out.max_passport_age_secs = None;
        Ok((out, used))
    }
}

/// `PASSporT` signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum StirAlgorithm {
    /// ECDSA P-256 / SHA-256 (SHAKEN mandatory; CNSA-EXCEPTION).
    #[default]
    #[serde(rename = "ES256")]
    Es256,
    /// ECDSA P-384 / SHA-384 (CNSA 2.0; non-interoperable for SHAKEN).
    /// Reserved: rejected by validation in this release.
    // POAM: ES384 bilateral PASSporT signing (needs P-384 STI certificates).
    #[serde(rename = "ES384")]
    Es384,
}

/// Where the signing key lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum StirKeySource {
    /// PKCS#8 DER/PEM file (owner-only permissions enforced).
    #[default]
    File,
    /// PKCS#11 token. Reserved; rejected by validation in this release.
    // POAM: PKCS#11/HSM custody of the STIR signing key.
    Pkcs11,
}

/// `[stir_shaken.signing]`.
///
/// ## NIST 800-53 Rev5: SC-12, SC-17, SC-28
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
// NIST 800-53 Rev5: CM-6 (a misspelt key is an error, never silently ignored)
#[serde(default, deny_unknown_fields)]
pub struct StirSigningConfig {
    /// Public HTTPS URL of the signing certificate (`PASSporT` `x5u`).
    pub certificate_url: Option<String>,
    /// PKCS#8 P-256 private key. Must not be group/world accessible and
    /// must not be a symlink.
    pub private_key_path: Option<PathBuf>,
    /// The STI-CA-issued certificate (PEM) published at `certificate_url`;
    /// used for the startup key/cert match and expiry self-check.
    pub certificate_path: Option<PathBuf>,
    /// Key custody.
    pub key_source: StirKeySource,
}

/// Attestation level as configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum StirAttestation {
    /// Full.
    A,
    /// Partial.
    B,
    /// Gateway (default).
    #[default]
    C,
}

/// `[stir_shaken.attestation]`: first matching rule wins, then the
/// `owned_numbers` A/B rule, then `default`.
///
/// ## NIST 800-53 Rev5: IA-9
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
// NIST 800-53 Rev5: CM-6 (a misspelt key is an error, never silently ignored)
#[serde(default, deny_unknown_fields)]
pub struct StirAttestationConfig {
    /// Attestation when no rule matches.
    pub default: StirAttestation,
    /// Calling-number prefixes this operator owns (digits, optional trailing
    /// `*`). An authenticated caller with an owned number gets A; an
    /// authenticated caller without one gets B.
    pub owned_numbers: Vec<String>,
    /// Explicit rules, evaluated in order before `owned_numbers`.
    pub rules: Vec<StirAttestationRule>,
}

/// One attestation rule. Every set field must match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct StirAttestationRule {
    /// Ingress trunk group id.
    pub source_trunk: Option<String>,
    /// Ingress zone (realm).
    pub source_realm: Option<String>,
    /// Caller authenticated (registered endpoint).
    pub authenticated: Option<bool>,
    /// Calling-number prefix (digits).
    pub orig_prefix: Option<String>,
    /// Attestation to apply.
    pub attest: StirAttestation,
}

/// What to do when verification fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum StirFailurePolicy {
    /// Forward without verstat.
    PassThrough,
    /// Forward with `verstat=TN-Validation-Failed` (default).
    #[default]
    Mark,
    /// Reject with the RFC 8224 §6.2.2 code (436/437/438).
    Reject,
}

/// `[stir_shaken.verification]`.
///
/// ## NIST 800-53 Rev5: IA-5(2), SC-7, SC-5, SC-17
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// NIST 800-53 Rev5: CM-6 (a misspelt key is an error, never silently ignored)
#[serde(default, deny_unknown_fields)]
pub struct StirVerificationConfig {
    /// Failure policy.
    pub failure_policy: StirFailurePolicy,
    /// Reject an INVITE with no Identity (428) on verify trunks.
    pub require_identity: bool,
    /// Certificate fetch deadline (100..=5000 ms).
    pub cert_fetch_timeout_ms: u64,
    /// Cached certificates (1..=100000).
    pub cert_cache_entries: usize,
    /// Positive cache TTL cap (seconds).
    pub cert_cache_ttl_secs: u64,
    /// Negative cache TTL (seconds).
    pub negative_cache_ttl_secs: u64,
    /// Maximum certificate response body (bytes, 1024..=65536).
    pub max_cert_bytes: usize,
    /// Concurrent certificate fetches (1..=1024).
    pub max_concurrent_fetches: usize,
    /// Concurrent certificate fetches started for one SIP source (IPv4
    /// address or IPv6 /64), `1..=max_concurrent_fetches`. Bounds how much
    /// of the fetch pool one peer can hold with `x5u` URLs on hosts it
    /// controls (POA&M-190).
    ///
    /// ## NIST 800-53 Rev5: SC-5
    pub max_fetches_per_source: usize,
    /// STI-CR trust anchors: a PEM bundle file or a directory of PEM files.
    pub trust_anchors_path: Option<PathBuf>,
    /// Trust-anchor reload interval (seconds, >= 60).
    pub trust_anchor_refresh_secs: u64,
    /// Optional `x5u` host allow-list (exact, case-insensitive). Empty =
    /// any public host.
    pub x5u_allow_hosts: Vec<String>,
    /// Maximum `PASSporT` age in seconds (RFC 8224 §6.2.2), 10..=300.
    pub max_passport_age_secs: u64,
}

impl Default for StirVerificationConfig {
    fn default() -> Self {
        Self {
            failure_policy: StirFailurePolicy::Mark,
            require_identity: false,
            cert_fetch_timeout_ms: 1500,
            cert_cache_entries: 4096,
            cert_cache_ttl_secs: 3600,
            negative_cache_ttl_secs: 60,
            max_cert_bytes: 16 * 1024,
            max_concurrent_fetches: 32,
            max_fetches_per_source: 4,
            trust_anchors_path: None,
            trust_anchor_refresh_secs: 86_400,
            x5u_allow_hosts: Vec::new(),
            max_passport_age_secs: 60,
        }
    }
}

/// Per-trunk STIR/SHAKEN settings (`[[trunk_groups.trunks]] stir_shaken`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrunkStirConfig {
    /// Sign INVITEs sent to this trunk.
    pub sign: bool,
    /// Verify Identity on INVITEs received from this trunk.
    pub verify: bool,
    /// Drop inbound Identity headers instead of passing them through to the
    /// B-leg. `false` marks the trunk trusted: its Identity is relayed
    /// verbatim and the call is not re-signed.
    pub strip_inbound_identity: bool,
}

impl Default for TrunkStirConfig {
    fn default() -> Self {
        Self {
            sign: false,
            verify: false,
            strip_inbound_identity: true,
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

    /// IPv6 prefix length per-source limiter and connection state is keyed
    /// on (one /64 is one source). Valid 32..=128.
    pub ipv6_prefix_len: u8,

    /// Cap on per-source token buckets. Valid 1024..=4,194,304.
    pub max_tracked_sources: u32,

    /// Cap on simultaneously blocked sources. Valid
    /// 1..=`max_tracked_sources`.
    pub max_blocked_sources: u32,

    /// Rate of the shared bucket that new sources use once
    /// `max_tracked_sources` is reached. `0` (default) means automatic:
    /// 1000 clamped into `per_ip_rps`..=`global_rps`. A non-zero value must
    /// lie in `per_ip_rps`..=`global_rps`.
    pub overflow_rps: u32,

    /// How long a source over 2x `per_ip_rps` stays blocked. Valid 1..=86400.
    pub block_duration_secs: u64,

    /// Interval of the limiter maintenance sweep (expired blocks, idle
    /// buckets). Valid 1..=300.
    pub sweep_interval_secs: u64,

    /// Interval at which rate-limit rejections are aggregated into audit
    /// records. Valid 1..=3600.
    ///
    /// ## NIST 800-53 Rev5: AU-4, AU-12
    pub audit_interval_secs: u64,

    /// Cap on aggregated rate-limit audit records per interval; the rest
    /// are summed into one `per_ip_rps_suppressed` record. Valid 1..=65536.
    pub audit_max_records_per_interval: u32,
}

impl RateLimitConfig {
    /// The overflow bucket rate in effect (resolves the `0` = automatic
    /// setting of `overflow_rps`).
    #[must_use]
    pub fn effective_overflow_rps(&self) -> u32 {
        if self.overflow_rps != 0 {
            return self.overflow_rps;
        }
        let ceiling = self.global_rps.max(self.per_ip_rps);
        1_000u32.clamp(self.per_ip_rps.min(ceiling), ceiling)
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            global_rps: 10000,
            per_ip_rps: 100,
            per_user_rps: 50,
            burst_multiplier: 2.0,
            ipv6_prefix_len: 64,
            max_tracked_sources: 65_536,
            max_blocked_sources: 16_384,
            overflow_rps: 0,
            block_duration_secs: 60,
            sweep_interval_secs: 10,
            audit_interval_secs: 60,
            audit_max_records_per_interval: 1_024,
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

    /// Output format: "json" or "text".
    pub format: String,

    /// Output destination: "stdout", "stderr" or a file path (appended).
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
/// Not implemented: no Prometheus, SNMP or syslog exporter reads these
/// keys, so `validate_config` rejects a present `[monitoring]` table rather
/// than silently ignoring it. The type is kept for API compatibility;
/// `deny_unknown_fields` makes feature-gated subkeys (`snmp`, `syslog`) an
/// error instead of vanishing in builds without those features.
///
/// ## NIST 800-53 Rev5: CM-6, CM-7 (POA&M-191)
// POAM: POA&M-195 telemetry export (Prometheus/SNMP/syslog/OTLP) not implemented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
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

    /// Client certificate names allowed to call the gRPC API when
    /// `require_mtls` is set. Each entry is matched exactly (DNS names
    /// ASCII case-insensitively) against the client certificate's SAN DNS
    /// names, SAN URIs and subject CN. Empty = any certificate that chains
    /// to `tls_ca_path` (a startup warning is logged).
    ///
    /// ## NIST 800-53 Rev5: AC-3 (Access Enforcement), IA-3
    pub allowed_client_names: Vec<String>,

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
            allowed_client_names: Vec::new(),
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
    /// Default trunk group for unmatched calls. Applies to outbound calls
    /// only (calls not arriving from a configured trunk), so a
    /// trunk-originated call is never relayed out another trunk by default.
    ///
    /// ## NIST 800-53 Rev5: AC-4 (Information Flow Enforcement)
    pub default_trunk_group: String,
    /// Trunk group that emergency-classified calls (`[vps]
    /// emergency_numbers`) are force-routed to, bypassing CSS, route
    /// patterns, the dial plan and every number transform. When unset, an
    /// emergency call follows normal routing with route-pattern blocks
    /// ignored. Must name a `[[trunk_groups]]` id.
    ///
    /// ## 47 CFR 9.16; NIST 800-53 Rev5: CP-8 (Telecommunications Services)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emergency_trunk_group: Option<String>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            use_dial_plan: true,
            max_failover_attempts: 3,
            default_trunk_group: "default".to_string(),
            emergency_trunk_group: None,
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
    /// Source trunk filter: only match calls arriving on this trunk group.
    /// A trunk id is accepted and resolved to its trunk group at load
    /// (`validate::resolve_source_trunk`).
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
    /// Zone this trunk group is bound to (must match a `[[zones]]` name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    /// Only trunks with `protocol = "tls"` are used for this group, on the
    /// primary selection and on every failover hop. With no usable TLS
    /// trunk the call is rejected with 503; it never falls back to UDP/TCP.
    /// Validation rejects a `require_tls` group without a TLS trunk.
    /// Signaling only; does not imply SRTP.
    ///
    /// ## NIST 800-53 Rev5: SC-8 (POA&M-48); RFC 5630 §3.1.3
    #[serde(default)]
    pub require_tls: bool,
    /// RFC 3325 Spec(T) trust-domain membership of this group's peers.
    ///
    /// Fail-closed (RFC 3325 §9.1): a group is trusted only when this is
    /// set to `true` explicitly.
    ///
    /// - `true`: inbound P-Asserted-Identity / P-Preferred-Identity from
    ///   these trunks is kept, and outbound `Privacy: id` keeps PAI toward
    ///   them (RFC 3325 §7); the Privacy header is passed on for the next
    ///   privacy service.
    /// - `false` (default): inbound PAI/PPI is stripped at ingress
    ///   (RFC 3325 §5) and outbound privacy is fully applied (RFC 3323
    ///   §5.1), including removal of the Privacy header.
    ///
    /// Registered endpoints are always outside the trust domain.
    /// `stir_shaken.sign = true` on a trunk of a group whose `trust_domain`
    /// is `false` or unset is a load warning: privacy wins and Identity is dropped when
    /// From is anonymized.
    ///
    /// ## NIST 800-53 Rev5: AC-21, SC-4, CM-6 (secure default); RFC 3325 §5, §7, §9.1
    #[serde(default)]
    pub trust_domain: bool,
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
    /// Maximum concurrent calls through this trunk on this node. When
    /// reached, routing skips the trunk; if every trunk is full or down the
    /// INVITE gets 503 with `Retry-After`. Must be > 0.
    pub max_calls: u32,
    /// Extra calls above `max_calls` on this trunk that only emergency
    /// calls may use: routing skips the trunk for a normal call at
    /// `max_calls` and for an emergency call at `max_calls +
    /// emergency_reserve_calls` (503 when no trunk is left). Defaults to
    /// 10% of `max_calls` (at least 1); must be 1..=`max_calls` when set.
    ///
    /// ## 47 CFR 9.16; NIST 800-53 Rev5: SC-5
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emergency_reserve_calls: Option<u32>,
    /// Cooldown period (seconds) after `max_failures` consecutive failed
    /// calls (timeout, transport error, 5xx), or immediately after a 503.
    pub cooldown_secs: u32,
    /// Consecutive failed calls before cooldown. Must be > 0.
    pub max_failures: u32,
    /// Send periodic SIP OPTIONS to this trunk; a trunk that stops answering
    /// 2xx is skipped by routing until it answers again.
    pub options_ping_enabled: bool,
    /// OPTIONS ping interval in seconds (5-3600) when enabled.
    pub options_ping_interval_secs: u32,
    /// STIR/SHAKEN per-trunk behaviour.
    pub stir_shaken: TrunkStirConfig,
    /// TLS server name the trunk certificate is verified against
    /// (`protocol = "tls"` only). Unset: `host` is verified (a DNS name,
    /// or an IP SAN when `host` is an IP literal). Verification is never
    /// skipped.
    ///
    /// ## NIST 800-53 Rev5: SC-23; RFC 5922 §7
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
    /// Present `security.tls_cert_path` / `tls_key_path` to this trunk as
    /// the TLS client certificate (mutual TLS). `protocol = "tls"` only.
    ///
    /// ## NIST 800-53 Rev5: IA-3
    pub tls_client_cert: bool,
    /// UAC digest MD5 policy for carrier REGISTER (POA&M-255). Parsed so
    /// that it is rejected with guidance rather than silently ignored:
    /// config-file trunks are not registered (only trunks in the trunk
    /// store/API carry `register_enabled` and credentials), so the key is
    /// accepted only on stored trunk JSON (`allow_md5_digest`, enforced by
    /// `sbc-trunk-services`). Validation refuses any value here.
    ///
    /// ## NIST 800-53 Rev5: CM-6
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_md5_digest: Option<bool>,
}

impl TrunkConfigSchema {
    /// Emergency headroom above `max_calls` in effect (configured or
    /// the 10% default).
    #[must_use]
    pub fn effective_emergency_reserve_calls(&self) -> u32 {
        self.emergency_reserve_calls
            .unwrap_or_else(|| default_emergency_reserve(self.max_calls))
    }
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
            emergency_reserve_calls: None,
            cooldown_secs: 30,
            max_failures: 5,
            options_ping_enabled: false,
            options_ping_interval_secs: 30,
            stir_shaken: TrunkStirConfig::default(),
            tls_server_name: None,
            tls_client_cert: false,
            allow_md5_digest: None,
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
    /// Hiding mode: "`signaling_only`" or "full" when `enabled`; "none" is
    /// only valid with `enabled = false`. Any other value (including the
    /// never-enforced "basic", POA&M-183) is rejected by validation
    /// (NIST 800-53 Rev5: CM-6).
    pub mode: String,
    /// External hostname to present.
    pub external_host: String,
    /// External port to present.
    pub external_port: u16,
    /// Whether to obfuscate SIP Call-ID headers.
    pub obfuscate_call_id: bool,
    /// External port presented for TLS elements (`transport=tls`, `sips:`),
    /// so the return path is not downgraded to a cleartext port
    /// (RFC 3261 §26.2; NIST 800-53 Rev5: SC-8). POA&M-151.
    pub external_tls_port: u16,
    /// Extra internal networks (CIDR, e.g. `"10.20.0.0/16"`), added to the
    /// built-in RFC 1918 / RFC 6598 / loopback / link-local / ULA defaults.
    pub internal_networks: Vec<String>,
    /// Extra internal DNS domains (a host matches `d` or `*.d`), added to
    /// the built-in defaults (`localhost`, `local`, `internal`, `lan`,
    /// `home.arpa`).
    pub internal_domains: Vec<String>,
}

impl Default for TopologyHidingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: "none".to_string(),
            external_host: String::new(),
            external_port: 5060,
            obfuscate_call_id: false,
            external_tls_port: 5061,
            internal_networks: Vec::new(),
            internal_domains: Vec::new(),
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
    fn trunk_allow_md5_digest_parses_and_round_trips() {
        let toml_str = r#"
            [[trunk_groups]]
            id = "g"
            name = "g"
            [[trunk_groups.trunks]]
            id = "a"
            host = "192.0.2.1"
            [[trunk_groups.trunks]]
            id = "b"
            host = "192.0.2.2"
            allow_md5_digest = false
        "#;
        let config: SbcConfig = toml::from_str(toml_str).expect("parse");
        let trunks = &config.trunk_groups[0].trunks;
        assert_eq!(trunks[0].allow_md5_digest, None);
        assert_eq!(trunks[1].allow_md5_digest, Some(false));
        let out = toml::to_string(&config).expect("serialize");
        assert_eq!(out.matches("allow_md5_digest").count(), 1, "{out}");
        assert!(toml::from_str::<SbcConfig>(&toml_str.replace("= false", "= \"no\"")).is_err());
    }

    // One long TOML fixture plus its assertions; splitting hides the example config.
    #[allow(clippy::too_many_lines)]
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

    // POAM-151 (QA): pre-POA&M-151 TOML without the new topology keys loads
    // with safe defaults; new keys round-trip when present.
    #[test]
    fn qa_topology_hiding_new_keys_default_and_parse() {
        let old: SbcConfig = toml::from_str(
            "[topology_hiding]\nenabled = true\nmode = \"full\"\nexternal_host = \"sbc.example.com\"\n",
        )
        .expect("old TOML loads");
        let t = old.topology_hiding.unwrap();
        assert_eq!(t.external_tls_port, 5061);
        assert_eq!(t.internal_networks, Vec::<String>::new());
        assert_eq!(t.internal_domains, Vec::<String>::new());

        let new: SbcConfig = toml::from_str(
            "[topology_hiding]\nenabled = true\nexternal_host = \"sbc.example.com\"\nexternal_tls_port = 15061\ninternal_networks = [\"10.20.0.0/16\"]\ninternal_domains = [\"corp.example\"]\n",
        )
        .expect("new TOML loads");
        let t = new.topology_hiding.unwrap();
        assert_eq!(t.external_tls_port, 15061);
        assert_eq!(t.internal_networks, vec!["10.20.0.0/16".to_string()]);
        assert_eq!(t.internal_domains, vec!["corp.example".to_string()]);
    }
}
