//! REST API server for the SBC daemon.
//!
//! This module provides an HTTP/HTTPS server using axum for management APIs,
//! metrics endpoints, and health probes.
//!
//! ## Endpoints
//!
//! - `GET /healthz` - Liveness probe
//! - `GET /readyz` - Readiness probe
//! - `GET /api/v1/system/health` - Detailed health status
//! - `GET /api/v1/system/metrics` - Prometheus metrics
//! - `GET /api/v1/system/stats` - Server statistics
//! - `GET /api/v1/system/tls` - TLS certificate reload status
//! - `POST /api/v1/system/tls/reload` - Trigger certificate reload
//! - `GET /api/v1/calls` - List active calls
//! - `GET /api/v1/registrations` - List registrations
//!
//! ## TLS Support
//!
//! The API server supports HTTPS with CNSA 2.0 compliant TLS 1.3:
//! - P-384 ECDSA certificates
//! - AES-256-GCM cipher suite
//! - Hot-reloadable certificates via SIGHUP or API
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-2**: Event Logging - All API requests are logged
//! - **SC-8**: Transmission Confidentiality (TLS enabled)
//! - **SC-12**: Cryptographic Key Establishment and Management (certificate rotation)
//! - **SC-13**: Cryptographic Protection (CNSA 2.0 compliant TLS)

use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use hyper_util::service::TowerToHyperService;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tower::Service;
use tower_http::trace::TraceLayer;
use tracing::{debug, info, warn};
use uc_health::{ComponentStatus, SystemHealth};
use uc_metrics::MetricRegistry;
use uc_transport::cert_reload::ReloadableTlsAcceptor;
use uc_transport::tls::RequiredKeyCurve;
use uc_types::protocol::CnsaCurve;

use crate::server::ServerStats;
use crate::shutdown::ShutdownSignal;

/// Token read once from `SBC_API_TOKEN` at startup. When set, API data
/// endpoints require `Authorization: Bearer <token>`. Health probes are
/// exempt. When unset, no auth is enforced (backwards-compatible, but a
/// warning is logged at startup).
static API_TOKEN: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

// POAM: POA&M-213 — when SBC_API_TOKEN is unset the daemon REST data
// endpoints are unauthenticated (warn only); IA-2 / AC-3.
fn expected_api_token() -> Option<&'static str> {
    API_TOKEN
        .get_or_init(|| {
            let tok = std::env::var("SBC_API_TOKEN")
                .ok()
                .filter(|s| !s.is_empty());
            if tok.is_none() {
                warn!(
                    "SBC_API_TOKEN not set — daemon REST API is unauthenticated. \
                   Set SBC_API_TOKEN to require bearer-token auth on data endpoints."
                );
            }
            tok
        })
        .as_deref()
}

async fn api_auth_middleware(req: Request<axum::body::Body>, next: Next) -> Response {
    if let Some(expected) = expected_api_token() {
        let authorized = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|t| api_token_matches(t, expected));
        if !authorized {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "valid Bearer token required"})),
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// Constant-time bearer-token comparison (length is not secret).
///
/// NIST 800-53 Rev5: IA-2 / IA-5 — no early-exit timing oracle.
fn api_token_matches(presented: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    presented.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1
}

/// TLS handshake deadline on the REST HTTPS listener.
///
/// NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection).
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum concurrent REST HTTPS connections (handshake + serving).
///
/// NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection).
pub const MAX_API_TLS_CONNECTIONS: usize = 256;
/// HTTP/1 request-header read deadline after the handshake (slowloris).
///
/// hyper arms this timer whenever the connection waits for a request head,
/// including the keep-alive gap between requests, so it is also the idle
/// timeout for an established REST HTTPS connection.
///
/// NIST 800-53 Rev5: SC-5, SC-10 (Network Disconnect).
pub const API_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum lifetime of one REST HTTPS connection. On expiry the connection
/// is shut down gracefully (in-flight request finishes, keep-alive ends) and
/// is force-closed after [`API_CONN_DRAIN_GRACE`], releasing its cap permit.
///
/// NIST 800-53 Rev5: SC-5, SC-10 (Network Disconnect).
pub const MAX_API_CONNECTION_AGE: Duration = Duration::from_secs(300);
/// Grace period after [`MAX_API_CONNECTION_AGE`] before a force close.
pub const API_CONN_DRAIN_GRACE: Duration = Duration::from_secs(10);
/// Poll interval for REST TLS certificate/key file changes.
///
/// NIST 800-53 Rev5: SC-17 (Public Key Infrastructure Certificates).
pub const TLS_RELOAD_POLL: Duration = Duration::from_secs(30);

/// Counter: REST TLS handshakes that exceeded [`TLS_HANDSHAKE_TIMEOUT`].
pub const METRIC_API_TLS_HANDSHAKE_TIMEOUTS: &str = "api_tls_handshake_timeouts_total";
/// Counter: REST TLS connections shed because the connection cap was full.
pub const METRIC_API_TLS_CONN_REJECTED: &str = "api_tls_connections_rejected_total";
/// Counter: successful REST TLS certificate reloads.
pub const METRIC_API_TLS_RELOADS: &str = "api_tls_cert_reloads_total";
/// Counter: failed REST TLS certificate reloads (old certificate kept).
pub const METRIC_API_TLS_RELOAD_FAILURES: &str = "api_tls_cert_reload_failures_total";

/// API server configuration.
#[derive(Debug, Clone)]
pub struct ApiServerConfig {
    /// Listen address for HTTP server.
    pub listen_addr: SocketAddr,
    /// Optional separate listen address for HTTPS. When set together with
    /// `tls`, the daemon serves HTTP on `listen_addr` and HTTPS on
    /// `tls_listen_addr` concurrently. If `None`, behavior depends on `tls`:
    /// when `tls` is Some the HTTPS listener uses `listen_addr` (legacy
    /// HTTPS-only mode); when `tls` is None the daemon runs plain HTTP.
    pub tls_listen_addr: Option<SocketAddr>,
    /// Enable CORS.
    pub enable_cors: bool,
    /// API version prefix.
    pub api_version: String,
    /// TLS configuration (cert + key paths). Required for HTTPS.
    pub tls: Option<TlsConfig>,
    /// TLS handshake deadline (default [`TLS_HANDSHAKE_TIMEOUT`]).
    pub tls_handshake_timeout: Duration,
    /// Concurrent HTTPS connection cap (default [`MAX_API_TLS_CONNECTIONS`]).
    pub max_tls_connections: usize,
    /// Certificate change poll interval (default [`TLS_RELOAD_POLL`]).
    pub tls_reload_poll: Duration,
    /// Request-head / keep-alive idle deadline (default
    /// [`API_HEADER_READ_TIMEOUT`]).
    pub tls_idle_timeout: Duration,
    /// Maximum HTTPS connection lifetime (default [`MAX_API_CONNECTION_AGE`]).
    pub max_tls_connection_age: Duration,
}

/// TLS configuration for the API server.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Path to TLS certificate (PEM format).
    pub cert_path: PathBuf,
    /// Path to TLS private key (PEM format).
    pub key_path: PathBuf,
}

impl Default for ApiServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080"
                .parse()
                .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 8080))),
            tls_listen_addr: None,
            enable_cors: false,
            api_version: "v1".to_string(),
            tls: None,
            tls_handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
            max_tls_connections: MAX_API_TLS_CONNECTIONS,
            tls_reload_poll: TLS_RELOAD_POLL,
            tls_idle_timeout: API_HEADER_READ_TIMEOUT,
            max_tls_connection_age: MAX_API_CONNECTION_AGE,
        }
    }
}

/// Persistence root for management objects. Each entity type is its own
/// JSON file (trunk_groups.json, phones.json, directory_numbers.json) so a
/// corrupt one doesn't take the others down. The mountpoint matches the
/// Helm chart's PVC mount at /var/lib/sbc.
const TRUNK_GROUPS_PATH: &str = "/var/lib/sbc/trunk_groups.json";
const PHONES_PATH: &str = "/var/lib/sbc/phones.json";
const DIRECTORY_PATH: &str = "/var/lib/sbc/directory_numbers.json";

/// In-memory store for management objects, with JSON-on-disk persistence
/// for the slices the dashboard mutates.
#[derive(Default)]
pub struct MemStore {
    /// Phones indexed by ID.
    pub phones: std::collections::HashMap<String, serde_json::Value>,
    /// Directory numbers indexed by DID.
    pub directory_numbers: std::collections::HashMap<String, serde_json::Value>,
    /// Trunk groups (route groups) indexed by ID.
    pub trunk_groups: std::collections::HashMap<String, serde_json::Value>,
}

impl MemStore {
    /// Generic loader for an entity-type JSON file. Missing file is the
    /// "fresh deployment" case and returns an empty map silently.
    fn load_map(path: &str, kind: &str) -> std::collections::HashMap<String, serde_json::Value> {
        let p = std::path::Path::new(path);
        if !p.exists() {
            return std::collections::HashMap::new();
        }
        match std::fs::read_to_string(p) {
            Ok(data) => match serde_json::from_str::<
                std::collections::HashMap<String, serde_json::Value>,
            >(&data)
            {
                Ok(map) => {
                    tracing::info!(count = map.len(), kind, path, "Loaded persisted entities");
                    map
                }
                Err(e) => {
                    tracing::warn!(error = %e, kind, path, "Failed to parse, starting fresh");
                    std::collections::HashMap::new()
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, kind, path, "Failed to read");
                std::collections::HashMap::new()
            }
        }
    }

    /// Generic atomic-write persister via temp-file + rename.
    fn save_map(
        map: &std::collections::HashMap<String, serde_json::Value>,
        path: &str,
        kind: &str,
    ) {
        // Ensure parent dir exists (no-op when PVC is mounted; helps in dev).
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let data = match serde_json::to_string_pretty(map) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, kind, "Failed to serialize");
                return;
            }
        };
        let tmp = format!("{path}.tmp");
        if let Err(e) = std::fs::write(&tmp, &data) {
            tracing::warn!(error = %e, kind, path = tmp, "Failed to write tmp");
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, path) {
            tracing::warn!(error = %e, kind, src = tmp, dst = path, "Failed to rename into place");
            return;
        }
        tracing::debug!(count = map.len(), kind, path, "Persisted entities");
    }

    pub fn load_trunk_groups() -> std::collections::HashMap<String, serde_json::Value> {
        Self::load_map(TRUNK_GROUPS_PATH, "trunk_groups")
    }
    pub fn load_phones() -> std::collections::HashMap<String, serde_json::Value> {
        Self::load_map(PHONES_PATH, "phones")
    }
    pub fn load_directory_numbers() -> std::collections::HashMap<String, serde_json::Value> {
        Self::load_map(DIRECTORY_PATH, "directory_numbers")
    }
    pub fn save_trunk_groups(&self) {
        Self::save_map(&self.trunk_groups, TRUNK_GROUPS_PATH, "trunk_groups");
    }
    pub fn save_phones(&self) {
        Self::save_map(&self.phones, PHONES_PATH, "phones");
    }
    pub fn save_directory_numbers(&self) {
        Self::save_map(&self.directory_numbers, DIRECTORY_PATH, "directory_numbers");
    }

    /// Loads all persisted entity types. Called once at startup.
    pub fn load_all(&mut self) {
        self.trunk_groups = Self::load_trunk_groups();
        self.phones = Self::load_phones();
        self.directory_numbers = Self::load_directory_numbers();
    }
}

/// Trunk status snapshot pushed by an external sbc-trunk-agent pod
/// (gRPC `TrunkStatusPublishService`). The agent owns the OPTIONS-ping
/// and carrier-registration loops in `SBC_TRUNK_SERVICES=external`
/// deployments; the daemon stores the latest snapshot here so the
/// `TrunkHealthService` read RPCs keep one consistent view for sbc-api
/// and the dashboard regardless of where the loops run.
#[derive(Debug, Default)]
pub struct RemoteTrunkStatus {
    /// Publishing agent's identity (pod name).
    pub agent_id: String,
    /// OPTIONS-ping health per trunk.
    pub health: Vec<crate::trunk_monitor::TrunkHealthStatus>,
    /// Carrier-registration status per trunk.
    pub registrations: Vec<crate::trunk_registrar::TrunkRegistrationStatus>,
    /// When the snapshot was received (staleness detection).
    pub received_at: Option<Instant>,
}

/// Shared application state for the API server.
pub struct AppState {
    /// Metrics registry.
    pub metrics: MetricRegistry,
    /// Server statistics.
    pub stats: Arc<ServerStats>,
    /// Version string.
    pub version: String,
    /// Start time for uptime calculation.
    pub start_time: Instant,
    /// Ready state.
    pub ready: AtomicU64,
    /// SIP stack for call/registration queries.
    pub sip_stack: Option<Arc<crate::sip_stack::SipStack>>,
    /// Egress flow table, for its counters on the metrics endpoint.
    pub flows: Option<Arc<crate::flows::FlowTable>>,
    /// Phone provisioning server.
    pub provisioning: Option<Arc<uc_phone_mgmt::provisioning::ProvisioningServer>>,
    /// SBC router for CSS/partition-based routing.
    pub sbc_router: Option<Arc<tokio::sync::RwLock<uc_routing::SbcRouter>>>,
    /// Trunk health monitor. `None` when trunk services run externally
    /// in the sbc-trunk-agent pod (`SBC_TRUNK_SERVICES=external`).
    pub trunk_monitor: Option<Arc<crate::trunk_monitor::TrunkMonitor>>,
    /// Trunk registrar (SBC registers to carriers). `None` when trunk
    /// services run externally (see [`Self::trunk_monitor`]).
    pub trunk_registrar: Option<Arc<crate::trunk_registrar::TrunkRegistrar>>,
    /// Latest trunk status snapshot published by an external
    /// sbc-trunk-agent pod via the gRPC `TrunkStatusPublishService`.
    /// Served by `TrunkHealthService` reads when `trunk_monitor` /
    /// `trunk_registrar` are `None`.
    pub remote_trunk_status: Arc<tokio::sync::RwLock<RemoteTrunkStatus>>,
    /// Zone registry for resolving zone IPs (signaling, media, external).
    pub zone_registry: Option<Arc<crate::zone::ResolvedZoneRegistry>>,
    /// In-memory store for management objects (phones, directory numbers, etc.).
    pub mem_store: Arc<tokio::sync::RwLock<MemStore>>,
    /// Postgres-backed directory-number store. When `Some`, DID handlers
    /// read/write Postgres instead of the JSON-on-disk `MemStore` path.
    /// Set at startup based on `config.storage.postgres`; `None` preserves
    /// the legacy single-pod JSON behavior.
    pub directory_store: Option<Arc<sbc_config_store::PostgresDirectoryNumberStore>>,
    /// Postgres-backed phone store. Same on/off semantics as
    /// `directory_store`; both keyed off the single `SBC_POSTGRES_URL`
    /// env var. When `Some`, phone CRUD and `serve_phone_config` query
    /// Postgres; the MemStore phones map is bypassed.
    pub phone_store: Option<Arc<sbc_config_store::PostgresPhoneStore>>,
    /// Postgres-backed trunk-group store. When `Some`, trunk-group and
    /// nested trunk CRUD persist to Postgres in addition to the existing
    /// `sip_stack`/`sbc_router` synchronization (which is unchanged —
    /// persistence and SIP-stack wiring are separate concerns here).
    pub trunk_group_store: Option<Arc<sbc_config_store::PostgresTrunkGroupStore>>,
    /// Postgres-backed dial-plan store. Before this PR, dial plans lived
    /// only in the `SbcRouter` and were lost on every daemon restart.
    /// When `Some`, dial-plan writes persist and the startup loop replays
    /// them into the router so SIP routing decisions survive restarts.
    pub dial_plan_store: Option<Arc<sbc_config_store::PostgresDialPlanStore>>,
    /// Postgres-backed SBC-routing stores (PR11). Pre-PR11 these lived
    /// only in-memory inside `SbcRouter` — a daemon restart wiped them.
    /// When `Some`, sbc-api owns the writes (and notifies via the gRPC
    /// `SbcSyncService`) and the daemon's startup loop replays them
    /// into the router so partition/CSS/route-pattern/route-list state
    /// survives restarts.
    pub partition_store: Option<Arc<sbc_config_store::PostgresPartitionStore>>,
    /// See [`Self::partition_store`].
    pub css_store: Option<Arc<sbc_config_store::PostgresCallingSearchSpaceStore>>,
    /// See [`Self::partition_store`].
    pub route_pattern_store: Option<Arc<sbc_config_store::PostgresRoutePatternStore>>,
    /// See [`Self::partition_store`].
    pub route_list_store: Option<Arc<sbc_config_store::PostgresRouteListStore>>,
    /// TLS acceptor for certificate hot-reload (if TLS is enabled).
    pub tls_acceptor: Option<Arc<ReloadableTlsAcceptor>>,
    /// Cluster health check function (when cluster feature is enabled).
    #[cfg(feature = "cluster")]
    pub cluster_health_fn: Option<
        Arc<
            dyn Fn() -> std::pin::Pin<
                    Box<dyn std::future::Future<Output = crate::cluster::ClusterHealth> + Send>,
                > + Send
                + Sync,
        >,
    >,
}

/// Gauge: audit records lost (queue full, writer thread dead, or sink
/// write failed).
pub const METRIC_AUDIT_RECORDS_DROPPED: &str = "audit_records_dropped";
/// Gauge: audit records the sink failed to persist (e.g. ENOSPC); included
/// in [`METRIC_AUDIT_RECORDS_DROPPED`].
pub const METRIC_AUDIT_WRITE_FAILURES: &str = "audit_write_failures";
/// Gauge: 1 while the audit writer thread runs, 0 once it has exited.
pub const METRIC_AUDIT_WRITER_ALIVE: &str = "audit_writer_alive";
/// Gauge: emergency INVITEs admitted through the emergency bypass.
pub const METRIC_EMERGENCY_ADMISSIONS: &str = "emergency_calls_admitted";
/// Call-path routing gauges mirroring monotonic counters (no labels).
///
/// ## NIST 800-53 Rev5: SI-4 (System Monitoring), AU-2
pub const ROUTING_METRICS: &[(&str, &str)] = &[
    (
        "sbc_route_blocked_total",
        "INVITEs refused with 403 by a blocked route pattern",
    ),
    (
        "sbc_emergency_force_routed_emergency_trunk_total",
        "Emergency calls force-routed to routing.emergency_trunk_group",
    ),
    (
        "sbc_emergency_force_routed_blocked_ignored_total",
        "Emergency calls routed past a blocked route pattern",
    ),
    (
        "sbc_emergency_unrouted_total",
        "Emergency calls refused with 503 because nothing could route them",
    ),
    (
        "sbc_user_limiter_overflow_total",
        "Per-user limiter keys allowed untracked because the key map was full",
    ),
    (
        "sbc_user_limiter_emergency_bypass_total",
        "Emergency INVITEs exempted from the per-user limiter",
    ),
    (
        "sbc_route_pattern_rejected_total",
        "Route patterns rejected for an unknown pattern_type (seed or sync)",
    ),
    // NIST 800-53 Rev5: SI-4, AU-6 - POA&M-156 fail-closed counters.
    (
        "sbc_topology_hiding_failures_total",
        "Messages dropped or replaced because topology hiding failed (fail closed)",
    ),
    (
        "sbc_header_manipulation_failures_total",
        "Messages whose header manipulation rules failed",
    ),
    // RFC 3261 §13.2.2.4: late INVITE 2xx after release, ACKed and BYE'd.
    (
        "sbc_late_invite_2xx_teardown_total",
        "INVITE 2xx responses received after the call was released, torn down with ACK+BYE",
    ),
    // NIST 800-53 Rev5: SI-4, AU-5, SC-5 - deferred-send queue overflow.
    (
        "sbc_deferred_send_dropped_total",
        "SBC-originated requests (e.g. post-announcement BYE) dropped because the deferred-send queue was full",
    ),
];
/// Gauge: CDRs accepted onto the writer queue.
pub const METRIC_CDR_EMITTED: &str = "cdr_emitted_total";
/// Gauge: CDRs dropped because the queue was full.
pub const METRIC_CDR_DROPPED_QUEUE_FULL: &str = "cdr_dropped_queue_full_total";
/// Gauge: CDRs dropped because the writer had exited.
pub const METRIC_CDR_DROPPED_WRITER_DEAD: &str = "cdr_dropped_writer_dead_total";
/// Gauge: CDR file sink write failures.
pub const METRIC_CDR_WRITE_ERRORS: &str = "cdr_write_errors_total";
/// Gauge: CDRs the syslog sink skipped because its own queue was full.
pub const METRIC_CDR_SYSLOG_DROPPED: &str = "cdr_syslog_dropped_total";
/// Gauge: CDRs waiting on the writer queue.
pub const METRIC_CDR_QUEUE_DEPTH: &str = "cdr_queue_depth";
/// Gauge: CDR file rotations.
pub const METRIC_CDR_ROTATIONS: &str = "cdr_rotations_total";
/// Gauge: 1 while the CDR writer thread runs.
pub const METRIC_CDR_WRITER_ALIVE: &str = "cdr_writer_alive";
/// Gauge: epoch seconds of the last CDR file write (0 = never).
pub const METRIC_CDR_LAST_WRITE: &str = "cdr_last_write_timestamp_seconds";

/// Egress flow-layer gauges (POA&M-5; bounded names, no per-peer labels).
///
/// ## NIST 800-53 Rev5: SC-5, SI-4
pub const FLOW_METRICS: &[(&str, &str)] = &[
    (
        "sip_egress_connections",
        "SBC-dialled TCP/TLS trunk connections currently open",
    ),
    (
        "sip_egress_connect_failures_total",
        "Egress trunk connect, handshake/verification, timeout or cap failures",
    ),
    (
        "sip_egress_dial_backoff_total",
        "Egress sends failed at once inside a dial-failure backoff window",
    ),
    (
        "sip_send_no_connection_total",
        "Sends to an accepted connection that had already closed",
    ),
    (
        "sip_stream_write_timeouts_total",
        "Stream writes that missed the write deadline (connection closed)",
    ),
    (
        "sip_send_lane_dropped_total",
        "Stream sends dropped because their per-destination queue was full",
    ),
    (
        "sip_send_lane_overflow_total",
        "Stream sends run unordered because the lane table was full",
    ),
];

/// `require_tls` trunk-group policy counters (POA&M-48; no labels).
///
/// Exported as gauges mirroring monotonic router counters: `MetricRegistry`
/// counters have no `set`, and a scrape-time delta would double count under
/// concurrent scrapes, so the names carry no `_total` suffix.
///
/// ## NIST 800-53 Rev5: SC-8, SI-4
pub const TLS_POLICY_METRICS: &[(&str, &str)] = &[
    (
        "routing_tls_required_skips",
        "Non-TLS trunks excluded, counted per routing decision",
    ),
    (
        "routing_tls_required_rejects",
        "require_tls group-level refusals (a later group may still carry the call)",
    ),
];

/// STIR/SHAKEN gauges (bounded names; no per-host or per-number labels).
///
/// ## NIST 800-53 Rev5: SI-4 (System Monitoring), IA-9
pub const STIR_METRICS: &[(&str, &str)] = &[
    (
        "stir_sign_ok_total",
        "INVITEs signed with a SHAKEN PASSporT",
    ),
    (
        "stir_sign_failed_total",
        "Signing attempts that failed (INVITE sent unsigned)",
    ),
    (
        "stir_verify_passed_total",
        "Inbound Identity verifications passed",
    ),
    (
        "stir_verify_failed_total",
        "Inbound Identity verifications failed",
    ),
    (
        "stir_verify_absent_total",
        "INVITEs on verify trunks without an Identity header",
    ),
    (
        "stir_verify_rejected_total",
        "INVITEs rejected by the STIR failure policy (403/428/436/437/438)",
    ),
    (
        "stir_verify_parked_calls",
        "INVITEs currently waiting on an x5u certificate fetch",
    ),
    (
        "stir_cert_cache_entries",
        "Cached STI certificates (positive and negative)",
    ),
    (
        "stir_signing_cert_expiry_seconds",
        "Seconds until the STIR signing certificate expires",
    ),
    (
        "stir_audit_events_dropped_total",
        "STIR failure audit events dropped because the aggregation table was full",
    ),
];

/// Registers the daemon's audit and emergency gauges, refreshed by
/// [`AppState::refresh_daemon_metrics`] before each export.
///
/// ## NIST 800-53 Rev5: AU-5, SI-4 (System Monitoring)
fn register_daemon_metrics(metrics: &mut MetricRegistry) {
    metrics.register_counter(
        METRIC_API_TLS_HANDSHAKE_TIMEOUTS,
        "REST HTTPS handshakes abandoned after the handshake deadline",
    );
    metrics.register_counter(
        METRIC_API_TLS_CONN_REJECTED,
        "REST HTTPS connections shed because the connection cap was reached",
    );
    metrics.register_counter(
        METRIC_API_TLS_RELOADS,
        "Successful REST HTTPS certificate reloads",
    );
    metrics.register_counter(
        METRIC_API_TLS_RELOAD_FAILURES,
        "Failed REST HTTPS certificate reloads (previous certificate kept)",
    );
    metrics.register_gauge(
        METRIC_AUDIT_RECORDS_DROPPED,
        "Audit records lost: audit queue full, writer exited, or sink write failed",
    );
    metrics.register_gauge(
        METRIC_AUDIT_WRITE_FAILURES,
        "Audit records the audit sink failed to persist (included in audit_records_dropped)",
    );
    metrics.register_gauge(
        METRIC_AUDIT_WRITER_ALIVE,
        "1 while the audit writer thread runs, 0 after it has exited",
    );
    metrics.register_gauge(
        METRIC_EMERGENCY_ADMISSIONS,
        "Emergency INVITEs admitted through the emergency bypass (47 CFR 9.16)",
    );
    for &(name, help) in ROUTING_METRICS {
        metrics.register_gauge(name, help);
    }
    // NIST 800-53 Rev5: AU-5 (CDR pipeline failure visibility)
    for (name, help) in [
        (METRIC_CDR_EMITTED, "CDRs accepted onto the writer queue"),
        (
            METRIC_CDR_DROPPED_QUEUE_FULL,
            "CDRs dropped because the writer queue was full",
        ),
        (
            METRIC_CDR_DROPPED_WRITER_DEAD,
            "CDRs dropped because the CDR writer thread had exited",
        ),
        (METRIC_CDR_WRITE_ERRORS, "CDR file sink write failures"),
        (
            METRIC_CDR_SYSLOG_DROPPED,
            "CDRs not forwarded to syslog because the syslog queue was full (file copy kept)",
        ),
        (METRIC_CDR_QUEUE_DEPTH, "CDRs waiting on the writer queue"),
        (METRIC_CDR_ROTATIONS, "CDR file rotations"),
        (
            METRIC_CDR_WRITER_ALIVE,
            "1 while the CDR writer thread runs, 0 after it has exited",
        ),
        (
            METRIC_CDR_LAST_WRITE,
            "Epoch seconds of the last successful CDR file write (0 = never)",
        ),
    ] {
        metrics.register_gauge(name, help);
    }
    for (name, help) in STIR_METRICS {
        metrics.register_gauge(*name, *help);
    }
    for (name, help) in FLOW_METRICS {
        metrics.register_gauge(*name, *help);
    }
    for (name, help) in TLS_POLICY_METRICS {
        metrics.register_gauge(*name, *help);
    }
}

/// Health of the CDR pipeline (component `cdr`): unhealthy when the writer
/// is dead or a file write failed in the last 60 s, degraded after recent
/// drops or syslog errors. Healthy when CDRs are disabled.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
fn cdr_component_status(cdr: Option<&crate::cdr::CdrContext>) -> ComponentStatus {
    let Some(cdr) = cdr else {
        return ComponentStatus::healthy("cdr");
    };
    let e = cdr.emitter();
    let s = e.stats();
    match e.health() {
        uc_cdr::CdrHealth::Healthy => ComponentStatus::healthy("cdr"),
        uc_cdr::CdrHealth::Degraded => ComponentStatus::degraded(
            "cdr",
            format!(
                "{} CDRs dropped, {} sink errors, {} not forwarded to syslog",
                s.dropped(),
                s.sink_errors,
                s.sink_dropped
            ),
        ),
        uc_cdr::CdrHealth::Unhealthy => ComponentStatus::unhealthy(
            "cdr",
            if s.writer_alive {
                format!("CDR file write failing ({} errors)", s.write_errors)
            } else {
                format!("CDR writer thread exited; {} CDRs dropped", s.dropped())
            },
        ),
    }
}

/// How long after the most recent dropped audit record the `audit` health
/// component stays degraded. The cumulative `sbc_audit_records_dropped`
/// counter is never reset, so alerting on its rate still sees every drop.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
pub const AUDIT_DROP_DEGRADED_WINDOW: Duration = Duration::from_secs(60);

/// Health of the audit pipeline: unhealthy once the writer thread has
/// exited (every record is dropped) or while the sink is failing writes
/// (an unopenable `logging.audit_path` stops startup instead); degraded while records were lost within [`AUDIT_DROP_DEGRADED_WINDOW`];
/// healthy otherwise.
///
/// ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
fn audit_component_status() -> ComponentStatus {
    audit_status_from(&uc_audit::stats(), AUDIT_DROP_DEGRADED_WINDOW)
}

/// Pure decision behind [`audit_component_status`].
///
/// ## NIST 800-53 Rev5: AU-5, SI-4 (System Monitoring)
fn audit_status_from(stats: &uc_audit::AuditStats, window: Duration) -> ComponentStatus {
    let dropped = stats.dropped;
    if !stats.writer_alive {
        return ComponentStatus::unhealthy(
            "audit",
            format!("audit writer thread exited; {dropped} records dropped"),
        );
    }
    if stats.sink_failing {
        return ComponentStatus::unhealthy(
            "audit",
            format!("audit sink write failing ({} errors)", stats.write_failures),
        );
    }
    let recent = [stats.last_drop, stats.last_write_failure]
        .into_iter()
        .flatten()
        .min();
    match recent {
        Some(ago) if ago < window => ComponentStatus::degraded(
            "audit",
            format!(
                "{dropped} audit records dropped, last {}s ago",
                ago.as_secs()
            ),
        ),
        _ => ComponentStatus::healthy("audit"),
    }
}

impl AppState {
    /// Sets the audit and emergency gauges from their sources. Call before
    /// exporting `metrics`.
    ///
    /// ## NIST 800-53 Rev5: AU-5, SI-4 (System Monitoring)
    pub fn refresh_daemon_metrics(&self) {
        let as_gauge = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
        if let Some(g) = self.metrics.gauge(METRIC_AUDIT_RECORDS_DROPPED) {
            g.set(as_gauge(uc_audit::dropped_records()));
        }
        if let Some(g) = self.metrics.gauge(METRIC_AUDIT_WRITER_ALIVE) {
            g.set(i64::from(uc_audit::writer_alive()));
        }
        if let Some(g) = self.metrics.gauge(METRIC_AUDIT_WRITE_FAILURES) {
            g.set(as_gauge(uc_audit::write_failures()));
        }
        if let (Some(g), Some(stack)) = (
            self.metrics.gauge(METRIC_EMERGENCY_ADMISSIONS),
            self.sip_stack.as_ref(),
        ) {
            g.set(as_gauge(stack.emergency_admissions()));
        }
        if let Some(stack) = self.sip_stack.as_ref() {
            let c = stack.routing_counters();
            let load =
                |a: &std::sync::atomic::AtomicU64| a.load(std::sync::atomic::Ordering::Relaxed);
            // Sized by ROUTING_METRICS so a missing value is a compile error
            // (the zip below would otherwise drop it silently).
            let values: [u64; ROUTING_METRICS.len()] = [
                load(&c.route_blocked),
                load(&c.emergency_force_routed_trunk),
                load(&c.emergency_force_routed_blocked_ignored),
                load(&c.emergency_unrouted),
                load(&c.user_limiter_overflow),
                load(&c.user_limiter_emergency_bypass),
                load(&crate::sip_stack::ROUTE_PATTERN_REJECTED),
                load(&c.topology_hiding_failures),
                load(&c.header_manipulation_failures),
                load(&c.late_2xx_teardowns),
                stack.deferred_send_dropped(),
            ];
            for (&(name, _), v) in ROUTING_METRICS.iter().zip(values) {
                if let Some(g) = self.metrics.gauge(name) {
                    g.set(as_gauge(v));
                }
            }
        }
        if let Some(cdr) = self.sip_stack.as_ref().and_then(|s| s.cdr()) {
            let s = cdr.emitter().stats();
            for (name, v) in [
                (METRIC_CDR_EMITTED, s.emitted),
                (METRIC_CDR_DROPPED_QUEUE_FULL, s.dropped_queue_full),
                (METRIC_CDR_DROPPED_WRITER_DEAD, s.dropped_writer_dead),
                (METRIC_CDR_WRITE_ERRORS, s.write_errors),
                (METRIC_CDR_SYSLOG_DROPPED, s.sink_dropped),
                (METRIC_CDR_QUEUE_DEPTH, s.queue_depth),
                (METRIC_CDR_ROTATIONS, s.rotations),
                (METRIC_CDR_WRITER_ALIVE, u64::from(s.writer_alive)),
                (METRIC_CDR_LAST_WRITE, s.last_write_ms / 1000),
            ] {
                if let Some(g) = self.metrics.gauge(name) {
                    g.set(as_gauge(v));
                }
            }
        }
        if let Some(flows) = self.flows.as_ref() {
            use std::sync::atomic::Ordering::Relaxed;
            let f = &flows.stats;
            for (name, v) in [
                (
                    "sip_egress_connections",
                    u64::try_from(f.egress_connections.load(Relaxed)).unwrap_or(u64::MAX),
                ),
                (
                    "sip_egress_connect_failures_total",
                    f.egress_connect_failures.load(Relaxed),
                ),
                (
                    "sip_egress_dial_backoff_total",
                    f.egress_dial_backoff.load(Relaxed),
                ),
                (
                    "sip_send_no_connection_total",
                    f.send_no_connection.load(Relaxed),
                ),
                (
                    "sip_stream_write_timeouts_total",
                    f.stream_write_timeouts.load(Relaxed),
                ),
                ("sip_send_lane_dropped_total", f.lane_dropped.load(Relaxed)),
                (
                    "sip_send_lane_overflow_total",
                    f.lane_overflow.load(Relaxed),
                ),
            ] {
                if let Some(g) = self.metrics.gauge(name) {
                    g.set(as_gauge(v));
                }
            }
        }
        // NIST 800-53 Rev5: SI-4 — lock-free read; never takes the router lock.
        if let Some(stack) = self.sip_stack.as_ref() {
            let c = stack.tls_policy_counters();
            for (name, v) in [
                ("routing_tls_required_skips", c.skips()),
                ("routing_tls_required_rejects", c.rejects()),
            ] {
                if let Some(g) = self.metrics.gauge(name) {
                    g.set(as_gauge(v));
                }
            }
        }
        if let Some(stir) = self.sip_stack.as_ref().and_then(|s| s.stir()) {
            use std::sync::atomic::Ordering::Relaxed;
            let m = &stir.metrics;
            for (name, v) in [
                ("stir_sign_ok_total", as_gauge(m.sign_ok.load(Relaxed))),
                (
                    "stir_sign_failed_total",
                    as_gauge(m.sign_failed.load(Relaxed)),
                ),
                (
                    "stir_verify_passed_total",
                    as_gauge(m.verify_passed.load(Relaxed)),
                ),
                (
                    "stir_verify_failed_total",
                    as_gauge(m.verify_failed.load(Relaxed)),
                ),
                (
                    "stir_verify_absent_total",
                    as_gauge(m.verify_absent.load(Relaxed)),
                ),
                (
                    "stir_verify_rejected_total",
                    as_gauge(m.verify_rejected.load(Relaxed)),
                ),
                ("stir_verify_parked_calls", m.parked.load(Relaxed)),
                (
                    "stir_cert_cache_entries",
                    i64::try_from(stir.cert_cache_entries()).unwrap_or(i64::MAX),
                ),
                (
                    "stir_signing_cert_expiry_seconds",
                    stir.signing_cert_expiry_secs().unwrap_or(0),
                ),
                (
                    "stir_audit_events_dropped_total",
                    as_gauge(stir.audit_events_dropped()),
                ),
            ] {
                if let Some(g) = self.metrics.gauge(name) {
                    g.set(v);
                }
            }
        }
    }

    /// Creates new application state.
    pub fn new(mut metrics: MetricRegistry, stats: Arc<ServerStats>) -> Self {
        register_daemon_metrics(&mut metrics);
        Self {
            metrics,
            stats,
            version: env!("CARGO_PKG_VERSION").to_string(),
            start_time: Instant::now(),
            ready: AtomicU64::new(1), // Start as ready
            sip_stack: None,
            flows: None,
            provisioning: None,
            sbc_router: None,
            mem_store: Arc::new(tokio::sync::RwLock::new(MemStore::default())),
            directory_store: None,
            phone_store: None,
            trunk_group_store: None,
            dial_plan_store: None,
            partition_store: None,
            css_store: None,
            route_pattern_store: None,
            route_list_store: None,
            trunk_monitor: None,
            trunk_registrar: None,
            remote_trunk_status: Arc::new(tokio::sync::RwLock::new(RemoteTrunkStatus::default())),
            zone_registry: None,
            tls_acceptor: None,
            #[cfg(feature = "cluster")]
            cluster_health_fn: None,
        }
    }

    /// Sets the cluster health check function.
    #[cfg(feature = "cluster")]
    pub fn set_cluster_health_fn<F, Fut>(&mut self, f: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = crate::cluster::ClusterHealth> + Send + 'static,
    {
        self.cluster_health_fn = Some(Arc::new(move || Box::pin(f())));
    }

    /// Reloads TLS certificates if TLS is enabled.
    ///
    /// Returns Ok(true) if reload succeeded, Ok(false) if TLS not enabled.
    pub fn reload_tls_certificates(&self) -> Result<bool, String> {
        match &self.tls_acceptor {
            Some(acceptor) => {
                acceptor.reload().map_err(|e| e.to_string())?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Returns TLS certificate reload statistics.
    pub fn tls_stats(&self) -> Option<TlsReloadStats> {
        self.tls_acceptor.as_ref().map(|acceptor| TlsReloadStats {
            reload_count: acceptor.reload_count(),
            last_reload_timestamp: acceptor.last_reload_timestamp(),
            cert_path: acceptor.cert_path().display().to_string(),
            key_path: acceptor.key_path().display().to_string(),
        })
    }

    /// Returns the uptime in seconds.
    pub fn uptime_secs(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Returns whether the server is ready.
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed) != 0
    }

    /// Sets the ready state.
    pub fn set_ready(&self, ready: bool) {
        self.ready.store(u64::from(ready), Ordering::Relaxed);
    }

    /// Performs a health check.
    #[allow(unused_mut)]
    pub fn check_health(&self) -> SystemHealth {
        let mut components = vec![
            ComponentStatus::healthy("sbc_core"),
            ComponentStatus::healthy("sip_transport"),
            ComponentStatus::healthy("media_engine"),
            audit_component_status(),
            cdr_component_status(
                self.sip_stack
                    .as_ref()
                    .and_then(|s| s.cdr())
                    .map(AsRef::as_ref),
            ),
        ];

        // Note: Cluster health is checked asynchronously via check_health_async
        // This synchronous version returns static component status
        #[cfg(feature = "cluster")]
        if self.cluster_health_fn.is_some() {
            components.push(ComponentStatus::healthy("cluster"));
        }

        SystemHealth::from_components(components)
            .with_uptime(self.uptime_secs())
            .with_version(&self.version)
    }

    /// Performs an async health check that includes cluster health.
    #[cfg(feature = "cluster")]
    pub async fn check_health_async(&self) -> SystemHealth {
        let mut components = vec![
            ComponentStatus::healthy("sbc_core"),
            ComponentStatus::healthy("sip_transport"),
            ComponentStatus::healthy("media_engine"),
            audit_component_status(),
            cdr_component_status(
                self.sip_stack
                    .as_ref()
                    .and_then(|s| s.cdr())
                    .map(AsRef::as_ref),
            ),
        ];

        // Check cluster health if configured
        if let Some(ref health_fn) = self.cluster_health_fn {
            let cluster_health = health_fn().await;
            let cluster_status = if cluster_health.healthy {
                ComponentStatus::healthy("cluster")
            } else {
                ComponentStatus::unhealthy("cluster", "Cluster health check failed")
            };
            components.push(cluster_status);

            // Add individual cluster components
            if cluster_health.storage_healthy {
                components.push(ComponentStatus::healthy("cluster_storage"));
            } else {
                components.push(ComponentStatus::unhealthy(
                    "cluster_storage",
                    "Storage backend unhealthy",
                ));
            }
            if cluster_health.discovery_healthy {
                components.push(ComponentStatus::healthy("cluster_discovery"));
            } else {
                components.push(ComponentStatus::unhealthy(
                    "cluster_discovery",
                    "Discovery service unhealthy",
                ));
            }
        }

        SystemHealth::from_components(components)
            .with_uptime(self.uptime_secs())
            .with_version(&self.version)
    }
}

/// API server.
pub struct ApiServer {
    /// Configuration.
    config: ApiServerConfig,
    /// Application state.
    state: Arc<AppState>,
    /// Shutdown signal.
    shutdown: ShutdownSignal,
}

impl ApiServer {
    /// Creates a new API server.
    pub const fn new(
        config: ApiServerConfig,
        state: Arc<AppState>,
        shutdown: ShutdownSignal,
    ) -> Self {
        Self {
            config,
            state,
            shutdown,
        }
    }

    /// Builds the router with all routes.
    ///
    /// As of PR8 the daemon's REST surface has shrunk to just the
    /// endpoints sbc-api still HTTP-proxies (because no gRPC equivalent
    /// exists yet) plus its own kubelet probes:
    ///
    /// - Health probes (`/healthz`, `/readyz`) — daemon pod's liveness.
    /// - (`/cdrs` moved to sbc-api over the gRPC `CdrService`.)
    /// - `/dialplans` and `/dialplans/{id}/entries` (GET only) — read-
    ///   only views of the SIP router's current dial-plan state. The
    ///   write endpoints moved to sbc-api in PR3+PR5.
    ///
    /// Everything else — phone/DID/trunk-group CRUD, dial-plan entry
    /// writes, calls/registrations reads, system stats/metrics/version/
    /// tls, the entire `/provision/*` surface, and the formerly-embedded
    /// dashboard — is now served by sbc-api, sbc-provision, or sbc-
    /// frontend, and has been removed from this router.
    pub fn router(&self) -> Router {
        let api_routes = Router::new()
            .route("/dialplans", get(get_dial_plans))
            .route("/dialplans/{plan_id}/entries", get(get_dial_plan_entries))
            .layer(axum::middleware::from_fn(api_auth_middleware));

        Router::new()
            // Kubelet probes — the daemon pod's own liveness/readiness.
            .route("/healthz", get(liveness_probe))
            .route("/readyz", get(readiness_probe))
            // API v1 routes
            .nest(&format!("/api/{}", self.config.api_version), api_routes)
            // Add state
            .with_state(Arc::clone(&self.state))
            // Add tracing
            .layer(TraceLayer::new_for_http())
    }

    /// Runs the API server. The combination of `listen_addr`, `tls_listen_addr`,
    /// and `tls` decides the topology:
    ///
    /// - `tls` set + `tls_listen_addr` set → HTTP on `listen_addr`, HTTPS on
    ///   `tls_listen_addr`, both run concurrently.
    /// - `tls` set + `tls_listen_addr` None → HTTPS on `listen_addr` (legacy).
    /// - `tls` None → plain HTTP on `listen_addr`.
    pub async fn run(&self) -> Result<(), ApiServerError> {
        match (&self.config.tls, self.config.tls_listen_addr) {
            (Some(tls_config), Some(tls_addr)) => {
                let http_addr = self.config.listen_addr;
                tokio::try_join!(
                    self.run_http(http_addr),
                    self.run_https(tls_config, tls_addr)
                )
                .map(|_| ())
            }
            (Some(tls_config), None) => self.run_https(tls_config, self.config.listen_addr).await,
            (None, _) => self.run_http(self.config.listen_addr).await,
        }
    }

    /// Runs the API server with plain HTTP on `addr`.
    // POAM: POA&M-212 — the plain-HTTP listener (axum::serve) has no
    // connection cap or header-read timeout (SC-5); bound to the pod network
    // behind NetworkPolicy in k8s.
    async fn run_http(&self, addr: SocketAddr) -> Result<(), ApiServerError> {
        let router = self.router();

        info!(address = %addr, tls = false, "Starting API server (HTTP)");

        let listener =
            tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| ApiServerError::BindFailed {
                    address: addr.to_string(),
                    reason: e.to_string(),
                })?;

        let shutdown = self.shutdown.clone();

        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                shutdown.wait_for_shutdown().await;
                info!("API server shutting down");
            })
            .await
            .map_err(|e| ApiServerError::ServerError {
                reason: e.to_string(),
            })?;

        Ok(())
    }

    /// Runs the API server with HTTPS (TLS) on `addr`.
    ///
    /// Always serves through the [`ReloadableTlsAcceptor`] installed in
    /// [`AppState::tls_acceptor`] (CNSA 2.0 provider, TLS 1.3 only, PR 177
    /// fail-closed key-file checks); there is no static fallback.
    ///
    /// ## NIST 800-53 Rev5: SC-8 (Transmission Confidentiality), SC-13, SC-5
    async fn run_https(
        &self,
        tls_config: &TlsConfig,
        addr: SocketAddr,
    ) -> Result<(), ApiServerError> {
        // Fail closed: TLS was configured, so never serve without the
        // CNSA acceptor built at startup.
        let Some(reloadable) = self.state.tls_acceptor.clone() else {
            return Err(ApiServerError::TlsError {
                reason: "HTTPS configured but no TLS acceptor installed".to_string(),
            });
        };
        let router = self.router();

        info!(
            address = %addr,
            cert = %tls_config.cert_path.display(),
            tls = true,
            max_connections = self.config.max_tls_connections,
            "Starting API server (HTTPS)"
        );

        let listener =
            tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| ApiServerError::BindFailed {
                    address: addr.to_string(),
                    reason: e.to_string(),
                })?;

        Self::spawn_tls_reload_watcher(
            Arc::clone(&reloadable),
            Arc::clone(&self.state),
            self.shutdown.clone(),
            self.config.tls_reload_poll,
        );

        let shutdown = self.shutdown.clone();
        let permits = Arc::new(tokio::sync::Semaphore::new(self.config.max_tls_connections));
        let handshake_timeout = self.config.tls_handshake_timeout;
        let idle_timeout = self.config.tls_idle_timeout;
        let max_age = self.config.max_tls_connection_age;
        // Resolved once; the shed path does no per-connection lookup.
        let rejected_counter = self.state.metrics.counter(METRIC_API_TLS_CONN_REJECTED);

        loop {
            tokio::select! {
                result = listener.accept() => {
                    let stream = match result {
                        Ok((stream, _peer_addr)) => stream,
                        Err(e) => {
                            warn!(error = %e, "Failed to accept connection");
                            continue;
                        }
                    };
                    // NIST 800-53 Rev5: SC-5 — shed immediately when full;
                    // never await a permit so the accept loop cannot stall.
                    let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                        drop(stream);
                        if let Some(c) = rejected_counter {
                            c.inc();
                        }
                        debug!("REST HTTPS connection cap reached; connection dropped");
                        continue;
                    };
                    let acceptor = reloadable.acceptor_arc();
                    let mut service = router.clone().into_make_service();
                    let state = Arc::clone(&self.state);

                    tokio::spawn(async move {
                        // Held for the whole connection (handshake + serving).
                        let _permit = permit;
                        let tls_stream = match tokio::time::timeout(
                            handshake_timeout,
                            acceptor.accept(stream),
                        )
                        .await
                        {
                            Ok(Ok(s)) => s,
                            Ok(Err(e)) => {
                                debug!(error = %e, "TLS handshake failed");
                                return;
                            }
                            Err(_) => {
                                if let Some(c) =
                                    state.metrics.counter(METRIC_API_TLS_HANDSHAKE_TIMEOUTS)
                                {
                                    c.inc();
                                }
                                debug!("TLS handshake timed out");
                                return;
                            }
                        };
                        let io = TokioIo::new(tls_stream);
                        let svc = match service.call(()).await {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(error = ?e, "Failed to create service");
                                return;
                            }
                        };
                        let hyper_svc = TowerToHyperService::new(svc);
                        // NIST 800-53 Rev5: SC-5 — HTTP/1 only. h2 (prior
                        // knowledge; no ALPN is offered) would let an idle
                        // client hold a permit with no header-read deadline.
                        let mut builder =
                            ServerBuilder::new(hyper_util::rt::TokioExecutor::new())
                                .http1_only();
                        builder
                            .http1()
                            .timer(hyper_util::rt::TokioTimer::new())
                            .header_read_timeout(idle_timeout);
                        let conn = builder.serve_connection(io, hyper_svc);
                        tokio::pin!(conn);
                        // NIST 800-53 Rev5: SC-10 — bound connection lifetime
                        // so slow bodies / slow readers cannot pin a permit.
                        let result = tokio::select! {
                            r = conn.as_mut() => r,
                            () = tokio::time::sleep(max_age) => {
                                conn.as_mut().graceful_shutdown();
                                tokio::time::timeout(API_CONN_DRAIN_GRACE, conn)
                                    .await
                                    .unwrap_or_else(|_| {
                                        debug!("HTTPS connection force-closed after max age");
                                        Ok(())
                                    })
                            }
                        };
                        if let Err(e) = result {
                            debug!(error = %e, "Error serving HTTPS connection");
                        }
                    });
                }
                () = shutdown.wait_for_shutdown() => {
                    info!("API server (HTTPS) shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Builds the REST HTTPS acceptor at startup (fail closed).
    ///
    /// Reuses `uc_transport` cert loading: `load_private_key_checked`
    /// (PR 177 mode/owner/symlink checks), the `security.curve` key-curve
    /// match, and `create_server_config` (CNSA 2.0 provider, TLS 1.3 only).
    /// The REST plane is TLS 1.3 only regardless of `security.min_tls_version`.
    ///
    /// ## NIST 800-53 Rev5: SC-12, SC-13, SC-28
    ///
    /// # Errors
    ///
    /// Returns [`ApiServerError::TlsError`] if the certificate or key cannot be
    /// loaded or fails a check.
    pub fn build_tls_acceptor(
        tls_config: &TlsConfig,
        curve: CnsaCurve,
    ) -> Result<Arc<ReloadableTlsAcceptor>, ApiServerError> {
        let required = match curve {
            CnsaCurve::P384 => RequiredKeyCurve::P384,
            CnsaCurve::P521 => RequiredKeyCurve::P521,
        };
        ReloadableTlsAcceptor::new_with_curve(
            tls_config.cert_path.clone(),
            tls_config.key_path.clone(),
            Some(required),
        )
        .map(Arc::new)
        .map_err(|e| ApiServerError::TlsError {
            reason: format!("Failed to create TLS acceptor: {e}"),
        })
    }

    /// Spawns a watcher that reloads the REST certificate when the cert or
    /// key file changes (mtime/length), e.g. cert-manager or Secret-volume
    /// rotation. A failed reload keeps the previous certificate in service.
    ///
    /// ## NIST 800-53 Rev5: SC-17 (Public Key Infrastructure Certificates)
    // POAM: POA&M-214 — REST TLS reloads are logged via tracing only; no
    // uc-audit record is emitted yet (AU-12).
    pub fn spawn_tls_reload_watcher(
        acceptor: Arc<ReloadableTlsAcceptor>,
        state: Arc<AppState>,
        shutdown: ShutdownSignal,
        poll: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut last = tls_files_fingerprint(&acceptor).await;
            let mut ticker = tokio::time::interval(poll);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = ticker.tick() => {}
                    () = shutdown.wait_for_shutdown() => break,
                }
                let current = tls_files_fingerprint(&acceptor).await;
                if current == last {
                    continue;
                }
                last = current;
                // File I/O + key parsing: keep it off the runtime workers.
                let reloader = Arc::clone(&acceptor);
                let ok = tokio::task::spawn_blocking(move || reloader.try_reload())
                    .await
                    .unwrap_or(false);
                let name = if ok {
                    METRIC_API_TLS_RELOADS
                } else {
                    METRIC_API_TLS_RELOAD_FAILURES
                };
                if let Some(c) = state.metrics.counter(name) {
                    c.inc();
                }
            }
        })
    }
}

/// `(mtime, len)` of the cert and key files; `None` entries on stat failure.
type TlsFileFingerprint = [Option<(std::time::SystemTime, u64)>; 2];

async fn tls_files_fingerprint(acceptor: &ReloadableTlsAcceptor) -> TlsFileFingerprint {
    async fn stat(p: &std::path::Path) -> Option<(std::time::SystemTime, u64)> {
        let m = tokio::fs::metadata(p).await.ok()?;
        Some((m.modified().ok()?, m.len()))
    }
    [
        stat(acceptor.cert_path()).await,
        stat(acceptor.key_path()).await,
    ]
}

// ============================================================================
// Health Probes
// ============================================================================

/// Liveness probe handler.
///
/// Returns 200 OK if the server is alive.
async fn liveness_probe() -> impl IntoResponse {
    Json(LivenessResponse { alive: true })
}

/// Readiness probe handler.
///
/// Returns 200 OK if the server is ready to accept traffic.
async fn readiness_probe(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let is_ready = state.is_ready();

    let response = ReadinessResponse {
        ready: is_ready,
        status: if is_ready { "ok" } else { "not_ready" }.to_string(),
    };

    if is_ready {
        (StatusCode::OK, Json(response))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(response))
    }
}

// ============================================================================
// (System / Call / Registration / DID / Dial-plan-write / Trunk-group /
// Phone / Provisioning / TLS handlers removed in PR8.) The daemon's REST
// surface is now just the endpoints listed in `router()` above — these
// dead handlers were left compiled-but-unused when 736af59 stripped the
// routes; this commit removes their bodies entirely. The SIP-stack sync
// helpers (`sync_trunk_group_to_router`, `sync_dial_plan_to_router`,
// `start_trunk_services`) are kept further down because runtime.rs and
// the gRPC sync services still call into them.
// ============================================================================

// ============================================================================
// Call Ladder Routes
// ============================================================================

// ============================================================================
// Dial Plan Routes
// ============================================================================

/// List dial plans.
async fn get_dial_plans(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(ref stack) = state.sip_stack {
        let plans = stack.list_dial_plans().await;
        Json(serde_json::json!({ "dial_plans": plans }))
    } else {
        Json(serde_json::json!({ "dial_plans": [] }))
    }
}

/// Get entries for a dial plan.
async fn get_dial_plan_entries(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(plan_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if let Some(ref stack) = state.sip_stack {
        let entries = stack.list_dial_plan_entries(&plan_id).await;
        Json(serde_json::json!({ "plan_id": plan_id, "entries": entries }))
    } else {
        Json(serde_json::json!({ "plan_id": plan_id, "entries": [] }))
    }
}

// ============================================================================
// Trunk Group Routes
// ============================================================================

/// Start OPTIONS monitoring and/or SIP registration for a trunk if enabled.
///
/// Still public — called by `runtime.rs` startup replay and (indirectly)
/// by the gRPC TrunkSyncService when sbc-api notifies the daemon of a
/// trunk change. The REST handler that used to wrap this got moved to
/// sbc-api / removed in PR8.
pub fn start_trunk_services(state: &Arc<AppState>, trunk: &serde_json::Value) {
    let trunk_id = trunk.get("id").and_then(|v| v.as_str()).unwrap_or_default();
    let host = trunk
        .get("host")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    if trunk_id.is_empty() || host.is_empty() {
        return;
    }
    let Some(port) = trunk_json_port(trunk) else {
        tracing::warn!(
            trunk_id,
            "Not starting trunk services: invalid protocol or port"
        );
        return;
    };

    // Resolve zone IPs for binding and Contact header.
    // The trunk's "zone" field specifies which interface to bind to.
    // Falls back to "outside", then "inside".
    let zone_name = trunk
        .get("zone")
        .and_then(|v| v.as_str())
        .unwrap_or("outside");
    let (bind_ip, external_ip) = state.zone_registry.as_ref().map_or((None, None), |zr| {
        let ip = zr
            .signaling_ip(zone_name)
            .or_else(|| zr.signaling_ip("outside"))
            .or_else(|| zr.signaling_ip("inside"));
        let ext = zr.external_ip(zone_name);
        (ip, ext)
    });

    // Start OPTIONS health monitoring
    if trunk
        .get("options_ping_enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        && let Some(ref monitor) = state.trunk_monitor
    {
        let interval = trunk
            .get("options_ping_interval")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(30) as u32;
        monitor.monitor_trunk(crate::trunk_monitor::MonitoredTrunk {
            trunk_id: trunk_id.to_string(),
            host: host.to_string(),
            port,
            interval_secs: interval,
            bind_ip,
        });
        tracing::info!(trunk_id, ?bind_ip, "Started OPTIONS health monitor via API");
    }

    // Start SIP registration
    if trunk
        .get("register_enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        let username = trunk
            .get("sip_username")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let password = trunk
            .get("sip_password")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !username.is_empty()
            && !password.is_empty()
            && let Some(ref registrar) = state.trunk_registrar
        {
            let domain = trunk
                .get("sip_domain")
                .and_then(|v| v.as_str())
                .unwrap_or(host);
            let expires = trunk
                .get("register_expires")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(25) as u32;
            // NIST 800-53 Rev5: CM-6, SI-10 — POA&M-255 MD5 policy; a non-bool
            // stored value refuses MD5 (fail closed).
            let (allow_md5_digest, md5_err) =
                sbc_config_store::trunk_allow_md5_digest_or_refuse(trunk);
            if let Some(e) = md5_err {
                tracing::warn!(trunk_id = %trunk_id, error = %e, "Invalid allow_md5_digest; refusing MD5");
            }
            tracing::info!(
                trunk_id,
                ?bind_ip,
                ?external_ip,
                expires,
                "Starting trunk registration with zone IPs"
            );
            registrar.register_trunk(crate::trunk_registrar::TrunkRegConfig {
                trunk_id: trunk_id.to_string(),
                host: host.to_string(),
                port,
                username: username.to_string(),
                password: password.to_string(),
                domain: domain.to_string(),
                expires,
                bind_ip,
                external_ip,
                allow_md5_digest,
            });
            tracing::info!(trunk_id, "Started SIP registration via API");
        }
    }
}

/// Port of a trunk JSON body: the `port` field, else the transport's
/// default (5061 for TLS, 5060 otherwise; RFC 3261 §19.1.2). `None` for an
/// unknown protocol or a port outside `1..=65535` (never truncated).
///
/// ## NIST 800-53 Rev5: SI-10 (Information Input Validation)
fn trunk_json_port(trunk: &serde_json::Value) -> Option<u16> {
    use sbc_config_store::trunk_policy::{trunk_port, trunk_transport};
    let transport = trunk_transport(trunk).ok()?;
    trunk_port(trunk, transport).ok()
}

/// Builds a router trunk group from a MemStore / config-store JSON body
/// (API, TrunkSync, central config). `None` when the body has no `id`.
///
/// ## NIST 800-53 Rev5: SC-8 (POA&M-48)
///
/// - `require_tls`: a JSON bool is used as-is, absent means `false`, any
///   other type means `true` (fail closed) plus a warning.
/// - Trunk `protocol` (falling back to `transport`) is honoured: `udp`,
///   `tcp`, `tls`; absent means `udp`. An unknown value skips the trunk with
///   a warning; it never silently becomes UDP.
/// - Trunk `port`: absent means 5061 for TLS, 5060 otherwise; outside
///   `1..=65535` skips the trunk with a warning.
pub fn trunk_group_from_json(group_json: &serde_json::Value) -> Option<uc_routing::TrunkGroup> {
    trunk_group_from_json_admitted(group_json, |_, raw| {
        Ok(u32::try_from(raw).unwrap_or(u32::MAX))
    })
    .ok()
    .flatten()
}

/// [`trunk_group_from_json`] with each trunk's `max_calls` mapped through
/// `max_calls` (this node's `cluster.admission` share). `Err` when any
/// trunk's cap is rejected; nothing is built.
///
/// ## NIST 800-53 Rev5: SC-5, CM-6 — API trunks get the same per-node
/// share as config-file trunks (POA&M-1).
fn trunk_group_from_json_admitted(
    group_json: &serde_json::Value,
    max_calls: impl Fn(&str, u64) -> Result<u32, String>,
) -> Result<Option<uc_routing::TrunkGroup>, String> {
    use sbc_config_store::trunk_policy::{TrunkTransport, group_require_tls, trunk_transport};

    let id = group_json
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let name = group_json
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(id);
    if id.is_empty() {
        return Ok(None);
    }

    let require_tls = group_require_tls(group_json).unwrap_or_else(|e| {
        tracing::warn!(trunk_group = id, error = %e, "require_tls is not a boolean; enforcing TLS-only (fail closed)");
        true
    });
    let mut group = uc_routing::TrunkGroup::new(id, name).with_require_tls(require_tls);

    if let Some(trunks) = group_json.get("trunks").and_then(|v| v.as_array()) {
        for t in trunks {
            let trunk_id = t.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            let host = t.get("host").and_then(|v| v.as_str()).unwrap_or_default();
            if trunk_id.is_empty() || host.is_empty() {
                continue;
            }
            // NIST 800-53 Rev5: SC-8 — the trunk's own transport, never a
            // hard-coded UDP (RFC 3261 §26.2: TLS where configured).
            let protocol = match trunk_transport(t) {
                Ok(TrunkTransport::Udp) => uc_routing::TrunkProtocol::Udp,
                Ok(TrunkTransport::Tcp) => uc_routing::TrunkProtocol::Tcp,
                Ok(TrunkTransport::Tls) => uc_routing::TrunkProtocol::Tls,
                Err(e) => {
                    tracing::warn!(trunk_group = id, trunk_id, error = %e, "Skipping trunk with invalid protocol");
                    continue;
                }
            };
            // RFC 3261 §19.1.2: default port follows the transport (5061 for
            // TLS); an out-of-range port skips the trunk, never truncated.
            let Some(port) = trunk_json_port(t) else {
                tracing::warn!(
                    trunk_group = id,
                    trunk_id,
                    "Skipping trunk with invalid port"
                );
                continue;
            };
            let is_tls = protocol == uc_routing::TrunkProtocol::Tls;
            // NIST 800-53 Rev5: SC-23; RFC 5922 §7 — TLS settings apply to TLS
            // trunks only. An empty name verifies against `host`.
            let tls_server_name = t
                .get("tls_server_name")
                .and_then(|v| v.as_str())
                .filter(|n| is_tls && !n.is_empty())
                .map(String::from);
            let tls_client_cert = is_tls
                && t.get("tls_client_cert")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);

            // NIST 800-53 Rev5: SC-5 — this node's share of the trunk cap.
            let max_calls = max_calls(
                trunk_id,
                t.get("max_calls")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(100),
            )?;
            let trunk_config = uc_routing::TrunkConfig {
                id: trunk_id.to_string(),
                name: trunk_id.to_string(),
                host: host.to_string(),
                port,
                protocol,
                priority: t
                    .get("priority")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(1) as u32,
                weight: t
                    .get("weight")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(100) as u32,
                max_calls,
                // Default emergency headroom (10% of max_calls, min 1).
                emergency_reserve_calls: None,
                cooldown_secs: t
                    .get("cooldown_seconds")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(30),
                max_failures: t
                    .get("max_failures")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(5) as u32,
                outbound_enabled: true,
                inbound_enabled: true,
                tls_server_name,
                tls_client_cert,
            };
            group.add_trunk(uc_routing::Trunk::new(trunk_config));
        }
    }
    Ok(Some(group))
}

/// True when `group` has a TLS trunk but no trunk CA bundle is configured.
fn tls_trunk_without_ca(group: &uc_routing::TrunkGroup, ca_configured: bool) -> bool {
    !ca_configured && group.non_tls_count() as usize != group.trunk_count()
}

/// Syncs a trunk group from MemStore JSON to the SipStack router.
///
/// Returns `Err` (nothing is installed) when a trunk `max_calls` is
/// invalid for this node's `cluster.admission` split.
pub async fn sync_trunk_group_to_router(
    state: &Arc<AppState>,
    group_json: &serde_json::Value,
) -> Result<(), String> {
    let Some(ref sip_stack) = state.sip_stack else {
        return Ok(());
    };
    let Some(group) = trunk_group_from_json_admitted(group_json, |id, raw| {
        sip_stack.api_trunk_max_calls(id, raw)
    })?
    else {
        return Ok(());
    };
    let id = group.id().to_string();
    let id = id.as_str();
    if tls_trunk_without_ca(&group, sip_stack.trunk_tls_ca_configured()) {
        // NIST 800-53 Rev5: SC-8, SI-4 — the TLS trunk fails closed (no
        // trust anchors), so calls on it are refused; flag it loudly.
        tracing::error!(
            trunk_group = id,
            "TLS trunk synced but security.trunk_tls_ca_path is not set; TLS connections to it will fail"
        );
    }

    sip_stack.add_trunk_group_to_router(group).await;

    // Register inbound trunk mapping (source IP → trunk group + CSS)
    let css_id = group_json.get("css_id").and_then(|v| v.as_str());
    let hosts: Vec<(String, u16)> = group_json
        .get("trunks")
        .and_then(|v| v.as_array())
        .map(|trunks| {
            trunks
                .iter()
                .filter_map(|t| {
                    let h = t.get("host").and_then(|v| v.as_str())?;
                    let p = trunk_json_port(t)?;
                    Some((h.to_string(), p))
                })
                .collect()
        })
        .unwrap_or_default();
    if !hosts.is_empty() {
        sip_stack.register_inbound_trunk(id, css_id, &hosts).await;
    }

    tracing::info!(trunk_group = id, css = ?css_id, "Synced trunk group to SIP stack router");
    Ok(())
}

/// Builds a router `DialPlan` from the JSON entries of an API dial plan.
fn dial_plan_from_entries(plan_id: &str, entries: &[serde_json::Value]) -> uc_routing::DialPlan {
    let mut plan = uc_routing::DialPlan::new(plan_id, plan_id);
    for (idx, entry) in entries.iter().enumerate() {
        let trunk_group = entry
            .get("trunk_group_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let pattern_value = entry
            .get("pattern")
            .or_else(|| entry.get("pattern_value"))
            .and_then(|v| v.as_str())
            .unwrap_or(".*");
        let pattern_type = entry
            .get("pattern_type")
            .and_then(|v| v.as_str())
            .unwrap_or("prefix");
        let priority = entry
            .get("priority")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(1) as u32;

        // Same pattern_type vocabulary as config dial plans and route patterns.
        // An absent pattern or the legacy ".*" default stays a catch-all.
        let pattern = if matches!(pattern_value, ".*" | "*" | "") {
            uc_routing::DialPattern::Any
        } else {
            match uc_routing::DialPattern::from_kind(pattern_type, pattern_value) {
                Ok(p) => p,
                Err(e) => {
                    // NIST 800-53 Rev5: SI-10 — skip, never a silent prefix.
                    tracing::warn!(plan = plan_id, entry = idx, error = %e, "Dial plan entry skipped");
                    continue;
                }
            }
        };
        let entry_id = format!("{plan_id}-{idx}");
        let dp_entry =
            uc_routing::DialPlanEntry::new(entry_id, pattern, trunk_group).with_priority(priority);
        plan.add_entry(dp_entry);
    }
    plan
}

/// Syncs a dial plan entry to the SipStack router.
pub async fn sync_dial_plan_to_router(
    state: &Arc<AppState>,
    plan_id: &str,
    entries: &[serde_json::Value],
) {
    let Some(ref sip_stack) = state.sip_stack else {
        return;
    };

    let plan = dial_plan_from_entries(plan_id, entries);

    sip_stack.add_dial_plan_to_router(plan).await;
    tracing::info!(
        plan_id,
        entries = entries.len(),
        "Synced dial plan to SIP stack router"
    );
}

/// Apply a JSON partition body to the live `SbcRouter`. Used by both
/// the boot-time replay (when `sbc_router` is `Some`) and the gRPC
/// `SbcSyncService.SyncPartition` handler. Idempotent: `add_partition`
/// upserts by ID.
pub async fn apply_partition_to_router(state: &Arc<AppState>, body: &serde_json::Value) {
    let Some(ref router) = state.sbc_router else {
        return;
    };
    let Some(id) = body.get("id").and_then(|v| v.as_str()) else {
        return;
    };
    if id.is_empty() {
        return;
    }
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or(id);
    let mut p = uc_routing::Partition::new(id, name);
    if let Some(desc) = body.get("description").and_then(|v| v.as_str())
        && !desc.is_empty()
    {
        p = p.with_description(desc);
    }
    router.write().await.add_partition(p);
}

/// Apply a JSON CSS body. `partitions` is an array of partition-ID
/// strings; ordering is preserved (SBC CSS lookup is ordered).
pub async fn apply_css_to_router(state: &Arc<AppState>, body: &serde_json::Value) {
    let Some(ref router) = state.sbc_router else {
        return;
    };
    let Some(id) = body.get("id").and_then(|v| v.as_str()) else {
        return;
    };
    if id.is_empty() {
        return;
    }
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or(id);
    let mut css = uc_routing::CallingSearchSpace::new(id, name);
    if let Some(arr) = body.get("partitions").and_then(|v| v.as_array()) {
        for pid in arr.iter().filter_map(|v| v.as_str()) {
            css.add_partition(pid);
        }
    }
    let mut router = router.write().await;
    // CSS has no upsert-by-id; remove-then-add gives the same shape.
    router.remove_css(id);
    router.add_css(css);
}

/// Apply a JSON route-pattern body. `pattern_type` chooses the
/// `DialPattern` variant (absent = `prefix`); an unknown value is
/// rejected and the previous pattern kept.
pub async fn apply_route_pattern_to_router(state: &Arc<AppState>, body: &serde_json::Value) {
    let Some(ref router) = state.sbc_router else {
        return;
    };
    let Some(id) = body.get("id").and_then(|v| v.as_str()) else {
        return;
    };
    if id.is_empty() {
        return;
    }
    let partition = body
        .get("partition_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let pattern_value = body.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
    let pattern_type = body
        .get("pattern_type")
        .and_then(|v| v.as_str())
        .unwrap_or("prefix");
    // NIST 800-53 Rev5: SI-10, CM-6 — an unknown kind keeps the previous
    // pattern instead of installing a silent prefix route.
    let pattern = match uc_routing::DialPattern::from_kind(pattern_type, pattern_value) {
        Ok(p) => p,
        Err(e) => {
            crate::sip_stack::ROUTE_PATTERN_REJECTED
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(id, error = %e, "Route pattern sync rejected; previous pattern kept");
            return;
        }
    };
    let mut rp = uc_routing::RoutePattern::new(id, pattern, partition);
    if let Some(rl) = body.get("route_list_id").and_then(|v| v.as_str())
        && !rl.is_empty()
    {
        rp = rp.with_route_list(rl);
    }
    if let Some(rg) = body.get("route_group_id").and_then(|v| v.as_str())
        && !rg.is_empty()
    {
        rp = rp.with_route_group(rg);
    }
    if let Some(desc) = body.get("description").and_then(|v| v.as_str())
        && !desc.is_empty()
    {
        rp = rp.with_description(desc);
    }
    if let Some(p) = body.get("priority").and_then(serde_json::Value::as_u64) {
        rp = rp.with_priority(p as u32);
    }
    if body
        .get("blocked")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        rp = rp.with_block(true);
    }
    rp = rp.with_transform(number_transform_from_json(body));
    let mut router = router.write().await;
    router.remove_route_pattern(id);
    router.add_route_pattern(rp);
}

/// Reads a route pattern's digit manipulation from its JSON document.
///
/// Uses the same spelling as dial-plan entries (`sbc-config`
/// `DialPlanEntryConfig`): `transform_type` is one of `none` (default),
/// `strip_prefix` (`transform_value` = digit count), `add_prefix`
/// (`transform_value` = digits to prepend), `replace_prefix`
/// (`transform_value` = `"from|to"`) or `replace` (`transform_value` = the
/// whole replacement number). Anything malformed yields `None`, so a bad
/// document never changes the dialled digits silently.
fn number_transform_from_json(body: &serde_json::Value) -> uc_routing::NumberTransform {
    use uc_routing::NumberTransform;
    let kind = body
        .get("transform_type")
        .and_then(|v| v.as_str())
        .unwrap_or("none");
    let value = body
        .get("transform_value")
        .map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default();
    match kind {
        "strip_prefix" => value
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
            .map_or(NumberTransform::None, NumberTransform::strip_prefix),
        "add_prefix" if !value.is_empty() => NumberTransform::add_prefix(&value),
        "replace_prefix" => match value.split_once('|') {
            Some((from, to)) if !from.is_empty() => NumberTransform::replace_prefix(from, to),
            _ => NumberTransform::None,
        },
        "replace" if !value.is_empty() => NumberTransform::Replace { number: value },
        _ => NumberTransform::None,
    }
}

/// Apply a JSON route-list body, including its ordered members.
///
/// Body shape:
/// ```json
/// {
///   "id": "rl-us",
///   "name": "US PSTN",
///   "description": "optional",
///   "members": [
///     {"route_group_id": "rg-bulkvs", "priority": 1},
///     {"route_group_id": "rg-backup", "priority": 2}
///   ]
/// }
/// ```
///
/// `priority` is optional and defaults to `members.len()` (i.e., the
/// array order doubles as the priority when callers don't care).
/// Per-member digit transforms aren't wired here yet; add them when a
/// dashboard caller needs them.
pub async fn apply_route_list_to_router(state: &Arc<AppState>, body: &serde_json::Value) {
    let Some(ref router) = state.sbc_router else {
        return;
    };
    let Some(id) = body.get("id").and_then(|v| v.as_str()) else {
        return;
    };
    if id.is_empty() {
        return;
    }
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or(id);
    let mut rl = uc_routing::RouteList::new(id, name);
    if let Some(desc) = body.get("description").and_then(|v| v.as_str())
        && !desc.is_empty()
    {
        rl = rl.with_description(desc);
    }
    if let Some(members) = body.get("members").and_then(|v| v.as_array()) {
        for (idx, m) in members.iter().enumerate() {
            let Some(rg_id) = m.get("route_group_id").and_then(|v| v.as_str()) else {
                continue;
            };
            if rg_id.is_empty() {
                continue;
            }
            let priority = m
                .get("priority")
                .and_then(serde_json::Value::as_u64)
                .map_or((idx + 1) as u32, |p| p as u32);
            rl.add_member(uc_routing::RouteListMember::new(rg_id, priority));
        }
    }
    let mut router = router.write().await;
    router.remove_route_list(id);
    router.add_route_list(rl);
}

// ============================================================================
// (Trunk health + registration REST handlers removed in PR9 — sbc-api
// now calls the daemon's TrunkHealthService gRPC.)
// ============================================================================

// ============================================================================
// (User Management handlers removed in PR10 — sbc-api owns /users CRUD
// through EncryptedUserStore<PostgresUserStore>; the daemon does not read
// the users table.)
// (Phone Management + Phone Provisioning handlers removed in PR8 —
// sbc-api owns phone CRUD; sbc-provision owns /provision/<MAC>.{cfg,xml}.)
// ============================================================================

// ============================================================================
// (SBC routing handlers removed in PR11 — sbc-api owns Postgres-
// backed CRUD for partitions, CSS, route patterns, and route lists;
// it notifies the daemon via SbcSyncService gRPC so the live
// SbcRouter catches up without a daemon restart.)
// ============================================================================

// ============================================================================
// (TLS handlers removed in PR8 — sbc-api now reaches the daemon's
// SystemService.GetTlsStatus / ReloadTls gRPC instead of REST.)
// ============================================================================

// ============================================================================
// Response Types
// ============================================================================

/// Liveness probe response.
#[derive(Debug, Serialize, Deserialize)]
pub struct LivenessResponse {
    /// Whether the server is alive.
    pub alive: bool,
}

/// Readiness probe response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ReadinessResponse {
    /// Whether the server is ready.
    pub ready: bool,
    /// Status message.
    pub status: String,
}

/// TLS certificate reload statistics. Still used by the daemon's gRPC
/// `SystemService.GetTlsStatus` / `ReloadTls` impls (the REST wrappers
/// were removed in PR8); kept here because `AppState::tls_stats()`
/// returns it.
#[derive(Debug, Serialize, Deserialize)]
pub struct TlsReloadStats {
    /// Number of successful certificate reloads.
    pub reload_count: u64,
    /// Unix timestamp of the last reload.
    pub last_reload_timestamp: u64,
    /// Path to the certificate file.
    pub cert_path: String,
    /// Path to the private key file.
    pub key_path: String,
}

// ============================================================================
// Errors
// ============================================================================

/// API server error.
#[derive(Debug)]
pub enum ApiServerError {
    /// Failed to bind to address.
    BindFailed {
        /// Address.
        address: String,
        /// Reason.
        reason: String,
    },
    /// Server error.
    ServerError {
        /// Reason.
        reason: String,
    },
    /// TLS configuration error.
    TlsError {
        /// Reason.
        reason: String,
    },
}

impl std::fmt::Display for ApiServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BindFailed { address, reason } => {
                write!(f, "Failed to bind to {address}: {reason}")
            }
            Self::ServerError { reason } => {
                write!(f, "Server error: {reason}")
            }
            Self::TlsError { reason } => {
                write!(f, "TLS error: {reason}")
            }
        }
    }
}

impl std::error::Error for ApiServerError {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;
    use uc_metrics::SbcMetrics;

    fn test_state() -> Arc<AppState> {
        let metrics = SbcMetrics::standard();
        let stats = Arc::new(ServerStats::default());
        Arc::new(AppState::new(metrics, stats))
    }

    async fn divided_state(n: u32) -> Arc<AppState> {
        let mut stack = crate::sip_stack::SipStack::new(crate::sip_stack::SipStackConfig {
            admission_divisor: n,
            ..crate::sip_stack::SipStackConfig::default()
        });
        stack.ensure_router().await;
        let mut state = AppState::new(SbcMetrics::standard(), Arc::new(ServerStats::default()));
        state.sip_stack = Some(Arc::new(stack));
        Arc::new(state)
    }

    async fn api_trunk_cap(state: &Arc<AppState>, group: &str, trunk: &str) -> Option<u32> {
        let stack = state.sip_stack.as_ref()?;
        let router = stack.router()?.read().await;
        router
            .get_trunk_group(group)
            .and_then(|g| g.get_trunk(trunk))
            .map(|t| t.config().max_calls)
    }

    #[tokio::test]
    async fn api_trunk_gets_cluster_share() {
        // NIST 800-53 Rev5: SC-5 — SEC-001: API trunks are divided too.
        let state = divided_state(3).await;
        let g = serde_json::json!({"id": "g", "trunks": [
            {"id": "a", "host": "127.0.0.9", "max_calls": 30},
            {"id": "b", "host": "127.0.0.10"}
        ]});
        sync_trunk_group_to_router(&state, &g)
            .await
            .expect("accepted");
        assert_eq!(api_trunk_cap(&state, "g", "a").await, Some(10));
        assert_eq!(api_trunk_cap(&state, "g", "b").await, Some(33));
        // per_node: unchanged.
        let state = divided_state(1).await;
        sync_trunk_group_to_router(&state, &g)
            .await
            .expect("accepted");
        assert_eq!(api_trunk_cap(&state, "g", "a").await, Some(30));
    }

    #[tokio::test]
    async fn api_trunk_bad_max_calls_rejected_and_not_installed() {
        let state = divided_state(3).await;
        for (cap, needle) in [
            (serde_json::json!(0), "must be 1-"),
            (
                serde_json::json!(2),
                "below cluster.admission.expected_nodes (3)",
            ),
            (serde_json::json!(u64::from(u32::MAX) + 1), "must be 1-"),
        ] {
            let g = serde_json::json!({"id": "g", "trunks": [
                {"id": "ok", "host": "127.0.0.9", "max_calls": 30},
                {"id": "bad", "host": "127.0.0.10", "max_calls": cap}
            ]});
            let err = sync_trunk_group_to_router(&state, &g)
                .await
                .expect_err("rejected");
            assert!(err.contains(needle), "{err}");
            assert_eq!(api_trunk_cap(&state, "g", "ok").await, None);
        }
        // max_calls = 0 is rejected under per_node as well.
        let state = divided_state(1).await;
        let g = serde_json::json!({"id": "g", "trunks": [
            {"id": "z", "host": "127.0.0.9", "max_calls": 0}
        ]});
        assert!(sync_trunk_group_to_router(&state, &g).await.is_err());
    }

    #[test]
    fn health_and_metrics_expose_audit_pipeline_and_emergency_admissions() {
        // No audit logger in this process: the pipeline reports healthy.
        let mut state = AppState::new(SbcMetrics::standard(), Arc::new(ServerStats::default()));
        let audit = state
            .check_health()
            .components
            .into_iter()
            .find(|c| c.name == "audit")
            .expect("audit component");
        assert_eq!(audit.status, uc_health::HealthStatus::Healthy);
        state.sip_stack = Some(Arc::new(crate::sip_stack::SipStack::new(
            crate::sip_stack::SipStackConfig::default(),
        )));
        state.refresh_daemon_metrics();
        let text = state.metrics.export();
        assert!(text.contains("sbc_audit_records_dropped 0"), "{text}");
        assert!(text.contains("sbc_audit_writer_alive 1"), "{text}");
        assert!(text.contains("sbc_audit_write_failures 0"), "{text}");
        assert!(text.contains("sbc_emergency_calls_admitted 0"), "{text}");
    }

    #[test]
    fn health_and_metrics_expose_cdr_pipeline() {
        let emitter = uc_cdr::CdrEmitter::start(
            uc_cdr::CdrEmitterConfig {
                node_id: "n1".into(),
                file: None,
                ..Default::default()
            },
            Vec::new(),
            None,
        )
        .expect("emitter");
        let mut stack =
            crate::sip_stack::SipStack::new(crate::sip_stack::SipStackConfig::default());
        stack.set_cdr(Arc::new(crate::cdr::CdrContext::new(
            Arc::clone(&emitter),
            &sbc_config::schema::CdrConfig::default(),
        )));
        let mut state = AppState::new(SbcMetrics::standard(), Arc::new(ServerStats::default()));
        state.sip_stack = Some(Arc::new(stack));
        let cdr = |state: &AppState| {
            state
                .check_health()
                .components
                .into_iter()
                .find(|c| c.name == "cdr")
                .expect("cdr component")
        };
        assert_eq!(cdr(&state).status, uc_health::HealthStatus::Healthy);
        assert!(emitter.emit(uc_cdr::CallRecord::default()));
        assert!(emitter.flush(Duration::from_secs(5)));
        state.refresh_daemon_metrics();
        let text = state.metrics.export();
        assert!(text.contains("sbc_cdr_emitted_total 1"), "{text}");
        assert!(text.contains("sbc_cdr_writer_alive 1"), "{text}");
        assert!(
            text.contains("sbc_cdr_dropped_writer_dead_total 0"),
            "{text}"
        );

        // Writer gone: unhealthy, and further CDRs count as dropped.
        assert!(emitter.shutdown(Duration::from_secs(5)));
        assert!(!emitter.emit(uc_cdr::CallRecord::default()));
        assert_eq!(cdr(&state).status, uc_health::HealthStatus::Unhealthy);
        state.refresh_daemon_metrics();
        let text = state.metrics.export();
        assert!(text.contains("sbc_cdr_writer_alive 0"), "{text}");
        assert!(
            text.contains("sbc_cdr_dropped_writer_dead_total 1"),
            "{text}"
        );
    }

    // POA&M-180: the fail-closed counters reach the metrics endpoint.
    #[test]
    fn metrics_export_topology_and_manipulation_failures() {
        use std::sync::atomic::Ordering;
        let stack = crate::sip_stack::SipStack::new(crate::sip_stack::SipStackConfig::default());
        let c = stack.routing_counters();
        c.topology_hiding_failures.store(3, Ordering::Relaxed);
        c.header_manipulation_failures.store(5, Ordering::Relaxed);
        c.late_2xx_teardowns.store(7, Ordering::Relaxed);
        stack.set_deferred_send_dropped_for_tests(11);
        let mut state = AppState::new(SbcMetrics::standard(), Arc::new(ServerStats::default()));
        state.sip_stack = Some(Arc::new(stack));
        state.refresh_daemon_metrics();
        let text = state.metrics.export();
        for (name, v) in [
            ("sbc_topology_hiding_failures_total", 3),
            ("sbc_header_manipulation_failures_total", 5),
            ("sbc_late_invite_2xx_teardown_total", 7),
            ("sbc_deferred_send_dropped_total", 11),
        ] {
            let want = format!("{name} {v}");
            assert!(text.lines().any(|l| l.ends_with(&want)), "{want}: {text}");
        }
    }

    /// Stats with the writer alive and the given loss.
    fn audit_stats(
        writer_alive: bool,
        dropped: u64,
        last_drop: Option<Duration>,
    ) -> uc_audit::AuditStats {
        uc_audit::AuditStats {
            writer_alive,
            dropped,
            queue_drops: dropped,
            last_drop,
            ..uc_audit::AuditStats::default()
        }
    }

    #[test]
    fn audit_status_recovers_after_drop_window() {
        use uc_health::HealthStatus;
        let w = AUDIT_DROP_DEGRADED_WINDOW;
        let st = |alive, dropped, last| audit_status_from(&audit_stats(alive, dropped, last), w);
        let dead = st(false, 7, None);
        assert_eq!(dead.status, HealthStatus::Unhealthy);
        assert_eq!(
            st(false, 7, Some(Duration::from_secs(1))).status,
            HealthStatus::Unhealthy
        );
        let recent = st(true, 7, Some(Duration::from_secs(5)));
        assert_eq!(recent.status, HealthStatus::Degraded);
        assert_eq!(
            recent.message.as_deref(),
            Some("7 audit records dropped, last 5s ago")
        );
        let old = st(true, 7, Some(Duration::from_secs(61)));
        assert_eq!(old.status, HealthStatus::Healthy);
        assert_eq!(st(true, 7, Some(w)).status, HealthStatus::Healthy);
        assert_eq!(st(true, 0, None).status, HealthStatus::Healthy);
    }

    #[test]
    fn qa_audit_status_window_boundary() {
        use uc_health::HealthStatus;
        let w = AUDIT_DROP_DEGRADED_WINDOW;
        assert_eq!(w, Duration::from_secs(60));
        let just_under = Duration::from_millis(59_999);
        let s = audit_status_from(&audit_stats(true, 2, Some(just_under)), w);
        assert_eq!(s.status, HealthStatus::Degraded);
        assert_eq!(
            s.message.as_deref(),
            Some("2 audit records dropped, last 59s ago")
        );
        let s = audit_status_from(&audit_stats(true, 1, Some(Duration::ZERO)), w);
        assert_eq!(s.status, HealthStatus::Degraded);
        assert_eq!(
            s.message.as_deref(),
            Some("1 audit records dropped, last 0s ago")
        );
        assert_eq!(
            audit_status_from(&audit_stats(true, 1, Some(w + Duration::from_millis(1))), w).status,
            HealthStatus::Healthy
        );
        // A zero window never reports degraded.
        assert_eq!(
            audit_status_from(&audit_stats(true, 1, Some(Duration::ZERO)), Duration::ZERO).status,
            HealthStatus::Healthy
        );
    }

    #[test]
    fn audit_status_unhealthy_when_sink_failing() {
        use uc_health::HealthStatus;
        let stats = uc_audit::AuditStats {
            writer_alive: true,
            dropped: 4,
            write_failures: 4,
            sink_failing: true,
            last_drop: Some(Duration::ZERO),
            last_write_failure: Some(Duration::ZERO),
            ..uc_audit::AuditStats::default()
        };
        let s = audit_status_from(&stats, AUDIT_DROP_DEGRADED_WINDOW);
        assert_eq!(s.status, HealthStatus::Unhealthy);
        assert_eq!(
            s.message.as_deref(),
            Some("audit sink write failing (4 errors)")
        );
        // A dead writer still takes precedence.
        let dead = uc_audit::AuditStats {
            writer_alive: false,
            ..stats
        };
        assert!(
            audit_status_from(&dead, AUDIT_DROP_DEGRADED_WINDOW)
                .message
                .is_some_and(|m| m.contains("writer thread exited"))
        );
    }

    #[test]
    fn audit_status_degraded_after_recent_write_failure() {
        use uc_health::HealthStatus;
        let w = AUDIT_DROP_DEGRADED_WINDOW;
        let stats = uc_audit::AuditStats {
            writer_alive: true,
            dropped: 1,
            write_failures: 1,
            sink_failing: false,
            last_drop: Some(Duration::from_secs(120)),
            last_write_failure: Some(Duration::from_secs(10)),
            ..uc_audit::AuditStats::default()
        };
        let s = audit_status_from(&stats, w);
        assert_eq!(s.status, HealthStatus::Degraded);
        assert_eq!(
            s.message.as_deref(),
            Some("1 audit records dropped, last 10s ago")
        );
        let old = uc_audit::AuditStats {
            last_write_failure: Some(Duration::from_secs(120)),
            ..stats
        };
        assert_eq!(audit_status_from(&old, w).status, HealthStatus::Healthy);
    }

    #[test]
    fn dial_plan_sync_honours_entry_pattern() {
        let entries = [
            serde_json::json!({"pattern": "+1", "trunk_group_id": "us"}),
            serde_json::json!({"pattern": "911", "pattern_type": "exact", "trunk_group_id": "es"}),
            serde_json::json!({"pattern": "1XXX", "pattern_type": "wildcard", "trunk_group_id": "ext"}),
        ];
        let plan = dial_plan_from_entries("p", &entries);

        assert_eq!(plan.match_number("+15551234567").unwrap().trunk_group, "us");
        assert_eq!(plan.match_number("911").unwrap().trunk_group, "es");
        assert_eq!(plan.match_number("1234").unwrap().trunk_group, "ext");
        // Numbers outside every configured pattern must not match.
        assert!(plan.match_number("0119005551234").is_none());
        assert!(plan.match_number("9110").is_none());
    }

    #[test]
    fn dial_plan_sync_keeps_explicit_catch_all() {
        for entry in [
            serde_json::json!({"trunk_group_id": "any"}),
            serde_json::json!({"pattern": ".*", "trunk_group_id": "any"}),
            serde_json::json!({"pattern_type": "any", "trunk_group_id": "any"}),
        ] {
            let plan = dial_plan_from_entries("p", &[entry]);
            assert_eq!(
                plan.match_number("0119005551234").unwrap().trunk_group,
                "any"
            );
        }
    }

    /// A router with one CSS (`css`) over one partition (`p`), as the sync
    /// path would have built from the API's partition/CSS documents.
    fn routed_state() -> Arc<AppState> {
        let metrics = SbcMetrics::standard();
        let server_stats = Arc::new(ServerStats::default());
        let mut state = AppState::new(metrics, server_stats);
        let mut router = uc_routing::SbcRouter::new();
        router.add_partition(uc_routing::Partition::new("p", "Partition"));
        let mut css = uc_routing::CallingSearchSpace::new("css", "CSS");
        css.add_partition("p");
        router.add_css(css);
        state.sbc_router = Some(Arc::new(tokio::sync::RwLock::new(router)));
        Arc::new(state)
    }

    #[tokio::test]
    async fn route_pattern_sync_applies_transform() {
        let state = routed_state();
        for (id, body, dialled, expect) in [
            (
                "strip",
                serde_json::json!({"id": "strip", "pattern": "9", "partition_id": "p",
                    "route_group_id": "rg", "transform_type": "strip_prefix", "transform_value": "1"}),
                "95551234",
                "5551234",
            ),
            (
                "add",
                serde_json::json!({"id": "add", "pattern": "555", "partition_id": "p",
                    "route_group_id": "rg", "transform_type": "add_prefix", "transform_value": "+1"}),
                "5551234",
                "+15551234",
            ),
            (
                "swap",
                serde_json::json!({"id": "swap", "pattern": "011", "partition_id": "p",
                    "route_group_id": "rg", "transform_type": "replace_prefix", "transform_value": "011|+"}),
                "011441234",
                "+441234",
            ),
            (
                "fixed",
                serde_json::json!({"id": "fixed", "pattern": "0", "pattern_type": "exact", "partition_id": "p",
                    "route_group_id": "rg", "transform_type": "replace", "transform_value": "2000"}),
                "0",
                "2000",
            ),
        ] {
            apply_route_pattern_to_router(&state, &body).await;
            let router = state.sbc_router.as_ref().unwrap().read().await;
            let result = router
                .route(dialled, Some("css"))
                .routed()
                .expect("pattern matches");
            assert_eq!(result.pattern_id, id);
            assert_eq!(result.transformed_number, expect, "{id}");
            assert_eq!(result.route_group_ids, vec!["rg".to_string()]);
            drop(router);
        }
    }

    #[test]
    fn malformed_transforms_become_none() {
        use uc_routing::NumberTransform;
        for body in [
            serde_json::json!({}),
            serde_json::json!({"transform_type": "none"}),
            serde_json::json!({"transform_type": "strip_prefix", "transform_value": "0"}),
            serde_json::json!({"transform_type": "strip_prefix", "transform_value": "abc"}),
            serde_json::json!({"transform_type": "add_prefix"}),
            serde_json::json!({"transform_type": "replace_prefix", "transform_value": "nodelimiter"}),
            serde_json::json!({"transform_type": "replace_prefix", "transform_value": "|to"}),
            serde_json::json!({"transform_type": "bogus", "transform_value": "1"}),
        ] {
            assert!(
                matches!(number_transform_from_json(&body), NumberTransform::None),
                "{body}"
            );
        }
        // A numeric JSON value for strip_prefix is accepted too.
        assert!(matches!(
            number_transform_from_json(
                &serde_json::json!({"transform_type": "strip_prefix", "transform_value": 2})
            ),
            NumberTransform::StripPrefix { count: 2 }
        ));
    }

    fn test_server() -> ApiServer {
        let config = ApiServerConfig::default();
        let state = test_state();
        let shutdown = ShutdownSignal::new();
        ApiServer::new(config, state, shutdown)
    }

    #[tokio::test]
    async fn test_liveness_probe() {
        let server = test_server();
        let router = server.router();

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readiness_probe() {
        let server = test_server();
        let router = server.router();

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_default_config() {
        let config = ApiServerConfig::default();
        assert_eq!(config.listen_addr.port(), 8080);
        assert!(!config.enable_cors);
        assert_eq!(config.api_version, "v1");
    }

    // RFC 3261 §19.1.2 (RFC-001/SEC-002): synced trunk port defaults follow
    // the transport; an out-of-range port skips the trunk, never truncates.
    #[test]
    fn synced_trunk_port_follows_transport() {
        let body = serde_json::json!({
            "id": "g",
            "trunks": [
                {"id": "tls", "host": "tls.example.com", "protocol": "tls"},
                {"id": "udp", "host": "udp.example.com"},
                {"id": "big", "host": "big.example.com", "port": 70_000},
                {"id": "set", "host": "set.example.com", "protocol": "tls", "port": 5080},
            ],
        });
        let g = trunk_group_from_json(&body).expect("group");
        let port = |id: &str| g.get_trunk(id).map(|t| t.config().port);
        assert_eq!(port("tls"), Some(5061));
        assert_eq!(port("udp"), Some(5060));
        assert_eq!(port("big"), None);
        assert_eq!(port("set"), Some(5080));
        assert_eq!(g.trunk_count(), 3);
    }

    // NIST-004: TLS trunk + no trunk CA bundle is detected.
    #[test]
    fn tls_trunk_without_ca_detected() {
        let tls = serde_json::json!({"id": "g", "trunks": [
            {"id": "a", "host": "a.example.com", "protocol": "tls"}]});
        let udp = serde_json::json!({"id": "g", "trunks": [
            {"id": "a", "host": "a.example.com"}]});
        let g = trunk_group_from_json(&tls).expect("group");
        assert!(tls_trunk_without_ca(&g, false));
        assert!(!tls_trunk_without_ca(&g, true));
        let g = trunk_group_from_json(&udp).expect("group");
        assert!(!tls_trunk_without_ca(&g, false));
    }

    #[tokio::test]
    async fn route_pattern_sync_rejects_unknown_pattern_type_and_keeps_previous() {
        let mut state = AppState::new(SbcMetrics::standard(), Arc::new(ServerStats::default()));
        let router = Arc::new(tokio::sync::RwLock::new(uc_routing::SbcRouter::new()));
        state.sbc_router = Some(Arc::clone(&router));
        let state = Arc::new(state);
        let good = serde_json::json!({"id": "rp", "partition_id": "pt", "pattern": "1900",
                                      "pattern_type": "prefix", "blocked": true});
        apply_route_pattern_to_router(&state, &good).await;
        let before =
            crate::sip_stack::ROUTE_PATTERN_REJECTED.load(std::sync::atomic::Ordering::Relaxed);
        let bogus = serde_json::json!({"id": "rp", "partition_id": "pt", "pattern": "1900",
                                       "pattern_type": "bogus"});
        apply_route_pattern_to_router(&state, &bogus).await;
        let r = router.read().await;
        let pats = r.list_route_patterns();
        assert_eq!(pats.len(), 1);
        assert!(pats[0].is_blocked(), "previous (blocked) pattern kept");
        assert!(
            crate::sip_stack::ROUTE_PATTERN_REJECTED.load(std::sync::atomic::Ordering::Relaxed)
                > before
        );
    }
}

/// REST HTTPS listener tests: CNSA provider, reload, SC-5 limits.
#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod rest_tls_tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, ServerName};
    use std::io::Write as _;
    use tokio::io::AsyncReadExt;
    use uc_metrics::SbcMetrics;

    struct Pki {
        _dir: tempfile::TempDir,
        cert: PathBuf,
        key: PathBuf,
    }

    fn write_secret(path: &std::path::Path, data: &str) {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .expect("open");
        f.write_all(data.as_bytes()).expect("write");
    }

    /// Writes a self-signed `localhost` cert + key using `alg`.
    fn write_pki(pki: &Pki, alg: &'static rcgen::SignatureAlgorithm) -> CertificateDer<'static> {
        let key = rcgen::KeyPair::generate_for(alg).expect("key");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
        let cert = params.self_signed(&key).expect("cert");
        write_secret(&pki.cert, &cert.pem());
        write_secret(&pki.key, &key.serialize_pem());
        cert.der().clone()
    }

    fn new_pki() -> (Pki, CertificateDer<'static>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let pki = Pki {
            cert: dir.path().join("cert.pem"),
            key: dir.path().join("key.pem"),
            _dir: dir,
        };
        let der = write_pki(&pki, &rcgen::PKCS_ECDSA_P384_SHA384);
        (pki, der)
    }

    fn free_addr() -> SocketAddr {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr")
    }

    struct Running {
        addr: SocketAddr,
        state: Arc<AppState>,
        shutdown: ShutdownSignal,
    }

    async fn start(pki: &Pki, tweak: impl FnOnce(&mut ApiServerConfig)) -> Running {
        let tls = TlsConfig {
            cert_path: pki.cert.clone(),
            key_path: pki.key.clone(),
        };
        let acceptor = ApiServer::build_tls_acceptor(&tls, CnsaCurve::P384).expect("acceptor");
        let mut state = AppState::new(SbcMetrics::standard(), Arc::new(ServerStats::default()));
        state.tls_acceptor = Some(acceptor);
        let state = Arc::new(state);
        let addr = free_addr();
        let mut config = ApiServerConfig {
            listen_addr: addr,
            tls: Some(tls),
            ..ApiServerConfig::default()
        };
        tweak(&mut config);
        let shutdown = ShutdownSignal::new();
        let server = ApiServer::new(config, Arc::clone(&state), shutdown.clone());
        tokio::spawn(async move {
            let _ = server.run().await;
        });
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Running {
            addr,
            state,
            shutdown,
        }
    }

    fn client_config(
        provider: rustls::crypto::CryptoProvider,
        trust: &CertificateDer<'static>,
    ) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(trust.clone()).expect("root");
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("versions")
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    async fn connect(
        addr: SocketAddr,
        cfg: Arc<rustls::ClientConfig>,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let name = ServerName::try_from("localhost").expect("name");
        tokio_rustls::TlsConnector::from(cfg)
            .connect(name, tcp)
            .await
    }

    fn counter(state: &AppState, name: &str) -> u64 {
        state
            .metrics
            .counter(name)
            .map_or(0, uc_metrics::Counter::get)
    }

    #[tokio::test]
    async fn rest_tls_negotiates_cnsa_suite() {
        let (pki, der) = new_pki();
        let srv = start(&pki, |_| {}).await;
        let tls = connect(
            srv.addr,
            client_config(uc_transport::tls::cnsa_provider(), &der),
        )
        .await
        .expect("handshake");
        let (_, conn) = tls.get_ref();
        assert_eq!(
            conn.negotiated_cipher_suite().map(|s| s.suite()),
            Some(rustls::CipherSuite::TLS13_AES_256_GCM_SHA384)
        );
        assert_eq!(
            conn.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        srv.shutdown.request_shutdown();
    }

    #[tokio::test]
    async fn rest_tls_rejects_non_cnsa_client() {
        use rustls::crypto::aws_lc_rs::{cipher_suite, default_provider, kx_group};
        let (pki, der) = new_pki();
        let srv = start(&pki, |_| {}).await;
        let weak = rustls::crypto::CryptoProvider {
            cipher_suites: vec![cipher_suite::TLS13_AES_128_GCM_SHA256],
            kx_groups: vec![kx_group::X25519],
            ..default_provider()
        };
        assert!(connect(srv.addr, client_config(weak, &der)).await.is_err());
        srv.shutdown.request_shutdown();
    }

    #[tokio::test]
    async fn rest_tls_reload_swaps_cert() {
        let (pki, der_a) = new_pki();
        let srv = start(&pki, |c| c.tls_reload_poll = Duration::from_millis(50)).await;
        let provider = uc_transport::tls::cnsa_provider;
        connect(srv.addr, client_config(provider(), &der_a))
            .await
            .expect("cert A");

        tokio::time::sleep(Duration::from_millis(20)).await;
        let der_b = write_pki(&pki, &rcgen::PKCS_ECDSA_P384_SHA384);
        // The watcher picks the change up without any signal.
        let mut swapped = false;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if counter(&srv.state, METRIC_API_TLS_RELOADS) >= 1 {
                swapped = true;
                break;
            }
        }
        assert!(swapped, "watcher reloaded");
        let tls = connect(srv.addr, client_config(provider(), &der_b))
            .await
            .expect("cert B");
        let peer = tls.get_ref().1.peer_certificates().expect("peer");
        assert_eq!(peer.first(), Some(&der_b));
        assert!(
            connect(srv.addr, client_config(provider(), &der_a))
                .await
                .is_err()
        );
        srv.shutdown.request_shutdown();
    }

    #[tokio::test]
    async fn rest_tls_reload_failure_keeps_old_cert() {
        let (pki, der_a) = new_pki();
        let srv = start(&pki, |_| {}).await;
        // P-256 is not CNSA and not `security.curve`: reload fails closed.
        write_pki(&pki, &rcgen::PKCS_ECDSA_P256_SHA256);
        assert!(srv.state.reload_tls_certificates().is_err());
        let tls = connect(
            srv.addr,
            client_config(uc_transport::tls::cnsa_provider(), &der_a),
        )
        .await
        .expect("still cert A");
        assert_eq!(
            tls.get_ref().1.peer_certificates().and_then(<[_]>::first),
            Some(&der_a)
        );
        srv.shutdown.request_shutdown();
    }

    #[tokio::test]
    async fn rest_tls_handshake_timeout() {
        let (pki, _) = new_pki();
        let srv = start(&pki, |c| {
            c.tls_handshake_timeout = Duration::from_millis(200);
        })
        .await;
        let mut tcp = tokio::net::TcpStream::connect(srv.addr).await.expect("tcp");
        let started = Instant::now();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf))
            .await
            .expect("server closed the idle connection")
            .unwrap_or(0);
        assert_eq!(n, 0);
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(counter(&srv.state, METRIC_API_TLS_HANDSHAKE_TIMEOUTS) >= 1);
        srv.shutdown.request_shutdown();
    }

    #[tokio::test]
    async fn rest_tls_connection_cap() {
        let (pki, _) = new_pki();
        let srv = start(&pki, |c| c.max_tls_connections = 2).await;
        // `start` probed the port with a connection that has since closed;
        // let its permit drain (handshake EOF) before filling the cap.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _a = tokio::net::TcpStream::connect(srv.addr).await.expect("a");
        let _b = tokio::net::TcpStream::connect(srv.addr).await.expect("b");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut c = tokio::net::TcpStream::connect(srv.addr).await.expect("c");
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf))
            .await
            .expect("third connection shed immediately")
            .unwrap_or(0);
        assert_eq!(n, 0);
        assert_eq!(counter(&srv.state, METRIC_API_TLS_CONN_REJECTED), 1);
        srv.shutdown.request_shutdown();
    }

    /// Opens `n` TLS sessions that never send a request.
    async fn idle_sessions(
        srv: &Running,
        der: &CertificateDer<'static>,
        n: usize,
    ) -> Vec<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(
                connect(
                    srv.addr,
                    client_config(uc_transport::tls::cnsa_provider(), der),
                )
                .await
                .expect("idle session"),
            );
        }
        v
    }

    /// Sends `GET /healthz` on a fresh TLS session; returns the status line.
    async fn get_health(srv: &Running, der: &CertificateDer<'static>) -> Option<String> {
        use tokio::io::AsyncWriteExt;
        let mut tls = connect(
            srv.addr,
            client_config(uc_transport::tls::cnsa_provider(), der),
        )
        .await
        .ok()?;
        tls.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .ok()?;
        let mut buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), tls.read_to_end(&mut buf))
            .await
            .ok()?
            .ok()?;
        let text = String::from_utf8_lossy(&buf);
        text.lines().next().map(str::to_string)
    }

    async fn served_after_bound(srv: &Running, der: &CertificateDer<'static>) -> bool {
        for _ in 0..100 {
            if get_health(srv, der).await.is_some() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    #[tokio::test]
    async fn rest_tls_idle_connections_release_cap_permits() {
        let (pki, der) = new_pki();
        let srv = start(&pki, |c| {
            c.max_tls_connections = 2;
            c.tls_idle_timeout = Duration::from_millis(300);
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let held = idle_sessions(&srv, &der, 2).await;
        // At the cap: a new connection is shed.
        assert!(get_health(&srv, &der).await.is_none());
        assert!(counter(&srv.state, METRIC_API_TLS_CONN_REJECTED) >= 1);
        // Idle sessions are closed by the keep-alive/header deadline.
        assert!(
            served_after_bound(&srv, &der).await,
            "new connection served once the bound expired"
        );
        drop(held);
        srv.shutdown.request_shutdown();
    }

    #[tokio::test]
    async fn rest_tls_max_connection_age_releases_cap_permits() {
        let (pki, der) = new_pki();
        let srv = start(&pki, |c| {
            c.max_tls_connections = 2;
            c.tls_idle_timeout = Duration::from_secs(60);
            c.max_tls_connection_age = Duration::from_millis(300);
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let held = idle_sessions(&srv, &der, 2).await;
        assert!(get_health(&srv, &der).await.is_none());
        assert!(
            served_after_bound(&srv, &der).await,
            "new connection served once the bound expired"
        );
        drop(held);
        srv.shutdown.request_shutdown();
    }

    #[tokio::test]
    async fn rest_tls_h2_prior_knowledge_not_served() {
        use tokio::io::AsyncWriteExt;
        let (pki, der) = new_pki();
        let srv = start(&pki, |_| {}).await;
        let mut tls = connect(
            srv.addr,
            client_config(uc_transport::tls::cnsa_provider(), &der),
        )
        .await
        .expect("handshake");
        tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .expect("preface");
        // Empty SETTINGS frame.
        tls.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0])
            .await
            .expect("settings");
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut buf))
            .await
            .expect("server closed the h2 connection");
        // An h2 server would answer with a SETTINGS frame (type 0x4).
        assert!(!(buf.len() >= 9 && buf[3] == 4), "server spoke HTTP/2");
        srv.shutdown.request_shutdown();
    }

    #[test]
    fn startup_fails_closed_on_bad_api_key_file() {
        use std::os::unix::fs::PermissionsExt;
        let (pki, _) = new_pki();
        let tls = TlsConfig {
            cert_path: pki.cert.clone(),
            key_path: pki.key.clone(),
        };
        // Wrong curve for `security.curve`.
        assert!(ApiServer::build_tls_acceptor(&tls, CnsaCurve::P521).is_err());
        // World-readable key file (PR 177 checks).
        std::fs::set_permissions(&pki.key, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        assert!(ApiServer::build_tls_acceptor(&tls, CnsaCurve::P384).is_err());
    }

    #[tokio::test]
    async fn https_without_acceptor_fails_closed() {
        let (pki, _) = new_pki();
        let state = Arc::new(AppState::new(
            SbcMetrics::standard(),
            Arc::new(ServerStats::default()),
        ));
        let config = ApiServerConfig {
            listen_addr: free_addr(),
            tls: Some(TlsConfig {
                cert_path: pki.cert.clone(),
                key_path: pki.key.clone(),
            }),
            ..ApiServerConfig::default()
        };
        let server = ApiServer::new(config, state, ShutdownSignal::new());
        assert!(matches!(
            server.run().await,
            Err(ApiServerError::TlsError { .. })
        ));
    }

    #[test]
    fn api_token_compare_constant_time() {
        assert!(api_token_matches("s3cret-token", "s3cret-token"));
        assert!(!api_token_matches("s3cret-tokex", "s3cret-token"));
        assert!(!api_token_matches("s3cret", "s3cret-token"));
        assert!(!api_token_matches("", "s3cret-token"));
    }
}
