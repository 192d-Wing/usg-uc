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

use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use hyper_util::service::TowerToHyperService;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use uc_health::{ComponentStatus, SystemHealth};
use uc_metrics::MetricRegistry;
use uc_transport::cert_reload::ReloadableTlsAcceptor;

use crate::server::ServerStats;
use crate::shutdown::ShutdownSignal;

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
    /// Phone provisioning server.
    pub provisioning: Option<Arc<uc_phone_mgmt::provisioning::ProvisioningServer>>,
    /// CUCM router for CSS/partition-based routing.
    pub cucm_router: Option<Arc<tokio::sync::RwLock<uc_routing::CucmRouter>>>,
    /// Trunk health monitor.
    pub trunk_monitor: Option<Arc<crate::trunk_monitor::TrunkMonitor>>,
    /// Trunk registrar (SBC registers to carriers).
    pub trunk_registrar: Option<Arc<crate::trunk_registrar::TrunkRegistrar>>,
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
    /// `sip_stack`/`cucm_router` synchronization (which is unchanged —
    /// persistence and SIP-stack wiring are separate concerns here).
    pub trunk_group_store: Option<Arc<sbc_config_store::PostgresTrunkGroupStore>>,
    /// Postgres-backed dial-plan store. Before this PR, dial plans lived
    /// only in the `CucmRouter` and were lost on every daemon restart.
    /// When `Some`, dial-plan writes persist and the startup loop replays
    /// them into the router so SIP routing decisions survive restarts.
    pub dial_plan_store: Option<Arc<sbc_config_store::PostgresDialPlanStore>>,
    /// Postgres-backed CUCM-routing stores (PR11). Pre-PR11 these lived
    /// only in-memory inside `CucmRouter` — a daemon restart wiped them.
    /// When `Some`, sbc-api owns the writes (and notifies via the gRPC
    /// `CucmSyncService`) and the daemon's startup loop replays them
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

impl AppState {
    /// Creates new application state.
    pub fn new(metrics: MetricRegistry, stats: Arc<ServerStats>) -> Self {
        Self {
            metrics,
            stats,
            version: env!("CARGO_PKG_VERSION").to_string(),
            start_time: Instant::now(),
            ready: AtomicU64::new(1), // Start as ready
            sip_stack: None,
            provisioning: None,
            cucm_router: None,
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
            zone_registry: None,
            tls_acceptor: None,
            #[cfg(feature = "cluster")]
            cluster_health_fn: None,
        }
    }

    /// Creates new application state with TLS acceptor for certificate reload support.
    pub fn with_tls(
        metrics: MetricRegistry,
        stats: Arc<ServerStats>,
        tls_acceptor: Arc<ReloadableTlsAcceptor>,
    ) -> Self {
        Self {
            metrics,
            stats,
            version: env!("CARGO_PKG_VERSION").to_string(),
            start_time: Instant::now(),
            ready: AtomicU64::new(1),
            sip_stack: None,
            provisioning: None,
            cucm_router: None,
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
            zone_registry: None,
            tls_acceptor: Some(tls_acceptor),
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
    /// - `/cdrs` — read-only CDR list, no gRPC service.
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
            // Registration deletes still come through HTTP today;
            // sbc-api hits CallService gRPC for list/get but the delete
            // path goes via DeleteRegistration RPC now too. Kept here
            // as a defense-in-depth — sbc-api's gRPC handler routes to
            // this anyway, but operator tools that bypass sbc-api still
            // have a way in. TODO: remove once we're confident nothing
            // hits the daemon directly.
            //
            // Read-only dial-plan views (still no gRPC reader).
            .route("/dialplans", get(get_dial_plans))
            .route("/dialplans/{plan_id}/entries", get(get_dial_plan_entries))
            // CDR list (no gRPC equivalent yet).
            .route("/cdrs", get(get_cdrs))
            // (trunk-health and trunk-registration routes moved to
            // sbc-api in PR9; backed by daemon's TrunkHealthService gRPC.)
            // (user CRUD moved to sbc-api in PR10; PostgresUserStore is
            // hit directly from sbc-api instead of via the daemon.)
            // (CUCM routing CRUD — partitions, CSS, route patterns,
            // route lists — moved to sbc-api in PR11; sbc-api owns the
            // Postgres writes and the daemon's live router catches up
            // via the new CucmSyncService gRPC.)
            ;

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
    async fn run_https(
        &self,
        tls_config: &TlsConfig,
        addr: SocketAddr,
    ) -> Result<(), ApiServerError> {
        let router = self.router();

        info!(
            address = %addr,
            cert = %tls_config.cert_path.display(),
            tls = true,
            "Starting API server (HTTPS)"
        );

        // Use the reloadable TLS acceptor from state if available (preferred for hot-reload),
        // otherwise fall back to creating a static one at startup.
        let reloadable_acceptor = self.state.tls_acceptor.clone();
        let static_acceptor = if reloadable_acceptor.is_none() {
            Some(Arc::new(Self::create_tls_acceptor(tls_config)?))
        } else {
            None
        };

        let listener =
            tokio::net::TcpListener::bind(addr)
                .await
                .map_err(|e| ApiServerError::BindFailed {
                    address: addr.to_string(),
                    reason: e.to_string(),
                })?;

        let shutdown = self.shutdown.clone();

        // Run HTTPS server with graceful shutdown
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, _peer_addr)) => {
                            // Get the current acceptor (supports hot-reload if reloadable)
                            let acceptor = match (&reloadable_acceptor, &static_acceptor) {
                                (Some(r), _) => r.acceptor_arc(),
                                (None, Some(s)) => Arc::clone(s),
                                (None, None) => {
                                    warn!("No TLS acceptor available");
                                    continue;
                                }
                            };
                            let mut service = router.clone().into_make_service();

                            tokio::spawn(async move {
                                match acceptor.accept(stream).await {
                                    Ok(tls_stream) => {
                                        let io = TokioIo::new(tls_stream);
                                        let svc = match service.call(()).await {
                                            Ok(s) => s,
                                            Err(e) => {
                                                warn!(error = ?e, "Failed to create service");
                                                return;
                                            }
                                        };

                                        let hyper_svc = TowerToHyperService::new(svc);
                                        if let Err(e) = ServerBuilder::new(hyper_util::rt::TokioExecutor::new())
                                            .serve_connection(io, hyper_svc)
                                            .await
                                        {
                                            warn!(error = %e, "Error serving HTTPS connection");
                                        }
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "TLS handshake failed");
                                    }
                                }
                            });
                        }
                        Err(e) => {
                            warn!(error = %e, "Failed to accept connection");
                        }
                    }
                }
                () = shutdown.wait_for_shutdown() => {
                    info!("API server (HTTPS) shutting down");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Creates a reloadable TLS acceptor for hot certificate rotation.
    ///
    /// ## NIST 800-53 Rev5: SC-12 (Cryptographic Key Establishment and Management)
    pub fn create_reloadable_tls_acceptor(
        tls_config: &TlsConfig,
    ) -> Result<ReloadableTlsAcceptor, ApiServerError> {
        ReloadableTlsAcceptor::new(tls_config.cert_path.clone(), tls_config.key_path.clone())
            .map_err(|e| ApiServerError::TlsError {
                reason: format!("Failed to create TLS acceptor: {e}"),
            })
    }

    /// Creates a TLS acceptor with CNSA 2.0 compliant configuration.
    fn create_tls_acceptor(tls_config: &TlsConfig) -> Result<TlsAcceptor, ApiServerError> {
        use rustls::pki_types::PrivateKeyDer;
        use rustls::pki_types::pem::PemObject;

        // Load certificate chain
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(&tls_config.cert_path)
                .map_err(|e| ApiServerError::TlsError {
                    reason: format!("Failed to open certificate file: {e}"),
                })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| ApiServerError::TlsError {
                    reason: format!("Failed to parse certificates: {e}"),
                })?;

        if certs.is_empty() {
            return Err(ApiServerError::TlsError {
                reason: "No certificates found in certificate file".to_string(),
            });
        }

        // Load private key
        let key = PrivateKeyDer::from_pem_file(&tls_config.key_path).map_err(|e| {
            ApiServerError::TlsError {
                reason: format!("Failed to load private key: {e}"),
            }
        })?;

        // Create TLS config with CNSA 2.0 compliant settings
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| ApiServerError::TlsError {
                reason: format!("Failed to create TLS config: {e}"),
            })?;

        Ok(TlsAcceptor::from(Arc::new(config)))
    }
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
// CDR Routes
// ============================================================================

/// List CDR records.
async fn get_cdrs(
    State(_state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let _start = params.get("start");
    let _end = params.get("end");
    let _caller = params.get("caller");
    let _callee = params.get("callee");
    let _status = params.get("status");

    // CDR storage not yet implemented — return empty
    Json(serde_json::json!({
        "cdrs": [],
        "total": 0,
        "page": 1,
        "page_size": 50
    }))
}

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
    let port = trunk.get("port").and_then(|v| v.as_u64()).unwrap_or(5060) as u16;

    if trunk_id.is_empty() || host.is_empty() {
        return;
    }

    // Resolve zone IPs for binding and Contact header.
    // The trunk's "zone" field specifies which interface to bind to.
    // Falls back to "outside", then "inside".
    let zone_name = trunk
        .get("zone")
        .and_then(|v| v.as_str())
        .unwrap_or("outside");
    let (bind_ip, external_ip) = if let Some(ref zr) = state.zone_registry {
        let ip = zr
            .signaling_ip(zone_name)
            .or_else(|| zr.signaling_ip("outside"))
            .or_else(|| zr.signaling_ip("inside"));
        let ext = zr.external_ip(zone_name);
        (ip, ext)
    } else {
        (None, None)
    };

    // Start OPTIONS health monitoring
    if trunk
        .get("options_ping_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        if let Some(ref monitor) = state.trunk_monitor {
            let interval = trunk
                .get("options_ping_interval")
                .and_then(|v| v.as_u64())
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
    }

    // Start SIP registration
    if trunk
        .get("register_enabled")
        .and_then(|v| v.as_bool())
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
        if !username.is_empty() && !password.is_empty() {
            if let Some(ref registrar) = state.trunk_registrar {
                let domain = trunk
                    .get("sip_domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or(host);
                let expires = trunk
                    .get("register_expires")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(25) as u32;
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
                });
                tracing::info!(trunk_id, "Started SIP registration via API");
            }
        }
    }
}

/// Syncs a trunk group from MemStore JSON to the SipStack router.
pub async fn sync_trunk_group_to_router(state: &Arc<AppState>, group_json: &serde_json::Value) {
    let Some(ref sip_stack) = state.sip_stack else {
        return;
    };
    let id = group_json
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let name = group_json
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(id);
    if id.is_empty() {
        return;
    }

    let mut group = uc_routing::TrunkGroup::new(id, name);

    if let Some(trunks) = group_json.get("trunks").and_then(|v| v.as_array()) {
        for t in trunks {
            let trunk_id = t.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            let host = t.get("host").and_then(|v| v.as_str()).unwrap_or_default();
            let port = t.get("port").and_then(|v| v.as_u64()).unwrap_or(5060) as u16;
            if trunk_id.is_empty() || host.is_empty() {
                continue;
            }

            let trunk_config = uc_routing::TrunkConfig {
                id: trunk_id.to_string(),
                name: trunk_id.to_string(),
                host: host.to_string(),
                port,
                protocol: uc_routing::TrunkProtocol::Udp,
                priority: t.get("priority").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
                weight: t.get("weight").and_then(|v| v.as_u64()).unwrap_or(100) as u32,
                max_calls: t.get("max_calls").and_then(|v| v.as_u64()).unwrap_or(100) as u32,
                cooldown_secs: t
                    .get("cooldown_seconds")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(30) as u64,
                max_failures: t.get("max_failures").and_then(|v| v.as_u64()).unwrap_or(5) as u32,
                outbound_enabled: true,
                inbound_enabled: true,
            };
            group.add_trunk(uc_routing::Trunk::new(trunk_config));
        }
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
                    let p = t.get("port").and_then(|v| v.as_u64()).unwrap_or(5060) as u16;
                    Some((h.to_string(), p))
                })
                .collect()
        })
        .unwrap_or_default();
    if !hosts.is_empty() {
        sip_stack.register_inbound_trunk(id, css_id, &hosts).await;
    }

    tracing::info!(trunk_group = id, css = ?css_id, "Synced trunk group to SIP stack router");
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

    let mut plan = uc_routing::DialPlan::new(plan_id, plan_id);
    for (idx, entry) in entries.iter().enumerate() {
        let trunk_group = entry
            .get("trunk_group_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let _pattern_value = entry
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or(".*");
        let priority = entry.get("priority").and_then(|v| v.as_u64()).unwrap_or(1) as u32;

        let pattern = uc_routing::DialPattern::Any;
        let entry_id = format!("{plan_id}-{idx}");
        let dp_entry =
            uc_routing::DialPlanEntry::new(entry_id, pattern, trunk_group).with_priority(priority);
        plan.add_entry(dp_entry);
    }

    sip_stack.add_dial_plan_to_router(plan).await;
    tracing::info!(
        plan_id,
        entries = entries.len(),
        "Synced dial plan to SIP stack router"
    );
}

/// Apply a JSON partition body to the live `CucmRouter`. Used by both
/// the boot-time replay (when `cucm_router` is `Some`) and the gRPC
/// `CucmSyncService.SyncPartition` handler. Idempotent: `add_partition`
/// upserts by ID.
pub async fn apply_partition_to_router(state: &Arc<AppState>, body: &serde_json::Value) {
    let Some(ref router) = state.cucm_router else {
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
    if let Some(desc) = body.get("description").and_then(|v| v.as_str()) {
        if !desc.is_empty() {
            p = p.with_description(desc);
        }
    }
    router.write().await.add_partition(p);
}

/// Apply a JSON CSS body. `partitions` is an array of partition-ID
/// strings; ordering is preserved (CUCM CSS lookup is ordered).
pub async fn apply_css_to_router(state: &Arc<AppState>, body: &serde_json::Value) {
    let Some(ref router) = state.cucm_router else {
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
/// `DialPattern` variant; unknown values fall back to `prefix` to match
/// the legacy REST handler.
pub async fn apply_route_pattern_to_router(state: &Arc<AppState>, body: &serde_json::Value) {
    let Some(ref router) = state.cucm_router else {
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
    let pattern = match pattern_type {
        "exact" => uc_routing::DialPattern::exact(pattern_value),
        "wildcard" => uc_routing::DialPattern::wildcard(pattern_value),
        "any" => uc_routing::DialPattern::Any,
        _ => uc_routing::DialPattern::prefix(pattern_value),
    };
    let mut rp = uc_routing::RoutePattern::new(id, pattern, partition);
    if let Some(rl) = body.get("route_list_id").and_then(|v| v.as_str()) {
        if !rl.is_empty() {
            rp = rp.with_route_list(rl);
        }
    }
    if let Some(rg) = body.get("route_group_id").and_then(|v| v.as_str()) {
        if !rg.is_empty() {
            rp = rp.with_route_group(rg);
        }
    }
    if let Some(desc) = body.get("description").and_then(|v| v.as_str()) {
        if !desc.is_empty() {
            rp = rp.with_description(desc);
        }
    }
    if let Some(p) = body.get("priority").and_then(|v| v.as_u64()) {
        rp = rp.with_priority(p as u32);
    }
    if body
        .get("blocked")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        rp = rp.with_block(true);
    }
    let mut router = router.write().await;
    router.remove_route_pattern(id);
    router.add_route_pattern(rp);
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
    let Some(ref router) = state.cucm_router else {
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
    if let Some(desc) = body.get("description").and_then(|v| v.as_str()) {
        if !desc.is_empty() {
            rl = rl.with_description(desc);
        }
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
                .and_then(|v| v.as_u64())
                .map(|p| p as u32)
                .unwrap_or((idx + 1) as u32);
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
// (User Management handlers removed in PR10 — sbc-api owns /users CRUD,
// reading and writing PostgresUserStore directly.)
// (Phone Management + Phone Provisioning handlers removed in PR8 —
// sbc-api owns phone CRUD; sbc-provision owns /provision/<MAC>.{cfg,xml}.)
// ============================================================================

// ============================================================================
// (CUCM routing handlers removed in PR11 — sbc-api owns Postgres-
// backed CRUD for partitions, CSS, route patterns, and route lists;
// it notifies the daemon via CucmSyncService gRPC so the live
// CucmRouter catches up without a daemon restart.)
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

    #[tokio::test]
    async fn test_health_endpoint() {
        let server = test_server();
        let router = server.router();

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/system/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let server = test_server();
        let router = server.router();

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/system/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let content_type = response.headers().get("content-type").unwrap();
        assert!(content_type.to_str().unwrap().contains("text/plain"));
    }

    #[tokio::test]
    async fn test_stats_endpoint() {
        let server = test_server();
        let router = server.router();

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/system/stats")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_version_endpoint() {
        let server = test_server();
        let router = server.router();

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/system/version")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_calls_endpoint() {
        let server = test_server();
        let router = server.router();

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/calls")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_registrations_endpoint() {
        let server = test_server();
        let router = server.router();

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/registrations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_tls_status_endpoint() {
        let server = test_server();
        let router = server.router();

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/system/tls")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_tls_reload_endpoint_no_tls() {
        let server = test_server();
        let router = server.router();

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/system/tls/reload")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 400 when TLS is not enabled
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_default_config() {
        let config = ApiServerConfig::default();
        assert_eq!(config.listen_addr.port(), 8080);
        assert!(!config.enable_cors);
        assert_eq!(config.api_version, "v1");
    }
}
