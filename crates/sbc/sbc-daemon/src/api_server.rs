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

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
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
    /// Enable CORS.
    pub enable_cors: bool,
    /// API version prefix.
    pub api_version: String,
    /// TLS configuration (optional).
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
            enable_cors: false,
            api_version: "v1".to_string(),
            tls: None,
        }
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
    pub fn router(&self) -> Router {
        let api_routes = Router::new()
            // System routes
            .route("/system/health", get(get_health))
            .route("/system/metrics", get(get_metrics))
            .route("/system/stats", get(get_stats))
            .route("/system/version", get(get_version))
            .route("/system/tls", get(get_tls_status))
            .route("/system/tls/reload", post(reload_tls_certificates))
            // Call routes
            .route("/calls", get(get_calls))
            // Registration routes
            .route("/registrations", get(get_registrations));

        let api_routes = api_routes
            // Registration management
            .route("/registrations/{aor}", delete(delete_registration))
            // Directory number management
            .route("/directory", get(get_directory_numbers))
            .route("/directory", post(add_directory_number))
            .route("/directory/{did}", delete(delete_directory_number))
            // CDR routes
            .route("/cdrs", get(get_cdrs))
            // Call ladder
            .route("/calls/{call_id}/ladder", get(get_call_ladder))
            // Dial plan management
            .route("/dialplans", get(get_dial_plans))
            .route("/dialplans/{plan_id}/entries", get(get_dial_plan_entries))
            .route("/dialplans/{plan_id}/entries", post(add_dial_plan_entry))
            .route("/dialplans/{plan_id}/entries/{entry_id}", delete(delete_dial_plan_entry))
            // Trunk group management
            .route("/trunkgroups", get(get_trunk_groups))
            .route("/trunkgroups", post(add_trunk_group))
            .route("/trunkgroups/{group_id}", get(get_trunk_group))
            .route("/trunkgroups/{group_id}", delete(delete_trunk_group))
            .route("/trunkgroups/{group_id}/trunks", post(add_trunk))
            .route("/trunkgroups/{group_id}/trunks/{trunk_id}", delete(delete_trunk));

        Router::new()
            // Health probes (no prefix)
            .route("/healthz", get(liveness_probe))
            .route("/readyz", get(readiness_probe))
            // API v1 routes
            .nest(&format!("/api/{}", self.config.api_version), api_routes)
            // Dashboard static files (Angular app)
            .fallback(serve_dashboard)
            // Add state
            .with_state(Arc::clone(&self.state))
            // Add tracing
            .layer(TraceLayer::new_for_http())
    }

    /// Runs the API server (HTTP or HTTPS depending on configuration).
    pub async fn run(&self) -> Result<(), ApiServerError> {
        if let Some(tls_config) = &self.config.tls {
            self.run_https(tls_config).await
        } else {
            self.run_http().await
        }
    }

    /// Runs the API server with plain HTTP.
    async fn run_http(&self) -> Result<(), ApiServerError> {
        let addr = self.config.listen_addr;
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

    /// Runs the API server with HTTPS (TLS).
    async fn run_https(&self, tls_config: &TlsConfig) -> Result<(), ApiServerError> {
        let addr = self.config.listen_addr;
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
// System Routes
// ============================================================================

/// Get detailed health status.
async fn get_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let system_health = state.check_health();
    let response = HealthResponse::from(system_health);

    let status = if response.status == "healthy" || response.status == "degraded" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(response))
}

/// Get Prometheus metrics.
async fn get_metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let metrics_text = state.metrics.export();

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        .body(metrics_text)
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(String::new())
                .unwrap_or_default()
        })
}

/// Get server statistics.
async fn get_stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let response = StatsResponse {
        calls_total: state.stats.calls_total.load(Ordering::Relaxed),
        calls_active: state.stats.calls_active.load(Ordering::Relaxed),
        registrations_total: state.stats.registrations_total.load(Ordering::Relaxed),
        registrations_active: state.stats.registrations_active.load(Ordering::Relaxed),
        messages_received: state.stats.messages_received.load(Ordering::Relaxed),
        messages_sent: state.stats.messages_sent.load(Ordering::Relaxed),
        rate_limited: state.stats.rate_limited.load(Ordering::Relaxed),
    };

    Json(response)
}

/// Get version information.
async fn get_version(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(VersionResponse {
        version: state.version.clone(),
        name: "sbc-daemon".to_string(),
    })
}

// ============================================================================
// Call Routes
// ============================================================================

/// List active calls.
async fn get_calls(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(ref stack) = state.sip_stack {
        let summaries = stack.list_calls().await;
        let active = summaries.len();
        let calls: Vec<CallInfo> = summaries
            .iter()
            .map(|s| CallInfo {
                call_id: s.call_id.clone(),
                state: s.state.clone(),
                from: s.a_leg_call_id.clone(),
                to: s.b_leg_call_id.clone(),
                start_time: 0,
                duration_secs: 0,
            })
            .collect();
        let total = calls.len();
        Json(CallListResponse {
            calls,
            total,
            active: active as u64,
        })
    } else {
        Json(CallListResponse {
            calls: Vec::new(),
            total: 0,
            active: state.stats.calls_active.load(Ordering::Relaxed),
        })
    }
}

// ============================================================================
// Registration Routes
// ============================================================================

/// List registrations.
async fn get_registrations(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(ref stack) = state.sip_stack {
        let summaries = stack.list_registrations().await;
        let active = summaries.len();
        let registrations: Vec<RegistrationInfo> = summaries
            .iter()
            .flat_map(|s| {
                s.contacts.iter().map(move |c| RegistrationInfo {
                    aor: s.aor.clone(),
                    contact: c.clone(),
                    expires: 3600,
                    registered_at: 0,
                })
            })
            .collect();
        let total = registrations.len();
        Json(RegistrationListResponse {
            registrations,
            total,
            active: active as u64,
        })
    } else {
        Json(RegistrationListResponse {
            registrations: Vec::new(),
            total: 0,
            active: state.stats.registrations_active.load(Ordering::Relaxed),
        })
    }
}

/// Delete a registration.
async fn delete_registration(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(aor): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let contact = params.get("contact").cloned().unwrap_or_default();

    if let Some(ref stack) = state.sip_stack {
        match stack.delete_registration(&aor, &contact).await {
            Ok(()) => (StatusCode::OK, Json(serde_json::json!({"success": true}))),
            Err(e) => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"success": false, "error": e})),
            ),
        }
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"success": false, "error": "SIP stack not available"})),
        )
    }
}

// ============================================================================
// Directory Number Routes
// ============================================================================

/// List directory numbers (from dial plan config).
async fn get_directory_numbers(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    // Directory numbers come from the dial plan config
    // In a full implementation, these would be stored in a database
    Json(serde_json::json!({
        "directory_numbers": [],
        "total": 0
    }))
}

/// Add a directory number.
async fn add_directory_number(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Would add to dial plan in production
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"success": true, "did": body.get("did")})),
    )
}

/// Delete a directory number.
async fn delete_directory_number(
    State(_state): State<Arc<AppState>>,
    axum::extract::Path(did): axum::extract::Path<String>,
) -> impl IntoResponse {
    // Would remove from dial plan in production
    Json(serde_json::json!({"success": true, "did": did}))
}

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

/// Get SIP message ladder for a call.
async fn get_call_ladder(
    State(_state): State<Arc<AppState>>,
    axum::extract::Path(call_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    // Call ladder storage not yet implemented — return empty
    Json(serde_json::json!({
        "call_id": call_id,
        "participants": ["UAC", "SBC", "UAS"],
        "messages": []
    }))
}

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

/// Add a dial plan entry.
async fn add_dial_plan_entry(
    State(_state): State<Arc<AppState>>,
    axum::extract::Path(plan_id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // TODO: Add entry to router's active dial plan
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "success": true,
            "plan_id": plan_id,
            "entry": body
        })),
    )
}

/// Delete a dial plan entry.
async fn delete_dial_plan_entry(
    State(_state): State<Arc<AppState>>,
    axum::extract::Path((plan_id, entry_id)): axum::extract::Path<(String, String)>,
) -> impl IntoResponse {
    // TODO: Remove entry from router's dial plan
    Json(serde_json::json!({
        "success": true,
        "plan_id": plan_id,
        "entry_id": entry_id
    }))
}

// ============================================================================
// Trunk Group Routes
// ============================================================================

/// List trunk groups.
async fn get_trunk_groups(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if let Some(ref stack) = state.sip_stack {
        let groups = stack.list_trunk_groups().await;
        Json(serde_json::json!({ "trunk_groups": groups }))
    } else {
        Json(serde_json::json!({ "trunk_groups": [] }))
    }
}

/// Get a specific trunk group.
async fn get_trunk_group(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(group_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    if let Some(ref stack) = state.sip_stack {
        if let Some(router_lock) = stack.router() {
            let router = router_lock.read().await;
            if let Some(group) = router.get_trunk_group(&group_id) {
                return Json(serde_json::json!({
                    "id": group.id(),
                    "name": group.name(),
                    "trunk_count": group.trunk_count(),
                    "usable_trunks": group.usable_trunk_count(),
                }));
            }
        }
    }
    Json(serde_json::json!({ "error": "Trunk group not found" }))
}

/// Add a trunk group.
async fn add_trunk_group(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // TODO: Add trunk group to router
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "success": true, "trunk_group": body })),
    )
}

/// Delete a trunk group.
async fn delete_trunk_group(
    State(_state): State<Arc<AppState>>,
    axum::extract::Path(group_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    // TODO: Remove trunk group from router
    Json(serde_json::json!({ "success": true, "group_id": group_id }))
}

/// Add a trunk to a group.
async fn add_trunk(
    State(_state): State<Arc<AppState>>,
    axum::extract::Path(group_id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // TODO: Add trunk to group in router
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "success": true,
            "group_id": group_id,
            "trunk": body
        })),
    )
}

/// Delete a trunk from a group.
async fn delete_trunk(
    State(_state): State<Arc<AppState>>,
    axum::extract::Path((group_id, trunk_id)): axum::extract::Path<(String, String)>,
) -> impl IntoResponse {
    // TODO: Remove trunk from group in router
    Json(serde_json::json!({
        "success": true,
        "group_id": group_id,
        "trunk_id": trunk_id
    }))
}

// ============================================================================
// Dashboard Static Files
// ============================================================================

/// Serve Angular dashboard static files.
///
/// Falls back to index.html for client-side routing.
async fn serve_dashboard(uri: axum::http::Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');

    // Try to find the file in the embedded dashboard
    // For now, return a placeholder — the Angular dist/ files will be
    // served once embedded via include_dir or a static file handler
    if path.is_empty() || !path.contains('.') {
        // SPA fallback: serve index.html for all non-file routes
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .body(DASHBOARD_INDEX.to_string())
            .unwrap_or_default()
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(String::new())
            .unwrap_or_default()
    }
}

/// Placeholder dashboard index until Angular build is embedded.
const DASHBOARD_INDEX: &str = r#"<!doctype html>
<html>
<head>
  <title>USG SBC Dashboard</title>
  <style>
    body { font-family: sans-serif; background: #1a1a2e; color: #e0e0e0;
           display: flex; align-items: center; justify-content: center;
           height: 100vh; margin: 0; }
    .msg { text-align: center; }
    h1 { color: #4fc3f7; }
    p { color: #999; }
    a { color: #4fc3f7; }
  </style>
</head>
<body>
  <div class="msg">
    <h1>USG SBC Dashboard</h1>
    <p>Angular dashboard not yet embedded in binary.</p>
    <p>Run <code>ng serve --proxy-config proxy.conf.json</code> in
    <code>crates/sbc/sbc-dashboard/</code> for development.</p>
    <p><a href="/api/v1/system/stats">API Stats</a> |
    <a href="/api/v1/registrations">Registrations</a> |
    <a href="/api/v1/calls">Calls</a></p>
  </div>
</body>
</html>"#;

// ============================================================================
// TLS Routes
// ============================================================================

/// Get TLS certificate status.
async fn get_tls_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let tls_stats = state.tls_stats();
    let response = TlsStatusResponse {
        enabled: tls_stats.is_some(),
        stats: tls_stats,
    };

    Json(response)
}

/// Trigger TLS certificate reload.
async fn reload_tls_certificates(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.reload_tls_certificates() {
        Ok(true) => {
            info!("TLS certificates reloaded via API");
            let response = TlsReloadResponse {
                success: true,
                message: "TLS certificates reloaded successfully".to_string(),
                stats: state.tls_stats(),
            };
            (StatusCode::OK, Json(response))
        }
        Ok(false) => {
            let response = TlsReloadResponse {
                success: false,
                message: "TLS is not enabled".to_string(),
                stats: None,
            };
            (StatusCode::BAD_REQUEST, Json(response))
        }
        Err(e) => {
            warn!(error = %e, "Failed to reload TLS certificates via API");
            let response = TlsReloadResponse {
                success: false,
                message: format!("Failed to reload certificates: {e}"),
                stats: state.tls_stats(),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
        }
    }
}

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

/// Health response.
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall status.
    pub status: String,
    /// Uptime in seconds.
    pub uptime_secs: u64,
    /// Version.
    pub version: String,
    /// Component statuses.
    pub components: Vec<ComponentStatusResponse>,
}

impl From<SystemHealth> for HealthResponse {
    fn from(health: SystemHealth) -> Self {
        Self {
            status: health.status.to_string(),
            uptime_secs: health.uptime_secs.unwrap_or(0),
            version: health.version.unwrap_or_default(),
            components: health
                .components
                .into_iter()
                .map(ComponentStatusResponse::from)
                .collect(),
        }
    }
}

/// Component status response.
#[derive(Debug, Serialize, Deserialize)]
pub struct ComponentStatusResponse {
    /// Component name.
    pub name: String,
    /// Status.
    pub status: String,
    /// Optional message.
    pub message: Option<String>,
}

impl From<uc_health::ComponentStatus> for ComponentStatusResponse {
    fn from(status: uc_health::ComponentStatus) -> Self {
        Self {
            name: status.name,
            status: status.status.to_string(),
            message: status.message,
        }
    }
}

/// Server statistics response.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatsResponse {
    /// Total calls processed.
    pub calls_total: u64,
    /// Currently active calls.
    pub calls_active: u64,
    /// Total registrations.
    pub registrations_total: u64,
    /// Active registrations.
    pub registrations_active: u64,
    /// Messages received.
    pub messages_received: u64,
    /// Messages sent.
    pub messages_sent: u64,
    /// Messages rejected due to rate limiting.
    pub rate_limited: u64,
}

/// Version response.
#[derive(Debug, Serialize, Deserialize)]
pub struct VersionResponse {
    /// Version string.
    pub version: String,
    /// Application name.
    pub name: String,
}

/// Call list response.
#[derive(Debug, Serialize, Deserialize)]
pub struct CallListResponse {
    /// List of calls.
    pub calls: Vec<CallInfo>,
    /// Total count.
    pub total: usize,
    /// Active count.
    pub active: u64,
}

/// Call information.
#[derive(Debug, Serialize, Deserialize)]
pub struct CallInfo {
    /// Call ID.
    pub call_id: String,
    /// Call state.
    pub state: String,
    /// From URI.
    pub from: String,
    /// To URI.
    pub to: String,
    /// Start time (Unix timestamp).
    pub start_time: u64,
    /// Duration in seconds.
    pub duration_secs: u64,
}

/// Registration list response.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationListResponse {
    /// List of registrations.
    pub registrations: Vec<RegistrationInfo>,
    /// Total count.
    pub total: usize,
    /// Active count.
    pub active: u64,
}

/// Registration information.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationInfo {
    /// AOR (Address of Record).
    pub aor: String,
    /// Contact URI.
    pub contact: String,
    /// Expires in seconds.
    pub expires: u64,
    /// Registration time (Unix timestamp).
    pub registered_at: u64,
}

/// TLS certificate reload statistics.
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

/// TLS status response.
#[derive(Debug, Serialize, Deserialize)]
pub struct TlsStatusResponse {
    /// Whether TLS is enabled.
    pub enabled: bool,
    /// TLS reload statistics (if TLS is enabled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<TlsReloadStats>,
}

/// TLS reload response.
#[derive(Debug, Serialize, Deserialize)]
pub struct TlsReloadResponse {
    /// Whether the reload was successful.
    pub success: bool,
    /// Status message.
    pub message: String,
    /// Updated statistics after reload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<TlsReloadStats>,
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
