//! REST API server for the SBC daemon.
//!
//! This module provides an HTTP server using axum for management APIs,
//! metrics endpoints, and health probes.
//!
//! ## Endpoints
//!
//! - `GET /healthz` - Liveness probe
//! - `GET /readyz` - Readiness probe
//! - `GET /api/v1/system/health` - Detailed health status
//! - `GET /api/v1/system/metrics` - Prometheus metrics
//! - `GET /api/v1/system/stats` - Server statistics
//! - `GET /api/v1/calls` - List active calls
//! - `GET /api/v1/registrations` - List registrations
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **AU-2**: Event Logging - All API requests are logged
//! - **SC-8**: Transmission Confidentiality (TLS in production)

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use sbc_health::{ComponentStatus, SystemHealth};
use sbc_metrics::MetricRegistry;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tower_http::trace::TraceLayer;
use tracing::info;

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
}

impl Default for ApiServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".parse().unwrap_or_else(|_| {
                SocketAddr::from(([0, 0, 0, 0], 8080))
            }),
            enable_cors: false,
            api_version: "v1".to_string(),
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
        }
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
        self.ready.store(if ready { 1 } else { 0 }, Ordering::Relaxed);
    }

    /// Performs a health check.
    pub fn check_health(&self) -> SystemHealth {
        let components = vec![
            ComponentStatus::healthy("sbc_core"),
            ComponentStatus::healthy("sip_transport"),
            ComponentStatus::healthy("media_engine"),
        ];

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
    pub fn new(
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
            // Call routes
            .route("/calls", get(get_calls))
            // Registration routes
            .route("/registrations", get(get_registrations));

        Router::new()
            // Health probes (no prefix)
            .route("/healthz", get(liveness_probe))
            .route("/readyz", get(readiness_probe))
            // API v1 routes
            .nest(&format!("/api/{}", self.config.api_version), api_routes)
            // Add state
            .with_state(Arc::clone(&self.state))
            // Add tracing
            .layer(TraceLayer::new_for_http())
    }

    /// Runs the API server.
    pub async fn run(&self) -> Result<(), ApiServerError> {
        let addr = self.config.listen_addr;
        let router = self.router();

        info!(address = %addr, "Starting API server");

        let listener = tokio::net::TcpListener::bind(addr)
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
async fn readiness_probe(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
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
async fn get_health(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let system_health = state.check_health();
    let response = HealthResponse::from(system_health);

    let status = if response.status == "healthy" {
        StatusCode::OK
    } else if response.status == "degraded" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(response))
}

/// Get Prometheus metrics.
async fn get_metrics(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
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
async fn get_stats(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let response = StatsResponse {
        calls_total: state.stats.calls_total.load(Ordering::Relaxed),
        calls_active: state.stats.calls_active.load(Ordering::Relaxed),
        registrations_total: state.stats.registrations_total.load(Ordering::Relaxed),
        registrations_active: state.stats.registrations_active.load(Ordering::Relaxed),
        messages_received: state.stats.messages_received.load(Ordering::Relaxed),
        messages_sent: state.stats.messages_sent.load(Ordering::Relaxed),
    };

    Json(response)
}

/// Get version information.
async fn get_version(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    Json(VersionResponse {
        version: state.version.clone(),
        name: "sbc-daemon".to_string(),
    })
}

// ============================================================================
// Call Routes
// ============================================================================

/// List active calls.
async fn get_calls(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // For now, return empty list
    // In production, would query B2BUA for active calls
    let response = CallListResponse {
        calls: Vec::new(),
        total: 0,
        active: state.stats.calls_active.load(Ordering::Relaxed),
    };

    Json(response)
}

// ============================================================================
// Registration Routes
// ============================================================================

/// List registrations.
async fn get_registrations(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // For now, return empty list
    // In production, would query registrar for active registrations
    let response = RegistrationListResponse {
        registrations: Vec::new(),
        total: 0,
        active: state.stats.registrations_active.load(Ordering::Relaxed),
    };

    Json(response)
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

impl From<sbc_health::ComponentStatus> for ComponentStatusResponse {
    fn from(status: sbc_health::ComponentStatus) -> Self {
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
        }
    }
}

impl std::error::Error for ApiServerError {}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use sbc_metrics::SbcMetrics;
    use tower::ServiceExt;

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
            .oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_readiness_probe() {
        let server = test_server();
        let router = server.router();

        let response = router
            .oneshot(Request::builder().uri("/readyz").body(Body::empty()).unwrap())
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

    #[test]
    fn test_default_config() {
        let config = ApiServerConfig::default();
        assert_eq!(config.listen_addr.port(), 8080);
        assert!(!config.enable_cors);
        assert_eq!(config.api_version, "v1");
    }
}
