//! sbc-provision-server — stand-alone phone provisioning HTTP pod.
//!
//! Serves `/provision/<MAC>.{cfg,xml}` (and the legacy bare-root path
//! `/<MAC>.{cfg,xml}` that some TEO firmwares hit pre-discovery) by
//! reading the phone record from Postgres and rendering the vendor-
//! specific config via `uc_phone_mgmt::ProvisioningServer`.
//!
//! Runs as its own pod so phone provisioning rolls and recovers
//! independently of the SIP-serving daemon. The daemon's old
//! `serve_phone_config` code path stays in place for now (PR6 doesn't
//! remove it) but stops being on the request path once the chart's
//! nginx routes `/provision/*` here.

use std::process::ExitCode;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use sbc_config_store::PostgresPhoneStore;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use uc_phone_mgmt::provisioning::ProvisioningServer;

mod config;

use config::Config;

#[derive(Clone)]
struct AppState {
    phones: Arc<PostgresPhoneStore>,
    provisioning: Arc<ProvisioningServer>,
    start_time: std::time::Instant,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sbc_provision_server=debug"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "sbc-provision-server starting"
    );

    let cfg = match Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "config error");
            return ExitCode::from(2);
        }
    };

    let phones = match PostgresPhoneStore::new(&cfg.database_url).await {
        Ok(p) => Arc::new(p),
        Err(e) => {
            error!(error = %e, "PostgresPhoneStore init failed");
            return ExitCode::from(3);
        }
    };

    let provisioning = Arc::new(ProvisioningServer::new(
        &cfg.provision_host,
        cfg.provision_port,
    ));
    info!(host = %cfg.provision_host, port = cfg.provision_port, "ProvisioningServer ready");

    let state = AppState {
        phones,
        provisioning,
        start_time: std::time::Instant::now(),
    };

    // Source-network restriction (defense in depth behind the Cilium
    // NetworkPolicy). Health/version probes come from the node, not the
    // phone subnet, so they bypass the check.
    let allowed = Arc::new(cfg.allowed_cidrs.clone());
    if allowed.is_empty() {
        info!(
            "SBC_PROVISION_ALLOWED_CIDRS unset — app-layer source restriction disabled (NetworkPolicy only)"
        );
    } else {
        info!(cidrs = ?allowed, "provisioning restricted to source networks");
    }

    let app = Router::new()
        .route("/healthz", get(liveness))
        .route("/readyz", get(readiness))
        .route("/system/version", get(version))
        // Canonical path used by phones after first boot (URL from the
        // rendered config's update_server field).
        .route("/provision/{*path}", get(serve_phone_config))
        // TEO global-config probe — daemon used to return 404 with a
        // specific body; same thing here so phones don't fall through
        // to nginx's SPA fallback.
        .route("/TCS7000A.xml", get(serve_teo_global))
        .layer(axum::middleware::from_fn_with_state(
            allowed,
            restrict_source,
        ))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = match tokio::net::TcpListener::bind(cfg.listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(addr = %cfg.listen_addr, error = %e, "bind failed");
            return ExitCode::from(4);
        }
    };
    info!(addr = %cfg.listen_addr, "listening");

    let shutdown = async {
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        #[cfg(unix)]
        let term = async {
            use tokio::signal::unix::{SignalKind, signal};
            if let Ok(mut s) = signal(SignalKind::terminate()) {
                s.recv().await;
            }
        };
        #[cfg(not(unix))]
        let term = std::future::pending::<()>();
        tokio::select! {
            () = ctrl_c => info!("SIGINT received, shutting down"),
            () = term => info!("SIGTERM received, shutting down"),
        }
    };

    if let Err(e) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        error!(error = %e, "server error");
        return ExitCode::from(5);
    }
    info!("clean shutdown");
    ExitCode::SUCCESS
}

/// Rejects provisioning requests whose originating client IP (from the
/// `X-Forwarded-For` header set by nginx) is outside the allowed source
/// networks. A no-op when no CIDRs are configured.
///
/// ## NIST 800-53 Rev5: SC-7 (Boundary Protection)
async fn restrict_source(
    axum::extract::State(allowed): axum::extract::State<Arc<Vec<ipnet::IpNet>>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if allowed.is_empty() {
        return next.run(req).await;
    }
    // Probes (kubelet) and version come from the node, not the phone
    // subnet — exempt them.
    let path = req.uri().path();
    if matches!(path, "/healthz" | "/readyz" | "/system/version") {
        return next.run(req).await;
    }

    let client_ip = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        // Leftmost entry is the originating client as nginx saw it.
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok());

    let permitted = client_ip.is_some_and(|ip| allowed.iter().any(|net| net.contains(&ip)));
    if permitted {
        return next.run(req).await;
    }

    warn!(
        ?client_ip,
        "provisioning request from disallowed source network"
    );
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({"error": "source network not permitted"})),
    )
        .into_response()
}

async fn liveness() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

async fn readiness(State(state): State<AppState>) -> impl IntoResponse {
    match state.phones.is_empty().await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({"status": "ready"}))),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "not_ready", "error": e.to_string()})),
        ),
    }
}

async fn version(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "service": "sbc-provision-server",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": state.start_time.elapsed().as_secs(),
    }))
}

async fn serve_teo_global() -> impl IntoResponse {
    // TEO spec p.19 — phones probe for a fleet-wide global file before
    // their per-MAC file. We don't ship a global; respond 404 with a
    // body distinct from the upstream proxy's "no such file" so phones
    // don't fall back to a cached config thinking the server's broken.
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(axum::body::Body::from(
            "No global Teo config served; per-MAC files only",
        ))
        .unwrap_or_default()
}

/// Serve a per-MAC phone provisioning config.
///
/// Logic is a faithful port of the daemon's old `serve_phone_config`
/// (`api_server.rs` in commits up to 0852812): extract MAC from filename,
/// normalize, look up phone by normalized MAC, render via vendor
/// generator, return with the right Content-Type per extension.
async fn serve_phone_config(State(state): State<AppState>, Path(path): Path<String>) -> Response {
    // Filename forms across vendors:
    //   <mac>.cfg           Polycom VVX/Edge
    //   <mac>.xml           Cisco MPP/9800
    //   <mac>-edge.cfg      Polycom Edge variant
    //   <MAC>.xml           Teo (uppercase mandated by spec)
    let filename = path.rsplit('/').next().unwrap_or(&path);
    let stem = filename.split('.').next().unwrap_or(filename);
    let mac_token = stem.split('-').next().unwrap_or(stem);
    let mac_key = mac_token.replace([':', '-'], "").to_lowercase();

    let phone = match state.phones.get_by_mac(&mac_key).await {
        Ok(p) => p,
        Err(sbc_config_store::ConfigStoreError::NotFound) => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(axum::body::Body::from(format!(
                    "No phone record for MAC {mac_key}"
                )))
                .unwrap_or_default();
        }
        Err(e) => {
            warn!(mac = %mac_key, error = %e, "phone lookup failed");
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::from(format!(
                    "phone store lookup failed: {e}"
                )))
                .unwrap_or_default();
        }
    };

    match state.provisioning.generate_config(&phone) {
        Ok(config_text) => {
            let ct = if filename.to_ascii_lowercase().ends_with(".xml") {
                "application/xml"
            } else {
                "text/plain"
            };
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", ct)
                .body(axum::body::Body::from(config_text))
                .unwrap_or_default()
        }
        Err(e) => Response::builder()
            .status(StatusCode::UNPROCESSABLE_ENTITY)
            .body(axum::body::Body::from(format!(
                "Cannot generate config: {e}"
            )))
            .unwrap_or_default(),
    }
}
