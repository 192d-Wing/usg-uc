//! Health + version endpoints (local to the sbc-api pod) plus
//! daemon-system passthroughs (`/system/stats`, `/system/metrics`,
//! `/system/tls`, `/system/tls/reload`) that proxy to the daemon's
//! `SystemService` gRPC instead of HTTP-reverse-proxying.
//!
//! `/healthz` and `/readyz` deliberately answer for *sbc-api*, not the
//! daemon. Kubelet probes hit the pod that's actually serving the
//! probe; if you want the daemon's health, query the daemon pod
//! directly. `/system/version` reports sbc-api's version; the daemon's
//! version is fetched separately via `/system/daemon-version` so
//! operators can see both side by side.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sbc_grpc_api::prelude::{
    GetMetricsRequest, GetStatsRequest, GetTlsStatusRequest, GetVersionRequest, ReloadTlsRequest,
};
use tracing::warn;

use crate::state::AppState;

pub async fn liveness() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

/// Readiness checks Postgres reachability via a cheap `is_empty()` call
/// against an arbitrary store. If Postgres is down, sbc-api is useless
/// and should be pulled from the LB rotation.
pub async fn readiness(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.phones.is_empty().await {
        Ok(_) => (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({"status": "ready"})),
        ),
        Err(e) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "not_ready", "error": e.to_string()})),
        ),
    }
}

pub async fn version(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(serde_json::json!({
        "service": "sbc-api-server",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": state.start_time.elapsed().as_secs(),
    }))
}

/// Daemon version via gRPC. Reachable at `/api/v1/system/daemon-version`.
pub async fn daemon_version(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut client = state.system.clone();
    match client.get_version(GetVersionRequest::default()).await {
        Ok(resp) => {
            let r = resp.into_inner();
            Json(serde_json::json!({
                "service": "sbc-daemon",
                "version": r.version,
                "name": r.name,
                "build_time": r.build_time,
                "git_commit": r.git_commit,
                "git_branch": r.git_branch,
                "rust_version": r.rust_version,
                "release_build": r.release_build,
            }))
        }
        Err(status) => {
            warn!(error = %status, "SystemService.GetVersion failed");
            Json(serde_json::json!({"error": status.message()}))
        }
    }
}

/// Daemon health summary for the dashboard's health card
/// (`/api/v1/system/health`): `status` reflects whether the daemon
/// answers on its `SystemService` gRPC, `uptime_seconds` comes from its
/// stats. Always 200 — "degraded" is a payload, not a transport error,
/// so the panel can render it.
pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut client = state.system.clone();
    match client.get_stats(GetStatsRequest::default()).await {
        Ok(resp) => {
            let r = resp.into_inner();
            Json(serde_json::json!({
                "status": "healthy",
                "uptime_seconds": r.uptime_secs,
            }))
        }
        Err(status) => {
            warn!(error = %status, "SystemService.GetStats failed for health");
            Json(serde_json::json!({
                "status": "degraded",
                "error": status.message(),
            }))
        }
    }
}

pub async fn stats(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut client = state.system.clone();
    match client.get_stats(GetStatsRequest::default()).await {
        Ok(resp) => {
            let r = resp.into_inner();
            Json(serde_json::json!({
                "uptime_secs": r.uptime_secs,
                "calls_total": r.calls_total,
                "calls_active": r.calls_active,
                "registrations_total": r.registrations_total,
                "registrations_active": r.registrations_active,
                "messages_received": r.messages_received,
                "messages_sent": r.messages_sent,
                "rate_limited": r.rate_limited,
            }))
        }
        Err(status) => {
            warn!(error = %status, "SystemService.GetStats failed");
            Json(serde_json::json!({"error": status.message()}))
        }
    }
}

/// Prometheus exposition format. Returns the daemon's metrics body
/// verbatim with `text/plain; version=0.0.4` so Prometheus scrapers
/// don't choke on a wrapped JSON shape.
pub async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let mut client = state.system.clone();
    match client.get_metrics(GetMetricsRequest::default()).await {
        Ok(resp) => {
            let r = resp.into_inner();
            let content_type = if r.content_type.is_empty() {
                "text/plain; version=0.0.4".to_string()
            } else {
                r.content_type
            };
            Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", content_type)
                .body(axum::body::Body::from(r.metrics))
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(status) => {
            warn!(error = %status, "SystemService.GetMetrics failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": status.message()})),
            )
                .into_response()
        }
    }
}

pub async fn tls_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut client = state.system.clone();
    match client.get_tls_status(GetTlsStatusRequest::default()).await {
        Ok(resp) => {
            let r = resp.into_inner();
            let enabled = r.enabled;
            let status_obj = r.status.map_or_else(
                || serde_json::json!(null),
                |s| {
                    serde_json::json!({
                        "cert_path": s.cert_path,
                        "key_path": s.key_path,
                        "cert_subject": s.cert_subject,
                        "cert_issuer": s.cert_issuer,
                        "cert_serial": s.cert_serial,
                        "days_until_expiry": s.days_until_expiry,
                        "reload_count": s.reload_count,
                        "tls_version": s.tls_version,
                        "cipher_suite": s.cipher_suite,
                        "cnsa_compliant": s.cnsa_compliant,
                    })
                },
            );
            Json(serde_json::json!({"enabled": enabled, "tls": status_obj}))
        }
        Err(status) => {
            warn!(error = %status, "SystemService.GetTlsStatus failed");
            Json(serde_json::json!({"error": status.message()}))
        }
    }
}

pub async fn tls_reload(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut client = state.system.clone();
    match client.reload_tls(ReloadTlsRequest::default()).await {
        Ok(resp) => {
            let r = resp.into_inner();
            Json(serde_json::json!({
                "success": r.success,
                "message": r.message,
            }))
        }
        Err(status) => {
            warn!(error = %status, "SystemService.ReloadTls failed");
            Json(serde_json::json!({
                "success": false,
                "error": status.message(),
            }))
        }
    }
}
