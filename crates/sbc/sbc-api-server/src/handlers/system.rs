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
///
/// Also not ready when the audit writer has died or the audit sink is
/// failing writes (e.g. disk full): CDR exports and permission denials
/// would go unrecorded (NIST 800-53 Rev5: AU-5).
pub async fn readiness(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let audit_ok = audit_ready(&uc_audit::stats());
    if !audit_ok {
        warn!("readiness: audit pipeline not persisting records");
        return readiness_response::<()>(false, &Ok(()));
    }
    let db = state.phones.is_empty().await.map(|_| ());
    if let Err(e) = &db {
        warn!(error = %e, "readiness: postgres check failed");
    }
    readiness_response(audit_ok, &db)
}

/// Audit half of readiness: writer running and the sink persisting.
///
/// NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
const fn audit_ready(stats: &uc_audit::AuditStats) -> bool {
    stats.writer_alive && !stats.sink_failing
}

/// Status + body for `/readyz`. Unauthenticated endpoint: the backend error
/// never reaches the body, only the log (done by the caller).
///
/// NIST 800-53 Rev5: SI-11 (Error Handling)
fn readiness_response<E>(
    audit_ok: bool,
    db: &Result<(), E>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    if audit_ok && db.is_ok() {
        (
            axum::http::StatusCode::OK,
            Json(serde_json::json!({"status": "ready"})),
        )
    } else {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "not_ready"})),
        )
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod readiness_tests {
    use super::*;

    #[test]
    fn not_ready_body_carries_no_backend_detail() {
        let secret = "connection to 10.0.0.5:5432 refused for user sbc password=hunter2";
        for (audit_ok, db) in [(true, Err(secret)), (false, Ok(())), (false, Err(secret))] {
            let (code, Json(body)) = readiness_response(audit_ok, &db);
            assert_eq!(code, axum::http::StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(body, serde_json::json!({"status": "not_ready"}));
        }
        let (code, Json(body)) = readiness_response::<&str>(true, &Ok(()));
        assert_eq!(code, axum::http::StatusCode::OK);
        assert_eq!(body, serde_json::json!({"status": "ready"}));
    }

    #[test]
    fn not_ready_when_audit_sink_failing() {
        let ok = uc_audit::AuditStats {
            writer_alive: true,
            ..uc_audit::AuditStats::default()
        };
        assert!(audit_ready(&ok));
        let failing = uc_audit::AuditStats {
            sink_failing: true,
            write_failures: 1,
            ..ok
        };
        assert!(!audit_ready(&failing));
        let (code, _) = readiness_response::<&str>(audit_ready(&failing), &Ok(()));
        assert_eq!(code, axum::http::StatusCode::SERVICE_UNAVAILABLE);
        let dead = uc_audit::AuditStats {
            writer_alive: false,
            ..ok
        };
        assert!(!audit_ready(&dead));
    }
}
