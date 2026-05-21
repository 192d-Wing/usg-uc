//! Local health + version endpoints. These are the pod's own probes —
//! they answer for sbc-api's liveness, not the daemon's.

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;

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
