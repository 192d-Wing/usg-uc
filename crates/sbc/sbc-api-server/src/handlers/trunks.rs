//! `/trunk-health` and `/trunk-registration` handlers backed by the
//! daemon's `TrunkHealthService` gRPC. Replaces the HTTP-proxy
//! fallback for these read paths so the daemon's REST endpoints can
//! be removed.
//!
//! Response shapes match what the daemon used to emit:
//!   GET /trunk-health           → {"trunk_health":[…]}
//!   GET /trunk-registration     → {"trunk_registrations":[…]}
//!   POST /trunk-registration/{id}/register → {"success":bool, "message":…}

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sbc_grpc_api::prelude::{
    ListTrunkHealthRequest, ListTrunkRegistrationsRequest, RegisterTrunkRequest,
};
use tracing::warn;

use crate::state::AppState;

pub async fn list_health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut client = state.trunk_health.clone();
    match client.list_trunk_health(ListTrunkHealthRequest {}).await {
        Ok(resp) => {
            let trunks: Vec<serde_json::Value> = resp
                .into_inner()
                .trunks
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "trunk_id": t.trunk_id,
                        "reachable": t.reachable,
                        "last_response_ms": t.last_response_ms,
                        "last_success": t.last_success_epoch,
                        "last_failure": t.last_failure_epoch,
                        "consecutive_success": t.consecutive_success,
                        "consecutive_failures": t.consecutive_failures,
                        "total_pings": t.total_pings,
                        "total_success": t.total_success,
                        "uptime_pct": t.uptime_pct,
                        "in_service_since": t.in_service_since_epoch,
                    })
                })
                .collect();
            Json(serde_json::json!({ "trunk_health": trunks }))
        }
        Err(status) => {
            warn!(error = %status, "TrunkHealthService.ListTrunkHealth failed");
            Json(serde_json::json!({
                "trunk_health": [],
                "error": status.message(),
            }))
        }
    }
}

pub async fn list_registrations(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut client = state.trunk_health.clone();
    match client
        .list_trunk_registrations(ListTrunkRegistrationsRequest {})
        .await
    {
        Ok(resp) => {
            let trunks: Vec<serde_json::Value> = resp
                .into_inner()
                .trunks
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "trunk_id": t.trunk_id,
                        "registered": t.registered,
                        "state": t.state,
                        "registrar": t.registrar,
                        "username": t.username,
                        "last_registered": t.last_registered_epoch,
                        "last_error": t.last_error,
                        "expires": t.expires_secs,
                        "attempts": t.attempts,
                        "successes": t.successes,
                    })
                })
                .collect();
            Json(serde_json::json!({ "trunk_registrations": trunks }))
        }
        Err(status) => {
            warn!(error = %status, "TrunkHealthService.ListTrunkRegistrations failed");
            Json(serde_json::json!({
                "trunk_registrations": [],
                "error": status.message(),
            }))
        }
    }
}

pub async fn register(
    State(state): State<Arc<AppState>>,
    Path(trunk_id): Path<String>,
) -> impl IntoResponse {
    let mut client = state.trunk_health.clone();
    match client
        .register_trunk(RegisterTrunkRequest {
            trunk_id: trunk_id.clone(),
        })
        .await
    {
        Ok(resp) => {
            let r = resp.into_inner();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": r.success,
                    "message": r.message,
                    "trunk_id": trunk_id,
                })),
            )
        }
        Err(status) => {
            warn!(trunk_id, error = %status, "TrunkHealthService.RegisterTrunk failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "success": false,
                    "error": status.message(),
                    "trunk_id": trunk_id,
                })),
            )
        }
    }
}
