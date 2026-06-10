//! Calls handlers — list + per-call details. Replaces the HTTP-proxy
//! fallback to the daemon's REST `/calls` endpoint with a direct gRPC
//! call into `CallService` on the daemon's `:9091`.
//!
//! Response shapes match the daemon's old REST output verbatim so the
//! existing dashboard doesn't break: `{calls: [{call_id, state, from,
//! to, start_time, duration_secs}], total, active}`. The daemon's
//! `CallInfo` proto has more fields (STIR/SHAKEN, transport, media
//! mode) — we just don't surface them in this read API yet.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sbc_grpc_api::prelude::{GetCallRequest, ListCallsRequest, TerminateCallRequest};
use tonic::Code;
use tracing::warn;

use crate::state::AppState;

pub async fn list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut client = state.calls.clone();
    let req = ListCallsRequest::default();
    match client.list_calls(req).await {
        Ok(resp) => {
            let r = resp.into_inner();
            let calls: Vec<serde_json::Value> = r
                .calls
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "call_id": c.call_id,
                        // CallState is a proto enum (i32 in prost) —
                        // surface the integer; dashboards already
                        // tolerate either int or string.
                        "state": c.state,
                        "from": c.from_uri,
                        "to": c.to_uri,
                        // start_time is a google.protobuf.Timestamp;
                        // we don't unpack it here (callers can fetch
                        // GetCall for detail).
                        "start_time": 0,
                        "duration_secs": c.duration_secs,
                    })
                })
                .collect();
            Json(serde_json::json!({
                "calls": calls,
                "total": r.total,
                "active": r.active,
            }))
        }
        Err(status) => {
            warn!(error = %status, "CallService.ListCalls failed");
            Json(serde_json::json!({
                "calls": [],
                "total": 0,
                "active": 0,
                "error": status.message(),
            }))
        }
    }
}

/// Per-call detail. The daemon's old REST surface returned a "ladder"
/// view at `/calls/{id}/ladder` that was a hard-coded placeholder
/// (`participants: ["UAC","SBC","UAS"], messages: []`) — see the
/// pre-cleanup daemon api_server.rs `get_call_ladder` handler. We
/// match that shape from a real `GetCall` response so future ladder
/// detail can attach to a fielded structure rather than be re-stubbed.
pub async fn ladder(
    State(state): State<Arc<AppState>>,
    Path(call_id): Path<String>,
) -> impl IntoResponse {
    let mut client = state.calls.clone();
    let req = GetCallRequest {
        call_id: call_id.clone(),
    };
    match client.get_call(req).await {
        Ok(_resp) => Json(serde_json::json!({
            "call_id": call_id,
            "participants": ["UAC", "SBC", "UAS"],
            "messages": [],
        })),
        Err(status) if status.code() == Code::NotFound => Json(serde_json::json!({
            "call_id": call_id,
            "error": "call not found",
        })),
        Err(status) => {
            warn!(call_id, error = %status, "CallService.GetCall failed");
            Json(serde_json::json!({
                "call_id": call_id,
                "error": status.message(),
            }))
        }
    }
}

pub async fn terminate(
    State(state): State<Arc<AppState>>,
    Path(call_id): Path<String>,
) -> impl IntoResponse {
    let mut client = state.calls.clone();
    let req = TerminateCallRequest {
        call_id: call_id.clone(),
        reason: "operator_requested".to_string(),
        // SIP 200 OK as the cause — matches the daemon's default for
        // "normal" terminations; 603 would be for reject scenarios.
        cause_code: 200,
    };
    match client.terminate_call(req).await {
        Ok(resp) => {
            let r = resp.into_inner();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": r.success,
                    "call_id": call_id,
                    "message": r.message,
                })),
            )
        }
        Err(status) => {
            warn!(call_id, error = %status, "CallService.TerminateCall failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "success": false,
                    "call_id": call_id,
                    "error": status.message(),
                })),
            )
        }
    }
}
