//! Dial-plan write handlers. Reads (`GET /dialplans`, `GET
//! /dialplans/{id}/entries`) stay on the daemon because they query the
//! live SIP router, not Postgres — those are caught by the proxy
//! fallback.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sbc_grpc_api::prelude::{RemoveDialPlanRequest, SyncDialPlanRequest};
use tracing::warn;

use crate::state::AppState;

pub async fn add_entry(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<String>,
    Json(mut body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if body.get("id").and_then(|v| v.as_str()).is_none() {
        body["id"] = serde_json::json!(uuid::Uuid::new_v4().to_string());
    }
    let mut doc = match state.dial_plans.get(&plan_id).await {
        Ok(v) => v,
        Err(sbc_config_store::ConfigStoreError::NotFound) => {
            serde_json::json!({"id": plan_id, "entries": []})
        }
        Err(e) => {
            warn!(plan_id, error = %e, "dial plan get failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("dial plan store error: {e}")})),
            );
        }
    };
    if let Some(obj) = doc.as_object_mut() {
        obj.insert("id".to_string(), serde_json::json!(&plan_id));
        let entries = obj
            .entry("entries".to_string())
            .or_insert_with(|| serde_json::json!([]));
        if let Some(arr) = entries.as_array_mut() {
            arr.push(body.clone());
        }
    }
    if let Err(e) = state.dial_plans.upsert(&plan_id, &doc).await {
        warn!(plan_id, error = %e, "dial plan upsert failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to persist changes"})),
        );
    }
    notify_dial_plan_sync(&state, &plan_id).await;
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "success": true,
            "plan_id": plan_id,
            "entry": body,
        })),
    )
}

pub async fn delete_entry(
    State(state): State<Arc<AppState>>,
    Path((plan_id, entry_id)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.dial_plans.get(&plan_id).await {
        Ok(mut doc) => {
            let became_empty = doc
                .get_mut("entries")
                .and_then(|v| v.as_array_mut())
                .is_none_or(|arr| {
                    arr.retain(|e| e.get("id").and_then(|v| v.as_str()) != Some(&entry_id));
                    arr.is_empty()
                });
            if became_empty {
                if let Err(e) = state.dial_plans.delete(&plan_id).await {
                    warn!(plan_id, error = %e, "dial plan delete failed");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "failed to persist changes"})),
                    )
                        .into_response();
                }
                notify_dial_plan_remove(&state, &plan_id).await;
            } else {
                if let Err(e) = state.dial_plans.upsert(&plan_id, &doc).await {
                    warn!(plan_id, error = %e, "dial plan upsert failed");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "failed to persist changes"})),
                    )
                        .into_response();
                }
                notify_dial_plan_sync(&state, &plan_id).await;
            }
        }
        Err(sbc_config_store::ConfigStoreError::NotFound) => { /* idempotent */ }
        Err(e) => warn!(plan_id, error = %e, "dial plan get during delete failed"),
    }
    Json(serde_json::json!({
        "success": true,
        "plan_id": plan_id,
        "entry_id": entry_id,
    }))
    .into_response()
}

async fn notify_dial_plan_sync(state: &Arc<AppState>, plan_id: &str) {
    let mut client = state.dial_plan_sync.clone();
    let req = SyncDialPlanRequest {
        plan_id: plan_id.to_string(),
    };
    if let Err(e) = client.sync_dial_plan(req).await {
        warn!(plan_id, error = %e, "daemon dial-plan sync RPC failed");
    }
}

async fn notify_dial_plan_remove(state: &Arc<AppState>, plan_id: &str) {
    let mut client = state.dial_plan_sync.clone();
    let req = RemoveDialPlanRequest {
        plan_id: plan_id.to_string(),
    };
    if let Err(e) = client.remove_dial_plan(req).await {
        warn!(plan_id, error = %e, "daemon dial-plan remove RPC failed");
    }
}
