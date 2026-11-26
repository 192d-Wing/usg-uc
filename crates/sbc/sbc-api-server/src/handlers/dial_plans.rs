//! Dial-plan write handlers. Reads (`GET /dialplans`, `GET
//! /dialplans/{id}/entries`) stay on the daemon because they query the
//! live SIP router, not Postgres — those are caught by the proxy
//! fallback.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sbc_grpc_api::prelude::{RemoveDialPlanRequest, SyncDialPlanRequest};
use sbc_http_util::mgmt_audit::{Op, Outcome};
use tracing::warn;

use super::write_audit::{audited, non_object, store_actor, store_reason};
use crate::authmw::Principal;
use crate::state::AppState;

/// Audit entity name for dial-plan entry writes (id `<plan>/<entry>`).
const ENTITY: &str = "dial_plan_entry";

pub async fn add_entry(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<String>,
    principal: Option<Extension<Principal>>,
    Json(mut body): Json<serde_json::Value>,
) -> Response {
    let p = principal.as_ref().map(|Extension(p)| p);
    if !body.is_object() {
        return non_object(p, ENTITY, &format!("{plan_id}/-"), Op::Create);
    }
    if body.get("id").and_then(|v| v.as_str()).is_none() {
        body["id"] = serde_json::json!(uuid::Uuid::new_v4().to_string());
    }
    let entry_id = body
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let audit_id = format!("{plan_id}/{entry_id}");
    let done = |outcome, resp: Response| audited(p, ENTITY, &audit_id, Op::Create, outcome, resp);
    let mut doc = match state.dial_plans.get(&plan_id).await {
        Ok(v) => v,
        Err(sbc_config_store::ConfigStoreError::NotFound) => {
            serde_json::json!({"id": plan_id, "entries": []})
        }
        Err(e) => {
            warn!(plan_id, error = %e, "dial plan get failed");
            return done(
                Outcome::Failed(store_reason(&e)),
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("dial plan store error: {e}")})),
                )
                    .into_response(),
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
    if let Err(e) = state
        .dial_plans
        .upsert(&plan_id, &doc, &store_actor(p))
        .await
    {
        warn!(plan_id, error = %e, "dial plan upsert failed");
        return done(
            Outcome::Failed(store_reason(&e)),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to persist changes"})),
            )
                .into_response(),
        );
    }
    notify_dial_plan_sync(&state, &plan_id).await;
    done(
        Outcome::Ok,
        (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "success": true,
                "plan_id": plan_id,
                "entry": body,
            })),
        )
            .into_response(),
    )
}

pub async fn delete_entry(
    State(state): State<Arc<AppState>>,
    Path((plan_id, entry_id)): Path<(String, String)>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let p = principal.as_ref().map(|Extension(p)| p);
    let audit_id = format!("{plan_id}/{entry_id}");
    let (outcome, resp) = delete_entry_inner(&state, p, &plan_id, &entry_id).await;
    audited(p, ENTITY, &audit_id, Op::Delete, outcome, resp)
}

async fn delete_entry_inner(
    state: &Arc<AppState>,
    p: Option<&Principal>,
    plan_id: &str,
    entry_id: &str,
) -> (Outcome, Response) {
    let actor = store_actor(p);
    let mut outcome = Outcome::Ok;
    match state.dial_plans.get(plan_id).await {
        Ok(mut doc) => {
            let became_empty = doc
                .get_mut("entries")
                .and_then(|v| v.as_array_mut())
                .is_none_or(|arr| {
                    arr.retain(|e| e.get("id").and_then(|v| v.as_str()) != Some(entry_id));
                    arr.is_empty()
                });
            if became_empty {
                if let Err(e) = state.dial_plans.delete(plan_id, &actor).await {
                    warn!(plan_id, error = %e, "dial plan delete failed");
                    return (Outcome::Failed(store_reason(&e)), persist_failed());
                }
                notify_dial_plan_remove(state, plan_id).await;
            } else {
                if let Err(e) = state.dial_plans.upsert(plan_id, &doc, &actor).await {
                    warn!(plan_id, error = %e, "dial plan upsert failed");
                    return (Outcome::Failed(store_reason(&e)), persist_failed());
                }
                notify_dial_plan_sync(state, plan_id).await;
            }
        }
        // Idempotent response; the record says nothing was removed.
        Err(sbc_config_store::ConfigStoreError::NotFound) => outcome = Outcome::Failed("not_found"),
        Err(e) => {
            warn!(plan_id, error = %e, "dial plan get during delete failed");
            let resp = (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to read dial plan"})),
            )
                .into_response();
            return (Outcome::Failed(store_reason(&e)), resp);
        }
    }
    let resp = Json(serde_json::json!({
        "success": true,
        "plan_id": plan_id,
        "entry_id": entry_id,
    }))
    .into_response();
    (outcome, resp)
}

fn persist_failed() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "failed to persist changes"})),
    )
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
