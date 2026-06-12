//! Trunk-group + nested trunk CRUD. Writes go to Postgres, then a
//! `TrunkSync` gRPC call to the daemon refreshes the SIP router. Lookup
//! helpers mirror the daemon's `lookup_trunk_group` / `persist_trunk_
//! group` pattern from PR3 so the branching logic shows up exactly
//! twice instead of once per handler.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sbc_grpc_api::prelude::{RemoveTrunkGroupRequest, SyncTrunkGroupRequest};
use tracing::warn;

use crate::handlers::redact;
use crate::state::AppState;

async fn lookup(state: &Arc<AppState>, id: &str) -> Option<serde_json::Value> {
    match state.trunk_groups.get(id).await {
        Ok(v) => Some(v),
        Err(sbc_config_store::ConfigStoreError::NotFound) => None,
        Err(e) => {
            warn!(group_id = id, error = %e, "trunk group lookup failed");
            None
        }
    }
}

async fn persist(state: &Arc<AppState>, id: &str, body: &serde_json::Value) -> bool {
    if let Err(e) = state.trunk_groups.upsert(id, body).await {
        warn!(group_id = id, error = %e, "trunk group upsert failed");
        return false;
    }
    true
}

async fn notify_sync(state: &Arc<AppState>, id: &str) {
    let mut client = state.trunk_sync.clone();
    let req = SyncTrunkGroupRequest {
        group_id: id.to_string(),
    };
    if let Err(e) = client.sync_trunk_group(req).await {
        warn!(group_id = id, error = %e, "daemon trunk-group sync RPC failed");
    }
}

async fn notify_remove(state: &Arc<AppState>, id: &str) {
    let mut client = state.trunk_sync.clone();
    let req = RemoveTrunkGroupRequest {
        group_id: id.to_string(),
    };
    if let Err(e) = client.remove_trunk_group(req).await {
        warn!(group_id = id, error = %e, "daemon trunk-group remove RPC failed");
    }
}

pub async fn list_groups(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.trunk_groups.list().await {
        Ok(groups) => {
            let total = groups.len();
            let groups: Vec<_> = groups.into_iter().map(redact::redacted).collect();
            Json(serde_json::json!({"trunk_groups": groups, "total": total}))
        }
        Err(e) => {
            warn!(error = %e, "list trunk groups failed");
            Json(serde_json::json!({"trunk_groups": [], "total": 0, "error": e.to_string()}))
        }
    }
}

pub async fn get_group(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
) -> impl IntoResponse {
    lookup(&state, &group_id).await.map_or_else(
        || Json(serde_json::json!({"error": format!("Trunk group {group_id} not found")})),
        |g| Json(redact::redacted(g)),
    )
}

pub async fn add_group(
    State(state): State<Arc<AppState>>,
    Json(mut body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let id = body
        .get("id")
        .and_then(|v| v.as_str())
        .map_or_else(|| uuid::Uuid::new_v4().to_string(), String::from);
    body["id"] = serde_json::json!(&id);
    if body.get("trunks").is_none() {
        body["trunks"] = serde_json::json!([]);
    }
    let existing = lookup(&state, &id).await;
    redact::restore_passwords(&mut body, existing.as_ref());
    if !persist(&state, &id, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": "trunk group store upsert failed"})),
        );
    }
    notify_sync(&state, &id).await;
    redact::trunk_group(&mut body);
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"success": true, "trunk_group": body})),
    )
}

pub async fn update_group(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    Json(mut body): Json<serde_json::Value>,
) -> impl IntoResponse {
    body["id"] = serde_json::json!(&group_id);
    let existing = lookup(&state, &group_id).await;
    redact::restore_passwords(&mut body, existing.as_ref());
    if !persist(&state, &group_id, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": "trunk group store upsert failed"})),
        );
    }
    notify_sync(&state, &group_id).await;
    redact::trunk_group(&mut body);
    (
        StatusCode::OK,
        Json(serde_json::json!({"success": true, "trunk_group": body})),
    )
}

pub async fn delete_group(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = state.trunk_groups.delete(&group_id).await
        && !matches!(e, sbc_config_store::ConfigStoreError::NotFound)
    {
        warn!(group_id, error = %e, "trunk group delete failed");
    }
    notify_remove(&state, &group_id).await;
    Json(serde_json::json!({"success": true, "group_id": group_id}))
}

pub async fn add_trunk(
    State(state): State<Arc<AppState>>,
    Path(group_id): Path<String>,
    Json(mut body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let Some(mut group_json) = lookup(&state, &group_id).await else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"success": false, "error": "Group not found"})),
        );
    };
    // A round-tripped marker on a brand-new trunk has no stored secret.
    redact::drop_marker_password(&mut body);
    match group_json.get_mut("trunks").and_then(|v| v.as_array_mut()) {
        Some(arr) => arr.push(body.clone()),
        None => {
            if let Some(obj) = group_json.as_object_mut() {
                obj.insert("trunks".to_string(), serde_json::json!([body.clone()]));
            }
        }
    }
    persist(&state, &group_id, &group_json).await;
    notify_sync(&state, &group_id).await;
    redact::trunk(&mut body);
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"success": true, "trunk": body})),
    )
}

pub async fn update_trunk(
    State(state): State<Arc<AppState>>,
    Path((group_id, trunk_id)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let Some(mut group_json) = lookup(&state, &group_id).await else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"success": false, "error": "Group not found"})),
        );
    };
    let Some(trunks) = group_json.get_mut("trunks").and_then(|v| v.as_array_mut()) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"success": false, "error": "Group not found"})),
        );
    };
    let Some(trunk) = trunks
        .iter_mut()
        .find(|t| t.get("id").and_then(|v| v.as_str()) == Some(&trunk_id))
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"success": false, "error": "Trunk not found"})),
        );
    };
    if let (Some(obj), Some(updates)) = (trunk.as_object_mut(), body.as_object()) {
        for (k, v) in updates {
            if k == "id" {
                continue;
            }
            // Round-tripped marker keeps the stored secret.
            if k == "sip_password" && v.as_str() == Some(redact::REDACTED) {
                continue;
            }
            obj.insert(k.clone(), v.clone());
        }
    }
    let mut updated = trunk.clone();
    persist(&state, &group_id, &group_json).await;
    notify_sync(&state, &group_id).await;
    redact::trunk(&mut updated);
    (
        StatusCode::OK,
        Json(serde_json::json!({"success": true, "trunk": updated})),
    )
}

pub async fn delete_trunk(
    State(state): State<Arc<AppState>>,
    Path((group_id, trunk_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Some(mut group_json) = lookup(&state, &group_id).await {
        if let Some(trunks) = group_json.get_mut("trunks").and_then(|v| v.as_array_mut()) {
            trunks.retain(|t| t.get("id").and_then(|v| v.as_str()) != Some(&trunk_id));
        }
        persist(&state, &group_id, &group_json).await;
        notify_sync(&state, &group_id).await;
    }
    Json(serde_json::json!({"success": true, "group_id": group_id, "trunk_id": trunk_id}))
}
