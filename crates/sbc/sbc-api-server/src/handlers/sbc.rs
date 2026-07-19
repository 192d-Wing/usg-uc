//! SBC routing CRUD handlers (PR11) — partitions, calling search
//! spaces, route patterns, route lists.
//!
//! Pattern matches the dial-plan handler set: write to Postgres, then
//! notify the daemon via the [`SbcSyncService`] gRPC so the live
//! `SbcRouter` catches up. Response shapes are kept byte-identical to
//! the daemon's old REST handlers so the dashboard doesn't need any
//! changes when nginx flips the upstream.
//!
//! `SbcSyncService` notify failures are logged but never block the
//! write — Postgres is the source of truth and the daemon's startup
//! replay re-applies whatever's there on the next boot.
//!
//! [`SbcSyncService`]: sbc_grpc_api::prelude::SbcSyncService

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sbc_grpc_api::prelude::{
    RemoveCallingSearchSpaceRequest, RemovePartitionRequest, RemoveRouteListRequest,
    RemoveRoutePatternRequest, SyncCallingSearchSpaceRequest, SyncPartitionRequest,
    SyncRouteListRequest, SyncRoutePatternRequest,
};
use tracing::warn;

use crate::state::AppState;

// ---------------- Partitions ----------------

pub async fn list_partitions(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.partitions.list().await {
        Ok(rows) => Json(serde_json::json!({"partitions": rows})),
        Err(e) => {
            warn!(error = %e, "list partitions failed");
            Json(serde_json::json!({"partitions": [], "error": e.to_string()}))
        }
    }
}

pub async fn create_partition(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !body.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"success": false, "error": "request body must be a JSON object"}),
            ),
        );
    }
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let id = body
        .get("id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map_or_else(|| name.clone(), String::from);
    if id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"success": false, "error": "id or name required"})),
        );
    }
    let mut doc = body.clone();
    if let serde_json::Value::Object(ref mut obj) = doc {
        obj.insert("id".to_string(), serde_json::Value::String(id.clone()));
        if !obj.contains_key("name") {
            obj.insert("name".to_string(), serde_json::Value::String(id.clone()));
        }
    }
    if let Err(e) = state.partitions.upsert(&id, &doc).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": e.to_string()})),
        );
    }
    notify_sync_partition(&state, &id).await;
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"success": true, "id": id})),
    )
}

pub async fn update_partition(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut doc = body;
    if let serde_json::Value::Object(ref mut obj) = doc {
        obj.insert("id".to_string(), serde_json::Value::String(id.clone()));
    }
    if let Err(e) = state.partitions.upsert(&id, &doc).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": e.to_string()})),
        );
    }
    notify_sync_partition(&state, &id).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"success": true, "id": id})),
    )
}

pub async fn delete_partition(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = state.partitions.delete(&id).await
        && !matches!(e, sbc_config_store::ConfigStoreError::NotFound)
    {
        warn!(id, error = %e, "delete partition failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to persist changes"})),
        )
            .into_response();
    }
    let mut client = state.sbc_sync.clone();
    if let Err(e) = client
        .remove_partition(RemovePartitionRequest {
            partition_id: id.clone(),
        })
        .await
    {
        warn!(id, error = %e, "SbcSyncService.RemovePartition failed");
    }
    Json(serde_json::json!({"success": true, "id": id})).into_response()
}

async fn notify_sync_partition(state: &Arc<AppState>, id: &str) {
    let mut client = state.sbc_sync.clone();
    if let Err(e) = client
        .sync_partition(SyncPartitionRequest {
            partition_id: id.to_string(),
        })
        .await
    {
        warn!(id, error = %e, "SbcSyncService.SyncPartition failed");
    }
}

// ---------------- Calling Search Spaces ----------------

pub async fn list_css(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.css.list().await {
        Ok(rows) => Json(serde_json::json!({"calling_search_spaces": rows})),
        Err(e) => {
            warn!(error = %e, "list css failed");
            Json(serde_json::json!({
                "calling_search_spaces": [],
                "error": e.to_string(),
            }))
        }
    }
}

pub async fn create_css(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !body.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"success": false, "error": "request body must be a JSON object"}),
            ),
        );
    }
    let id = match body.get("id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"success": false, "error": "id is required"})),
            );
        }
    };
    if let Some(p) = body.get("partitions") {
        if !p.is_array() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"success": false, "error": "partitions must be an array"})),
            );
        }
    }
    if let Err(e) = state.css.upsert(&id, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": e.to_string()})),
        );
    }
    notify_sync_css(&state, &id).await;
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"success": true, "id": id})),
    )
}

pub async fn update_css(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut doc = body;
    if let serde_json::Value::Object(ref mut obj) = doc {
        obj.insert("id".to_string(), serde_json::Value::String(id.clone()));
    }
    if let Err(e) = state.css.upsert(&id, &doc).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": e.to_string()})),
        );
    }
    notify_sync_css(&state, &id).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"success": true, "id": id})),
    )
}

pub async fn delete_css(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = state.css.delete(&id).await
        && !matches!(e, sbc_config_store::ConfigStoreError::NotFound)
    {
        warn!(id, error = %e, "delete css failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to persist changes"})),
        )
            .into_response();
    }
    let mut client = state.sbc_sync.clone();
    if let Err(e) = client
        .remove_calling_search_space(RemoveCallingSearchSpaceRequest { css_id: id.clone() })
        .await
    {
        warn!(id, error = %e, "SbcSyncService.RemoveCallingSearchSpace failed");
    }
    Json(serde_json::json!({"success": true, "id": id})).into_response()
}

async fn notify_sync_css(state: &Arc<AppState>, id: &str) {
    let mut client = state.sbc_sync.clone();
    if let Err(e) = client
        .sync_calling_search_space(SyncCallingSearchSpaceRequest {
            css_id: id.to_string(),
        })
        .await
    {
        warn!(id, error = %e, "SbcSyncService.SyncCallingSearchSpace failed");
    }
}

// ---------------- Route Patterns ----------------

pub async fn list_route_patterns(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.route_patterns.list().await {
        Ok(rows) => Json(serde_json::json!({"route_patterns": rows})),
        Err(e) => {
            warn!(error = %e, "list route_patterns failed");
            Json(serde_json::json!({"route_patterns": [], "error": e.to_string()}))
        }
    }
}

pub async fn create_route_pattern(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !body.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"success": false, "error": "request body must be a JSON object"}),
            ),
        );
    }
    let id = match body.get("id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"success": false, "error": "id is required"})),
            );
        }
    };
    if body
        .get("pattern")
        .and_then(|v| v.as_str())
        .is_none_or(|s| s.is_empty())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"success": false, "error": "pattern is required and must be a non-empty string"}),
            ),
        );
    }
    if let Err(e) = state.route_patterns.upsert(&id, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": e.to_string()})),
        );
    }
    notify_sync_route_pattern(&state, &id).await;
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"success": true, "id": id})),
    )
}

pub async fn update_route_pattern(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut doc = body;
    if let serde_json::Value::Object(ref mut obj) = doc {
        obj.insert("id".to_string(), serde_json::Value::String(id.clone()));
    }
    if let Err(e) = state.route_patterns.upsert(&id, &doc).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": e.to_string()})),
        );
    }
    notify_sync_route_pattern(&state, &id).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"success": true, "id": id})),
    )
}

pub async fn delete_route_pattern(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = state.route_patterns.delete(&id).await
        && !matches!(e, sbc_config_store::ConfigStoreError::NotFound)
    {
        warn!(id, error = %e, "delete route_pattern failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to persist changes"})),
        )
            .into_response();
    }
    let mut client = state.sbc_sync.clone();
    if let Err(e) = client
        .remove_route_pattern(RemoveRoutePatternRequest {
            pattern_id: id.clone(),
        })
        .await
    {
        warn!(id, error = %e, "SbcSyncService.RemoveRoutePattern failed");
    }
    Json(serde_json::json!({"success": true, "id": id})).into_response()
}

async fn notify_sync_route_pattern(state: &Arc<AppState>, id: &str) {
    let mut client = state.sbc_sync.clone();
    if let Err(e) = client
        .sync_route_pattern(SyncRoutePatternRequest {
            pattern_id: id.to_string(),
        })
        .await
    {
        warn!(id, error = %e, "SbcSyncService.SyncRoutePattern failed");
    }
}

// ---------------- Route Lists ----------------

pub async fn list_route_lists(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.route_lists.list().await {
        Ok(rows) => Json(serde_json::json!({"route_lists": rows})),
        Err(e) => {
            warn!(error = %e, "list route_lists failed");
            Json(serde_json::json!({"route_lists": [], "error": e.to_string()}))
        }
    }
}

pub async fn create_route_list(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !body.is_object() {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"success": false, "error": "request body must be a JSON object"}),
            ),
        );
    }
    let id = match body.get("id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"success": false, "error": "id is required"})),
            );
        }
    };
    if let Err(e) = state.route_lists.upsert(&id, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": e.to_string()})),
        );
    }
    notify_sync_route_list(&state, &id).await;
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"success": true, "id": id})),
    )
}

pub async fn update_route_list(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let mut doc = body;
    if let serde_json::Value::Object(ref mut obj) = doc {
        obj.insert("id".to_string(), serde_json::Value::String(id.clone()));
    }
    if let Err(e) = state.route_lists.upsert(&id, &doc).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": e.to_string()})),
        );
    }
    notify_sync_route_list(&state, &id).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"success": true, "id": id})),
    )
}

pub async fn delete_route_list(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = state.route_lists.delete(&id).await
        && !matches!(e, sbc_config_store::ConfigStoreError::NotFound)
    {
        warn!(id, error = %e, "delete route_list failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to persist changes"})),
        )
            .into_response();
    }
    let mut client = state.sbc_sync.clone();
    if let Err(e) = client
        .remove_route_list(RemoveRouteListRequest {
            list_id: id.clone(),
        })
        .await
    {
        warn!(id, error = %e, "SbcSyncService.RemoveRouteList failed");
    }
    Json(serde_json::json!({"success": true, "id": id})).into_response()
}

async fn notify_sync_route_list(state: &Arc<AppState>, id: &str) {
    let mut client = state.sbc_sync.clone();
    if let Err(e) = client
        .sync_route_list(SyncRouteListRequest {
            list_id: id.to_string(),
        })
        .await
    {
        warn!(id, error = %e, "SbcSyncService.SyncRouteList failed");
    }
}
