//! Directory-number (DID) CRUD. Writes go to Postgres and then trigger
//! a DidMappingSync gRPC call to the daemon so the SIP stack's DID→user
//! routing map stays current.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sbc_grpc_api::prelude::{RemoveDirectoryNumberRequest, SyncDirectoryNumberRequest};
use tracing::warn;

use crate::state::AppState;

pub async fn list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.directory.list().await {
        Ok(dns) => {
            let total = dns.len();
            let values: Vec<serde_json::Value> =
                dns.iter().filter_map(|d| d.to_json().ok()).collect();
            Json(serde_json::json!({"directory_numbers": values, "total": total}))
        }
        Err(e) => {
            warn!(error = %e, "list DIDs failed");
            Json(serde_json::json!({"directory_numbers": [], "total": 0, "error": e.to_string()}))
        }
    }
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Json(mut body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let did = body
        .get("did")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    body["did"] = serde_json::json!(&did);

    let dn = match sbc_config_store::DirectoryNumber::from_json(body.clone()) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("malformed DID body: {e}"),
                })),
            );
        }
    };
    if let Err(e) = state.directory.upsert(&dn).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": format!("directory store upsert failed: {e}"),
            })),
        );
    }
    notify_did_sync(&state, &did).await;
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"success": true, "directory_number": body})),
    )
}

pub async fn update(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    Json(mut body): Json<serde_json::Value>,
) -> impl IntoResponse {
    body["did"] = serde_json::json!(&did);
    // Preserve the existing "404 when missing" semantic the dashboard
    // expects on PUT.
    match state.directory.get(&did).await {
        Ok(_) => {}
        Err(sbc_config_store::ConfigStoreError::NotFound) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Directory number not found",
                })),
            );
        }
        Err(e) => warn!(did, error = %e, "directory store get failed during update"),
    }
    let dn = match sbc_config_store::DirectoryNumber::from_json(body.clone()) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("malformed DID body: {e}"),
                })),
            );
        }
    };
    if let Err(e) = state.directory.upsert(&dn).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": format!("directory store upsert failed: {e}"),
            })),
        );
    }
    notify_did_sync(&state, &did).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({"success": true, "directory_number": body})),
    )
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = state.directory.delete(&did).await {
        if !matches!(e, sbc_config_store::ConfigStoreError::NotFound) {
            warn!(did, error = %e, "directory delete failed");
        }
    }
    notify_did_remove(&state, &did).await;
    Json(serde_json::json!({"success": true, "did": did}))
}

async fn notify_did_sync(state: &Arc<AppState>, did: &str) {
    let mut client = state.did_sync.clone();
    let req = SyncDirectoryNumberRequest {
        did: did.to_string(),
    };
    if let Err(e) = client.sync_directory_number(req).await {
        warn!(did, error = %e, "daemon DID sync RPC failed");
    }
}

async fn notify_did_remove(state: &Arc<AppState>, did: &str) {
    let mut client = state.did_sync.clone();
    let req = RemoveDirectoryNumberRequest {
        did: did.to_string(),
    };
    if let Err(e) = client.remove_directory_number(req).await {
        warn!(did, error = %e, "daemon DID remove RPC failed");
    }
}
