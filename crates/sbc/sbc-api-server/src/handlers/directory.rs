//! Directory-number (DID) CRUD. Writes go to Postgres and then trigger
//! a `DidMappingSync` gRPC call to the daemon so the SIP stack's DID→user
//! routing map stays current.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sbc_grpc_api::prelude::{RemoveDirectoryNumberRequest, SyncDirectoryNumberRequest};
use sbc_http_util::mgmt_audit::{Op, Outcome};
use tracing::warn;

use super::write_audit::{audited, non_object, store_actor, store_reason};
use crate::authmw::Principal;
use crate::state::AppState;

/// Audit entity name for DID writes.
const ENTITY: &str = "directory_number";

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
    principal: Option<Extension<Principal>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let p = principal.as_ref().map(|Extension(p)| p);
    write(&state, p, None, body).await
}

pub async fn update(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let p = principal.as_ref().map(|Extension(p)| p);
    write(&state, p, Some(did), body).await
}

/// Create (`path_did` is `None`) or update, audited with the real outcome.
async fn write(
    state: &Arc<AppState>,
    p: Option<&Principal>,
    path_did: Option<String>,
    body: serde_json::Value,
) -> Response {
    let op = if path_did.is_some() {
        Op::Update
    } else {
        Op::Create
    };
    if !body.is_object() {
        return non_object(p, ENTITY, path_did.as_deref().unwrap_or_default(), op);
    }
    let (did, outcome, resp) = match path_did {
        None => create_inner(state, p, body).await,
        Some(did) => update_inner(state, p, did, body).await,
    };
    audited(p, ENTITY, &did, op, outcome, resp)
}

async fn create_inner(
    state: &Arc<AppState>,
    p: Option<&Principal>,
    mut body: serde_json::Value,
) -> (String, Outcome, Response) {
    let did = body
        .get("did")
        .and_then(|v| v.as_str())
        .map_or_else(|| uuid::Uuid::new_v4().to_string(), String::from);
    body["did"] = serde_json::json!(&did);

    let dn = match sbc_config_store::DirectoryNumber::from_json(body.clone()) {
        Ok(d) => d,
        Err(e) => {
            return (did, Outcome::Failed("invalid"), malformed(&e.to_string()));
        }
    };
    if let Err(e) = state.directory.upsert(&dn, &store_actor(p)).await {
        return (did, Outcome::Failed(store_reason(&e)), upsert_failed(&e));
    }
    notify_did_sync(state, &did).await;
    let resp = (
        StatusCode::CREATED,
        Json(serde_json::json!({"success": true, "directory_number": body})),
    )
        .into_response();
    (did, Outcome::Ok, resp)
}

fn malformed(e: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "success": false,
            "error": format!("malformed DID body: {e}"),
        })),
    )
        .into_response()
}

fn upsert_failed(e: &sbc_config_store::ConfigStoreError) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({
            "success": false,
            "error": format!("directory store upsert failed: {e}"),
        })),
    )
        .into_response()
}

async fn update_inner(
    state: &Arc<AppState>,
    p: Option<&Principal>,
    did: String,
    mut body: serde_json::Value,
) -> (String, Outcome, Response) {
    body["did"] = serde_json::json!(&did);
    // Preserve the existing "404 when missing" semantic the dashboard
    // expects on PUT.
    match state.directory.get(&did).await {
        Ok(_) => {}
        Err(sbc_config_store::ConfigStoreError::NotFound) => {
            let resp = (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "success": false,
                    "error": "Directory number not found",
                })),
            )
                .into_response();
            return (did, Outcome::Failed("not_found"), resp);
        }
        Err(e) => warn!(did, error = %e, "directory store get failed during update"),
    }
    let dn = match sbc_config_store::DirectoryNumber::from_json(body.clone()) {
        Ok(d) => d,
        Err(e) => {
            return (did, Outcome::Failed("invalid"), malformed(&e.to_string()));
        }
    };
    if let Err(e) = state.directory.upsert(&dn, &store_actor(p)).await {
        return (did, Outcome::Failed(store_reason(&e)), upsert_failed(&e));
    }
    notify_did_sync(state, &did).await;
    let resp = (
        StatusCode::OK,
        Json(serde_json::json!({"success": true, "directory_number": body})),
    )
        .into_response();
    (did, Outcome::Ok, resp)
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let p = principal.as_ref().map(|Extension(p)| p);
    let done = |outcome, resp: Response| audited(p, ENTITY, &did, Op::Delete, outcome, resp);
    let outcome = match state.directory.delete(&did, &store_actor(p)).await {
        Ok(()) => Outcome::Ok,
        Err(sbc_config_store::ConfigStoreError::NotFound) => Outcome::Failed("not_found"),
        Err(e) => {
            warn!(did, error = %e, "directory delete failed");
            return done(
                Outcome::Failed(store_reason(&e)),
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "failed to persist changes"})),
                )
                    .into_response(),
            );
        }
    };
    notify_did_remove(&state, &did).await;
    done(
        outcome,
        Json(serde_json::json!({"success": true, "did": did})).into_response(),
    )
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
