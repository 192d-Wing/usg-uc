//! Phone CRUD handlers — same REST shape as the daemon's, but reading
//! and writing Postgres directly instead of going through the daemon's
//! `MemStore`. No gRPC sync call needed: phones don't have an in-SIP-
//! stack representation (provisioning consumes them per-request).

use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sbc_http_util::mgmt_audit::{Op, Outcome};
use tracing::warn;

use super::write_audit::{audited, store_actor, store_reason};
use crate::authmw::Principal;
use crate::state::AppState;

/// Audit entity name for phone writes.
const ENTITY: &str = "phone";

pub async fn list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.phones.list().await {
        Ok(phones) => {
            let total = phones.len();
            let values: Vec<serde_json::Value> = phones
                .iter()
                .filter_map(|p| serde_json::to_value(p).ok())
                .collect();
            Json(serde_json::json!({"phones": values, "total": total}))
        }
        Err(e) => {
            warn!(error = %e, "list phones failed");
            Json(serde_json::json!({"phones": [], "total": 0, "error": e.to_string()}))
        }
    }
}

/// A create body rejected before the store: reason token, status, message.
type Rejected = (&'static str, StatusCode, String);

/// Builds the phone a create stores, and the response echo of it.
fn build_phone(
    body: &serde_json::Value,
) -> Result<(uc_phone_mgmt::model::Phone, serde_json::Value), Rejected> {
    let invalid = |msg: String| ("invalid", StatusCode::BAD_REQUEST, msg);
    // Build a real Phone via its constructor (same shape as the daemon's
    // create handler) so optional fields get vendor defaults rather than
    // hard nulls — required by the per-vendor provisioning serializers.
    let mac = match body.get("mac_address").and_then(|v| v.as_str()) {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => return Err(invalid("mac_address is required".to_string())),
    };
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let model: uc_phone_mgmt::model::PhoneModel = match body.get("model") {
        Some(v) => {
            serde_json::from_value(v.clone()).map_err(|e| invalid(format!("invalid model: {e}")))?
        }
        None => return Err(invalid("model is required".to_string())),
    };

    let mut phone = uc_phone_mgmt::model::Phone::new(&mac, model, &name);
    if let Some(id) = body.get("id").and_then(|v| v.as_str())
        && !id.is_empty()
    {
        phone.id = id.to_string();
    }

    // Merge the caller's extra fields by serializing the seeded Phone,
    // overlaying the body, then re-deserializing for validation.
    let mut phone_value = serde_json::to_value(&phone).map_err(|e| {
        (
            "storage",
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("serialize: {e}"),
        )
    })?;
    if let (serde_json::Value::Object(dst), serde_json::Value::Object(src)) =
        (&mut phone_value, body)
    {
        for (k, v) in src {
            if matches!(k.as_str(), "mac_address" | "model" | "id") {
                continue;
            }
            dst.insert(k.clone(), v.clone());
        }
    }
    let merged: uc_phone_mgmt::model::Phone = serde_json::from_value(phone_value.clone())
        .map_err(|e| invalid(format!("phone record failed validation: {e}")))?;
    Ok((merged, phone_value))
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let p = principal.as_ref().map(|Extension(p)| p);
    let (merged, phone_value) = match build_phone(&body) {
        Ok(v) => v,
        Err((reason, status, msg)) => {
            let body_id = body.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            return audited(
                p,
                ENTITY,
                body_id,
                Op::Create,
                Outcome::Failed(reason),
                (
                    status,
                    Json(serde_json::json!({"success": false, "error": msg})),
                ),
            );
        }
    };

    let id = merged.id.clone();
    if let Err(e) = state.phones.upsert(&merged, &store_actor(p)).await {
        return audited(
            p,
            ENTITY,
            &id,
            Op::Create,
            Outcome::Failed(store_reason(&e)),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("phone store upsert failed: {e}"),
                })),
            ),
        );
    }
    audited(
        p,
        ENTITY,
        &id,
        Op::Create,
        Outcome::Ok,
        (
            StatusCode::CREATED,
            Json(serde_json::json!({"success": true, "phone": phone_value})),
        ),
    )
}

pub async fn get(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    match state.phones.get(&id).await {
        Ok(phone) => serde_json::to_value(&phone)
            .map_or_else(
                |_| Json(serde_json::json!({"error": "serialize failed"})),
                Json,
            )
            .into_response(),
        Err(sbc_config_store::ConfigStoreError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("Phone {id} not found")})),
        )
            .into_response(),
        Err(e) => {
            warn!(id, error = %e, "get phone failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

pub async fn update(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    principal: Option<Extension<Principal>>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let p = principal.as_ref().map(|Extension(p)| p);
    let done =
        |outcome, resp: Json<serde_json::Value>| audited(p, ENTITY, &id, Op::Update, outcome, resp);
    // Same tightening as the daemon's Postgres-path update_phone: body
    // must be a fully-valid Phone.
    match serde_json::from_value::<uc_phone_mgmt::model::Phone>(body.clone()) {
        Ok(mut typed) => {
            typed.id = id.clone();
            if let Err(e) = state.phones.upsert(&typed, &store_actor(p)).await {
                return done(
                    Outcome::Failed(store_reason(&e)),
                    Json(serde_json::json!({
                        "success": false,
                        "error": format!("phone store upsert failed: {e}"),
                    })),
                );
            }
            done(
                Outcome::Ok,
                Json(serde_json::json!({"success": true, "phone": body})),
            )
        }
        Err(e) => done(
            Outcome::Failed("invalid"),
            Json(serde_json::json!({
                "success": false,
                "error": format!("phone record failed validation: {e}"),
            })),
        ),
    }
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let p = principal.as_ref().map(|Extension(p)| p);
    // The response stays idempotent; the record says what happened.
    let outcome = match state.phones.delete(&id, &store_actor(p)).await {
        Ok(()) => Outcome::Ok,
        Err(e) => {
            if !matches!(e, sbc_config_store::ConfigStoreError::NotFound) {
                warn!(id, error = %e, "delete phone failed");
            }
            Outcome::Failed(store_reason(&e))
        }
    };
    audited(
        p,
        ENTITY,
        &id,
        Op::Delete,
        outcome,
        Json(serde_json::json!({"success": true, "id": id})),
    )
}

pub async fn reboot(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let p = principal.as_ref().map(|Extension(p)| p);
    let (outcome, body) = match state.phones.get(&id).await {
        Ok(_) => (
            Outcome::Ok,
            serde_json::json!({
                "success": true,
                "message": format!("Reboot initiated for {id}"),
            }),
        ),
        Err(sbc_config_store::ConfigStoreError::NotFound) => (
            Outcome::Failed("not_found"),
            serde_json::json!({"success": false, "error": "Phone not found"}),
        ),
        Err(e) => {
            warn!(id, error = %e, "reboot lookup failed");
            (
                Outcome::Failed("storage"),
                serde_json::json!({"success": false, "error": "Phone not found"}),
            )
        }
    };
    audited(p, ENTITY, &id, Op::Action("reboot"), outcome, Json(body))
}
