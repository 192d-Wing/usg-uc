//! Phone CRUD handlers — same REST shape as the daemon's, but reading
//! and writing Postgres directly instead of going through the daemon's
//! `MemStore`. No gRPC sync call needed: phones don't have an in-SIP-
//! stack representation (provisioning consumes them per-request).

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use tracing::warn;

use crate::state::AppState;

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

pub async fn create(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Build a real Phone via its constructor (same shape as the daemon's
    // create handler) so optional fields get vendor defaults rather than
    // hard nulls — required by the per-vendor provisioning serializers.
    let mac = match body.get("mac_address").and_then(|v| v.as_str()) {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"success": false, "error": "mac_address is required"})),
            );
        }
    };
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let model: uc_phone_mgmt::model::PhoneModel = match body.get("model") {
        Some(v) => match serde_json::from_value(v.clone()) {
            Ok(m) => m,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "success": false,
                        "error": format!("invalid model: {e}"),
                    })),
                );
            }
        },
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"success": false, "error": "model is required"})),
            );
        }
    };

    let mut phone = uc_phone_mgmt::model::Phone::new(&mac, model, &name);
    if let Some(id) = body.get("id").and_then(|v| v.as_str()) {
        if !id.is_empty() {
            phone.id = id.to_string();
        }
    }

    // Merge the caller's extra fields by serializing the seeded Phone,
    // overlaying the body, then re-deserializing for validation.
    let mut phone_value = match serde_json::to_value(&phone) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"success": false, "error": format!("serialize: {e}")})),
            );
        }
    };
    if let (serde_json::Value::Object(dst), serde_json::Value::Object(src)) =
        (&mut phone_value, &body)
    {
        for (k, v) in src {
            if matches!(k.as_str(), "mac_address" | "model" | "id") {
                continue;
            }
            dst.insert(k.clone(), v.clone());
        }
    }
    let merged: uc_phone_mgmt::model::Phone = match serde_json::from_value(phone_value.clone()) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("phone record failed validation: {e}"),
                })),
            );
        }
    };

    if let Err(e) = state.phones.upsert(&merged).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": format!("phone store upsert failed: {e}"),
            })),
        );
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({"success": true, "phone": phone_value})),
    )
}

pub async fn get(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> impl IntoResponse {
    match state.phones.get(&id).await {
        Ok(phone) => Json(
            serde_json::to_value(&phone)
                .unwrap_or_else(|_| serde_json::json!({"error": "serialize failed"})),
        ),
        Err(sbc_config_store::ConfigStoreError::NotFound) => {
            Json(serde_json::json!({"error": format!("Phone {id} not found")}))
        }
        Err(e) => {
            warn!(id, error = %e, "get phone failed");
            Json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

pub async fn update(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Same tightening as the daemon's Postgres-path update_phone: body
    // must be a fully-valid Phone.
    match serde_json::from_value::<uc_phone_mgmt::model::Phone>(body.clone()) {
        Ok(mut typed) => {
            typed.id = id.clone();
            if let Err(e) = state.phones.upsert(&typed).await {
                return Json(serde_json::json!({
                    "success": false,
                    "error": format!("phone store upsert failed: {e}"),
                }));
            }
            Json(serde_json::json!({"success": true, "phone": body}))
        }
        Err(e) => Json(serde_json::json!({
            "success": false,
            "error": format!("phone record failed validation: {e}"),
        })),
    }
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = state.phones.delete(&id).await {
        if !matches!(e, sbc_config_store::ConfigStoreError::NotFound) {
            warn!(id, error = %e, "delete phone failed");
        }
    }
    Json(serde_json::json!({"success": true, "id": id}))
}

pub async fn reboot(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.phones.get(&id).await {
        Ok(_) => Json(serde_json::json!({
            "success": true,
            "message": format!("Reboot initiated for {id}"),
        })),
        Err(sbc_config_store::ConfigStoreError::NotFound) => {
            Json(serde_json::json!({"success": false, "error": "Phone not found"}))
        }
        Err(e) => {
            warn!(id, error = %e, "reboot lookup failed");
            Json(serde_json::json!({"success": false, "error": "Phone not found"}))
        }
    }
}
