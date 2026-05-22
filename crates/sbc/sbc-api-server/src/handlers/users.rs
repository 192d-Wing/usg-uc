//! `/users` CRUD handlers — Postgres-backed via `uc-user-mgmt`'s
//! `PostgresUserStore`. As of PR10 these handlers live in sbc-api and
//! the daemon's REST `/users` routes are stripped. SIP digest auth in
//! the daemon still reads through the same `users` table via its own
//! pool — sbc-api is the only writer.
//!
//! Response shapes match what the daemon's REST surface used to emit so
//! the dashboard's existing fetch logic doesn't need to change:
//!   GET    /users        → {"users": [...], "total": N}
//!   POST   /users        → 201 {"success": true, "user": {...}}
//!   GET    /users/{id}   → {...user fields...}  or  {"error": "..."}
//!   PUT    /users/{id}   → {"success": true|false, "user"?: {...}, "error"?: "..."}
//!   DELETE /users/{id}   → {"success": true|false, "error"?: "..."}

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use tracing::warn;
use uc_user_mgmt::digest::compute_ha1;
use uc_user_mgmt::model::{AuthType, User, UserFilter};
use uc_user_mgmt::store::UserStore;

use crate::state::AppState;

fn now_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn body_str<'a>(body: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    body.get(key).and_then(serde_json::Value::as_str)
}

pub async fn list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match state.users.list_users(&UserFilter::default()).await {
        Ok(users) => Json(serde_json::json!({
            "users": users,
            "total": users.len(),
        })),
        Err(e) => {
            warn!(error = %e, "list users failed");
            Json(serde_json::json!({
                "users": [],
                "total": 0,
                "error": e.to_string(),
            }))
        }
    }
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let username = body_str(&body, "username").unwrap_or("").to_string();
    let display_name = body_str(&body, "display_name").unwrap_or("").to_string();
    let email = body_str(&body, "email").unwrap_or("").to_string();
    let sip_uri = body_str(&body, "sip_uri")
        .unwrap_or(&username)
        .to_string();
    let digest_ha1 = body_str(&body, "password")
        .filter(|p| !p.is_empty())
        .map(|password| {
            let realm = body_str(&body, "sip_domain").unwrap_or("sbc-local");
            compute_ha1(&username, realm, password)
        });
    let certificate_dn = body_str(&body, "certificate_dn").map(String::from);
    let calling_search_space = body_str(&body, "calling_search_space").map(String::from);

    let user = User {
        id: uuid::Uuid::new_v4().to_string(),
        username,
        display_name,
        email,
        sip_uri,
        auth_type: AuthType::Digest,
        digest_ha1,
        certificate_dn,
        certificate_san: None,
        calling_search_space,
        device_ids: Vec::new(),
        partition: None,
        enabled: true,
        created_at: now_epoch_secs(),
        updated_at: 0,
        last_login: None,
        metadata: HashMap::new(),
    };

    match state.users.create_user(user).await {
        Ok(created) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"success": true, "user": created})),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"success": false, "error": e.to_string()})),
        ),
    }
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.users.get_user(&id).await {
        Ok(user) => Json(serde_json::json!(user)),
        Err(e) => Json(serde_json::json!({"error": e.to_string()})),
    }
}

pub async fn update(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let existing = match state.users.get_user(&id).await {
        Ok(u) => u,
        Err(e) => {
            return Json(serde_json::json!({"success": false, "error": e.to_string()}));
        }
    };

    let username = body_str(&body, "username")
        .unwrap_or(&existing.username)
        .to_string();
    let digest_ha1 = body_str(&body, "password")
        .filter(|p| !p.is_empty())
        .map(|password| {
            let realm = body_str(&body, "sip_domain").unwrap_or("sbc-local");
            compute_ha1(&username, realm, password)
        })
        .or(existing.digest_ha1);

    let updated = User {
        id: id.clone(),
        username,
        display_name: body_str(&body, "display_name")
            .unwrap_or(&existing.display_name)
            .to_string(),
        email: body_str(&body, "email")
            .unwrap_or(&existing.email)
            .to_string(),
        sip_uri: body_str(&body, "sip_uri")
            .unwrap_or(&existing.sip_uri)
            .to_string(),
        auth_type: existing.auth_type,
        digest_ha1,
        certificate_dn: body_str(&body, "certificate_dn")
            .map(String::from)
            .or(existing.certificate_dn),
        certificate_san: existing.certificate_san,
        calling_search_space: body_str(&body, "calling_search_space")
            .map(String::from)
            .or(existing.calling_search_space),
        device_ids: existing.device_ids,
        partition: existing.partition,
        enabled: body
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(existing.enabled),
        created_at: existing.created_at,
        updated_at: now_epoch_secs(),
        last_login: existing.last_login,
        metadata: existing.metadata,
    };

    match state.users.update_user(updated).await {
        Ok(u) => Json(serde_json::json!({"success": true, "user": u})),
        Err(e) => Json(serde_json::json!({"success": false, "error": e.to_string()})),
    }
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.users.delete_user(&id).await {
        Ok(()) => Json(serde_json::json!({"success": true})),
        Err(e) => Json(serde_json::json!({"success": false, "error": e.to_string()})),
    }
}
