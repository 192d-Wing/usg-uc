//! Registration handlers. Replaces the HTTP-proxy fallback for
//! `/registrations` and `/registrations/{aor}` (DELETE) with direct
//! gRPC calls into the daemon's `RegistrationService` on `:9091`.
//!
//! Shape matches the daemon's old REST output:
//! `{registrations: [{aor, contact, expires, registered_at}], total,
//! active}` — flattened to one row per contact, with the daemon's
//! `RegistrationInfo.contacts` array fanned out.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sbc_grpc_api::prelude::{DeleteRegistrationRequest, ListRegistrationsRequest};
use std::collections::HashMap;
use tracing::warn;

use crate::state::AppState;

pub async fn list(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut client = state.registrations.clone();
    let req = ListRegistrationsRequest::default();
    match client.list_registrations(req).await {
        Ok(resp) => {
            let r = resp.into_inner();
            // Fan out each AOR's contacts into one REST row per (aor,
            // contact) — matches the daemon's old shape.
            let registrations: Vec<serde_json::Value> = r
                .registrations
                .iter()
                .flat_map(|rinfo| {
                    rinfo.contacts.iter().map(move |c| {
                        serde_json::json!({
                            "aor": rinfo.aor,
                            "contact": c.uri,
                            "expires": c.expires,
                            "registered_at": 0,
                        })
                    })
                })
                .collect();
            let total = registrations.len();
            Json(serde_json::json!({
                "registrations": registrations,
                "total": total,
                "active": r.active,
            }))
        }
        Err(status) => {
            warn!(error = %status, "RegistrationService.ListRegistrations failed");
            Json(serde_json::json!({
                "registrations": [],
                "total": 0,
                "active": 0,
                "error": status.message(),
            }))
        }
    }
}

pub async fn delete(
    State(state): State<Arc<AppState>>,
    Path(aor): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let mut client = state.registrations.clone();
    let req = DeleteRegistrationRequest {
        aor: aor.clone(),
        contact_uri: params.get("contact").cloned().unwrap_or_default(),
        reason: params
            .get("reason")
            .cloned()
            .unwrap_or_else(|| "operator_requested".to_string()),
    };
    match client.delete_registration(req).await {
        Ok(resp) => {
            let r = resp.into_inner();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": r.success,
                    "aor": aor,
                    "contacts_removed": r.contacts_removed,
                    "message": r.message,
                })),
            )
        }
        Err(status) => {
            warn!(aor, error = %status, "RegistrationService.DeleteRegistration failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({
                    "success": false,
                    "aor": aor,
                    "error": status.message(),
                })),
            )
        }
    }
}
