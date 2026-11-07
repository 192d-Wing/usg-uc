//! Trunk-group + nested trunk CRUD. Writes go to Postgres, then a
//! `TrunkSync` gRPC call to the daemon refreshes the SIP router. Lookup
//! helpers mirror the daemon's `lookup_trunk_group` / `persist_trunk_
//! group` pattern from PR3 so the branching logic shows up exactly
//! twice instead of once per handler.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sbc_grpc_api::prelude::{RemoveTrunkGroupRequest, SyncTrunkGroupRequest};
use tracing::warn;

use crate::authmw::Principal;
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

/// `require_tls` transport policy on the group as it would be stored
/// (NIST 800-53 Rev5: SC-8, CM-6, SI-10; POA&M-48). Malformed: 400.
/// TLS-only group with trunks but none TLS: 422. Nothing is persisted and no
/// sync is sent on either. A TLS-only group with no trunks is accepted with a
/// warning (groups are created first, trunks added after).
fn check_policy(
    group: &serde_json::Value,
) -> Result<Vec<String>, (StatusCode, Json<serde_json::Value>)> {
    use sbc_config_store::TrunkPolicyError;
    sbc_config_store::validate_trunk_group_json(group).map_err(|e| {
        let status = match e {
            TrunkPolicyError::Invalid(_) => StatusCode::BAD_REQUEST,
            TrunkPolicyError::Policy(_) => StatusCode::UNPROCESSABLE_ENTITY,
        };
        warn!(error = %e, "trunk group rejected by require_tls policy check");
        (
            status,
            Json(serde_json::json!({"success": false, "error": e.to_string()})),
        )
    })
}

/// Writes a `ConfigurationChange` audit record when a successful mutation
/// changed the group's `require_tls` flag or a trunk's transport. `old` /
/// `new` are the stored bodies before and after (`None`: absent).
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, CM-3 (Configuration Change Control), SC-8
fn audit_transport_change(
    principal: Option<&Principal>,
    group_id: &str,
    old: Option<&serde_json::Value>,
    new: Option<&serde_json::Value>,
) {
    let Some(diff) = sbc_config_store::trunk_policy::transport_policy_diff(old, new) else {
        return;
    };
    uc_audit::log_event(uc_audit::AuditEvent::ConfigurationChange(
        uc_audit::event::ConfigurationChange {
            admin: principal.map_or_else(|| "unknown".to_string(), |p| p.user.clone()),
            change_type: uc_audit::event::ConfigChangeType::Modified,
            description: format!(
                "trunk_group={} {diff} outcome=success",
                group_id.escape_default()
            ),
        },
    ));
}

/// Adds `warnings` to a success body when there are any.
fn with_warnings(mut body: serde_json::Value, warnings: &[String]) -> serde_json::Value {
    if !warnings.is_empty() {
        body["warnings"] = serde_json::json!(warnings);
    }
    body
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
    principal: Option<Extension<Principal>>,
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
    let warnings = match check_policy(&body) {
        Ok(w) => w,
        Err(rej) => return rej,
    };
    let existing = lookup(&state, &id).await;
    redact::restore_passwords(&mut body, existing.as_ref());
    if !persist(&state, &id, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": "trunk group store upsert failed"})),
        );
    }
    audit_transport_change(principal.as_deref(), &id, existing.as_ref(), Some(&body));
    notify_sync(&state, &id).await;
    redact::trunk_group(&mut body);
    (
        StatusCode::CREATED,
        Json(with_warnings(
            serde_json::json!({"success": true, "trunk_group": body}),
            &warnings,
        )),
    )
}

pub async fn update_group(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Path(group_id): Path<String>,
    Json(mut body): Json<serde_json::Value>,
) -> impl IntoResponse {
    body["id"] = serde_json::json!(&group_id);
    let warnings = match check_policy(&body) {
        Ok(w) => w,
        Err(rej) => return rej,
    };
    let existing = lookup(&state, &group_id).await;
    redact::restore_passwords(&mut body, existing.as_ref());
    if !persist(&state, &group_id, &body).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": "trunk group store upsert failed"})),
        );
    }
    audit_transport_change(
        principal.as_deref(),
        &group_id,
        existing.as_ref(),
        Some(&body),
    );
    notify_sync(&state, &group_id).await;
    redact::trunk_group(&mut body);
    (
        StatusCode::OK,
        Json(with_warnings(
            serde_json::json!({"success": true, "trunk_group": body}),
            &warnings,
        )),
    )
}

pub async fn delete_group(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Path(group_id): Path<String>,
) -> impl IntoResponse {
    let existing = lookup(&state, &group_id).await;
    if let Err(e) = state.trunk_groups.delete(&group_id).await
        && !matches!(e, sbc_config_store::ConfigStoreError::NotFound)
    {
        warn!(group_id, error = %e, "trunk group delete failed");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to persist changes"})),
        )
            .into_response();
    }
    audit_transport_change(principal.as_deref(), &group_id, existing.as_ref(), None);
    notify_remove(&state, &group_id).await;
    Json(serde_json::json!({"success": true, "group_id": group_id})).into_response()
}

pub async fn add_trunk(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Path(group_id): Path<String>,
    Json(mut body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let Some(mut group_json) = lookup(&state, &group_id).await else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"success": false, "error": "Group not found"})),
        );
    };
    let old = group_json.clone();
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
    let warnings = match check_policy(&group_json) {
        Ok(w) => w,
        Err(rej) => return rej,
    };
    if !persist(&state, &group_id, &group_json).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": "failed to persist changes"})),
        );
    }
    audit_transport_change(
        principal.as_deref(),
        &group_id,
        Some(&old),
        Some(&group_json),
    );
    notify_sync(&state, &group_id).await;
    redact::trunk(&mut body);
    (
        StatusCode::CREATED,
        Json(with_warnings(
            serde_json::json!({"success": true, "trunk": body}),
            &warnings,
        )),
    )
}

pub async fn update_trunk(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Path((group_id, trunk_id)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let Some(mut group_json) = lookup(&state, &group_id).await else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"success": false, "error": "Group not found"})),
        );
    };
    let old = group_json.clone();
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
    let warnings = match check_policy(&group_json) {
        Ok(w) => w,
        Err(rej) => return rej,
    };
    if !persist(&state, &group_id, &group_json).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"success": false, "error": "failed to persist changes"})),
        );
    }
    audit_transport_change(
        principal.as_deref(),
        &group_id,
        Some(&old),
        Some(&group_json),
    );
    notify_sync(&state, &group_id).await;
    redact::trunk(&mut updated);
    (
        StatusCode::OK,
        Json(with_warnings(
            serde_json::json!({"success": true, "trunk": updated}),
            &warnings,
        )),
    )
}

pub async fn delete_trunk(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Path((group_id, trunk_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut warnings = Vec::new();
    if let Some(mut group_json) = lookup(&state, &group_id).await {
        let old = group_json.clone();
        if let Some(trunks) = group_json.get_mut("trunks").and_then(|v| v.as_array_mut()) {
            trunks.retain(|t| t.get("id").and_then(|v| v.as_str()) != Some(&trunk_id));
        }
        // Deleting the last TLS trunk of a require_tls group is refused
        // (422); deleting the last trunk of one is accepted with a warning.
        warnings = match check_policy(&group_json) {
            Ok(w) => w,
            Err(rej) => return rej.into_response(),
        };
        if !persist(&state, &group_id, &group_json).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to persist changes"})),
            )
                .into_response();
        }
        audit_transport_change(
            principal.as_deref(),
            &group_id,
            Some(&old),
            Some(&group_json),
        );
        notify_sync(&state, &group_id).await;
    }
    Json(with_warnings(
        serde_json::json!({"success": true, "group_id": group_id, "trunk_id": trunk_id}),
        &warnings,
    ))
    .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    // POA&M-48 (SC-8): status codes the handlers return before persisting.
    #[test]
    fn require_tls_policy_check() {
        let code = |b: serde_json::Value| check_policy(&b).map_err(|(s, _)| s);
        let udp = json!({"id": "u", "host": "192.0.2.1", "transport": "udp"});
        let tls = json!({"id": "t", "host": "192.0.2.2", "transport": "tls"});
        // Create/update a TLS-only group without a TLS trunk.
        assert_eq!(
            code(json!({"require_tls": true, "trunks": [udp]})),
            Err(StatusCode::UNPROCESSABLE_ENTITY)
        );
        // Add a UDP trunk to an empty TLS-only group (same check on the
        // post-change group).
        assert_eq!(
            code(json!({"require_tls": true, "trunks": [udp, tls]})),
            Ok(Vec::new())
        );
        // Malformed.
        assert_eq!(
            code(json!({"require_tls": "true"})),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(
            code(json!({"trunks": [{"id": "x", "protocol": "sctp"}]})),
            Err(StatusCode::BAD_REQUEST)
        );
        // RFC-001: out-of-range port is 400, never truncated.
        assert_eq!(
            code(json!({"trunks": [{"id": "x", "port": 70_000}]})),
            Err(StatusCode::BAD_REQUEST)
        );
        // Empty TLS-only group: accepted with a warning.
        let w = code(json!({"require_tls": true, "trunks": []})).unwrap();
        assert_eq!(w.len(), 1);
        let body = with_warnings(json!({"success": true}), &w);
        assert!(
            body["warnings"][0]
                .as_str()
                .unwrap()
                .contains("require_tls")
        );
        assert!(with_warnings(json!({}), &[]).get("warnings").is_none());
    }

    // SEC-003 / NIST-001: a require_tls or trunk-protocol change is audited
    // with who, group, old/new values and outcome; other edits are not.
    #[test]
    fn transport_change_is_audited() {
        let capture = uc_audit::capture::start();
        let old = json!({"require_tls": false, "trunks": [{"id": "a", "protocol": "udp"}]});
        let new = json!({"require_tls": true, "trunks": [{"id": "a", "protocol": "tls"}]});
        let p = Principal::admin();
        audit_transport_change(Some(&p), "g1", Some(&old), Some(&new));
        audit_transport_change(Some(&p), "g1", Some(&new), Some(&new));
        let changes: Vec<_> = capture
            .events()
            .into_iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::ConfigurationChange(c) => Some(c),
                _ => None,
            })
            .collect();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].admin, "admin");
        assert_eq!(
            changes[0].description,
            "trunk_group=g1 require_tls=false->true trunk_protocols=[a:udp->tls] outcome=success"
        );
    }

    // QA (POA&M-48): delete_trunk runs check_policy on the group with the
    // trunk removed. Deleting the last TLS trunk while a UDP trunk remains
    // is 422; deleting every trunk leaves an empty group (warning only).
    // NOTE: handler-level (Postgres + gRPC) test not possible here: no
    // store harness in sbc-api-server. This replays the handler's retain.
    #[test]
    fn qa_delete_last_tls_trunk_is_422() {
        let mut group = json!({
            "require_tls": true,
            "trunks": [
                {"id": "u", "host": "192.0.2.1", "transport": "udp"},
                {"id": "t", "host": "192.0.2.2", "transport": "tls"},
            ],
        });
        let delete = |g: &mut serde_json::Value, id: &str| {
            if let Some(trunks) = g.get_mut("trunks").and_then(|v| v.as_array_mut()) {
                trunks.retain(|t| t.get("id").and_then(|v| v.as_str()) != Some(id));
            }
        };
        let mut after = group.clone();
        delete(&mut after, "t");
        assert_eq!(
            check_policy(&after).map_err(|(s, _)| s),
            Err(StatusCode::UNPROCESSABLE_ENTITY)
        );
        // Deleting the UDP trunk is fine.
        delete(&mut group, "u");
        assert_eq!(check_policy(&group).map_err(|(s, _)| s), Ok(Vec::new()));
        // Then deleting the last (TLS) trunk: empty group, accepted + warning.
        delete(&mut group, "t");
        assert_eq!(check_policy(&group).unwrap().len(), 1);
        // A second TLS trunk keeps the group valid when one is deleted.
        let mut two = json!({"require_tls": true, "trunks": [
            {"id": "u", "transport": "udp"},
            {"id": "t1", "protocol": "tls"},
            {"id": "t2", "transport": "TLS"},
        ]});
        delete(&mut two, "t1");
        assert!(check_policy(&two).is_ok());
    }
}
