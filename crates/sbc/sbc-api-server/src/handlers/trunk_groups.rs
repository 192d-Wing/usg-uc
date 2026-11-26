//! Trunk-group + nested trunk CRUD. Writes go to Postgres, then a
//! `TrunkSync` gRPC call to the daemon refreshes the SIP router. Lookup
//! helpers mirror the daemon's `lookup_trunk_group` / `persist_trunk_
//! group` pattern from PR3 so the branching logic shows up exactly
//! twice instead of once per handler.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sbc_grpc_api::prelude::{RemoveTrunkGroupRequest, SyncTrunkGroupRequest};
use sbc_http_util::mgmt_audit::Op;
use tracing::warn;

use super::write_audit::{audited, mark_absent, non_object, outcome_of, store_actor};
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

async fn persist(state: &Arc<AppState>, id: &str, body: &serde_json::Value, actor: &str) -> bool {
    if let Err(e) = state.trunk_groups.upsert(id, body, actor).await {
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
            admin: principal.map_or_else(|| "unknown".to_string(), Principal::actor_id),
            change_type: uc_audit::event::ConfigChangeType::Modified,
            description: format!(
                "trunk_group={} {diff} outcome=success",
                group_id.escape_default()
            ),
        },
    ));
}

/// 422 `secret_reentry_required` when a write keeps a trunk `sip_password`
/// marker (or, for a single-trunk update, omits it) while changing where the
/// stored secret is sent. Names the field, never a value.
///
/// ## NIST 800-53 Rev5: IA-5
fn reentry_rejection(
    body: &serde_json::Value,
    existing: Option<&serde_json::Value>,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let field = redact::trunk_group_reentry_field(body, existing)?;
    warn!(field = %field, "trunk group write refused: secret re-entry required");
    Some((
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({
            "success": false,
            "error": "secret_reentry_required",
            "field": field,
        })),
    ))
}

/// [`reentry_rejection`] for a single-trunk update: `merged` is the trunk
/// after applying the update, `body` the update. The stored secret is kept
/// when the update sends the marker or no `sip_password` at all.
fn trunk_update_reentry_rejection(
    old_group: &serde_json::Value,
    merged: &serde_json::Value,
    body: &serde_json::Value,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let keeps = body
        .get("sip_password")
        .is_none_or(|v| v.as_str() == Some(redact::REDACTED));
    if !keeps {
        return None;
    }
    let mut probe = merged.clone();
    probe["sip_password"] = serde_json::json!(redact::REDACTED);
    let (status, Json(mut err)) =
        reentry_rejection(&serde_json::json!({"trunks": [probe]}), Some(old_group))?;
    // The probe group has one trunk: report the bare field name.
    if let Some(f) = err["field"]
        .as_str()
        .and_then(|f| f.strip_prefix("trunks[0]."))
    {
        err["field"] = serde_json::json!(f);
    }
    Some((status, Json(err)))
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

async fn add_group_inner(
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
    if let Some(rej) = reentry_rejection(&body, existing.as_ref()) {
        return rej;
    }
    redact::restore_passwords(&mut body, existing.as_ref());
    if !persist(&state, &id, &body, &store_actor(principal.as_deref())).await {
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

async fn update_group_inner(
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
    if let Some(rej) = reentry_rejection(&body, existing.as_ref()) {
        return rej;
    }
    redact::restore_passwords(&mut body, existing.as_ref());
    if !persist(&state, &group_id, &body, &store_actor(principal.as_deref())).await {
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

async fn delete_group_inner(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Path(group_id): Path<String>,
) -> impl IntoResponse {
    let existing = lookup(&state, &group_id).await;
    let absent = match state
        .trunk_groups
        .delete(&group_id, &store_actor(principal.as_deref()))
        .await
    {
        Ok(()) => false,
        Err(sbc_config_store::ConfigStoreError::NotFound) => true,
        Err(e) => {
            warn!(group_id, error = %e, "trunk group delete failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to persist changes"})),
            )
                .into_response();
        }
    };
    audit_transport_change(principal.as_deref(), &group_id, existing.as_ref(), None);
    notify_remove(&state, &group_id).await;
    mark_absent(
        Json(serde_json::json!({"success": true, "group_id": group_id})).into_response(),
        absent,
    )
}

async fn add_trunk_inner(
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
    if !persist(
        &state,
        &group_id,
        &group_json,
        &store_actor(principal.as_deref()),
    )
    .await
    {
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

async fn update_trunk_inner(
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
    if let Some(rej) = trunk_update_reentry_rejection(&old, &updated, &body) {
        return rej;
    }
    let warnings = match check_policy(&group_json) {
        Ok(w) => w,
        Err(rej) => return rej,
    };
    if !persist(
        &state,
        &group_id,
        &group_json,
        &store_actor(principal.as_deref()),
    )
    .await
    {
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

async fn delete_trunk_inner(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Path((group_id, trunk_id)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut warnings = Vec::new();
    // No group, or no such trunk in it: idempotent 200, recorded not_found.
    let mut absent = true;
    if let Some(mut group_json) = lookup(&state, &group_id).await {
        let old = group_json.clone();
        if let Some(trunks) = group_json.get_mut("trunks").and_then(|v| v.as_array_mut()) {
            let before = trunks.len();
            trunks.retain(|t| t.get("id").and_then(|v| v.as_str()) != Some(&trunk_id));
            absent = trunks.len() == before;
        }
        // Deleting the last TLS trunk of a require_tls group is refused
        // (422); deleting the last trunk of one is accepted with a warning.
        warnings = match check_policy(&group_json) {
            Ok(w) => w,
            Err(rej) => return rej.into_response(),
        };
        if !persist(
            &state,
            &group_id,
            &group_json,
            &store_actor(principal.as_deref()),
        )
        .await
        {
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
    mark_absent(
        Json(with_warnings(
            serde_json::json!({"success": true, "group_id": group_id, "trunk_id": trunk_id}),
            &warnings,
        ))
        .into_response(),
        absent,
    )
}

// ---------------- Audited entry points ----------------
//
// Each write records one `ConfigurationChange` (entity, id, op, outcome of
// the response status; an absent delete is `not_found`) besides the
// transport-policy diff record above. Trunk ids are `<group>/<trunk>`.
// NIST 800-53 Rev5: AU-2, AU-3, AU-12, CM-3

fn status_audited(
    p: Option<&Principal>,
    entity: &'static str,
    id: &str,
    op: Op,
    resp: impl IntoResponse,
) -> Response {
    let resp = resp.into_response();
    let outcome = outcome_of(&resp);
    audited(p, entity, id, op, outcome, resp)
}

/// Audit id of a trunk: `<group>/<trunk>` (`<group>/-` without a trunk id).
fn trunk_audit_id(group_id: &str, trunk_id: &str) -> String {
    let t = if trunk_id.is_empty() { "-" } else { trunk_id };
    format!("{group_id}/{t}")
}

pub async fn add_group(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Json(mut body): Json<serde_json::Value>,
) -> Response {
    if !body.is_object() {
        return non_object(principal.as_deref(), "trunk_group", "", Op::Create);
    }
    // Fix the id here so the record names the group the inner handler
    // creates.
    let id = body
        .get("id")
        .and_then(|v| v.as_str())
        .map_or_else(|| uuid::Uuid::new_v4().to_string(), String::from);
    body["id"] = serde_json::json!(&id);
    let p = principal.clone();
    let resp = add_group_inner(State(state), principal, Json(body)).await;
    status_audited(p.as_deref(), "trunk_group", &id, Op::Create, resp)
}

pub async fn update_group(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Path(group_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if !body.is_object() {
        return non_object(principal.as_deref(), "trunk_group", &group_id, Op::Update);
    }
    let p = principal.clone();
    let resp =
        update_group_inner(State(state), principal, Path(group_id.clone()), Json(body)).await;
    status_audited(p.as_deref(), "trunk_group", &group_id, Op::Update, resp)
}

pub async fn delete_group(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Path(group_id): Path<String>,
) -> Response {
    let p = principal.clone();
    let resp = delete_group_inner(State(state), principal, Path(group_id.clone())).await;
    status_audited(p.as_deref(), "trunk_group", &group_id, Op::Delete, resp)
}

pub async fn add_trunk(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Path(group_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let id = trunk_audit_id(
        &group_id,
        body.get("id").and_then(|v| v.as_str()).unwrap_or_default(),
    );
    let p = principal.clone();
    let resp = add_trunk_inner(State(state), principal, Path(group_id), Json(body)).await;
    status_audited(p.as_deref(), "trunk", &id, Op::Create, resp)
}

pub async fn update_trunk(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Path((group_id, trunk_id)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let id = trunk_audit_id(&group_id, &trunk_id);
    let p = principal.clone();
    let resp = update_trunk_inner(
        State(state),
        principal,
        Path((group_id, trunk_id)),
        Json(body),
    )
    .await;
    status_audited(p.as_deref(), "trunk", &id, Op::Update, resp)
}

pub async fn delete_trunk(
    State(state): State<Arc<AppState>>,
    principal: Option<Extension<Principal>>,
    Path((group_id, trunk_id)): Path<(String, String)>,
) -> Response {
    let id = trunk_audit_id(&group_id, &trunk_id);
    let p = principal.clone();
    let resp = delete_trunk_inner(State(state), principal, Path((group_id, trunk_id))).await;
    status_audited(p.as_deref(), "trunk", &id, Op::Delete, resp)
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
        assert_eq!(changes[0].admin, "admin:admin");
        assert_eq!(
            changes[0].description,
            "trunk_group=g1 require_tls=false->true trunk_protocols=[a:udp->tls] outcome=success"
        );
    }

    // SR-39: a kept (or, on a single-trunk update, omitted) trunk secret
    // with a changed destination is refused with the field named.
    #[test]
    fn trunk_destination_change_with_kept_secret_is_422() {
        let stored = json!({"id": "g1", "trunks": [
            {"id": "t1", "host": "a.example.mil", "protocol": "tls", "sip_password": "trunk-pw"},
        ]});
        // Group write: marker kept, host changed.
        let mut body = redact::redacted(stored.clone());
        assert!(reentry_rejection(&body, Some(&stored)).is_none());
        body["trunks"][0]["host"] = json!("evil.example");
        let (status, Json(err)) = reentry_rejection(&body, Some(&stored)).unwrap();
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(err["error"], "secret_reentry_required");
        assert_eq!(err["field"], "trunks[0].host");
        assert!(!err.to_string().contains("trunk-pw"), "{err}");
        body["trunks"][0]["sip_password"] = json!("trunk-new");
        assert!(reentry_rejection(&body, Some(&stored)).is_none());

        // Single-trunk update: the merged trunk holds the stored secret.
        let mut merged = stored["trunks"][0].clone();
        merged["host"] = json!("evil.example");
        for update in [
            json!({"host": "evil.example"}),
            json!({"host": "evil.example", "sip_password": redact::REDACTED}),
        ] {
            let (status, Json(err)) =
                trunk_update_reentry_rejection(&stored, &merged, &update).unwrap();
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(err["field"], "host", "{update}");
            assert!(!err.to_string().contains("trunk-pw"), "{err}");
        }
        let update = json!({"host": "evil.example", "sip_password": "trunk-new"});
        merged["sip_password"] = json!("trunk-new");
        assert!(trunk_update_reentry_rejection(&stored, &merged, &update).is_none());
        // Same destination, other edits: allowed.
        let merged = stored["trunks"][0].clone();
        assert!(
            trunk_update_reentry_rejection(&stored, &merged, &json!({"priority": 2})).is_none()
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
