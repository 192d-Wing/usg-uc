//! HTTP surface: health probes and the site-scoped sync endpoints.
//!
//! Sync is the fleet-facing read API the per-site `sbc-config-sync` agent
//! pulls. Each handler authorizes the caller against the path's
//! `site_code` (see [`crate::auth`]) before touching the store, so a
//! site can only ever read its own shard.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use serde::Deserialize;
use serde_json::{Value, json};
use tower_http::trace::TraceLayer;
use tracing::warn;

use central_config_store::{CentralError, ConfigTable, DeltaResult};

use crate::auth::{authorize_operator, authorize_site};
use crate::state::AppState;

/// Build the router.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        // Sync surface (site-scoped tokens).
        .route("/v1/sync/{site_code}/epoch", get(sync_epoch))
        .route("/v1/sync/{site_code}/delta", get(sync_delta))
        .route("/v1/sync/{site_code}/snapshot", get(sync_snapshot))
        .route("/v1/sync/{site_code}/upload", post(sync_upload))
        // Operator surface (config-admin tokens). GET reads + writes.
        .route("/v1/sites", get(list_sites).post(register_site))
        .route(
            "/v1/sites/{site_code}/phones",
            get(list_phones).post(upsert_phone),
        )
        .route(
            "/v1/sites/{site_code}/phones/{id}",
            get(get_phone).delete(delete_phone),
        )
        .route(
            "/v1/sites/{site_code}/directory",
            get(list_directory).post(upsert_did),
        )
        .route(
            "/v1/sites/{site_code}/directory/{did}",
            get(get_directory).delete(delete_did),
        )
        .route(
            "/v1/sites/{site_code}/trunkgroups",
            get(list_trunk_groups).post(upsert_trunk_group),
        )
        .route(
            "/v1/sites/{site_code}/trunkgroups/{id}",
            get(get_trunk_group).delete(delete_trunk_group),
        )
        .route(
            "/v1/sites/{site_code}/dialplans",
            get(list_dial_plans).post(upsert_dial_plan),
        )
        .route(
            "/v1/sites/{site_code}/dialplans/{id}",
            get(get_dial_plan).delete(delete_dial_plan),
        )
        .route(
            "/v1/sites/{site_code}/config",
            get(get_site_config).put(put_site_config),
        )
        // SBC routing entities (partitions / calling_search_spaces /
        // route_patterns / route_lists), JSON pass-through by id.
        .route(
            "/v1/sites/{site_code}/routing/{kind}",
            get(list_routing).post(upsert_routing),
        )
        .route(
            "/v1/sites/{site_code}/routing/{kind}/{id}",
            get(get_routing).delete(delete_routing),
        )
        // Global templates + materialization (config-admin tokens).
        .route(
            "/v1/templates/{kind}/{id}",
            put(put_template).delete(delete_template),
        )
        .route(
            "/v1/templates/{kind}/{id}/sites/{site_code}",
            put(assign_template),
        )
        .route(
            "/v1/templates/{kind}/{id}/materialize",
            post(materialize_template),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Parse a `{kind}` path segment into a [`TemplateKind`]. The error arm is
/// a ready-to-return 400 `Response` (intentionally large).
#[allow(clippy::result_large_err)]
fn parse_kind(kind: &str) -> Result<central_config_store::TemplateKind, Response> {
    central_config_store::TemplateKind::parse(kind)
        .ok_or_else(|| bad_request("kind must be trunk_group or dial_plan"))
}

/// Liveness: the process is up. No dependencies checked.
async fn healthz() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

/// Readiness: the database is reachable and the JWKS cache is primed.
/// Unready (503) keeps the pod out of rotation until it can serve.
async fn readyz(State(state): State<Arc<AppState>>) -> Response {
    let db_ok = state.store.ping().await.is_ok();
    let jwks_ok = state.sync_validator.jwks().ready().await;
    if db_ok && jwks_ok {
        Json(json!({ "status": "ready",
            "uptime_secs": state.start_time.elapsed().as_secs() }))
        .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "unready", "db": db_ok, "jwks": jwks_ok })),
        )
            .into_response()
    }
}

/// `?since=` query for the delta endpoint; absent means "from the start".
#[derive(Debug, Deserialize)]
struct DeltaQuery {
    #[serde(default)]
    since: i64,
}

/// `GET /v1/sync/{site}/epoch` — the cheap staleness probe.
async fn sync_epoch(
    State(state): State<Arc<AppState>>,
    Path(site_code): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(rej) = authorize_site(&state.sync_validator, &headers, &site_code).await {
        return rej.into_response();
    }
    match state.store.epoch(&site_code).await {
        Ok(epoch) => Json(json!({ "epoch": epoch })).into_response(),
        Err(e) => store_error(&site_code, "epoch", &e),
    }
}

/// `GET /v1/sync/{site}/delta?since=N` — changes since epoch `N`. Returns
/// a tagged body: `{kind: "delta", ...}` to apply, or `{kind:
/// "must_snapshot", current}` when the caller's `since` is ahead of the
/// shard (its local DB regressed) and it must re-snapshot.
async fn sync_delta(
    State(state): State<Arc<AppState>>,
    Path(site_code): Path<String>,
    Query(q): Query<DeltaQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(rej) = authorize_site(&state.sync_validator, &headers, &site_code).await {
        return rej.into_response();
    }
    match state.store.delta(&site_code, q.since).await {
        Ok(result @ (DeltaResult::Delta { .. } | DeltaResult::MustSnapshot { .. })) => {
            Json(result).into_response()
        }
        Err(e) => store_error(&site_code, "delta", &e),
    }
}

/// `GET /v1/sync/{site}/snapshot` — the full live shard at the current epoch.
async fn sync_snapshot(
    State(state): State<Arc<AppState>>,
    Path(site_code): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(rej) = authorize_site(&state.sync_validator, &headers, &site_code).await {
        return rej.into_response();
    }
    match state.store.snapshot(&site_code).await {
        Ok(snap) => Json(snap).into_response(),
        Err(e) => store_error(&site_code, "snapshot", &e),
    }
}

/// `POST /v1/sync/{site}/upload` — a site uploads the local edits it made
/// while partitioned (DDIL reconcile). Authorized by the **site's own**
/// `config-sync` token (the same site-scoped check as the read surface),
/// so a base can adopt changes only into its own shard. Central applies
/// them in order — local wins — and they become central-origin, flowing
/// back to the site (now converged) and onward to the fleet. Returns the
/// resulting epoch.
async fn sync_upload(
    State(state): State<Arc<AppState>>,
    Path(site_code): Path<String>,
    headers: HeaderMap,
    Json(batch): Json<central_config_store::UploadBatch>,
) -> Response {
    let claims = match authorize_site(&state.sync_validator, &headers, &site_code).await {
        Ok(c) => c,
        Err(rej) => return rej.into_response(),
    };
    // Attribute the adoption to the uploading site's service account.
    let actor = format!("site:{}", claims.sub);
    let mut last_epoch = None;
    for change in &batch.changes {
        match state
            .store
            .apply_change(
                &site_code,
                change.table,
                change.op,
                &change.id,
                change.payload.as_ref(),
                &actor,
            )
            .await
        {
            Ok(epoch) => last_epoch = Some(epoch),
            // A delete of an already-absent row is fine during reconcile
            // (idempotent re-upload); keep going.
            Err(CentralError::NotFound) => {}
            Err(e) => return store_error(&site_code, "upload", &e),
        }
    }
    let epoch = match last_epoch {
        Some(e) => e,
        None => match state.store.epoch(&site_code).await {
            Ok(e) => e,
            Err(e) => return store_error(&site_code, "upload", &e),
        },
    };
    Json(json!({ "epoch": epoch, "applied": batch.changes.len() })).into_response()
}

/// Map a store error to an HTTP response. An unknown site is a clean 404;
/// everything else is an internal error (logged with context).
fn store_error(site: &str, op: &str, err: &CentralError) -> Response {
    match err {
        CentralError::UnknownSite(s) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "unknown_site", "site": s })),
        )
            .into_response(),
        other => {
            warn!(site, op, error = %other, "sync request failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "internal", "detail": other.to_string() })),
            )
                .into_response()
        }
    }
}

// ============================================================ write surface
//
// Operator-authorized (config-admin scope). Each write drives one
// transactional store call (epoch bump + revision stamp + journal) and is
// attributed to the token subject.

/// Normalize a MAC the same way the phone store and sync agent do.
fn normalize_mac(mac: &str) -> String {
    mac.replace([':', '-'], "").to_lowercase()
}

/// Map a write-path store error to HTTP.
fn write_error(err: &CentralError) -> Response {
    let (status, code) = match err {
        CentralError::UnknownSite(_) => (StatusCode::NOT_FOUND, "unknown_site"),
        CentralError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
        CentralError::DidConflict { .. } => (StatusCode::CONFLICT, "did_conflict"),
        CentralError::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
        CentralError::InvalidSiteCode(_) => (StatusCode::BAD_REQUEST, "invalid_site_code"),
        CentralError::Serialization(_) => (StatusCode::BAD_REQUEST, "bad_payload"),
        CentralError::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
    };
    (
        status,
        Json(json!({ "error": code, "detail": err.to_string() })),
    )
        .into_response()
}

/// 400 with a validation message.
fn bad_request(detail: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "bad_request", "detail": detail.into() })),
    )
        .into_response()
}

/// `{ epoch }` 200 on a successful write.
fn ok_epoch(epoch: i64) -> Response {
    Json(json!({ "epoch": epoch })).into_response()
}

// ----------------------------------------------------------- read surface
//
// Operator-authorized GET reads for the dashboard. Lists return
// `{ "items": [payload…] }`; single-row GETs return the payload or 404.

/// List a table's live rows for a site as `{ "items": [...] }`.
async fn do_list(
    state: &AppState,
    headers: &HeaderMap,
    site: &str,
    table: ConfigTable,
) -> Response {
    if let Err(rej) = authorize_operator(&state.admin_validator, headers).await {
        return rej.into_response();
    }
    match state.store.list_rows(table, site).await {
        Ok(rows) => {
            let items: Vec<Value> = rows.into_iter().map(|r| r.payload).collect();
            Json(json!({ "items": items })).into_response()
        }
        Err(e) => write_error(&e),
    }
}

/// Fetch one row's payload, or 404.
async fn do_get(
    state: &AppState,
    headers: &HeaderMap,
    site: &str,
    table: ConfigTable,
    id: &str,
) -> Response {
    if let Err(rej) = authorize_operator(&state.admin_validator, headers).await {
        return rej.into_response();
    }
    match state.store.get_row(table, site, id).await {
        Ok(Some(v)) => Json(v).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))).into_response(),
        Err(e) => write_error(&e),
    }
}

/// `GET /v1/sites` — list registered sites (the dashboard's site selector).
async fn list_sites(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(rej) = authorize_operator(&state.admin_validator, &headers).await {
        return rej.into_response();
    }
    match state.store.list_sites().await {
        Ok(sites) => Json(json!({ "sites": sites })).into_response(),
        Err(e) => write_error(&e),
    }
}

async fn list_phones(
    State(s): State<Arc<AppState>>,
    Path(site): Path<String>,
    h: HeaderMap,
) -> Response {
    do_list(&s, &h, &site, ConfigTable::Phones).await
}
async fn get_phone(
    State(s): State<Arc<AppState>>,
    Path((site, id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    do_get(&s, &h, &site, ConfigTable::Phones, &id).await
}
async fn list_directory(
    State(s): State<Arc<AppState>>,
    Path(site): Path<String>,
    h: HeaderMap,
) -> Response {
    do_list(&s, &h, &site, ConfigTable::DirectoryNumbers).await
}
async fn get_directory(
    State(s): State<Arc<AppState>>,
    Path((site, did)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    do_get(&s, &h, &site, ConfigTable::DirectoryNumbers, &did).await
}
async fn list_trunk_groups(
    State(s): State<Arc<AppState>>,
    Path(site): Path<String>,
    h: HeaderMap,
) -> Response {
    do_list(&s, &h, &site, ConfigTable::TrunkGroups).await
}
async fn get_trunk_group(
    State(s): State<Arc<AppState>>,
    Path((site, id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    do_get(&s, &h, &site, ConfigTable::TrunkGroups, &id).await
}
async fn list_dial_plans(
    State(s): State<Arc<AppState>>,
    Path(site): Path<String>,
    h: HeaderMap,
) -> Response {
    do_list(&s, &h, &site, ConfigTable::DialPlans).await
}
async fn get_dial_plan(
    State(s): State<Arc<AppState>>,
    Path((site, id)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    do_get(&s, &h, &site, ConfigTable::DialPlans, &id).await
}
async fn list_routing(
    State(s): State<Arc<AppState>>,
    Path((site, kind)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    match routing_table(&kind) {
        Some(t) => do_list(&s, &h, &site, t).await,
        None => bad_request("unknown routing kind"),
    }
}
async fn get_routing(
    State(s): State<Arc<AppState>>,
    Path((site, kind, id)): Path<(String, String, String)>,
    h: HeaderMap,
) -> Response {
    match routing_table(&kind) {
        Some(t) => do_get(&s, &h, &site, t, &id).await,
        None => bad_request("unknown routing kind"),
    }
}
/// `GET /v1/sites/{site}/config` — the site telephony settings document.
async fn get_site_config(
    State(s): State<Arc<AppState>>,
    Path(site): Path<String>,
    h: HeaderMap,
) -> Response {
    do_get(&s, &h, &site, ConfigTable::SiteTelephonyConfig, "default").await
}

/// `POST /v1/sites` — register a site (creates its partitions).
async fn register_site(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(rej) = authorize_operator(&state.admin_validator, &headers).await {
        return rej.into_response();
    }
    let Some(site) = body.get("site_code").and_then(Value::as_str) else {
        return bad_request("site_code is required");
    };
    let display = body
        .get("display_name")
        .and_then(Value::as_str)
        .unwrap_or(site);
    let Some(fqdn) = body.get("fqdn_base").and_then(Value::as_str) else {
        return bad_request("fqdn_base is required");
    };
    let tz = body
        .get("timezone")
        .and_then(Value::as_str)
        .unwrap_or("UTC");
    let status = body
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("planned");
    match state
        .store
        .register_site(site, display, fqdn, tz, status)
        .await
    {
        Ok(()) => (StatusCode::CREATED, Json(json!({ "site_code": site }))).into_response(),
        Err(e) => write_error(&e),
    }
}

/// `POST /v1/sites/{site}/phones` — upsert a phone (body is the Phone JSON).
async fn upsert_phone(
    State(state): State<Arc<AppState>>,
    Path(site): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize_operator(&state.admin_validator, &headers).await {
        Ok(c) => c.sub,
        Err(rej) => return rej.into_response(),
    };
    let Some(id) = body.get("id").and_then(Value::as_str) else {
        return bad_request("phone id is required");
    };
    let Some(mac) = body.get("mac_address").and_then(Value::as_str) else {
        return bad_request("mac_address is required");
    };
    match state
        .store
        .upsert_phone(&site, id, &normalize_mac(mac), &body, &actor)
        .await
    {
        Ok(epoch) => ok_epoch(epoch),
        Err(e) => write_error(&e),
    }
}

/// `DELETE /v1/sites/{site}/phones/{id}` — tombstone a phone.
async fn delete_phone(
    State(state): State<Arc<AppState>>,
    Path((site, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let actor = match authorize_operator(&state.admin_validator, &headers).await {
        Ok(c) => c.sub,
        Err(rej) => return rej.into_response(),
    };
    match state
        .store
        .delete(ConfigTable::Phones, &site, &id, &actor)
        .await
    {
        Ok(epoch) => ok_epoch(epoch),
        Err(e) => write_error(&e),
    }
}

/// `POST /v1/sites/{site}/directory` — upsert a DID (body `{did, user?, …}`).
async fn upsert_did(
    State(state): State<Arc<AppState>>,
    Path(site): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize_operator(&state.admin_validator, &headers).await {
        Ok(c) => c.sub,
        Err(rej) => return rej.into_response(),
    };
    let Some(obj) = body.as_object() else {
        return bad_request("directory body must be a JSON object");
    };
    let Some(did) = obj.get("did").and_then(Value::as_str) else {
        return bad_request("did is required");
    };
    let str_field = |k: &str| obj.get(k).and_then(Value::as_str).map(str::to_string);
    let (user, partition, description) = (
        str_field("user"),
        str_field("partition"),
        str_field("description"),
    );
    // Everything else becomes `extra`.
    let mut extra = obj.clone();
    for k in ["did", "user", "partition", "description"] {
        extra.remove(k);
    }
    match state
        .store
        .upsert_did(
            &site,
            did,
            user.as_deref(),
            partition.as_deref(),
            description.as_deref(),
            &extra,
            &actor,
        )
        .await
    {
        Ok(epoch) => ok_epoch(epoch),
        Err(e) => write_error(&e),
    }
}

/// `DELETE /v1/sites/{site}/directory/{did}` — tombstone a DID.
async fn delete_did(
    State(state): State<Arc<AppState>>,
    Path((site, did)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let actor = match authorize_operator(&state.admin_validator, &headers).await {
        Ok(c) => c.sub,
        Err(rej) => return rej.into_response(),
    };
    match state
        .store
        .delete(ConfigTable::DirectoryNumbers, &site, &did, &actor)
        .await
    {
        Ok(epoch) => ok_epoch(epoch),
        Err(e) => write_error(&e),
    }
}

/// `POST /v1/sites/{site}/trunkgroups` — upsert a trunk group, validated
/// against the typed `TrunkGroupConfig` schema before it's stored.
async fn upsert_trunk_group(
    State(state): State<Arc<AppState>>,
    Path(site): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize_operator(&state.admin_validator, &headers).await {
        Ok(c) => c.sub,
        Err(rej) => return rej.into_response(),
    };
    let cfg = match serde_json::from_value::<sbc_config::schema::TrunkGroupConfig>(body.clone()) {
        Ok(c) => c,
        Err(e) => return bad_request(format!("invalid trunk group: {e}")),
    };
    match state
        .store
        .upsert_json(ConfigTable::TrunkGroups, &site, &cfg.id, &body, &actor)
        .await
    {
        Ok(epoch) => ok_epoch(epoch),
        Err(e) => write_error(&e),
    }
}

/// `DELETE /v1/sites/{site}/trunkgroups/{id}`.
async fn delete_trunk_group(
    State(state): State<Arc<AppState>>,
    Path((site, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let actor = match authorize_operator(&state.admin_validator, &headers).await {
        Ok(c) => c.sub,
        Err(rej) => return rej.into_response(),
    };
    match state
        .store
        .delete(ConfigTable::TrunkGroups, &site, &id, &actor)
        .await
    {
        Ok(epoch) => ok_epoch(epoch),
        Err(e) => write_error(&e),
    }
}

/// `POST /v1/sites/{site}/dialplans` — upsert a dial plan, validated
/// against the typed `DialPlanConfig` schema.
async fn upsert_dial_plan(
    State(state): State<Arc<AppState>>,
    Path(site): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize_operator(&state.admin_validator, &headers).await {
        Ok(c) => c.sub,
        Err(rej) => return rej.into_response(),
    };
    let cfg = match serde_json::from_value::<sbc_config::schema::DialPlanConfig>(body.clone()) {
        Ok(c) => c,
        Err(e) => return bad_request(format!("invalid dial plan: {e}")),
    };
    match state
        .store
        .upsert_json(ConfigTable::DialPlans, &site, &cfg.id, &body, &actor)
        .await
    {
        Ok(epoch) => ok_epoch(epoch),
        Err(e) => write_error(&e),
    }
}

/// `DELETE /v1/sites/{site}/dialplans/{id}`.
async fn delete_dial_plan(
    State(state): State<Arc<AppState>>,
    Path((site, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let actor = match authorize_operator(&state.admin_validator, &headers).await {
        Ok(c) => c.sub,
        Err(rej) => return rej.into_response(),
    };
    match state
        .store
        .delete(ConfigTable::DialPlans, &site, &id, &actor)
        .await
    {
        Ok(epoch) => ok_epoch(epoch),
        Err(e) => write_error(&e),
    }
}

/// Map a `{kind}` routing path segment to its config table.
fn routing_table(kind: &str) -> Option<ConfigTable> {
    match kind {
        "partitions" => Some(ConfigTable::SbcPartitions),
        "calling_search_spaces" => Some(ConfigTable::SbcCallingSearchSpaces),
        "route_patterns" => Some(ConfigTable::SbcRoutePatterns),
        "route_lists" => Some(ConfigTable::SbcRouteLists),
        _ => None,
    }
}

/// `POST /v1/sites/{site}/routing/{kind}` — upsert an SBC routing entity
/// (body is the entity JSON; must carry an `id`).
async fn upsert_routing(
    State(state): State<Arc<AppState>>,
    Path((site, kind)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize_operator(&state.admin_validator, &headers).await {
        Ok(c) => c.sub,
        Err(rej) => return rej.into_response(),
    };
    let Some(table) = routing_table(&kind) else {
        return bad_request(
            "kind must be partitions, calling_search_spaces, route_patterns, or route_lists",
        );
    };
    let Some(id) = body.get("id").and_then(Value::as_str) else {
        return bad_request("routing entity id is required");
    };
    match state
        .store
        .upsert_json(table, &site, id, &body, &actor)
        .await
    {
        Ok(epoch) => ok_epoch(epoch),
        Err(e) => write_error(&e),
    }
}

/// `DELETE /v1/sites/{site}/routing/{kind}/{id}` — tombstone a routing entity.
async fn delete_routing(
    State(state): State<Arc<AppState>>,
    Path((site, kind, id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    let actor = match authorize_operator(&state.admin_validator, &headers).await {
        Ok(c) => c.sub,
        Err(rej) => return rej.into_response(),
    };
    let Some(table) = routing_table(&kind) else {
        return bad_request("unknown routing kind");
    };
    match state.store.delete(table, &site, &id, &actor).await {
        Ok(epoch) => ok_epoch(epoch),
        Err(e) => write_error(&e),
    }
}

/// `PUT /v1/sites/{site}/config` — replace the site's telephony settings
/// document (a single `default` row).
async fn put_site_config(
    State(state): State<Arc<AppState>>,
    Path(site): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize_operator(&state.admin_validator, &headers).await {
        Ok(c) => c.sub,
        Err(rej) => return rej.into_response(),
    };
    if !body.is_object() {
        return bad_request("site config must be a JSON object");
    }
    match state
        .store
        .upsert_json(
            ConfigTable::SiteTelephonyConfig,
            &site,
            "default",
            &body,
            &actor,
        )
        .await
    {
        Ok(epoch) => ok_epoch(epoch),
        Err(e) => write_error(&e),
    }
}

/// `PUT /v1/templates/{kind}/{id}` — author/update a global template.
async fn put_template(
    State(state): State<Arc<AppState>>,
    Path((kind, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let actor = match authorize_operator(&state.admin_validator, &headers).await {
        Ok(c) => c.sub,
        Err(rej) => return rej.into_response(),
    };
    let kind = match parse_kind(&kind) {
        Ok(k) => k,
        Err(r) => return r,
    };
    match state.store.upsert_template(kind, &id, &body, &actor).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "id": id }))).into_response(),
        Err(e) => write_error(&e),
    }
}

/// `DELETE /v1/templates/{kind}/{id}` — delete a template (tombstones its
/// materialized rows, leaves site overrides).
async fn delete_template(
    State(state): State<Arc<AppState>>,
    Path((kind, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if let Err(rej) = authorize_operator(&state.admin_validator, &headers).await {
        return rej.into_response();
    }
    let kind = match parse_kind(&kind) {
        Ok(k) => k,
        Err(r) => return r,
    };
    match state.store.delete_template(kind, &id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => write_error(&e),
    }
}

/// `PUT /v1/templates/{kind}/{id}/sites/{site}` — assign a template to a
/// site in a rollout ring (body `{ "ring": N }`, default 0).
async fn assign_template(
    State(state): State<Arc<AppState>>,
    Path((kind, id, site)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if let Err(rej) = authorize_operator(&state.admin_validator, &headers).await {
        return rej.into_response();
    }
    let kind = match parse_kind(&kind) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let ring = body
        .get("ring")
        .and_then(serde_json::Value::as_i64)
        .and_then(|n| i32::try_from(n).ok())
        .unwrap_or(0);
    match state.store.assign_template(kind, &id, &site, ring).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({ "site_code": site, "ring": ring })),
        )
            .into_response(),
        Err(e) => write_error(&e),
    }
}

/// `?ring=` ceiling for materialization; absent means ring 0 (canary only).
#[derive(Debug, Deserialize)]
struct MaterializeQuery {
    #[serde(default)]
    ring: i32,
}

/// `POST /v1/templates/{kind}/{id}/materialize?ring=N` — materialize the
/// template into assigned sites up to ring `N`, returning a per-site report.
async fn materialize_template(
    State(state): State<Arc<AppState>>,
    Path((kind, id)): Path<(String, String)>,
    Query(q): Query<MaterializeQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(rej) = authorize_operator(&state.admin_validator, &headers).await {
        return rej.into_response();
    }
    let kind = match parse_kind(&kind) {
        Ok(k) => k,
        Err(r) => return r,
    };
    match state.store.materialize_template(kind, &id, q.ring).await {
        Ok(report) => Json(report).into_response(),
        Err(e) => write_error(&e),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::option_if_let_else)]
mod tests {
    //! End-to-end HTTP tests over the real router, store, and OIDC
    //! validator. The bearer tokens are minted with a fresh ES256 key
    //! (no private material in the tree) and a static JWKS. Skipped
    //! unless `CENTRAL_STORE_TEST_DSN` (CREATE DATABASE rights) is set:
    //!
    //! ```sh
    //! CENTRAL_STORE_TEST_DSN=postgres://postgres@127.0.0.1:5432/postgres \
    //!     cargo test -p central-config-api
    //! ```

    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use proto_jwt::{JwksCache, Validator, ValidatorConfig};
    use serde_json::Value;
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
    use tower::ServiceExt;

    use central_config_store::CentralConfigStore;

    use super::*;
    use crate::state::{ADMIN_SCOPE, AppState, SYNC_SCOPE};

    const TEST_KID: &str = "test-key-1";
    const TEST_ISSUER: &str = "https://idp.example.mil/realms/config";
    const TEST_AUDIENCE: &str = "usg-uc-config-sync";

    struct TestKey {
        encoding: EncodingKey,
        jwks: JwkSet,
    }

    /// Fresh ES256 keypair, once per process.
    fn test_key() -> &'static TestKey {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        static KEY: std::sync::OnceLock<TestKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &SystemRandom::new(),
            )
            .expect("generate key");
            let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
                .expect("parse key");
            let point = pair.public_key().as_ref();
            let jwks = serde_json::from_value(serde_json::json!({
                "keys": [{
                    "kty": "EC", "crv": "P-256", "kid": TEST_KID, "alg": "ES256", "use": "sig",
                    "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
                    "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
                }]
            }))
            .expect("jwks");
            TestKey {
                encoding: EncodingKey::from_ec_der(pkcs8.as_ref()),
                jwks,
            }
        })
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs()
    }

    /// Mint a token. Overridable bits let each test bend exactly one
    /// dimension (scope, site, audience, expiry).
    fn mint(site_code: Option<&str>, scope: &str, aud: &str, exp: u64) -> String {
        let mut claims = serde_json::Map::new();
        claims.insert("sub".into(), "svc-sync".into());
        claims.insert("iss".into(), TEST_ISSUER.into());
        claims.insert("aud".into(), aud.into());
        claims.insert("scope".into(), scope.into());
        claims.insert("exp".into(), exp.into());
        if let Some(s) = site_code {
            claims.insert("site_code".into(), s.into());
        }
        let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(TEST_KID.to_string());
        encode(&header, &Value::Object(claims), &test_key().encoding).expect("encode token")
    }

    /// A valid token for `site` with the right scope/audience, far expiry.
    fn good_token(site: &str) -> String {
        mint(Some(site), SYNC_SCOPE, TEST_AUDIENCE, now() + 3600)
    }

    async fn scratch_store(admin: &str, name: &str) -> CentralConfigStore {
        let opts = PgConnectOptions::from_str(admin).expect("parse dsn");
        let admin_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(opts.clone())
            .await
            .expect("admin connect");
        sqlx::query(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
            .execute(&admin_pool)
            .await
            .expect("drop");
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin_pool)
            .await
            .expect("create");
        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect_with(opts.database(name))
            .await
            .expect("scratch connect");
        CentralConfigStore::from_pool(pool).await.expect("migrate")
    }

    /// Build the router over a scratch store seeded with one site + phone.
    async fn app(admin: &str, name: &str) -> Router {
        let store = scratch_store(admin, name).await;
        store
            .register_site("MUHJ", "MUHJ", "muhj.x", "UTC", "active")
            .await
            .expect("register");
        store
            .upsert_phone(
                "MUHJ",
                "p1",
                "aabbccddeeff",
                &serde_json::json!({"id": "p1"}),
                "op",
            )
            .await
            .expect("seed phone");
        let jwks = Arc::new(JwksCache::with_static(test_key().jwks.clone()));
        let validator_for = |scope: &'static str| {
            Arc::new(Validator::new(
                Arc::clone(&jwks),
                ValidatorConfig {
                    issuer: TEST_ISSUER.to_string(),
                    audiences: vec![TEST_AUDIENCE.to_string()],
                    required_scope: scope,
                    leeway_secs: 30,
                },
            ))
        };
        router(Arc::new(AppState {
            store,
            sync_validator: validator_for(SYNC_SCOPE),
            admin_validator: validator_for(ADMIN_SCOPE),
            start_time: Instant::now(),
        }))
    }

    async fn send(app: &Router, uri: &str, auth: Option<&str>) -> (StatusCode, Value) {
        let mut req = Request::builder().uri(uri).method("GET");
        if let Some(token) = auth {
            req = req.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).expect("req"))
            .await
            .expect("response");
        let status = resp.status();
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json body")
        };
        (status, body)
    }

    /// Send a request with a method, optional JSON body, and bearer token.
    async fn send_req(
        app: &Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut req = Request::builder().uri(uri).method(method);
        if let Some(t) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let body = match body {
            Some(v) => {
                req = req.header(header::CONTENT_TYPE, "application/json");
                Body::from(serde_json::to_vec(&v).expect("encode body"))
            }
            None => Body::empty(),
        };
        let resp = app
            .clone()
            .oneshot(req.body(body).expect("req"))
            .await
            .expect("response");
        let status = resp.status();
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json")
        };
        (status, body)
    }

    /// An operator token (config-admin scope, no site claim).
    fn admin_token() -> String {
        mint(None, ADMIN_SCOPE, TEST_AUDIENCE, now() + 3600)
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn write_surface_authz_validation_and_epochs() {
        let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
            return;
        };
        let app = app(&admin, "cca_writes").await; // seeds site MUHJ + phone p1 (epoch 1)
        let admin_tok = admin_token();

        // A site sync token must NOT be able to write (wrong scope here).
        let (s, _) = send_req(
            &app,
            "POST",
            "/v1/sites/MUHJ/phones",
            Some(&good_token("MUHJ")),
            Some(json!({"id": "p9", "mac_address": "99:99:99:99:99:99"})),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "sync-scoped token cannot write");

        // No token → 401.
        let (s, _) = send_req(&app, "POST", "/v1/sites/MUHJ/phones", None, Some(json!({}))).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);

        // Operator upsert lands and bumps the epoch (seed was 1 → 2).
        let (s, b) = send_req(
            &app,
            "POST",
            "/v1/sites/MUHJ/phones",
            Some(&admin_tok),
            Some(json!({"id": "p2", "mac_address": "22:22:22:22:22:22"})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["epoch"], 2);

        // Missing required field → 400.
        let (s, _) = send_req(
            &app,
            "POST",
            "/v1/sites/MUHJ/phones",
            Some(&admin_tok),
            Some(json!({"mac_address": "33:33:33:33:33:33"})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "phone id required");

        // Typed validation: a trunk group with no id fails the schema → 400.
        let (s, _) = send_req(
            &app,
            "POST",
            "/v1/sites/MUHJ/trunkgroups",
            Some(&admin_tok),
            Some(json!({"name": "no id here"})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "trunk group must validate");

        // A valid trunk group stores and bumps the epoch (2 → 3).
        let (s, b) = send_req(
            &app,
            "POST",
            "/v1/sites/MUHJ/trunkgroups",
            Some(&admin_tok),
            Some(json!({"id": "us-domestic", "strategy": "priority", "trunks": []})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["epoch"], 3);

        // Register a brand-new site, then write into it.
        let (s, _) = send_req(
            &app,
            "POST",
            "/v1/sites",
            Some(&admin_tok),
            Some(json!({"site_code": "MPLS", "fqdn_base": "mpls.x"})),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED);
        let (s, b) = send_req(
            &app,
            "POST",
            "/v1/sites/MPLS/dialplans",
            Some(&admin_tok),
            Some(json!({"id": "main", "entries": []})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["epoch"], 1, "new site's first write is epoch 1");

        // Writing to an unregistered site → 404.
        let (s, _) = send_req(
            &app,
            "POST",
            "/v1/sites/GHST/dialplans",
            Some(&admin_tok),
            Some(json!({"id": "main", "entries": []})),
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);

        // Delete the seeded phone (tombstone), epoch advances; re-delete 404s.
        let (s, _) = send_req(
            &app,
            "DELETE",
            "/v1/sites/MUHJ/phones/p1",
            Some(&admin_tok),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = send_req(
            &app,
            "DELETE",
            "/v1/sites/MUHJ/phones/p1",
            Some(&admin_tok),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "second delete finds no live row");

        // The writes are visible on the sync surface the agent pulls.
        let (s, b) = send(&app, "/v1/sync/MUHJ/snapshot", Some(&good_token("MUHJ"))).await;
        assert_eq!(s, StatusCode::OK);
        let tg = b["tables"]
            .as_array()
            .expect("tables")
            .iter()
            .find(|t| t["table"] == "trunk_groups")
            .expect("trunk_groups");
        assert_eq!(tg["rows"].as_array().expect("rows").len(), 1);

        // Template flow over HTTP: author → assign MPLS at ring 0 →
        // materialize → MPLS's dial_plans shard gets the materialized row.
        let (s, _) = send_req(
            &app,
            "PUT",
            "/v1/templates/dial_plan/baseline",
            Some(&admin_tok),
            Some(json!({"id": "baseline", "entries": []})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = send_req(
            &app,
            "PUT",
            "/v1/templates/dial_plan/baseline/sites/MPLS",
            Some(&admin_tok),
            Some(json!({"ring": 0})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let (s, b) = send_req(
            &app,
            "POST",
            "/v1/templates/dial_plan/baseline/materialize?ring=0",
            Some(&admin_tok),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let applied = b["sites"]
            .as_array()
            .expect("sites")
            .iter()
            .any(|x| x["result"] == "applied" && x["site_code"] == "MPLS");
        assert!(applied, "MPLS materialized: {b}");

        // Invalid kind → 400.
        let (s, _) = send_req(
            &app,
            "PUT",
            "/v1/templates/bogus/x",
            Some(&admin_tok),
            Some(json!({"id": "x"})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);

        // SBC routing entities: upsert a partition (200), unknown kind (400),
        // then delete it (200).
        let (s, _) = send_req(
            &app,
            "POST",
            "/v1/sites/MUHJ/routing/partitions",
            Some(&admin_tok),
            Some(json!({"id": "internal", "description": "on-net"})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = send_req(
            &app,
            "POST",
            "/v1/sites/MUHJ/routing/bogus",
            Some(&admin_tok),
            Some(json!({"id": "x"})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = send_req(
            &app,
            "DELETE",
            "/v1/sites/MUHJ/routing/partitions/internal",
            Some(&admin_tok),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK);

        // Operator reads (the dashboard's GETs): list sites, list phones,
        // get one phone, and a get-miss → 404.
        let (s, b) = send_req(&app, "GET", "/v1/sites", Some(&admin_tok), None).await;
        assert_eq!(s, StatusCode::OK);
        let sites = b["sites"].as_array().expect("sites");
        assert!(sites.iter().any(|x| x["site_code"] == "MUHJ"));
        assert!(sites.iter().any(|x| x["site_code"] == "MPLS"));

        let (s, b) = send_req(&app, "GET", "/v1/sites/MUHJ/phones", Some(&admin_tok), None).await;
        assert_eq!(s, StatusCode::OK);
        let items = b["items"].as_array().expect("items");
        assert!(
            items.iter().any(|p| p["id"] == "p2"),
            "p1 was deleted, p2 listed: {b}"
        );

        let (s, b) = send_req(
            &app,
            "GET",
            "/v1/sites/MUHJ/phones/p2",
            Some(&admin_tok),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["id"], "p2");

        let (s, _) = send_req(
            &app,
            "GET",
            "/v1/sites/MUHJ/phones/ghost",
            Some(&admin_tok),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND);

        // A GET still requires the admin scope (a sync token is rejected).
        let (s, _) = send_req(
            &app,
            "GET",
            "/v1/sites/MUHJ/phones",
            Some(&good_token("MUHJ")),
            None,
        )
        .await;
        assert_eq!(
            s,
            StatusCode::FORBIDDEN,
            "config-sync token can't use the operator read surface"
        );
    }

    #[tokio::test]
    async fn authz_matrix_and_sync_responses() {
        let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
            return;
        };
        let app = app(&admin, "cca_authz").await;

        // Health needs no auth.
        let (s, _) = send(&app, "/healthz", None).await;
        assert_eq!(s, StatusCode::OK);

        // No token → 401.
        let (s, _) = send(&app, "/v1/sync/MUHJ/epoch", None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);

        // Garbage token → 401.
        let (s, _) = send(&app, "/v1/sync/MUHJ/epoch", Some("not-a-jwt")).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);

        // Expired token (well past the validator's leeway) → 401.
        let expired = mint(Some("MUHJ"), SYNC_SCOPE, TEST_AUDIENCE, now() - 3600);
        let (s, _) = send(&app, "/v1/sync/MUHJ/epoch", Some(&expired)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);

        // Wrong scope → 403 insufficient_scope.
        let no_scope = mint(Some("MUHJ"), "openid", TEST_AUDIENCE, now() + 3600);
        let (s, b) = send(&app, "/v1/sync/MUHJ/epoch", Some(&no_scope)).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(b["error"], "insufficient_scope");

        // Wrong audience → 401 (invalid token).
        let bad_aud = mint(Some("MUHJ"), SYNC_SCOPE, "some-other-api", now() + 3600);
        let (s, _) = send(&app, "/v1/sync/MUHJ/epoch", Some(&bad_aud)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);

        // Token for a different site → 403 wrong_site (the boundary).
        let (s, b) = send(&app, "/v1/sync/MUHJ/epoch", Some(&good_token("MPLS"))).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(b["error"], "wrong_site");

        // Token with no site_code claim → 403 wrong_site.
        let no_site = mint(None, SYNC_SCOPE, TEST_AUDIENCE, now() + 3600);
        let (s, b) = send(&app, "/v1/sync/MUHJ/epoch", Some(&no_site)).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(b["error"], "wrong_site");

        // Happy path: epoch.
        let token = good_token("MUHJ");
        let (s, b) = send(&app, "/v1/sync/MUHJ/epoch", Some(&token)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["epoch"], 1);

        // Delta from 0 → one change (the seeded phone).
        let (s, b) = send(&app, "/v1/sync/MUHJ/delta?since=0", Some(&token)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["kind"], "delta");
        assert_eq!(b["to"], 1);
        assert_eq!(b["changes"].as_array().expect("changes").len(), 1);

        // Delta with since ahead → must_snapshot directive.
        let (s, b) = send(&app, "/v1/sync/MUHJ/delta?since=999", Some(&token)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["kind"], "must_snapshot");
        assert_eq!(b["current"], 1);

        // Snapshot → the live phone.
        let (s, b) = send(&app, "/v1/sync/MUHJ/snapshot", Some(&token)).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["epoch"], 1);
        let phones = b["tables"]
            .as_array()
            .expect("tables")
            .iter()
            .find(|t| t["table"] == "phones")
            .expect("phones table");
        let rows = phones["rows"].as_array().expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], "p1");
        assert_eq!(rows[0]["payload"], serde_json::json!({"id": "p1"}));

        // A site that exists in auth but not the registry: token for a
        // never-registered site (auth passes on claim match, store 404s).
        let (s, b) = send(&app, "/v1/sync/GHST/epoch", Some(&good_token("GHST"))).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(b["error"], "unknown_site");

        // Upload (DDIL reconcile): a site uploads a local edit to its OWN
        // shard with its config-sync token → adopted, epoch bumps.
        let upload = json!({ "changes": [
            { "table": "phones", "id": "p-edge", "op": "upsert",
              "payload": { "id": "p-edge", "mac_address": "ab:cd:ef:00:11:22" } }
        ]});
        let (s, b) = send_req(
            &app,
            "POST",
            "/v1/sync/MUHJ/upload",
            Some(&good_token("MUHJ")),
            Some(upload.clone()),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["applied"], 1);

        // The uploaded row is now served on the snapshot.
        let (_, b) = send(&app, "/v1/sync/MUHJ/snapshot", Some(&good_token("MUHJ"))).await;
        let has_edge = b["tables"].as_array().expect("tables").iter().any(|t| {
            t["table"] == "phones"
                && t["rows"]
                    .as_array()
                    .is_some_and(|r| r.iter().any(|x| x["id"] == "p-edge"))
        });
        assert!(has_edge, "uploaded phone present: {b}");

        // A token for another site cannot upload into MUHJ's shard.
        let (s, _) = send_req(
            &app,
            "POST",
            "/v1/sync/MUHJ/upload",
            Some(&good_token("MPLS")),
            Some(upload),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "cross-site upload rejected");
    }

    /// End-to-end over the real HTTP wire: boot the router on a port and
    /// drive it with the *actual* sync-agent client (`CentralClient` +
    /// `reconcile`), not the in-process router. Exercises reqwest GET/POST,
    /// JSON (de)serialization across the boundary, bearer headers, the
    /// pull (snapshot + delta) and the DDIL upload — the seams the other
    /// tests only reach in-process.
    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn http_wire_pull_and_ddil_upload() {
        let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
            return;
        };

        // Central store behind the booted API.
        let central = scratch_store(&admin, "cca_wire_central").await;
        central
            .register_site("MUHJ", "MUHJ", "muhj.x", "UTC", "active")
            .await
            .expect("register");
        central
            .upsert_phone(
                "MUHJ",
                "p1",
                "aaaaaaaaaaaa",
                &json!({"id": "p1", "mac_address": "aa:aa:aa:aa:aa:aa"}),
                "op",
            )
            .await
            .expect("seed p1");

        // Boot the real router on an ephemeral port.
        let jwks = Arc::new(JwksCache::with_static(test_key().jwks.clone()));
        let validator_for = |scope: &'static str| {
            Arc::new(Validator::new(
                Arc::clone(&jwks),
                ValidatorConfig {
                    issuer: TEST_ISSUER.to_string(),
                    audiences: vec![TEST_AUDIENCE.to_string()],
                    required_scope: scope,
                    leeway_secs: 30,
                },
            ))
        };
        let app = router(Arc::new(AppState {
            store: central.clone(),
            sync_validator: validator_for(SYNC_SCOPE),
            admin_validator: validator_for(ADMIN_SCOPE),
            start_time: Instant::now(),
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let base_url = format!("http://{addr}");

        // The real sync-agent client over real HTTP, with a static token.
        let client = sbc_config_sync::CentralClient::new(
            reqwest::Client::new(),
            base_url,
            sbc_config_sync::Auth::Static(good_token("MUHJ")),
        );

        // A real site-local DB with the SBC schema for the agent to apply into.
        let local = {
            let opts = PgConnectOptions::from_str(&admin).expect("dsn");
            let admin_pool = PgPoolOptions::new()
                .max_connections(1)
                .connect_with(opts.clone())
                .await
                .expect("admin");
            sqlx::query("DROP DATABASE IF EXISTS cca_wire_local WITH (FORCE)")
                .execute(&admin_pool)
                .await
                .expect("drop");
            sqlx::query("CREATE DATABASE cca_wire_local")
                .execute(&admin_pool)
                .await
                .expect("create");
            PgPoolOptions::new()
                .max_connections(5)
                .connect_with(opts.database("cca_wire_local"))
                .await
                .expect("local connect")
        };
        sbc_config_store::ensure_schema(&local)
            .await
            .expect("local schema");

        // First reconcile over HTTP: never-synced → snapshot pull.
        let outcome =
            sbc_config_sync::reconcile(&local, &client, &sbc_config_sync::NoopRefresher, "MUHJ")
                .await
                .expect("reconcile over http");
        assert!(
            matches!(outcome, sbc_config_sync::Outcome::Snapshotted { .. }),
            "got {outcome:?}"
        );
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM phones WHERE id = 'p1' AND NOT deleted")
                .fetch_one(&local)
                .await
                .expect("count");
        assert_eq!(n, 1, "snapshot pulled the phone over HTTP");

        // Central adds a phone → delta pull over HTTP.
        central
            .upsert_phone(
                "MUHJ",
                "p2",
                "bbbbbbbbbbbb",
                &json!({"id": "p2", "mac_address": "bb:bb:bb:bb:bb:bb"}),
                "op",
            )
            .await
            .expect("p2");
        sbc_config_sync::reconcile(&local, &client, &sbc_config_sync::NoopRefresher, "MUHJ")
            .await
            .expect("delta over http");
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM phones WHERE NOT deleted")
            .fetch_one(&local)
            .await
            .expect("count");
        assert_eq!(n, 2, "delta pulled p2 over HTTP");

        // DDIL: a local edit, then reconcile uploads it over HTTP and
        // central adopts it (local wins).
        sqlx::query(
            "INSERT INTO phones (id, mac_normalized, data, updated_by) VALUES ($1,$2,$3,'local')",
        )
        .bind("p-edge")
        .bind("cccccccccccc")
        .bind(json!({"id":"p-edge","mac_address":"cc:cc:cc:cc:cc:cc"}))
        .execute(&local)
        .await
        .expect("local edit");
        sbc_config_sync::reconcile(&local, &client, &sbc_config_sync::NoopRefresher, "MUHJ")
            .await
            .expect("upload over http");
        // The edit reached central through POST /upload.
        let snap = central.snapshot("MUHJ").await.expect("central snapshot");
        let has_edge = snap
            .tables
            .iter()
            .find(|t| t.table == ConfigTable::Phones)
            .is_some_and(|t| t.rows.iter().any(|r| r.id == "p-edge"));
        assert!(has_edge, "local edit uploaded to central over HTTP");
    }
}
