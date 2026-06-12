//! HTTP surface: health probes and the site-scoped sync endpoints.
//!
//! Sync is the fleet-facing read API the per-site `sbc-config-sync` agent
//! pulls. Each handler authorizes the caller against the path's
//! `site_code` (see [`crate::auth`]) before touching the store, so a
//! site can only ever read its own shard.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::Json;
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
        // Operator write surface (config-admin tokens).
        .route("/v1/sites", post(register_site))
        .route("/v1/sites/{site_code}/phones", post(upsert_phone))
        .route("/v1/sites/{site_code}/phones/{id}", axum::routing::delete(delete_phone))
        .route("/v1/sites/{site_code}/directory", post(upsert_did))
        .route("/v1/sites/{site_code}/directory/{did}", axum::routing::delete(delete_did))
        .route("/v1/sites/{site_code}/trunkgroups", post(upsert_trunk_group))
        .route("/v1/sites/{site_code}/trunkgroups/{id}", axum::routing::delete(delete_trunk_group))
        .route("/v1/sites/{site_code}/dialplans", post(upsert_dial_plan))
        .route("/v1/sites/{site_code}/dialplans/{id}", axum::routing::delete(delete_dial_plan))
        .route("/v1/sites/{site_code}/config", put(put_site_config))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
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
    (status, Json(json!({ "error": code, "detail": err.to_string() }))).into_response()
}

/// 400 with a validation message.
fn bad_request(detail: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": "bad_request", "detail": detail.into() })))
        .into_response()
}

/// `{ epoch }` 200 on a successful write.
fn ok_epoch(epoch: i64) -> Response {
    Json(json!({ "epoch": epoch })).into_response()
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
    let display = body.get("display_name").and_then(Value::as_str).unwrap_or(site);
    let Some(fqdn) = body.get("fqdn_base").and_then(Value::as_str) else {
        return bad_request("fqdn_base is required");
    };
    let tz = body.get("timezone").and_then(Value::as_str).unwrap_or("UTC");
    let status = body.get("status").and_then(Value::as_str).unwrap_or("planned");
    match state.store.register_site(site, display, fqdn, tz, status).await {
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
    match state.store.upsert_phone(&site, id, &normalize_mac(mac), &body, &actor).await {
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
    match state.store.delete(ConfigTable::Phones, &site, &id, &actor).await {
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
    let (user, partition, description) =
        (str_field("user"), str_field("partition"), str_field("description"));
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
    match state.store.delete(ConfigTable::DirectoryNumbers, &site, &did, &actor).await {
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
    match state.store.upsert_json(ConfigTable::TrunkGroups, &site, &cfg.id, &body, &actor).await {
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
    match state.store.delete(ConfigTable::TrunkGroups, &site, &id, &actor).await {
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
    match state.store.upsert_json(ConfigTable::DialPlans, &site, &cfg.id, &body, &actor).await {
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
    match state.store.delete(ConfigTable::DialPlans, &site, &id, &actor).await {
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
        .upsert_json(ConfigTable::SiteTelephonyConfig, &site, "default", &body, &actor)
        .await
    {
        Ok(epoch) => ok_epoch(epoch),
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
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
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
            TestKey { encoding: EncodingKey::from_ec_der(pkcs8.as_ref()), jwks }
        })
    }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs()
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
        sqlx::query(&format!("CREATE DATABASE {name}")).execute(&admin_pool).await.expect("create");
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
        store.register_site("MUHJ", "MUHJ", "muhj.x", "UTC", "active").await.expect("register");
        store
            .upsert_phone("MUHJ", "p1", "aabbccddeeff", &serde_json::json!({"id": "p1"}), "op")
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
        let resp = app.clone().oneshot(req.body(body).expect("req")).await.expect("response");
        let status = resp.status();
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        let body =
            if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).expect("json") };
        (status, body)
    }

    /// An operator token (config-admin scope, no site claim).
    fn admin_token() -> String {
        mint(None, ADMIN_SCOPE, TEST_AUDIENCE, now() + 3600)
    }

    #[tokio::test]
    async fn write_surface_authz_validation_and_epochs() {
        let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else { return };
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
        let (s, _) =
            send_req(&app, "DELETE", "/v1/sites/MUHJ/phones/p1", Some(&admin_tok), None).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) =
            send_req(&app, "DELETE", "/v1/sites/MUHJ/phones/p1", Some(&admin_tok), None).await;
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
    }

    #[tokio::test]
    async fn authz_matrix_and_sync_responses() {
        let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else { return };
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
    }
}
