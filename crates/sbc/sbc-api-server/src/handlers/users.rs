//! `/users` CRUD handlers — Postgres-backed via `uc-user-mgmt`'s
//! `PostgresUserStore`, wrapped in `EncryptedUserStore` so `digest_ha1`
//! is AES-256-GCM ciphertext at rest. sbc-api is the only reader and
//! writer of the `users` table; SIP digest auth in sbc-daemon does not
//! consume it today.
//!
//! Response shapes match what the daemon's REST surface used to emit so
//! the dashboard's existing fetch logic doesn't need to change:
//!   GET    /users        → {"users": [...], "total": N, "limit": L, "offset": O}
//!   POST   /users        → 201 {"success": true, "user": {...}}
//!   GET    /users/{id}   → {...user fields...}  or  {"error": "..."}
//!   PUT    /users/{id}   → {"success": true|false, "user"?: {...}, "error"?: "..."}
//!   DELETE /users/{id}   → {"success": true|false, "error"?: "..."}
//!
//! `total` is the row count of the whole table (not the page).
//!
//! Reads need `users:read`, writes `users:admin` (route layers in
//! `authmw`). Every create/update/delete emits an `AccountManagement`
//! audit event, success or failure. Error bodies are fixed strings;
//! backend error text is logged only.
//!
//! ## NIST 800-53 Rev5: AC-2, AC-2(4), AC-3, AC-6, AU-2, AU-3, SI-11, SC-5

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::rejection::JsonRejection;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use serde::Deserialize;
use tracing::error;
use uc_audit::event::{AccountAction, AccountManagement};
use uc_user_mgmt::digest::compute_ha1;
use uc_user_mgmt::error::UserMgmtError;
use uc_user_mgmt::model::{AuthType, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, User, UserFilter};
use uc_user_mgmt::store::UserStore;

use crate::authmw::{Principal, require_users_admin, require_users_read};

/// State for the users routes: the store plus what's needed to resolve the
/// client IP for audit records.
pub struct UsersState<U> {
    pub store: Arc<U>,
    pub trusted_proxies: Arc<Vec<ipnet::IpNet>>,
}

impl<U> Clone for UsersState<U> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            trusted_proxies: Arc::clone(&self.trusted_proxies),
        }
    }
}

/// `/users` routes with their permission layers, state applied.
///
/// ## NIST 800-53 Rev5: AC-3, AC-6
pub fn routes<U, S>(state: UsersState<U>) -> Router<S>
where
    U: UserStore + 'static,
    S: Clone + Send + Sync + 'static,
{
    let read = || axum::middleware::from_fn(require_users_read);
    let admin = || axum::middleware::from_fn(require_users_admin);
    Router::new()
        .route(
            "/users",
            get(list::<U>)
                .route_layer(read())
                .merge(axum::routing::post(create::<U>).route_layer(admin())),
        )
        .route(
            "/users/{id}",
            get(get_one::<U>).route_layer(read()).merge(
                axum::routing::put(update::<U>)
                    .delete(delete::<U>)
                    .route_layer(admin()),
            ),
        )
        .with_state(state)
}

fn now_epoch_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().cast_signed())
}

fn body_str<'a>(body: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    body.get(key).and_then(serde_json::Value::as_str)
}

/// Fixed audit/client token for an error; never contains backend text.
const fn reason(e: &UserMgmtError) -> &'static str {
    match e {
        UserMgmtError::UserNotFound => "not_found",
        UserMgmtError::UserAlreadyExists => "already_exists",
        UserMgmtError::InvalidCredentials | UserMgmtError::CertificateValidationFailed(_) => {
            "invalid"
        }
        UserMgmtError::StorageError(_) | UserMgmtError::LdapError(_) => "storage",
    }
}

/// Client-facing status + message for an error. Details go to the log.
///
/// ## NIST 800-53 Rev5: SI-11 (Error Handling)
fn client_error(op: &'static str, e: &UserMgmtError) -> (StatusCode, &'static str) {
    match e {
        UserMgmtError::UserNotFound => (StatusCode::NOT_FOUND, "user not found"),
        UserMgmtError::UserAlreadyExists => (StatusCode::CONFLICT, "user already exists"),
        UserMgmtError::InvalidCredentials | UserMgmtError::CertificateValidationFailed(_) => {
            (StatusCode::BAD_REQUEST, "invalid request")
        }
        UserMgmtError::StorageError(_) | UserMgmtError::LdapError(_) => {
            error!(op, error = %e, "user store error");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

/// Who made the request, for audit records.
struct Actor {
    user: String,
    issuer: Option<String>,
    ip: Option<IpAddr>,
}

impl Actor {
    fn new<U>(
        st: &UsersState<U>,
        p: Option<&Extension<Principal>>,
        headers: &HeaderMap,
        ci: Option<&Extension<ConnectInfo<SocketAddr>>>,
    ) -> Self {
        Self {
            user: p.map_or_else(|| "anonymous".to_string(), |Extension(p)| p.user.clone()),
            issuer: p.and_then(|Extension(p)| p.issuer.clone()),
            ip: source_ip(st, headers, ci),
        }
    }
}

fn source_ip<U>(
    st: &UsersState<U>,
    headers: &HeaderMap,
    ci: Option<&Extension<ConnectInfo<SocketAddr>>>,
) -> Option<IpAddr> {
    let Extension(ConnectInfo(peer)) = ci?;
    Some(sbc_http_util::resolve_client_ip(
        headers,
        peer.ip(),
        &st.trusted_proxies,
    ))
}

/// Emit one `AccountManagement` audit record.
///
/// ## NIST 800-53 Rev5: AC-2(4), AU-2, AU-3, AU-12
fn audit(
    actor: &Actor,
    action: AccountAction,
    user_id: &str,
    username: &str,
    result: Result<(), &UserMgmtError>,
    changed: &[&str],
) {
    uc_audit::log_event(uc_audit::AuditEvent::AccountManagement(AccountManagement {
        actor: actor.user.clone(),
        actor_issuer: actor.issuer.clone(),
        target_user_id: user_id.to_string(),
        target_username: username.to_string(),
        action,
        success: result.is_ok(),
        failure_reason: result.err().map(|e| reason(e).to_string()),
        source_ip: actor.ip,
        changed: changed.iter().map(|s| (*s).to_string()).collect(),
    }));
}

/// Audit and reject a body the JSON extractor refused (malformed JSON,
/// wrong content type, oversize). The rejection text is logged only.
///
/// ## NIST 800-53 Rev5: AC-2(4), SI-11
fn reject_body(
    actor: &Actor,
    action: AccountAction,
    user_id: &str,
    rej: &JsonRejection,
) -> Response {
    tracing::debug!(error = %rej.body_text(), "users request body rejected");
    audit(
        actor,
        action,
        user_id,
        "",
        Err(&UserMgmtError::InvalidCredentials),
        &[],
    );
    (
        rej.status(),
        Json(serde_json::json!({"success": false, "error": "invalid request body"})),
    )
        .into_response()
}

#[derive(Debug, Default, Deserialize)]
pub struct ListParams {
    limit: Option<u32>,
    offset: Option<u32>,
}

/// Paged list. Default 100, capped at 1000 (values above are clamped).
///
/// ## NIST 800-53 Rev5: SC-5
pub async fn list<U: UserStore>(
    State(st): State<UsersState<U>>,
    Query(p): Query<ListParams>,
) -> Response {
    let limit = p.limit.unwrap_or(DEFAULT_PAGE_SIZE).min(MAX_PAGE_SIZE);
    let offset = p.offset.unwrap_or(0);
    let filter = UserFilter {
        limit: Some(limit),
        offset: Some(offset),
        ..UserFilter::default()
    };
    let users = match st.store.list_users(&filter).await {
        Ok(u) => u,
        Err(e) => {
            let (code, msg) = client_error("list_users", &e);
            return (
                code,
                Json(serde_json::json!({"users": [], "total": 0, "error": msg})),
            )
                .into_response();
        }
    };
    let total = match st.store.count_users().await {
        Ok(n) => n,
        Err(e) => {
            let (code, msg) = client_error("count_users", &e);
            return (
                code,
                Json(serde_json::json!({"users": [], "total": 0, "error": msg})),
            )
                .into_response();
        }
    };
    Json(serde_json::json!({
        "users": users,
        "total": total,
        "limit": limit,
        "offset": offset,
    }))
    .into_response()
}

pub async fn create<U: UserStore>(
    State(st): State<UsersState<U>>,
    principal: Option<Extension<Principal>>,
    ci: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let who = Actor::new(&st, principal.as_ref(), &headers, ci.as_ref());
    let id = uuid::Uuid::new_v4().to_string();
    let body = match body {
        Ok(Json(b)) => b,
        Err(rej) => return reject_body(&who, AccountAction::Create, &id, &rej),
    };
    let username = body_str(&body, "username").unwrap_or("").to_string();
    if username.is_empty() {
        audit(
            &who,
            AccountAction::Create,
            &id,
            "",
            Err(&UserMgmtError::InvalidCredentials),
            &[],
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"success": false, "error": "username required"})),
        )
            .into_response();
    }
    let display_name = body_str(&body, "display_name").unwrap_or("").to_string();
    let email = body_str(&body, "email").unwrap_or("").to_string();
    let sip_uri = body_str(&body, "sip_uri").unwrap_or(&username).to_string();
    let digest_ha1 = body_str(&body, "password")
        .filter(|p| !p.is_empty())
        .map(|password| {
            let realm = body_str(&body, "sip_domain").unwrap_or("sbc-local");
            compute_ha1(&username, realm, password)
        });
    let certificate_dn = body_str(&body, "certificate_dn").map(String::from);
    let calling_search_space = body_str(&body, "calling_search_space").map(String::from);

    let user = User {
        id: id.clone(),
        username: username.clone(),
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

    match st.store.create_user(user).await {
        Ok(created) => {
            audit(&who, AccountAction::Create, &id, &username, Ok(()), &[]);
            (
                StatusCode::CREATED,
                Json(serde_json::json!({"success": true, "user": created})),
            )
                .into_response()
        }
        Err(e) => {
            audit(&who, AccountAction::Create, &id, &username, Err(&e), &[]);
            let (code, msg) = client_error("create_user", &e);
            (
                code,
                Json(serde_json::json!({"success": false, "error": msg})),
            )
                .into_response()
        }
    }
}

pub async fn get_one<U: UserStore>(
    State(st): State<UsersState<U>>,
    Path(id): Path<String>,
) -> Response {
    match st.store.get_user(&id).await {
        Ok(user) => Json(serde_json::json!(user)).into_response(),
        Err(e) => {
            let (code, msg) = client_error("get_user", &e);
            (code, Json(serde_json::json!({"error": msg}))).into_response()
        }
    }
}

pub async fn update<U: UserStore>(
    State(st): State<UsersState<U>>,
    principal: Option<Extension<Principal>>,
    ci: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let who = Actor::new(&st, principal.as_ref(), &headers, ci.as_ref());
    let body = match body {
        Ok(Json(b)) => b,
        Err(rej) => return reject_body(&who, AccountAction::Update, &id, &rej),
    };
    let fail = |username: &str, changed: &[&str], e: &UserMgmtError| {
        audit(&who, AccountAction::Update, &id, username, Err(e), changed);
        let (code, msg) = client_error("update_user", e);
        (
            code,
            Json(serde_json::json!({"success": false, "error": msg})),
        )
            .into_response()
    };
    let existing = match st.store.get_user(&id).await {
        Ok(u) => u,
        Err(e) => return fail("", &[], &e),
    };

    let username = body_str(&body, "username")
        .unwrap_or(&existing.username)
        .to_string();
    let new_ha1 = body_str(&body, "password")
        .filter(|p| !p.is_empty())
        .map(|password| {
            let realm = body_str(&body, "sip_domain").unwrap_or("sbc-local");
            compute_ha1(&username, realm, password)
        });
    let password_set = new_ha1.is_some();
    let existing_snapshot = Snapshot::of(&existing);
    let digest_ha1 = new_ha1.or(existing.digest_ha1);

    let updated = User {
        id: id.clone(),
        username: username.clone(),
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

    let changed = changed_groups(&existing_snapshot, &updated, password_set);
    match st.store.update_user(updated).await {
        Ok(u) => {
            audit(
                &who,
                AccountAction::Update,
                &id,
                &username,
                Ok(()),
                &changed,
            );
            Json(serde_json::json!({"success": true, "user": u})).into_response()
        }
        Err(e) => fail(&username, &changed, &e),
    }
}

/// Non-secret attributes compared to classify an update for audit.
struct Snapshot {
    username: String,
    enabled: bool,
    profile: (String, String, String, Option<String>, Option<String>),
}

impl Snapshot {
    fn of(u: &User) -> Self {
        Self {
            username: u.username.clone(),
            enabled: u.enabled,
            profile: (
                u.display_name.clone(),
                u.email.clone(),
                u.sip_uri.clone(),
                u.certificate_dn.clone(),
                u.calling_search_space.clone(),
            ),
        }
    }
}

/// Attribute groups an update changes (`password`, `enabled`, `username`,
/// `profile`). NIST 800-53 Rev5: AC-2, IA-5, AU-3
fn changed_groups(before: &Snapshot, after: &User, password_set: bool) -> Vec<&'static str> {
    let now = Snapshot::of(after);
    let mut out = Vec::new();
    if password_set {
        out.push("password");
    }
    if before.enabled != now.enabled {
        out.push("enabled");
    }
    if before.username != now.username {
        out.push("username");
    }
    if before.profile != now.profile {
        out.push("profile");
    }
    out
}

pub async fn delete<U: UserStore>(
    State(st): State<UsersState<U>>,
    principal: Option<Extension<Principal>>,
    ci: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let who = Actor::new(&st, principal.as_ref(), &headers, ci.as_ref());
    // Best-effort username for the audit record; the delete is by id.
    let username = st
        .store
        .get_user(&id)
        .await
        .map(|u| u.username)
        .unwrap_or_default();
    match st.store.delete_user(&id).await {
        Ok(()) => {
            audit(&who, AccountAction::Delete, &id, &username, Ok(()), &[]);
            Json(serde_json::json!({"success": true})).into_response()
        }
        Err(e) => {
            audit(&who, AccountAction::Delete, &id, &username, Err(&e), &[]);
            let (code, msg) = client_error("delete_user", &e);
            (
                code,
                Json(serde_json::json!({"success": false, "error": msg})),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;
    use uc_crypto::aead::Aes256GcmKey;
    use uc_user_mgmt::encrypt::EncryptedUserStore;
    use uc_user_mgmt::sqlite::SqliteUserStore;

    type Store = EncryptedUserStore<SqliteUserStore>;

    fn app() -> (Router, Arc<Store>) {
        let store = Arc::new(EncryptedUserStore::new(
            SqliteUserStore::in_memory().unwrap(),
            Aes256GcmKey::generate().unwrap(),
        ));
        let r = routes(UsersState {
            store: Arc::clone(&store),
            trusted_proxies: Arc::new(Vec::new()),
        });
        (r, store)
    }

    fn principal(roles: &[&str]) -> Principal {
        let c: proto_jwt::Claims = serde_json::from_value(serde_json::json!({
            "sub": "s-1", "preferred_username": "op1", "roles": roles, "scope": "config-admin",
        }))
        .unwrap();
        Principal::from_claims(&c)
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
        p: Option<Principal>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
            .unwrap();
        if let Some(p) = p {
            req.extensions_mut().insert(p);
        }
        let resp = app.clone().oneshot(req).await.unwrap();
        let code = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            code,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn account_events(c: &uc_audit::capture::CaptureGuard) -> Vec<AccountManagement> {
        c.events()
            .into_iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::AccountManagement(a) => Some(a),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn every_route_forbidden_without_role() {
        let (app, _) = app();
        let body = Some(serde_json::json!({"username": "x"}));
        for roles in [&[][..], &["cdr-exporter"][..]] {
            for (m, u, b) in [
                ("GET", "/users", None),
                ("GET", "/users/u1", None),
                ("POST", "/users", body.clone()),
                ("PUT", "/users/u1", body.clone()),
                ("DELETE", "/users/u1", None),
            ] {
                let (code, _) = call(&app, m, u, b, Some(principal(roles))).await;
                assert_eq!(code, StatusCode::FORBIDDEN, "{m} {u} {roles:?}");
            }
        }
        // users-reader may read but not write.
        let r = principal(&["users-reader"]);
        assert_eq!(
            call(&app, "GET", "/users", None, Some(r.clone())).await.0,
            StatusCode::OK
        );
        for (m, u) in [
            ("POST", "/users"),
            ("PUT", "/users/u1"),
            ("DELETE", "/users/u1"),
        ] {
            let (code, _) = call(&app, m, u, body.clone(), Some(r.clone())).await;
            assert_eq!(code, StatusCode::FORBIDDEN, "{m} {u}");
        }
    }

    #[tokio::test]
    async fn rejected_json_bodies_are_audited() {
        let capture = uc_audit::capture::start();
        let (app, _) = app();
        let p = principal(&["users-admin"]).with_issuer("https://idp.example.invalid");
        for (m, u) in [("POST", "/users"), ("PUT", "/users/u1")] {
            let mut req = axum::http::Request::builder()
                .method(m)
                .uri(u)
                .header("content-type", "application/json")
                .body(Body::from("{not json"))
                .unwrap();
            req.extensions_mut().insert(p.clone());
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{m}");
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
                .await
                .unwrap();
            let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(v["error"], "invalid request body");
        }
        let ev = account_events(&capture);
        let got: Vec<_> = ev
            .iter()
            .map(|e| (e.action, e.success, e.failure_reason.as_deref()))
            .collect();
        assert_eq!(
            got,
            [
                (AccountAction::Create, false, Some("invalid")),
                (AccountAction::Update, false, Some("invalid")),
            ]
        );
        assert_eq!(ev[1].target_user_id, "u1");
        assert_eq!(
            ev[0].actor_issuer.as_deref(),
            Some("https://idp.example.invalid")
        );
    }

    #[tokio::test]
    async fn update_audit_records_changed_groups() {
        let capture = uc_audit::capture::start();
        let (app, _) = app();
        let admin = Some(principal(&["users-admin"]));
        let (_, v) = call(
            &app,
            "POST",
            "/users",
            Some(serde_json::json!({"username": "bob", "password": "pw"})),
            admin.clone(),
        )
        .await;
        let id = v["user"]["id"].as_str().unwrap().to_string();
        for body in [
            serde_json::json!({"password": "pw2"}),
            serde_json::json!({"enabled": false}),
            serde_json::json!({"email": "b@example.invalid"}),
            serde_json::json!({}),
        ] {
            let (code, _) = call(
                &app,
                "PUT",
                &format!("/users/{id}"),
                Some(body),
                admin.clone(),
            )
            .await;
            assert_eq!(code, StatusCode::OK);
        }
        let changed: Vec<Vec<String>> = account_events(&capture)
            .into_iter()
            .filter(|e| e.action == AccountAction::Update)
            .map(|e| e.changed)
            .collect();
        assert_eq!(
            changed,
            [
                vec!["password".to_string()],
                vec!["enabled".to_string()],
                vec!["profile".to_string()],
                Vec::<String>::new(),
            ]
        );
    }

    #[tokio::test]
    async fn denial_is_audited() {
        let capture = uc_audit::capture::start();
        let (app, _) = app();
        let (code, _) = call(
            &app,
            "POST",
            "/users",
            Some(serde_json::json!({"username": "x"})),
            Some(principal(&["users-reader"])),
        )
        .await;
        assert_eq!(code, StatusCode::FORBIDDEN);
        let denied: Vec<_> = capture
            .events()
            .into_iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::AuthorizationDecision(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].action, crate::authmw::PERM_USERS_ADMIN);
        assert_eq!(denied[0].policy, "users-rbac");
        assert!(account_events(&capture).is_empty());
    }

    #[tokio::test]
    async fn admin_crud_is_audited_and_ha1_encrypted() {
        let capture = uc_audit::capture::start();
        let (app, store) = app();
        let admin = Some(principal(&["users-admin"]));
        let (code, v) = call(
            &app,
            "POST",
            "/users",
            Some(serde_json::json!({"username": "alice", "password": "pw"})),
            admin.clone(),
        )
        .await;
        assert_eq!(code, StatusCode::CREATED);
        let id = v["user"]["id"].as_str().unwrap().to_string();
        assert!(v["user"].get("digest_ha1").is_none(), "HA1 not serialized");
        let raw = store.inner().get_user(&id).await.unwrap();
        assert!(
            raw.digest_ha1
                .unwrap()
                .starts_with(uc_user_mgmt::encrypt::MARKER_V1)
        );

        // Duplicate: failure, generic body, audited.
        let (code, v) = call(
            &app,
            "POST",
            "/users",
            Some(serde_json::json!({"username": "alice"})),
            admin.clone(),
        )
        .await;
        assert_eq!(code, StatusCode::CONFLICT);
        assert_eq!(v["error"], "user already exists");

        let (code, _) = call(
            &app,
            "PUT",
            &format!("/users/{id}"),
            Some(serde_json::json!({"display_name": "A"})),
            admin.clone(),
        )
        .await;
        assert_eq!(code, StatusCode::OK);
        let (code, _) = call(
            &app,
            "PUT",
            "/users/missing",
            Some(serde_json::json!({})),
            admin.clone(),
        )
        .await;
        assert_eq!(code, StatusCode::NOT_FOUND);
        let (code, _) = call(&app, "DELETE", &format!("/users/{id}"), None, admin.clone()).await;
        assert_eq!(code, StatusCode::OK);
        let (code, _) = call(&app, "DELETE", &format!("/users/{id}"), None, admin).await;
        assert_eq!(code, StatusCode::NOT_FOUND);

        let ev = account_events(&capture);
        let summary: Vec<_> = ev.iter().map(|e| (e.action, e.success)).collect();
        assert_eq!(
            summary,
            vec![
                (AccountAction::Create, true),
                (AccountAction::Create, false),
                (AccountAction::Update, true),
                (AccountAction::Update, false),
                (AccountAction::Delete, true),
                (AccountAction::Delete, false),
            ]
        );
        assert!(ev.iter().all(|e| e.actor == "op1"));
        assert_eq!(ev[0].target_username, "alice");
        assert_eq!(ev[1].failure_reason.as_deref(), Some("already_exists"));
        let json = serde_json::to_string(&ev).unwrap();
        assert!(!json.contains("password") && !json.contains("digest_ha1"));
        assert!(!json.contains("enc:v1"));
    }

    #[tokio::test]
    async fn list_is_paged_and_capped() {
        let (app, store) = app();
        for i in 0..5 {
            let u = User {
                id: format!("u{i}"),
                username: format!("user{i}"),
                display_name: String::new(),
                email: String::new(),
                sip_uri: String::new(),
                auth_type: AuthType::Digest,
                digest_ha1: None,
                certificate_dn: None,
                certificate_san: None,
                calling_search_space: None,
                device_ids: Vec::new(),
                partition: None,
                enabled: true,
                created_at: 0,
                updated_at: 0,
                last_login: None,
                metadata: HashMap::new(),
            };
            store.create_user(u).await.unwrap();
        }
        let r = Some(principal(&["users-reader"]));
        let (_, v) = call(&app, "GET", "/users?limit=2&offset=1", None, r.clone()).await;
        assert_eq!(v["users"].as_array().unwrap().len(), 2);
        assert_eq!(v["users"][0]["username"], "user1");
        assert_eq!(v["total"], 5);
        let (_, v) = call(&app, "GET", "/users", None, r.clone()).await;
        assert_eq!(v["limit"], DEFAULT_PAGE_SIZE);
        let (_, v) = call(&app, "GET", "/users?limit=999999", None, r.clone()).await;
        assert_eq!(v["limit"], MAX_PAGE_SIZE);
        let (code, _) = call(&app, "GET", "/users?limit=-1", None, r).await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn storage_errors_are_generic() {
        let (code, msg) = client_error(
            "op",
            &UserMgmtError::StorageError("relation \"users\" does not exist".into()),
        );
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(msg, "internal error");
    }

    // QA: auditor holds users:read only; every write route must 403, and a
    // missing Principal must never reach a handler.
    #[tokio::test]
    async fn auditor_reads_but_cannot_write_and_no_principal_is_rejected() {
        let (app, _) = app();
        let a = principal(&["auditor"]);
        assert_eq!(
            call(&app, "GET", "/users", None, Some(a.clone())).await.0,
            StatusCode::OK
        );
        let body = Some(serde_json::json!({"username": "x"}));
        for (m, u) in [
            ("POST", "/users"),
            ("PUT", "/users/u1"),
            ("DELETE", "/users/u1"),
        ] {
            let (code, _) = call(&app, m, u, body.clone(), Some(a.clone())).await;
            assert_eq!(code, StatusCode::FORBIDDEN, "auditor {m} {u}");
        }
        for (m, u) in [
            ("GET", "/users"),
            ("GET", "/users/u1"),
            ("POST", "/users"),
            ("PUT", "/users/u1"),
            ("DELETE", "/users/u1"),
        ] {
            let (code, _) = call(&app, m, u, body.clone(), None).await;
            assert!(code.is_client_error(), "no principal {m} {u}: {code}");
        }
    }

    // QA: failure audit carries target id and a fixed reason token.
    #[tokio::test]
    async fn failed_delete_audit_fields() {
        let capture = uc_audit::capture::start();
        let (app, _) = app();
        let (code, v) = call(
            &app,
            "DELETE",
            "/users/nope",
            None,
            Some(principal(&["fleet-admin"])),
        )
        .await;
        assert_eq!(code, StatusCode::NOT_FOUND);
        assert!(
            !v.to_string().contains("nope"),
            "body echoes no backend text: {v}"
        );
        let ev = account_events(&capture);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].action, AccountAction::Delete);
        assert!(!ev[0].success);
        assert_eq!(ev[0].target_user_id, "nope");
        assert!(ev[0].failure_reason.is_some());
    }
}
