//! SR-40: every non-GET route emits exactly one `ConfigurationChange` with
//! the actor, entity, id, op and outcome. Handlers record their own and mark
//! the response `WriteAudited`; the router backstop records anything
//! unmarked (`entity=route`). `/auth/*` is audited separately.
//!
//! The stub-router tests need no database. The route-table tests build the
//! real `AppState` and are skipped unless `SBC_CONFIG_STORE_TEST_DSN` is
//! set; the daemon gRPC endpoint is unreachable on purpose.
//!
//! ## NIST 800-53 Rev5: AU-2, AU-3, AU-12, CM-3, CM-5

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use tower::ServiceExt;
use uc_audit::AuditEvent;
use uc_audit::event::ConfigurationChange;
use uc_auth::CredentialId;

use super::{WriteAudited, write_audit_backstop};
use crate::authmw::Principal;

/// SR-40 grammar records only (not the trunk-group transport-diff ones).
fn changes(events: &[AuditEvent]) -> Vec<ConfigurationChange> {
    events
        .iter()
        .filter_map(|e| match e {
            AuditEvent::ConfigurationChange(c) if c.description.starts_with("entity=") => {
                Some(c.clone())
            }
            _ => None,
        })
        .collect()
}

fn kv<'a>(desc: &'a str, key: &str) -> Vec<&'a str> {
    desc.split(' ')
        .filter_map(|t| t.split_once('='))
        .filter(|(k, _)| *k == key)
        .map(|(_, v)| v)
        .collect()
}

// ---- stub router: the backstop alone ------------------------------------

const STUB_IP: &str = "192.0.2.60";

async fn as_admin(mut req: Request, next: Next) -> Response {
    req.extensions_mut().insert(Principal::legacy(
        CredentialId::Session {
            subject: "admin".to_string(),
        },
        Some(STUB_IP.parse().unwrap()),
    ));
    next.run(req).await
}

async fn marked() -> Response {
    let mut r = StatusCode::OK.into_response();
    r.extensions_mut().insert(WriteAudited);
    r
}

fn stub() -> Router {
    Router::new()
        .route(
            "/api/v1/things/{id}",
            post(|| async { StatusCode::CREATED })
                .get(|| async { "ok" })
                .delete(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        )
        .route("/api/v1/marked", post(marked).put(marked))
        .route(
            "/api/v1/auth/login",
            post(|| async { StatusCode::UNAUTHORIZED }),
        )
        .route("/api/v1/auth/logout", post(|| async { "ok" }))
        .layer(axum::middleware::from_fn(write_audit_backstop))
        .layer(axum::middleware::from_fn(as_admin))
}

async fn stub_call(method: &str, uri: &str) -> StatusCode {
    let req = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    stub().oneshot(req).await.unwrap().status()
}

#[tokio::test]
async fn backstop_audits_unmarked_write() {
    let cap = uc_audit::capture::start();
    assert_eq!(
        stub_call("POST", "/api/v1/things/abc").await,
        StatusCode::CREATED
    );
    let c = changes(&cap.events());
    assert_eq!(c.len(), 1, "{c:?}");
    let d = c[0].description.as_str();
    assert_eq!(c[0].admin, "admin:admin");
    assert_eq!(kv(d, "entity"), ["route"]);
    assert_eq!(
        kv(d, "id"),
        ["/api/v1/things/{id}"],
        "matched route, not the raw path"
    );
    assert_eq!(kv(d, "op"), ["POST"]);
    assert_eq!(kv(d, "outcome").len(), 1);
    assert!(d.contains("201"), "status recorded: {d}");
    assert_eq!(kv(d, "src"), [STUB_IP]);

    // A failing unmarked write is recorded too.
    let cap = uc_audit::capture::start();
    assert_eq!(
        stub_call("DELETE", "/api/v1/things/abc").await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    let c = changes(&cap.events());
    assert_eq!(c.len(), 1, "{c:?}");
    assert_eq!(kv(&c[0].description, "op"), ["DELETE"]);
    assert!(c[0].description.contains("500"), "{}", c[0].description);
}

#[tokio::test]
async fn backstop_skips_marked_write() {
    let cap = uc_audit::capture::start();
    assert_eq!(stub_call("POST", "/api/v1/marked").await, StatusCode::OK);
    assert_eq!(stub_call("PUT", "/api/v1/marked").await, StatusCode::OK);
    assert!(changes(&cap.events()).is_empty(), "{:?}", cap.events());
}

#[tokio::test]
async fn get_is_not_audited() {
    let cap = uc_audit::capture::start();
    assert_eq!(stub_call("GET", "/api/v1/things/abc").await, StatusCode::OK);
    assert!(cap.events().is_empty(), "{:?}", cap.events());
}

#[tokio::test]
async fn auth_routes_excluded_from_backstop() {
    // Login is audited by the login path; logout (round 1, SEC-007) is a
    // write like any other and gets one backstop record.
    let cap = uc_audit::capture::start();
    assert_eq!(
        stub_call("POST", "/api/v1/auth/login").await,
        StatusCode::UNAUTHORIZED
    );
    assert!(changes(&cap.events()).is_empty(), "{:?}", cap.events());
    assert_eq!(
        stub_call("POST", "/api/v1/auth/logout").await,
        StatusCode::OK
    );
    let c = changes(&cap.events());
    assert_eq!(c.len(), 1, "{c:?}");
    assert_eq!(kv(&c[0].description, "id"), ["/api/v1/auth/logout"]);
    assert_eq!(c[0].admin, "admin:admin");
}

/// SR-40 round 1 (SEC-004): a handler that panics still yields a 500 that
/// the backstop records.
#[tokio::test]
async fn panicking_write_is_audited_by_backstop() {
    async fn boom() -> StatusCode {
        panic!("handler bug");
    }
    let app = Router::new()
        .route("/api/v1/boom", post(boom))
        .layer(tower_http::catch_panic::CatchPanicLayer::new())
        .layer(axum::middleware::from_fn(write_audit_backstop))
        .layer(axum::middleware::from_fn(as_admin));
    let cap = uc_audit::capture::start();
    let req = axum::http::Request::post("/api/v1/boom")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let c = changes(&cap.events());
    assert_eq!(c.len(), 1, "{c:?}");
    assert_eq!(kv(&c[0].description, "outcome"), ["failed"]);
}

// ---- real router over Postgres ------------------------------------------

const PW: &str = "sr40-write-audit-password";
const PEER: &str = "192.0.2.50:41000";

struct Pg {
    app: Router,
    state: Arc<crate::state::AppState>,
    token: String,
}

/// The real router with a lazily-connected (unreachable) daemon channel.
async fn pg() -> Option<Pg> {
    let dsn = std::env::var("SBC_CONFIG_STORE_TEST_DSN").ok()?;
    static ENV: std::sync::Once = std::sync::Once::new();
    ENV.call_once(|| {
        // Test-only process environment for `Authenticator::from_env`.
        #[allow(unsafe_code)]
        // SAFETY: set once, before any reader in this module; the values are
        // only read by `AppState::build` below.
        unsafe {
            std::env::set_var("SBC_ADMIN_PASSWORD", PW);
            std::env::remove_var("SBC_ADMIN_PASSWORD_HASH");
            std::env::remove_var("SBC_ADMIN_USER");
            std::env::set_var("SBC_AUTH_SIGNING_KEY", "5a".repeat(48));
        }
    });
    let key = tempfile::Builder::new().tempfile().unwrap();
    tokio::fs::write(key.path(), "ab".repeat(32)).await.unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        tokio::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
    }
    let key = key.into_temp_path().keep().unwrap();
    let cfg = crate::config::Config {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        database_url: dsn,
        daemon_grpc_url: "http://127.0.0.1:9".to_string(),
        daemon_http_url: "http://127.0.0.1:9".to_string(),
        oidc_issuer: None,
        oidc_audience: None,
        trusted_proxies: Vec::new(),
        daemon_grpc_tls: None,
        user_ha1_key_file: key,
        audit_path: None,
    };
    let state = crate::state::AppState::build(&cfg).await.expect("state");
    let token = state.auth.login("admin", PW).expect("login");
    Some(Pg {
        app: super::router(Arc::clone(&state)),
        state,
        token,
    })
}

async fn send(
    pg: &Pg,
    method: &str,
    uri: &str,
    body: Option<&serde_json::Value>,
    peer: &str,
) -> (StatusCode, serde_json::Value) {
    let mut req = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", pg.token));
    let body = match body {
        Some(v) => {
            req = req.header("content-type", "application/json");
            Body::from(serde_json::to_vec(v).unwrap())
        }
        None => Body::empty(),
    };
    let mut req = req.body(body).unwrap();
    let peer: SocketAddr = peer.parse().unwrap();
    req.extensions_mut().insert(ConnectInfo(peer));
    let resp = pg.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

struct W {
    method: &'static str,
    uri: String,
    body: Option<serde_json::Value>,
    entity: &'static str,
    op: &'static str,
    id: Option<String>,
}

fn nonce() -> String {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}{:x}", std::process::id(), t & 0xff_ffff)
}

#[allow(clippy::too_many_lines)]
fn write_routes(n: &str) -> Vec<W> {
    use serde_json::json;
    let w = |method, uri: String, body, entity, op, id: Option<String>| W {
        method,
        uri,
        body,
        entity,
        op,
        id,
    };
    let s = |v: &str| Some(v.to_string());
    let (ph, did, dp, tg, tr) = (
        format!("ph-{n}"),
        format!("d-{n}"),
        format!("dp-{n}"),
        format!("tg-{n}"),
        format!("tr-{n}"),
    );
    let mut v = vec![
        w(
            "POST",
            "/api/v1/phones".into(),
            Some(
                json!({"id": ph, "mac_address": "02:40:00:00:00:01", "model": "PolycomVVX450", "name": "qa"}),
            ),
            "phone",
            "create",
            s(&ph),
        ),
        w(
            "PUT",
            format!("/api/v1/phones/{ph}"),
            Some(
                json!({"id": ph, "mac_address": "02:40:00:00:00:01", "model": "PolycomVVX450", "name": "qa2"}),
            ),
            "phone",
            "update",
            s(&ph),
        ),
        w(
            "POST",
            format!("/api/v1/phones/{ph}/reboot"),
            Some(json!({})),
            "phone",
            "reboot",
            s(&ph),
        ),
        w(
            "DELETE",
            format!("/api/v1/phones/{ph}"),
            None,
            "phone",
            "delete",
            s(&ph),
        ),
        w(
            "POST",
            "/api/v1/directory".into(),
            Some(json!({"did": did})),
            "directory_number",
            "create",
            s(&did),
        ),
        w(
            "PUT",
            format!("/api/v1/directory/{did}"),
            Some(json!({"description": "qa"})),
            "directory_number",
            "update",
            s(&did),
        ),
        w(
            "DELETE",
            format!("/api/v1/directory/{did}"),
            None,
            "directory_number",
            "delete",
            s(&did),
        ),
        w(
            "POST",
            format!("/api/v1/dialplans/{dp}/entries"),
            Some(json!({"id": format!("e-{n}"), "pattern": "9"})),
            "dial_plan_entry",
            "create",
            None,
        ),
        w(
            "DELETE",
            format!("/api/v1/dialplans/{dp}/entries/e-{n}"),
            None,
            "dial_plan_entry",
            "delete",
            None,
        ),
    ];
    for (path, entity) in [
        ("partitions", "partition"),
        ("css", "css"),
        ("routepatterns", "route_pattern"),
        ("routelists", "route_list"),
    ] {
        let id = format!("{entity}-{n}");
        v.push(w(
            "POST",
            format!("/api/v1/{path}"),
            Some(json!({"id": id, "pattern": "9", "description": "qa"})),
            entity,
            "create",
            s(&id),
        ));
        v.push(w(
            "PUT",
            format!("/api/v1/{path}/{id}"),
            Some(json!({"id": id, "pattern": "9", "description": "qa2"})),
            entity,
            "update",
            s(&id),
        ));
        v.push(w(
            "DELETE",
            format!("/api/v1/{path}/{id}"),
            None,
            entity,
            "delete",
            s(&id),
        ));
    }
    // Round 1 (NIST-005): trunk records name `<group>/<trunk>`.
    let trunk = json!({"id": tr, "host": "a.carrier.example", "protocol": "tls"});
    v.extend([
        w(
            "POST",
            "/api/v1/trunkgroups".into(),
            Some(json!({"id": tg, "strategy": "priority", "trunks": []})),
            "trunk_group",
            "create",
            s(&tg),
        ),
        w(
            "PUT",
            format!("/api/v1/trunkgroups/{tg}"),
            Some(json!({"id": tg, "strategy": "round_robin", "trunks": []})),
            "trunk_group",
            "update",
            s(&tg),
        ),
        w(
            "POST",
            format!("/api/v1/trunkgroups/{tg}/trunks"),
            Some(trunk.clone()),
            "trunk",
            "create",
            Some(format!("{tg}/{tr}")),
        ),
        w(
            "PUT",
            format!("/api/v1/trunkgroups/{tg}/trunks/{tr}"),
            Some(trunk),
            "trunk",
            "update",
            Some(format!("{tg}/{tr}")),
        ),
        w(
            "DELETE",
            format!("/api/v1/trunkgroups/{tg}/trunks/{tr}"),
            None,
            "trunk",
            "delete",
            Some(format!("{tg}/{tr}")),
        ),
        w(
            "DELETE",
            format!("/api/v1/trunkgroups/{tg}"),
            None,
            "trunk_group",
            "delete",
            s(&tg),
        ),
        w(
            "DELETE",
            "/api/v1/registrations/sip%3Aqa%40example.invalid".into(),
            None,
            "registration",
            "delete",
            None,
        ),
        w(
            "POST",
            format!("/api/v1/calls/c-{n}/terminate"),
            None,
            "call",
            "terminate",
            Some(format!("c-{n}")),
        ),
        w(
            "POST",
            "/api/v1/system/tls/reload".into(),
            None,
            "tls",
            "tls_reload",
            None,
        ),
        w(
            "POST",
            format!("/api/v1/trunk-registration/{tr}/register"),
            None,
            "trunk_registration",
            "register",
            s(&tr),
        ),
    ]);
    v
}

/// The handler's own success verdict: 2xx and no `"success": false`.
fn succeeded(status: StatusCode, body: &serde_json::Value) -> bool {
    status.is_success() && body.get("success") != Some(&serde_json::Value::Bool(false))
}

#[tokio::test]
async fn every_write_route_emits_one_config_change_with_actor() {
    let Some(pg) = pg().await else { return };
    let n = nonce();
    let routes = write_routes(&n);
    assert_eq!(
        routes.len(),
        31,
        "every owned non-GET route except /auth and /users"
    );
    let peer_ip: IpAddr = PEER.parse::<SocketAddr>().unwrap().ip();

    for r in routes {
        let cap = uc_audit::capture::start();
        let (status, body) = send(&pg, r.method, &r.uri, r.body.as_ref(), PEER).await;
        let c = changes(&cap.events());
        let what = format!("{} {} -> {status} {body}: {c:?}", r.method, r.uri);
        assert_eq!(c.len(), 1, "exactly one record: {what}");
        let d = c[0].description.as_str();
        assert_eq!(c[0].admin, "admin:admin", "{what}");
        assert_eq!(kv(d, "entity"), [r.entity], "{what}");
        assert_eq!(kv(d, "op"), [r.op], "{what}");
        match &r.id {
            Some(id) => assert_eq!(kv(d, "id"), [id.as_str()], "{what}"),
            None => assert_eq!(kv(d, "id").len(), 1, "{what}"),
        }
        let want = if succeeded(status, &body) {
            "ok"
        } else {
            "failed"
        };
        assert_eq!(kv(d, "outcome"), [want], "{what}");
        assert_eq!(kv(d, "src"), [peer_ip.to_string().as_str()], "{what}");
    }

    // Decision Q2: no in-repo client writes through the daemon proxy, so
    // the catch-all refuses non-GET instead of forwarding it.
    for method in ["POST", "PUT", "DELETE"] {
        let (status, _) = send(
            &pg,
            method,
            "/api/v1/qa-unowned/x",
            Some(&serde_json::json!({})),
            PEER,
        )
        .await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} via proxy");
    }
}

#[tokio::test]
async fn daemon_unreachable_write_is_audited_failed() {
    let Some(pg) = pg().await else { return };
    for uri in [
        "/api/v1/calls/c-gone/terminate",
        "/api/v1/system/tls/reload",
    ] {
        let cap = uc_audit::capture::start();
        let (status, body) = send(&pg, "POST", uri, None, PEER).await;
        assert!(!succeeded(status, &body), "{uri}: daemon is unreachable");
        let c = changes(&cap.events());
        assert_eq!(c.len(), 1, "{uri}: {c:?}");
        assert_eq!(kv(&c[0].description, "outcome"), ["failed"]);
        assert_eq!(kv(&c[0].description, "reason"), ["daemon_unavailable"]);
    }
}

#[tokio::test]
async fn store_updated_by_holds_principal() {
    let Some(pg) = pg().await else { return };
    let id = format!("ph-ub-{}", nonce());
    let (status, body) = send(
        &pg,
        "POST",
        "/api/v1/phones",
        Some(&serde_json::json!({
            "id": id, "mac_address": "02:40:00:00:00:02", "model": "PolycomVVX450", "name": "qa"
        })),
        PEER,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let by: String = sqlx::query_scalar("SELECT updated_by FROM phones WHERE id = $1")
        .bind(&id)
        .fetch_one(pg.state.phones.pool())
        .await
        .unwrap();
    assert_eq!(by, "local:admin:admin");

    let (status, _) = send(&pg, "DELETE", &format!("/api/v1/phones/{id}"), None, PEER).await;
    assert!(status.is_success());
    let by: String = sqlx::query_scalar("SELECT updated_by FROM phones WHERE id = $1")
        .bind(&id)
        .fetch_one(pg.state.phones.pool())
        .await
        .unwrap();
    assert_eq!(by, "local:admin:admin", "tombstone carries the principal");
}

#[tokio::test]
async fn trunk_group_update_keeps_transport_diff_record() {
    let Some(pg) = pg().await else { return };
    let tg = format!("tg-diff-{}", nonce());
    let trunks = serde_json::json!([{"id": "t1", "host": "a.carrier.example", "protocol": "tls"}]);
    let (status, body) = send(
        &pg,
        "POST",
        "/api/v1/trunkgroups",
        Some(&serde_json::json!({"id": tg, "require_tls": true, "trunks": trunks})),
        PEER,
    )
    .await;
    assert!(succeeded(status, &body), "{body}");

    let cap = uc_audit::capture::start();
    let (status, body) = send(
        &pg,
        "PUT",
        &format!("/api/v1/trunkgroups/{tg}"),
        Some(&serde_json::json!({"id": tg, "require_tls": false, "trunks": trunks})),
        PEER,
    )
    .await;
    assert!(succeeded(status, &body), "{body}");
    let c = changes(&cap.events());
    assert_eq!(c.len(), 1, "{c:?}");
    assert_eq!(kv(&c[0].description, "op"), ["update"]);
    let diff: Vec<_> = cap
        .events()
        .into_iter()
        .filter_map(|e| match e {
            AuditEvent::ConfigurationChange(c) if c.description.starts_with("trunk_group=") => {
                Some(c)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        diff.len(),
        1,
        "transport-policy diff record kept: {:?}",
        cap.events()
    );
    assert_eq!(
        diff[0].admin, "admin:admin",
        "diff record uses the actor id too"
    );
}

#[tokio::test]
async fn session_check_failure_is_audited() {
    let Some(pg) = pg().await else { return };
    let cap = uc_audit::capture::start();
    let from: IpAddr = "2001:db8:a:1::1".parse().unwrap();
    let mut req = axum::http::Request::get("/api/v1/auth/session")
        .header("authorization", "Bearer v2.forged.session")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(from, 40000)));
    let resp = pg.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let a: Vec<_> = cap
        .events()
        .into_iter()
        .filter_map(|e| match e {
            AuditEvent::AuthenticationAttempt(a) if a.source_ip == from => Some(a),
            _ => None,
        })
        .collect();
    assert_eq!(a.len(), 1, "{a:?}");
    assert!(!a[0].success);
    assert!(
        a[0].failure_reason
            .as_deref()
            .unwrap_or_default()
            .starts_with("invalid_token"),
        "{a:?}"
    );

    // No credential at all: not audited.
    let cap = uc_audit::capture::start();
    let from2: IpAddr = "2001:db8:a:1::2".parse().unwrap();
    let mut req = axum::http::Request::get("/api/v1/auth/session")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(from2, 40000)));
    let resp = pg.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(cap.events().is_empty(), "{:?}", cap.events());
}

/// SR-40 round 1: an absent delete keeps its idempotent 200 and is recorded
/// `not_found` (NIST-006); a non-object body is an audited 400, not a
/// handler panic (SEC-004).
#[tokio::test]
async fn absent_delete_and_non_object_body_are_audited_failed() {
    let Some(pg) = pg().await else { return };
    for uri in [
        "/api/v1/partitions/ghost-part",
        "/api/v1/trunkgroups/ghost-tg",
        "/api/v1/trunkgroups/ghost-tg/trunks/t9",
    ] {
        let cap = uc_audit::capture::start();
        let (status, _) = send(&pg, "DELETE", uri, None, PEER).await;
        assert_eq!(status, StatusCode::OK, "{uri}");
        let c = changes(&cap.events());
        assert_eq!(c.len(), 1, "{uri}: {c:?}");
        assert_eq!(kv(&c[0].description, "outcome"), ["failed"], "{uri}");
        assert_eq!(kv(&c[0].description, "reason"), ["not_found"], "{uri}");
    }
    for (method, uri) in [
        ("POST", "/api/v1/trunkgroups"),
        ("PUT", "/api/v1/trunkgroups/tg-x"),
        ("POST", "/api/v1/directory"),
        ("POST", "/api/v1/dialplans/dp-x/entries"),
    ] {
        let cap = uc_audit::capture::start();
        let (status, _) = send(&pg, method, uri, Some(&serde_json::json!([1, 2])), PEER).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {uri}");
        let c = changes(&cap.events());
        assert_eq!(c.len(), 1, "{method} {uri}: {c:?}");
        assert_eq!(kv(&c[0].description, "reason"), ["invalid"]);
    }
}
