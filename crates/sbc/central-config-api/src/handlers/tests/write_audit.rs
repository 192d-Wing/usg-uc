//! SR-40: every operator write and every uploaded sync change emits one
//! `ConfigurationChange` naming the actor (`oidc:<sub>@<iss>`, or
//! `site:<sub>` for uploads), entity, id, op and outcome. DSN-gated like
//! the parent module; `oneshot` on the current-thread runtime so the
//! thread-local audit capture sees every record.
//!
//! ## NIST 800-53 Rev5: AU-2, AU-3, AU-12, CM-3, CM-5

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use uc_audit::AuditEvent;
use uc_audit::event::ConfigurationChange;

use super::*;

const PEER: &str = "192.0.2.40:51000";

/// `send_req` with a TCP peer (`ConnectInfo`) attached.
async fn send_from(
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
            Body::from(serde_json::to_vec(&v).expect("encode"))
        }
        None => Body::empty(),
    };
    let mut req = req.body(body).expect("req");
    let peer: SocketAddr = PEER.parse().expect("peer");
    req.extensions_mut().insert(ConnectInfo(peer));
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

/// SR-40 config-change records (the `entity=` grammar), excluding the
/// trunk-group transport-diff records.
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

fn oidc_actor() -> String {
    // `mint_full` signs every token as sub `svc-sync`.
    format!("oidc:svc-sync@{TEST_ISSUER}")
}

struct Write {
    method: &'static str,
    uri: &'static str,
    body: Option<Value>,
    entity: &'static str,
    /// Accepted `op=` tokens (an upsert may be logged as create or update).
    ops: &'static [&'static str],
    id: Option<&'static str>,
    site: Option<&'static str>,
}

const UPSERT: &[&str] = &["create", "update"];

#[allow(clippy::too_many_lines)]
fn operator_writes() -> Vec<Write> {
    let w = |method, uri, body, entity, ops, id, site| Write {
        method,
        uri,
        body,
        entity,
        ops,
        id,
        site,
    };
    let muhj = Some("MUHJ");
    vec![
        w(
            "POST",
            "/v1/sites",
            Some(json!({"site_code": "MSRF", "fqdn_base": "msrf.x"})),
            "site",
            &["create"],
            Some("MSRF"),
            None,
        ),
        w(
            "POST",
            "/v1/sites/MUHJ/phones",
            Some(json!({"id": "p40", "mac_address": "40:40:40:40:40:40"})),
            "phone",
            UPSERT,
            Some("p40"),
            muhj,
        ),
        w(
            "DELETE",
            "/v1/sites/MUHJ/phones/p40",
            None,
            "phone",
            &["delete"],
            Some("p40"),
            muhj,
        ),
        w(
            "POST",
            "/v1/sites/MUHJ/directory",
            Some(json!({"did": "4040"})),
            "directory_number",
            UPSERT,
            Some("4040"),
            muhj,
        ),
        w(
            "DELETE",
            "/v1/sites/MUHJ/directory/4040",
            None,
            "directory_number",
            &["delete"],
            Some("4040"),
            muhj,
        ),
        w(
            "POST",
            "/v1/sites/MUHJ/trunkgroups",
            Some(json!({"id": "tg40", "strategy": "priority", "trunks": []})),
            "trunk_group",
            UPSERT,
            Some("tg40"),
            muhj,
        ),
        w(
            "DELETE",
            "/v1/sites/MUHJ/trunkgroups/tg40",
            None,
            "trunk_group",
            &["delete"],
            Some("tg40"),
            muhj,
        ),
        w(
            "POST",
            "/v1/sites/MUHJ/dialplans",
            Some(json!({"id": "dp40", "entries": []})),
            "dial_plan",
            UPSERT,
            Some("dp40"),
            muhj,
        ),
        w(
            "DELETE",
            "/v1/sites/MUHJ/dialplans/dp40",
            None,
            "dial_plan",
            &["delete"],
            Some("dp40"),
            muhj,
        ),
        w(
            "POST",
            "/v1/sites/MUHJ/routing/partitions",
            Some(json!({"id": "part40"})),
            "routing",
            UPSERT,
            Some("part40"),
            muhj,
        ),
        w(
            "DELETE",
            "/v1/sites/MUHJ/routing/partitions/part40",
            None,
            "routing",
            &["delete"],
            Some("part40"),
            muhj,
        ),
        w(
            "PUT",
            "/v1/sites/MUHJ/config",
            Some(json!({"timezone": "UTC"})),
            "site_config",
            UPSERT,
            None,
            muhj,
        ),
        w(
            "PUT",
            "/v1/templates/dial_plan/t40",
            Some(json!({"id": "t40", "entries": []})),
            "template",
            UPSERT,
            Some("t40"),
            None,
        ),
        w(
            "PUT",
            "/v1/templates/dial_plan/t40/sites/MUHJ",
            Some(json!({"ring": 0})),
            "template_assignment",
            &["assign"],
            None,
            muhj,
        ),
        w(
            "POST",
            "/v1/templates/dial_plan/t40/materialize?ring=0",
            None,
            "template",
            &["materialize"],
            Some("t40"),
            None,
        ),
        w(
            "DELETE",
            "/v1/templates/dial_plan/t40",
            None,
            "template",
            &["delete"],
            Some("t40"),
            None,
        ),
    ]
}

#[tokio::test]
async fn every_operator_write_emits_config_change_with_sub_and_iss() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = app(&admin, "cca_sr40_writes").await;
    let tok = admin_token();
    let writes = operator_writes();
    assert_eq!(writes.len(), 16, "every operator write route");
    let peer_ip: IpAddr = PEER.parse::<SocketAddr>().expect("peer").ip();

    for w in writes {
        let cap = uc_audit::capture::start();
        let (status, body) = send_from(&app, w.method, w.uri, Some(&tok), w.body.clone()).await;
        let c = changes(&cap.events());
        let what = format!("{} {} -> {status} {body}: {c:?}", w.method, w.uri);
        assert_eq!(c.len(), 1, "exactly one record: {what}");
        let r = &c[0];
        let d = r.description.as_str();
        assert_eq!(r.admin, oidc_actor(), "{what}");
        assert_eq!(kv(d, "entity"), [w.entity], "{what}");
        let op = kv(d, "op");
        assert!(op.len() == 1 && w.ops.contains(&op[0]), "{what}");
        if let Some(id) = w.id {
            assert_eq!(kv(d, "id"), [id], "{what}");
        } else {
            assert_eq!(kv(d, "id").len(), 1, "{what}");
        }
        if let Some(site) = w.site {
            assert_eq!(kv(d, "site"), [site], "{what}");
        }
        assert_eq!(kv(d, "iss"), [TEST_ISSUER], "{what}");
        assert_eq!(kv(d, "src"), [peer_ip.to_string().as_str()], "{what}");
        let want = if status.is_success() { "ok" } else { "failed" };
        assert_eq!(kv(d, "outcome"), [want], "{what}");
        if w.entity == "routing" {
            assert!(d.contains("partitions"), "routing kind recorded: {what}");
        }
    }
}

#[tokio::test]
async fn rejected_write_is_audited_failed() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = app(&admin, "cca_sr40_rejected").await;
    let tok = admin_token();

    for (uri, body, reason) in [
        // Missing id: rejected by validation.
        (
            "/v1/sites/MUHJ/phones",
            json!({"mac_address": "41:41:41:41:41:41"}),
            "invalid",
        ),
        // Typed validation failure.
        (
            "/v1/sites/MUHJ/trunkgroups",
            json!({"name": "no id"}),
            "invalid",
        ),
        // Unregistered site.
        (
            "/v1/sites/GHST/dialplans",
            json!({"id": "main", "entries": []}),
            "not_found",
        ),
    ] {
        let cap = uc_audit::capture::start();
        let (status, _) = send_from(&app, "POST", uri, Some(&tok), Some(body)).await;
        assert!(status.is_client_error(), "{uri}: {status}");
        let c = changes(&cap.events());
        assert_eq!(c.len(), 1, "{uri}: {c:?}");
        let d = c[0].description.as_str();
        assert_eq!(c[0].admin, oidc_actor());
        assert_eq!(kv(d, "outcome"), ["failed"], "{uri}: {d}");
        assert_eq!(kv(d, "reason"), [reason], "{uri}: {d}");
    }

    // Deleting a missing row is a failed delete, not silence.
    let cap = uc_audit::capture::start();
    let (status, _) = send_from(
        &app,
        "DELETE",
        "/v1/sites/MUHJ/phones/ghost",
        Some(&tok),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let c = changes(&cap.events());
    assert_eq!(c.len(), 1, "{c:?}");
    assert_eq!(kv(&c[0].description, "op"), ["delete"]);
    assert_eq!(kv(&c[0].description, "reason"), ["not_found"]);
}

#[tokio::test]
async fn sync_upload_audits_each_change_as_site_actor() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = app(&admin, "cca_sr40_upload").await; // seeds MUHJ + phone p1
    let upload = json!({ "changes": [
        { "table": "phones", "id": "p-edge", "op": "upsert",
          "payload": { "id": "p-edge", "mac_address": "ab:cd:ef:00:11:40" } },
        { "table": "phones", "id": "p1", "op": "delete" },
    ]});
    let cap = uc_audit::capture::start();
    let (status, body) = send_from(
        &app,
        "POST",
        "/v1/sync/MUHJ/upload",
        Some(&good_token("MUHJ")),
        Some(upload),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let c = changes(&cap.events());
    assert_eq!(c.len(), 2, "one record per uploaded change: {c:?}");
    for r in &c {
        assert_eq!(r.admin, "site:svc-sync");
        assert_eq!(kv(&r.description, "entity"), ["sync_change"]);
        assert_eq!(kv(&r.description, "site"), ["MUHJ"]);
        assert_eq!(kv(&r.description, "outcome"), ["ok"]);
        assert!(
            r.description.contains("phones"),
            "table recorded: {}",
            r.description
        );
    }
    let mut ids: Vec<_> = c.iter().flat_map(|r| kv(&r.description, "id")).collect();
    ids.sort_unstable();
    assert_eq!(ids, ["p-edge", "p1"]);
    assert_eq!(kv(&c[1].description, "op"), ["delete"]);

    // A rejected upload (token for another site) writes no change record.
    let cap = uc_audit::capture::start();
    let (status, _) = send_from(
        &app,
        "POST",
        "/v1/sync/MUHJ/upload",
        Some(&good_token("MPLS")),
        Some(json!({"changes": [
            { "table": "phones", "id": "p-x", "op": "upsert", "payload": {"id": "p-x"} }
        ]})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(changes(&cap.events()).is_empty());
}

/// SR-40 (decision): a secret re-entry refusal (422) after authorization is
/// audited as a failed change with actor, site and entity id, and no
/// secret or body value reaches the record.
#[tokio::test]
async fn secret_reentry_refusal_is_audited_failed_without_secrets() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = app(&admin, "cca_sr40_reentry").await;
    let tok = admin_token();
    let secret = "sr40-trunk-secret";
    let group = |host: &str, pw: &str| {
        json!({"id": "tg-s", "strategy": "priority", "trunks": [
            {"id": "t1", "host": host, "protocol": "tls", "sip_password": pw}
        ]})
    };
    let (s, b) = send_from(
        &app,
        "POST",
        "/v1/sites/MUHJ/trunkgroups",
        Some(&tok),
        Some(group("a.carrier.example", secret)),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "seed: {b}");

    let cap = uc_audit::capture::start();
    // Marker kept while the trunk destination changes: re-entry required.
    let (s, b) = send_from(
        &app,
        "POST",
        "/v1/sites/MUHJ/trunkgroups",
        Some(&tok),
        Some(group("b.carrier.example", "***REDACTED***")),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
    let c = changes(&cap.events());
    assert_eq!(c.len(), 1, "{c:?}");
    let d = c[0].description.as_str();
    assert_eq!(c[0].admin, oidc_actor());
    assert_eq!(kv(d, "entity"), ["trunk_group"]);
    assert_eq!(kv(d, "id"), ["tg-s"]);
    assert_eq!(kv(d, "site"), ["MUHJ"]);
    assert_eq!(kv(d, "outcome"), ["failed"]);
    let all = serde_json::to_string(&cap.events()).expect("json");
    assert!(
        !all.contains(secret) && !all.contains("carrier.example"),
        "no body values in audit: {all}"
    );
}

/// SR-40 round 1 (NIST-007): the site's claimed local writer rides on the
/// `sync_change` record as `claimed_origin_actor` (round 2, SEC-010: keyed
/// as a claim, 250 B actor cap); the actor stays the site account.
#[tokio::test]
async fn sync_upload_records_origin_actor() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = app(&admin, "cca_sr40_origin").await;
    let long = format!("local:{}", "o".repeat(300));
    let upload = json!({ "changes": [
        { "table": "phones", "id": "p-o", "op": "upsert",
          "origin_actor": "local:admin:admin",
          "payload": { "id": "p-o", "mac_address": "ab:cd:ef:00:11:41" } },
        { "table": "phones", "id": "p-l", "op": "upsert",
          "origin_actor": long,
          "payload": { "id": "p-l", "mac_address": "ab:cd:ef:00:11:42" } },
    ]});
    let cap = uc_audit::capture::start();
    let (status, body) = send_from(
        &app,
        "POST",
        "/v1/sync/MUHJ/upload",
        Some(&good_token("MUHJ")),
        Some(upload),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let c = changes(&cap.events());
    assert_eq!(c.len(), 2, "{c:?}");
    assert!(c.iter().all(|c| c.admin == "site:svc-sync"));
    assert_eq!(kv(&c[0].description, "origin_actor"), Vec::<&str>::new());
    assert_eq!(
        kv(&c[0].description, "claimed_origin_actor"),
        ["local:admin:admin"]
    );
    let capped = kv(&c[1].description, "claimed_origin_actor");
    assert_eq!(
        capped,
        [&long[..sbc_http_util::mgmt_audit::MAX_ACTOR_BYTES]]
    );
}

/// SR-40 round 1 (NIST-008): a classified write whose body the extractor
/// refused (before authorization) is recorded as `unauthenticated`.
#[tokio::test]
async fn extractor_rejected_write_is_recorded_unauthenticated() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = app(&admin, "cca_sr40_extractor").await;
    let tok = admin_token();
    let cap = uc_audit::capture::start();
    let mut req = Request::builder()
        .uri("/v1/sites/MUHJ/phones")
        .method("POST")
        .header(header::AUTHORIZATION, format!("Bearer {tok}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{not json"))
        .expect("req");
    let peer: SocketAddr = "192.0.2.77:51000".parse().expect("peer");
    req.extensions_mut().insert(ConnectInfo(peer));
    let resp = app.clone().oneshot(req).await.expect("response");
    assert!(resp.status().is_client_error(), "{}", resp.status());
    let c = changes(&cap.events());
    assert_eq!(c.len(), 1, "{c:?}");
    assert_eq!(c[0].admin, "unauthenticated");
    let d = c[0].description.as_str();
    assert_eq!(kv(d, "entity"), ["phone"]);
    assert_eq!(kv(d, "reason"), ["invalid"]);
    assert_eq!(kv(d, "site"), ["MUHJ"]);
    assert_eq!(kv(d, "src"), ["192.0.2.77"]);
}
