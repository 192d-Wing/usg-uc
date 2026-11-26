//! Secret redaction on the operator surface (SR-39). Phone line SIP
//! passwords, the phone LDAP bind password and trunk SIP passwords are
//! returned as the marker on every operator read, for every role. A write
//! that sends the marker back keeps the stored value; the sync surface
//! still carries the real secrets. DSN-gated like the parent module.
//!
//! ## NIST 800-53 Rev5: IA-5, AC-3, AC-6, SI-12

#![allow(clippy::panic)] // test harness: fail loudly with context

use super::*;

const MARKER: &str = "***REDACTED***";
const LINE1_PW: &str = "line-one-secret";
const LINE2_PW: &str = "line-two-secret";
const LDAP_PW: &str = "ldap-bind-secret";
const TRUNK1_PW: &str = "trunk-one-secret";
const TRUNK2_PW: &str = "trunk-two-secret";
const SECRETS: [&str; 5] = [LINE1_PW, LINE2_PW, LDAP_PW, TRUNK1_PW, TRUNK2_PW];

fn phone_body(line1: &str, line2: &str, ldap: &str) -> Value {
    json!({
        "id": "ps",
        "mac_address": "00:11:22:33:44:55",
        "lines": [
            {"index": 1, "directory_number": "1001", "display_name": "One",
             "sip_username": "1001", "sip_password": line1,
             "sip_server": "sip.muhj.x", "sip_port": 5061, "transport": "tls"},
            {"index": 2, "directory_number": "1002", "display_name": "Two",
             "sip_username": "1002", "sip_password": line2,
             "sip_server": "sip.muhj.x", "sip_port": 5061, "transport": "tls"},
        ],
        "directory": {
            "enabled": true,
            "ldap_server": "ldap.muhj.x",
            "ldap_port": 636,
            "ldap_base_dn": "dc=muhj,dc=x",
            "ldap_bind_dn": "cn=phone,dc=muhj,dc=x",
            "ldap_password": ldap,
            "ldap_tls": true,
        },
    })
}

fn trunk_group_body(t1: &str, t2: &str) -> Value {
    json!({
        "id": "tg1",
        "strategy": "priority",
        "trunks": [
            {"id": "t1", "host": "a.carrier.x", "protocol": "tls", "sip_password": t1},
            {"id": "t2", "host": "b.carrier.x", "protocol": "tls", "sip_password": t2},
        ],
    })
}

/// Router over a scratch store with MUHJ, phone `ps` (two lines + LDAP) and
/// trunk group `tg1` (two trunks), all holding plaintext secrets.
async fn seeded(admin: &str, name: &str) -> Router {
    let app = app(admin, name).await;
    let tok = admin_token();
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(phone_body(LINE1_PW, LINE2_PW, LDAP_PW)),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "seed phone: {b}");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/trunkgroups",
        Some(&tok),
        Some(trunk_group_body(TRUNK1_PW, TRUNK2_PW)),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "seed trunk group: {b}");
    app
}

/// The live payload of `table`/`id` on the site sync snapshot.
async fn snapshot_row(app: &Router, table: &str, id: &str) -> Value {
    let (s, b) = send(app, "/v1/sync/MUHJ/snapshot", Some(&good_token("MUHJ"))).await;
    assert_eq!(s, StatusCode::OK);
    b["tables"]
        .as_array()
        .expect("tables")
        .iter()
        .find(|t| t["table"] == table)
        .and_then(|t| t["rows"].as_array())
        .and_then(|rows| rows.iter().find(|r| r["id"] == id))
        .map_or_else(
            || panic!("{table}/{id} missing from snapshot: {b}"),
            |r| r["payload"].clone(),
        )
}

fn assert_no_secret(ctx: &str, body: &Value) {
    let text = body.to_string();
    for secret in SECRETS {
        assert!(!text.contains(secret), "{ctx}: {secret} leaked: {text}");
    }
}

fn assert_phone_marked(ctx: &str, p: &Value) {
    assert_eq!(p["lines"][0]["sip_password"], MARKER, "{ctx}: {p}");
    assert_eq!(p["lines"][1]["sip_password"], MARKER, "{ctx}: {p}");
    assert_eq!(p["directory"]["ldap_password"], MARKER, "{ctx}: {p}");
}

fn assert_trunks_marked(ctx: &str, g: &Value) {
    assert_eq!(g["trunks"][0]["sip_password"], MARKER, "{ctx}: {g}");
    assert_eq!(g["trunks"][1]["sip_password"], MARKER, "{ctx}: {g}");
}

fn find_item<'a>(list: &'a Value, id: &str) -> &'a Value {
    list["items"]
        .as_array()
        .expect("items")
        .iter()
        .find(|x| x["id"] == id)
        .unwrap_or_else(|| panic!("{id} not listed: {list}"))
}

#[tokio::test]
async fn reader_list_and_get_phone_hide_secrets() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_reader_phone").await;
    for role in ["auditor", "config-reader"] {
        let tok = operator_token(&[role], &["MUHJ"]);
        let (s, list) = send_req(&app, "GET", "/v1/sites/MUHJ/phones", Some(&tok), None).await;
        assert_eq!(s, StatusCode::OK, "{role} list");
        assert_no_secret(role, &list);
        assert_phone_marked(role, find_item(&list, "ps"));

        let (s, one) = send_req(&app, "GET", "/v1/sites/MUHJ/phones/ps", Some(&tok), None).await;
        assert_eq!(s, StatusCode::OK, "{role} get");
        assert_no_secret(role, &one);
        assert_phone_marked(role, &one);
        // Non-secret fields survive.
        assert_eq!(one["lines"][0]["sip_username"], "1001");
        assert_eq!(one["directory"]["ldap_server"], "ldap.muhj.x");
    }
}

#[tokio::test]
async fn reader_list_and_get_trunk_group_hide_secrets() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_reader_tg").await;
    for role in ["auditor", "config-reader"] {
        let tok = operator_token(&[role], &["MUHJ"]);
        let (s, list) = send_req(&app, "GET", "/v1/sites/MUHJ/trunkgroups", Some(&tok), None).await;
        assert_eq!(s, StatusCode::OK, "{role} list");
        assert_no_secret(role, &list);
        assert_trunks_marked(role, find_item(&list, "tg1"));

        let (s, one) = send_req(
            &app,
            "GET",
            "/v1/sites/MUHJ/trunkgroups/tg1",
            Some(&tok),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{role} get");
        assert_no_secret(role, &one);
        assert_trunks_marked(role, &one);
        assert_eq!(one["trunks"][0]["host"], "a.carrier.x");
    }
}

#[tokio::test]
async fn admin_reads_are_redacted_too() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_admin_reads").await;
    let fleet = admin_token();
    let config_admin = operator_token(&["config-admin"], &["MUHJ"]);
    let site_admin = operator_token(&["site-admin"], &["MUHJ"]);
    let phones_admin = operator_token(&["phones-admin"], &["MUHJ"]);
    let trunk_admin = operator_token(&["trunk-admin"], &["MUHJ"]);
    let raw_phones = operator_token(&["phones:read"], &["MUHJ"]);
    let raw_trunks = operator_token(&["trunkgroups:*"], &["MUHJ"]);
    let phone_uris = ["/v1/sites/MUHJ/phones", "/v1/sites/MUHJ/phones/ps"];
    let tg_uris = [
        "/v1/sites/MUHJ/trunkgroups",
        "/v1/sites/MUHJ/trunkgroups/tg1",
    ];
    let cases: Vec<(&str, &String, &[&str])> = vec![
        ("fleet-admin", &fleet, &phone_uris),
        ("fleet-admin", &fleet, &tg_uris),
        ("config-admin", &config_admin, &phone_uris),
        ("config-admin", &config_admin, &tg_uris),
        ("site-admin", &site_admin, &phone_uris),
        ("site-admin", &site_admin, &tg_uris),
        ("phones-admin", &phones_admin, &phone_uris),
        ("trunk-admin", &trunk_admin, &tg_uris),
        ("phones:read", &raw_phones, &phone_uris),
        ("trunkgroups:*", &raw_trunks, &tg_uris),
    ];
    for (role, tok, uris) in cases {
        for uri in uris {
            let (s, b) = send_req(&app, "GET", uri, Some(tok), None).await;
            assert_eq!(s, StatusCode::OK, "{role} GET {uri}");
            assert_no_secret(&format!("{role} GET {uri}"), &b);
            let text = b.to_string();
            assert!(
                text.contains(MARKER),
                "{role} GET {uri} shows marker: {text}"
            );
        }
    }
}

#[tokio::test]
async fn phone_write_with_marker_preserves_stored_secret() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_phone_marker").await;
    let tok = operator_token(&["config-admin"], &["MUHJ"]);

    // Dashboard flow: GET, edit a non-secret field, POST back.
    let (s, mut body) = send_req(&app, "GET", "/v1/sites/MUHJ/phones/ps", Some(&tok), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_phone_marked("GET before edit", &body);
    body["lines"][0]["display_name"] = json!("One (edited)");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "round-trip write: {b}");

    let p = snapshot_row(&app, "phones", "ps").await;
    assert_eq!(p["lines"][0]["display_name"], "One (edited)");
    assert_eq!(p["lines"][0]["sip_password"], LINE1_PW, "{p}");
    assert_eq!(p["lines"][1]["sip_password"], LINE2_PW, "{p}");
    assert_eq!(p["directory"]["ldap_password"], LDAP_PW, "{p}");

    // An explicit marker body (no prior GET) behaves the same.
    let (s, _) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(phone_body(MARKER, MARKER, MARKER)),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let p = snapshot_row(&app, "phones", "ps").await;
    assert!(!p.to_string().contains(MARKER), "marker stored: {p}");
    assert_eq!(p["lines"][0]["sip_password"], LINE1_PW);
    assert_eq!(p["lines"][1]["sip_password"], LINE2_PW);
    assert_eq!(p["directory"]["ldap_password"], LDAP_PW);
}

#[tokio::test]
async fn phone_write_with_new_value_replaces_secret() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_phone_new").await;
    let tok = operator_token(&["phones-admin"], &["MUHJ"]);
    let (s, _) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(phone_body("line-one-rotated", MARKER, "ldap-rotated")),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let p = snapshot_row(&app, "phones", "ps").await;
    assert_eq!(p["lines"][0]["sip_password"], "line-one-rotated");
    assert_eq!(p["lines"][1]["sip_password"], LINE2_PW, "marker line kept");
    assert_eq!(p["directory"]["ldap_password"], "ldap-rotated");

    // Empty / null clear the secret.
    let mut body = phone_body("", MARKER, "");
    body["directory"]["ldap_password"] = Value::Null;
    let (s, _) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let p = snapshot_row(&app, "phones", "ps").await;
    assert_eq!(p["lines"][0]["sip_password"], "");
    assert_eq!(p["lines"][1]["sip_password"], LINE2_PW);
    assert!(p["directory"]["ldap_password"].is_null(), "{p}");
}

#[tokio::test]
async fn trunk_group_write_with_marker_preserves_stored_secret() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_tg_marker").await;
    let tok = operator_token(&["trunk-admin"], &["MUHJ"]);

    let (s, mut body) = send_req(
        &app,
        "GET",
        "/v1/sites/MUHJ/trunkgroups/tg1",
        Some(&tok),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_trunks_marked("GET before edit", &body);
    body["name"] = json!("edited");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/trunkgroups",
        Some(&tok),
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "round-trip write: {b}");

    let g = snapshot_row(&app, "trunk_groups", "tg1").await;
    assert_eq!(g["name"], "edited");
    assert_eq!(g["trunks"][0]["sip_password"], TRUNK1_PW, "{g}");
    assert_eq!(g["trunks"][1]["sip_password"], TRUNK2_PW, "{g}");
}

#[tokio::test]
async fn trunk_group_write_with_new_value_replaces_secret() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_tg_new").await;
    let tok = operator_token(&["trunk-admin"], &["MUHJ"]);
    let (s, _) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/trunkgroups",
        Some(&tok),
        Some(trunk_group_body("trunk-one-rotated", MARKER)),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let g = snapshot_row(&app, "trunk_groups", "tg1").await;
    assert_eq!(g["trunks"][0]["sip_password"], "trunk-one-rotated");
    assert_eq!(
        g["trunks"][1]["sip_password"], TRUNK2_PW,
        "marker trunk kept"
    );
}

#[tokio::test]
async fn marker_on_new_phone_is_not_stored() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_new_marker").await;
    let tok = admin_token();

    let mut body = phone_body(MARKER, MARKER, MARKER);
    body["id"] = json!("pn");
    body["mac_address"] = json!("66:77:88:99:aa:bb");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let phone = snapshot_row(&app, "phones", "pn").await;
    assert_eq!(phone["lines"][0]["sip_password"], "", "{phone}");
    assert_eq!(phone["lines"][1]["sip_password"], "", "{phone}");
    assert!(phone["directory"]["ldap_password"].is_null(), "{phone}");

    // Never resolved against another row of the same site.
    assert!(!phone.to_string().contains(LINE1_PW), "{phone}");

    // Same for a brand-new trunk group: the marker is dropped.
    let mut tg = trunk_group_body(MARKER, MARKER);
    tg["id"] = json!("tg-new");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/trunkgroups",
        Some(&tok),
        Some(tg),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let group = snapshot_row(&app, "trunk_groups", "tg-new").await;
    assert!(group["trunks"][0].get("sip_password").is_none(), "{group}");
    assert!(group["trunks"][1].get("sip_password").is_none(), "{group}");

    // The journal never carries the marker either.
    let (_, delta) = send(
        &app,
        "/v1/sync/MUHJ/delta?since=0",
        Some(&good_token("MUHJ")),
    )
    .await;
    assert!(
        !delta.to_string().contains(MARKER),
        "marker in journal: {delta}"
    );
}

#[tokio::test]
async fn sync_delta_and_snapshot_carry_real_secrets() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_sync_real").await;
    let sync = good_token("MUHJ");

    let (s, snap) = send(&app, "/v1/sync/MUHJ/snapshot", Some(&sync)).await;
    assert_eq!(s, StatusCode::OK);
    let (s, delta) = send(&app, "/v1/sync/MUHJ/delta?since=0", Some(&sync)).await;
    assert_eq!(s, StatusCode::OK);
    for (ctx, body) in [("snapshot", &snap), ("delta", &delta)] {
        let text = body.to_string();
        for secret in SECRETS {
            assert!(text.contains(secret), "{ctx} lacks {secret}: {text}");
        }
        assert!(!text.contains(MARKER), "{ctx} carries the marker: {text}");
    }

    // A marker round-trip by an operator leaves the sync payloads real.
    let tok = admin_token();
    let (_, body) = send_req(&app, "GET", "/v1/sites/MUHJ/phones/ps", Some(&tok), None).await;
    let (s, _) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, delta) = send(&app, "/v1/sync/MUHJ/delta?since=0", Some(&sync)).await;
    let text = delta.to_string();
    assert!(!text.contains(MARKER), "delta after round-trip: {text}");
    let p = snapshot_row(&app, "phones", "ps").await;
    assert_eq!(p["lines"][0]["sip_password"], LINE1_PW);
}

#[tokio::test]
async fn template_marker_is_dropped() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_template").await;
    let tok = admin_token();
    let mut tpl = trunk_group_body(MARKER, "tpl-real-secret");
    tpl["id"] = json!("tpl-tg");
    let (s, _) = send_req(
        &app,
        "PUT",
        "/v1/templates/trunk_group/tpl-tg",
        Some(&tok),
        Some(tpl),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = send_req(
        &app,
        "PUT",
        "/v1/templates/trunk_group/tpl-tg/sites/MUHJ",
        Some(&tok),
        Some(json!({"ring": 0})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, r) = send_req(
        &app,
        "POST",
        "/v1/templates/trunk_group/tpl-tg/materialize?ring=0",
        Some(&tok),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{r}");

    let (_, snap) = send(&app, "/v1/sync/MUHJ/snapshot", Some(&good_token("MUHJ"))).await;
    assert!(
        !snap.to_string().contains(MARKER),
        "marker materialized: {snap}"
    );
    let g = snapshot_row(&app, "trunk_groups", "tpl-tg").await;
    assert!(g["trunks"][0].get("sip_password").is_none(), "{g}");
    // A real secret in the template is materialized as-is.
    assert_eq!(g["trunks"][1]["sip_password"], "tpl-real-secret");
}

/// Decision 1: keeping the LDAP marker while changing where the bind
/// password goes (host, port, TLS, bind DN) is refused with 422
/// `secret_reentry_required`; the stored row is unchanged. SIP lines are
/// not subject to the rule.
#[tokio::test]
async fn ldap_marker_with_changed_destination_requires_reentry() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_ldap_reentry").await;
    let tok = operator_token(&["config-admin"], &["MUHJ"]);

    for (field, value) in [
        ("ldap_server", json!("ldap.elsewhere.x")),
        ("ldap_port", json!(389)),
        ("ldap_tls", json!(false)),
        ("ldap_bind_dn", json!("cn=other,dc=muhj,dc=x")),
    ] {
        let mut body = phone_body(MARKER, MARKER, MARKER);
        body["directory"][field] = value;
        let (s, b) = send_req(
            &app,
            "POST",
            "/v1/sites/MUHJ/phones",
            Some(&tok),
            Some(body),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{field}: {b}");
        assert_eq!(b["error"], "secret_reentry_required", "{field}: {b}");
        assert_no_secret(field, &b);
    }
    let p = snapshot_row(&app, "phones", "ps").await;
    assert_eq!(
        p["directory"]["ldap_server"], "ldap.muhj.x",
        "refused writes not stored"
    );
    assert_eq!(p["directory"]["ldap_password"], LDAP_PW);

    // Re-entering the password with the new destination is accepted.
    let mut body = phone_body(MARKER, MARKER, "ldap-reentered");
    body["directory"]["ldap_server"] = json!("ldap2.muhj.x");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let p = snapshot_row(&app, "phones", "ps").await;
    assert_eq!(p["directory"]["ldap_server"], "ldap2.muhj.x");
    assert_eq!(p["directory"]["ldap_password"], "ldap-reentered");
    assert_eq!(p["lines"][0]["sip_password"], LINE1_PW);

    // Round-1 decision (supersedes LDAP-only): a SIP line's server change
    // with the marker kept is refused too, naming the field.
    let mut body = phone_body(MARKER, MARKER, MARKER);
    body["directory"]["ldap_server"] = json!("ldap2.muhj.x");
    body["lines"][0]["sip_server"] = json!("sip2.muhj.x");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(body.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
    assert_eq!(b["error"], "secret_reentry_required", "{b}");
    assert_eq!(b["field"], "lines[0].sip_server", "{b}");
    assert_no_secret("sip_server", &b);

    // Re-entering that line's password allows it; other markers are kept.
    body["lines"][0]["sip_password"] = json!("line-one-reentered");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let p = snapshot_row(&app, "phones", "ps").await;
    assert_eq!(p["lines"][0]["sip_server"], "sip2.muhj.x");
    assert_eq!(p["lines"][0]["sip_password"], "line-one-reentered");
    assert_eq!(p["lines"][1]["sip_password"], LINE2_PW);
    assert_eq!(p["directory"]["ldap_password"], "ldap-reentered");
}

/// Round 1: a kept trunk marker with a changed trunk destination is
/// refused with the field named; the stored group is unchanged.
#[tokio::test]
async fn trunk_destination_change_with_marker_requires_reentry() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_trunk_reentry").await;
    let tok = operator_token(&["config-admin"], &["MUHJ"]);
    let mut body = trunk_group_body(MARKER, MARKER);
    body["trunks"][1]["host"] = json!("evil.carrier.x");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/trunkgroups",
        Some(&tok),
        Some(body.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
    assert_eq!(b["error"], "secret_reentry_required", "{b}");
    assert_eq!(b["field"], "trunks[1].host", "{b}");
    assert_no_secret("trunk host", &b);
    let g = snapshot_row(&app, "trunk_groups", "tg1").await;
    assert_eq!(g["trunks"][1]["host"], "b.carrier.x");

    body["trunks"][1]["sip_password"] = json!("trunk-two-reentered");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/trunkgroups",
        Some(&tok),
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let g = snapshot_row(&app, "trunk_groups", "tg1").await;
    assert_eq!(g["trunks"][0]["sip_password"], TRUNK1_PW);
    assert_eq!(g["trunks"][1]["sip_password"], "trunk-two-reentered");
}

/// SEC-003: every table is classified for read redaction (DB-free, runs in
/// CI). The expectation is an exhaustive match, so a new table fails to
/// compile until it is classified here and in `redact_for_read`.
#[test]
fn redact_for_read_classifies_every_table() {
    let payload = json!({
        "id": "x",
        "lines": [{"index": 1, "sip_password": LINE1_PW}],
        "directory": {"ldap_password": LDAP_PW},
        "trunks": [{"id": "t1", "sip_password": TRUNK1_PW}],
    });
    for table in ConfigTable::ALL {
        let mut got = payload.clone();
        redact_for_read(table, &mut got);
        let mut want = payload.clone();
        match table {
            ConfigTable::Phones => {
                want["lines"][0]["sip_password"] = json!(MARKER);
                want["directory"]["ldap_password"] = json!(MARKER);
            }
            ConfigTable::TrunkGroups => {
                want["trunks"][0]["sip_password"] = json!(MARKER);
            }
            ConfigTable::DirectoryNumbers
            | ConfigTable::DialPlans
            | ConfigTable::SiteTelephonyConfig
            | ConfigTable::SbcPartitions
            | ConfigTable::SbcCallingSearchSpaces
            | ConfigTable::SbcRoutePatterns
            | ConfigTable::SbcRouteLists => {}
        }
        assert_eq!(got, want, "{table:?}");
    }
}

/// SEC-001: keeping markers while moving the phone to another MAC would
/// provision the stored secrets to a different device: 422, row unchanged.
#[tokio::test]
async fn mac_change_with_marker_requires_reentry() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_mac_reentry").await;
    let tok = operator_token(&["config-admin"], &["MUHJ"]);

    let mut body = phone_body(MARKER, MARKER, MARKER);
    body["mac_address"] = json!("66:77:88:99:aa:bb");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
    assert_eq!(b["error"], "secret_reentry_required", "{b}");
    assert_eq!(b["field"], "mac_address", "{b}");
    assert_no_secret("mac", &b);
    let p = snapshot_row(&app, "phones", "ps").await;
    assert_eq!(p["mac_address"], "00:11:22:33:44:55");
    assert_eq!(p["lines"][0]["sip_password"], LINE1_PW);

    // Same MAC in another spelling is not a change.
    let mut body = phone_body(MARKER, MARKER, MARKER);
    body["mac_address"] = json!("00-11-22-33-44-55");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");

    // Re-entering every secret allows the move.
    let mut body = phone_body("l1-new", "l2-new", "ldap-new");
    body["mac_address"] = json!("66:77:88:99:aa:bb");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let p = snapshot_row(&app, "phones", "ps").await;
    assert_eq!(p["lines"][0]["sip_password"], "l1-new");
    assert_eq!(p["directory"]["ldap_password"], "ldap-new");
}

/// SEC-002: removing line 1 and renumbering line 2 to index 1 keeps the
/// marker; it must not pick up line 1's password. The username at index 1
/// changed, so the write is refused; a renumber that only changes the
/// directory number stores `""` instead of copying the secret.
#[tokio::test]
async fn renumbered_line_marker_does_not_take_other_line_secret() {
    let Ok(admin) = std::env::var("CENTRAL_STORE_TEST_DSN") else {
        return;
    };
    let app = seeded(&admin, "cca_sr39_renumber").await;
    let tok = operator_token(&["config-admin"], &["MUHJ"]);
    let (_, mut body) = send_req(&app, "GET", "/v1/sites/MUHJ/phones/ps", Some(&tok), None).await;
    let lines = body["lines"].as_array_mut().expect("lines");
    lines.remove(0);
    lines[0]["index"] = json!(1);
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(body.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
    assert_eq!(b["field"], "lines[0].sip_username", "{b}");
    assert_no_secret("renumber", &b);

    // Same username and destination, different directory number: accepted,
    // and the marker is cleared rather than restored.
    body["lines"][0]["sip_username"] = json!("1001");
    let (s, b) = send_req(
        &app,
        "POST",
        "/v1/sites/MUHJ/phones",
        Some(&tok),
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    let p = snapshot_row(&app, "phones", "ps").await;
    assert_eq!(p["lines"][0]["directory_number"], "1002", "{p}");
    assert_eq!(p["lines"][0]["sip_password"], "", "{p}");
    assert!(!p.to_string().contains(LINE1_PW), "{p}");
    assert_eq!(p["directory"]["ldap_password"], LDAP_PW);
}
