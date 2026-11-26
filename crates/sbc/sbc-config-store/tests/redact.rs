//! Shared secret redaction (`sbc_config_store::redact`): phone line SIP
//! passwords, the phone LDAP bind password, and trunk SIP passwords are
//! replaced with a marker on read and restored from the stored row when a
//! client sends the marker back. No database needed.
//!
//! ## NIST 800-53 Rev5: IA-5, AC-3, SI-12

#![allow(clippy::unwrap_used)] // test harness

use sbc_config_store::redact::{self, REDACTED};
use serde_json::{Value, json};

const LINE1_PW: &str = "line-one-secret";
const LINE2_PW: &str = "line-two-secret";
const LDAP_PW: &str = "ldap-bind-secret";

fn stored_phone() -> Value {
    json!({
        "id": "p1",
        "mac_address": "00:11:22:33:44:55",
        "lines": [
            {"index": 1, "directory_number": "1001", "sip_username": "1001",
             "sip_password": LINE1_PW, "sip_server": "sip.example.mil"},
            {"index": 2, "directory_number": "1002", "sip_username": "1002",
             "sip_password": LINE2_PW, "sip_server": "sip.example.mil"},
        ],
        "directory": {
            "enabled": true,
            "ldap_server": "ldap.example.mil",
            "ldap_port": 636,
            "ldap_bind_dn": "cn=phone,dc=example,dc=mil",
            "ldap_password": LDAP_PW,
            "ldap_tls": true,
        },
    })
}

#[test]
fn marker_is_unchanged() {
    // Clients (site API, dashboard) already know this exact string.
    assert_eq!(REDACTED, "***REDACTED***");
}

#[test]
fn phone_redacts_line_and_ldap_passwords() {
    let mut p = stored_phone();
    redact::phone(&mut p);
    assert_eq!(p["lines"][0]["sip_password"], REDACTED);
    assert_eq!(p["lines"][1]["sip_password"], REDACTED);
    assert_eq!(p["directory"]["ldap_password"], REDACTED);
    // Non-secret fields are untouched.
    assert_eq!(p["lines"][0]["sip_username"], "1001");
    assert_eq!(p["directory"]["ldap_bind_dn"], "cn=phone,dc=example,dc=mil");
    let text = p.to_string();
    for secret in [LINE1_PW, LINE2_PW, LDAP_PW] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
}

#[test]
fn phone_keeps_empty_and_null_secrets_unmarked() {
    let mut p = json!({
        "id": "p1",
        "lines": [
            {"index": 1, "sip_password": ""},
            {"index": 2, "sip_password": null},
            {"index": 3},
        ],
        "directory": {"ldap_password": null},
    });
    let before = p.clone();
    redact::phone(&mut p);
    assert_eq!(p, before, "empty/null/absent secrets are not marked");

    let mut p = json!({"id": "p1", "directory": {"ldap_password": ""}});
    redact::phone(&mut p);
    assert_eq!(p["directory"]["ldap_password"], "");

    // No lines / no directory: no panic, no change.
    let mut p = json!({"id": "p1"});
    redact::phone(&mut p);
    assert_eq!(p, json!({"id": "p1"}));
}

#[test]
fn phone_marker_restores_stored_by_line_index() {
    let stored = stored_phone();
    let mut body = stored.clone();
    redact::phone(&mut body);
    // Client reorders lines; matching is by `index`, not position.
    body["lines"].as_array_mut().unwrap().reverse();
    redact::restore_phone_secrets(&mut body, Some(&stored));
    assert_eq!(body["lines"][0]["index"], 2);
    assert_eq!(body["lines"][0]["sip_password"], LINE2_PW);
    assert_eq!(body["lines"][1]["sip_password"], LINE1_PW);
    assert_eq!(body["directory"]["ldap_password"], LDAP_PW);
}

#[test]
fn phone_new_value_replaces_stored() {
    let stored = stored_phone();
    let mut body = stored.clone();
    redact::phone(&mut body);
    body["lines"][0]["sip_password"] = json!("line-one-new");
    body["directory"]["ldap_password"] = json!("ldap-new");
    redact::restore_phone_secrets(&mut body, Some(&stored));
    assert_eq!(body["lines"][0]["sip_password"], "line-one-new");
    assert_eq!(body["lines"][1]["sip_password"], LINE2_PW, "marker kept");
    assert_eq!(body["directory"]["ldap_password"], "ldap-new");

    // Empty string / null clear the secret; they are not restored.
    let mut body = stored.clone();
    body["lines"][0]["sip_password"] = json!("");
    body["directory"]["ldap_password"] = Value::Null;
    redact::restore_phone_secrets(&mut body, Some(&stored));
    assert_eq!(body["lines"][0]["sip_password"], "");
    assert!(body["directory"]["ldap_password"].is_null());
}

#[test]
fn phone_marker_without_stored_line_becomes_empty() {
    // New phone: nothing stored.
    let mut body = json!({"id": "p1", "lines": [{"index": 1, "sip_password": REDACTED}]});
    redact::restore_phone_secrets(&mut body, None);
    assert_eq!(body["lines"][0]["sip_password"], "");

    // Stored phone without that line.
    let stored = json!({"id": "p1", "lines": []});
    let mut body = json!({"id": "p1", "lines": [{"index": 1, "sip_password": REDACTED}]});
    redact::restore_phone_secrets(&mut body, Some(&stored));
    assert_eq!(body["lines"][0]["sip_password"], "");

    // Stored line without a password.
    let stored = json!({"id": "p1", "lines": [{"index": 1}]});
    let mut body = json!({"id": "p1", "lines": [{"index": 1, "sip_password": REDACTED}]});
    redact::restore_phone_secrets(&mut body, Some(&stored));
    assert_eq!(body["lines"][0]["sip_password"], "");
}

#[test]
fn phone_ldap_marker_without_stored_becomes_null() {
    let mut body = json!({"id": "p1", "directory": {"ldap_password": REDACTED}});
    redact::restore_phone_secrets(&mut body, None);
    assert!(body["directory"]["ldap_password"].is_null(), "{body}");

    let stored = json!({"id": "p1", "directory": {"ldap_server": "ldap.example.mil"}});
    let mut body = json!({"id": "p1", "directory": {
        "ldap_server": "ldap.example.mil", "ldap_password": REDACTED}});
    redact::restore_phone_secrets(&mut body, Some(&stored));
    assert!(body["directory"]["ldap_password"].is_null(), "{body}");
}

#[test]
fn phone_marker_never_restores_from_other_line_index() {
    let stored = json!({"id": "p1", "lines": [{"index": 1, "sip_password": LINE1_PW}]});
    let mut body = json!({"id": "p1", "lines": [{"index": 2, "sip_password": REDACTED}]});
    redact::restore_phone_secrets(&mut body, Some(&stored));
    assert_eq!(body["lines"][0]["sip_password"], "");

    // A line with no index never matches anything.
    let mut body = json!({"id": "p1", "lines": [{"sip_password": REDACTED}]});
    redact::restore_phone_secrets(&mut body, Some(&stored));
    assert_eq!(body["lines"][0]["sip_password"], "");
    assert!(!body.to_string().contains(LINE1_PW));
}

#[test]
fn phone_restore_never_persists_the_marker() {
    let stored = stored_phone();
    for existing in [None, Some(&stored)] {
        let mut body = json!({
            "id": "p1",
            "lines": [
                {"index": 1, "sip_password": REDACTED},
                {"index": 9, "sip_password": REDACTED},
            ],
            "directory": {"ldap_password": REDACTED},
        });
        redact::restore_phone_secrets(&mut body, existing);
        assert!(!body.to_string().contains(REDACTED), "{body}");
    }
}

#[test]
fn trunk_redact_and_restore_roundtrip() {
    let stored = json!({
        "id": "g1",
        "trunks": [
            {"id": "t1", "host": "a.example.mil", "sip_password": "trunk-one"},
            {"id": "t2", "host": "b.example.mil", "sip_password": "trunk-two"},
            {"id": "t3", "host": "c.example.mil", "sip_password": ""},
        ],
    });
    let mut group = stored.clone();
    redact::trunk_group(&mut group);
    assert_eq!(group["trunks"][0]["sip_password"], REDACTED);
    assert_eq!(group["trunks"][1]["sip_password"], REDACTED);
    assert_eq!(group["trunks"][2]["sip_password"], "");
    assert_eq!(redact::redacted(stored.clone()), group);

    // Round-trip: t1 kept (marker), t2 replaced, new t4 with a marker dropped.
    group["trunks"][1]["sip_password"] = json!("trunk-two-new");
    group["trunks"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "t4", "sip_password": REDACTED}));
    redact::restore_passwords(&mut group, Some(&stored));
    assert_eq!(group["trunks"][0]["sip_password"], "trunk-one");
    assert_eq!(group["trunks"][1]["sip_password"], "trunk-two-new");
    assert!(group["trunks"][3].get("sip_password").is_none());

    // No stored group (e.g. a template): every marker is dropped.
    let mut tpl = json!({"trunks": [{"id": "t1", "sip_password": REDACTED}]});
    redact::restore_passwords(&mut tpl, None);
    assert!(tpl["trunks"][0].get("sip_password").is_none());

    let mut t = json!({"id": "t9", "sip_password": REDACTED});
    redact::drop_marker_password(&mut t);
    assert!(t.get("sip_password").is_none());
    let mut t = json!({"id": "t9", "sip_password": "x"});
    redact::trunk(&mut t);
    assert_eq!(t["sip_password"], REDACTED);
}
