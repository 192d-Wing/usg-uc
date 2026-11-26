//! LDAP bind-password re-entry rule: a phone write that keeps the
//! redaction marker for `directory.ldap_password` while changing where that
//! password is sent (host, port, TLS, bind DN) must re-enter the password.
//! The check runs on the incoming body before marker restore. Round 1
//! widened the rule to SIP line destinations (see `redact` unit tests for
//! the MAC, line and trunk cases).
//!
//! API: `sbc_config_store::redact::phone_secret_reentry_required(body,
//! existing) -> bool`. The central handler maps `true` to 422
//! `secret_reentry_required`.
//!
//! ## NIST 800-53 Rev5: IA-5

use sbc_config_store::redact::{REDACTED, phone_secret_reentry_required};
use serde_json::{Value, json};

fn stored() -> Value {
    json!({
        "id": "p1",
        "lines": [{"index": 1, "sip_password": "line-secret", "sip_server": "sip.example.mil"}],
        "directory": {
            "enabled": true,
            "ldap_server": "ldap.example.mil",
            "ldap_port": 636,
            "ldap_bind_dn": "cn=phone,dc=example,dc=mil",
            "ldap_password": "ldap-secret",
            "ldap_tls": true,
        },
    })
}

fn marker_body() -> Value {
    let mut b = stored();
    b["lines"][0]["sip_password"] = json!(REDACTED);
    b["directory"]["ldap_password"] = json!(REDACTED);
    b
}

#[test]
fn unchanged_destination_with_marker_is_allowed() {
    let s = stored();
    assert!(!phone_secret_reentry_required(&marker_body(), Some(&s)));
}

#[test]
fn marker_with_changed_ldap_destination_requires_reentry() {
    let s = stored();
    for (field, value) in [
        ("ldap_server", json!("ldap.attacker.example")),
        ("ldap_port", json!(389)),
        ("ldap_tls", json!(false)),
        ("ldap_bind_dn", json!("cn=other,dc=example,dc=mil")),
    ] {
        let mut b = marker_body();
        b["directory"][field] = value;
        assert!(
            phone_secret_reentry_required(&b, Some(&s)),
            "marker kept with changed {field} must require re-entry"
        );
    }
    // Removing the destination field counts as a change too.
    let mut b = marker_body();
    if let Some(d) = b["directory"].as_object_mut() {
        d.remove("ldap_server");
    }
    assert!(phone_secret_reentry_required(&b, Some(&s)));
}

#[test]
fn new_ldap_password_with_changed_destination_is_allowed() {
    let s = stored();
    let mut b = marker_body();
    b["directory"]["ldap_server"] = json!("ldap2.example.mil");
    b["directory"]["ldap_password"] = json!("ldap-new-secret");
    assert!(!phone_secret_reentry_required(&b, Some(&s)));
}

#[test]
fn sip_line_server_change_with_marker_requires_reentry() {
    // Round-1 decision (supersedes decision 1's LDAP-only scope): a kept
    // line marker with a changed `sip_server` must re-enter the password.
    let s = stored();
    let mut b = marker_body();
    b["lines"][0]["sip_server"] = json!("sip2.example.mil");
    assert!(phone_secret_reentry_required(&b, Some(&s)));
    b["lines"][0]["sip_password"] = json!("line-new-secret");
    assert!(!phone_secret_reentry_required(&b, Some(&s)));
}

#[test]
fn no_stored_row_is_not_reentry() {
    // A marker with nothing stored is cleared by restore, not refused.
    assert!(!phone_secret_reentry_required(&marker_body(), None));
}
