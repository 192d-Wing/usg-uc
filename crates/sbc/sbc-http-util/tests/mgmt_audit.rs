//! SR-40: management-plane audit helpers shared by sbc-api and
//! central-config-api. Records are captured per thread
//! (`uc_audit::capture`); the auth-failure aggregator is process-global, so
//! every test uses its own documentation-range source addresses. Tests
//! that flush the aggregator live in their own binaries
//! (`mgmt_audit_flush.rs`, `mgmt_audit_cap.rs`): a flush at a future
//! instant closes every key's window, including other tests' live keys.
//!
//! ## NIST 800-53 Rev5: AU-2, AU-3, AU-12, CM-3, AC-7, SI-10, SC-5

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;

use sbc_http_util::mgmt_audit::{
    Actor, Op, Outcome, audit_field, auth_failure, auth_success, config_change,
};
use uc_audit::AuditEvent;
use uc_audit::event::{AuthMethod, AuthenticationAttempt, ConfigChangeType, ConfigurationChange};

const ISS: &str = "https://idp.example/realms/qa";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn oidc_actor() -> Actor {
    Actor {
        id: format!("oidc:s-1@{ISS}"),
        issuer: Some(ISS.to_string()),
        display: Some("op1".to_string()),
        source_ip: Some(ip("192.0.2.10")),
    }
}

fn changes(events: &[AuditEvent]) -> Vec<ConfigurationChange> {
    events
        .iter()
        .filter_map(|e| match e {
            AuditEvent::ConfigurationChange(c) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

fn auth_events(events: &[AuditEvent], from: IpAddr) -> Vec<AuthenticationAttempt> {
    events
        .iter()
        .filter_map(|e| match e {
            AuditEvent::AuthenticationAttempt(a) if a.source_ip == from => Some(a.clone()),
            _ => None,
        })
        .collect()
}

/// `key=value` pairs of a description (space separated).
fn kv(desc: &str) -> Vec<(String, String)> {
    desc.split(' ')
        .filter_map(|t| t.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn get<'a>(pairs: &'a [(String, String)], key: &str) -> Vec<&'a str> {
    pairs
        .iter()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .collect()
}

#[test]
fn config_change_description_has_entity_id_op_outcome() {
    let cap = uc_audit::capture::start();
    let a = oidc_actor();
    config_change(&a, "phone", "p1", Op::Create, Outcome::Ok, None);
    config_change(
        &a,
        "phone",
        "p1",
        Op::Update,
        Outcome::Failed("not_found"),
        None,
    );
    config_change(&a, "phone", "p1", Op::Delete, Outcome::Ok, Some("MUHJ"));
    config_change(
        &a,
        "phone",
        "p1",
        Op::Action("reboot"),
        Outcome::Failed("daemon_unavailable"),
        None,
    );
    let c = changes(&cap.events());
    assert_eq!(c.len(), 4, "{c:?}");
    for r in &c {
        assert_eq!(r.change_type, ConfigChangeType::Modified);
    }

    let p = kv(&c[0].description);
    assert_eq!(get(&p, "entity"), ["phone"]);
    assert_eq!(get(&p, "id"), ["p1"]);
    assert_eq!(get(&p, "op"), ["create"]);
    assert_eq!(get(&p, "outcome"), ["ok"]);
    assert!(get(&p, "reason").is_empty());
    assert!(
        c[0].description
            .starts_with("entity=phone id=p1 op=create outcome=ok"),
        "fixed field order: {}",
        c[0].description
    );

    let p = kv(&c[1].description);
    assert_eq!(get(&p, "op"), ["update"]);
    assert_eq!(get(&p, "outcome"), ["failed"]);
    assert_eq!(get(&p, "reason"), ["not_found"]);

    let p = kv(&c[2].description);
    assert_eq!(get(&p, "op"), ["delete"]);
    assert_eq!(get(&p, "site"), ["MUHJ"]);

    let p = kv(&c[3].description);
    assert_eq!(get(&p, "op"), ["reboot"]);
    assert_eq!(get(&p, "reason"), ["daemon_unavailable"]);
    assert_eq!(get(&p, "src"), ["192.0.2.10"]);
}

#[test]
fn config_change_admin_is_oidc_sub_at_iss() {
    let cap = uc_audit::capture::start();
    config_change(
        &oidc_actor(),
        "trunk_group",
        "tg1",
        Op::Update,
        Outcome::Ok,
        None,
    );
    let c = changes(&cap.events());
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].admin, format!("oidc:s-1@{ISS}"));
    let p = kv(&c[0].description);
    assert_eq!(get(&p, "iss"), [ISS]);
    // The display name is informational only, never the actor.
    assert_eq!(get(&p, "user"), ["op1"]);
    assert_ne!(c[0].admin, "op1");

    // Legacy / API-key actors carry no issuer.
    let cap = uc_audit::capture::start();
    let legacy = Actor {
        id: "apikey:0123456789abcdef".to_string(),
        issuer: None,
        display: None,
        source_ip: None,
    };
    config_change(
        &legacy,
        "tls",
        "server",
        Op::Action("tls_reload"),
        Outcome::Ok,
        None,
    );
    let c = changes(&cap.events());
    assert_eq!(c[0].admin, "apikey:0123456789abcdef");
    let p = kv(&c[0].description);
    assert!(get(&p, "iss").is_empty() && get(&p, "src").is_empty());
}

#[test]
fn audit_field_strips_control_chars_and_caps() {
    assert_eq!(audit_field("a\r\nb\u{0}c\td\u{1b}[2Je\u{7f}"), "abcd[2Je");
    assert_eq!(audit_field("plain-id_1.2"), "plain-id_1.2");
    let long = "x".repeat(500);
    assert_eq!(audit_field(&long).len(), 128);
    // Multi-byte input is cut on a char boundary at or under the cap.
    let wide = "\u{e9}".repeat(100); // 200 bytes
    let cut = audit_field(&wide);
    assert!(cut.len() <= 128 && cut.len() >= 126, "{}", cut.len());
    assert!(cut.chars().all(|c| c == '\u{e9}'));
    // C1 controls are stripped too.
    assert_eq!(audit_field("a\u{85}b\u{9b}c"), "abc");
}

/// A variable field cannot forge or duplicate a grammar key: ids, paths and
/// display names come from the caller.
#[test]
fn config_change_field_cannot_inject_keys() {
    let cap = uc_audit::capture::start();
    let a = Actor {
        id: "oidc:x outcome=ok@iss".to_string(),
        issuer: Some("iss op=create".to_string()),
        display: Some("op1 entity=tls".to_string()),
        source_ip: None,
    };
    config_change(
        &a,
        "route_pattern",
        "rp1 outcome=ok op=create\r\nentity=phone",
        Op::Delete,
        Outcome::Failed("storage"),
        Some("MUHJ site=MPLS"),
    );
    let c = changes(&cap.events());
    assert_eq!(c.len(), 1);
    let d = &c[0].description;
    assert!(!d.contains('\r') && !d.contains('\n'), "{d}");
    let p = kv(d);
    for key in [
        "entity", "id", "op", "outcome", "reason", "site", "iss", "user",
    ] {
        assert!(get(&p, key).len() <= 1, "duplicate {key} in {d}");
    }
    assert_eq!(get(&p, "entity"), ["route_pattern"]);
    assert_eq!(get(&p, "op"), ["delete"]);
    assert_eq!(get(&p, "outcome"), ["failed"]);
}

#[test]
fn auth_success_is_emitted_per_event() {
    let cap = uc_audit::capture::start();
    let from = ip("2001:db8:5:1::1");
    auth_success("admin", from, AuthMethod::Password);
    auth_success("admin", from, AuthMethod::Password);
    let a = auth_events(&cap.events(), from);
    assert_eq!(a.len(), 2, "successes are not aggregated");
    assert!(a.iter().all(|e| e.success && e.failure_reason.is_none()));
    assert_eq!(a[0].identity, "admin");
    assert_eq!(a[0].method, AuthMethod::Password);
}

#[test]
fn auth_failures_aggregate_per_ip_and_reason() {
    let cap = uc_audit::capture::start();
    let one = ip("2001:db8:5:2::1");
    // Another /64 (round 1: keys are the client /64, not the address).
    let two = ip("2001:db8:5:12::2");
    for _ in 0..50 {
        auth_failure("admin", one, AuthMethod::Password, "invalid_credentials");
    }
    // Same IP, different reason: its own key.
    auth_failure("unknown", one, AuthMethod::Jwt, "invalid_token");
    // Different IP, same reason: its own key.
    auth_failure("admin", two, AuthMethod::Password, "invalid_credentials");

    // Same /64, other address: same key, suppressed (round 1, SEC-002).
    auth_failure(
        "admin",
        ip("2001:db8:5:2::99"),
        AuthMethod::Password,
        "invalid_credentials",
    );
    let a = auth_events(&cap.events(), one);
    assert_eq!(a.len(), 2, "one record per (ip, reason) per window: {a:?}");
    assert!(auth_events(&cap.events(), ip("2001:db8:5:2::99")).is_empty());
    let reasons: Vec<_> = a
        .iter()
        .map(|e| e.failure_reason.clone().unwrap_or_default())
        .collect();
    assert!(reasons[0].starts_with("invalid_credentials"), "{reasons:?}");
    assert!(reasons[1].starts_with("invalid_token"), "{reasons:?}");
    assert!(a.iter().all(|e| !e.success));
    assert_eq!(a[0].method, AuthMethod::Password);
    assert_eq!(a[1].method, AuthMethod::Jwt);
    assert_eq!(auth_events(&cap.events(), two).len(), 1);
}
