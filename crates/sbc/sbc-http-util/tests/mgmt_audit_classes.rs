//! SR-40 round 1: bad-bearer noise cannot evict login-failure keys
//! (separate bounded tables per class), one flush emits at most
//! `MAX_FLUSH_RECORDS`, and a write refused before authorization is
//! recorded once per client /64 and window. Its own binary: it fills the
//! process-global tables.
//!
//! ## NIST 800-53 Rev5: AU-2, AU-5, AC-7, SC-5

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use http::StatusCode;
use sbc_http_util::mgmt_audit::{
    MAX_FLUSH_RECORDS, Op, auth_failure, flush_auth_failures, rejected_write,
};
use uc_audit::AuditEvent;
use uc_audit::aggregate::MAX_KEYS;
use uc_audit::event::AuthMethod;

/// The n-th distinct /64 under a per-test prefix.
fn nth(prefix: u16, n: usize) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(
        0x2001,
        0xdb8,
        prefix,
        u16::try_from(n).unwrap(),
        0,
        0,
        0,
        1,
    ))
}

/// Waits out the first-emission budget (one second's burst).
fn refill() {
    std::thread::sleep(Duration::from_millis(1100));
}

fn auth_from(events: &[AuditEvent], from: IpAddr) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, AuditEvent::AuthenticationAttempt(a) if a.source_ip == from))
        .count()
}

#[test]
fn classes_are_isolated_flush_is_bounded_and_rejected_writes_aggregate() {
    let cap = uc_audit::capture::start();

    // Fill the token table with live keys.
    for i in 0..MAX_KEYS {
        auth_failure("unknown", nth(0x10, i), AuthMethod::Jwt, "invalid_token");
    }
    let past = nth(0x11, 0);
    auth_failure("unknown", past, AuthMethod::Jwt, "invalid_token");
    assert_eq!(auth_from(&cap.events(), past), 0, "token table full");
    // Filling the table spent the process-wide first-emission budget
    // (round 2, SEC-008); let it refill.
    refill();

    // A wrong password from a new source is still recorded.
    let login = nth(0x12, 0);
    auth_failure("admin", login, AuthMethod::Password, "invalid_credentials");
    assert_eq!(auth_from(&cap.events(), login), 1, "own table");
    auth_failure("unknown", login, AuthMethod::Password, "rate_limited");
    assert_eq!(
        auth_from(&cap.events(), login),
        2,
        "lockout has its own table"
    );

    // More suppressed keys than one flush may emit.
    let n = MAX_FLUSH_RECORDS + 40;
    for i in 0..n {
        let from = nth(0x13, i);
        auth_failure("admin", from, AuthMethod::Password, "invalid_credentials");
        auth_failure("admin", from, AuthMethod::Password, "invalid_credentials");
    }
    let counted = |evs: &[AuditEvent]| {
        evs.iter()
            .filter(|e| {
                matches!(e, AuditEvent::AuthenticationAttempt(a)
                    if a.failure_reason.as_deref().is_some_and(|r| r.ends_with("count=1")))
            })
            .count()
    };
    let later = Instant::now() + Duration::from_secs(61);
    flush_auth_failures(later);
    assert_eq!(counted(&cap.events()), MAX_FLUSH_RECORDS, "capped");
    flush_auth_failures(later);
    assert_eq!(counted(&cap.events()), n, "the rest stayed pending");

    // A write refused before authorization: one record per /64 and window.
    let changes = |evs: &[AuditEvent]| {
        evs.iter()
            .filter_map(|e| match e {
                AuditEvent::ConfigurationChange(c) if c.admin == "unauthenticated" => {
                    Some(c.description.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    refill();
    let w = nth(0x14, 0);
    for _ in 0..5 {
        rejected_write(
            w,
            "phone",
            Op::Update,
            Some("MUHJ"),
            StatusCode::BAD_REQUEST,
        );
    }
    let c = changes(&cap.events());
    assert_eq!(c.len(), 1, "{c:?}");
    assert!(c[0].starts_with("entity=phone id=- op=update outcome=failed reason=invalid"));
    assert!(
        c[0].contains("site=MUHJ") && c[0].contains("status=400"),
        "{}",
        c[0]
    );
    flush_auth_failures(Instant::now() + Duration::from_secs(122));
    let c = changes(&cap.events());
    assert_eq!(c.len(), 2, "{c:?}");
    assert!(
        c[1].contains("count=4") && c[1].contains("last_entity=phone"),
        "{}",
        c[1]
    );
}
