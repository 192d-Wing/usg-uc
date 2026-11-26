//! SR-40: the auth-failure key table is bounded. Its own test binary,
//! because filling the process-global table would starve other tests.
//!
//! ## NIST 800-53 Rev5: AU-4, AU-5, SC-5

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use sbc_http_util::mgmt_audit::{auth_failure, budget_suppressed, flush_auth_failures};
use uc_audit::AuditEvent;
use uc_audit::aggregate::MAX_KEYS;
use uc_audit::event::AuthMethod;

/// The n-th distinct client /64 (keys are per /64 since round 1).
fn nth(n: usize) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(
        0x2001,
        0xdb8,
        u16::try_from(n >> 16).unwrap(),
        u16::try_from(n & 0xffff).unwrap(),
        0,
        0,
        0,
        1,
    ))
}

#[test]
fn auth_failure_key_cap_counts_drops() {
    let cap = uc_audit::capture::start();
    for i in 0..MAX_KEYS {
        auth_failure("unknown", nth(i), AuthMethod::Jwt, "invalid_token");
    }
    let auth = |evs: &[AuditEvent]| {
        evs.iter()
            .filter(|e| matches!(e, AuditEvent::AuthenticationAttempt(_)))
            .count()
    };
    // Every key is tracked; first emissions past the process-wide budget
    // (round 2, SEC-008) are suppressed and counted, not emitted.
    let over_budget = usize::try_from(budget_suppressed()).unwrap();
    assert!(
        over_budget > 0,
        "4096 first emissions exceed one second's budget"
    );
    assert_eq!(auth(&cap.events()), MAX_KEYS - over_budget);

    // Table full of live keys: three new sources are dropped, not emitted.
    for i in 0..3 {
        auth_failure(
            "unknown",
            nth(MAX_KEYS + i),
            AuthMethod::Jwt,
            "invalid_token",
        );
    }
    assert_eq!(
        auth(&cap.events()),
        MAX_KEYS - over_budget,
        "no record past the cap"
    );
    assert_eq!(usize::try_from(budget_suppressed()).unwrap(), over_budget);

    // The periodic flush reports the drop delta as an audit record.
    flush_auth_failures(Instant::now() + Duration::from_secs(61));
    let dropped: Vec<u64> = cap
        .events()
        .iter()
        .filter_map(|e| match e {
            AuditEvent::AuditRecordsDropped(d) => Some(d.count),
            _ => None,
        })
        .collect();
    assert_eq!(
        dropped,
        vec![3 + budget_suppressed()],
        "one marker: table drops plus budget suppressions"
    );

    // Delta, not total: a second flush reports nothing new.
    flush_auth_failures(Instant::now() + Duration::from_secs(122));
    let markers = cap
        .events()
        .iter()
        .filter(|e| matches!(e, AuditEvent::AuditRecordsDropped(_)))
        .count();
    assert_eq!(markers, 1);
}
