//! SR-40 round 2: each class gets a minimum share of one flush (SEC-009),
//! and first emissions past the process-wide budget are suppressed and
//! counted, then reported by the flush (SEC-008). Its own binary: it fills
//! the process-global tables and budget.
//!
//! ## NIST 800-53 Rev5: AU-4, AU-5, SC-5

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use sbc_http_util::mgmt_audit::{
    MAX_FIRST_EMISSIONS_PER_SEC, MAX_FLUSH_RECORDS, auth_failure, budget_suppressed,
    flush_auth_failures,
};
use uc_audit::AuditEvent;
use uc_audit::event::AuthMethod;

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

/// Flushed records (`count=1`) per reason prefix.
fn flushed(events: &[AuditEvent], reason: &str) -> usize {
    events
        .iter()
        .filter(|e| {
            matches!(e, AuditEvent::AuthenticationAttempt(a)
                if a.failure_reason.as_deref() == Some(&format!("{reason} count=1")))
        })
        .count()
}

fn firsts(events: &[AuditEvent]) -> usize {
    events
        .iter()
        .filter(|e| {
            matches!(e, AuditEvent::AuthenticationAttempt(a)
                if a.failure_reason.as_deref().is_some_and(|r| !r.contains("count=")))
        })
        .count()
}

#[test]
fn flush_shares_and_first_emission_budget() {
    let cap = uc_audit::capture::start();
    let per_class = 300;
    let start = Instant::now();
    for i in 0..per_class {
        for _ in 0..2 {
            auth_failure(
                "admin",
                nth(0x20, i),
                AuthMethod::Password,
                "invalid_credentials",
            );
            auth_failure("unknown", nth(0x21, i), AuthMethod::Jwt, "invalid_token");
        }
    }
    let elapsed = start.elapsed();

    // 600 first emissions: one second's burst (plus any refill while the
    // loop ran) is emitted, the rest suppressed and counted, none queued.
    let emitted = firsts(&cap.events());
    let suppressed = usize::try_from(budget_suppressed()).unwrap();
    assert_eq!(emitted + suppressed, 2 * per_class);
    let refill =
        usize::try_from(elapsed.as_millis() * u128::from(MAX_FIRST_EMISSIONS_PER_SEC) / 1000 + 1)
            .unwrap();
    let burst = usize::try_from(MAX_FIRST_EMISSIONS_PER_SEC).unwrap();
    assert!(emitted >= burst && emitted <= burst + refill, "{emitted}");

    // One flush: the token class still gets its minimum share, though the
    // credentials class alone could fill the whole flush.
    let later = Instant::now() + Duration::from_secs(61);
    flush_auth_failures(later);
    let share = MAX_FLUSH_RECORDS / 5;
    let ev = cap.events();
    assert_eq!(flushed(&ev, "invalid_token"), share);
    assert_eq!(
        flushed(&ev, "invalid_credentials"),
        MAX_FLUSH_RECORDS - share,
        "the unused shares are passed on"
    );
    let dropped: Vec<u64> = ev
        .iter()
        .filter_map(|e| match e {
            AuditEvent::AuditRecordsDropped(d) => Some(d.count),
            _ => None,
        })
        .collect();
    assert_eq!(dropped, vec![budget_suppressed()], "suppressions reported");

    // Later flushes drain the rest, still capped.
    flush_auth_failures(later);
    let total =
        |ev: &[AuditEvent]| flushed(ev, "invalid_token") + flushed(ev, "invalid_credentials");
    assert_eq!(total(&cap.events()), 2 * MAX_FLUSH_RECORDS);
    flush_auth_failures(later);
    assert_eq!(total(&cap.events()), 2 * per_class);
}
