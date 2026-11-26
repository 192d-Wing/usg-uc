//! SR-40: aggregated auth failures are carried by the periodic flush. Its
//! own test binary: `flush_auth_failures` at a future instant closes every
//! key in the process-global aggregator, which would re-open the windows
//! of tests running in parallel in the same binary.
//!
//! ## NIST 800-53 Rev5: AU-2, AU-3, AC-7, SC-5

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::time::{Duration, Instant};

use sbc_http_util::mgmt_audit::{auth_failure, flush_auth_failures};
use uc_audit::AuditEvent;
use uc_audit::event::{AuthMethod, AuthenticationAttempt};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
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

#[test]
fn auth_failure_flush_carries_suppressed_count() {
    let cap = uc_audit::capture::start();
    let from = ip("2001:db8:5:3::1");
    for _ in 0..7 {
        auth_failure("admin", from, AuthMethod::Password, "rate_limited");
    }
    assert_eq!(auth_events(&cap.events(), from).len(), 1);

    // Window still open: nothing for this key.
    flush_auth_failures(Instant::now());
    assert_eq!(auth_events(&cap.events(), from).len(), 1);

    flush_auth_failures(Instant::now() + Duration::from_secs(61));
    let a = auth_events(&cap.events(), from);
    assert_eq!(a.len(), 2, "{a:?}");
    let r = a[1].failure_reason.clone().unwrap_or_default();
    assert!(r.starts_with("rate_limited"), "{r}");
    assert!(r.ends_with("count=6"), "suppressed count carried: {r}");
    assert!(!a[1].success);

    // Flushed: nothing more is owed.
    flush_auth_failures(Instant::now() + Duration::from_secs(122));
    assert_eq!(auth_events(&cap.events(), from).len(), 2);
}
