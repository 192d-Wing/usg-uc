//! SR-40: the failure aggregator lives in uc-audit so the management APIs
//! can bound auth-failure audit volume without depending on uc-sti.

#![allow(clippy::unwrap_used)]

use std::time::{Duration, Instant};

use uc_audit::aggregate::{FailureAggregator, MAX_KEYS, Pending, Seen};

#[test]
fn aggregator_is_exported_from_uc_audit() {
    let a = FailureAggregator::new(Duration::from_secs(60));
    let t0 = Instant::now();
    let seen = Seen {
        source_ip: Some(std::net::IpAddr::from([192, 0, 2, 9])),
        call_id_hash: "",
    };
    assert_eq!(
        a.record_seen("192.0.2.9", "invalid_credentials", t0, seen),
        Some(1)
    );
    assert_eq!(
        a.record_seen("192.0.2.9", "invalid_credentials", t0, seen),
        None
    );
    let p: Vec<Pending> = a.flush(t0 + Duration::from_secs(61));
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].count, 1);
    assert_eq!(MAX_KEYS, 4096);
}
