//! SR-41 QA: Play concurrency caps (`crate::limits`).
//!
//! ## NIST 800-53 Rev5: SC-5

use std::net::IpAddr;

use crate::limits::{LimitRefusal, PlayLimits};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap_or(IpAddr::from([0, 0, 0, 0]))
}

#[test]
fn qa_global_cap_refuses_when_full() {
    let limits = PlayLimits::new(2, 2);
    let a = limits.try_acquire(ip("192.0.2.1"));
    let b = limits.try_acquire(ip("192.0.2.2"));
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(limits.active(), 2);
    assert_eq!(
        limits.try_acquire(ip("192.0.2.3")).err(),
        Some(LimitRefusal::Global)
    );
    // The refusal did not leak a slot.
    assert_eq!(limits.active(), 2);
    assert_eq!(limits.active_for(ip("192.0.2.3")), 0);
}

#[test]
fn qa_per_dest_cap_refuses_same_ip_other_port() {
    let limits = PlayLimits::new(8, 2);
    let _a = limits.try_acquire(ip("198.51.100.7"));
    let _b = limits.try_acquire(ip("198.51.100.7"));
    assert_eq!(limits.active_for(ip("198.51.100.7")), 2);
    // Keyed by IP: any port on the same address counts.
    assert_eq!(
        limits.try_acquire(ip("198.51.100.7")).err(),
        Some(LimitRefusal::PerDestination)
    );
    // The per-destination refusal released its global permit.
    assert_eq!(limits.active(), 2);
    // A v4-mapped form is the same destination.
    assert_eq!(
        limits.try_acquire(ip("::ffff:198.51.100.7")).err(),
        Some(LimitRefusal::PerDestination)
    );
    // Another address is unaffected.
    assert!(limits.try_acquire(ip("198.51.100.8")).is_ok());
}

#[test]
fn qa_guards_release_on_drop() {
    let limits = PlayLimits::new(1, 1);
    let g = limits.try_acquire(ip("203.0.113.5")).ok();
    assert!(g.is_some());
    assert!(limits.try_acquire(ip("203.0.113.6")).is_err());
    drop(g);
    assert_eq!(limits.active(), 0);
    assert_eq!(limits.active_for(ip("203.0.113.5")), 0);
    // Slot reusable, and the per-destination map does not keep stale keys
    // growing (bounded by the global cap).
    for i in 0..100u8 {
        let g = limits.try_acquire(IpAddr::from([203, 0, 113, i]));
        assert!(g.is_ok(), "iteration {i}");
    }
    assert_eq!(limits.tracked_destinations(), 0);
    // A guard moved into a task and dropped there releases too.
    let g = limits.try_acquire(ip("203.0.113.5")).ok();
    std::thread::spawn(move || drop(g))
        .join()
        .unwrap_or_default();
    assert_eq!(limits.active(), 0);
}
