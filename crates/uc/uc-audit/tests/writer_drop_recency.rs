//! Drop recency for AU-5 health recovery (own process: one global logger).
#![allow(clippy::unwrap_used)]

mod common;

use common::{ev, install_gated};
use std::time::Duration;
use uc_audit::AUDIT_QUEUE_CAPACITY;

#[test]
fn last_drop_elapsed_tracks_recent_drops_and_counter_stays_monotonic() {
    let (_mem, gate) = install_gated();
    assert_eq!(uc_audit::last_drop_elapsed(), None);

    uc_audit::log_event(ev(0));
    gate.wait_blocked();
    for i in 1..=AUDIT_QUEUE_CAPACITY + 3 {
        uc_audit::log_event(ev(i));
    }
    assert_eq!(uc_audit::dropped_records(), 3);
    let first = uc_audit::last_drop_elapsed().unwrap();
    assert!(first < Duration::from_secs(1), "drop not recent: {first:?}");

    gate.release();
    assert!(uc_audit::flush(Duration::from_secs(10)));
    std::thread::sleep(Duration::from_millis(20));
    // Elapsed grows once drops stop; the cumulative counter never resets.
    assert!(uc_audit::last_drop_elapsed().unwrap() >= first);
    assert_eq!(uc_audit::dropped_records(), 3);
}
