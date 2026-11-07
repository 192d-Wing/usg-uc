//! `flush()` with a full queue waits for the drain (own process).
#![allow(clippy::unwrap_used)]

mod common;

use common::{ev, install_gated};
use std::time::Duration;
use uc_audit::AUDIT_QUEUE_CAPACITY;

#[test]
fn flush_with_full_queue_waits_for_drain() {
    let (mem, gate) = install_gated();
    uc_audit::log_event(ev(0));
    gate.wait_blocked();
    for i in 1..=AUDIT_QUEUE_CAPACITY {
        uc_audit::log_event(ev(i));
    }
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        gate.release();
    });
    // Shutdown flush with a generous timeout must wait for the drain.
    assert!(uc_audit::flush(Duration::from_secs(10)));
    assert_eq!(mem.records().len(), AUDIT_QUEUE_CAPACITY + 1);
    assert_eq!(uc_audit::dropped_records(), 0);
}
