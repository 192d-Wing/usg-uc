//! Queue-full behaviour of the global audit writer (own process: one global logger).
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use common::{ev, install_gated};
use std::time::Duration;
use uc_audit::{AUDIT_QUEUE_CAPACITY, AuditEvent};

#[test]
fn queue_full_drops_are_counted_and_chain_stays_contiguous() {
    let (mem, gate) = install_gated();

    // First record: writer dequeues it and blocks inside the sink.
    uc_audit::log_event(ev(0));
    gate.wait_blocked();
    // Fill the queue exactly, then overflow by 10. log_event must not block.
    let start = std::time::Instant::now();
    for i in 1..=AUDIT_QUEUE_CAPACITY + 10 {
        uc_audit::log_event(ev(i));
    }
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "log_event blocked"
    );
    assert_eq!(uc_audit::dropped_records(), 10);

    // Release the writer and drain.
    gate.release();
    // flush() waits for room for its marker, then for the drain.
    assert!(
        uc_audit::flush(Duration::from_secs(10)),
        "queue never drained"
    );
    let records = mem.records();
    // Failed flush markers may have counted as drops? They must not.
    assert_eq!(records.len(), AUDIT_QUEUE_CAPACITY + 1);
    let mut prev = [0u8; 48];
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.sequence, i as u64, "sequence gap at {i}");
        assert!(r.verify(&prev), "chain broken at {i}");
        prev = r.hash_chain;
        match &r.event {
            AuditEvent::SystemShutdown(e) => assert_eq!(e.reason, format!("r{i}")),
            other => panic!("unexpected {other:?}"),
        }
    }
    // Dropped records leave no hole: later records still chain.
    uc_audit::log_event(ev(99_999));
    assert!(uc_audit::flush(Duration::from_secs(5)));
    let records = mem.records();
    let last = records.last().unwrap();
    assert_eq!(last.sequence, (AUDIT_QUEUE_CAPACITY + 1) as u64);
    assert!(last.verify(&records[records.len() - 2].hash_chain));
    assert_eq!(uc_audit::dropped_records(), 10);
}
