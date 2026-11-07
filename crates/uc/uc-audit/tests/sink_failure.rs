//! A failing sink is visible and leaves no chain gap (own process: one
//! global logger).
//!
//! ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use common::{MemorySink, ev};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use uc_audit::sink::AuditSink;
use uc_audit::{AuditDropReason, AuditEvent, AuditRecord};

/// Fails while `failures` > 0 (e.g. ENOSPC), then persists.
struct Flaky {
    mem: Arc<MemorySink>,
    failures: Arc<AtomicU32>,
}

impl AuditSink for Flaky {
    fn write(&self, record: &AuditRecord) -> std::io::Result<()> {
        let left = self.failures.load(Ordering::Relaxed);
        if left > 0 {
            self.failures.store(left - 1, Ordering::Relaxed);
            return Err(std::io::Error::other("No space left on device"));
        }
        self.mem.write(record)
    }
}

#[test]
fn failing_sink_is_unhealthy_counted_and_marked_in_chain() {
    let mem = Arc::new(MemorySink::default());
    let failures = Arc::new(AtomicU32::new(0));
    uc_audit::init_with_sink(Box::new(Flaky {
        mem: Arc::clone(&mem),
        failures: Arc::clone(&failures),
    }))
    .unwrap();
    uc_audit::log_event(ev(0));
    assert!(uc_audit::flush(Duration::from_secs(5)));
    assert!(!uc_audit::sink_failing());

    // Disk full: every write (records and retried markers) fails.
    failures.store(1_000, Ordering::Relaxed);
    for i in 1..=3 {
        uc_audit::log_event(ev(i));
    }
    assert!(uc_audit::flush(Duration::from_secs(5)));
    let s = uc_audit::stats();
    assert!(s.sink_failing, "{s:?}");
    assert!(s.writer_alive);
    assert_eq!(s.write_failures, 3);
    assert_eq!(s.queue_drops, 0);
    assert_eq!(uc_audit::dropped_records(), 3);
    assert_eq!(uc_audit::write_failures(), 3);
    assert!(s.last_write_failure.is_some());
    assert!(s.last_drop.is_some());

    failures.store(0, Ordering::Relaxed);
    // Recovery: the next write clears the failure; the marker follows it.
    uc_audit::log_event(ev(4));
    assert!(uc_audit::flush(Duration::from_secs(5)));
    assert!(!uc_audit::sink_failing());
    let records = mem.records();
    assert_eq!(records.len(), 3, "r0, r4, marker");
    let mut prev = [0u8; 48];
    for (i, r) in records.iter().enumerate() {
        assert_eq!(r.sequence, i as u64);
        assert!(r.verify(&prev), "chain broken at {i}");
        prev = r.hash_chain;
    }
    match &records[2].event {
        AuditEvent::AuditRecordsDropped(m) => {
            assert_eq!(m.reason, AuditDropReason::SinkWriteFailed);
            assert_eq!(m.count, 3);
            assert_eq!(m.total, 3);
        }
        other => panic!("expected marker, got {other:?}"),
    }
    // Timestamps are taken by the writer, in sequence order (AU-8).
    assert!(records.windows(2).all(|w| w[0].timestamp <= w[1].timestamp));
}
