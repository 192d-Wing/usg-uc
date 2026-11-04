//! Queue-full behaviour of the global audit writer (own process: one global logger).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use uc_audit::event::SystemShutdown;
use uc_audit::sink::AuditSink;
use uc_audit::{AUDIT_QUEUE_CAPACITY, AuditEvent, AuditRecord};

/// Sink that blocks the writer on its first record until released.
struct Gated {
    mem: Arc<MemorySink>,
    gate: Arc<(Mutex<(bool, bool)>, Condvar)>, // (writer_blocked, released)
}

impl AuditSink for Gated {
    fn write(&self, record: &AuditRecord) {
        let (lock, cv) = &*self.gate;
        let mut g = lock.lock().unwrap();
        g.0 = true;
        cv.notify_all();
        while !g.1 {
            g = cv.wait(g).unwrap();
        }
        drop(g);
        self.mem.write(record);
    }
}

fn ev(i: usize) -> AuditEvent {
    AuditEvent::SystemShutdown(SystemShutdown {
        reason: format!("r{i}"),
        graceful: true,
    })
}

#[derive(Default)]
struct MemorySink(Mutex<Vec<AuditRecord>>);
impl MemorySink {
    fn new() -> Self {
        Self::default()
    }
    fn records(&self) -> Vec<AuditRecord> {
        self.0.lock().unwrap().clone()
    }
}
impl AuditSink for MemorySink {
    fn write(&self, record: &AuditRecord) {
        self.0.lock().unwrap().push(record.clone());
    }
}

#[test]
fn queue_full_drops_are_counted_and_chain_stays_contiguous() {
    let mem = Arc::new(MemorySink::new());
    let gate = Arc::new((Mutex::new((false, false)), Condvar::new()));
    uc_audit::init_with_sink(Box::new(Gated {
        mem: Arc::clone(&mem),
        gate: Arc::clone(&gate),
    }))
    .unwrap();

    // First record: writer dequeues it and blocks inside the sink.
    uc_audit::log_event(ev(0));
    {
        let (lock, cv) = &*gate;
        let mut g = lock.lock().unwrap();
        while !g.0 {
            g = cv.wait(g).unwrap();
        }
    }
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
    {
        let (lock, cv) = &*gate;
        lock.lock().unwrap().1 = true;
        cv.notify_all();
    }
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
