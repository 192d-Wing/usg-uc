//! Many concurrent writers into the global audit writer (own process).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::significant_drop_tightening
)]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use uc_audit::event::SystemShutdown;
use uc_audit::sink::AuditSink;
use uc_audit::{AuditEvent, AuditRecord};

struct Shared(Arc<MemorySink>);
impl AuditSink for Shared {
    fn write(&self, record: &AuditRecord) {
        self.0.write(record);
    }
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
fn concurrent_writers_keep_contiguous_verified_chain_and_flush_drains() {
    const THREADS: usize = 16;
    const PER: usize = 200; // 3200 < AUDIT_QUEUE_CAPACITY, so nothing may drop
    let mem = Arc::new(MemorySink::new());
    uc_audit::init_with_sink(Box::new(Shared(Arc::clone(&mem)))).unwrap();

    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            std::thread::spawn(move || {
                for i in 0..PER {
                    uc_audit::log_event(AuditEvent::SystemShutdown(SystemShutdown {
                        reason: format!("t{t}-{i}"),
                        graceful: true,
                    }));
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    // Shutdown-style flush drains everything queued.
    assert!(uc_audit::flush(Duration::from_secs(10)));
    let records = mem.records();
    assert_eq!(records.len(), THREADS * PER);
    assert_eq!(uc_audit::dropped_records(), 0);

    let mut prev = [0u8; 48];
    let mut seen = HashSet::new();
    let mut last_per_thread = vec![None::<usize>; THREADS];
    for (n, r) in records.iter().enumerate() {
        assert_eq!(r.sequence, n as u64);
        assert!(r.verify(&prev), "chain broken at {n}");
        prev = r.hash_chain;
        let AuditEvent::SystemShutdown(e) = &r.event else {
            panic!("unexpected event");
        };
        assert!(seen.insert(e.reason.clone()), "duplicate {}", e.reason);
        let (t, i) = e.reason[1..].split_once('-').unwrap();
        let (t, i): (usize, usize) = (t.parse().unwrap(), i.parse().unwrap());
        // Per-producer order is preserved.
        assert!(last_per_thread[t].is_none_or(|p| p < i));
        last_per_thread[t] = Some(i);
    }
    // Tampering is detected by the chain verification.
    let mut bad = records[5].clone();
    if let AuditEvent::SystemShutdown(e) = &mut bad.event {
        e.reason.push('x');
    }
    assert!(!bad.verify(&records[4].hash_chain));
}
