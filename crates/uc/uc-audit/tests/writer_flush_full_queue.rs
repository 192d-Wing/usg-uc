//! `flush()` with a full queue waits for the drain (own process).
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
fn flush_with_full_queue_waits_for_drain() {
    let mem = Arc::new(MemorySink::new());
    let gate = Arc::new((Mutex::new((false, false)), Condvar::new()));
    uc_audit::init_with_sink(Box::new(Gated {
        mem: Arc::clone(&mem),
        gate: Arc::clone(&gate),
    }))
    .unwrap();
    uc_audit::log_event(ev(0));
    {
        let (lock, cv) = &*gate;
        let mut g = lock.lock().unwrap();
        while !g.0 {
            g = cv.wait(g).unwrap();
        }
    }
    for i in 1..=AUDIT_QUEUE_CAPACITY {
        uc_audit::log_event(ev(i));
    }
    let g2 = Arc::clone(&gate);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        let (lock, cv) = &*g2;
        lock.lock().unwrap().1 = true;
        cv.notify_all();
    });
    // Shutdown flush with a generous timeout must wait for the drain.
    assert!(uc_audit::flush(Duration::from_secs(10)));
    assert_eq!(mem.records().len(), AUDIT_QUEUE_CAPACITY + 1);
}
