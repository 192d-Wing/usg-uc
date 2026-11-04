//! Shared harness for the global-writer integration tests. Each test file is
//! its own process, so each can install the one global logger.
#![allow(dead_code, clippy::unwrap_used)]

use std::sync::{Arc, Condvar, Mutex};
use uc_audit::event::SystemShutdown;
use uc_audit::sink::AuditSink;
use uc_audit::{AuditEvent, AuditRecord};

/// A numbered event whose `reason` (`r{i}`) identifies it in the output.
pub fn ev(i: usize) -> AuditEvent {
    AuditEvent::SystemShutdown(SystemShutdown {
        reason: format!("r{i}"),
        graceful: true,
    })
}

/// Sink that keeps every record it is given.
#[derive(Default)]
pub struct MemorySink(Mutex<Vec<AuditRecord>>);

impl MemorySink {
    pub fn records(&self) -> Vec<AuditRecord> {
        self.0.lock().unwrap().clone()
    }
}

impl AuditSink for MemorySink {
    fn write(&self, record: &AuditRecord) {
        self.0.lock().unwrap().push(record.clone());
    }
}

/// Forwards to a shared [`MemorySink`] the test can still read.
pub struct Shared(pub Arc<MemorySink>);

impl AuditSink for Shared {
    fn write(&self, record: &AuditRecord) {
        self.0.write(record);
    }
}

/// `(writer_blocked, released)` plus the condvar both sides wait on.
type GateState = Arc<(Mutex<(bool, bool)>, Condvar)>;

/// Sink that blocks the writer on its first record until [`Gate::release`].
pub struct Gated {
    mem: Arc<MemorySink>,
    gate: GateState,
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

/// Test-side handle on a [`Gated`] sink.
#[derive(Clone)]
pub struct Gate(GateState);

impl Gate {
    /// Waits until the writer is blocked inside the sink.
    pub fn wait_blocked(&self) {
        let (lock, cv) = &*self.0;
        drop(cv.wait_while(lock.lock().unwrap(), |g| !g.0).unwrap());
    }

    /// Lets the writer continue.
    pub fn release(&self) {
        let (lock, cv) = &*self.0;
        lock.lock().unwrap().1 = true;
        cv.notify_all();
    }
}

/// Installs a gated global logger and returns its records and gate.
pub fn install_gated() -> (Arc<MemorySink>, Gate) {
    let mem = Arc::new(MemorySink::default());
    let gate: GateState = Arc::new((Mutex::new((false, false)), Condvar::new()));
    uc_audit::init_with_sink(Box::new(Gated {
        mem: Arc::clone(&mem),
        gate: Arc::clone(&gate),
    }))
    .unwrap();
    (mem, Gate(gate))
}
