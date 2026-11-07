//! A dead writer thread is visible (own process: one global logger).
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use common::ev;
use std::time::{Duration, Instant};
use uc_audit::AuditRecord;
use uc_audit::sink::AuditSink;

/// Sink whose first write panics, killing the writer thread.
struct Panicking;

impl AuditSink for Panicking {
    fn write(&self, _record: &AuditRecord) -> std::io::Result<()> {
        panic!("simulated sink failure");
    }
}

#[test]
fn dead_writer_is_reported_and_drops_are_counted() {
    assert!(uc_audit::writer_alive(), "no logger yet: nothing failed");
    uc_audit::init_with_sink(Box::new(Panicking)).unwrap();
    assert!(uc_audit::writer_alive());
    uc_audit::log_event(ev(0));
    let deadline = Instant::now() + Duration::from_secs(5);
    while uc_audit::writer_alive() {
        assert!(Instant::now() < deadline, "writer death not detected");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(uc_audit::dropped_records(), 0);
    for i in 1..=3 {
        uc_audit::log_event(ev(i));
    }
    assert_eq!(uc_audit::dropped_records(), 3);
    // A flush cannot succeed against a dead writer, and returns at once.
    let start = Instant::now();
    assert!(!uc_audit::flush(Duration::from_secs(5)));
    assert!(start.elapsed() < Duration::from_secs(1));
}
