//! `FileSink` chain resume across restarts and file modes, through the
//! global logger (own process).
//!
//! ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information)
#![allow(clippy::unwrap_used)]

mod common;

use common::ev;
use std::time::Duration;
use uc_audit::sink::{AuditSink, FileSink};

#[test]
fn global_logger_continues_chain_from_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit").join("audit.log");
    // A previous run left two chained records.
    {
        let sink = FileSink::open(&path).unwrap();
        let mut prev = [0u8; 48];
        for (seq, i) in [(0u64, 0usize), (1, 1)] {
            let r = uc_audit::AuditRecord::new(seq, ev(i), chrono::Utc::now(), prev);
            prev = r.hash_chain;
            sink.write(&r).unwrap();
        }
    }
    uc_audit::init_with_sink(Box::new(FileSink::open(&path).unwrap())).unwrap();
    for i in 2..5 {
        uc_audit::log_event(ev(i));
    }
    assert!(uc_audit::flush(Duration::from_secs(5)));
    let r = uc_audit::verify::verify_file(&path).unwrap();
    assert_eq!(r.records, 5);
    assert_eq!(r.first_sequence, Some(0));
    assert_eq!(r.last_sequence, Some(4));
    assert!(r.anchored);
    assert_eq!(r.drop_markers, 0);
}
