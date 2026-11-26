//! SR-42 (QA-first): `stop` mode marks the pipeline halted and failing
//! (AU-5) without deleting audit files, and the writer counts the refused
//! records, through the global logger (own process).
//!
//! ## NIST 800-53 Rev5: AU-5 (Response to Audit Logging Process Failures)
#![allow(clippy::unwrap_used)]

mod common;

use common::ev;
use std::time::Duration;
use uc_audit::sink::{CapacityAction, FileSink, FileSinkOptions};

#[test]
fn stop_mode_sets_capacity_halted_and_counts_refused_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sink = FileSink::open_with(
        &path,
        FileSinkOptions {
            max_file_bytes: 2048,
            max_rotated_files: 1,
            on_full: CapacityAction::Stop,
        },
    )
    .unwrap();
    uc_audit::init_with_sink(Box::new(sink)).unwrap();
    for i in 0..60 {
        uc_audit::log_event(ev(i));
    }
    assert!(uc_audit::flush(Duration::from_secs(5)));
    let s = uc_audit::stats();
    assert!(s.capacity_halted, "{s:?}");
    assert!(uc_audit::sink_failing());
    assert!(s.write_failures > 0, "{s:?}");
    assert_eq!(s.capacity_deletions, 0);
    assert!(path.exists());
}
