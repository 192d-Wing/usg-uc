//! SR-42 (QA-first): `overwrite_oldest` (decision a) counts rotations and
//! capacity deletions in `AuditStats` and chains an `AuditFileDeleted`
//! record per dropped file, through the global logger (own process).
//!
//! ## NIST 800-53 Rev5: AU-4, AU-5 (alert on capacity), SI-4
#![allow(clippy::unwrap_used)]

mod common;

use common::ev;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uc_audit::sink::{CapacityAction, FileSink, FileSinkOptions};
use uc_audit::{AuditEvent, AuditRecord};

fn rotated(path: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix("audit.log."))
                .is_some_and(|d| d.len() == 20 && d.bytes().all(|b| b.is_ascii_digit()))
        })
        .collect();
    v.sort();
    v
}

#[test]
fn capacity_stats_count_rotations_and_deletions() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sink = FileSink::open_with(
        &path,
        FileSinkOptions {
            max_file_bytes: 2048,
            max_rotated_files: 2,
            on_full: CapacityAction::OverwriteOldest,
        },
    )
    .unwrap();
    uc_audit::init_with_sink(Box::new(sink)).unwrap();
    assert_eq!(uc_audit::stats().rotations, 0);
    for i in 0..80 {
        uc_audit::log_event(ev(i));
    }
    assert!(uc_audit::flush(Duration::from_secs(5)));

    let kept = rotated(&path);
    assert_eq!(kept.len(), 2);
    let s = uc_audit::stats();
    assert!(s.rotations >= 4, "{s:?}");
    assert_eq!(s.capacity_deletions, s.rotations - 2, "{s:?}");
    assert!(!s.capacity_halted);
    assert_eq!(s.dropped, 0);
    assert!(!uc_audit::sink_failing());

    // The deletions are themselves chained (AU-5 alert in the trail).
    let mut files = kept;
    files.push(path);
    let deleted: Vec<(String, String)> = files
        .iter()
        .flat_map(|p| {
            std::fs::read_to_string(p)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str::<AuditRecord>(l).unwrap())
                .collect::<Vec<_>>()
        })
        .filter_map(|r| match r.event {
            AuditEvent::AuditFileDeleted(d) => Some((d.file, d.reason)),
            _ => None,
        })
        .collect();
    assert_ne!(deleted, []);
    for (file, reason) in &deleted {
        assert_eq!(reason, "capacity");
        assert!(!Path::new(file).exists(), "{file}");
    }
}
