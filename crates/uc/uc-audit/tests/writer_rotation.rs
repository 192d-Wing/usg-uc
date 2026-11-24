//! SR-42 (QA-first): the writer chains an `AuditFileRotated` record as the
//! first record of each new file, through the global logger (own process).
//!
//! ## NIST 800-53 Rev5: AU-4, AU-9 (chain continuity across rotation)
#![allow(clippy::unwrap_used)]

mod common;

use common::ev;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uc_audit::sink::{CapacityAction, FileSink, FileSinkOptions};
use uc_audit::{AuditEvent, AuditRecord};

fn records(p: &Path) -> Vec<AuditRecord> {
    std::fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// `audit.log.<20 digits>` files oldest first, then `audit.log`.
fn set_paths(path: &Path) -> Vec<PathBuf> {
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
    v.push(path.to_path_buf());
    v
}

#[test]
fn writer_chains_rotated_record_first_in_new_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    let sink = FileSink::open_with(
        &path,
        FileSinkOptions {
            max_file_bytes: 2048,
            max_rotated_files: 64,
            on_full: CapacityAction::OverwriteOldest,
        },
    )
    .unwrap();
    uc_audit::init_with_sink(Box::new(sink)).unwrap();
    for i in 0..40 {
        uc_audit::log_event(ev(i));
    }
    assert!(uc_audit::flush(Duration::from_secs(5)));

    let files = set_paths(&path);
    assert!(files.len() >= 3, "{files:?}");
    let refs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
    let reports = uc_audit::verify::verify_files(&refs).unwrap();
    assert!(reports.iter().all(|r| r.anchored), "{reports:?}");

    for (prev, cur) in files.iter().zip(&files[1..]) {
        let first = records(cur).into_iter().next().unwrap();
        assert!(
            matches!(first.event, AuditEvent::AuditFileRotated(_)),
            "{} starts with {:?}",
            cur.display(),
            first.event
        );
        let AuditEvent::AuditFileRotated(r) = &first.event else {
            continue;
        };
        assert_eq!(Path::new(&r.file), prev.as_path());
        let bytes = std::fs::read(prev).unwrap();
        assert_eq!(r.sha384, hex::encode(uc_crypto::hash::sha384(&bytes)));
        let last = records(prev).last().unwrap().sequence;
        assert_eq!(r.last_sequence, last);
        assert_eq!(first.sequence, last + 1);
    }

    // Every logged event is on disk once, in order.
    let ours: Vec<String> = files
        .iter()
        .flat_map(|p| records(p))
        .filter_map(|r| match r.event {
            AuditEvent::SystemShutdown(e) => Some(e.reason),
            _ => None,
        })
        .collect();
    let want: Vec<String> = (0..40).map(|i| format!("r{i}")).collect();
    assert_eq!(ours, want);
    let stats = uc_audit::stats();
    assert_eq!(stats.rotations, (files.len() - 1) as u64);
    assert_eq!(stats.dropped, 0);
}
