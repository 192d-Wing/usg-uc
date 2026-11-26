//! `file_sink_write`: writer-thread cost of one audit record on the file
//! sink (serialize, append, flush) and of building the chained record.
//! SR-42 rotation adds a length check per write and a rotation once per
//! `max_file_bytes`.
#![allow(missing_docs, clippy::unwrap_used)]

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use uc_audit::sink::{AuditSink, FileSink, FileSinkOptions};
use uc_audit::{AuditEvent, AuditRecord};

fn event(i: u64) -> AuditEvent {
    AuditEvent::SystemShutdown(uc_audit::event::SystemShutdown {
        reason: format!("bench-{i}"),
        graceful: true,
    })
}

fn bench(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    // Small files so the measurement includes rotations at their real rate
    // for 1 MiB files (about one per 3000 records).
    let sink = FileSink::open_with(
        dir.path().join("audit.log"),
        FileSinkOptions {
            max_file_bytes: 1024 * 1024,
            max_rotated_files: 4,
            ..FileSinkOptions::default()
        },
    )
    .unwrap();
    let mut seq = 0u64;
    let mut prev = [0u8; 48];
    c.bench_function("audit_record_build", |b| {
        b.iter(|| black_box(AuditRecord::new(1, event(1), chrono::Utc::now(), [0u8; 48])));
    });
    c.bench_function("audit_file_sink_write", |b| {
        b.iter(|| {
            let r = AuditRecord::new(seq, event(seq), chrono::Utc::now(), prev);
            prev = r.hash_chain;
            seq += 1;
            sink.write(black_box(&r)).unwrap();
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
