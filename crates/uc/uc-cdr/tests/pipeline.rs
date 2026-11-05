//! QA: end-to-end CDR pipeline tests through the public `uc-cdr` API
//! (emitter -> writer thread -> file / syslog / ring -> verify).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use uc_cdr::{
    CallRecord, CdrEmitter, CdrEmitterConfig, CdrFilter, CdrFormat, CdrHealth, CdrObserver,
    CdrSink, Direction, Disposition, FileSinkConfig, HmacKey, PiiPolicy, ReleaseCause, ReleaseSide,
    SyslogConnector, SyslogSink, SyslogSinkConfig, Transport, TrunkAttempt, TrunkOutcome,
    verify_files, verify_sidecar,
};

const T: Duration = Duration::from_secs(10);

fn file_cfg(dir: &Path) -> FileSinkConfig {
    FileSinkConfig {
        directory: dir.to_path_buf(),
        rotate_interval: None,
        fsync_interval: Duration::ZERO,
        retention_files: 0,
        retention_days: 0,
        ..FileSinkConfig::default()
    }
}

fn emitter(dir: &Path, f: impl FnOnce(&mut CdrEmitterConfig)) -> Arc<CdrEmitter> {
    let mut c = CdrEmitterConfig {
        node_id: "qa-node".into(),
        file: Some(file_cfg(dir)),
        ..CdrEmitterConfig::default()
    };
    f(&mut c);
    CdrEmitter::start(c, Vec::new(), None).unwrap()
}

fn answered() -> CallRecord {
    let mut r = CallRecord {
        a_call_id: "a-1@10.0.0.1".into(),
        b_call_ids: vec!["b-1".into(), "b-2".into()],
        internal_call_id: "int-1".into(),
        direction: Direction::Outbound,
        caller: "+12025550100".into(),
        callee_dialed: "9112".into(),
        callee_translated: Some("+12025550199".into()),
        caller_translated: Some("2025550100".into()),
        source_ip: "10.0.0.1".into(),
        source_port: 5061,
        transport: Transport::Tls,
        ingress_zone: Some("inside".into()),
        egress_zone: Some("outside".into()),
        trunk_group: Some("pstn".into()),
        trunks_tried: vec![
            TrunkAttempt {
                trunk_id: "t1".into(),
                status: TrunkOutcome::Status(503),
                at_ms: 1_000_050,
            },
            TrunkAttempt {
                trunk_id: "t2".into(),
                status: TrunkOutcome::Status(200),
                at_ms: 1_000_300,
            },
        ],
        final_trunk: Some("t2".into()),
        failover_count: 1,
        setup_ms: 1_000_000,
        ring_ms: Some(1_000_400),
        answer_ms: Some(1_002_000),
        end_ms: 1_062_000,
        disposition: Disposition::Answered,
        final_sip_status: 200,
        release_side: ReleaseSide::Caller,
        release_cause: ReleaseCause::Normal,
        media_node: Some("rtpengine-1".into()),
        media_anchored: true,
        codec: Some("PCMU".into()),
        srtp: Some("AES_256_GCM".into()),
        emergency: true,
        ..Default::default()
    };
    r.compute_durations();
    r
}

fn cdr_files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl" || e == "csv"))
        .collect();
    v.sort();
    v
}

fn records(path: &Path) -> Vec<CallRecord> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .skip(1)
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn verify_all(dir: &Path) -> u64 {
    let files = cdr_files(dir);
    let refs: Vec<&Path> = files.iter().map(PathBuf::as_path).collect();
    verify_files(&refs).unwrap().iter().map(|r| r.records).sum()
}

#[test]
fn answered_call_content_is_correct_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let e = emitter(dir.path(), |_| {});
    let mut sent = answered();
    assert!(e.emit(sent.clone()));
    assert!(e.shutdown(T));

    let files = cdr_files(dir.path());
    assert_eq!(files.len(), 1);
    let got = records(&files[0]);
    assert_eq!(got.len(), 1);
    let r = &got[0];
    // Timestamp ordering and durations.
    assert!(r.setup_ms <= r.ring_ms.unwrap());
    assert!(r.ring_ms.unwrap() <= r.answer_ms.unwrap());
    assert!(r.answer_ms.unwrap() <= r.end_ms);
    assert_eq!(r.duration_ms, 60_000);
    assert_eq!(r.pdd_ms, Some(400));
    // Pre/post translation, trunk, media, emergency survive unchanged.
    assert_eq!(r.caller, "+12025550100");
    assert_eq!(r.caller_translated.as_deref(), Some("2025550100"));
    assert_eq!(r.callee_dialed, "9112");
    assert_eq!(r.callee_translated.as_deref(), Some("+12025550199"));
    assert_eq!(r.final_trunk.as_deref(), Some("t2"));
    assert_eq!(r.trunks_tried.len(), 2);
    assert_eq!(r.trunks_tried[0].status, TrunkOutcome::Status(503));
    assert_eq!(r.media_node.as_deref(), Some("rtpengine-1"));
    assert!(r.media_anchored);
    assert!(r.emergency);
    // Stamped by the writer.
    assert_eq!(r.schema_version, 1);
    assert_eq!(r.node_id, "qa-node");
    assert_eq!(r.record_id, "qa-node-0");
    assert_eq!(r.hash.len(), 96);
    assert_eq!(r.prev_hash.len(), 96);
    // Everything else is identical to what was emitted.
    sent.schema_version = r.schema_version;
    sent.node_id.clone_from(&r.node_id);
    sent.record_id.clone_from(&r.record_id);
    sent.prev_hash.clone_from(&r.prev_hash);
    sent.hash.clone_from(&r.hash);
    assert_eq!(&sent, r);
    assert!(verify_sidecar(&files[0]).unwrap());
}

#[test]
fn chain_continuous_across_rotation_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let small = |c: &mut CdrEmitterConfig| {
        if let Some(f) = c.file.as_mut() {
            f.rotate_size_bytes = 3000;
        }
    };
    let e = emitter(dir.path(), small);
    for _ in 0..12 {
        assert!(e.emit(answered()));
    }
    assert!(e.shutdown(T));
    let first_run = cdr_files(dir.path()).len();
    assert!(
        first_run >= 3,
        "expected size rotation, got {first_run} files"
    );
    assert!(e.stats().rotations >= 2);

    // Restart: sequence and chain continue from the tail of the newest file.
    let e = emitter(dir.path(), small);
    assert!(e.stats().chain_ok);
    for _ in 0..5 {
        assert!(e.emit(answered()));
    }
    assert!(e.shutdown(T));
    assert_eq!(verify_all(dir.path()), 17);
    let files = cdr_files(dir.path());
    let last = records(files.last().unwrap());
    assert_eq!(last.last().unwrap().sequence, 16);
    for f in &files {
        assert!(verify_sidecar(f).unwrap(), "sidecar {}", f.display());
    }

    // Deleting a middle file breaks cross-file continuity.
    std::fs::remove_file(&files[1]).unwrap();
    let rest = cdr_files(dir.path());
    let refs: Vec<&Path> = rest.iter().map(PathBuf::as_path).collect();
    assert!(verify_files(&refs).is_err());
}

#[test]
fn pii_hash_applied_before_chain_and_mask_caller() {
    let dir = tempfile::tempdir().unwrap();
    let key = HmacKey::from_bytes(vec![7u8; 48]).unwrap();
    let policy = PiiPolicy::Hash(key);
    let expect_caller = policy.apply_caller("+12025550100");
    let e = emitter(dir.path(), |c| c.pii = policy.clone());
    assert!(e.emit(answered()));
    assert!(e.shutdown(T));
    let files = cdr_files(dir.path());
    let text = std::fs::read_to_string(&files[0]).unwrap();
    for raw in ["+12025550100", "2025550100", "9112", "+12025550199"] {
        assert!(!text.contains(&format!("\"{raw}\"")), "raw {raw} leaked");
    }
    let r = &records(&files[0])[0];
    assert_eq!(r.caller, expect_caller);
    assert_eq!(r.caller.len(), 96);
    // Ring holds the same (hashed) value; chain verifies over hashed bytes.
    assert_eq!(e.ring().get("qa-node-0").unwrap().caller, expect_caller);
    assert_eq!(verify_all(dir.path()), 1);

    let dir2 = tempfile::tempdir().unwrap();
    let e = emitter(dir2.path(), |c| c.pii = PiiPolicy::MaskCaller);
    assert!(e.emit(answered()));
    assert!(e.shutdown(T));
    let r = &records(&cdr_files(dir2.path())[0])[0];
    assert!(r.caller.ends_with("0100") && !r.caller.contains("202555"));
    assert_eq!(r.callee_dialed, "9112", "mask_caller keeps callee");
    assert_eq!(verify_all(dir2.path()), 1);
}

#[test]
fn ring_paging_through_emitter() {
    let e = CdrEmitter::start(
        CdrEmitterConfig {
            file: None,
            ring_capacity: 20,
            ..CdrEmitterConfig::default()
        },
        Vec::new(),
        None,
    )
    .unwrap();
    for i in 0..25u64 {
        let mut r = answered();
        r.setup_ms = 1_000 + i;
        if i % 2 == 0 {
            r.disposition = Disposition::Failed;
        }
        assert!(e.emit(r));
    }
    assert!(e.flush(T));
    let all = CdrFilter::default();
    let mut seen = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let page = e.ring().query(&all, token.as_deref(), 7);
        assert_eq!(page.total_in_ring, 20);
        assert!(page.records.len() <= 7);
        seen.extend(page.records.iter().map(|r| r.sequence));
        match page.next_page_token {
            Some(t) => token = Some(t),
            None => break,
        }
    }
    // Newest first, oldest 5 evicted, no duplicates or gaps.
    assert_eq!(seen, (5..25).rev().collect::<Vec<u64>>());
    let failed = CdrFilter {
        disposition: Some(Disposition::Failed),
        ..CdrFilter::default()
    };
    let page = e.ring().query(&failed, None, 500);
    assert!(
        page.records
            .iter()
            .all(|r| r.disposition == Disposition::Failed)
    );
    assert_eq!(page.records.len(), 10);
    let window = CdrFilter {
        start_ms: Some(1_010),
        end_ms: Some(1_015),
        ..CdrFilter::default()
    };
    assert_eq!(e.ring().query(&window, None, 500).records.len(), 5);
    assert!(e.ring().query(&all, Some("not-a-number"), 5).records.len() <= 5);
}

#[test]
fn csv_formula_injection_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let e = emitter(dir.path(), |c| {
        if let Some(f) = c.file.as_mut() {
            f.format = CdrFormat::Csv;
        }
    });
    let mut r = answered();
    r.caller = "=HYPERLINK(\"http://evil\",\"x\")".into();
    r.callee_dialed = "+1555,\r\n@SUM(A1)".into();
    r.a_call_id = "-2+3".into();
    assert!(e.emit(r));
    assert!(e.shutdown(T));
    let files = cdr_files(dir.path());
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].extension().unwrap(), "csv");
    let text = std::fs::read_to_string(&files[0]).unwrap();
    let rows = parse_csv(
        text.lines()
            .filter(|l| !l.starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n")
            .as_str(),
    );
    assert_eq!(rows.len(), 2, "header + one row: {rows:?}");
    assert_eq!(rows[0].len(), rows[1].len());
    for cell in rows.iter().flatten() {
        assert!(
            !cell.starts_with(['=', '@', '+', '-', '\t', '\r']),
            "unguarded cell {cell:?}"
        );
    }
    let row = &rows[1];
    assert!(row.contains(&"'=HYPERLINK(\"http://evil\",\"x\")".to_string()));
    assert!(row.contains(&"'-2+3".to_string()));
    assert!(
        row.iter()
            .any(|c| c.starts_with("'+1555,") && c.contains("@SUM"))
    );
    assert!(verify_sidecar(&files[0]).unwrap());
}

/// Minimal RFC 4180 reader (quoted fields may contain `,`, `"\"`, CR, LF).
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                chars.next();
                cell.push('"');
            }
            (true, '"') => quoted = false,
            (false, '"') => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut cell)),
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            (_, c) => cell.push(c),
        }
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    rows
}

/// Captures every byte written by the syslog sink.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FakeConnector {
    cap: Capture,
    connects: Arc<Mutex<u32>>,
}

impl SyslogConnector for FakeConnector {
    fn connect(&mut self) -> io::Result<Box<dyn Write + Send>> {
        *self.connects.lock().unwrap() += 1;
        Ok(Box::new(self.cap.clone()))
    }
}

#[test]
fn syslog_sink_octet_counted_frames_via_fake_connector() {
    let cap = Capture::default();
    let connects = Arc::new(Mutex::new(0));
    let sink = SyslogSink::new(
        &SyslogSinkConfig {
            hostname: "qa node\n".into(),
            app_name: "usg-sbc".into(),
            facility: 16,
        },
        Box::new(FakeConnector {
            cap: cap.clone(),
            connects: Arc::clone(&connects),
        }),
    );
    let e = CdrEmitter::start(
        CdrEmitterConfig {
            file: None,
            node_id: "qa-node".into(),
            ..CdrEmitterConfig::default()
        },
        vec![Box::new(sink) as Box<dyn CdrSink>],
        None,
    )
    .unwrap();
    let mut hostile = answered();
    hostile.caller = "a\r\n<13>1 forged".into();
    for r in [answered(), hostile, answered()] {
        assert!(e.emit(r));
    }
    assert!(e.shutdown(T));
    assert_eq!(*connects.lock().unwrap(), 1, "one connection reused");
    let bytes = cap.0.lock().unwrap().clone();
    let mut rest = std::str::from_utf8(&bytes).unwrap();
    let mut frames = Vec::new();
    while !rest.is_empty() {
        let (len, tail) = rest.split_once(' ').unwrap();
        let len: usize = len.parse().unwrap();
        let (msg, tail) = tail.split_at(len);
        frames.push(msg.to_string());
        rest = tail;
    }
    assert_eq!(frames.len(), 3);
    for (i, f) in frames.iter().enumerate() {
        // PRI = 16*8+6 = 134; hostname control chars and spaces stripped.
        assert!(f.starts_with("<134>1 "), "{f}");
        let parts: Vec<&str> = f.splitn(8, ' ').collect();
        assert_eq!(parts[2], "qanode");
        assert_eq!(parts[3], "usg-sbc");
        assert_eq!(parts[5], "CDR");
        assert!(
            !f.contains('\n') && !f.contains('\r'),
            "raw newline in frame"
        );
        // RFC 5424 §6.4 BOM before the UTF-8 MSG.
        let json = parts[7].strip_prefix('\u{FEFF}').expect("BOM");
        let rec: CallRecord = serde_json::from_str(json).unwrap();
        assert_eq!(rec.sequence, i as u64);
    }
}

/// Observer that stalls the writer thread on every rotation, so the queue
/// fills (`rotate_size_bytes = 1` rotates after every record).
struct SlowObserver;
impl CdrObserver for SlowObserver {
    fn on_rotated(&self, _: &Path, _: &str) {
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn burst_drops_without_blocking_and_degrades_health() {
    let dir = tempfile::tempdir().unwrap();
    let mut fc = file_cfg(dir.path());
    fc.rotate_size_bytes = 1;
    let e = CdrEmitter::start(
        CdrEmitterConfig {
            file: Some(fc),
            queue_capacity: 64,
            ..CdrEmitterConfig::default()
        },
        Vec::new(),
        Some(Arc::new(SlowObserver) as Arc<dyn CdrObserver>),
    )
    .unwrap();
    assert_eq!(e.health(), CdrHealth::Healthy);
    let n = 5_000u64;
    // Collect first so all producers run concurrently.
    #[allow(clippy::needless_collect)]
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let e = Arc::clone(&e);
            std::thread::spawn(move || {
                let mut worst = Duration::ZERO;
                for _ in 0..n / 4 {
                    let t = Instant::now();
                    let _ = e.emit(answered());
                    worst = worst.max(t.elapsed());
                }
                worst
            })
        })
        .collect();
    let worst = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .max()
        .unwrap();
    // The writer sleeps 20 ms per record; a blocking emit would show it.
    assert!(
        worst < Duration::from_millis(15),
        "emit blocked for {worst:?}"
    );
    let s = e.stats();
    assert!(s.dropped_queue_full > 0);
    assert_eq!(s.emitted + s.dropped_queue_full, n);
    assert_eq!(s.dropped_writer_dead, 0);
    assert!(s.queue_depth <= 64);
    assert_eq!(e.health(), CdrHealth::Degraded);
    assert!(e.last_drop_elapsed().is_some());
}

/// Syslog sink whose collector never answers: every write blocks until the
/// test releases it (a blackholed TCP peer with long timeouts).
struct StalledSink(Arc<(Mutex<bool>, std::sync::Condvar)>);
impl CdrSink for StalledSink {
    fn name(&self) -> &'static str {
        "syslog"
    }
    fn write(&mut self, _: &CallRecord, _: &str) -> io::Result<()> {
        let (lock, cvar) = &*self.0;
        drop(
            cvar.wait_while(lock.lock().unwrap(), |released| !*released)
                .unwrap(),
        );
        Ok(())
    }
}

/// PERF-1: a stalled syslog collector must never delay local file writes;
/// its own queue overflows and is counted, the file copy is complete.
#[test]
fn stalled_syslog_does_not_delay_file_writes() {
    let dir = tempfile::tempdir().unwrap();
    let gate = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
    let mut fc = file_cfg(dir.path());
    fc.fsync_interval = Duration::from_secs(60);
    let em = CdrEmitter::start(
        CdrEmitterConfig {
            node_id: "qa-node".into(),
            file: Some(fc),
            ..CdrEmitterConfig::default()
        },
        vec![Box::new(StalledSink(Arc::clone(&gate))) as Box<dyn CdrSink>],
        None,
    )
    .unwrap();
    let n = uc_cdr::writer::SINK_QUEUE_CAPACITY as u64 + 500;
    let started = Instant::now();
    let mut accepted = 0;
    for _ in 0..n {
        // Pace below the writer queue so only the syslog queue overflows.
        while em.stats().queue_depth > 1000 {
            std::thread::yield_now();
        }
        if em.emit(answered()) {
            accepted += 1;
        }
    }
    assert!(em.flush(T), "file flush waited on the stalled collector");
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
    let stats = em.stats();
    assert_eq!(accepted, n);
    assert_eq!(stats.written, n, "{stats:?}");
    assert!(stats.sink_dropped >= 400, "{stats:?}");
    assert_eq!(em.health(), CdrHealth::Degraded);
    let (lock, cvar) = &*gate;
    *lock.lock().unwrap() = true;
    cvar.notify_all();
    assert!(em.shutdown(T));
}

#[test]
fn health_transitions_write_error_and_writer_dead() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("cdr");
    std::fs::create_dir(&sub).unwrap();
    let e = emitter(&sub, |c| {
        if let Some(f) = c.file.as_mut() {
            f.rotate_size_bytes = 1;
        }
    });
    assert!(e.emit(answered()));
    assert!(e.flush(T));
    assert_eq!(e.health(), CdrHealth::Healthy);
    assert_eq!(e.stats().write_errors, 0);

    // Remove the directory under the writer: the next file open must fail.
    std::fs::remove_dir_all(&sub).unwrap();
    std::fs::write(&sub, b"not a dir").unwrap();
    assert!(e.emit(answered()));
    assert!(e.emit(answered()));
    assert!(e.flush(T));
    let s = e.stats();
    assert!(s.write_errors >= 1, "{s:?}");
    assert_eq!(e.health(), CdrHealth::Unhealthy);
    assert!(s.writer_alive, "write errors must not kill the writer");
    // Records still reach the ring (API visibility) even when disk fails.
    assert_eq!(s.ring_size, 3);

    assert!(e.shutdown(T));
    let deadline = Instant::now() + T;
    while e.writer_alive() && Instant::now() < deadline {
        std::thread::yield_now();
    }
    assert!(!e.writer_alive());
    assert_eq!(e.health(), CdrHealth::Unhealthy);
    assert!(!e.emit(answered()));
    assert_eq!(e.stats().dropped_writer_dead, 1);
}

/// Restart after a crash that tore the last JSONL line (partial write).
/// Expected: resume from the last complete record, so record ids stay
/// unique and the sequence does not reset.
#[test]
fn torn_last_line_does_not_reset_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let e = emitter(dir.path(), |_| {});
    for _ in 0..3 {
        assert!(e.emit(answered()));
    }
    assert!(e.flush(T));
    drop(e); // simulate crash: no shutdown, file left open (no sidecar)
    std::thread::sleep(Duration::from_millis(400));
    let f = cdr_files(dir.path()).pop().unwrap();
    let mut fh = std::fs::OpenOptions::new().append(true).open(&f).unwrap();
    fh.write_all(b"{\"schema_version\":1,\"record_id\":\"qa-no")
        .unwrap();
    drop(fh);
    let e = emitter(dir.path(), |_| {});
    assert!(e.emit(answered()));
    assert!(e.flush(T));
    let ids: Vec<String> = e
        .ring()
        .query(&CdrFilter::default(), None, 10)
        .records
        .iter()
        .map(|r| r.record_id.clone())
        .collect();
    assert_eq!(ids, vec!["qa-node-3".to_string()]);
}

/// Restart when the last CSV row contains a quoted CR/LF from SIP input.
#[test]
fn csv_resume_after_row_with_embedded_newline() {
    let dir = tempfile::tempdir().unwrap();
    let csv = |c: &mut CdrEmitterConfig| {
        if let Some(f) = c.file.as_mut() {
            f.format = CdrFormat::Csv;
        }
    };
    let e = emitter(dir.path(), csv);
    let mut r = answered();
    r.callee_dialed = "x\r\ny".into();
    assert!(e.emit(answered()));
    assert!(e.emit(r));
    assert!(e.flush(T));
    drop(e);
    std::thread::sleep(Duration::from_millis(400));
    let e = emitter(dir.path(), csv);
    assert!(
        e.stats().chain_ok,
        "chain resume failed after hostile CRLF row"
    );
    assert!(e.emit(answered()));
    assert!(e.flush(T));
    let page = e.ring().query(&CdrFilter::default(), None, 10);
    assert_eq!(page.records[0].sequence, 2);
}
