//! QA: CDR pipeline integration. sbc-daemon is a binary crate and cannot
//! be linked here, so this drives the same stages the daemon wires up:
//! TOML `[cdr]` -> `uc-cdr` emitter with a file sink -> on-disk chain
//! verify -> ring query -> gRPC proto mapping (with the `grpc` feature).

use std::path::{Path, PathBuf};
use std::time::Duration;

use uc_cdr::{
    CallRecord, CdrEmitter, CdrEmitterConfig, CdrFilter, CdrFormat, Disposition, FileSinkConfig,
    PiiPolicy, ReleaseCause, ReleaseSide, TrunkAttempt, TrunkOutcome,
};

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(
            format!(
                "sbc-it-cdr-{tag}-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
            )
            .replace([' ', ':', '{', '}', ','], "_"),
        );
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Builds the emitter config from a parsed `[cdr]` table the way the
/// daemon's `start_from_config` does (no PII key, ring + file, and the
/// attempts stream when `separate_attempts`).
fn emitter_from(cfg: &sbc_config::schema::CdrConfig) -> CdrEmitterConfig {
    use sbc_config::schema::CdrFormatConfig;
    let file = FileSinkConfig {
        directory: cfg.directory.clone(),
        format: match cfg.format {
            CdrFormatConfig::Jsonl => CdrFormat::Jsonl,
            CdrFormatConfig::Csv => CdrFormat::Csv,
        },
        rotate_size_bytes: u64::from(cfg.rotate_size_mb) * 1024 * 1024,
        rotate_interval: cfg
            .rotate_interval_secs()
            .filter(|s| *s > 0)
            .map(Duration::from_secs),
        retention_files: cfg.retention_files,
        retention_days: cfg.retention_days,
        fsync_interval: Duration::from_millis(u64::from(cfg.fsync_interval_ms)),
        stream: uc_cdr::CdrStream::Calls,
    };
    let attempts = cfg.separate_attempts.then(|| FileSinkConfig {
        rotate_size_bytes: u64::from(cfg.attempts_rotate_size_mb) * 1024 * 1024,
        retention_files: cfg.attempts_retention_files,
        retention_days: cfg.attempts_retention_days,
        stream: uc_cdr::CdrStream::Attempts,
        ..file.clone()
    });
    CdrEmitterConfig {
        node_id: cfg.node_id.clone().unwrap_or_else(|| "it".into()),
        queue_capacity: cfg.queue_capacity,
        ring_capacity: cfg.ring_capacity,
        hash_chain: cfg.hash_chain,
        pii: PiiPolicy::Full,
        file: Some(file),
        attempts,
    }
}

fn call(n: u64) -> CallRecord {
    let mut r = CallRecord {
        a_call_id: format!("a{n}@uac"),
        b_call_ids: vec![format!("b{n}@sbc")],
        caller: "+12025550100".into(),
        callee_dialed: "+15551234567".into(),
        callee_translated: Some("5551234567".into()),
        source_ip: "192.0.2.10".into(),
        source_port: 5060,
        trunk_group: Some("carriers".into()),
        trunks_tried: vec![TrunkAttempt {
            trunk_id: "t1".into(),
            status: TrunkOutcome::Status(200),
            at_ms: 1_000 + n,
        }],
        final_trunk: Some("t1".into()),
        setup_ms: 1_000 * n,
        ring_ms: Some(1_000 * n + 100),
        answer_ms: Some(1_000 * n + 300),
        end_ms: 1_000 * n + 900,
        disposition: Disposition::Answered,
        final_sip_status: 200,
        release_side: ReleaseSide::Caller,
        release_cause: ReleaseCause::Normal,
        codec: Some("PCMU".into()),
        ..Default::default()
    };
    r.compute_durations();
    r
}

fn jsonl_files(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    v.sort();
    v
}

#[test]
fn config_to_file_to_verify_to_ring() {
    let dir = TempDir::new("e2e");
    let toml = format!(
        "[cdr]\ndirectory = \"{}\"\nnode_id = \"it-node\"\nrotate_interval = \"0\"\nfsync_interval_ms = 0\n",
        dir.0.display()
    );
    let cfg = sbc_config::load_from_str(&toml).unwrap().cdr;
    let em = CdrEmitter::start(emitter_from(&cfg), Vec::new(), None).unwrap();
    for n in 1..=10 {
        assert!(em.emit(call(n)));
    }
    assert!(em.shutdown(Duration::from_secs(10)));

    // Calls stream only: the attempts stream (separate_attempts, default
    // on) has its own, here header-only, cdra- file.
    let files: Vec<PathBuf> = jsonl_files(&dir.0)
        .into_iter()
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("cdr-"))
        .collect();
    assert_eq!(files.len(), 1);
    let rep = uc_cdr::verify_file(&files[0]).unwrap();
    assert_eq!(rep.records, 10);
    assert_eq!(rep.node_id, "it-node");
    assert!(rep.chained);
    assert!(uc_cdr::verify_sidecar(&files[0]).unwrap());
    let name = files[0].file_name().unwrap().to_string_lossy().to_string();
    assert!(name.starts_with("cdr-it-node-"), "{name}");

    let page = em.ring().query(
        &CdrFilter {
            callee: Some("5551234567".into()),
            ..CdrFilter::default()
        },
        None,
        500,
    );
    assert_eq!(page.records.len(), 10);
    assert_eq!(page.records[0].record_id, "it-node-9");

    #[cfg(feature = "grpc")]
    for r in &page.records {
        let p = sbc_grpc_api::cdr::to_proto(r);
        let back = sbc_grpc_api::cdr::from_proto(&p).unwrap();
        assert_eq!(&back, &**r);
    }
}

#[cfg(unix)]
#[test]
fn files_are_0640_in_0750_directory() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("perm");
    let sub = dir.0.join("cdr");
    let cfg = sbc_config::load_from_str(&format!(
        "[cdr]\ndirectory = \"{}\"\nrotate_interval = \"0\"\n",
        sub.display()
    ))
    .unwrap()
    .cdr;
    let em = CdrEmitter::start(emitter_from(&cfg), Vec::new(), None).unwrap();
    assert!(em.emit(call(1)));
    assert!(em.shutdown(Duration::from_secs(10)));
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&sub), 0o750);
    for f in jsonl_files(&sub) {
        assert_eq!(mode(&f), 0o640, "{}", f.display());
    }
}

#[test]
fn disabled_config_needs_no_directory() {
    let cfg = sbc_config::load_from_str("[cdr]\nenabled = false\ndirectory = \"relative\"\n")
        .unwrap()
        .cdr;
    assert!(!cfg.enabled);
}

/// SR-43 (QA-first, plan 8 / decision b, POA&M-432/433): from a TOML
/// `[cdr]` with a small size rotation and a 3-file safety cap, a flood of
/// SBC-generated rejects (unique Call-IDs, never routed) must not evict the
/// answered-call CDR files written before it: rejects go to the separate
/// attempts stream (`separate_attempts` defaults on). `emitter_from` must
/// map the attempts stream the way the daemon's `start_from_config` does.
/// NIST 800-53 Rev5: AU-11, AU-4, SC-5
#[test]
fn qa_cdr_reject_flood_keeps_answered_cdrs() {
    let dir = TempDir::new("flood");
    let toml = format!(
        "[cdr]\ndirectory = \"{}\"\nnode_id = \"it-node\"\nrotate_interval = \"0\"\n\
         rotate_size_mb = 1\nretention_files = 3\nretention_days = 90\n\
         fsync_interval_ms = 60000\nqueue_capacity = 1000000\nring_capacity = 0\n",
        dir.0.display()
    );
    let cfg = sbc_config::load_from_str(&toml).unwrap().cdr;
    let em = CdrEmitter::start(emitter_from(&cfg), Vec::new(), None).unwrap();
    let answered = 1_500u64;
    for n in 1..=answered {
        assert!(em.emit(call(n)));
    }
    assert!(em.flush(Duration::from_secs(30)));
    let calls = |d: &Path| -> Vec<PathBuf> {
        jsonl_files(d)
            .into_iter()
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("cdr-it-node-")
            })
            .collect()
    };
    let sealed: Vec<PathBuf> = calls(&dir.0)
        .into_iter()
        .filter(|p| uc_cdr::chain::sidecar_path(p).exists())
        .collect();
    assert!(
        !sealed.is_empty(),
        "answered calls must fill a 1 MiB file first"
    );

    for n in 0..8_000u64 {
        let mut r = CallRecord {
            a_call_id: format!("flood-{n}@spoofed"),
            caller: "+12025550199".into(),
            callee_dialed: "+15551234567".into(),
            source_ip: "198.51.100.77".into(),
            source_port: 5060,
            setup_ms: 2_000_000 + n,
            end_ms: 2_000_000 + n,
            disposition: Disposition::Rejected,
            final_sip_status: 403,
            release_side: ReleaseSide::Sbc,
            release_cause: ReleaseCause::PolicyDenied,
            ..Default::default()
        };
        r.compute_durations();
        assert!(em.emit(r));
    }
    assert!(em.shutdown(Duration::from_secs(60)));

    for p in &sealed {
        assert!(p.exists(), "{} was evicted by a reject flood", p.display());
        assert!(uc_cdr::verify_sidecar(p).unwrap(), "{}", p.display());
    }
    let left = calls(&dir.0);
    let refs: Vec<&Path> = left.iter().map(PathBuf::as_path).collect();
    let reps = uc_cdr::verify_files(&refs).unwrap();
    assert_eq!(
        reps.iter().map(|r| r.records).sum::<u64>(),
        answered,
        "every answered CDR is still on disk and no reject is in the calls stream"
    );
}
