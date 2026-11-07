//! Binary-level exit code of `sbc-cli audit verify` (AU-9 evidence).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;
use uc_audit::sink::{AuditSink, FileSink};

fn write_chain(path: &std::path::Path, n: u64) {
    let sink = FileSink::open(path).unwrap();
    let mut prev = [0u8; 48];
    for seq in 0..n {
        let event = uc_audit::AuditEvent::SystemShutdown(uc_audit::event::SystemShutdown {
            reason: format!("reason-{seq}"),
            graceful: true,
        });
        let r = uc_audit::AuditRecord::new(seq, event, chrono::Utc::now(), prev);
        prev = r.hash_chain;
        sink.write(&r).unwrap();
    }
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sbc-cli"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn verify_exit_codes_ok_tampered_reordered_deleted_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    write_chain(&path, 4);
    let p = path.to_str().unwrap();

    let ok = run(&["audit", "verify", p]);
    assert!(ok.status.success(), "{ok:?}");
    assert!(String::from_utf8_lossy(&ok.stdout).contains("OK"));

    let text = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = text.lines().collect();

    // tampered
    std::fs::write(&path, text.replacen("reason-2", "reason-X", 1)).unwrap();
    let out = run(&["audit", "verify", p]);
    assert_eq!(out.status.code(), Some(1), "tampered: {out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("FAILED"));

    // reordered
    let mut re = lines.clone();
    re.swap(1, 2);
    std::fs::write(&path, re.join("\n") + "\n").unwrap();
    assert_eq!(
        run(&["audit", "verify", p]).status.code(),
        Some(1),
        "reordered"
    );

    // deleted middle line
    let mut del = lines.clone();
    del.remove(2);
    std::fs::write(&path, del.join("\n") + "\n").unwrap();
    assert_eq!(
        run(&["audit", "verify", p]).status.code(),
        Some(1),
        "deleted"
    );

    // head deleted: unanchored, warned; fails with --require-anchor
    std::fs::write(&path, lines[2..].join("\n") + "\n").unwrap();
    let out = run(&["audit", "verify", p]);
    assert!(out.status.success(), "unanchored without flag: {out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("WARN  UNANCHORED"));
    let out = run(&["audit", "verify", "--require-anchor", p]);
    assert_eq!(out.status.code(), Some(1), "unanchored with flag: {out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("unanchored"));

    // injected key: not canonical
    std::fs::write(
        &path,
        text.replacen("\"graceful\"", "\"note\":\"approved\",\"graceful\"", 1),
    )
    .unwrap();
    assert_eq!(
        run(&["audit", "verify", p]).status.code(),
        Some(1),
        "injected key"
    );

    // missing file and no args
    let missing = dir.path().join("nope.log");
    assert_eq!(
        run(&["audit", "verify", missing.to_str().unwrap()])
            .status
            .code(),
        Some(1)
    );
    assert_eq!(run(&["audit", "verify"]).status.code(), Some(1));
}
