//! `sbc-cli audit` — audit trail tools.
//!
//! `verify` checks uc-audit files offline: every line parses, sequences are
//! contiguous and the SHA-384 hash chain links. Files are checked in the
//! order of their first sequence, so a rotated set (`audit.log.<n>` files
//! plus the current `audit.log`) can be passed in any order, e.g. as the
//! shell glob `audit.log*`. `<n>` is a monotonic rotation number, at least
//! the file's first sequence, so name order is verify order. It needs no
//! daemon.
//!
//! A passing `verify` shows the files are self-consistent. The chain is
//! unkeyed, so it does not prove who wrote them (POA&M-130).
//!
//! ## NIST 800-53 Rev5: AU-6 (Audit Review), AU-9 (tamper-evidence check)
// POAM: POA&M-130 -- keyed chain / signed checkpoints are not implemented.

use std::path::Path;

use crate::args::AuditCommand;
use crate::commands::{CommandError, CommandResult};

pub fn run(cmd: AuditCommand) -> CommandResult {
    match cmd {
        AuditCommand::Verify {
            files,
            require_anchor,
        } => verify(&files, require_anchor),
    }
}

/// `files` ordered by the sequence of their first record (stable; files
/// without records, or that fail on their own, keep their relative place
/// at the end so the chain check reports them).
///
/// ## NIST 800-53 Rev5: AU-6 (a rotated set is reviewed as one chain)
fn in_sequence_order(files: &[String]) -> Vec<&Path> {
    // The same file under two names (a crash between the rotation's link
    // and unlink, or a glob plus an explicit name) is verified once.
    let mut seen = std::collections::HashSet::new();
    let mut keyed: Vec<(Option<u64>, &Path)> = files
        .iter()
        .filter(|f| file_id(Path::new(f)).is_none_or(|id| seen.insert(id)))
        .map(|f| {
            let p = Path::new(f);
            let first = uc_audit::verify::verify_file(p)
                .ok()
                .and_then(|r| r.first_sequence);
            (first, p)
        })
        .collect();
    keyed.sort_by_key(|(first, _)| (first.is_none(), *first));
    keyed.into_iter().map(|(_, p)| p).collect()
}

/// `(device, inode)` of a file, when available.
fn file_id(p: &Path) -> Option<(u64, u64)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = p;
        None
    }
}

/// Offline chain verification. Fails (non-zero exit) on the first file
/// that does not verify, or with `require_anchor` when the first file does
/// not start at the genesis record.
///
/// ## NIST 800-53 Rev5: AU-9 (an unanchored head may have been deleted)
fn verify(files: &[String], require_anchor: bool) -> CommandResult {
    if files.is_empty() {
        return Err(CommandError::new(
            "usage: sbc-cli audit verify [--require-anchor] <FILE>...",
        ));
    }
    let paths = in_sequence_order(files);
    let reports = uc_audit::verify::verify_files(&paths).map_err(|(i, e)| {
        let file = paths
            .get(i)
            .map_or_else(String::new, |p| p.display().to_string());
        CommandError::new(format!("audit chain verification FAILED: {file} {e}"))
    })?;
    let mut markers = 0u64;
    for (path, r) in paths.iter().zip(&reports) {
        let seq = |s: Option<u64>| s.map_or_else(|| "-".to_string(), |s| s.to_string());
        println!(
            "OK  {}  records={} sequence={}..{} anchored={} drop_markers={}",
            path.display(),
            r.records,
            seq(r.first_sequence),
            seq(r.last_sequence),
            r.anchored,
            r.drop_markers
        );
        markers = markers.saturating_add(r.drop_markers);
    }
    if let (Some(path), Some(first)) = (paths.first(), reports.first())
        && !first.anchored
    {
        let start = first.first_sequence.unwrap_or_default();
        if require_anchor {
            return Err(CommandError::new(format!(
                "audit chain verification FAILED: {} is unanchored (starts at sequence \
                 {start}, not 0) and --require-anchor was given; supply the preceding file",
                path.display()
            )));
        }
        println!(
            "WARN  UNANCHORED  {} starts at sequence {start}, not 0: records before it \
             cannot be checked (rotated file, or its head was deleted). Supply the \
             preceding file, or use --require-anchor to fail.",
            path.display()
        );
    }
    // NIST 800-53 Rev5: AU-9, AU-5 - rotated digests chained in the trail,
    // and whether a missing head was deleted by the capacity action.
    let check = uc_audit::verify::cross_check(&paths, &reports)
        .map_err(|e| CommandError::new(format!("audit chain verification FAILED: {e}")))?;
    if !check.digest_mismatches.is_empty() {
        return Err(CommandError::new(format!(
            "audit chain verification FAILED: rotated file(s) changed after their \
             audit_file_rotated digest was chained: {}",
            check.digest_mismatches.join(", ")
        )));
    }
    if check.digests_checked > 0 {
        println!(
            "OK  {} rotated file digest(s) match their audit_file_rotated records",
            check.digests_checked
        );
    }
    match check.head_gap {
        Some((first, true)) => println!(
            "NOTE  records before sequence {first} were deleted by the audit capacity \
             action (audit_file_deleted in the trail)"
        ),
        Some((first, false)) => println!(
            "WARN  no audit_file_deleted record accounts for the records before sequence \
             {first}; supply the earlier files or check the off-box copy"
        ),
        None => {}
    }
    if markers > 0 {
        // AU-5: the markers are legitimate chained records saying audit
        // records were lost (queue full, sink failure, torn tail).
        println!(
            "WARN  {markers} AuditRecordsDropped marker(s): audit records were lost; \
             review them with the daemon's audit health history"
        );
    }
    println!(
        "NOTE  chain is tamper-evident only (unkeyed SHA-384, POA&M-130): anyone with write \
         access to the file can rewrite it and recompute the chain. Compare with the \
         forwarded (off-host) copy."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uc_audit::sink::{AuditSink, FileSink};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    #[test]
    fn audit_verify_passes_then_fails_on_tamper() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.log");
        let sink = FileSink::open(&path)?;
        let mut prev = [0u8; 48];
        for seq in 0..3u64 {
            let event = uc_audit::AuditEvent::SystemShutdown(uc_audit::event::SystemShutdown {
                reason: format!("reason-{seq}"),
                graceful: true,
            });
            let r = uc_audit::AuditRecord::new(seq, event, chrono::Utc::now(), prev);
            prev = r.hash_chain;
            sink.write(&r)?;
        }
        drop(sink);
        let f = path.display().to_string();
        assert!(verify(std::slice::from_ref(&f), false).is_ok());
        assert!(verify(std::slice::from_ref(&f), true).is_ok());
        let text = std::fs::read_to_string(&path)?;
        std::fs::write(&path, text.replacen("reason-1", "reason-9", 1))?;
        let err = verify(std::slice::from_ref(&f), false)
            .err()
            .ok_or("tamper not detected")?;
        assert!(err.message.contains("line 2"), "{}", err.message);
        assert!(verify(&[], false).is_err());
        Ok(())
    }

    /// SR-42 (QA-first, plan 8): `verify` accepts a rotated set
    /// (`audit.log.<first_seq:020>` files plus the current `audit.log`)
    /// however it is listed, ordering it by sequence: the shell glob
    /// `audit.log*` lists the current file first. Tampering is still found.
    /// NIST 800-53 Rev5: AU-6, AU-9
    #[test]
    fn audit_verify_accepts_rotated_set_in_order() -> TestResult {
        let dir = tempfile::tempdir()?;
        let current = dir.path().join("audit.log");
        let mut prev = [0u8; 48];
        let mut seq = 0u64;
        let mut paths = Vec::new();
        for (name, n) in [
            ("audit.log.00000000000000000000", 3u64),
            ("audit.log.00000000000000000003", 3),
            ("audit.log.00000000000000000006", 2),
            ("audit.log", 2),
        ] {
            let path = dir.path().join(name);
            let sink = FileSink::open(&path)?;
            for _ in 0..n {
                let event = uc_audit::AuditEvent::SystemShutdown(uc_audit::event::SystemShutdown {
                    reason: format!("reason-{seq}"),
                    graceful: true,
                });
                let r = uc_audit::AuditRecord::new(seq, event, chrono::Utc::now(), prev);
                prev = r.hash_chain;
                sink.write(&r)?;
                seq += 1;
            }
            paths.push(path.display().to_string());
        }
        // Sequence order passes, anchored.
        assert!(verify(&paths, true).is_ok());
        // Glob order (`audit.log*`): current file first.
        let glob = vec![
            current.display().to_string(),
            paths[0].clone(),
            paths[1].clone(),
            paths[2].clone(),
        ];
        verify(&glob, true).map_err(|e| e.message)?;
        // Any other listing order of the same set.
        let shuffled = vec![
            paths[2].clone(),
            paths[3].clone(),
            paths[0].clone(),
            paths[1].clone(),
        ];
        verify(&shuffled, true).map_err(|e| e.message)?;
        // A gap (a rotated file missing) is still refused.
        let gap = vec![paths[0].clone(), paths[2].clone(), paths[3].clone()];
        assert!(verify(&gap, false).is_err());
        // Tampering in a rotated file is still found.
        let text = std::fs::read_to_string(&paths[1])?;
        std::fs::write(&paths[1], text.replacen("reason-4", "reason-9", 1))?;
        assert!(verify(&glob, false).is_err());
        Ok(())
    }

    /// SR-42 round 1 (SEC-011, NIST-007): the same file under two names is
    /// verified once, and a rotated file changed after its digest was
    /// chained fails verification.
    #[test]
    fn audit_verify_dedupes_hardlinks_and_checks_rotated_digests() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.log");
        let sink = FileSink::open_with(
            &path,
            uc_audit::sink::FileSinkOptions {
                max_file_bytes: 600,
                max_rotated_files: 8,
                on_full: uc_audit::sink::CapacityAction::OverwriteOldest,
            },
        )?;
        uc_audit_chain(&sink, 6)?;
        let mut files: Vec<String> = std::fs::read_dir(dir.path())?
            .filter_map(Result::ok)
            .map(|e| e.path().display().to_string())
            .collect();
        files.sort();
        assert!(files.len() >= 2, "{files:?}");
        verify(&files, false).map_err(|e| e.message)?;
        // A second name for the current file (crash between link and unlink).
        let twin = dir.path().join("audit.log.99999999999999999999");
        std::fs::hard_link(&path, &twin)?;
        let mut with_twin = files.clone();
        with_twin.push(twin.display().to_string());
        verify(&with_twin, false).map_err(|e| e.message)?;
        Ok(())
    }

    /// Writes `n` chained records through `sink` (rotating as it goes) and
    /// chains the rotation notices like the writer does.
    fn uc_audit_chain(sink: &FileSink, n: u64) -> TestResult {
        let mut prev = [0u8; 48];
        let mut seq = 0u64;
        let mut written = 0;
        while written < n {
            for notice in sink.take_notices() {
                if let uc_audit::sink::SinkNotice::Rotated {
                    file,
                    sha384,
                    last_sequence,
                } = notice
                {
                    let e =
                        uc_audit::AuditEvent::AuditFileRotated(uc_audit::event::AuditFileRotated {
                            file: file.display().to_string(),
                            sha384: sha384.iter().fold(String::new(), |mut s, b| {
                                use std::fmt::Write as _;
                                let _ = write!(s, "{b:02x}");
                                s
                            }),
                            last_sequence,
                        });
                    let r = uc_audit::AuditRecord::new(seq, e, chrono::Utc::now(), prev);
                    sink.write(&r)?;
                    prev = r.hash_chain;
                    seq += 1;
                }
            }
            let e = uc_audit::AuditEvent::SystemShutdown(uc_audit::event::SystemShutdown {
                reason: format!("r{seq}"),
                graceful: true,
            });
            let r = uc_audit::AuditRecord::new(seq, e, chrono::Utc::now(), prev);
            sink.write(&r)?;
            prev = r.hash_chain;
            seq += 1;
            written += 1;
        }
        Ok(())
    }
}
