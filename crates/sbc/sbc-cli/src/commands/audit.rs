//! `sbc-cli audit` — audit trail tools.
//!
//! `verify` checks uc-audit files offline: every line parses, sequences are
//! contiguous and the SHA-384 hash chain links (files continue each other in
//! the order given). It needs no daemon.
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
    let paths: Vec<&Path> = files.iter().map(Path::new).collect();
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
}
