//! Offline verification of audit files written by [`crate::sink::FileSink`].
//!
//! Checks every line parses as an [`AuditRecord`], sequences are contiguous
//! and each record's SHA-384 link to its predecessor. A file whose first
//! record is sequence 0 is anchored at the zero hash; a file starting later
//! (rotated by the platform) is accepted as an unanchored continuation, with
//! the remaining links still checked, unless the previous file is given.
//!
//! A passing verification shows the file is self-consistent. The chain is
//! unkeyed, so it does not prove who wrote it.
//!
//! ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information), AU-6, SI-11
// POAM: POA&M-130 -- unkeyed chain: a writer with file access can rewrite
// records and recompute every hash; this verifier cannot detect that.

use crate::event::AuditEvent;
use crate::record::{AuditRecord, parse_canonical};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

/// Longest line accepted (bytes, without the newline).
///
/// ## NIST 800-53 Rev5: SC-5 (bounded memory on a hostile file)
pub const MAX_LINE_LEN: usize = 1024 * 1024;

/// Result of a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Records checked.
    pub records: u64,
    /// Sequence of the first record, if any.
    pub first_sequence: Option<u64>,
    /// Sequence of the last record, if any.
    pub last_sequence: Option<u64>,
    /// Hash of the last record (hex; empty when the file has no records).
    pub last_hash: String,
    /// Whether the first record was checked against a known predecessor
    /// (genesis or the previous file). Vacuously true for an empty file.
    pub anchored: bool,
    /// `AuditRecordsDropped` markers seen (legitimate, chained records that
    /// say records were lost).
    pub drop_markers: u64,
}

/// Verification failure.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The file could not be read.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A line failed a check (tamper, truncation or corruption).
    #[error("line {line}: {reason}")]
    Line {
        /// 1-based line number.
        line: u64,
        /// What failed. Never echoes line content.
        reason: String,
    },
}

fn line_err(line: u64, reason: impl Into<String>) -> VerifyError {
    VerifyError::Line {
        line,
        reason: reason.into(),
    }
}

/// Reads one line of at most [`MAX_LINE_LEN`] bytes. `Ok(false)` at EOF.
fn read_line_bounded<R: BufRead>(
    r: &mut R,
    buf: &mut Vec<u8>,
    line: u64,
) -> Result<bool, VerifyError> {
    buf.clear();
    let n = r
        .by_ref()
        .take(
            u64::try_from(MAX_LINE_LEN)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(false);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    } else if buf.len() > MAX_LINE_LEN {
        return Err(line_err(line, "line exceeds maximum length"));
    } else {
        return Err(line_err(line, "unterminated final line (torn write)"));
    }
    Ok(true)
}

/// Verifies one audit stream. `prev` is the `(last_sequence, last_hash)` of
/// the file this one continues; `None` for the first file.
///
/// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information)
///
/// # Errors
/// Returns [`VerifyError::Line`] for the first line that is empty,
/// unparsable (including a malformed hash), out of sequence or whose hash
/// does not chain; [`VerifyError::Io`] when reading fails.
pub fn verify_reader<R: Read>(
    reader: R,
    prev: Option<(u64, [u8; 48])>,
) -> Result<VerifyReport, VerifyError> {
    let mut r = BufReader::new(reader);
    let mut buf = Vec::new();
    let mut line: u64 = 0;
    let mut report = VerifyReport {
        records: 0,
        first_sequence: None,
        last_sequence: None,
        last_hash: String::new(),
        anchored: true,
        drop_markers: 0,
    };
    let mut last: Option<(u64, [u8; 48])> = prev;
    loop {
        line = line.saturating_add(1);
        if !read_line_bounded(&mut r, &mut buf, line)? {
            break;
        }
        if buf.is_empty() {
            return Err(line_err(line, "empty line"));
        }
        let record: AuditRecord = parse_canonical(&buf).map_err(|e| line_err(line, e))?;
        match last {
            Some((seq, hash)) => {
                if record.sequence != seq.wrapping_add(1) {
                    return Err(line_err(
                        line,
                        format!(
                            "sequence gap: expected {}, found {}",
                            seq.wrapping_add(1),
                            record.sequence
                        ),
                    ));
                }
                if !record.verify(&hash) {
                    return Err(line_err(line, "hash chain mismatch"));
                }
            }
            None if record.sequence == 0 => {
                if !record.verify(&[0u8; 48]) {
                    return Err(line_err(line, "hash chain mismatch at genesis"));
                }
            }
            None => {
                // Rotated file: records carry no prev_hash, so the first
                // link cannot be checked.
                report.anchored = false;
            }
        }
        if matches!(record.event, AuditEvent::AuditRecordsDropped(_)) {
            report.drop_markers = report.drop_markers.saturating_add(1);
        }
        report.records = report.records.saturating_add(1);
        report.first_sequence.get_or_insert(record.sequence);
        report.last_sequence = Some(record.sequence);
        last = Some((record.sequence, record.hash_chain));
    }
    if report.records > 0
        && let Some((_, hash)) = last
    {
        report.last_hash = hex::encode(hash);
    }
    Ok(report)
}

/// Verifies one audit file.
///
/// # Errors
/// See [`verify_reader`].
pub fn verify_file(path: &Path) -> Result<VerifyReport, VerifyError> {
    verify_reader(std::fs::File::open(path)?, None)
}

/// Verifies files in order, each continuing the previous one's chain.
///
/// # Errors
/// See [`verify_reader`]; the error is for the first failing file (its
/// index is the length of the reports a caller has printed so far).
pub fn verify_files(paths: &[&Path]) -> Result<Vec<VerifyReport>, (usize, VerifyError)> {
    let mut reports = Vec::with_capacity(paths.len());
    let mut prev: Option<(u64, [u8; 48])> = None;
    for (i, path) in paths.iter().enumerate() {
        let file = std::fs::File::open(path).map_err(|e| (i, VerifyError::Io(e)))?;
        let report = verify_reader(file, prev).map_err(|e| (i, e))?;
        if let Some(seq) = report.last_sequence {
            let mut hash = [0u8; 48];
            hex::decode_to_slice(&report.last_hash, &mut hash)
                .map_err(|e| (i, line_err(0, format!("internal: {e}"))))?;
            prev = Some((seq, hash));
        }
        reports.push(report);
    }
    Ok(reports)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::event::{AuditDropReason, AuditRecordsDropped, SystemShutdown};

    fn ev(i: u64) -> AuditEvent {
        AuditEvent::SystemShutdown(SystemShutdown {
            reason: format!("r{i}"),
            graceful: true,
        })
    }

    /// `n` chained records starting at `first`, continuing `prev`.
    fn chain(first: u64, n: u64, prev: [u8; 48]) -> (Vec<String>, [u8; 48]) {
        let mut prev = prev;
        let mut lines = Vec::new();
        for seq in first..first + n {
            let event = if seq == first + 1 {
                AuditEvent::AuditRecordsDropped(AuditRecordsDropped {
                    count: 1,
                    total: 1,
                    reason: AuditDropReason::QueueFull,
                })
            } else {
                ev(seq)
            };
            let r = AuditRecord::new(seq, event, chrono::Utc::now(), prev);
            prev = r.hash_chain;
            lines.push(serde_json::to_string(&r).unwrap());
        }
        (lines, prev)
    }

    fn text(lines: &[String]) -> String {
        let mut s = lines.join("\n");
        s.push('\n');
        s
    }

    fn check(lines: &[String]) -> Result<VerifyReport, VerifyError> {
        verify_reader(text(lines).as_bytes(), None)
    }

    fn failing_line(r: Result<VerifyReport, VerifyError>) -> u64 {
        match r {
            Err(VerifyError::Line { line, .. }) => line,
            other => panic!("expected a line error, got {other:?}"),
        }
    }

    #[test]
    fn verify_ok() {
        let (lines, last) = chain(0, 5, [0u8; 48]);
        let r = check(&lines).unwrap();
        assert_eq!(r.records, 5);
        assert_eq!(r.first_sequence, Some(0));
        assert_eq!(r.last_sequence, Some(4));
        assert!(r.anchored);
        assert_eq!(r.drop_markers, 1);
        assert_eq!(r.last_hash, hex::encode(last));
        let empty = verify_reader(&b""[..], None).unwrap();
        assert_eq!(empty.records, 0);
    }

    #[test]
    fn tamper_one_byte_detected() {
        let (mut lines, _) = chain(0, 4, [0u8; 48]);
        lines[2] = lines[2].replacen("\"r2\"", "\"r9\"", 1);
        assert_eq!(failing_line(check(&lines)), 3);
    }

    #[test]
    fn deleted_line_detected() {
        let (mut lines, _) = chain(0, 4, [0u8; 48]);
        lines.remove(1);
        assert_eq!(failing_line(check(&lines)), 2);
    }

    #[test]
    fn reordered_lines_detected() {
        let (mut lines, _) = chain(0, 4, [0u8; 48]);
        lines.swap(1, 2);
        assert_eq!(failing_line(check(&lines)), 2);
    }

    #[test]
    fn bad_hex_line_reported_not_panic() {
        let (mut lines, _) = chain(0, 3, [0u8; 48]);
        let mut v: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        v["hash_chain"] = serde_json::Value::String("\u{e9}".repeat(48));
        lines[1] = v.to_string();
        match check(&lines) {
            Err(VerifyError::Line { line: 2, reason }) => {
                assert!(reason.starts_with("bad record"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
        lines[1] = "{not json".to_string();
        assert_eq!(failing_line(check(&lines)), 2);
        lines[1] = String::new();
        assert_eq!(failing_line(check(&lines)), 2);
    }

    #[test]
    fn unanchored_start_accepted_links_checked() {
        let (lines, _) = chain(10, 4, [7u8; 48]);
        let r = check(&lines).unwrap();
        assert!(!r.anchored);
        assert_eq!(r.first_sequence, Some(10));
        let mut tampered = lines;
        tampered[3] = tampered[3].replacen("\"r13\"", "\"r99\"", 1);
        assert_eq!(failing_line(check(&tampered)), 4);
        // Sequence 0 must verify against genesis.
        let (bad_genesis, _) = chain(0, 2, [7u8; 48]);
        assert_eq!(failing_line(check(&bad_genesis)), 1);
    }

    #[test]
    fn multi_file_continuation() {
        let dir = tempfile::tempdir().unwrap();
        let (a, last) = chain(0, 3, [0u8; 48]);
        let (b, _) = chain(3, 3, last);
        let pa = dir.path().join("a.log");
        let pb = dir.path().join("b.log");
        std::fs::write(&pa, text(&a)).unwrap();
        std::fs::write(&pb, text(&b)).unwrap();
        let reports = verify_files(&[&pa, &pb]).unwrap();
        assert_eq!(reports.len(), 2);
        assert!(reports[1].anchored);
        assert_eq!(reports[1].last_sequence, Some(5));
        // Wrong order: b does not continue a's predecessor.
        let err = verify_files(&[&pb, &pa]).unwrap_err();
        assert_eq!(err.0, 1);
        // b alone is an unanchored continuation.
        assert!(!verify_file(&pb).unwrap().anchored);
    }

    #[test]
    fn long_line_rejected() {
        let long = "x".repeat(MAX_LINE_LEN + 10);
        assert_eq!(
            failing_line(verify_reader(format!("{long}\n").as_bytes(), None)),
            1
        );
    }

    #[test]
    fn torn_final_line_rejected() {
        let (lines, _) = chain(0, 2, [0u8; 48]);
        let mut t = text(&lines);
        t.push_str("{\"sequence\":2");
        assert_eq!(failing_line(verify_reader(t.as_bytes(), None)), 3);
    }

    #[test]
    fn non_canonical_bytes_rejected() {
        let (lines, _) = chain(0, 3, [0u8; 48]);
        assert!(check(&lines).is_ok());
        let reason = |r: Result<VerifyReport, VerifyError>| match r {
            Err(VerifyError::Line { line: 2, reason }) => reason,
            other => panic!("expected line 2 error, got {other:?}"),
        };
        let mutate = |f: &dyn Fn(&str) -> String| {
            let mut l = lines.clone();
            l[1] = f(&l[1]);
            check(&l)
        };
        // Extra top-level key (deny_unknown_fields).
        let r = reason(mutate(&|l| l.replacen('{', "{\"note\":\"approved\",", 1)));
        assert!(r.starts_with("bad record"), "{r}");
        // Extra key inside the event: serde ignores it, the bytes check
        // does not.
        let r = reason(mutate(&|l| {
            l.replacen("\"type\":", "\"actor\":\"admin\",\"type\":", 1)
        }));
        assert!(r.contains("canonical"), "{r}");
        // Reordered keys (serde_json::Value sorts them).
        let r = reason(mutate(&|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .unwrap()
                .to_string()
        }));
        assert!(r.contains("canonical"), "{r}");
        // Same instant, alternate offset spelling.
        let r = reason(mutate(&|l| l.replacen("Z\"", "+00:00\"", 1)));
        assert!(r.contains("canonical"), "{r}");
        // Whitespace.
        let r = reason(mutate(&|l| l.replacen(':', ": ", 1)));
        assert!(r.contains("canonical"), "{r}");
    }
}
