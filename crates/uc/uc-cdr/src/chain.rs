//! SHA-384 hash chain over canonical JSON records, and offline verification.
//!
//! `hash = SHA-384(prev_hash_bytes || canonical_json(record with hash = ""))`
//! where `record.prev_hash` is already set to the hex of `prev_hash_bytes`.
//! Each JSONL file starts with a [`FileHeader`] whose `chain_start` is the
//! hash the first record chains from, so consecutive files link up.
//!
//! The chain is unkeyed and unsigned, so it is tamper-evident only: it
//! detects edits, deletions and reordering by anyone who does not also
//! recompute the chain and sidecars. Someone with write access to the CDR
//! directory can rewrite all three. It is anchored off-host only when the
//! per-file digest (`CdrFileRotated` uc-audit event) reaches a chained,
//! forwarded audit log, or records go to the syslog sink (AU-9(2)).
//!
//! ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information; partial, tamper-evident only)
//! CNSA 2.0: SHA-384 via `uc-crypto` only.
// POAM: no non-repudiation (AU-10). Sign file headers/sidecars with
// ML-DSA-87 (CNSA 2.0) or key the chain (HMAC-SHA-384 with a managed key)
// so a record is bound to the node that wrote it.

use crate::error::{CdrError, CdrResult};
use crate::record::{CallRecord, FileHeader, SCHEMA_VERSION};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use uc_crypto::hash::Sha384;

/// SHA-384 output length.
pub const HASH_LEN: usize = 48;

/// Chain value before the first record ever written by a node.
pub const GENESIS: [u8; HASH_LEN] = [0u8; HASH_LEN];

/// Longest line accepted when reading a CDR file.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
pub const MAX_LINE_LEN: usize = 64 * 1024;

/// Lowercase hex encoding.
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// Decodes a 96-char hex SHA-384 value.
pub fn from_hex(s: &str) -> Option<[u8; HASH_LEN]> {
    let b = s.as_bytes();
    if b.len() != HASH_LEN * 2 {
        return None;
    }
    let mut out = [0u8; HASH_LEN];
    for (i, [h, l]) in b.as_chunks::<2>().0.iter().enumerate() {
        let hi = hex_val(*h)?;
        let lo = hex_val(*l)?;
        *out.get_mut(i)? = (hi << 4) | lo;
    }
    Some(out)
}

const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Computes the chain hash of `record` (its `hash` field is ignored).
pub fn compute_hash(prev: &[u8; HASH_LEN], record: &CallRecord) -> CdrResult<[u8; HASH_LEN]> {
    let mut canonical = record.clone();
    canonical.hash.clear();
    let json = serde_json::to_vec(&canonical)?;
    let mut h = Sha384::new();
    h.update(prev);
    h.update(&json);
    Ok(h.finish())
}

/// Sets `prev_hash`/`hash` on `record` and returns the new chain value.
///
/// ## NIST 800-53 Rev5: AU-9 (tamper-evident chain)
pub fn seal(record: &mut CallRecord, prev: &[u8; HASH_LEN]) -> CdrResult<[u8; HASH_LEN]> {
    record.prev_hash = to_hex(prev);
    record.hash.clear();
    let h = compute_hash(prev, record)?;
    record.hash = to_hex(&h);
    Ok(h)
}

/// Result of verifying one or more JSONL CDR files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Records checked.
    pub records: u64,
    /// Node id from the header.
    pub node_id: String,
    /// Sequence of the first record (or the header's `first_sequence`).
    pub first_sequence: u64,
    /// Sequence of the last record, if any.
    pub last_sequence: Option<u64>,
    /// Header `chain_start` (hex; empty when chaining is off).
    pub chain_start: String,
    /// Last chain value (hex; equals `chain_start` when the file is empty).
    pub last_hash: String,
    /// Whether the file carries a hash chain.
    pub chained: bool,
}

/// Reads one line of at most [`MAX_LINE_LEN`] bytes. `Ok(None)` at EOF.
pub(crate) fn read_line_bounded<R: BufRead>(r: &mut R, buf: &mut Vec<u8>) -> CdrResult<Option<()>> {
    buf.clear();
    let n = r
        .by_ref()
        .take(u64::try_from(MAX_LINE_LEN).unwrap_or(u64::MAX) + 1)
        .read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    } else if buf.len() > MAX_LINE_LEN {
        return Err(CdrError::verify(0, "line exceeds maximum length"));
    }
    Ok(Some(()))
}

/// Verifies a JSONL CDR stream: header, sequence continuity, `prev_hash`
/// linkage and every record hash.
///
/// ## NIST 800-53 Rev5: AU-9 (Protection of Audit Information)
pub fn verify_reader<R: Read>(reader: R) -> CdrResult<VerifyReport> {
    let mut r = BufReader::new(reader);
    let mut buf = Vec::new();
    let mut line_no: u64 = 1;
    if read_line_bounded(&mut r, &mut buf)
        .map_err(|_| CdrError::verify(1, "header line too long"))?
        .is_none()
    {
        return Err(CdrError::verify(1, "empty file (missing header)"));
    }
    let header: FileHeader = serde_json::from_slice(&buf)
        .map_err(|e| CdrError::verify(1, format!("bad header: {e}")))?;
    if header.kind != "header" || header.schema_version != SCHEMA_VERSION {
        return Err(CdrError::verify(1, "unsupported header"));
    }
    let chained = !header.chain_start.is_empty();
    let mut prev = if chained {
        Some(from_hex(&header.chain_start).ok_or_else(|| CdrError::verify(1, "bad chain_start"))?)
    } else {
        None
    };
    let mut report = VerifyReport {
        records: 0,
        node_id: header.node_id.clone(),
        first_sequence: header.first_sequence,
        last_sequence: None,
        chain_start: header.chain_start.clone(),
        last_hash: header.chain_start.clone(),
        chained,
    };
    let mut expect_seq = header.first_sequence;
    loop {
        line_no += 1;
        match read_line_bounded(&mut r, &mut buf) {
            Ok(Some(())) => {}
            Ok(None) => break,
            Err(_) => return Err(CdrError::verify(line_no, "line exceeds maximum length")),
        }
        if buf.is_empty() {
            return Err(CdrError::verify(line_no, "empty line"));
        }
        let rec: CallRecord = serde_json::from_slice(&buf)
            .map_err(|e| CdrError::verify(line_no, format!("bad record: {e}")))?;
        if rec.schema_version != SCHEMA_VERSION {
            return Err(CdrError::verify(line_no, "schema_version mismatch"));
        }
        if rec.node_id != header.node_id {
            return Err(CdrError::verify(line_no, "node_id differs from header"));
        }
        if rec.sequence != expect_seq {
            return Err(CdrError::verify(
                line_no,
                format!(
                    "sequence gap: expected {expect_seq}, found {}",
                    rec.sequence
                ),
            ));
        }
        expect_seq = expect_seq.wrapping_add(1);
        if let Some(p) = prev.as_mut() {
            if rec.prev_hash != to_hex(p) {
                return Err(CdrError::verify(line_no, "prev_hash does not link"));
            }
            let h = compute_hash(p, &rec)?;
            if to_hex(&h) != rec.hash {
                return Err(CdrError::verify(line_no, "record hash mismatch"));
            }
            *p = h;
            report.last_hash.clone_from(&rec.hash);
        } else if !rec.hash.is_empty() || !rec.prev_hash.is_empty() {
            return Err(CdrError::verify(line_no, "hash present in unchained file"));
        }
        report.last_sequence = Some(rec.sequence);
        report.records += 1;
    }
    Ok(report)
}

/// Verifies one JSONL CDR file.
pub fn verify_file(path: &Path) -> CdrResult<VerifyReport> {
    verify_reader(std::fs::File::open(path)?)
}

/// Verifies files in order and checks that each one continues the previous
/// file's chain and sequence. Returns one report per file.
pub fn verify_files(paths: &[&Path]) -> CdrResult<Vec<VerifyReport>> {
    let mut out: Vec<VerifyReport> = Vec::with_capacity(paths.len());
    for path in paths {
        let rep = verify_file(path)?;
        if let Some(prev) = out.last()
            && prev.node_id == rep.node_id
        {
            let expected_start = prev.last_hash.as_str();
            let links = !(prev.chained && rep.chained) || rep.chain_start == expected_start;
            if !links {
                return Err(CdrError::verify(
                    0,
                    format!(
                        "{} does not continue the previous file's chain",
                        path.display()
                    ),
                ));
            }
            let next = prev.last_sequence.map_or(prev.first_sequence, |s| s + 1);
            if rep.first_sequence != next {
                return Err(CdrError::verify(
                    0,
                    format!(
                        "{} sequence does not continue the previous file",
                        path.display()
                    ),
                ));
            }
        }
        out.push(rep);
    }
    Ok(out)
}

/// Streaming SHA-384 of a file.
pub fn file_sha384(path: &Path) -> CdrResult<[u8; HASH_LEN]> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha384::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(buf.get(..n).unwrap_or_default());
    }
    Ok(h.finish())
}

/// Sidecar digest path: `<file>.sha384`.
pub fn sidecar_path(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".sha384");
    std::path::PathBuf::from(s)
}

/// Checks a file against its `.sha384` sidecar (`sha384sum` format).
pub fn verify_sidecar(path: &Path) -> CdrResult<bool> {
    let text = std::fs::read_to_string(sidecar_path(path))?;
    let want = text
        .split_whitespace()
        .next()
        .and_then(from_hex)
        .ok_or_else(|| CdrError::verify(0, "malformed sidecar"))?;
    Ok(file_sha384(path)? == want)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{header_json_line, new_header, to_json_line};

    fn chain_file(n: u64) -> String {
        let mut out = header_json_line(&new_header("n1", 0, to_hex(&GENESIS), 0)).unwrap();
        out.push('\n');
        let mut prev = GENESIS;
        for i in 0..n {
            let mut r = CallRecord {
                schema_version: SCHEMA_VERSION,
                node_id: "n1".into(),
                sequence: i,
                record_id: format!("n1-{i}"),
                caller: format!("100{i}"),
                ..Default::default()
            };
            prev = seal(&mut r, &prev).unwrap();
            out.push_str(&to_json_line(&r).unwrap());
            out.push('\n');
        }
        out
    }

    #[test]
    fn hex_roundtrip() {
        let h = uc_crypto::hash::sha384(b"x");
        assert_eq!(from_hex(&to_hex(&h)), Some(h));
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex(&"g".repeat(96)), None);
    }

    #[test]
    fn verify_ok() {
        let f = chain_file(5);
        let rep = verify_reader(f.as_bytes()).unwrap();
        assert_eq!(rep.records, 5);
        assert_eq!(rep.last_sequence, Some(4));
        assert!(rep.chained);
    }

    #[test]
    fn tamper_one_byte_detected() {
        let f = chain_file(5).replacen("\"caller\":\"1002\"", "\"caller\":\"1009\"", 1);
        let err = verify_reader(f.as_bytes()).unwrap_err();
        assert!(matches!(err, CdrError::Verify { line: 4, .. }), "{err}");
    }

    #[test]
    fn deleted_line_detected() {
        let f = chain_file(5);
        let mut lines: Vec<&str> = f.lines().collect();
        lines.remove(3);
        let f = lines.join("\n") + "\n";
        assert!(verify_reader(f.as_bytes()).is_err());
    }

    #[test]
    fn hash_recomputed_by_attacker_still_breaks_link() {
        // Change a record and recompute its own hash: the next record's
        // prev_hash no longer links.
        let f = chain_file(3);
        let mut lines: Vec<String> = f.lines().map(String::from).collect();
        let mut r: CallRecord = serde_json::from_str(&lines[1]).unwrap();
        r.caller = "evil".into();
        seal(&mut r, &GENESIS).unwrap();
        lines[1] = to_json_line(&r).unwrap();
        let f = lines.join("\n") + "\n";
        let err = verify_reader(f.as_bytes()).unwrap_err();
        assert!(matches!(err, CdrError::Verify { line: 3, .. }), "{err}");
    }

    #[test]
    fn missing_header_and_long_line_rejected() {
        assert!(verify_reader(&b""[..]).is_err());
        let long = "x".repeat(MAX_LINE_LEN + 10);
        assert!(verify_reader(long.as_bytes()).is_err());
    }
}
