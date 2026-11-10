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
use crate::record::{CallRecord, FileHeader, is_readable_schema};
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
    if header.kind != "header" || !is_readable_schema(header.schema_version) {
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
        // A file holds one schema version (the writer opens a new file on
        // start); v1..v4 files are all readable.
        if rec.schema_version != header.schema_version {
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
    use crate::record::{Attestation, MediaKindTag, RecordingTag, SCHEMA_VERSION, Verstat};

    /// A v1 file (header and records at schema 1, no v2 fields) written by
    /// the previous release still verifies: unset v2 fields are not
    /// serialised, so the chain hash is unchanged.
    #[test]
    fn v1_file_still_verifies() {
        let mut h = new_header("n1", 0, to_hex(&GENESIS), 0);
        h.schema_version = 1;
        let mut out = header_json_line(&h).unwrap();
        out.push('\n');
        let mut r = CallRecord {
            schema_version: 1,
            node_id: "n1".into(),
            record_id: "n1-0".into(),
            stir_attestation: Some(Attestation::B),
            ..Default::default()
        };
        seal(&mut r, &GENESIS).unwrap();
        let line = to_json_line(&r).unwrap();
        assert!(!line.contains("stir_verstat"), "{line}");
        out.push_str(&line);
        out.push('\n');
        assert_eq!(verify_reader(out.as_bytes()).unwrap().records, 1);
    }

    #[test]
    fn v2_fields_roundtrip_in_chain() {
        let mut out = header_json_line(&new_header("n1", 0, to_hex(&GENESIS), 0)).unwrap();
        out.push('\n');
        let mut r = CallRecord {
            schema_version: SCHEMA_VERSION,
            node_id: "n1".into(),
            record_id: "n1-0".into(),
            stir_verstat: Some(Verstat::TnValidationFailed),
            stir_verify_reason: Some("bad-signature".into()),
            stir_inbound_attestation: Some(Attestation::A),
            stir_x5u_host: Some("cert.example.invalid".into()),
            ..Default::default()
        };
        seal(&mut r, &GENESIS).unwrap();
        let line = to_json_line(&r).unwrap();
        assert!(
            line.contains(r#""stir_verstat":"tn-validation-failed""#),
            "{line}"
        );
        out.push_str(&line);
        out.push('\n');
        assert_eq!(verify_reader(out.as_bytes()).unwrap().records, 1);
        // Mixed versions in one file are rejected.
        let mut bad = header_json_line(&new_header("n1", 0, to_hex(&GENESIS), 0)).unwrap();
        bad.push('\n');
        let mut r1 = r.clone();
        r1.schema_version = 1;
        seal(&mut r1, &GENESIS).unwrap();
        bad.push_str(&to_json_line(&r1).unwrap());
        bad.push('\n');
        assert!(verify_reader(bad.as_bytes()).is_err());
    }

    /// QA: one chained file per version, `first` sequence and chain start.
    fn versioned_file(
        version: u16,
        first: u64,
        n: u64,
        start: [u8; HASH_LEN],
    ) -> (String, [u8; HASH_LEN]) {
        let mut h = new_header("n1", 0, to_hex(&start), first);
        h.schema_version = version;
        let mut out = header_json_line(&h).unwrap();
        out.push('\n');
        let mut prev = start;
        for i in first..first + n {
            let mut r = CallRecord {
                schema_version: version,
                node_id: "n1".into(),
                sequence: i,
                record_id: format!("n1-{i}"),
                ..Default::default()
            };
            if version >= 2 {
                r.stir_verstat = Some(Verstat::TnValidationPassed);
                r.stir_inbound_attestation = Some(Attestation::A);
                r.stir_x5u_host = Some("cert.example.invalid".into());
            }
            if version >= 3 {
                r.media_kinds = vec![MediaKindTag::Audio, MediaKindTag::Image];
            }
            if version >= 4 {
                r.recording = Some(RecordingTag::Recorded);
                r.recording_session_id = Some("rs-0001".into());
            }
            prev = seal(&mut r, &prev).unwrap();
            out.push_str(&to_json_line(&r).unwrap());
            out.push('\n');
        }
        (out, prev)
    }

    /// QA: upgrade path. A v1 file followed by a v2 file that continues its
    /// chain verifies as one sequence (what `sbc-cli cdrs verify` runs).
    #[test]
    fn qa_v1_then_v2_files_verify_across_upgrade() {
        let dir = tempfile::tempdir().unwrap();
        let (v1, last) = versioned_file(1, 0, 3, GENESIS);
        let (v2, _) = versioned_file(SCHEMA_VERSION, 3, 2, last);
        let p1 = dir.path().join("a.jsonl");
        let p2 = dir.path().join("b.jsonl");
        std::fs::write(&p1, v1).unwrap();
        std::fs::write(&p2, &v2).unwrap();
        let reps = verify_files(&[p1.as_path(), p2.as_path()]).unwrap();
        assert_eq!(reps.iter().map(|r| r.records).sum::<u64>(), 5);

        // A v2 file that does not continue the v1 chain is rejected.
        let (v2_bad, _) = versioned_file(SCHEMA_VERSION, 3, 2, GENESIS);
        std::fs::write(&p2, v2_bad).unwrap();
        assert!(verify_files(&[p1.as_path(), p2.as_path()]).is_err());
    }

    /// QA: tampering with any v2 STIR field breaks the record hash.
    #[test]
    fn qa_v2_stir_field_tamper_detected() {
        let (good, _) = versioned_file(SCHEMA_VERSION, 0, 2, GENESIS);
        assert_eq!(verify_reader(good.as_bytes()).unwrap().records, 2);
        for (from, to) in [
            ("tn-validation-passed", "tn-validation-failed"),
            (
                r#""stir_inbound_attestation":"A""#,
                r#""stir_inbound_attestation":"C""#,
            ),
            ("cert.example.invalid", "evil.example.invalid"),
        ] {
            let bad = good.replacen(from, to, 1);
            assert_ne!(bad, good, "{from}");
            assert!(
                verify_reader(bad.as_bytes()).is_err(),
                "{from} tamper accepted"
            );
        }
        // Stripping a v2 field entirely is also detected.
        let stripped = good.replacen(r#","stir_x5u_host":"cert.example.invalid""#, "", 1);
        assert_ne!(stripped, good);
        assert!(verify_reader(stripped.as_bytes()).is_err());
    }

    /// v1 and v2 files followed by a v3 file continuing the chain verify,
    /// and tampering with or stripping `media_kinds` is detected.
    #[test]
    fn v2_then_v3_media_kinds_chain() {
        let (v1, last) = versioned_file(1, 0, 1, GENESIS);
        let (v2, last) = versioned_file(2, 1, 1, last);
        let (v3, _) = versioned_file(3, 2, 2, last);
        assert!(!v2.contains("media_kinds"));
        assert!(!v3.contains("recording"));
        assert!(v3.contains(r#""media_kinds":["audio","image"]"#), "{v3}");
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<_> = [v1, v2, v3.clone()]
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let p = dir.path().join(format!("{i}.jsonl"));
                std::fs::write(&p, f).unwrap();
                p
            })
            .collect();
        let path_refs: Vec<_> = paths.iter().map(std::path::PathBuf::as_path).collect();
        let reps = verify_files(&path_refs).unwrap();
        assert_eq!(reps.iter().map(|r| r.records).sum::<u64>(), 4);

        let tampered = v3.replacen(r#"["audio","image"]"#, r#"["audio"]"#, 1);
        assert!(verify_reader(tampered.as_bytes()).is_err());
        let stripped = v3.replacen(r#","media_kinds":["audio","image"]"#, "", 1);
        assert_ne!(stripped, v3);
        assert!(verify_reader(stripped.as_bytes()).is_err());
    }

    /// QA (POA&M-294): every edit to `media_kinds` in a sealed v3 record
    /// (reorder, add, inject an unknown tag) breaks verification or parsing.
    #[test]
    fn qa_v3_media_kinds_edits_detected() {
        let (v3, _) = versioned_file(SCHEMA_VERSION, 0, 2, GENESIS);
        assert!(verify_reader(v3.as_bytes()).is_ok());
        for (from, to) in [
            (r#"["audio","image"]"#, r#"["image","audio"]"#),
            (r#"["audio","image"]"#, r#"["audio","image","audio"]"#),
            (r#"["audio","image"]"#, r#"["audio","video"]"#),
            (r#"["audio","image"]"#, "[]"),
        ] {
            let t = v3.replacen(from, to, 1);
            assert_ne!(t, v3);
            assert!(verify_reader(t.as_bytes()).is_err(), "{to} accepted");
        }
    }

    /// v1, v2 and v3 files written by earlier releases, followed by a v4
    /// file continuing the chain, verify as one sequence; the v4 recording
    /// fields are inside the hash (AU-9): editing or stripping them is
    /// detected.
    #[test]
    fn v3_then_v4_recording_chain() {
        assert_eq!(SCHEMA_VERSION, 4);
        let (v1, last) = versioned_file(1, 0, 1, GENESIS);
        let (v2, last) = versioned_file(2, 1, 1, last);
        let (v3, last) = versioned_file(3, 2, 2, last);
        let (v4, _) = versioned_file(SCHEMA_VERSION, 4, 2, last);
        assert!(!v3.contains("recording"), "{v3}");
        assert!(
            v4.contains(r#""recording":"recorded","recording_session_id":"rs-0001""#),
            "{v4}"
        );
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<_> = [v1, v2, v3.clone(), v4.clone()]
            .iter()
            .enumerate()
            .map(|(i, f)| {
                let p = dir.path().join(format!("{i}.jsonl"));
                std::fs::write(&p, f).unwrap();
                p
            })
            .collect();
        let path_refs: Vec<_> = paths.iter().map(std::path::PathBuf::as_path).collect();
        let reps = verify_files(&path_refs).unwrap();
        assert_eq!(reps.iter().map(|r| r.records).sum::<u64>(), 6);

        // A v4 file that does not continue the v3 chain is rejected.
        let (v4_bad, _) = versioned_file(SCHEMA_VERSION, 4, 2, GENESIS);
        std::fs::write(&paths[3], v4_bad).unwrap();
        assert!(verify_files(&path_refs).is_err());

        assert_eq!(verify_reader(v4.as_bytes()).unwrap().records, 2);
        for (from, to) in [
            // Claim a failed/unrecorded call was recorded, and the reverse.
            (r#""recording":"recorded""#, r#""recording":"failed""#),
            (r#""recording":"recorded""#, r#""recording":"partial""#),
            (r#""recording":"recorded""#, r#""recording":"opt_out""#),
            // Unknown tag: refused by the parser.
            (r#""recording":"recorded""#, r#""recording":"yes""#),
            // Point the record at another recording session.
            ("rs-0001", "rs-0002"),
            // Strip either field, or both.
            (r#""recording":"recorded","#, ""),
            (r#","recording_session_id":"rs-0001""#, ""),
            (
                r#""recording":"recorded","recording_session_id":"rs-0001","#,
                "",
            ),
        ] {
            let t = v4.replacen(from, to, 1);
            assert_ne!(t, v4, "{from}");
            assert!(
                verify_reader(t.as_bytes()).is_err(),
                "{from} -> {to} accepted"
            );
        }

        // Adding the field to a sealed v3 record is detected too.
        let added = v3.replacen(
            r#""failover_takeover""#,
            r#""recording":"recorded","failover_takeover""#,
            1,
        );
        assert_ne!(added, v3);
        assert!(verify_reader(added.as_bytes()).is_err());
    }

    /// QA: a v4 file with one record per `recording` tag (the `failed` one
    /// released with cause `recording_failure`), continuing a chain at
    /// `last` with sequence 6.
    fn v4_recording_file(last: [u8; HASH_LEN]) -> String {
        let mut h = new_header("node-a", 1_700_000_100_000, to_hex(&last), 6);
        assert_eq!(h.schema_version, 4);
        h.schema_version = SCHEMA_VERSION;
        let mut v4 = header_json_line(&h).unwrap();
        v4.push('\n');
        let mut prev = last;
        for (i, tag) in [
            RecordingTag::Recorded,
            RecordingTag::Partial,
            RecordingTag::Failed,
            RecordingTag::NotRecordable,
            RecordingTag::OptOut,
        ]
        .into_iter()
        .enumerate()
        {
            let seq = 6 + i as u64;
            let mut r = CallRecord {
                schema_version: SCHEMA_VERSION,
                node_id: "node-a".into(),
                sequence: seq,
                record_id: format!("node-a-{seq}"),
                recording: Some(tag),
                recording_session_id: (tag != RecordingTag::OptOut)
                    .then(|| format!("0b0e7f8c-6c0c-4d53-9f0a-2a1d2c3b4e{seq:02}")),
                ..Default::default()
            };
            if tag == RecordingTag::Failed {
                r.disposition = crate::record::Disposition::RecordingFailure;
                r.release_cause = crate::record::ReleaseCause::RecordingFailure;
            }
            prev = seal(&mut r, &prev).unwrap();
            let line = to_json_line(&r).unwrap();
            assert!(
                line.contains(&format!(r#""recording":"{}""#, tag.as_str())),
                "{line}"
            );
            v4.push_str(&line);
            v4.push('\n');
        }
        assert!(v4.contains(r#""release_cause":"recording_failure""#));
        v4
    }

    /// QA (AU-9, upgrade path): known-answer files. The three fixtures were
    /// written by the previous release's code (origin/main 748097f, schema
    /// v1, v2 and v3 headers, one chain across the three files). They are
    /// frozen bytes, not regenerated by this build, so this fails if the v4
    /// serializer or hash input changes anything for an old record:
    ///
    /// - the files verify as one chain under the v4 reader;
    /// - each record line parses and re-serialises byte-identically (no
    ///   `recording` key appears in an old record);
    /// - a v4 file with `recording` fields continues the chain;
    /// - editing an old record, or grafting a `recording` claim onto one,
    ///   is detected.
    #[test]
    fn qa_files_from_release_748097f_verify_and_chain_into_v4() {
        const V1: &str = include_str!("../tests/fixtures/cdr-v1-release-748097f.jsonl");
        const V2: &str = include_str!("../tests/fixtures/cdr-v2-release-748097f.jsonl");
        const V3: &str = include_str!("../tests/fixtures/cdr-v3-release-748097f.jsonl");
        // The last hash of the v3 file, as the previous release wrote it.
        const LAST: &str = "121485261606a7c639aeb554bcca739163d422fc0759444fab8ee0c22fa6c830\
                            eee8313e4e20fa4842a35e87056c7169";

        for (version, file) in [(1u16, V1), (2, V2), (3, V3)] {
            assert_eq!(
                verify_reader(file.as_bytes()).unwrap().records,
                2,
                "v{version}"
            );
            assert!(!file.contains("recording"), "v{version}");
            for line in file.lines().skip(1) {
                let r: CallRecord = serde_json::from_str(line).unwrap();
                assert_eq!(r.schema_version, version);
                assert_eq!(r.recording, None);
                assert_eq!(r.recording_session_id, None);
                assert_eq!(
                    to_json_line(&r).unwrap(),
                    line,
                    "v{version} re-serialises as written"
                );
            }
        }
        assert!(V3.trim_end().ends_with(&format!(r#""hash":"{LAST}"}}"#)));

        // A v4 file (this release) continuing the old chain.
        let v4 = v4_recording_file(from_hex(LAST).unwrap());

        let dir = tempfile::tempdir().unwrap();
        let write = |name: &str, text: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, text).unwrap();
            p
        };
        let paths = [
            write("1.jsonl", V1),
            write("2.jsonl", V2),
            write("3.jsonl", V3),
            write("4.jsonl", &v4),
        ];
        let path_refs: Vec<_> = paths.iter().map(std::path::PathBuf::as_path).collect();
        let reps = verify_files(&path_refs).unwrap();
        assert_eq!(reps.iter().map(|r| r.records).sum::<u64>(), 11);
        // Out of order, or with a file missing, the chain does not verify.
        assert!(verify_files(&[path_refs[0], path_refs[2], path_refs[3]]).is_err());
        assert!(verify_files(&[path_refs[1], path_refs[0]]).is_err());

        // Tampering with a legacy record, including grafting a recording
        // claim onto a call that predates recording, is detected.
        for (from, to) in [
            (r#""caller":"+15550000004""#, r#""caller":"+15550009999""#),
            (
                r#""failover_takeover":false"#,
                r#""recording":"recorded","failover_takeover":false"#,
            ),
            (
                r#""failover_takeover":false"#,
                r#""recording_session_id":"x","failover_takeover":false"#,
            ),
            (r#""media_kinds":["audio","image"],"#, ""),
        ] {
            let t = V3.replacen(from, to, 1);
            assert_ne!(t, V3, "{from}");
            assert!(verify_reader(t.as_bytes()).is_err(), "{to} accepted");
        }
        // A legacy file relabelled as v4 (header and records) is detected:
        // the version is inside the hash.
        let relabelled = V3.replace(r#""schema_version":3"#, r#""schema_version":4"#);
        assert!(verify_reader(relabelled.as_bytes()).is_err());
    }

    /// QA: future (v5) and zero schema headers are refused.
    #[test]
    fn qa_unknown_schema_versions_rejected() {
        for v in [0, SCHEMA_VERSION + 1] {
            let (f, _) = versioned_file(v, 0, 1, GENESIS);
            assert!(verify_reader(f.as_bytes()).is_err(), "schema {v} accepted");
        }
    }

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
