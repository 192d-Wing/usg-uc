//! CDR output formats: JSON lines (canonical) and fixed-column CSV.
//!
//! JSON goes through `serde_json`, which escapes every control character
//! U+0000-U+001F as RFC 8259 §7 requires, so attacker-controlled SIP values
//! cannot break a line. CSV follows RFC 4180 quoting and neutralizes spreadsheet
//! formula injection (CWE-1236).
//!
//! ## NIST 800-53 Rev5: AU-3 (Content of Audit Records), SI-10 (Information Input Validation)

use crate::error::CdrResult;
use crate::record::{CallRecord, FileHeader, SCHEMA_VERSION};
use std::fmt::Write as _;

/// On-disk file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CdrFormat {
    /// One JSON object per line (default; carries the hash chain).
    #[default]
    Jsonl,
    /// Fixed v1 column set, RFC 4180.
    Csv,
}

impl CdrFormat {
    /// File extension without the dot.
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Jsonl => "jsonl",
            Self::Csv => "csv",
        }
    }
}

/// Serializes a record as one canonical JSON line (no trailing newline).
pub fn to_json_line(record: &CallRecord) -> CdrResult<String> {
    Ok(serde_json::to_string(record)?)
}

/// Serializes a file header line (no trailing newline).
pub fn header_json_line(header: &FileHeader) -> CdrResult<String> {
    Ok(serde_json::to_string(header)?)
}

/// Fixed v2 CSV columns, in order. `sequence` is the second column and
/// `hash` the last so the writer can resume from a file's last row.
///
/// v2 inserts the four `stir_*` verification columns after
/// `failover_takeover` (before the hash pair, which must stay last).
pub const CSV_COLUMNS: &[&str] = &[
    "schema_version",
    "sequence",
    "record_id",
    "node_id",
    "a_call_id",
    "b_call_ids",
    "internal_call_id",
    "direction",
    "caller",
    "callee_dialed",
    "callee_translated",
    "caller_translated",
    "source_ip",
    "source_port",
    "transport",
    "ingress_zone",
    "egress_zone",
    "trunk_group",
    "trunks_tried",
    "final_trunk",
    "failover_count",
    "setup_ms",
    "ring_ms",
    "answer_ms",
    "end_ms",
    "duration_ms",
    "pdd_ms",
    "disposition",
    "final_sip_status",
    "release_side",
    "release_cause",
    "q850_cause",
    "media_node",
    "media_anchored",
    "codec",
    "srtp",
    "emergency",
    "stir_attestation",
    "failover_takeover",
    "stir_verstat",
    "stir_verify_reason",
    "stir_inbound_attestation",
    "stir_x5u_host",
    "prev_hash",
    "hash",
];

/// Number of CSV columns in schema v1 (readers accept both widths).
pub const CSV_COLUMNS_V1: usize = 41;

/// CSV header row (no trailing newline).
pub fn csv_header() -> String {
    CSV_COLUMNS.join(",")
}

/// CSV comment line that opens each file (no trailing newline).
pub fn csv_comment(header: &FileHeader) -> String {
    let mut s = String::from("# usg-sbc cdr");
    // node_id is validated filename-safe, hashes are hex: no escaping needed.
    let _ = write!(
        s,
        " schema_version={} node_id={} created_ms={} chain_start={} first_sequence={}",
        header.schema_version,
        header.node_id,
        header.created_ms,
        header.chain_start,
        header.first_sequence
    );
    s
}

/// Escapes one CSV field.
///
/// Values starting with `= + - @ TAB CR` get a leading `'` so spreadsheets do
/// not evaluate them (CWE-1236). Values containing `,` `"` CR or LF are quoted,
/// with embedded quotes doubled (RFC 4180 §2).
///
/// ## NIST 800-53 Rev5: SI-10 (Information Input Validation)
pub fn csv_field(value: &str, out: &mut String) {
    let guard = matches!(
        value.as_bytes().first(),
        Some(b'=' | b'+' | b'-' | b'@' | b'\t' | b'\r')
    );
    let quote = value
        .bytes()
        .any(|b| matches!(b, b',' | b'"' | b'\r' | b'\n'));
    if quote {
        out.push('"');
    }
    if guard {
        out.push('\'');
    }
    for c in value.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    if quote {
        out.push('"');
    }
}

fn push_opt(value: Option<&str>, out: &mut String) {
    if let Some(v) = value {
        csv_field(v, out);
    }
}

fn push_num<T: std::fmt::Display>(value: T, out: &mut String) {
    let _ = write!(out, "{value}");
}

fn push_opt_num<T: std::fmt::Display>(value: Option<T>, out: &mut String) {
    if let Some(v) = value {
        push_num(v, out);
    }
}

/// Serializes a record as one CSV row (no trailing newline).
///
/// List fields (`b_call_ids`, `trunks_tried`) are embedded as JSON arrays so
/// they stay unambiguous inside one column.
pub fn to_csv_row(r: &CallRecord) -> CdrResult<String> {
    let mut out = String::with_capacity(512);
    let b_ids = serde_json::to_string(&r.b_call_ids)?;
    let tried = serde_json::to_string(&r.trunks_tried)?;
    let stir = r.stir_attestation.map(crate::record::Attestation::as_str);
    let mut first = true;
    let mut sep = |out: &mut String| {
        if !first {
            out.push(',');
        }
        first = false;
    };
    macro_rules! col {
        ($e:expr) => {{
            sep(&mut out);
            $e;
        }};
    }
    col!(push_num(r.schema_version, &mut out));
    col!(push_num(r.sequence, &mut out));
    col!(csv_field(&r.record_id, &mut out));
    col!(csv_field(&r.node_id, &mut out));
    col!(csv_field(&r.a_call_id, &mut out));
    col!(csv_field(&b_ids, &mut out));
    col!(csv_field(&r.internal_call_id, &mut out));
    col!(out.push_str(r.direction.as_str()));
    col!(csv_field(&r.caller, &mut out));
    col!(csv_field(&r.callee_dialed, &mut out));
    col!(push_opt(r.callee_translated.as_deref(), &mut out));
    col!(push_opt(r.caller_translated.as_deref(), &mut out));
    col!(csv_field(&r.source_ip, &mut out));
    col!(push_num(r.source_port, &mut out));
    col!(out.push_str(r.transport.as_str()));
    col!(push_opt(r.ingress_zone.as_deref(), &mut out));
    col!(push_opt(r.egress_zone.as_deref(), &mut out));
    col!(push_opt(r.trunk_group.as_deref(), &mut out));
    col!(csv_field(&tried, &mut out));
    col!(push_opt(r.final_trunk.as_deref(), &mut out));
    col!(push_num(r.failover_count, &mut out));
    col!(push_num(r.setup_ms, &mut out));
    col!(push_opt_num(r.ring_ms, &mut out));
    col!(push_opt_num(r.answer_ms, &mut out));
    col!(push_num(r.end_ms, &mut out));
    col!(push_num(r.duration_ms, &mut out));
    col!(push_opt_num(r.pdd_ms, &mut out));
    col!(out.push_str(r.disposition.as_str()));
    col!(push_num(r.final_sip_status, &mut out));
    col!(out.push_str(r.release_side.as_str()));
    col!(out.push_str(r.release_cause.as_str()));
    col!(push_opt_num(r.q850_cause, &mut out));
    col!(push_opt(r.media_node.as_deref(), &mut out));
    col!(push_num(r.media_anchored, &mut out));
    col!(push_opt(r.codec.as_deref(), &mut out));
    col!(push_opt(r.srtp.as_deref(), &mut out));
    col!(push_num(r.emergency, &mut out));
    col!(push_opt(stir, &mut out));
    col!(push_num(r.failover_takeover, &mut out));
    col!(push_opt(
        r.stir_verstat.map(crate::record::Verstat::as_str),
        &mut out
    ));
    col!(push_opt(r.stir_verify_reason.as_deref(), &mut out));
    col!(push_opt(
        r.stir_inbound_attestation
            .map(crate::record::Attestation::as_str),
        &mut out
    ));
    col!(push_opt(r.stir_x5u_host.as_deref(), &mut out));
    col!(out.push_str(&r.prev_hash));
    col!(out.push_str(&r.hash));
    Ok(out)
}

/// Default file header for a new file.
pub(crate) fn new_header(
    node_id: &str,
    created_ms: u64,
    chain_start: String,
    first_sequence: u64,
) -> FileHeader {
    FileHeader {
        schema_version: SCHEMA_VERSION,
        kind: "header".to_string(),
        node_id: node_id.to_string(),
        created_ms,
        chain_start,
        first_sequence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{TrunkAttempt, TrunkOutcome};

    /// Minimal RFC 4180 parser for one row (test oracle).
    pub fn parse_csv_row(line: &str) -> Vec<String> {
        let mut fields = Vec::new();
        let mut cur = String::new();
        let mut chars = line.chars().peekable();
        let mut in_quotes = false;
        while let Some(c) = chars.next() {
            if in_quotes {
                if c == '"' {
                    if chars.peek() == Some(&'"') {
                        cur.push('"');
                        chars.next();
                    } else {
                        in_quotes = false;
                    }
                } else {
                    cur.push(c);
                }
            } else if c == '"' {
                in_quotes = true;
            } else if c == ',' {
                fields.push(std::mem::take(&mut cur));
            } else {
                cur.push(c);
            }
        }
        fields.push(cur);
        fields
    }

    fn hostile() -> CallRecord {
        CallRecord {
            caller: "=HYPERLINK(\"http://x\")".to_string(),
            callee_dialed: "a,b\r\nc\"d".to_string(),
            a_call_id: "x\u{0}\u{1}\u{1f}\u{7f}\u{2028}y".to_string(),
            callee_translated: Some("+15550100".to_string()),
            caller_translated: Some("\rcmd".to_string()),
            b_call_ids: vec!["b1".into(), "@b2".into()],
            trunks_tried: vec![TrunkAttempt {
                trunk_id: "t,1".into(),
                status: TrunkOutcome::Status(503),
                at_ms: 5,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn json_escapes_all_c0_controls() {
        let mut r = hostile();
        let all_c0: String = (0u8..0x20).map(char::from).collect();
        r.caller = all_c0;
        let line = to_json_line(&r).unwrap();
        assert!(
            line.bytes().all(|b| b >= 0x20),
            "raw control byte in JSON line"
        );
        assert!(!line.contains('\n'));
        let back: CallRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn json_roundtrip_unicode() {
        let r = hostile();
        let line = to_json_line(&r).unwrap();
        let back: CallRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn csv_formula_injection_guarded() {
        let cases = [
            ("=1+1", "'=1+1"),
            ("+15550100", "'+15550100"),
            ("-2", "'-2"),
            ("@SUM(A1)", "'@SUM(A1)"),
            ("\tx", "'\tx"),
            ("alice", "alice"),
        ];
        for (input, want) in cases {
            let mut out = String::new();
            csv_field(input, &mut out);
            assert_eq!(out, want, "input {input:?}");
        }
        let mut out = String::new();
        csv_field("\rx", &mut out);
        assert_eq!(out, "\"'\rx\"");
    }

    #[test]
    fn csv_quotes_cr_lf_quote_comma() {
        for v in ["a\rb", "a\nb", "a\"b", "a,b"] {
            let mut out = String::new();
            csv_field(v, &mut out);
            assert!(out.starts_with('"') && out.ends_with('"'), "{v:?} -> {out}");
        }
        let mut out = String::new();
        csv_field("a\"b", &mut out);
        assert_eq!(out, "\"a\"\"b\"");
    }

    #[test]
    fn csv_row_roundtrip_column_count() {
        let r = hostile();
        let row = to_csv_row(&r).unwrap();
        let fields = parse_csv_row(&row);
        assert_eq!(fields.len(), CSV_COLUMNS.len());
        assert_eq!(fields[8], "'=HYPERLINK(\"http://x\")");
        assert_eq!(fields[9], "a,b\r\nc\"d");
        let ids: Vec<String> = serde_json::from_str(&fields[5]).unwrap();
        assert_eq!(ids, r.b_call_ids);
        assert_eq!(csv_header().split(',').count(), CSV_COLUMNS.len());
    }
}
