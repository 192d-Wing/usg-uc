//! QA: `[cdr]` table, parsed through TOML (the operator path), one check per key.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sbc_config::load_from_str;
use sbc_config::schema::{CdrFormatConfig, CdrOnFailure, CdrPiiMode, CdrRecordUnanswered};
use std::path::PathBuf;

fn load(cdr: &str) -> Result<sbc_config::SbcConfig, String> {
    load_from_str(cdr).map_err(|e| e.to_string())
}

fn rejected(toml: &str, needle: &str) {
    let e = load(toml).expect_err(&format!("should reject:\n{toml}"));
    assert!(e.contains(needle), "error {e:?} should mention {needle:?}");
}

#[test]
fn empty_config_has_documented_defaults() {
    let c = load("").unwrap().cdr;
    assert!(c.enabled);
    assert_eq!(c.format, CdrFormatConfig::Jsonl);
    assert_eq!(c.directory, PathBuf::from("/var/lib/usg-sbc/cdr"));
    assert_eq!(c.node_id, None);
    assert_eq!(c.rotate_size_mb, 100);
    assert_eq!(c.rotate_interval, "1h");
    assert_eq!(c.rotate_interval_secs(), Some(3600));
    assert_eq!(c.retention_files, 168);
    assert_eq!(c.retention_days, 90);
    assert_eq!(c.fsync_interval_ms, 1000);
    assert_eq!(c.queue_capacity, 8192);
    assert_eq!(c.ring_capacity, 10_000);
    assert!(c.hash_chain);
    assert_eq!(c.record_unanswered, CdrRecordUnanswered::All);
    assert!(!c.record_auth_challenges);
    assert_eq!(c.pii, CdrPiiMode::Full);
    assert_eq!(c.pii_hash_key_file, None);
    assert_eq!(c.on_failure, CdrOnFailure::Continue);
    assert!(!c.syslog.enabled);
    assert_eq!(c.syslog.target, "tls://collector:6514");
    assert_eq!(c.syslog.ca_path, None);
    assert_eq!(c.syslog.facility, 16);
}

#[test]
fn every_key_parses_to_its_value() {
    let c = load(
        r#"
[cdr]
enabled = true
format = "csv"
directory = "/data/cdr"
node_id = "sbc-a.1_x"
rotate_size_mb = 4096
rotate_interval = "24h"
retention_files = 0
retention_days = 1
fsync_interval_ms = 0
queue_capacity = 64
ring_capacity = 0
hash_chain = false
record_unanswered = "routed"
record_auth_challenges = true
pii = "hash"
pii_hash_key_file = "/etc/usg-sbc/cdr.key"
on_failure = "reject_new_calls"
[cdr.syslog]
enabled = true
target = "tls://collector.example:6514"
ca_path = "/etc/pki/ca.pem"
facility = 23
"#,
    )
    .unwrap()
    .cdr;
    assert_eq!(c.format, CdrFormatConfig::Csv);
    assert_eq!(c.directory, PathBuf::from("/data/cdr"));
    assert_eq!(c.node_id.as_deref(), Some("sbc-a.1_x"));
    assert_eq!(c.rotate_size_mb, 4096);
    assert_eq!(c.rotate_interval_secs(), Some(86_400));
    assert_eq!((c.retention_files, c.retention_days), (0, 1));
    assert_eq!(c.fsync_interval_ms, 0);
    assert_eq!(c.queue_capacity, 64);
    assert_eq!(c.ring_capacity, 0);
    assert!(!c.hash_chain);
    assert_eq!(c.record_unanswered, CdrRecordUnanswered::Routed);
    assert!(c.record_auth_challenges);
    assert_eq!(c.pii, CdrPiiMode::Hash);
    assert_eq!(c.on_failure, CdrOnFailure::RejectNewCalls);
    assert!(c.syslog.enabled);
    assert_eq!(c.syslog.facility, 23);
    assert_eq!(c.syslog.ca_path, Some(PathBuf::from("/etc/pki/ca.pem")));
}

#[test]
fn enum_values_and_mask_caller_none() {
    let c = load("[cdr]\npii = \"mask_caller\"\nrecord_unanswered = \"none\"\n")
        .unwrap()
        .cdr;
    assert_eq!(c.pii, CdrPiiMode::MaskCaller);
    assert_eq!(c.record_unanswered, CdrRecordUnanswered::None);
}

#[test]
fn unknown_keys_and_bad_enums_rejected() {
    rejected("[cdr]\nfile_directory = \"/x\"\n", "unknown field");
    rejected("[cdr.syslog]\nport = 6514\n", "unknown field");
    rejected("[cdr]\nformat = \"xml\"\n", "unknown variant");
    rejected("[cdr]\npii = \"redact\"\n", "unknown variant");
    rejected("[cdr]\nrecord_unanswered = \"some\"\n", "unknown variant");
    rejected("[cdr]\non_failure = \"block\"\n", "unknown variant");
    rejected("[cdr]\nqueue_capacity = -1\n", "parse");
}

#[test]
fn range_boundaries_inclusive() {
    for ok in [
        "rotate_size_mb = 1",
        "rotate_size_mb = 4096",
        "rotate_interval = \"0\"",
        "rotate_interval = \"5m\"",
        "rotate_interval = \"86400s\"",
        "fsync_interval_ms = 60000",
        "queue_capacity = 1000000",
        "ring_capacity = 200000",
    ] {
        load(&format!("[cdr]\n{ok}\n")).unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    for (bad, key) in [
        ("rotate_size_mb = 0", "rotate_size_mb"),
        ("rotate_size_mb = 4097", "rotate_size_mb"),
        ("rotate_interval = \"299s\"", "rotate_interval"),
        ("rotate_interval = \"86401\"", "rotate_interval"),
        ("rotate_interval = \"1h30m\"", "rotate_interval"),
        ("fsync_interval_ms = 60001", "fsync_interval_ms"),
        ("queue_capacity = 63", "queue_capacity"),
        ("queue_capacity = 1000001", "queue_capacity"),
        ("ring_capacity = 200001", "ring_capacity"),
        ("node_id = \"\"", "node_id"),
        ("node_id = \"a/b\"", "node_id"),
        ("directory = \"relative/cdr\"", "cdr.directory"),
        ("pii = \"hash\"", "pii_hash_key_file"),
        ("pii_hash_key_file = \"/k\"", "only valid with"),
    ] {
        rejected(&format!("[cdr]\n{bad}\n"), key);
    }
    let long = "a".repeat(65);
    rejected(&format!("[cdr]\nnode_id = \"{long}\"\n"), "node_id");
}

#[test]
fn syslog_keys_validated_only_when_enabled() {
    rejected(
        "[cdr.syslog]\nenabled = true\ntarget = \"tcp://c:514\"\n",
        "tls://",
    );
    rejected(
        "[cdr.syslog]\nenabled = true\ntarget = \"tls://c:0\"\n",
        "tls://",
    );
    rejected(
        "[cdr.syslog]\nenabled = true\ntarget = \"tls://c\\r\\n:6514\"\n",
        "tls://",
    );
    rejected(
        "[cdr.syslog]\nenabled = true\nca_path = \"ca.pem\"\n",
        "ca_path",
    );
    rejected("[cdr.syslog]\nenabled = true\nfacility = 24\n", "facility");
    // Disabled CDR skips all [cdr] validation (documented).
    load("[cdr]\nenabled = false\ndirectory = \"rel\"\n").unwrap();
}

#[test]
fn shipped_example_config_cdr_block_parses() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../deploy/config/config.toml"
    );
    let text = std::fs::read_to_string(path).unwrap();
    assert!(text.contains("[cdr]"));
    sbc_config::load_from_file(path).unwrap();
}
