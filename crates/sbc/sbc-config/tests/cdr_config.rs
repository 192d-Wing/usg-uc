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
    // SR-43: 2232 hourly files = 93 days, covering retention_days.
    assert_eq!(c.retention_files, 2232);
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
        // SR-43: a 5-minute interval needs 25920 files for 90 days.
        "rotate_interval = \"5m\"\nretention_files = 25920\nattempts_retention_files = 25920",
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

/// SR-43 (QA-first, plan 8): the shipped example config validates and its
/// `[cdr]` count cap covers `retention_days` (90) on both streams, and it
/// documents the new attempts and audit-rotation keys.
/// NIST 800-53 Rev5: AU-11, AU-4, CM-6
#[test]
fn shipped_config_toml_validates_and_covers_90_days() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../deploy/config/config.toml"
    );
    let c = sbc_config::load_from_file(path).unwrap().cdr;
    assert_eq!(c.retention_days, 90);
    let secs = c.rotate_interval_secs().unwrap();
    assert!(secs > 0, "shipped config rotates by time");
    assert!(
        u64::from(c.retention_files) * secs >= 90 * 86_400,
        "{} files x {secs}s does not cover 90 days",
        c.retention_files
    );
    let text = std::fs::read_to_string(path).unwrap();
    for key in [
        "separate_attempts",
        "attempts_retention_files",
        "attempts_retention_days",
        "audit_max_file_mb",
        "audit_max_files",
        "audit_on_full",
    ] {
        assert!(
            text.contains(key),
            "deploy/config/config.toml should document {key}"
        );
    }
}

/// SR-43 (QA-first): the new `[cdr]` keys parse through TOML and are
/// enforced: coverage of `retention_days` by the count cap, attempts keys
/// only with `separate_attempts`.
#[test]
fn qa_sr43_new_cdr_keys_parse_and_are_enforced() {
    load(
        "[cdr]\nseparate_attempts = true\nattempts_retention_files = 2160\n\
         attempts_retention_days = 90\n",
    )
    .unwrap();
    load("[cdr]\nseparate_attempts = false\n").unwrap();
    rejected(
        "[cdr]\nseparate_attempts = false\nattempts_retention_files = 5000\n",
        "separate_attempts",
    );
    // The old default (168 hourly files) no longer passes against 90 days.
    rejected(
        "[cdr]\nrotate_interval = \"1h\"\nretention_files = 168\nretention_days = 90\n",
        "retention_files",
    );
    rejected(
        "[cdr]\nrotate_interval = \"1h\"\nattempts_retention_files = 10\n\
         attempts_retention_days = 90\n",
        "attempts_retention_files",
    );
}

/// SR-42 (QA-first): `[logging]` audit rotation keys through TOML.
/// NIST 800-53 Rev5: AU-4, AU-5, CM-6
#[test]
fn qa_sr42_audit_rotation_keys_through_toml() {
    load("[logging]\naudit_max_file_mb = 4096\naudit_max_files = 1024\naudit_on_full = \"stop\"\n")
        .unwrap();
    for (bad, key) in [
        ("audit_max_file_mb = 0", "audit_max_file_mb"),
        ("audit_max_file_mb = 4097", "audit_max_file_mb"),
        ("audit_max_files = 0", "audit_max_files"),
        ("audit_max_files = 1025", "audit_max_files"),
    ] {
        rejected(&format!("[logging]\n{bad}\n"), key);
    }
    let e = load("[logging]\naudit_on_full = \"halt\"\n").expect_err("bad audit_on_full");
    assert!(
        e.contains("audit_on_full") || e.contains("unknown variant"),
        "{e}"
    );
}
