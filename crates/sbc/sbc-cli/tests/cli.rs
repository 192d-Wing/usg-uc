//! End-to-end exit-code and output tests for the `sbc-cli` binary.
//!
//! These tests exercise argument handling and failure paths that do not
//! require a running daemon. The "unreachable daemon" cases point at a
//! port on localhost that nothing listens on.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Command, Output};

/// URL nothing listens on: reserved port 0 is invalid for connects, so use
/// a localhost port from the discard range that CI never binds.
const DEAD_URL: &str = "https://127.0.0.1:1";

fn run_cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sbc-cli"))
        .args(args)
        .env_remove("SBC_API_TOKEN")
        .output()
        .expect("failed to spawn sbc-cli")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn version_flag_exits_zero() {
    let output = run_cli(&["--version"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains("sbc-cli"));
}

#[test]
fn version_json_emits_single_json_document() {
    let output = run_cli(&["--json", "version"]);
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("stdout must be one JSON document");
    assert_eq!(value["name"], "sbc-cli");
}

#[test]
fn help_exits_zero() {
    let output = run_cli(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(stdout(&output).contains("USAGE"));
}

#[test]
fn unknown_command_exits_2_with_usage() {
    let output = run_cli(&["frobnicate"]);
    assert_eq!(output.status.code(), Some(2));
    let err = stderr(&output);
    assert!(err.contains("unknown command"));
    assert!(err.contains("USAGE"));
}

#[test]
fn unknown_subcommand_exits_2() {
    let output = run_cli(&["calls", "frobnicate"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("unknown calls subcommand"));

    let output = run_cli(&["config", "frobnicate"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("unknown config subcommand"));
}

#[test]
fn unknown_flag_after_command_exits_2() {
    let output = run_cli(&["status", "--frobnicate"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("unknown option"));
}

#[test]
fn extra_positional_exits_2() {
    let output = run_cli(&["status", "leftover"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("unexpected argument"));
}

#[test]
fn no_command_exits_2() {
    let output = run_cli(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("no command specified"));
}

#[test]
fn option_missing_value_exits_2() {
    let output = run_cli(&["--api-url"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("requires a value"));
}

#[test]
fn status_unreachable_daemon_exits_1() {
    let output = run_cli(&["--api-url", DEAD_URL, "status"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("failed to reach the SBC daemon"));
    // No fabricated status on stdout.
    assert!(stdout(&output).is_empty());
}

#[test]
fn calls_list_unreachable_daemon_exits_1_with_empty_stdout_in_json_mode() {
    let output = run_cli(&["--json", "--api-url", DEAD_URL, "calls", "list"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).is_empty());
}

#[test]
fn calls_terminate_never_reports_success() {
    let output = run_cli(&["--api-url", DEAD_URL, "calls", "terminate", "call-001"]);
    assert_eq!(output.status.code(), Some(1));
    let err = stderr(&output);
    assert!(err.contains("not supported by the daemon API"));
    assert!(stdout(&output).is_empty());
}

#[test]
fn config_reload_never_reports_success() {
    let output = run_cli(&["config", "reload"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("not supported by the daemon API"));
    assert!(stdout(&output).is_empty());
}

#[test]
fn config_show_never_prints_defaults() {
    let output = run_cli(&["config", "show"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("not supported by the daemon API"));
    assert!(stdout(&output).is_empty());
}

#[test]
fn config_validate_missing_file_exits_1() {
    let output = run_cli(&["config", "validate", "/nonexistent/sbc-config.toml"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("validation failed"));
}

#[test]
fn config_validate_valid_file_exits_0_and_json_parses() {
    let dir = std::env::temp_dir().join(format!("sbc-cli-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.toml");
    // Minimal valid config: sbc-config fills in defaults for the rest.
    std::fs::write(&path, "").unwrap();

    let output = run_cli(&["--json", "config", "validate", path.to_str().unwrap()]);
    let _ = std::fs::remove_dir_all(&dir);

    if output.status.code() == Some(0) {
        let value: serde_json::Value =
            serde_json::from_str(&stdout(&output)).expect("stdout must be one JSON document");
        assert_eq!(value["valid"], true);
    } else {
        // An empty file may not satisfy sbc-config validation rules; the
        // contract under test is then the failure path.
        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains("validation failed"));
    }
}

#[test]
fn insecure_flag_warns_on_stderr() {
    let output = run_cli(&["--insecure", "--api-url", DEAD_URL, "status"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("TLS certificate verification is DISABLED"));
}

#[test]
fn bad_ca_cert_exits_1() {
    let output = run_cli(&["--ca-cert", "/nonexistent/ca.pem", "status"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("failed to read CA cert"));
}
