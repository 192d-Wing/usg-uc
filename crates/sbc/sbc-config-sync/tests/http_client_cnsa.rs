//! SR-16: the central-API / token-endpoint HTTP client
//! (`sbc_config_sync::build_http_client`) is CNSA-only. It has no extra-CA
//! input, so trust comes from the OS store; the tests point
//! `SSL_CERT_FILE` at the test CA in a re-executed child process.
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

#[path = "../../../uc/uc-transport/tests/common/cnsa_reqwest_checks.rs"]
mod checks;

/// Child half (no-op unless re-executed with `SSL_CERT_FILE`).
#[tokio::test]
async fn http_client_os_roots_child() {
    checks::os_roots_child(sbc_config_sync::build_http_client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sbc_config_sync_http_client_trusts_os_roots() {
    let child = checks::fx::test_name(module_path!(), "http_client_os_roots_child");
    checks::assert_os_roots_trusted_and_non_cnsa_refused(child, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sbc_config_sync_http_client_refuses_non_cnsa_server() {
    let child = checks::fx::test_name(module_path!(), "http_client_os_roots_child");
    checks::assert_os_roots_trusted_and_non_cnsa_refused(child, true).await;
}

#[test]
fn sbc_config_sync_http_client_builds_without_default_provider() {
    // reqwest without a provider panics in `build()` unless TLS is
    // preconfigured; the builder must never fall back to `Client::new()`.
    sbc_config_sync::build_http_client().expect("http client");
}
