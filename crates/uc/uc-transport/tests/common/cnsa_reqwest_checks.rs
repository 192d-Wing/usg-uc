//! Test-only reqwest checks for SR-16 management-plane HTTP client builders.
//!
//! Included through `#[path]` by sbc-daemon, sbc-api-server,
//! sbc-client-config-server, central-config-api and sbc-config-sync. Each
//! crate passes its own builder fn; the checks make real reqwest requests
//! to an in-process TLS server (`cnsa_https_server.rs`). uc-transport itself
//! does not include this file (it has no reqwest).
#![allow(
    dead_code,
    missing_docs,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

#[path = "cnsa_https_server.rs"]
pub mod fx;

use std::fmt::Debug;

pub use fx::Profile;

/// GET `url`; `Ok(body)` only for a 2xx response.
pub async fn get_ok(client: &reqwest::Client, url: &str) -> Result<String, reqwest::Error> {
    client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
}

/// `<crate>_http_client_trusts_extra_ca`: a builder given the server's CA
/// as the extra PEM reaches a CNSA server, and negotiates TLS 1.3
/// `AES_256_GCM_SHA384`; given an unrelated CA it does not.
pub async fn assert_trusts_extra_ca<E: Debug>(
    build: impl Fn(Option<&[u8]>) -> Result<reqwest::Client, E>,
) {
    let server = fx::spawn(Profile::Cnsa).await;
    let client = build(Some(server.ca_pem.as_bytes())).expect("builder with extra CA");
    let body = get_ok(&client, &server.url())
        .await
        .expect("CNSA server signed by the extra CA must be reachable");
    assert_eq!(body, "ok");
    let hs = server.wait_handshakes(1).await;
    assert_eq!(hs.len(), 1, "one handshake");
    assert_eq!(hs[0].version, rustls::ProtocolVersion::TLSv1_3);
    assert_eq!(hs[0].suite, rustls::CipherSuite::TLS13_AES_256_GCM_SHA384);

    // Control: the same server is refused when its CA is not trusted.
    let unrelated = fx::pki(fx::LeafKey::P384);
    let client = build(Some(unrelated.ca_pem.as_bytes())).expect("builder with other CA");
    assert!(
        get_ok(&client, &server.url()).await.is_err(),
        "server signed by an untrusted CA must be refused"
    );
}

/// `<crate>_http_client_refuses_non_cnsa_server`: with the server's CA
/// trusted (so only the crypto can fail), every non-CNSA profile is
/// refused and the server never completes a handshake. A CNSA server is
/// checked first so a broken trust path cannot make this pass.
pub async fn assert_refuses_non_cnsa<E: Debug>(
    build: impl Fn(Option<&[u8]>) -> Result<reqwest::Client, E>,
) {
    let good = fx::spawn(Profile::Cnsa).await;
    let client = build(Some(good.ca_pem.as_bytes())).expect("builder");
    get_ok(&client, &good.url())
        .await
        .expect("sanity: CNSA server with trusted CA must be reachable");

    for profile in Profile::NON_CNSA {
        let server = fx::spawn(profile).await;
        let client = build(Some(server.ca_pem.as_bytes())).expect("builder");
        let r = get_ok(&client, &server.url()).await;
        assert!(
            r.is_err(),
            "{profile:?}: non-CNSA server must be refused, got {r:?} with {:?}",
            server.completed_handshakes()
        );
        assert!(
            server.completed_handshakes().is_empty(),
            "{profile:?}: server completed a handshake: {:?}",
            server.completed_handshakes()
        );
    }
}

/// Child half for builders without an extra-CA input (trust comes from the
/// OS store, here `SSL_CERT_FILE`). Call from a `#[tokio::test]` named
/// `child_test`; it is a no-op unless re-executed by
/// [`assert_os_roots_trusted_and_non_cnsa_refused`].
pub async fn os_roots_child<E: Debug>(build: impl Fn() -> Result<reqwest::Client, E>) {
    let Some(mode) = fx::child_mode() else {
        return;
    };
    let client = build().expect("builder");
    let r = get_ok(&client, &fx::child_server_url()).await;
    match mode.as_str() {
        "accept" => assert_eq!(r.expect("CA from SSL_CERT_FILE must be trusted"), "ok"),
        "refuse" => assert!(r.is_err(), "non-CNSA server must be refused, got {r:?}"),
        other => panic!("unknown child mode {other}"),
    }
}

/// Parent half: runs `child_test` (a fully qualified libtest name, see
/// [`fx::test_name`]) with `SSL_CERT_FILE` holding the server CA, once
/// against a CNSA server (`accept`) and, when `refuse_non_cnsa`, once per
/// non-CNSA profile (`refuse`). Needs a multi-thread runtime.
pub async fn assert_os_roots_trusted_and_non_cnsa_refused(
    child_test: String,
    refuse_non_cnsa: bool,
) {
    let good = fx::spawn(Profile::Cnsa).await;
    let roots = fx::temp_file("os-roots", good.ca_pem.as_bytes());
    assert!(
        fx::run_child_async(child_test.clone(), "accept", roots, Some(good.addr)).await,
        "CNSA server with CA in SSL_CERT_FILE must be reachable (see child output)"
    );
    assert_eq!(
        good.wait_handshakes(1).await[0].suite,
        rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
    );
    if !refuse_non_cnsa {
        return;
    }
    for profile in Profile::NON_CNSA {
        let server = fx::spawn(profile).await;
        let roots = fx::temp_file("os-roots", server.ca_pem.as_bytes());
        assert!(
            fx::run_child_async(child_test.clone(), "refuse", roots, Some(server.addr)).await,
            "{profile:?}: child did not observe a refusal (see child output)"
        );
        assert!(
            server.completed_handshakes().is_empty(),
            "{profile:?}: server completed a handshake"
        );
    }
}
