//! SR-16: `uc_transport::https_client::create_https_client_config`, the CNSA
//! rustls client config used for outbound management-plane HTTPS (identity provider /
//! JWKS, central config API) via reqwest `use_preconfigured_tls`.
//!
//! Every handshake runs against an in-process tokio-rustls server with a
//! random rcgen P-384 PKI (`common/cnsa_https_server.rs`).
//!
//! Run: `cargo test -p uc-transport --features https-client --test https_client`
#![cfg(feature = "https-client")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

#[path = "common/cnsa_https_server.rs"]
mod fx;

use fx::Profile;
use rustls::{CipherSuite, NamedGroup, ProtocolVersion};
use uc_transport::TransportError;
use uc_transport::https_client::create_https_client_config;
use uc_transport::tls::{MinTlsVersion, cnsa_provider};

fn cfg(extra_ca: Option<&str>, min: MinTlsVersion) -> rustls::ClientConfig {
    create_https_client_config(extra_ca.map(str::as_bytes), min).expect("client config")
}

#[test]
fn https_client_config_is_cnsa_and_fips() {
    let want = cnsa_provider();
    let want_suites: Vec<CipherSuite> = want
        .cipher_suites
        .iter()
        .map(rustls::SupportedCipherSuite::suite)
        .collect();
    let want_groups: Vec<NamedGroup> = want.kx_groups.iter().map(|g| g.name()).collect();

    for min in [MinTlsVersion::V1_2, MinTlsVersion::V1_3] {
        let pki = fx::pki(fx::LeafKey::P384);
        let c = cfg(Some(&pki.ca_pem), min);
        let p = c.crypto_provider();
        let suites: Vec<CipherSuite> = p
            .cipher_suites
            .iter()
            .map(rustls::SupportedCipherSuite::suite)
            .collect();
        let groups: Vec<NamedGroup> = p.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(
            suites, want_suites,
            "{min:?}: cipher suites must be cnsa_provider()'s"
        );
        assert_eq!(
            groups, want_groups,
            "{min:?}: kx groups must be cnsa_provider()'s"
        );
        assert!(p.fips(), "{min:?}: provider must report FIPS");
        assert!(c.fips(), "{min:?}: ClientConfig must report FIPS");
        assert!(
            c.alpn_protocols.is_empty(),
            "no ALPN: reqwest stays on HTTP/1.1"
        );
    }
}

#[tokio::test]
async fn https_client_versions_follow_min_version() {
    let both = fx::spawn(Profile::Cnsa).await;
    let only12 = fx::spawn(Profile::CnsaTls12Only).await;

    // V1_2 offers 1.3 first and falls back to the CNSA 1.2 suite.
    let n = fx::rustls_handshake(cfg(Some(&both.ca_pem), MinTlsVersion::V1_2), both.addr)
        .await
        .expect("1.3 handshake");
    assert_eq!(n.version, ProtocolVersion::TLSv1_3);
    assert_eq!(n.suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
    assert_eq!(n.group, Some(NamedGroup::MLKEM1024));

    let n = fx::rustls_handshake(cfg(Some(&only12.ca_pem), MinTlsVersion::V1_2), only12.addr)
        .await
        .expect("1.2 handshake");
    assert_eq!(n.version, ProtocolVersion::TLSv1_2);
    assert_eq!(
        n.suite,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    );
    assert_eq!(n.group, Some(NamedGroup::secp384r1));

    // V1_3 refuses a 1.2-only server.
    assert!(
        fx::rustls_handshake(cfg(Some(&only12.ca_pem), MinTlsVersion::V1_3), only12.addr)
            .await
            .is_err(),
        "V1_3 config must not negotiate TLS 1.2"
    );
    let n = fx::rustls_handshake(cfg(Some(&both.ca_pem), MinTlsVersion::V1_3), both.addr)
        .await
        .expect("1.3-only handshake");
    assert_eq!(n.version, ProtocolVersion::TLSv1_3);
}

async fn assert_refused(profile: Profile) {
    let server = fx::spawn(profile).await;
    for min in [MinTlsVersion::V1_2, MinTlsVersion::V1_3] {
        let r = fx::rustls_handshake(cfg(Some(&server.ca_pem), min), server.addr).await;
        assert!(
            r.is_err(),
            "{profile:?} / {min:?}: non-CNSA server must be refused, negotiated {r:?}"
        );
    }
    assert!(
        server.completed_handshakes().is_empty(),
        "{profile:?}: server completed a handshake"
    );
}

#[tokio::test]
async fn https_client_rejects_aes128_only_server() {
    assert_refused(Profile::Aes128Only).await;
}

#[tokio::test]
async fn https_client_rejects_x25519_only_server() {
    assert_refused(Profile::X25519Only).await;
}

#[tokio::test]
async fn https_client_tls12_rejects_rsa_or_non_cnsa_suite() {
    assert_refused(Profile::Tls12RsaLeaf).await;
    assert_refused(Profile::Tls12NonCnsaSuite).await;
}

#[tokio::test]
async fn https_client_accepts_cnsa_server_via_extra_ca() {
    let server = fx::spawn(Profile::Cnsa).await;
    let n = fx::rustls_handshake(cfg(Some(&server.ca_pem), MinTlsVersion::V1_2), server.addr)
        .await
        .expect("CNSA server with trusted extra CA");
    assert_eq!(n.suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
    assert_eq!(server.wait_handshakes(1).await.len(), 1);

    // A bundle with more than one cert (another CA first) still trusts ours.
    let other = fx::pki(fx::LeafKey::P384);
    let bundle = format!("{}\n{}", other.ca_pem, server.ca_pem);
    fx::rustls_handshake(cfg(Some(&bundle), MinTlsVersion::V1_2), server.addr)
        .await
        .expect("multi-cert extra CA bundle");
}

#[tokio::test]
async fn https_client_without_extra_ca_rejects_private_ca() {
    // The test CA is in neither the OS store nor the extra bundle.
    let server = fx::spawn(Profile::Cnsa).await;
    let unrelated = fx::pki(fx::LeafKey::P384);
    let r = fx::rustls_handshake(
        cfg(Some(&unrelated.ca_pem), MinTlsVersion::V1_2),
        server.addr,
    )
    .await;
    assert!(r.is_err(), "untrusted CA must fail path validation: {r:?}");
}

#[test]
fn extra_ca_pem_without_certs_is_rejected() {
    let key_only = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
        .unwrap()
        .serialize_pem();
    let bad_cert = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    let cases: [(&str, &[u8]); 4] = [
        ("empty", b""),
        ("not pem", b"definitely not a certificate"),
        ("private key only", key_only.as_bytes()),
        ("garbage certificate", bad_cert.as_bytes()),
    ];
    for (name, pem) in cases {
        match create_https_client_config(Some(pem), MinTlsVersion::V1_2) {
            Err(TransportError::TlsCertificateError { .. }) => {}
            Err(e) => panic!("{name}: want TlsCertificateError, got {e:?}"),
            Ok(_) => panic!("{name}: extra CA without a usable certificate was accepted"),
        }
    }
}

/// Child half of the `SSL_CERT_FILE` tests: does work only when re-executed
/// by `fx::run_child`, so the parent never mutates its own environment.
#[tokio::test]
async fn native_roots_child() {
    let Some(mode) = fx::child_mode() else {
        return; // parent run: nothing to do
    };
    match mode.as_str() {
        "empty" => {
            match create_https_client_config(None, MinTlsVersion::V1_2) {
                Err(TransportError::TlsCertificateError { .. }) => {}
                Err(e) => panic!("empty root store: want TlsCertificateError, got {e:?}"),
                Ok(_) => panic!("empty root store must be rejected (no trust anchors)"),
            }
            // An extra CA alone is a non-empty store.
            let pki = fx::pki(fx::LeafKey::P384);
            create_https_client_config(Some(pki.ca_pem.as_bytes()), MinTlsVersion::V1_2)
                .expect("extra CA alone is enough");
        }
        "trusted" => {
            // SSL_CERT_FILE holds the parent server's CA: no extra CA.
            let c = create_https_client_config(None, MinTlsVersion::V1_2).expect("OS roots");
            let n = fx::rustls_handshake(c, fx::child_server_addr())
                .await
                .expect("CA from SSL_CERT_FILE must be trusted");
            assert_eq!(n.suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
        }
        other => panic!("unknown child mode {other}"),
    }
}

#[test]
fn empty_root_store_is_rejected() {
    let empty = fx::temp_file("empty-roots", b"");
    assert!(
        fx::run_child(
            &fx::test_name(module_path!(), "native_roots_child"),
            "empty",
            &empty,
            None
        ),
        "child failed: see its output above"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_client_trusts_os_roots_from_ssl_cert_file() {
    let server = fx::spawn(Profile::Cnsa).await;
    let roots = fx::temp_file("os-roots", server.ca_pem.as_bytes());
    assert!(
        fx::run_child_async(
            fx::test_name(module_path!(), "native_roots_child"),
            "trusted",
            roots,
            Some(server.addr)
        )
        .await,
        "child failed: see its output above"
    );
    assert_eq!(server.wait_handshakes(1).await.len(), 1);
}
