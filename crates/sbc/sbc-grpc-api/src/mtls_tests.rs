//! SR-41 QA: the shared gRPC mTLS helper (`crate::mtls`), ported from the
//! sbc-media listener tests plus the caller-env and client-side checks.
//!
//! `authorize` and `CertName` are reached as `pub(crate)` items; moving this
//! file under `mtls/` as `mod tests` with `use super::*` works the same.
//!
//! ## NIST 800-53 Rev5: IA-3, SC-8, AC-3, SC-7

use std::net::SocketAddr;

use rustls_pki_types::CertificateDer;
use tonic::Request;
use tonic::service::Interceptor;

use crate::mtls::{
    CertName, ClientNameGate, ClientTls, MtlsEnvNames, ServerTls, authorize, check_client_url,
    check_listener, parse_allowed_client_names, server_tls_from,
};

const MEDIA: MtlsEnvNames = MtlsEnvNames {
    listen: "SBC_MEDIA_GRPC_LISTEN",
    tls_prefix: "SBC_MEDIA_GRPC_TLS",
    allowed: "SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES",
};

const ANN: MtlsEnvNames = MtlsEnvNames {
    listen: "SBC_ANN_GRPC_LISTEN",
    tls_prefix: "SBC_ANN_GRPC_TLS",
    allowed: "SBC_ANN_GRPC_ALLOWED_CLIENT_NAMES",
};

fn s(v: &str) -> Option<String> {
    v.to_string().into()
}

fn tls() -> ServerTls {
    ServerTls {
        cert: "/t/c".into(),
        key: "/t/k".into(),
        client_ca: "/t/ca".into(),
    }
}

fn addr(a: &str) -> SocketAddr {
    a.parse()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
}

// ── ported from sbc-media grpc_tls.rs ─────────────────────────────

#[test]
fn server_tls_all_or_none() {
    assert_eq!(server_tls_from(&MEDIA, None, None, None), Ok(None));
    assert_eq!(server_tls_from(&MEDIA, s(""), s(""), s(" ")), Ok(None));
    assert_eq!(
        server_tls_from(&MEDIA, s("/t/c"), s("/t/k"), s("/t/ca")),
        Ok(Some(tls()))
    );
    for (c, k, ca) in [
        (s("/t/c"), None, None),
        (None, s("/t/k"), s("/t/ca")),
        (s("/t/c"), s("/t/k"), None),
    ] {
        let r = server_tls_from(&MEDIA, c, k, ca);
        assert!(
            r.as_ref().is_err_and(|e| e.contains("SBC_MEDIA_GRPC_TLS")),
            "{r:?}"
        );
    }
}

#[test]
fn allowed_names_parsed_and_bounded() {
    assert_eq!(parse_allowed_client_names(&MEDIA, None), Ok(Vec::new()));
    assert_eq!(
        parse_allowed_client_names(&MEDIA, Some(" sbc-daemon , spiffe://x/y ,")),
        Ok(vec!["sbc-daemon".to_string(), "spiffe://x/y".to_string()])
    );
    assert!(parse_allowed_client_names(&MEDIA, Some("has space")).is_err());
    assert!(parse_allowed_client_names(&MEDIA, Some(&"a".repeat(254))).is_err());
    let many: Vec<String> = (0..65).map(|i| format!("c{i}")).collect();
    assert!(parse_allowed_client_names(&MEDIA, Some(&many.join(","))).is_err());
}

#[test]
fn non_loopback_listener_needs_mtls_and_names() {
    let names = vec!["sbc-daemon".to_string()];
    assert!(check_listener(&MEDIA, addr("127.0.0.1:9096"), None, &[]).is_ok());
    assert!(check_listener(&MEDIA, addr("[::1]:9096"), None, &[]).is_ok());
    for a in ["0.0.0.0:9096", "[::]:9096", "172.28.2.11:9096"] {
        let r = check_listener(&MEDIA, addr(a), None, &[]);
        assert!(
            r.as_ref()
                .is_err_and(|e| e.contains("SBC_MEDIA_GRPC_LISTEN") && e.contains("loopback")),
            "{a}: {r:?}"
        );
        assert!(
            check_listener(&MEDIA, addr(a), Some(&tls()), &[]).is_err(),
            "{a}"
        );
        assert!(
            check_listener(&MEDIA, addr(a), Some(&tls()), &names).is_ok(),
            "{a}"
        );
    }
    assert!(check_listener(&MEDIA, addr("127.0.0.1:9096"), None, &names).is_err());
    assert!(check_listener(&MEDIA, addr("127.0.0.1:9096"), Some(&tls()), &[]).is_ok());
}

#[test]
fn missing_or_garbage_cert_refused() {
    assert!(authorize(None, &[]).is_err());
    assert!(authorize(Some(&[]), &[]).is_err());
    let junk = CertificateDer::from(vec![0x30, 0x82, 0xff, 0xff, 0x01]);
    assert!(authorize(Some(&[junk]), &["x".to_string()]).is_err());
}

#[test]
fn gate_without_tls_passes_through_and_with_tls_needs_cert() {
    let mut open = ClientNameGate::new(false, &[], "AnnouncementService");
    assert!(open.call(Request::new(())).is_ok());
    let mut gate = ClientNameGate::new(true, &["sbc-daemon".to_string()], "AnnouncementService");
    assert_eq!(
        gate.call(Request::new(())).err().map(|e| e.code()),
        Some(tonic::Code::PermissionDenied)
    );
}

#[test]
fn dns_names_case_insensitive_uris_exact() {
    assert!(CertName::Dns("SBC-Daemon".into()).matches("sbc-daemon"));
    assert!(CertName::Uri("spiffe://sbc/daemon".into()).matches("spiffe://sbc/daemon"));
    assert!(!CertName::Uri("spiffe://SBC/daemon".into()).matches("spiffe://sbc/daemon"));
}

// ── SR-41 additions ───────────────────────────────────────────────

/// Every listener-side error names the calling binary's variables, never
/// another binary's.
#[test]
fn qa_error_messages_name_caller_env() {
    let names = vec!["sbc-daemon".to_string()];
    let many: Vec<String> = (0..65).map(|i| format!("c{i}")).collect();
    let errs = [
        server_tls_from(&ANN, s("/t/c"), None, None).err(),
        parse_allowed_client_names(&ANN, Some("has space")).err(),
        parse_allowed_client_names(&ANN, Some(&many.join(","))).err(),
        check_listener(&ANN, addr("0.0.0.0:9095"), None, &[]).err(),
        check_listener(&ANN, addr("0.0.0.0:9095"), Some(&tls()), &[]).err(),
        check_listener(&ANN, addr("127.0.0.1:9095"), None, &names).err(),
    ];
    for (i, e) in errs.into_iter().enumerate() {
        let e = e.unwrap_or_else(|| panic!("case {i} must be an error"));
        assert!(e.contains("SBC_ANN_GRPC_"), "case {i}: {e}");
        assert!(!e.contains("SBC_MEDIA"), "case {i}: {e}");
    }
    let e = check_listener(&ANN, addr("0.0.0.0:9095"), None, &[]).unwrap_err();
    assert!(e.contains("SBC_ANN_GRPC_LISTEN"), "{e}");
    let e = check_listener(&ANN, addr("127.0.0.1:9095"), None, &names).unwrap_err();
    assert!(e.contains("SBC_ANN_GRPC_ALLOWED_CLIENT_NAMES"), "{e}");
}

#[test]
fn qa_client_tls_all_or_none() {
    const P: &str = "SBC_ANNOUNCEMENT_TLS";
    assert_eq!(ClientTls::from_parts(P, None, None, None, None), Ok(None));
    assert_eq!(
        ClientTls::from_parts(P, s(" "), s(""), s(""), s("")),
        Ok(None)
    );
    let full = ClientTls::from_parts(P, s("/c/ca"), s("/c/crt"), s("/c/key"), None)
        .ok()
        .flatten()
        .expect("all three files set");
    assert_eq!(full.ca, std::path::PathBuf::from("/c/ca"));
    assert_eq!(full.cert, std::path::PathBuf::from("/c/crt"));
    assert_eq!(full.key, std::path::PathBuf::from("/c/key"));
    assert_eq!(full.domain, None);
    let with_domain =
        ClientTls::from_parts(P, s("/c/ca"), s("/c/crt"), s("/c/key"), s("ann.example"))
            .ok()
            .flatten()
            .expect("files plus domain");
    assert_eq!(with_domain.domain.as_deref(), Some("ann.example"));
    for (ca, cert, key, domain) in [
        (s("/c/ca"), None, None, None),
        (None, s("/c/crt"), s("/c/key"), None),
        (s("/c/ca"), s("/c/crt"), None, None),
        // A domain override without the files is refused, not ignored.
        (None, None, None, s("ann.example")),
    ] {
        let r = ClientTls::from_parts(P, ca, cert, key, domain);
        assert!(
            r.as_ref()
                .is_err_and(|e| e.contains("SBC_ANNOUNCEMENT_TLS")),
            "{r:?}"
        );
    }
}

#[test]
fn qa_client_url_https_with_tls_loopback_without() {
    const P: &str = "SBC_ANNOUNCEMENT_TLS";
    let tls = ClientTls::from_parts(P, s("/c/ca"), s("/c/crt"), s("/c/key"), None)
        .ok()
        .flatten()
        .expect("client tls");
    // With TLS: https only (any case), never plaintext.
    assert!(check_client_url(P, "https://sbc-announcement.ns.svc:9095", Some(&tls)).is_ok());
    assert!(check_client_url(P, "HTTPS://sbc-announcement:9095", Some(&tls)).is_ok());
    for url in ["http://sbc-announcement:9095", "http://127.0.0.1:9095"] {
        let r = check_client_url(P, url, Some(&tls));
        assert!(
            r.as_ref()
                .is_err_and(|e| e.contains("https") && e.contains("SBC_ANNOUNCEMENT_TLS")),
            "{url}: {r:?}"
        );
    }
    // Without TLS: plaintext to loopback only.
    for url in [
        "http://127.0.0.1:9095",
        "http://127.8.9.10:9095",
        "http://[::1]:9095",
        "http://localhost:9095",
    ] {
        assert!(check_client_url(P, url, None).is_ok(), "{url}");
    }
    for url in [
        "http://sbc-announcement.ns.svc.cluster.local:9095",
        "http://10.0.0.7:9095",
        "http://[2001:db8::1]:9095",
        "http://0.0.0.0:9095",
        "not a url",
    ] {
        let r = check_client_url(P, url, None);
        assert!(
            r.as_ref()
                .is_err_and(|e| e.contains("SBC_ANNOUNCEMENT_TLS")),
            "{url}: {r:?}"
        );
    }
}
