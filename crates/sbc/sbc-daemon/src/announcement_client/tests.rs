//! SR-41 QA: daemon-side announcement client TLS, URL rule, startup check
//! and the refusal/fallback split (orchestrator decision Q1).
//!
//! Wire from `announcement_client.rs` with `#[cfg(test)] mod tests;`
//! (the module is compiled only with `--features grpc`).
//!
//! ## NIST 800-53 Rev5: IA-3, SC-8, SC-7, CM-6

use std::collections::HashMap;

use super::*;

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

fn tls() -> AnnouncementTls {
    announcement_tls_from(s("/c/ca"), s("/c/crt"), s("/c/key"), None)
        .ok()
        .flatten()
        .expect("all three files")
}

#[test]
fn qa_announcement_tls_all_or_none() {
    assert!(matches!(
        announcement_tls_from(None, None, None, None),
        Ok(None)
    ));
    assert!(matches!(
        announcement_tls_from(s(""), s(" "), s(""), s("")),
        Ok(None)
    ));
    let t = tls();
    assert_eq!(t.ca, std::path::PathBuf::from("/c/ca"));
    for (ca, cert, key, domain) in [
        (s("/c/ca"), None, None, None),
        (None, s("/c/crt"), s("/c/key"), None),
        (None, None, None, s("ann.example")),
    ] {
        let r = announcement_tls_from(ca, cert, key, domain);
        assert!(
            r.as_ref()
                .is_err_and(|e| e.contains("SBC_ANNOUNCEMENT_TLS")),
            "{:?}",
            r.err()
        );
    }
}

#[test]
fn qa_announcement_url_plaintext_non_loopback_refused() {
    for url in [
        "http://sbc-announcement.ns.svc.cluster.local:9095",
        "http://10.0.0.7:9095",
    ] {
        let r = check_announcement_url(url, None);
        assert!(
            r.as_ref()
                .is_err_and(|e| e.contains("SBC_ANNOUNCEMENT_TLS")),
            "{url}: {r:?}"
        );
    }
    assert!(check_announcement_url("http://127.0.0.1:9095", None).is_ok());
    assert!(check_announcement_url("http://[::1]:9095", None).is_ok());
}

#[test]
fn qa_announcement_url_http_with_tls_refused() {
    let t = tls();
    let r = check_announcement_url("http://sbc-announcement:9095", Some(&t));
    assert!(r.as_ref().is_err_and(|e| e.contains("https")), "{r:?}");
    let r = check_announcement_url("http://127.0.0.1:9095", Some(&t));
    assert!(r.is_err(), "plaintext URL under TLS, even on loopback");
    assert!(check_announcement_url("https://sbc-announcement.ns.svc:9095", Some(&t)).is_ok());
}

/// The pure startup check `main` runs (it exits 2 on `Err`).
#[test]
fn qa_announcement_startup_check_exits_on_bad_env() {
    let check = |pairs: &[(&str, &str)]| {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        check_announcement_startup(|k: &str| m.get(k).cloned())
    };
    // URL unset: announcements stay in-process, nothing to check.
    assert!(matches!(check(&[]), Ok(None)));
    // Remote plaintext URL without TLS.
    assert!(check(&[("SBC_ANNOUNCEMENT_URL", "http://sbc-announcement:9095")]).is_err());
    // Partial TLS.
    assert!(
        check(&[
            ("SBC_ANNOUNCEMENT_URL", "https://sbc-announcement:9095"),
            ("SBC_ANNOUNCEMENT_TLS_CA_FILE", "/c/ca"),
        ])
        .is_err()
    );
    // TLS with an http URL.
    assert!(
        check(&[
            ("SBC_ANNOUNCEMENT_URL", "http://sbc-announcement:9095"),
            ("SBC_ANNOUNCEMENT_TLS_CA_FILE", "/c/ca"),
            ("SBC_ANNOUNCEMENT_TLS_CERT_FILE", "/c/crt"),
            ("SBC_ANNOUNCEMENT_TLS_KEY_FILE", "/c/key"),
        ])
        .is_err()
    );
    // Valid: https with all three files.
    let ok = check(&[
        ("SBC_ANNOUNCEMENT_URL", "https://sbc-announcement:9095"),
        ("SBC_ANNOUNCEMENT_TLS_CA_FILE", "/c/ca"),
        ("SBC_ANNOUNCEMENT_TLS_CERT_FILE", "/c/crt"),
        ("SBC_ANNOUNCEMENT_TLS_KEY_FILE", "/c/key"),
    ]);
    assert!(matches!(ok, Ok(Some(_))), "{:?}", ok.err());
    // Valid: loopback plaintext (lab).
    assert!(matches!(
        check(&[("SBC_ANNOUNCEMENT_URL", "http://127.0.0.1:9095")]),
        Ok(None)
    ));
}

/// Q1: a pod refusal must not fall back to in-process playback (that would
/// bypass the pod's caps and destination policy); transport failures do.
#[test]
fn qa_announcement_refusal_codes_skip_fallback() {
    for code in [
        tonic::Code::ResourceExhausted,
        tonic::Code::InvalidArgument,
        tonic::Code::PermissionDenied,
    ] {
        assert!(!fallback_allowed(code), "{code:?} must not fall back");
    }
    for code in [tonic::Code::Unavailable, tonic::Code::DeadlineExceeded] {
        assert!(fallback_allowed(code), "{code:?} falls back");
    }
}
