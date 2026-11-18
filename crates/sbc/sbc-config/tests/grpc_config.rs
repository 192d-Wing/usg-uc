//! QA: `grpc.allowed_client_names`, parsed through TOML (the operator path).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sbc_config::load_from_str;
use std::fmt::Write as _;

const MTLS: &str = r#"
[grpc]
enabled = true
require_mtls = true
tls_cert_path = "/etc/sbc/grpc/tls.crt"
tls_key_path = "/etc/sbc/grpc/tls.key"
tls_ca_path = "/etc/sbc/grpc/ca.crt"
"#;

fn rejected(toml: &str, needle: &str) {
    let e = load_from_str(toml)
        .map(|_| ())
        .expect_err(&format!("should reject:\n{toml}"))
        .to_string();
    assert!(e.contains(needle), "error {e:?} should mention {needle:?}");
}

#[test]
fn allowed_client_names_default_empty_and_parsed() {
    let c = load_from_str(MTLS).unwrap().grpc.unwrap();
    assert_eq!(c.allowed_client_names, Vec::<String>::new());
    let toml = format!("{MTLS}allowed_client_names = [\"sbc-api.sbc.svc\"]\n");
    let c = load_from_str(&toml).unwrap().grpc.unwrap();
    assert_eq!(c.allowed_client_names, vec!["sbc-api.sbc.svc".to_string()]);
}

#[test]
fn allowed_client_names_without_mtls_rejected() {
    rejected(
        "[grpc]\nenabled = true\nallowed_client_names = [\"sbc-api\"]\n",
        "require_mtls",
    );
}

#[test]
fn malformed_allowed_client_names_rejected() {
    for bad in ["\"\"", "\"has space\"", &format!("\"{}\"", "a".repeat(254))] {
        rejected(
            &format!("{MTLS}allowed_client_names = [{bad}]\n"),
            "allowed_client_names",
        );
    }
    let many: Vec<String> = (0..65).map(|i| format!("\"c{i}\"")).collect();
    rejected(
        &format!("{MTLS}allowed_client_names = [{}]\n", many.join(",")),
        "more than 64",
    );
}

// --- Listener policy: a non-loopback gRPC listener must require mTLS ------

#[test]
fn qa_grpc_wildcard_listen_without_mtls_rejected() {
    for addr in ["0.0.0.0:9091", "[::]:9091", "10.0.0.5:9091"] {
        let toml = format!("[grpc]\nenabled = true\nlisten_addr = \"{addr}\"\n");
        let e = load_from_str(&toml)
            .map(|_| ())
            .expect_err(&format!(
                "non-loopback plaintext listener {addr} must be rejected"
            ))
            .to_string();
        assert!(
            e.contains("listen_addr"),
            "error {e:?} should name listen_addr"
        );
        assert!(
            e.contains("require_mtls"),
            "error {e:?} should name require_mtls"
        );
    }
}

#[test]
fn qa_grpc_loopback_without_mtls_accepted() {
    for addr in ["127.0.0.1:9091", "[::1]:9091"] {
        let toml = format!("[grpc]\nenabled = true\nlisten_addr = \"{addr}\"\n");
        let c = load_from_str(&toml)
            .unwrap_or_else(|e| panic!("loopback listener {addr} should load: {e}"))
            .grpc
            .unwrap();
        assert!(!c.require_mtls);
        assert!(c.listen_addr.ip().is_loopback());
    }
}

#[test]
fn qa_grpc_disabled_section_not_checked() {
    let toml = "[grpc]\nenabled = false\nlisten_addr = \"0.0.0.0:9091\"\nrequire_mtls = true\n";
    let c = load_from_str(toml)
        .expect("a disabled [grpc] section is not validated")
        .grpc
        .unwrap();
    assert!(!c.enabled);
}

#[test]
fn qa_grpc_require_mtls_without_tls_paths_rejected() {
    let full = [
        ("tls_cert_path", "/etc/sbc/grpc/tls.crt"),
        ("tls_key_path", "/etc/sbc/grpc/tls.key"),
        ("tls_ca_path", "/etc/sbc/grpc/ca.crt"),
    ];
    for missing in 0..full.len() {
        let mut toml = String::from(
            "[grpc]\nenabled = true\nlisten_addr = \"0.0.0.0:9091\"\nrequire_mtls = true\n",
        );
        for (i, (k, v)) in full.iter().enumerate() {
            if i != missing {
                writeln!(toml, "{k} = \"{v}\"").unwrap();
            }
        }
        // The message must point the operator at the mTLS settings.
        rejected(&toml, "require_mtls");
    }
}

#[test]
fn qa_grpc_default_listen_is_loopback_9091() {
    let d = sbc_config::schema::GrpcConfig::default();
    assert_eq!(d.listen_addr, "127.0.0.1:9091".parse().unwrap());
    assert!(!d.enabled);
}

#[test]
fn non_loopback_mtls_listener_requires_allowed_client_names() {
    let base = format!("{MTLS}listen_addr = \"0.0.0.0:9091\"\n");
    rejected(&base, "allowed_client_names");
    let named = format!("{base}allowed_client_names = [\"sbc-api\"]\n");
    assert!(load_from_str(&named).is_ok(), "named clients load");
    // On loopback an empty list stays allowed (startup warning only).
    assert!(load_from_str(MTLS).is_ok());
}
