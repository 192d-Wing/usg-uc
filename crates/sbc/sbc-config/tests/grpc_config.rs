//! QA: `grpc.allowed_client_names`, parsed through TOML (the operator path).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sbc_config::load_from_str;

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
