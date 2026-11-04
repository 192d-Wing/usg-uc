//! Configuration integration tests.

use sbc_config::{default_config, load_from_str};
use uc_types::media::MediaMode;
use uc_types::protocol::CnsaCurve;

#[test]
fn test_default_config_values() {
    let config = default_config();

    assert_eq!(config.general.instance_name, "sbc-01");
    assert_eq!(config.general.max_calls, 10000);
    assert_eq!(config.media.default_mode, MediaMode::Relay);
    assert!(config.media.srtp.required);
    assert_eq!(config.security.curve, CnsaCurve::P384);
}

#[test]
fn test_config_from_toml() {
    let toml = r#"
        [general]
        instance_name = "test-sbc"
        max_calls = 5000

        [media]
        default_mode = "PassThrough"

        [security]
        tls_cert_path = "/etc/sbc/tls.crt"
        tls_key_path = "/etc/sbc/tls.key"
        tls_ca_path = "/etc/sbc/client-ca.pem"
        require_mtls = true
    "#;

    let config = load_from_str(toml).unwrap();
    assert_eq!(config.general.instance_name, "test-sbc");
    assert_eq!(config.general.max_calls, 5000);
    assert_eq!(config.media.default_mode, MediaMode::PassThrough);
    assert!(config.security.require_mtls);
    assert_eq!(
        config.security.tls_ca_path.as_deref(),
        Some(std::path::Path::new("/etc/sbc/client-ca.pem"))
    );
}

#[test]
fn test_require_mtls_without_ca_is_rejected() {
    // Mutual TLS cannot be enforced without a CA to verify clients against,
    // so the configuration is refused instead of silently accepted.
    let toml = r#"
        [security]
        tls_cert_path = "/etc/sbc/tls.crt"
        tls_key_path = "/etc/sbc/tls.key"
        require_mtls = true
    "#;
    let err = load_from_str(toml).unwrap_err().to_string();
    assert!(err.contains("tls_ca_path"), "{err}");
}

#[test]
fn test_config_partial_toml() {
    let toml = r#"
        [general]
        instance_name = "minimal-sbc"
    "#;

    let config = load_from_str(toml).unwrap();
    assert_eq!(config.general.instance_name, "minimal-sbc");
    assert_eq!(config.general.max_calls, 10000); // default
}

#[test]
fn test_config_invalid_toml() {
    let invalid = "not valid toml [[[";
    let result = load_from_str(invalid);
    assert!(result.is_err());
}

#[test]
fn test_cnsa_compliance_defaults() {
    let config = default_config();

    // CNSA 2.0 requirements
    assert!(matches!(
        config.security.curve,
        CnsaCurve::P384 | CnsaCurve::P521
    ));
    assert_eq!(config.security.min_tls_version, "1.3");
    assert!(config.media.srtp.required);
}
