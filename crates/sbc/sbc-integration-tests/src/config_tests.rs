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
        default_mode = "Relay"

        [security]
        tls_cert_path = "/etc/sbc/tls.crt"
        tls_key_path = "/etc/sbc/tls.key"
        tls_ca_path = "/etc/sbc/client-ca.pem"
        require_mtls = true
    "#;

    let config = load_from_str(toml).unwrap();
    assert_eq!(config.general.instance_name, "test-sbc");
    assert_eq!(config.general.max_calls, 5000);
    assert_eq!(config.media.default_mode, MediaMode::Relay);
    assert!(config.security.require_mtls);
    assert_eq!(
        config.security.tls_ca_path.as_deref(),
        Some(std::path::Path::new("/etc/sbc/client-ca.pem"))
    );
}

#[test]
fn test_media_pass_through_is_rejected() {
    // The live call path always anchors media; a mode it would silently
    // ignore is refused (CM-6).
    let toml = r#"
        [media]
        default_mode = "PassThrough"
    "#;
    let err = load_from_str(toml).unwrap_err().to_string();
    assert!(err.contains("media.default_mode"), "{err}");
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

// ── QA: dead-config keys are enforced or rejected (CM-6) ────────────────

fn repo_path(rel: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(rel)
}

fn rejected_naming(toml: &str, key: &str) {
    let err = load_from_str(toml).expect_err(&format!("must reject: {toml}"));
    let msg = err.to_string();
    assert!(msg.contains(key), "error names `{key}`: {msg}");
}

#[test]
fn qa_media_default_mode_non_relay_rejected() {
    for mode in ["PassThrough", "SignalingOnly"] {
        rejected_naming(
            &format!("[media]\ndefault_mode = \"{mode}\"\n"),
            "media.default_mode",
        );
    }
    assert!(load_from_str("[media]\ndefault_mode = \"Relay\"\n").is_ok());
}

#[test]
fn qa_media_realm_modes_rejected_even_when_relay() {
    rejected_naming(
        "[media.realm_modes]\nexternal = \"Relay\"\n",
        "media.realm_modes",
    );
    rejected_naming(
        "[media.realm_modes]\nexternal = \"PassThrough\"\n",
        "media.realm_modes",
    );
}

#[test]
fn qa_media_codecs_only_default_set_accepted() {
    // Default set in any order is accepted (Decision 7).
    for list in [
        r#"["Opus", "G722", "G711Ulaw", "G711Alaw"]"#,
        r#"["G711Alaw", "G711Ulaw", "G722", "Opus"]"#,
    ] {
        assert!(
            load_from_str(&format!("[media]\ncodecs = {list}\n")).is_ok(),
            "{list}"
        );
    }
    for list in [
        r#"["G711Ulaw", "G711Alaw", "G722"]"#,
        r#"["Opus"]"#,
        r#"["Opus", "Opus", "G722", "G711Ulaw", "G711Alaw"]"#,
    ] {
        rejected_naming(&format!("[media]\ncodecs = {list}\n"), "media.codecs");
    }
    // Empty list: rejected by the pre-existing "at least one codec" rule.
    assert!(load_from_str("[media]\ncodecs = []\n").is_err());
}

#[test]
fn qa_general_max_registrations_zero_rejected() {
    rejected_naming("[general]\nmax_registrations = 0\n", "max_registrations");
    let cfg = load_from_str("[general]\nmax_registrations = 1\n").unwrap();
    assert_eq!(cfg.general.max_registrations, 1);
}

fn trunk_toml(extra: &str) -> String {
    format!(
        "[[trunk_groups]]\nid = \"g\"\nname = \"G\"\nstrategy = \"priority\"\n\
         [[trunk_groups.trunks]]\nid = \"t\"\nhost = \"127.0.0.2\"\nport = 5060\n\
         protocol = \"udp\"\npriority = 1\n{extra}"
    )
}

#[test]
fn qa_trunk_limit_keys_enforced_or_rejected() {
    rejected_naming(&trunk_toml("max_calls = 0\n"), "max_calls");
    rejected_naming(&trunk_toml("max_failures = 0\n"), "max_failures");
    let cfg = load_from_str(&trunk_toml(
        "max_calls = 3\nmax_failures = 2\ncooldown_secs = 77\n",
    ))
    .unwrap();
    let t = &cfg.trunk_groups[0].trunks[0];
    assert_eq!((t.max_calls, t.max_failures, t.cooldown_secs), (3, 2, 77));
}

#[test]
fn qa_trunk_options_ping_keys_bounds() {
    for bad in [0_u32, 4, 3601] {
        rejected_naming(
            &trunk_toml(&format!(
                "options_ping_enabled = true\noptions_ping_interval_secs = {bad}\n"
            )),
            "options_ping_interval_secs",
        );
    }
    for good in [5_u32, 30, 3600] {
        assert!(
            load_from_str(&trunk_toml(&format!(
                "options_ping_enabled = true\noptions_ping_interval_secs = {good}\n"
            )))
            .is_ok(),
            "{good}"
        );
    }
    // Defaults: disabled, 30 s.
    let cfg = load_from_str(&trunk_toml("")).unwrap();
    let t = &cfg.trunk_groups[0].trunks[0];
    assert!(!t.options_ping_enabled);
    assert_eq!(t.options_ping_interval_secs, 30);
}

#[test]
fn qa_repo_deploy_configs_validate() {
    for rel in ["deploy/config/config.toml", "deploy/test/sbc-test.toml"] {
        let path = repo_path(rel);
        sbc_config::load_from_file(&path).unwrap_or_else(|e| panic!("{rel}: {e}"));
    }
}

/// Minimal render of the Helm `sbc.config` helper (no `helm` binary in CI
/// images): substitutes the chart default values and evaluates every
/// `{{- if }}` block both ways, then validates the result.
#[test]
fn qa_helm_rendered_sbc_config_validates() {
    let tpl = std::fs::read_to_string(repo_path("deploy/helm/sbc/templates/_helpers.tpl")).unwrap();
    let start = tpl
        .find("{{- define \"sbc.config\" -}}")
        .expect("sbc.config define");
    let body = &tpl[start..];
    let body = &body[body.find('\n').unwrap() + 1..];
    // The define's own closing `{{- end }}` is the last one before the next define / EOF.
    let end = body.rfind("{{- end }}").unwrap();
    let body = &body[..end];
    let values = [
        ("{{ .Values.site.name | quote }}", "\"site-a\""),
        ("{{ .Values.sbcDaemon.config.max_calls }}", "5000"),
        ("{{ .Values.sbcDaemon.config.max_registrations }}", "10000"),
        (
            "{{ .Values.sbcDaemon.config.api_listen | quote }}",
            "\"0.0.0.0:80\"",
        ),
        (
            "{{ .Values.sbcDaemon.config.media_mode | quote }}",
            "\"Relay\"",
        ),
        ("{{ .Values.sbcDaemon.config.srtp_required }}", "true"),
        (
            "{{ .Values.sbcDaemon.config.metrics_listen | quote }}",
            "\"0.0.0.0:9090\"",
        ),
        (
            "{{ .Values.sbcDaemon.config.grpc_listen | quote }}",
            "\"0.0.0.0:9091\"",
        ),
        (
            "{{ printf \"sbc.%s\" .Values.site.fqdn_base | quote }}",
            "\"sbc.example.mil\"",
        ),
        (
            "{{ .Values.sbcDaemon.topologyHiding.mode | quote }}",
            "\"Basic\"",
        ),
        (
            "{{ .Values.sbcDaemon.topologyHiding.externalHost | default (printf \"sbc.%s\" .Values.site.fqdn_base) | quote }}",
            "\"sbc.example.mil\"",
        ),
        (
            "{{ .Values.sbcDaemon.topologyHiding.externalPort }}",
            "5060",
        ),
        (
            "{{ .Values.sbcDaemon.topologyHiding.obfuscateCallId }}",
            "false",
        ),
        ("{{ .Values.sbcDaemon.sipTls.secretName }}", "sip-tls"),
    ];
    for keep_if_bodies in [false, true] {
        let mut out = String::new();
        let mut depth_skipping = 0_u32;
        let mut in_comment = false;
        for line in body.lines() {
            let t = line.trim();
            if t.starts_with("{{/*") {
                in_comment = !t.ends_with("*/}}");
                continue;
            }
            if in_comment {
                in_comment = !t.ends_with("*/}}");
                continue;
            }
            if t.starts_with("{{- if") {
                if !keep_if_bodies || depth_skipping > 0 {
                    depth_skipping += 1;
                }
                continue;
            }
            if t.starts_with("{{- end") {
                depth_skipping = depth_skipping.saturating_sub(1);
                continue;
            }
            if depth_skipping > 0 {
                continue;
            }
            let mut l = line.replace("__POD_IP__", "10.0.0.5");
            for (k, v) in values {
                l = l.replace(k, v);
            }
            assert!(!l.contains("{{"), "unrendered template: {l}");
            out.push_str(&l);
            out.push('\n');
        }
        match load_from_str(&out) {
            Ok(cfg) => assert_eq!(cfg.media.default_mode, MediaMode::Relay),
            Err(e) => {
                let msg = e.to_string();
                // With the TLS branch rendered, cert files do not exist on
                // the test host; only non-media failures of that kind are
                // tolerated.
                assert!(
                    keep_if_bodies && !msg.contains("media.") && !msg.contains("max_registrations"),
                    "helm config (if-bodies={keep_if_bodies}) failed: {msg}\n{out}"
                );
            }
        }
    }
}
