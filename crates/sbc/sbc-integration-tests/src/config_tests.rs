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

/// SEC-2/NIST-05: the chart's CDR retention fits the dedicated CDR volume
/// (retentionFiles * rotateSizeMb <= cdr.persistence.size), and the chart
/// mounts that volume at the CDR directory.
/// SEC-8: with grpcMtls the chart allow-lists its own sbc-api client
/// certificate CN by default, so another certificate from the same issuer
/// cannot call the daemon.
/// POA&M-270: the shipped config carries `[digest_auth]` switched off, and
/// the same file with its commented keys enabled loads with REGISTER digest
/// on. A half-enabled section fails the load. (The daemon is a binary
/// crate, so the REGISTER round trip from TOML is tested there:
/// `runtime::tests::digest_register_end_to_end_from_toml`.)
#[test]
fn qa_shipped_digest_auth_section_loads_off_and_on() {
    let shipped = std::fs::read_to_string(repo_path("deploy/config/config.toml")).unwrap();
    let off = load_from_str(&shipped).unwrap();
    assert!(!off.digest_auth.require_auth);
    assert_eq!(off.digest_auth.realm, None);
    assert_eq!(off.digest_auth.credentials_file, None);

    let section = shipped
        .split("[digest_auth]")
        .nth(1)
        .and_then(|rest| rest.split("\n[").next())
        .expect("[digest_auth] section in the shipped config");
    for key in [
        "# realm = ",
        "# algorithm = ",
        "# credentials_file = ",
        "# nonce_ttl_secs = ",
    ] {
        assert!(section.contains(key), "shipped section documents {key}");
    }
    let enable = |keys: &[&str]| {
        let mut on = section.replace("require_auth = false", "require_auth = true");
        for key in keys {
            on = on.replace(&format!("# {key} = "), &format!("{key} = "));
        }
        shipped.replace(section, &on)
    };

    let on = load_from_str(&enable(&[
        "realm",
        "algorithm",
        "credentials_file",
        "nonce_ttl_secs",
    ]))
    .unwrap();
    assert!(on.digest_auth.require_auth);
    assert_eq!(on.digest_auth.realm.as_deref(), Some("sip.example.mil"));
    assert_eq!(
        on.digest_auth.algorithm(),
        sbc_config::DigestAuthAlgorithm::Sha256
    );
    assert_eq!(
        on.digest_auth.credentials_file.as_deref(),
        Some(std::path::Path::new("/etc/usg-sbc/digest.ha1"))
    );
    assert_eq!(on.digest_auth.nonce_ttl_secs(), 300);

    // F3 / NIST-004 / SEC-007: while require_auth = false, uncommenting any
    // other key of the shipped section fails the load (never ignored).
    for key in ["realm", "algorithm", "credentials_file", "nonce_ttl_secs"] {
        let toml = shipped.replace(
            section,
            &section.replace(&format!("# {key} = "), &format!("{key} = ")),
        );
        let err = load_from_str(&toml).unwrap_err().to_string();
        assert!(
            err.contains(&format!("digest_auth.{key} is only valid with")),
            "{key}: {err}"
        );
    }

    for (keys, missing) in [
        (&["realm"][..], "digest_auth.credentials_file"),
        (&["credentials_file"][..], "digest_auth.realm"),
        (&[][..], "digest_auth.realm"),
    ] {
        let err = load_from_str(&enable(keys)).unwrap_err().to_string();
        assert!(err.contains(missing), "{err}");
    }
    // A file named while auth is off is rejected, not ignored.
    let staged = shipped.replace(
        "# credentials_file = \"/etc/usg-sbc/digest.ha1\"",
        "credentials_file = \"/etc/usg-sbc/digest.ha1\"",
    );
    let err = load_from_str(&staged).unwrap_err().to_string();
    assert!(
        err.contains("only valid with digest_auth.require_auth = true"),
        "{err}"
    );
}

#[test]
fn qa_helm_grpc_allow_list_defaults_to_sbc_api_cert() {
    let helpers =
        std::fs::read_to_string(repo_path("deploy/helm/sbc/templates/_helpers.tpl")).unwrap();
    let mtls =
        std::fs::read_to_string(repo_path("deploy/helm/sbc/templates/26-sbc-grpc-mtls.yaml"))
            .unwrap();
    let cn = r#"printf "%s-sbc-api" (include "sbc.fullname" .)"#;
    assert!(
        mtls.contains(&format!("commonName: {{{{ {cn} }}}}")),
        "client cert CN"
    );
    let define = helpers
        .split("{{- define \"sbc.grpcAllowedClientNames\" -}}")
        .nth(1)
        .expect("allow-list helper");
    // Up to the next helper (inner `{{- end }}`s may close if-blocks).
    let define = &define[..define
        .find("{{- define")
        .or_else(|| define.find("{{/*"))
        .unwrap_or(define.len())];
    // Default list: the sbc-api client CN, plus the trunk-agent client CN
    // when the trunk agent is enabled (it now has a gRPC TLS client).
    assert!(define.contains(cn), "sbc-api CN in default list: {define}");
    assert!(
        define.contains(r#"printf "%s-sbc-trunk-agent" (include "sbc.fullname" .)"#),
        "trunk-agent CN in default list: {define}"
    );
    assert!(
        define.contains(".Values.sbcTrunkAgent.enabled"),
        "trunk-agent CN only when the agent is enabled: {define}"
    );
    assert!(define.contains(".Values.sbcDaemon.grpcMtls.allowedClientNames"));
    let grpc = helpers.split("[grpc]").nth(1).expect("[grpc] block");
    let block = &grpc[..grpc.find("{{- end }}").expect("grpcMtls if")];
    assert!(
        block.contains(r#"allowed_client_names = {{ include "sbc.grpcAllowedClientNames" . }}"#)
    );
}

#[test]
fn qa_helm_cdr_retention_fits_its_volume() {
    let values = std::fs::read_to_string(repo_path("deploy/helm/sbc/values.yaml")).unwrap();
    let start = values.find("\n  cdr:\n").expect("sbcDaemon.cdr block");
    let block = &values[start..];
    let num = |key: &str| -> u64 {
        let line = block
            .lines()
            .find(|l| l.trim_start().starts_with(key))
            .unwrap_or_else(|| panic!("{key}"));
        let v = line.split(':').nth(1).unwrap().split('#').next().unwrap();
        v.trim()
            .trim_end_matches("Gi")
            .trim_end_matches("Mi")
            .parse()
            .unwrap()
    };
    let size_line = block
        .lines()
        .find(|l| l.trim_start().starts_with("size:"))
        .unwrap();
    let size_mib = if size_line.contains("Gi") {
        num("size:") * 1024
    } else {
        num("size:")
    };
    let total = num("retentionFiles:") * num("rotateSizeMb:");
    assert!(
        total <= size_mib,
        "{total} MiB of CDRs on a {size_mib} MiB volume"
    );
    let deploy = std::fs::read_to_string(repo_path(
        "deploy/helm/sbc/templates/12-sbc-deployment.yaml",
    ))
    .unwrap();
    assert!(deploy.contains("claimName: {{ include \"sbc.fullname\" . }}-cdr"));
}

/// Minimal render of the Helm `sbc.config` helper (no `helm` binary in CI
/// images): substitutes the chart default values and evaluates every
/// `{{- if }}` block both ways, then validates the result.
#[test]
#[allow(clippy::too_many_lines)] // flat value table
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
        // sbc.grpcListen with grpcMtls on (the chart default) is grpc_listen.
        (
            "{{ include \"sbc.grpcListen\" . | quote }}",
            "\"0.0.0.0:9091\"",
        ),
        (
            "{{ printf \"sbc.%s\" .Values.site.fqdn_base | quote }}",
            "\"sbc.example.mil\"",
        ),
        (
            "{{ .Values.sbcDaemon.topologyHiding.mode | quote }}",
            "\"signaling_only\"",
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
            "{{ .Values.sbcDaemon.topologyHiding.externalTlsPort | default 5061 }}",
            "5061",
        ),
        (
            "{{ .Values.sbcDaemon.topologyHiding.internalNetworks | toJson }}",
            "[\"10.0.0.0/8\", \"fd00::/8\"]",
        ),
        (
            "{{ .Values.sbcDaemon.topologyHiding.internalDomains | toJson }}",
            "[\"corp.example\"]",
        ),
        (
            "{{ .Values.sbcDaemon.topologyHiding.obfuscateCallId }}",
            "false",
        ),
        ("{{ .Values.sbcDaemon.sipTls.secretName }}", "sip-tls"),
        // values.yaml sbcDaemon.trunkTls / stirShaken (rendered with the
        // optional blocks on in the keep_if_bodies pass).
        (
            "{{ .Values.sbcDaemon.stirShaken.verificationEnabled }}",
            "true",
        ),
        ("{{ .Values.sbcDaemon.stirShaken.signingEnabled }}", "true"),
        (
            "{{ .Values.sbcDaemon.stirShaken.certificateUrl | quote }}",
            "\"https://certs.example.net/sti.pem\"",
        ),
        // values.yaml sbcDaemon.cdr defaults.
        ("{{ .Values.sbcDaemon.cdr.enabled }}", "true"),
        (
            "{{ .Values.sbcDaemon.cdr.directory | quote }}",
            "\"/var/lib/sbc/cdr\"",
        ),
        ("{{ .Values.sbcDaemon.cdr.format | quote }}", "\"jsonl\""),
        ("{{ .Values.sbcDaemon.cdr.rotateSizeMb }}", "16"),
        ("{{ .Values.sbcDaemon.cdr.retentionDays }}", "90"),
        ("{{ .Values.sbcDaemon.cdr.retentionFiles }}", "48"),
        ("{{ .Values.sbcDaemon.grpcMtls.enabled }}", "true"),
        (
            "{{ include \"sbc.grpcAllowedClientNames\" . }}",
            "[\"sbc-sbc-api\"]",
        ),
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
        assert!(
            out.contains("listen_addr = \"0.0.0.0:9091\"") && out.contains("require_mtls = true"),
            "rendered [grpc] (if-bodies={keep_if_bodies}):\n{out}"
        );
        check_rendered_sbc_config_load(&out, keep_if_bodies);
    }
}

/// Loads one rendering of the `sbc.config` helper and checks the outcome:
/// without the if-bodies only the `require_mtls` check may fail; with them
/// only missing TLS files on the test host are tolerated.
fn check_rendered_sbc_config_load(out: &str, keep_if_bodies: bool) {
    match load_from_str(out) {
        Ok(cfg) => {
            assert!(
                keep_if_bodies,
                "require_mtls without TLS paths must not load:\n{out}"
            );
            assert_eq!(cfg.media.default_mode, MediaMode::Relay);
        }
        Err(e) => {
            let msg = e.to_string();
            // Without the if-bodies the [grpc] TLS paths are absent, so
            // the only acceptable failure is the require_mtls check.
            // With them rendered, cert files do not exist on the test
            // host; only TLS-file failures are tolerated.
            let tolerated = if keep_if_bodies {
                !msg.contains("media.")
                    && !msg.contains("max_registrations")
                    && !msg.contains("grpc.listen_addr")
            } else {
                msg.contains("require_mtls")
            };
            assert!(
                tolerated,
                "helm config (if-bodies={keep_if_bodies}) failed: {msg}\n{out}"
            );
        }
    }
}

// ── QA: containment hardening, chart and realm text checks ─────────────
// Always run (no helm binary in CI); `helm_render` covers real renders.

fn read_repo(rel: &str) -> String {
    std::fs::read_to_string(repo_path(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The text of `{{- define "<name>" -}}` up to the next define or comment
/// (inner `{{- end }}`s may close if-blocks, so they are not the boundary).
fn helm_define<'a>(tpl: &'a str, name: &str) -> Option<&'a str> {
    let open = tpl.find(&format!("define \"{name}\""))?;
    let body = &tpl[open..];
    let rest = &body[1..];
    let end = [rest.find("{{- define"), rest.find("{{/*")]
        .into_iter()
        .flatten()
        .min()
        .map_or(body.len(), |i| i + 1);
    Some(&body[..end])
}

#[test]
fn qa_helm_grpc_mtls_on_by_default() {
    let values = read_repo("deploy/helm/sbc/values.yaml");
    let start = values
        .find("\n  grpcMtls:\n")
        .expect("sbcDaemon.grpcMtls block");
    let enabled = values[start..]
        .lines()
        .skip(2)
        .find(|l| l.trim_start().starts_with("enabled:"))
        .expect("grpcMtls.enabled");
    let v = enabled
        .split(':')
        .nth(1)
        .unwrap()
        .split('#')
        .next()
        .unwrap()
        .trim();
    assert_eq!(v, "true", "sbcDaemon.grpcMtls.enabled default: {enabled}");
}

#[test]
fn qa_helm_grpc_listen_uses_loopback_helper() {
    let helpers = read_repo("deploy/helm/sbc/templates/_helpers.tpl");
    let grpc = helpers.split("\n[grpc]\n").nth(1).expect("[grpc] block");
    let grpc = &grpc[..grpc.find("\n[").unwrap_or(grpc.len())];
    assert!(
        grpc.contains(r#"listen_addr = {{ include "sbc.grpcListen" . | quote }}"#),
        "[grpc] listen_addr must come from sbc.grpcListen:\n{grpc}"
    );
    let define = helm_define(&helpers, "sbc.grpcListen").expect("sbc.grpcListen helper");
    assert!(define.contains("127.0.0.1"), "loopback branch: {define}");
    assert!(
        define.contains(".Values.sbcDaemon.grpcMtls.enabled"),
        "{define}"
    );
    assert!(
        define.contains(".Values.sbcDaemon.config.grpc_listen"),
        "{define}"
    );
}

#[test]
fn qa_helm_trunk_agent_grpc_mtls_supported() {
    let mtls = read_repo("deploy/helm/sbc/templates/26-sbc-grpc-mtls.yaml");
    assert!(
        !mtls.contains("cannot be combined"),
        "trunk agent and grpcMtls must be combinable"
    );
    assert!(
        mtls.contains("-grpc-trunk-agent"),
        "trunk-agent client Certificate"
    );
    let agent = read_repo("deploy/helm/sbc/templates/24-sbc-trunk-agent.yaml");
    for needle in [
        "SBC_DAEMON_GRPC_TLS_CA_FILE",
        "SBC_DAEMON_GRPC_TLS_CERT_FILE",
        "SBC_DAEMON_GRPC_TLS_KEY_FILE",
        r#"include "sbc.daemonGrpcUrl" ."#,
    ] {
        assert!(
            agent.contains(needle),
            "24-sbc-trunk-agent.yaml lacks {needle}"
        );
    }
    assert!(
        !agent.contains("value: \"http://{{ include \"sbc.fullname\" . }}-grpc."),
        "the agent URL must follow grpcMtls (sbc.daemonGrpcUrl), not hard-coded http"
    );
}

#[test]
fn qa_helm_sbc_media_binds_loopback() {
    let deploy = read_repo("deploy/helm/sbc/templates/12-sbc-deployment.yaml");
    let at = deploy
        .find("- name: SBC_MEDIA_GRPC_LISTEN")
        .expect("SBC_MEDIA_GRPC_LISTEN env");
    let value = deploy[at..].lines().nth(1).unwrap().trim();
    assert_eq!(value, "value: \"127.0.0.1:9096\"");
    assert!(
        !deploy.contains("containerPort: 9096"),
        "the loopback media controller port is not advertised"
    );
}

#[test]
fn qa_helm_networkpolicy_template_present() {
    let path = "deploy/helm/sbc/templates/28-sbc-networkpolicy.yaml";
    assert!(repo_path(path).exists(), "{path} missing");
    let np = read_repo(path);
    assert!(np.contains("kind: NetworkPolicy"));
    assert!(
        np.contains(".Values.networkPolicy.enabled"),
        "values switch"
    );
    assert!(np.contains("policyTypes"), "policyTypes");
    assert!(np.contains("- Ingress"), "Ingress policy type");
    assert!(np.contains("-default-deny"), "default-deny baseline");
    let at = np.find("9091").expect("daemon gRPC rule");
    let rule = &np[at.saturating_sub(800)..(at + 800).min(np.len())];
    assert!(
        rule.contains("sbc.apiSelectorLabels"),
        "9091 is admitted from sbc-api pods: {rule}"
    );
}

#[test]
fn qa_helm_provision_trusted_proxies_rendered() {
    let prov = read_repo("deploy/helm/sbc/templates/19-sbc-provision.yaml");
    assert!(
        prov.contains("SBC_TRUSTED_PROXIES"),
        "19-sbc-provision.yaml"
    );
    assert!(prov.contains(".Values.sbcProvision.trustedProxies"));
    let values = read_repo("deploy/helm/sbc/values.yaml");
    let start = values
        .find("\nsbcProvision:\n")
        .expect("sbcProvision block");
    // The sbcProvision block runs until the next top-level key.
    let block = values[start + 1..]
        .lines()
        .enumerate()
        .take_while(|(i, l)| *i == 0 || l.is_empty() || l.starts_with([' ', '#']))
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        block.contains("trustedProxies:"),
        "sbcProvision.trustedProxies value"
    );
}

#[test]
fn qa_central_chart_has_no_default_db_password() {
    let values = read_repo("deploy/helm/central-config/values.yaml");
    for line in values.lines() {
        let t = line.split('#').next().unwrap().trim();
        if let Some(v) = t.strip_prefix("password:") {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            assert!(
                v.is_empty(),
                "central-config default password must be empty: {line}"
            );
        }
    }
    assert!(!values.contains("\"change-me\""), "no change-me default");
    for tpl in ["11-postgres-cnpg.yaml", "10-postgres.yaml"] {
        let t = read_repo(&format!("deploy/helm/central-config/templates/{tpl}"));
        assert!(
            !t.contains("default \"change-me\""),
            "{tpl} defaults the password"
        );
        assert!(t.contains("required"), "{tpl} must require a password");
        assert!(
            t.contains("change-me"),
            "{tpl} must refuse the change-me placeholder"
        );
    }
}

#[test]
fn qa_central_cnpg_dsn_verify_full() {
    let t = read_repo("deploy/helm/central-config/templates/11-postgres-cnpg.yaml");
    let dsns: Vec<&str> = t.lines().filter(|l| l.contains("postgres://")).collect();
    assert!(dsns.len() >= 2, "rw and ro DSNs: {dsns:?}");
    for l in dsns {
        assert!(l.contains("sslmode=verify-full"), "{l}");
        assert!(l.contains("sslrootcert="), "{l}");
    }
}

#[test]
fn qa_keycloak_config_admin_scope_role_bound() {
    let realm: serde_json::Value = serde_json::from_str(&read_repo(
        "deploy/keycloak/dcim-central-config-partial-import.json",
    ))
    .expect("realm JSON");
    let mappings = realm["scopeMappings"]
        .as_array()
        .expect("scopeMappings: config-admin must be bound to a role");
    assert!(
        mappings.iter().any(|m| m["clientScope"] == "config-admin"
            && m["roles"]
                .as_array()
                .is_some_and(|r| r.iter().any(|x| x == "fleet-admin"))),
        "config-admin scope mapped to role fleet-admin: {mappings:?}"
    );
    for client in realm["clients"].as_array().expect("clients") {
        let id = client["clientId"].as_str().unwrap_or_default();
        let has = |k: &str| {
            client[k]
                .as_array()
                .is_some_and(|a| a.iter().any(|s| s == "config-admin"))
        };
        assert!(
            !has("defaultClientScopes"),
            "{id}: config-admin must not be a default scope"
        );
        if id == "usg-uc-config-admin" {
            assert!(
                has("optionalClientScopes"),
                "{id} offers config-admin as optional"
            );
        } else {
            assert!(
                !has("optionalClientScopes"),
                "{id} must not offer config-admin"
            );
        }
    }
}

/// Client-address trust is refused at render time when the NetworkPolicy
/// that makes it sound is off (`trustedProxies`) or the frontend edge is
/// open (`realIpFrom`). Text check; `helm_render` renders it.
#[test]
fn helm_client_address_preflight_present() {
    let helpers = read_repo("deploy/helm/sbc/templates/_helpers.tpl");
    let define = helm_define(&helpers, "sbc.clientAddressPreflight").expect("preflight helper");
    for needle in [
        ".Values.sbcProvision.trustedProxies",
        ".Values.sbcApi.trustedProxies",
        "trustedProxiesWithoutPolicy",
        ".Values.sbcFrontend.realIpFrom",
        "edgeFrom",
        "fail",
    ] {
        assert!(define.contains(needle), "{needle} in {define}");
    }
    let services = read_repo("deploy/helm/sbc/templates/13-sbc-services.yaml");
    assert!(services.contains(r#"include "sbc.clientAddressPreflight" ."#));
    let values = read_repo("deploy/helm/sbc/values.yaml");
    assert!(values.contains("trustedProxiesWithoutPolicy: false"));
}

/// DSN passwords are percent-encoded; the raw value stays in `password`.
#[test]
fn central_dsn_password_url_encoded() {
    for tpl in ["10-postgres.yaml", "11-postgres-cnpg.yaml"] {
        let t = read_repo(&format!("deploy/helm/central-config/templates/{tpl}"));
        assert!(t.contains("urlquery"), "{tpl}");
        for l in t.lines().filter(|l| l.contains("postgres://")) {
            assert!(l.contains("$passUrl"), "{tpl}: {l}");
        }
    }
}

// ── POA&M quick wins: emergency list, Retry-After bound ────────────────

#[test]
fn emergency_numbers_default_when_vps_section_omits_them() {
    let config = load_from_str("[vps]\nenabled = true\n").unwrap();
    assert_eq!(
        config.vps.unwrap().emergency_numbers,
        vec!["911", "933", "112"]
    );
    assert_eq!(
        sbc_config::schema::VpsConfig::default().emergency_numbers,
        vec!["911", "933", "112"]
    );
}

#[test]
fn emergency_numbers_configurable_and_validated() {
    let config = load_from_str("[vps]\nemergency_numbers = [\"911\", \"*99#\"]\n").unwrap();
    assert_eq!(config.vps.unwrap().emergency_numbers, vec!["911", "*99#"]);
    // Empty is accepted (the daemon warns at startup).
    assert!(load_from_str("[vps]\nemergency_numbers = []\n").is_ok());
    for bad in ["\"\"", "\"9-1-1\"", "\"911@evil\"", "\"+\""] {
        let toml = format!("[vps]\nemergency_numbers = [{bad}]\n");
        let err = load_from_str(&toml).expect_err(bad).to_string();
        assert!(err.contains("emergency_numbers"), "{bad}: {err}");
    }
    let many = (0..33)
        .map(|i| format!("\"{i}\""))
        .collect::<Vec<_>>()
        .join(", ");
    assert!(load_from_str(&format!("[vps]\nemergency_numbers = [{many}]\n")).is_err());
}

#[test]
fn trunk_retry_after_max_secs_default_and_range() {
    assert_eq!(default_config().general.trunk_retry_after_max_secs, 300);
    let ok = load_from_str("[general]\ntrunk_retry_after_max_secs = 3600\n").unwrap();
    assert_eq!(ok.general.trunk_retry_after_max_secs, 3600);
    for bad in ["0", "3601", "-1"] {
        assert!(
            load_from_str(&format!("[general]\ntrunk_retry_after_max_secs = {bad}\n")).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn router_emergency_admission_and_cooldown_override() {
    use std::time::Duration;
    use uc_routing::{Admission, Router, RouterConfig, Trunk, TrunkConfig, TrunkGroup};

    let mut router = Router::new(
        RouterConfig::default()
            .with_dial_plan(false)
            .with_default_trunk_group("g"),
    );
    let mut group = TrunkGroup::new("g", "G");
    group.add_trunk(Trunk::new(
        TrunkConfig::new("a", "a.example.com").with_max_calls(1),
    ));
    router.add_trunk_group(group);
    router.route("1").unwrap();
    assert!(router.route("1").is_err(), "a is at max_calls");
    assert_eq!(
        router
            .route_for("911", Admission::Emergency)
            .unwrap()
            .trunk_id,
        "a"
    );
    router.cooldown_trunk("g", "a", Some(Duration::from_secs(120)));
    assert!(
        router.route_for("911", Admission::Emergency).is_err(),
        "cooldown still applies to emergency calls"
    );
}

// NIST 800-53 Rev5: SC-8, SC-23 (POA&M-5) — a TLS trunk needs trunk trust
// anchors; the per-trunk TLS keys are accepted only on TLS trunks.
#[test]
fn test_tls_trunk_requires_trunk_ca_and_accepts_tls_keys() {
    let trunk = r#"
[[trunk_groups]]
id = "g1"
name = "g1"
strategy = "priority"
  [[trunk_groups.trunks]]
  id = "t1"
  host = "sip.example.net"
  port = 5061
  protocol = "tls"
  tls_server_name = "sip.example.net"
"#;
    let err = load_from_str(trunk).unwrap_err().to_string();
    assert!(err.contains("trunk_tls_ca_path"), "{err}");

    let ok = format!("[security]\ntrunk_tls_ca_path = \"/etc/sbc/trunk-ca.pem\"\n{trunk}");
    let config = load_from_str(&ok).unwrap();
    let t = &config.trunk_groups[0].trunks[0];
    assert_eq!(t.tls_server_name.as_deref(), Some("sip.example.net"));
    assert!(!t.tls_client_cert, "mTLS to trunks defaults off");

    let udp = ok.replace("protocol = \"tls\"", "protocol = \"udp\"");
    assert!(load_from_str(&udp).is_err(), "TLS-only keys on a UDP trunk");
}

// NIST 800-53 Rev5: SC-8, CM-6 (POA&M-48) — `require_tls` trunk groups load
// only with a TLS trunk, and route only to TLS trunks.
#[test]
fn test_require_tls_trunk_group_config() {
    use uc_routing::{Router, RouterConfig, Trunk, TrunkConfig, TrunkGroup, TrunkProtocol};

    let mixed = r#"
[security]
trunk_tls_ca_path = "/etc/sbc/trunk-ca.pem"

[[trunk_groups]]
id = "g1"
name = "g1"
strategy = "priority"
require_tls = true
  [[trunk_groups.trunks]]
  id = "udp1"
  host = "192.0.2.10"
  port = 5060
  protocol = "udp"
  priority = 1
  [[trunk_groups.trunks]]
  id = "tls1"
  host = "sip.example.net"
  port = 5061
  protocol = "tls"
  priority = 2
"#;
    let config = load_from_str(mixed).unwrap();
    assert!(config.trunk_groups[0].require_tls);
    assert!(!config.security.require_tls_trunks);

    // Same group without its TLS trunk is a config error.
    let no_tls = mixed
        .split("  [[trunk_groups.trunks]]\n  id = \"tls1\"")
        .next()
        .unwrap();
    let err = load_from_str(no_tls).unwrap_err().to_string();
    assert!(err.contains("require_tls"), "{err}");

    // Global key: a plain UDP group fails to load.
    let global = trunk_toml("").replace(
        "[[trunk_groups]]",
        "[security]\nrequire_tls_trunks = true\n\n[[trunk_groups]]",
    );
    rejected_naming(&global, "require_tls_trunks");

    // Routing over the loaded group never picks the UDP trunk.
    let mut router = Router::new(RouterConfig::default().with_dial_plan(false));
    let g = &config.trunk_groups[0];
    let mut group = TrunkGroup::new(&g.id, &g.name).with_require_tls(g.require_tls);
    for t in &g.trunks {
        let proto = if t.protocol == "tls" {
            TrunkProtocol::Tls
        } else {
            TrunkProtocol::Udp
        };
        group.add_trunk(Trunk::new(
            TrunkConfig::new(&t.id, &t.host)
                .with_protocol(proto)
                .with_priority(t.priority),
        ));
    }
    router.add_trunk_group(group);
    let d = router.route_to_group("1", "g1").unwrap();
    assert_eq!(d.trunk_id, "tls1");
    assert_eq!(d.failover_targets, Vec::<(String, String)>::new());
}

/// QA (POA&M-191): `[monitoring]` fails a full config load end to end,
/// alongside otherwise valid tables; `[cdr.syslog]`-free baseline loads.
#[test]
fn qa_monitoring_table_rejected_on_load() {
    let base = "[general]\ninstance_name = \"qa\"\n";
    assert!(load_from_str(base).is_ok());
    let err = load_from_str(&format!(
        "{base}[monitoring]\nmetrics_bind = \"0.0.0.0:9090\"\n"
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("monitoring"), "{err}");
    // Unknown keys under [monitoring] are an error too (deny_unknown_fields).
    assert!(load_from_str(&format!("{base}[monitoring]\nbogus = 1\n")).is_err());
}

/// QA (POA&M-190): `max_fetches_per_source` bounds via TOML.
#[test]
fn qa_stir_max_fetches_per_source_toml_bounds() {
    let t = |n: usize| {
        format!(
            "[stir_shaken.verification]\nmax_concurrent_fetches = 8\nmax_fetches_per_source = {n}\n"
        )
    };
    assert!(load_from_str(&t(0)).is_err());
    assert!(load_from_str(&t(9)).is_err());
    let c = load_from_str(&t(8)).unwrap();
    assert_eq!(c.stir_shaken.verification.max_fetches_per_source, 8);
    assert_eq!(
        load_from_str("")
            .unwrap()
            .stir_shaken
            .verification
            .max_fetches_per_source,
        4
    );
}

// ── QA SR-53: dashboard / login edge TLS (text checks; `helm_render` renders)
// NIST 800-53 Rev5: SC-8, SC-13, CM-6, CM-7

/// The top-level `<key>:` block of a values file, up to the next top-level key.
fn top_level_block<'a>(values: &'a str, key: &str) -> Option<&'a str> {
    let start = values.find(&format!("\n{key}:\n"))? + 1;
    let body = &values[start..];
    let end = body
        .match_indices('\n')
        .map(|(i, _)| i + 1)
        .find(|&i| {
            body[i..]
                .chars()
                .next()
                .is_some_and(|c| !c.is_whitespace() && c != '#')
        })
        .unwrap_or(body.len());
    Some(&body[..end])
}

/// `key: value` within a block, without trailing comments.
fn block_value<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    block.lines().find_map(|l| {
        let v = l.trim_start().strip_prefix(&format!("{key}:"))?;
        Some(v.split(" #").next().unwrap_or("").trim())
    })
}

/// True when some `fail` call in `tpl` names `needle` within its message.
fn fail_names(tpl: &str, needle: &str) -> bool {
    tpl.match_indices("fail ").any(|(i, _)| {
        let tail = &tpl[i..];
        let end = tail.find("}}").unwrap_or(tail.len());
        tail[..end].contains(needle)
    })
}

#[test]
fn qa_helm_edge_tls_defaults_secure() {
    let values = read_repo("deploy/helm/sbc/values.yaml");
    let edge = top_level_block(&values, "edge").expect("top-level edge: block in values.yaml");
    assert_eq!(
        block_value(edge, "insecureLabHttp"),
        Some("false"),
        "{edge}"
    );
    assert_eq!(block_value(edge, "entryPoint"), Some("websecure"), "{edge}");
    assert_eq!(block_value(edge, "createTlsOption"), Some("true"), "{edge}");
    assert_eq!(block_value(edge, "httpRedirect"), Some("true"), "{edge}");
    assert_eq!(
        block_value(edge, "allowHttpProvisioning"),
        Some("false"),
        "{edge}"
    );
}

#[test]
fn qa_helm_ingress_template_fails_without_tls() {
    let ing = read_repo("deploy/helm/sbc/templates/22-sbc-ingress.yaml");
    assert!(ing.contains("router.entrypoints"), "entrypoint pin");
    assert!(
        fail_names(&ing, "ingressTlsSecretName"),
        "22-sbc-ingress.yaml must fail naming ingressTlsSecretName"
    );
    let fe = read_repo("deploy/helm/sbc/templates/16-sbc-frontend.yaml");
    assert!(
        fail_names(&fe, "edge.insecureLabHttp"),
        "16-sbc-frontend.yaml must fail naming edge.insecureLabHttp"
    );
}

#[test]
fn qa_helm_edge_tlsoption_template_tls13_p384() {
    let t = read_repo("deploy/helm/sbc/templates/29-sbc-edge-tls.yaml");
    assert!(t.contains("apiVersion: traefik.io/v1alpha1"), "{t}");
    assert!(
        t.matches("VersionTLS13").count() >= 2,
        "min and max TLS 1.3"
    );
    assert!(t.contains("CurveP384"));
    assert!(t.contains("TLS_AES_256_GCM_SHA384"));
    assert!(!t.contains("VersionTLS12"));
}

#[test]
fn qa_helm_edge_text_helpers_self_test() {
    let v = "a: 1\nedge:\n  insecureLabHttp: false   # lab\n  # c\n  traefik:\n    entryPoint: websecure\nnext:\n  x: 1\n";
    let e = top_level_block(v, "edge").unwrap();
    assert_eq!(block_value(e, "insecureLabHttp"), Some("false"));
    assert_eq!(block_value(e, "entryPoint"), Some("websecure"));
    assert!(block_value(e, "x").is_none());
    assert!(fail_names(
        "{{- fail \"set sbcClientConfig.ingressTlsSecretName\" }}",
        "ingressTlsSecretName"
    ));
    assert!(!fail_names(
        "{{ fail \"x\" }} ingressTlsSecretName",
        "ingressTlsSecretName"
    ));
}
