//! QA: `helm template` / `helm lint` checks for the sbc and central-config
//! charts (containment hardening: daemon gRPC mTLS, NetworkPolicy, media
//! controller loopback, trusted proxies, central Postgres credentials and
//! TLS).
//!
//! CI images have no `helm` binary, so every test is ignored by default.
//! Run locally (helm v3.14+ or v4) with:
//!
//! ```text
//! cargo test -p sbc-integration-tests --lib helm_render -- --ignored
//! ```
//!
//! The always-run text checks live in `config_tests.rs`.
//!
//! ## NIST 800-53 Rev5: CM-6, CM-7, SC-7, SC-8, IA-3, IA-5

use std::path::PathBuf;
use std::process::Command;

/// Values the sbc chart cannot render without.
const SBC_MIN: &[&str] = &[
    "sbcApi.ha1Key.existingSecret=x",
    "sbcPostgres.password=p",
    "sbcClientConfig.ingressTlsSecretName=qa-edge-tls",
];
/// The extra input the daemon gRPC mTLS default needs.
const SBC_ISSUER: &str = "sbcDaemon.grpcMtls.clusterIssuer=qa-issuer";
/// Values the central-config chart cannot render without.
const CENTRAL_MIN: &[&str] = &["api.oidc.issuer=https://idp.example/realms/r"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// Appends `--set k=v` (or `--set-json` for a `json:` prefix).
fn push_sets(cmd: &mut Command, sets: &[&str]) {
    for s in sets {
        if let Some(j) = s.strip_prefix("json:") {
            cmd.args(["--set-json", j]);
        } else {
            cmd.args(["--set", s]);
        }
    }
}

/// `helm template t deploy/helm/<chart> --kube-version 1.30.0 ...`.
/// `Ok(stdout)` on success, `Err(stderr)` when the chart refuses to render.
fn render(chart: &str, sets: &[&str], show_only: Option<&str>) -> Result<String, String> {
    let mut cmd = Command::new("helm");
    cmd.current_dir(repo_root())
        .args(["template", "t", &format!("deploy/helm/{chart}")])
        .args(["--kube-version", "1.30.0"]);
    push_sets(&mut cmd, sets);
    if let Some(s) = show_only {
        cmd.args(["--show-only", s]);
    }
    let out = cmd.output().expect("run helm (is it on PATH?)");
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

fn sbc(extra: &[&str]) -> Result<String, String> {
    let sets: Vec<&str> = SBC_MIN.iter().chain(extra).copied().collect();
    render("sbc", &sets, None)
}

fn central(extra: &[&str]) -> Result<String, String> {
    let sets: Vec<&str> = CENTRAL_MIN.iter().chain(extra).copied().collect();
    render("central-config", &sets, None)
}

fn must_render(r: Result<String, String>, what: &str) -> String {
    r.unwrap_or_else(|e| panic!("{what} should render:\n{e}"))
}

fn must_fail(r: Result<String, String>, needle: &str, what: &str) {
    match r {
        Ok(_) => panic!("{what} must fail to render (expected an error naming {needle})"),
        Err(e) => assert!(
            e.contains(needle),
            "{what}: error should name {needle}:\n{e}"
        ),
    }
}

/// Rendered YAML documents.
fn docs(out: &str) -> Vec<&str> {
    out.split("\n---").filter(|d| d.contains("kind:")).collect()
}

fn kind_of(doc: &str) -> &str {
    doc.lines()
        .find_map(|l| l.strip_prefix("kind: "))
        .unwrap_or("")
        .trim()
}

fn name_of(doc: &str) -> &str {
    let meta = doc.split("\nmetadata:\n").nth(1).unwrap_or("");
    meta.lines()
        .find_map(|l| l.strip_prefix("  name: "))
        .unwrap_or("")
        .trim()
        .trim_matches('"')
}

fn find<'a>(out: &'a str, kind: &str, name: &str) -> Option<&'a str> {
    docs(out)
        .into_iter()
        .find(|d| kind_of(d) == kind && name_of(d) == name)
}

fn get<'a>(out: &'a str, kind: &str, name: &str) -> &'a str {
    find(out, kind, name).unwrap_or_else(|| {
        let have: Vec<String> = docs(out)
            .iter()
            .map(|d| format!("{}/{}", kind_of(d), name_of(d)))
            .collect();
        panic!("no {kind}/{name} rendered; have {have:?}")
    })
}

/// The chart's fullname (the ServiceAccount carries it).
fn fullname(out: &str) -> String {
    docs(out)
        .into_iter()
        .find(|d| kind_of(d) == "ServiceAccount")
        .map(|d| name_of(d).to_string())
        .expect("ServiceAccount")
}

/// The `|` block scalar under `key:` (dedented).
fn block_scalar(doc: &str, key: &str) -> String {
    let marker = format!("{key}: |");
    let at = doc.find(&marker).unwrap_or_else(|| panic!("{key} block"));
    let line_start = doc[..at].rfind('\n').map_or(0, |i| i + 1);
    let mut lines = doc[line_start..].lines();
    let head = lines.next().unwrap();
    let base = head.len() - head.trim_start().len();
    let mut indent = None;
    let mut out = String::new();
    for l in lines {
        if l.trim().is_empty() {
            out.push('\n');
            continue;
        }
        let ind = l.len() - l.trim_start().len();
        if ind <= base {
            break;
        }
        let i = *indent.get_or_insert(ind);
        out.push_str(l.get(i..).unwrap_or_else(|| l.trim_start()));
        out.push('\n');
    }
    out
}

/// The value line(s) that follow `- name: <env>` (up to the next env).
fn env_entry<'a>(doc: &'a str, env: &str) -> Option<&'a str> {
    let at = doc.find(&format!("- name: {env}\n"))?;
    let rest = &doc[at + 2..];
    let end = rest.find("- name: ").unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Items of the `ingress:` list of a NetworkPolicy, one string each.
fn ingress_rules(doc: &str) -> Vec<String> {
    let Some(at) = doc.find("\n  ingress:\n") else {
        return Vec::new();
    };
    let body = &doc[at + "\n  ingress:\n".len()..];
    let mut rules: Vec<String> = Vec::new();
    let mut item_indent = None;
    for l in body.lines() {
        if l.trim().is_empty() {
            continue;
        }
        let ind = l.len() - l.trim_start().len();
        let ii = *item_indent.get_or_insert(ind);
        if ind < ii {
            break;
        }
        if ind == ii && l.trim_start().starts_with("- ") {
            rules.push(String::new());
        } else if ind == ii {
            break;
        }
        if let Some(r) = rules.last_mut() {
            r.push_str(l);
            r.push('\n');
        }
    }
    rules
}

fn components(rule: &str) -> Vec<String> {
    rule.lines()
        .filter_map(|l| l.trim().strip_prefix("app.kubernetes.io/component:"))
        .map(|c| c.trim().trim_matches('"').to_string())
        .collect()
}

fn grpc_rule(np: &str) -> Option<String> {
    ingress_rules(np)
        .into_iter()
        .find(|r| r.contains("port: 9091"))
}

/// The daemon `config.toml` from the `-config` ConfigMap, pod IP filled in.
fn daemon_config(out: &str) -> String {
    let cm = get(out, "ConfigMap", &format!("{}-config", fullname(out)));
    block_scalar(cm, "config.toml").replace("__POD_IP__", "10.0.0.5")
}

// ── daemon gRPC ────────────────────────────────────────────────

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_mtls_default_with_issuer() {
    let out = must_render(sbc(&[SBC_ISSUER]), "minimal + clusterIssuer");
    let cfg = sbc_config::load_from_str(&daemon_config(&out)).expect("rendered config loads");
    let grpc = cfg.grpc.expect("[grpc]");
    assert!(grpc.enabled && grpc.require_mtls, "{grpc:?}");
    assert_eq!(grpc.listen_addr, "0.0.0.0:9091".parse().unwrap());

    let fname = fullname(&out);
    get(&out, "NetworkPolicy", &format!("{fname}-default-deny"));
    let daemon = get(&out, "NetworkPolicy", &format!("{fname}-daemon"));
    assert!(daemon.contains("- Ingress"), "{daemon}");
    let rule = grpc_rule(daemon).expect("9091 rule with mTLS");
    assert_eq!(components(&rule), vec!["api".to_string()], "{rule}");
    for port in ["port: 5060", "port: 5061", "port: 16384", "endPort: 32768"] {
        assert!(
            daemon.contains(port),
            "daemon policy lacks {port}:\n{daemon}"
        );
    }
    assert!(!daemon.contains("port: 9096"), "no media-controller rule");
    get(&out, "Service", &format!("{fname}-grpc"));
}

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_mtls_default_without_issuer_fails() {
    must_fail(
        sbc(&[]),
        "grpcMtls.clusterIssuer",
        "minimal values without an issuer or Secret names",
    );
    // Explicit Secret names are the alternative to an issuer.
    must_render(
        sbc(&[
            "sbcDaemon.grpcMtls.serverSecretName=srv",
            "sbcDaemon.grpcMtls.clientSecretName=cli",
        ]),
        "explicit gRPC Secret names",
    );
}

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_plaintext_grpc_with_sbc_api_fails() {
    must_fail(
        sbc(&["sbcDaemon.grpcMtls.enabled=false"]),
        "sbcApi.enabled",
        "grpcMtls off with sbc-api on",
    );
    must_fail(
        sbc(&[
            "sbcDaemon.grpcMtls.enabled=false",
            "sbcApi.enabled=false",
            "sbcTrunkAgent.enabled=true",
        ]),
        "sbcTrunkAgent.enabled",
        "grpcMtls off with the trunk agent on",
    );
}

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_plaintext_grpc_is_loopback_only() {
    let out = must_render(
        sbc(&["sbcDaemon.grpcMtls.enabled=false", "sbcApi.enabled=false"]),
        "grpcMtls off, no in-cluster gRPC clients",
    );
    let cfg = sbc_config::load_from_str(&daemon_config(&out)).expect("rendered config loads");
    let grpc = cfg.grpc.expect("[grpc]");
    assert!(!grpc.require_mtls);
    assert_eq!(grpc.listen_addr, "127.0.0.1:9091".parse().unwrap());
    let fname = fullname(&out);
    assert!(
        find(&out, "Service", &format!("{fname}-grpc")).is_none(),
        "no gRPC Service for a loopback listener"
    );
    let daemon = get(&out, "NetworkPolicy", &format!("{fname}-daemon"));
    assert!(grpc_rule(daemon).is_none(), "no 9091 rule:\n{daemon}");
}

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_trunk_agent_with_mtls() {
    let out = must_render(
        sbc(&[SBC_ISSUER, "sbcTrunkAgent.enabled=true"]),
        "trunk agent + issuer",
    );
    let fname = fullname(&out);
    let cert = get(&out, "Certificate", &format!("{fname}-grpc-trunk-agent"));
    assert!(
        cert.contains(&format!("{fname}-sbc-trunk-agent")),
        "trunk-agent Certificate names the agent CN"
    );
    assert!(
        cert.contains("client auth"),
        "trunk-agent Certificate has client auth"
    );
    assert!(
        cert.contains("384"),
        "trunk-agent Certificate uses a P-384 key"
    );

    let cfg = sbc_config::load_from_str(&daemon_config(&out)).expect("rendered config loads");
    let names = cfg.grpc.expect("[grpc]").allowed_client_names;
    assert!(names.contains(&format!("{fname}-sbc-api")), "{names:?}");
    assert!(
        names.contains(&format!("{fname}-sbc-trunk-agent")),
        "{names:?}"
    );

    let agent = get(&out, "Deployment", &format!("{fname}-trunk-agent"));
    let url = env_entry(agent, "SBC_DAEMON_GRPC_URL").expect("SBC_DAEMON_GRPC_URL");
    assert!(url.contains("value: \"https://"), "{url}");
    for env in [
        "SBC_DAEMON_GRPC_TLS_CA_FILE",
        "SBC_DAEMON_GRPC_TLS_CERT_FILE",
        "SBC_DAEMON_GRPC_TLS_KEY_FILE",
    ] {
        assert!(env_entry(agent, env).is_some(), "agent lacks {env}");
    }

    let daemon = get(&out, "NetworkPolicy", &format!("{fname}-daemon"));
    let mut from = components(&grpc_rule(daemon).expect("9091 rule"));
    from.sort();
    assert_eq!(from, vec!["api".to_string(), "trunk-agent".to_string()]);
}

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_plaintext_wildcard_listen_fails() {
    must_fail(
        sbc(&[
            "sbcDaemon.grpcMtls.enabled=false",
            "sbcApi.enabled=false",
            "sbcDaemon.config.grpc_listen=0.0.0.0:9091",
        ]),
        "grpc_listen",
        "plaintext gRPC with an explicit wildcard listen",
    );
}

// ── media controller ───────────────────────────────────────────

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_media_split_loopback() {
    let out = must_render(
        sbc(&[SBC_ISSUER, "mediaSplit.enabled=true"]),
        "mediaSplit on",
    );
    let fname = fullname(&out);
    let daemon = get(&out, "Deployment", &fname);
    let listen = env_entry(daemon, "SBC_MEDIA_GRPC_LISTEN").expect("SBC_MEDIA_GRPC_LISTEN");
    assert!(listen.contains("value: \"127.0.0.1:9096\""), "{listen}");
    assert!(
        !daemon.contains("containerPort: 9096"),
        "media controller port must not be advertised"
    );
}

// ── SR-57: connection caps sized for the pod ───────────────────
// NIST 800-53 Rev5: SC-5, SC-6, CM-6

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_connection_caps() {
    let out = must_render(sbc(&[SBC_ISSUER]), "minimal + clusterIssuer");
    let rendered = daemon_config(&out);
    assert!(
        rendered.contains("max_connections_total = 8000"),
        "default render sets max_connections_total = 8000:\n{rendered}"
    );
    let cfg = sbc_config::load_from_str(&rendered).expect("rendered config loads");
    assert_eq!(cfg.transport.max_connections_total, 8000);
    assert_eq!(cfg.transport.max_connections_per_listener, 6000);

    let out = must_render(
        sbc(&[
            SBC_ISSUER,
            "sbcDaemon.config.max_connections_total=4000",
            "sbcDaemon.config.max_connections_per_listener=3000",
        ]),
        "caps overridden",
    );
    let cfg = sbc_config::load_from_str(&daemon_config(&out)).expect("rendered config loads");
    assert_eq!(cfg.transport.max_connections_total, 4000);
    assert_eq!(cfg.transport.max_connections_per_listener, 3000);

    // A values file parses large numbers as floats; `| int64` keeps them
    // integers (`4e+06` would fail to load as a u32).
    let values = std::env::temp_dir().join(format!(
        "qa-helm-connection-caps-{}.yaml",
        std::process::id()
    ));
    std::fs::write(
        &values,
        "sbcDaemon:\n  config:\n    max_connections_per_listener: 1000000\n    \
         max_connections_total: 4000000\n",
    )
    .expect("write values file");
    let mut cmd = Command::new("helm");
    cmd.current_dir(repo_root())
        .args([
            "template",
            "t",
            "deploy/helm/sbc",
            "--kube-version",
            "1.30.0",
        ])
        .arg("-f")
        .arg(&values);
    let sets: Vec<&str> = SBC_MIN.iter().copied().chain([SBC_ISSUER]).collect();
    push_sets(&mut cmd, &sets);
    let res = cmd.output().expect("run helm");
    let _ = std::fs::remove_file(&values);
    assert!(
        res.status.success(),
        "values-file render failed:\n{}",
        String::from_utf8_lossy(&res.stderr)
    );
    let rendered = daemon_config(&String::from_utf8_lossy(&res.stdout));
    assert!(
        rendered.contains("max_connections_total = 4000000"),
        "values-file caps render as integers:\n{rendered}"
    );
    let cfg = sbc_config::load_from_str(&rendered).expect("values-file config loads");
    assert_eq!(cfg.transport.max_connections_total, 4_000_000);
    assert_eq!(cfg.transport.max_connections_per_listener, 1_000_000);
}

// ── trusted proxies, provisioning secret, nginx real IP ────────

/// An edge peer for the frontend policy (ingress controller namespace).
const EDGE_FROM: &str = r#"json:networkPolicy.edgeFrom=[{"namespaceSelector":{"matchLabels":{"kubernetes.io/metadata.name":"ingress"}}}]"#;

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn helm_render_trusted_proxies_need_network_policy() {
    for tp in [
        "sbcProvision.trustedProxies={10.42.0.0/16}",
        "sbcApi.trustedProxies={10.42.0.0/16}",
    ] {
        must_fail(
            sbc(&[SBC_ISSUER, tp, "networkPolicy.enabled=false"]),
            "networkPolicy.enabled",
            "trustedProxies with NetworkPolicy off",
        );
        must_render(
            sbc(&[
                SBC_ISSUER,
                tp,
                "networkPolicy.enabled=false",
                "networkPolicy.trustedProxiesWithoutPolicy=true",
            ]),
            "trustedProxies with NetworkPolicy off and the explicit acknowledgement",
        );
        must_render(
            sbc(&[SBC_ISSUER, tp]),
            "trustedProxies with NetworkPolicy on",
        );
    }
}

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn helm_render_real_ip_from_needs_edge_from() {
    must_fail(
        sbc(&[SBC_ISSUER, "sbcFrontend.realIpFrom={10.42.0.7/32}"]),
        "networkPolicy.edgeFrom",
        "realIpFrom with an open frontend policy",
    );
    let out = must_render(
        sbc(&[
            SBC_ISSUER,
            "sbcFrontend.realIpFrom={10.42.0.7/32}",
            EDGE_FROM,
        ]),
        "realIpFrom with edgeFrom",
    );
    let np = get(
        &out,
        "NetworkPolicy",
        &format!("{}-frontend", fullname(&out)),
    );
    assert!(np.contains("namespaceSelector"), "{np}");
}

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn helm_render_central_dsn_password_is_url_encoded() {
    let out = must_render(
        central(&["postgres.mode=cnpg", "postgres.cnpg.password=p@ss/w?rd#1%"]),
        "cnpg with a password needing escapes",
    );
    let secret = get(&out, "Secret", &format!("{}-cnpg", fullname(&out)));
    let dsn = secret
        .lines()
        .find(|l| l.trim_start().starts_with("dsn:"))
        .expect("dsn");
    assert!(dsn.contains(":p%40ss%2Fw%3Frd%231%25@"), "{dsn}");
    let pw = secret
        .lines()
        .find(|l| l.trim_start().starts_with("password:"))
        .expect("password");
    assert!(pw.contains("p@ss/w?rd#1%"), "raw password kept: {pw}");
    let out = must_render(
        central(&["postgres.password=p@ss/w?rd#1%"]),
        "bundled with a password needing escapes",
    );
    assert!(
        out.contains(":p%40ss%2Fw%3Frd%231%25@"),
        "bundled DSN escaped"
    );
}

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_provision_trusted_proxies() {
    must_fail(
        sbc(&[
            SBC_ISSUER,
            "sbcProvision.allowedSourceCidrs={10.0.100.0/24}",
        ]),
        "trustedProxies",
        "provision source CIDRs without trusted proxies",
    );
    let out = must_render(
        sbc(&[
            SBC_ISSUER,
            "sbcProvision.allowedSourceCidrs={10.0.100.0/24}",
            "sbcProvision.trustedProxies={10.42.0.0/16}",
            "sbcProvision.provisionSecret.existingSecret=s",
        ]),
        "provision with trusted proxies and secret",
    );
    let fname = fullname(&out);
    let prov = get(&out, "Deployment", &format!("{fname}-provision"));
    let tp = env_entry(prov, "SBC_TRUSTED_PROXIES").expect("SBC_TRUSTED_PROXIES");
    assert!(tp.contains("10.42.0.0/16"), "{tp}");
    let secret = env_entry(prov, "SBC_PROVISION_SECRET").expect("SBC_PROVISION_SECRET");
    assert!(
        secret.contains("secretKeyRef"),
        "SBC_PROVISION_SECRET comes from a secretKeyRef"
    );
    assert!(
        secret.contains("name: s\n"),
        "SBC_PROVISION_SECRET references the existing Secret"
    );
}

/// The sbc-api login limiter keys on `X-Real-IP` only from the networks in
/// `SBC_TRUSTED_PROXIES`; the chart must pass `sbcApi.trustedProxies`
/// through, and leave the variable unset when the value is empty.
/// NIST 800-53 Rev5: AC-7, SC-7
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_sbc_api_trusted_proxies() {
    let out = must_render(
        sbc(&[SBC_ISSUER, "sbcApi.trustedProxies={10.42.0.0/16}"]),
        "sbc-api with trusted proxies",
    );
    let fname = fullname(&out);
    let api = get(&out, "Deployment", &format!("{fname}-sbc-api"));
    let tp = env_entry(api, "SBC_TRUSTED_PROXIES").expect("SBC_TRUSTED_PROXIES on sbc-api");
    assert!(tp.contains("value: \"10.42.0.0/16\""), "{tp}");

    let out = must_render(sbc(&[SBC_ISSUER]), "sbc-api default");
    let api = get(&out, "Deployment", &format!("{fname}-sbc-api"));
    assert!(
        env_entry(api, "SBC_TRUSTED_PROXIES").is_none(),
        "SBC_TRUSTED_PROXIES must be absent without sbcApi.trustedProxies"
    );
}

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_frontend_real_ip_from() {
    let out = must_render(sbc(&[SBC_ISSUER]), "default frontend");
    let fname = fullname(&out);
    let fe = get(&out, "Deployment", &format!("{fname}-frontend"));
    assert!(
        env_entry(fe, "SBC_REAL_IP_CONF").is_some(),
        "SBC_REAL_IP_CONF must always be defined (envsubst)"
    );

    // realIpFrom needs networkPolicy.edgeFrom (only the edge may reach nginx).
    let out = must_render(
        sbc(&[
            SBC_ISSUER,
            "sbcFrontend.realIpFrom={10.42.0.0/16}",
            EDGE_FROM,
        ]),
        "frontend realIpFrom",
    );
    let fe = get(&out, "Deployment", &format!("{fname}-frontend"));
    let conf = env_entry(fe, "SBC_REAL_IP_CONF").expect("SBC_REAL_IP_CONF");
    assert!(conf.contains("set_real_ip_from 10.42.0.0/16;"), "{conf}");

    must_fail(
        sbc(&[
            SBC_ISSUER,
            r#"json:sbcFrontend.realIpFrom=["1.2.3.4/8; evil"]"#,
        ]),
        "realIpFrom",
        "malformed realIpFrom entry",
    );
}

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_networkpolicy_switch() {
    let out = must_render(
        sbc(&[SBC_ISSUER, "networkPolicy.enabled=false"]),
        "networkPolicy off",
    );
    assert!(!out.contains("kind: NetworkPolicy"));
    let on = must_render(sbc(&[SBC_ISSUER]), "networkPolicy default");
    assert!(
        on.contains("kind: NetworkPolicy"),
        "NetworkPolicy on by default"
    );
}

// ── central-config Postgres ────────────────────────────────────

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_central_cnpg_password_and_tls() {
    must_fail(
        central(&["postgres.mode=cnpg"]),
        "postgres.cnpg.password",
        "cnpg without a password",
    );
    must_fail(
        central(&["postgres.mode=cnpg", "postgres.cnpg.password=change-me"]),
        "change-me",
        "cnpg with the placeholder password",
    );
    let out = must_render(
        central(&["postgres.mode=cnpg", "postgres.cnpg.password=s3cret"]),
        "cnpg with a password",
    );
    let fname = fullname(&out);
    let secret = get(&out, "Secret", &format!("{fname}-cnpg"));
    let tls = "sslmode=verify-full&sslrootcert=/etc/central-config/pg-ca/ca.crt";
    for key in ["dsn:", "dsnRo:"] {
        let line = secret
            .lines()
            .find(|l| l.trim_start().starts_with(key))
            .unwrap_or_else(|| panic!("{key} present in the CNPG Secret"));
        assert!(
            line.contains(tls),
            "{key} uses sslmode=verify-full with the CNPG CA"
        );
    }
    let api = get(&out, "Deployment", &format!("{fname}-api"));
    assert!(
        api.contains(&format!("{fname}-pg-ca")),
        "CA Secret mount:\n{api}"
    );
    assert!(api.contains("/etc/central-config/pg-ca"), "{api}");

    let out = must_render(
        central(&["postgres.mode=cnpg", "postgres.cnpg.existingSecret=x"]),
        "cnpg with an operator-owned Secret",
    );
    assert!(
        find(&out, "Secret", &format!("{fname}-cnpg")).is_none(),
        "no chart-owned credential Secret"
    );
    let api = get(&out, "Deployment", &format!("{fname}-api"));
    for env in ["CENTRAL_POSTGRES_URL", "CENTRAL_POSTGRES_RO_URL"] {
        let e = env_entry(api, env).unwrap_or_else(|| panic!("{env}"));
        assert!(
            e.contains("name: x\n"),
            "{env} must reference the operator Secret: {e}"
        );
    }
}

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_central_bundled_requires_password() {
    must_fail(central(&[]), "postgres.password", "bundled default");
    must_fail(
        central(&["postgres.password=change-me"]),
        "change-me",
        "bundled with the placeholder password",
    );
    let out = must_render(central(&["postgres.password=s3cret"]), "bundled");
    assert!(
        out.contains("sslmode=disable"),
        "lab DSN is explicit about plaintext"
    );
}

// ── Lint ──────────────────────────────────────────────────────────────

fn lint(chart: &str, files: &[&str], sets: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new("helm");
    cmd.current_dir(repo_root())
        .args(["lint", &format!("deploy/helm/{chart}")])
        .args(["--kube-version", "1.30.0"]);
    for f in files {
        cmd.args(["-f", f]);
    }
    push_sets(&mut cmd, sets);
    let out = cmd.output().expect("run helm");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(text)
    } else {
        Err(text)
    }
}

#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_lint_both_charts() {
    let sbc_sets: Vec<&str> = SBC_MIN.iter().copied().chain([SBC_ISSUER]).collect();
    must_render(lint("sbc", &[], &sbc_sets), "helm lint sbc");
    must_render(
        lint(
            "sbc",
            &["deploy/helm/sites/sbc/oopl-001/values.yaml"],
            &sbc_sets,
        ),
        "helm lint sbc with oopl-001",
    );
    let central_sets: Vec<&str> = CENTRAL_MIN
        .iter()
        .copied()
        .chain(["postgres.password=s3cret"])
        .collect();
    must_render(
        lint("central-config", &[], &central_sets),
        "helm lint central-config",
    );
}

/// The text helpers above, on a fixed document (runs without helm).
#[test]
fn qa_helm_render_parsers_self_test() {
    let out = r#"---
# Source: sbc/templates/00-sa.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sbc-x
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sbc-x-daemon
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/component: daemon
  policyTypes:
    - Ingress
  ingress:
    - ports:
        - { protocol: UDP, port: 5060 }
    - from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/instance: t
              app.kubernetes.io/component: api
        - podSelector:
            matchLabels:
              app.kubernetes.io/component: trunk-agent
      ports:
        - protocol: TCP
          port: 9091
---
kind: Deployment
metadata:
  name: sbc-x
spec:
  template:
    spec:
      containers:
        - env:
            - name: A
              value: "1"
            - name: B
              valueFrom:
                secretKeyRef:
                  name: s
                  key: k
"#;
    assert_eq!(fullname(out), "sbc-x");
    let np = get(out, "NetworkPolicy", "sbc-x-daemon");
    let rules = ingress_rules(np);
    assert_eq!(rules.len(), 2, "{rules:?}");
    let rule = grpc_rule(np).unwrap();
    assert_eq!(components(&rule), vec!["api", "trunk-agent"]);
    let d = get(out, "Deployment", "sbc-x");
    assert!(env_entry(d, "A").unwrap().contains("value: \"1\""));
    assert!(env_entry(d, "B").unwrap().contains("name: s\n"));
    assert!(find(out, "Service", "sbc-x").is_none());
    let cm = "data:\n  config.toml: |\n    [grpc]\n    enabled = true\n\n    x = 1\n  other: y\n";
    assert_eq!(
        block_scalar(cm, "config.toml"),
        "[grpc]\nenabled = true\n\nx = 1\n"
    );
}

// ── SR-53: dashboard / login edge TLS (Traefik) ───────────────────────
// NIST 800-53 Rev5: SC-8, SC-8(1), SC-13, SC-23, AC-17(2), IA-5(1), CM-6, CM-7

/// `helm template` with `-f <values_file>` (repo-relative) before the sets.
fn render_values(chart: &str, values_file: &str, sets: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new("helm");
    cmd.current_dir(repo_root())
        .args(["template", "t", &format!("deploy/helm/{chart}")])
        .args(["--kube-version", "1.30.0"])
        .args(["-f", values_file]);
    push_sets(&mut cmd, sets);
    let out = cmd.output().expect("run helm (is it on PATH?)");
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned())
    }
}

/// The value of the first `key: value` line (any indent), unquoted.
fn scalar<'a>(doc: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}:");
    doc.lines().find_map(|l| {
        let v = l.trim_start().strip_prefix(&prefix)?;
        Some(v.trim().trim_matches('"').trim_matches('\''))
    })
}

/// A `metadata.annotations` value.
fn annotation<'a>(doc: &'a str, key: &str) -> Option<&'a str> {
    scalar(doc, key)
}

/// The list under `key:`, block (`- a`) or flow (`[a, b]`) style.
fn yaml_list(doc: &str, key: &str) -> Vec<String> {
    let marker = format!("{key}:");
    let Some((i, head)) = doc
        .lines()
        .enumerate()
        .find(|(_, l)| l.trim_start().starts_with(&marker))
    else {
        return Vec::new();
    };
    let unq = |s: &str| s.trim().trim_matches('"').trim_matches('\'').to_string();
    let rest = head.trim_start()[marker.len()..].trim();
    if let Some(flow) = rest.strip_prefix('[') {
        return flow
            .trim_end_matches(']')
            .split(',')
            .map(unq)
            .filter(|s| !s.is_empty())
            .collect();
    }
    let base = head.len() - head.trim_start().len();
    let mut items = Vec::new();
    for l in doc.lines().skip(i + 1) {
        if l.trim().is_empty() {
            continue;
        }
        let ind = l.len() - l.trim_start().len();
        let t = l.trim_start();
        if ind < base || (ind == base && !t.starts_with("- ")) {
            break;
        }
        if let Some(item) = t.strip_prefix("- ") {
            items.push(unq(item));
        }
    }
    items
}

/// Every `- path:` of an Ingress.
fn ingress_paths(doc: &str) -> Vec<String> {
    doc.lines()
        .filter_map(|l| l.trim_start().strip_prefix("- path:"))
        .map(|p| p.trim().trim_matches('"').to_string())
        .collect()
}

fn has_spec_tls(doc: &str) -> bool {
    doc.contains("\n  tls:\n")
}

const EP: &str = "traefik.ingress.kubernetes.io/router.entrypoints";
const RTLS: &str = "traefik.ingress.kubernetes.io/router.tls";
const RTLS_OPT: &str = "traefik.ingress.kubernetes.io/router.tls.options";
const RMW: &str = "traefik.ingress.kubernetes.io/router.middlewares";
const NO_SECRET: &str = "sbcClientConfig.ingressTlsSecretName=";
const LAB: &str = "edge.insecureLabHttp=true";

fn entrypoints(doc: &str) -> Vec<String> {
    annotation(doc, EP)
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// T1: no TLS secret and no lab flag fails closed, naming the key.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_ingress_requires_tls_secret() {
    must_fail(
        sbc(&[SBC_ISSUER, NO_SECRET]),
        "sbcClientConfig.ingressTlsSecretName",
        "client-config Ingress without a TLS secret",
    );
    // The client-config route carries bearer tokens even without the dashboard.
    must_fail(
        sbc(&[SBC_ISSUER, NO_SECRET, "sbcFrontend.enabled=false"]),
        "sbcClientConfig.ingressTlsSecretName",
        "client-config Ingress (no frontend) without a TLS secret",
    );
}

/// T2: the lab flag renders today's cleartext Ingress, with no TLS objects;
/// the flag is off by default.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_ingress_insecure_lab_flag() {
    let out = must_render(sbc(&[SBC_ISSUER, NO_SECRET, LAB]), "lab HTTP ingress");
    let fname = fullname(&out);
    let ing = get(&out, "Ingress", &format!("{fname}-client-config"));
    assert!(!has_spec_tls(ing), "lab Ingress must not carry tls:\n{ing}");
    assert!(annotation(ing, RTLS).is_none(), "{ing}");
    assert!(annotation(ing, RTLS_OPT).is_none(), "{ing}");
    assert!(
        docs(&out).iter().all(|d| kind_of(d) != "TLSOption"),
        "no TLSOption in lab mode"
    );
    assert!(find(&out, "Middleware", &format!("{fname}-hsts")).is_none());

    // Off by default: the default render (secret set) is TLS-only.
    let out = must_render(sbc(&[SBC_ISSUER]), "default ingress");
    let ing = get(&out, "Ingress", &format!("{fname}-client-config"));
    assert_eq!(annotation(ing, RTLS), Some("true"), "{ing}");
}

/// T3: the Ingress router is bound to websecure only, with the CNSA
/// TLSOption and the HSTS middleware.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_ingress_websecure_only() {
    let out = must_render(sbc(&[SBC_ISSUER]), "ingress with TLS secret");
    let fname = fullname(&out);
    let ing = get(&out, "Ingress", &format!("{fname}-client-config"));
    assert_eq!(entrypoints(ing), vec!["websecure"], "{ing}");
    assert_eq!(annotation(ing, RTLS), Some("true"), "{ing}");
    assert_eq!(
        annotation(ing, RTLS_OPT),
        Some(format!("default-{fname}-cnsa@kubernetescrd").as_str()),
        "{ing}"
    );
    let mw = annotation(ing, RMW).unwrap_or("");
    assert!(
        mw.split(',')
            .any(|m| m.trim() == format!("default-{fname}-hsts@kubernetescrd")),
        "router.middlewares must include the HSTS middleware: {mw:?}"
    );
    assert!(has_spec_tls(ing), "{ing}");
    assert_eq!(scalar(ing, "secretName"), Some("qa-edge-tls"));
    assert!(ing.contains("\"sbc.kfk-001.usg.example.com\""), "{ing}");
}

/// T4: the shipped TLSOption is TLS 1.3 only, AES-256-GCM, P-384, sniStrict.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_traefik_tlsoption_cnsa() {
    let out = must_render(sbc(&[SBC_ISSUER]), "edge TLS objects");
    let fname = fullname(&out);
    let opt = get(&out, "TLSOption", &format!("{fname}-cnsa"));
    assert_eq!(scalar(opt, "apiVersion"), Some("traefik.io/v1alpha1"));
    assert_eq!(scalar(opt, "minVersion"), Some("VersionTLS13"));
    assert_eq!(scalar(opt, "maxVersion"), Some("VersionTLS13"));
    assert_eq!(
        yaml_list(opt, "cipherSuites"),
        vec!["TLS_AES_256_GCM_SHA384"]
    );
    assert_eq!(yaml_list(opt, "curvePreferences"), vec!["CurveP384"]);
    assert_eq!(scalar(opt, "sniStrict"), Some("true"));
    assert!(!opt.contains("VersionTLS12"), "{opt}");
}

/// T5: HSTS middleware.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_hsts_middleware() {
    let out = must_render(sbc(&[SBC_ISSUER]), "edge TLS objects");
    let fname = fullname(&out);
    let mw = get(&out, "Middleware", &format!("{fname}-hsts"));
    assert_eq!(scalar(mw, "apiVersion"), Some("traefik.io/v1alpha1"));
    assert_eq!(scalar(mw, "stsSeconds"), Some("31536000"));
    assert_eq!(scalar(mw, "stsIncludeSubdomains"), Some("true"));
    assert_eq!(scalar(mw, "forceSTSHeader"), Some("true"));
}

/// T6: redirect-only router on `web`; switchable off.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_http_redirect_router() {
    let out = must_render(sbc(&[SBC_ISSUER]), "default redirect");
    let fname = fullname(&out);
    let red = get(&out, "Ingress", &format!("{fname}-client-config-redirect"));
    assert_eq!(entrypoints(red), vec!["web"], "{red}");
    assert!(!has_spec_tls(red), "{red}");
    assert_ne!(annotation(red, RTLS), Some("true"), "{red}");
    let mw = annotation(red, RMW).unwrap_or("");
    assert_eq!(
        mw.trim(),
        format!("default-{fname}-https-redirect@kubernetescrd"),
        "the redirect router's only middleware is the scheme redirect"
    );
    let m = get(&out, "Middleware", &format!("{fname}-https-redirect"));
    assert_eq!(scalar(m, "apiVersion"), Some("traefik.io/v1alpha1"));
    assert_eq!(scalar(m, "scheme"), Some("https"));
    assert_eq!(scalar(m, "permanent"), Some("true"));

    let out = must_render(
        sbc(&[SBC_ISSUER, "edge.traefik.httpRedirect=false"]),
        "no redirect",
    );
    assert!(find(&out, "Ingress", &format!("{fname}-client-config-redirect")).is_none());
    assert!(find(&out, "Middleware", &format!("{fname}-https-redirect")).is_none());
    // The TLS router is unchanged.
    let ing = get(&out, "Ingress", &format!("{fname}-client-config"));
    assert_eq!(entrypoints(ing), vec!["websecure"], "{ing}");
}

/// T7: bring-your-own TLSOption.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_external_tlsoption_ref() {
    let out = must_render(
        sbc(&[
            SBC_ISSUER,
            "edge.traefik.createTlsOption=false",
            "edge.traefik.tlsOption=infra-cnsa@kubernetescrd",
        ]),
        "external TLSOption",
    );
    let fname = fullname(&out);
    assert!(
        docs(&out).iter().all(|d| kind_of(d) != "TLSOption"),
        "no chart TLSOption when createTlsOption=false"
    );
    let ing = get(&out, "Ingress", &format!("{fname}-client-config"));
    assert_eq!(annotation(ing, RTLS_OPT), Some("infra-cnsa@kubernetescrd"));
    must_fail(
        sbc(&[SBC_ISSUER, "edge.traefik.createTlsOption=false"]),
        "edge.traefik.tlsOption",
        "createTlsOption=false without a tlsOption ref",
    );
}

/// T8: a frontend LoadBalancer with no edge is cleartext; lab-only.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_frontend_loadbalancer_requires_edge() {
    must_fail(
        sbc(&[SBC_ISSUER, "sbcClientConfig.enabled=false"]),
        "edge.insecureLabHttp",
        "frontend LoadBalancer with no edge",
    );
    let out = must_render(
        sbc(&[SBC_ISSUER, "sbcClientConfig.enabled=false", LAB]),
        "lab frontend LoadBalancer",
    );
    let fname = fullname(&out);
    let svc = get(&out, "Service", &format!("{fname}-frontend"));
    assert_eq!(scalar(svc, "type"), Some("LoadBalancer"), "{svc}");

    // Regression: the Gateway edge keeps working, with and without the Ingress.
    for extra in [&[][..], &["sbcClientConfig.enabled=false"][..]] {
        let mut sets = vec![
            SBC_ISSUER,
            "gateway.enabled=true",
            "gateway.clusterIssuer=qa",
        ];
        sets.extend_from_slice(extra);
        let out = must_render(sbc(&sets), "gateway edge");
        let svc = get(&out, "Service", &format!("{fname}-frontend"));
        assert_eq!(scalar(svc, "type"), Some("ClusterIP"), "{svc}");
        let route = get(&out, "HTTPRoute", &format!("{fname}-redirect"));
        assert_eq!(scalar(route, "scheme"), Some("https"), "{route}");
    }
}

/// T9: the oopl-001 site values render with the edge TLS profile.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_site_oopl_001_edge_tls() {
    let out = must_render(
        render_values(
            "sbc",
            "deploy/helm/sites/sbc/oopl-001/values.yaml",
            &["sbcPostgres.password=p", SBC_ISSUER],
        ),
        "oopl-001 site",
    );
    let fname = fullname(&out);
    let ing = get(&out, "Ingress", &format!("{fname}-client-config"));
    assert_eq!(entrypoints(ing), vec!["websecure"], "{ing}");
    assert_eq!(scalar(ing, "secretName"), Some("sbc-oopl-001-ingress-tls"));
    assert!(ing.contains("\"sbc.oopl.dev.mil\""), "{ing}");
    assert_eq!(
        annotation(ing, RTLS_OPT),
        Some(format!("default-{fname}-cnsa@kubernetescrd").as_str())
    );
    let opt = get(&out, "TLSOption", &format!("{fname}-cnsa"));
    assert_eq!(scalar(opt, "minVersion"), Some("VersionTLS13"));
}

/// T10: `helm lint` passes for both charts and the edge variants, and
/// refuses the sbc chart without a TLS secret.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_lint_charts() {
    let sbc_sets: Vec<&str> = SBC_MIN.iter().copied().chain([SBC_ISSUER]).collect();
    must_render(lint("sbc", &[], &sbc_sets), "helm lint sbc");
    let with = |extra: &[&'static str]| -> Vec<&str> {
        sbc_sets
            .iter()
            .copied()
            .chain(extra.iter().copied())
            .collect()
    };
    must_render(
        lint("sbc", &[], &with(&[NO_SECRET, LAB])),
        "helm lint sbc lab",
    );
    must_render(
        lint(
            "sbc",
            &[],
            &with(&[
                "edge.traefik.createTlsOption=false",
                "edge.traefik.tlsOption=infra-cnsa@kubernetescrd",
            ]),
        ),
        "helm lint sbc external TLSOption",
    );
    // `helm lint` reports a template `fail` as an INFO line and exits 0
    // (v3.20, v4.3); T1 covers the fail-closed render. Assert the message.
    let text = lint("sbc", &[], &with(&[NO_SECRET])).unwrap_or_else(|e| e);
    assert!(
        text.contains("sbcClientConfig.ingressTlsSecretName"),
        "helm lint sbc without a TLS secret must report the fail message:\n{text}"
    );
    let central_sets: Vec<&str> = CENTRAL_MIN
        .iter()
        .copied()
        .chain(["postgres.password=s3cret"])
        .collect();
    must_render(
        lint("central-config", &[], &central_sets),
        "helm lint central-config",
    );
}

/// Decision Q2: plain-HTTP provisioning is an opt-in router for
/// `/provision/` only; nothing else is served on `web`.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_http_provisioning_opt_in() {
    let out = must_render(sbc(&[SBC_ISSUER]), "default");
    let fname = fullname(&out);
    let name = format!("{fname}-provision-http");
    assert!(
        find(&out, "Ingress", &name).is_none(),
        "HTTP provisioning router must be off by default"
    );

    let out = must_render(
        sbc(&[SBC_ISSUER, "edge.traefik.allowHttpProvisioning=true"]),
        "HTTP provisioning opt-in",
    );
    let ing = get(&out, "Ingress", &name);
    assert_eq!(entrypoints(ing), vec!["web"], "{ing}");
    assert!(!has_spec_tls(ing), "{ing}");
    assert!(annotation(ing, RTLS_OPT).is_none(), "{ing}");
    assert!(
        !annotation(ing, RMW).unwrap_or("").contains("-hsts@"),
        "HSTS must not be sent over HTTP (RFC 6797 7.2)"
    );
    let paths = ingress_paths(ing);
    assert_eq!(paths, vec!["/provision/"], "{ing}");
    // Every Ingress on `web` is either the redirect or the provisioning router.
    for d in docs(&out).into_iter().filter(|d| kind_of(d) == "Ingress") {
        if entrypoints(d).iter().any(|e| e == "web") {
            let n = name_of(d);
            assert!(
                n == name || n == format!("{fname}-client-config-redirect"),
                "unexpected router on web: {n}"
            );
        }
    }
    // The TLS router is unchanged.
    let main = get(&out, "Ingress", &format!("{fname}-client-config"));
    assert_eq!(entrypoints(main), vec!["websecure"], "{main}");
}

/// The SR-53 text helpers, on a fixed document (runs without helm).
#[test]
fn qa_helm_render_edge_parsers_self_test() {
    let d = "apiVersion: traefik.io/v1alpha1\nkind: TLSOption\nmetadata:\n  name: x-cnsa\n  annotations:\n    traefik.ingress.kubernetes.io/router.entrypoints: \"websecure\"\nspec:\n  minVersion: VersionTLS13\n  cipherSuites:\n    - TLS_AES_256_GCM_SHA384\n  curvePreferences: [CurveP384]\n  sniStrict: true\n  tls:\n    - hosts:\n        - a\n  rules:\n    - http:\n        paths:\n          - path: /provision/\n";
    assert_eq!(entrypoints(d), vec!["websecure"]);
    assert_eq!(scalar(d, "minVersion"), Some("VersionTLS13"));
    assert_eq!(yaml_list(d, "cipherSuites"), vec!["TLS_AES_256_GCM_SHA384"]);
    assert_eq!(yaml_list(d, "curvePreferences"), vec!["CurveP384"]);
    assert!(has_spec_tls(d));
    assert_eq!(ingress_paths(d), vec!["/provision/"]);
    assert!(annotation(d, RTLS).is_none());
}

// ── SR-53 fix round 1: edge preflights and HTTP provisioning confinement ──
// NIST 800-53 Rev5: CM-6, SC-7, SC-8, SC-13, IA-5(1)(c)

/// SEC-001: a string "false"/"true" for an edge flag is truthy in templates,
/// so each flag must be a boolean. Reached from 22 and, without the
/// Ingress, from 16.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_edge_flags_must_be_bool() {
    for key in [
        "edge.insecureLabHttp",
        "edge.traefik.allowHttpProvisioning",
        "edge.traefik.httpRedirect",
        "edge.traefik.createTlsOption",
    ] {
        for v in ["false", "true"] {
            let set = format!("json:{key}=\"{v}\"");
            must_fail(
                sbc(&[SBC_ISSUER, &set]),
                key,
                &format!("string {key}={v:?}"),
            );
        }
    }
    // Frontend path (no Ingress): the check runs from 16-sbc-frontend.yaml.
    must_fail(
        sbc(&[
            SBC_ISSUER,
            "sbcClientConfig.enabled=false",
            "gateway.enabled=true",
            "gateway.clusterIssuer=qa",
            "json:edge.insecureLabHttp=\"false\"",
        ]),
        "edge.insecureLabHttp",
        "string lab flag on the Gateway path",
    );
}

/// NIST-005: HSTS max-age has a one-year floor.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_hsts_max_age_floor() {
    must_fail(
        sbc(&[SBC_ISSUER, "edge.traefik.hsts.maxAgeSeconds=86400"]),
        "edge.traefik.hsts.maxAgeSeconds",
        "HSTS max-age below one year",
    );
    let out = must_render(
        sbc(&[SBC_ISSUER, "edge.traefik.hsts.maxAgeSeconds=63072000"]),
        "HSTS two years",
    );
    let fname = fullname(&out);
    let mw = get(&out, "Middleware", &format!("{fname}-hsts"));
    assert_eq!(scalar(mw, "stsSeconds"), Some("63072000"), "{mw}");
}

/// SEC-004 / NIST-009: the TLS router and the cleartext routers cannot
/// share an entrypoint.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_edge_entrypoint_collision() {
    must_fail(
        sbc(&[SBC_ISSUER, "edge.traefik.entryPoint=web"]),
        "edge.traefik.entryPoint",
        "entryPoint == httpEntryPoint with the redirect router",
    );
    must_fail(
        sbc(&[
            SBC_ISSUER,
            "edge.traefik.entryPoint=web",
            "edge.traefik.httpRedirect=false",
            "edge.traefik.allowHttpProvisioning=true",
        ]),
        "edge.traefik.entryPoint",
        "entryPoint == httpEntryPoint with the provisioning router",
    );
    let out = must_render(
        sbc(&[
            SBC_ISSUER,
            "edge.traefik.entryPoint=web",
            "edge.traefik.httpRedirect=false",
        ]),
        "no cleartext router",
    );
    let fname = fullname(&out);
    let ing = get(&out, "Ingress", &format!("{fname}-client-config"));
    assert_eq!(annotation(ing, RTLS), Some("true"), "{ing}");
}

/// SEC-004 / NIST-004: Traefik's cluster default TLSOption is not a
/// dedicated edge policy.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_tlsoption_default_rejected() {
    for r in ["default", "default@internal", "default@kubernetescrd"] {
        let set = format!("edge.traefik.tlsOption={r}");
        must_fail(
            sbc(&[SBC_ISSUER, "edge.traefik.createTlsOption=false", &set]),
            "edge.traefik.tlsOption",
            &format!("tlsOption {r}"),
        );
    }
}

/// SEC-003: the HTTP provisioning router tags its requests, the TLS router
/// clears the tag, and the frontend nginx refuses tagged requests outside
/// /provision/.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_http_provisioning_marker() {
    let out = must_render(
        sbc(&[SBC_ISSUER, "edge.traefik.allowHttpProvisioning=true"]),
        "HTTP provisioning opt-in",
    );
    let fname = fullname(&out);
    let ing = get(&out, "Ingress", &format!("{fname}-provision-http"));
    assert_eq!(
        annotation(ing, RMW),
        Some(format!("default-{fname}-provision-marker@kubernetescrd").as_str()),
        "{ing}"
    );
    let marker = get(&out, "Middleware", &format!("{fname}-provision-marker"));
    assert_eq!(scalar(marker, "apiVersion"), Some("traefik.io/v1alpha1"));
    assert_eq!(scalar(marker, "X-Sbc-Edge-Route"), Some("provision-http"));
    let hsts = get(&out, "Middleware", &format!("{fname}-hsts"));
    assert_eq!(scalar(hsts, "X-Sbc-Edge-Route"), Some(""), "{hsts}");
    let nginx = get(&out, "ConfigMap", &format!("{fname}-frontend-nginx"));
    assert!(
        nginx.contains("map $http_x_sbc_edge_route $sbc_edge_marked"),
        "{nginx}"
    );
    assert!(nginx.contains("\"~^1/provision/\" 0;"), "{nginx}");
    assert!(nginx.contains("if ($sbc_edge_deny)"), "{nginx}");
    assert!(nginx.contains("return 403;"), "{nginx}");

    // Off by default: no marker middleware.
    let out = must_render(sbc(&[SBC_ISSUER]), "default");
    assert!(find(&out, "Middleware", &format!("{fname}-provision-marker")).is_none());
}

/// NIST-006: the Gateway edge certificate uses an ECDSA P-384 key.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_gateway_cert_ecdsa_p384() {
    let out = must_render(
        sbc(&[
            SBC_ISSUER,
            "gateway.enabled=true",
            "gateway.clusterIssuer=qa",
        ]),
        "gateway edge",
    );
    let fname = fullname(&out);
    let cert = get(&out, "Certificate", &format!("{fname}-tls"));
    // The manifest is not echoed into the failure message.
    assert_eq!(
        scalar(cert, "algorithm"),
        Some("ECDSA"),
        "Gateway Certificate privateKey.algorithm"
    );
    assert_eq!(
        scalar(cert, "size"),
        Some("384"),
        "Gateway Certificate privateKey.size"
    );
}
