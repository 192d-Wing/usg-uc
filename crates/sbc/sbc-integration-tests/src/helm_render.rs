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
const SBC_MIN: &[&str] = &["sbcApi.ha1Key.existingSecret=x", "sbcPostgres.password=p"];
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
    push_sets(&mut cmd, &[SBC_MIN[0], SBC_MIN[1], SBC_ISSUER]);
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

// ── announcement server (SR-41) ────────────────────────────────

/// Announcement pod on, with the values it cannot render without.
const ANN_ON: &[&str] = &[
    "sbcAnnouncement.enabled=true",
    "sbcAnnouncement.advertisedIp=203.0.113.9",
];

fn ann(extra: &[&str]) -> Result<String, String> {
    let sets: Vec<&str> = ANN_ON.iter().chain(extra).copied().collect();
    sbc(&sets)
}

/// The quoted `value:` of env `name` in `doc`, if any.
fn env_value(doc: &str, name: &str) -> Option<String> {
    let e = env_entry(doc, name)?;
    let v = e.lines().find_map(|l| l.trim().strip_prefix("value: "))?;
    Some(v.trim().trim_matches('"').to_string())
}

/// cert-manager Certificates whose spec mentions `needle`.
fn certs_with<'a>(out: &'a str, needle: &str) -> Vec<&'a str> {
    docs(out)
        .into_iter()
        .filter(|d| kind_of(d) == "Certificate" && d.contains(needle))
        .collect()
}

/// mTLS with an issuer: server and daemon-client P-384 Certificates, an
/// https URL on the daemon, TLS env on both sides.
/// NIST 800-53 Rev5: IA-3, SC-8, SC-13
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_announcement_mtls_with_issuer() {
    let out = must_render(ann(&[SBC_ISSUER]), "announcement + issuer");
    let fname = fullname(&out);
    let svc_host = format!("{fname}-announcement.default.svc.cluster.local");

    let server: Vec<&str> = certs_with(&out, &format!("- {fname}-announcement"))
        .into_iter()
        .filter(|c| c.contains("server auth"))
        .collect();
    assert_eq!(server.len(), 1, "one announcement server Certificate");
    let server = server[0];
    assert!(server.contains(&format!("- {svc_host}")), "{server}");
    assert!(server.contains("size: 384"), "P-384:\n{server}");

    let client: Vec<&str> = certs_with(&out, &format!("{fname}-sbc-daemon"))
        .into_iter()
        .filter(|c| c.contains("client auth"))
        .collect();
    assert_eq!(client.len(), 1, "one daemon client Certificate");
    let client = client[0];
    // The pod gate matches SAN DNS names, not the CN.
    assert!(
        client.contains("dnsNames:") && client.contains(&format!("- {fname}-sbc-daemon")),
        "daemon client Certificate needs SAN DNS {fname}-sbc-daemon:\n{client}"
    );
    assert!(client.contains("size: 384"), "P-384:\n{client}");

    let daemon = get(&out, "Deployment", &fname);
    let url = env_value(daemon, "SBC_ANNOUNCEMENT_URL").expect("SBC_ANNOUNCEMENT_URL");
    assert_eq!(url, format!("https://{svc_host}:9095"));
    for env in [
        "SBC_ANNOUNCEMENT_TLS_CA_FILE",
        "SBC_ANNOUNCEMENT_TLS_CERT_FILE",
        "SBC_ANNOUNCEMENT_TLS_KEY_FILE",
    ] {
        assert!(env_entry(daemon, env).is_some(), "daemon lacks {env}");
    }

    let pod = get(&out, "Deployment", &format!("{fname}-announcement"));
    for env in [
        "SBC_ANN_GRPC_TLS_CERT_FILE",
        "SBC_ANN_GRPC_TLS_KEY_FILE",
        "SBC_ANN_GRPC_TLS_CLIENT_CA_FILE",
    ] {
        assert!(env_entry(pod, env).is_some(), "pod lacks {env}");
    }
    let names = env_value(pod, "SBC_ANN_GRPC_ALLOWED_CLIENT_NAMES").expect("allowed client names");
    assert_eq!(names, format!("{fname}-sbc-daemon"));
    assert!(
        env_entry(pod, "SBC_ANN_ALLOW_LOOPBACK_DEST").is_none(),
        "the lab loopback flag is not exposed in Helm"
    );
}

/// Plaintext Play off loopback is not renderable.
/// NIST 800-53 Rev5: IA-3, CM-7
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_announcement_without_grpc_mtls_fails() {
    must_fail(
        ann(&["sbcDaemon.grpcMtls.enabled=false", "sbcApi.enabled=false"]),
        "sbcAnnouncement",
        "announcement pod with grpcMtls off",
    );
}

/// Explicit Secrets instead of an issuer; without them (and no issuer) the
/// chart refuses.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_announcement_secrets_without_issuer() {
    let daemon_secrets = [
        "sbcDaemon.grpcMtls.serverSecretName=srv",
        "sbcDaemon.grpcMtls.clientSecretName=cli",
    ];
    must_fail(
        ann(&daemon_secrets),
        "sbcAnnouncement.grpcMtls",
        "announcement without issuer or announcement Secret names",
    );
    let mut sets: Vec<&str> = daemon_secrets.to_vec();
    sets.extend([
        "sbcAnnouncement.grpcMtls.serverSecretName=ann-srv",
        "sbcAnnouncement.grpcMtls.daemonClientSecretName=ann-cli",
    ]);
    let out = must_render(ann(&sets), "announcement with explicit Secrets");
    assert!(
        docs(&out).iter().all(|d| kind_of(d) != "Certificate"),
        "no Certificates without an issuer"
    );
    let fname = fullname(&out);
    let pod = get(&out, "Deployment", &format!("{fname}-announcement"));
    assert!(
        pod.contains("secretName: ann-srv"),
        "pod mounts ann-srv:\n{pod}"
    );
    let daemon = get(&out, "Deployment", &fname);
    assert!(
        daemon.contains("secretName: ann-cli"),
        "daemon mounts ann-cli"
    );
    let url = env_value(daemon, "SBC_ANNOUNCEMENT_URL").expect("SBC_ANNOUNCEMENT_URL");
    assert!(url.starts_with("https://"), "{url}");
}

/// Pins the #221 rule: TCP 9095 only from daemon pods of this release; RTP
/// UDP stays open.
/// NIST 800-53 Rev5: SC-7, AC-4
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_announcement_networkpolicy_daemon_only() {
    let out = must_render(ann(&[SBC_ISSUER]), "announcement + issuer");
    let fname = fullname(&out);
    let np = get(&out, "NetworkPolicy", &format!("{fname}-announcement"));
    assert!(
        np.contains("app.kubernetes.io/component: announcement"),
        "selects the announcement pods:\n{np}"
    );
    let rules = ingress_rules(np);
    let grpc: Vec<&String> = rules.iter().filter(|r| r.contains("port: 9095")).collect();
    assert_eq!(grpc.len(), 1, "{rules:?}");
    assert_eq!(
        components(grpc[0]),
        vec!["daemon".to_string()],
        "{}",
        grpc[0]
    );
    assert!(
        grpc[0].contains("app.kubernetes.io/instance: t"),
        "same release only:\n{}",
        grpc[0]
    );
    assert!(grpc[0].contains("protocol: TCP"), "{}", grpc[0]);
    assert!(
        !grpc[0].contains("namespaceSelector") && !grpc[0].contains("ipBlock"),
        "no wider peers:\n{}",
        grpc[0]
    );
    assert!(
        rules
            .iter()
            .any(|r| r.contains("protocol: UDP") && !r.contains("from:")),
        "RTP UDP rule:\n{np}"
    );
}

/// Caps and the media CIDR allow-list reach the pod env; defaults follow
/// the plan (128 / 32 / 30 s, no CIDR restriction).
/// NIST 800-53 Rev5: SC-5, SC-7, CM-6
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_announcement_caps_and_cidrs_env() {
    let out = must_render(ann(&[SBC_ISSUER]), "announcement defaults");
    let fname = fullname(&out);
    let pod = get(&out, "Deployment", &format!("{fname}-announcement"));
    assert_eq!(env_value(pod, "SBC_ANN_MAX_PLAYS").as_deref(), Some("128"));
    assert_eq!(
        env_value(pod, "SBC_ANN_MAX_PLAYS_PER_DEST").as_deref(),
        Some("32")
    );
    assert_eq!(
        env_value(pod, "SBC_ANN_MAX_PLAY_SECS").as_deref(),
        Some("30")
    );
    assert!(
        env_entry(pod, "SBC_ANN_ALLOWED_DEST_CIDRS").is_none(),
        "empty allowedMediaCidrs leaves the variable unset"
    );

    let out = must_render(
        ann(&[
            SBC_ISSUER,
            "sbcAnnouncement.maxPlays=64",
            "sbcAnnouncement.maxPlaysPerDestination=4",
            "sbcAnnouncement.maxPlaySeconds=20",
            "sbcAnnouncement.allowedMediaCidrs={10.0.0.0/8,192.0.2.0/24}",
        ]),
        "announcement caps and CIDRs",
    );
    let pod = get(&out, "Deployment", &format!("{fname}-announcement"));
    assert_eq!(env_value(pod, "SBC_ANN_MAX_PLAYS").as_deref(), Some("64"));
    assert_eq!(
        env_value(pod, "SBC_ANN_MAX_PLAYS_PER_DEST").as_deref(),
        Some("4")
    );
    assert_eq!(
        env_value(pod, "SBC_ANN_MAX_PLAY_SECS").as_deref(),
        Some("20")
    );
    assert_eq!(
        env_value(pod, "SBC_ANN_ALLOWED_DEST_CIDRS").as_deref(),
        Some("10.0.0.0/8,192.0.2.0/24")
    );
}

/// kubelet gRPC probes carry no client certificate, so they cannot pass an
/// mTLS-only listener: the pod must not probe 9095 with `grpc:`.
#[test]
#[ignore = "requires the helm binary; run with --ignored"]
fn qa_helm_render_announcement_probes_work_with_mtls() {
    let out = must_render(ann(&[SBC_ISSUER]), "announcement + issuer");
    let fname = fullname(&out);
    let pod = get(&out, "Deployment", &format!("{fname}-announcement"));
    for probe in ["livenessProbe:", "readinessProbe:"] {
        let at = pod.find(probe).unwrap_or_else(|| panic!("{probe} missing"));
        let body: String = pod[at..]
            .lines()
            .skip(1)
            .take(3)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !body.contains("grpc:"),
            "{probe} uses a gRPC probe against the mTLS listener:\n{body}"
        );
    }
}
