//! Real-handshake test for the client-certificate gate (QA, SEC-8 gap).
//!
//! Starts [`GrpcServer::run`] exactly as the daemon does (configure_tls +
//! `InterceptorLayer(ClientCertGate)` + `serve_with_shutdown`) with
//! `require_mtls` and `allowed_client_names`, using rcgen P-384 CA, server
//! and client certificates, and drives it with a tonic TLS client. Verifies
//! that tonic actually exposes `peer_certs()` to the gate in production
//! wiring.
//!
//! Runs on a current-thread runtime so server-side audit events land in the
//! thread-local `uc_audit::capture`.

use super::*;
use crate::server::ServerStats;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    PKCS_ECDSA_P384_SHA384,
};
use sbc_grpc_api::sbc::ListCdrsRequest;
use sbc_grpc_api::sbc::cdr_service_client::CdrServiceClient;
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Pki {
    pem: String,
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl Pki {
    fn new() -> Result<Self, rcgen::Error> {
        let mut p = CertificateParams::new(Vec::<String>::new())?;
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.distinguished_name.push(DnType::CommonName, "qa-grpc-ca");
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?;
        let ca_cert = p.self_signed(&ca_key)?;
        Ok(Self {
            pem: pem("CERTIFICATE", ca_cert.der()),
            cert: ca_cert,
            key: ca_key,
        })
    }

    /// Leaf signed by this CA: `(cert_pem, key_pem)`.
    fn leaf(
        &self,
        cn: &str,
        sans: &[&str],
        eku: ExtendedKeyUsagePurpose,
    ) -> Result<(String, String), rcgen::Error> {
        let mut p =
            CertificateParams::new(sans.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())?;
        p.distinguished_name = rcgen::DistinguishedName::new();
        p.distinguished_name.push(DnType::CommonName, cn);
        p.extended_key_usages = vec![eku];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?;
        let cert = p.signed_by(&key, &self.cert, &self.key)?;
        Ok((
            pem("CERTIFICATE", cert.der()),
            pem("PRIVATE KEY", &key.serialize_der()),
        ))
    }
}

fn state_with_ring() -> Result<Arc<AppState>, uc_cdr::CdrError> {
    let emitter = uc_cdr::CdrEmitter::start(
        uc_cdr::CdrEmitterConfig {
            node_id: "qa-node".into(),
            file: None,
            ..Default::default()
        },
        Vec::new(),
        None,
    )?;
    let ctx = Arc::new(crate::cdr::CdrContext::new(
        emitter,
        &sbc_config::schema::CdrConfig::default(),
    ));
    let mut stack = crate::sip_stack::SipStack::new(crate::sip_stack::SipStackConfig::default());
    stack.set_cdr(ctx);
    let mut state = AppState::new(
        uc_metrics::SbcMetrics::standard(),
        Arc::new(ServerStats::default()),
    );
    state.sip_stack = Some(Arc::new(stack));
    Ok(Arc::new(state))
}

fn free_port() -> std::io::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

async fn connect(
    port: u16,
    ca_pem: &str,
    client: Option<&(String, String)>,
) -> Result<Channel, tonic::transport::Error> {
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_pem))
        .domain_name("localhost");
    if let Some((c, k)) = client {
        tls = tls.identity(Identity::from_pem(c, k));
    }
    Endpoint::from_shared(format!("https://localhost:{port}"))?
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5))
        .connect()
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn real_mtls_handshake_gate_sees_client_certificate() -> TestResult {
    // As main.rs does: process-level aws-lc provider (Err = already set).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let pki = Pki::new()?;
    let (srv_c, srv_k) = pki.leaf(
        "localhost",
        &["localhost"],
        ExtendedKeyUsagePurpose::ServerAuth,
    )?;
    let good = pki.leaf("rel-sbc-api", &[], ExtendedKeyUsagePurpose::ClientAuth)?;
    let rogue = pki.leaf(
        "rogue-workload",
        &["rogue.default.svc"],
        ExtendedKeyUsagePurpose::ClientAuth,
    )?;

    let dir = tempfile::tempdir()?;
    let write = |n: &str, s: &str| -> std::io::Result<std::path::PathBuf> {
        let p = dir.path().join(n);
        std::fs::write(&p, s)?;
        Ok(p)
    };
    let port = free_port()?;
    let config = GrpcConfig {
        enabled: true,
        listen_addr: format!("127.0.0.1:{port}").parse()?,
        tls_cert_path: Some(write("srv.pem", &srv_c)?),
        tls_key_path: Some(write("srv.key", &srv_k)?),
        tls_ca_path: Some(write("ca.pem", &pki.pem)?),
        require_mtls: true,
        allowed_client_names: vec!["rel-sbc-api".to_string()],
        ..GrpcConfig::default()
    };
    let shutdown = ShutdownSignal::new();
    #[cfg(not(feature = "cluster"))]
    let server = GrpcServer::new(config, state_with_ring()?, shutdown.clone());
    #[cfg(feature = "cluster")]
    let server = GrpcServer::new(config, state_with_ring()?, shutdown.clone(), None);
    let capture = uc_audit::capture::start();
    let handle = tokio::spawn(async move { server.run().await });

    // Wait for the listener.
    let mut up = false;
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(up, "gRPC server did not start");

    // 1. Allow-listed certificate: ListCdrs succeeds, principal from cert.
    let ch = connect(port, &pki.pem, Some(&good)).await?;
    let mut req = tonic::Request::new(ListCdrsRequest::default());
    req.metadata_mut()
        .insert("x-sbc-user", "api:admin".parse()?);
    let resp = CdrServiceClient::new(ch).list_cdrs(req).await?.into_inner();
    assert_eq!(resp.node_id, "qa-node");

    // 2. CA-signed but not allow-listed: PERMISSION_DENIED.
    let ch = connect(port, &pki.pem, Some(&rogue)).await?;
    let rogue_code = CdrServiceClient::new(ch)
        .list_cdrs(ListCdrsRequest::default())
        .await
        .err()
        .map(|s| s.code());
    assert_eq!(rogue_code, Some(tonic::Code::PermissionDenied));

    // 3. No client certificate: handshake or request fails, never Ok.
    let no_cert = match connect(port, &pki.pem, None).await {
        Err(_) => None,
        Ok(ch) => Some(
            CdrServiceClient::new(ch)
                .list_cdrs(ListCdrsRequest::default())
                .await,
        ),
    };
    if let Some(r) = &no_cert {
        let code = r.as_ref().err().map(tonic::Status::code);
        assert!(r.is_err(), "request without client cert succeeded");
        assert_ne!(
            code,
            Some(tonic::Code::PermissionDenied),
            "rejected by gate, not by TLS: {code:?}"
        );
    }

    let events = capture.events();
    let exports: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            uc_audit::AuditEvent::CdrExport(x) => Some(x),
            _ => None,
        })
        .collect();
    assert_eq!(exports.len(), 1, "{exports:?}");
    assert!(
        exports[0].user.starts_with("cert:rel-sbc-api@127.0.0.1:"),
        "{}",
        exports[0].user
    );
    assert_eq!(exports[0].on_behalf_of, "api:admin");
    let denies: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            uc_audit::AuditEvent::AuthorizationDecision(d) if !d.granted => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(denies.len(), 1, "{denies:?}");
    assert!(
        denies[0].identity.contains("rogue.default.svc"),
        "{}",
        denies[0].identity
    );
    assert_eq!(denies[0].policy, "grpc.allowed_client_names");
    // SEC-12 observation: record what the gate sees as resource.
    eprintln!("QA: deny resource = {:?}", denies[0].resource);

    shutdown.request_shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
    Ok(())
}

/// PEM armour (rcgen is built without its `pem` feature here).
fn pem(label: &str, der: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for chunk in der.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | (u32::from(b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                b64.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                b64.push('=');
            }
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out + &format!("-----END {label}-----\n")
}
