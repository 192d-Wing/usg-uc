//! SR-29 (POA&M-401 phase (a)) daemon wiring: CRL checks on the SIP mTLS
//! listener (V1), trunk TLS (V2, V3) and the SIPREC recorder (V4); startup
//! audit per role; a bad CRL fails the path; no downgrade after a
//! revocation failure.

use super::*;
use crate::tls_revocation::tests::{TestCa, TestLeaf, rejected, write};
use crate::tls_revocation::{Role, rejections};
use uc_transport::RevocationFailure;

const REGISTER: &[u8] = b"REGISTER sip:sbc.example.test SIP/2.0\r\n\
Via: SIP/2.0/TLS 127.0.0.1:5061;branch=z9hG4bK-crl-1\r\n\
Max-Forwards: 70\r\n\
From: <sip:alice@sbc.example.test>;tag=crl1\r\n\
To: <sip:alice@sbc.example.test>\r\n\
Call-ID: crl-register-1@test\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:alice@127.0.0.1:5061;transport=tls>\r\n\
Expires: 60\r\n\
Content-Length: 0\r\n\r\n";

/// SBC certificate, mutual TLS with `client_ca`, and `crl` as
/// `security.tls_crl_path`, listening on 127.0.0.1.
#[cfg(unix)]
fn mtls_config(dir: &std::path::Path, client_ca: &TestCa, crl: &str) -> SbcConfig {
    let (cert, key) = write_cert_and_key(dir);
    let mut config = SbcConfig::default();
    config.transport.tls_listen = vec!["127.0.0.1:0".parse().unwrap()];
    config.security.tls_cert_path = Some(cert);
    config.security.tls_key_path = Some(key);
    config.security.require_mtls = true;
    config.security.tls_ca_path = Some(write(dir, "client-ca.pem", &client_ca.pem()));
    config.security.tls_crl_path = Some(write(dir, "client-crl.pem", crl));
    config
}

/// A client presenting `leaf`, trusting the SBC certificate in `config`.
fn sip_client(config: &SbcConfig, leaf: &TestLeaf) -> Arc<rustls::ClientConfig> {
    let roots = uc_transport::tls::load_root_store(config.security.tls_cert_path.as_ref().unwrap())
        .unwrap();
    Arc::new(
        uc_transport::tls::create_client_config_with(uc_transport::tls::TlsClientOptions {
            roots,
            min_version: uc_transport::tls::MinTlsVersion::V1_3,
            client_auth: Some((leaf.chain.clone(), leaf.key.clone_key())),
        })
        .unwrap(),
    )
}

/// Sends a REGISTER over TLS; returns the first bytes of the answer, or
/// `None` when the connection fails or closes without one.
async fn register_over_tls(
    addr: SbcSocketAddr,
    client: Arc<rustls::ClientConfig>,
) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let attempt = async {
        let tcp = tokio::net::TcpStream::connect(std::net::SocketAddr::from(addr))
            .await
            .ok()?;
        let name = rustls_pki_types::ServerName::try_from("sbc.example.test").unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(client)
            .connect(name, tcp)
            .await
            .ok()?;
        tls.write_all(REGISTER).await.ok()?;
        let mut buf = vec![0u8; 512];
        let n = tls.read(&mut buf).await.ok()?;
        (n > 0).then(|| buf[..n].to_vec())
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), attempt)
        .await
        .ok()
        .flatten()
}

/// Binds the configured TLS listener and runs its accept loop.
async fn serve_tls(server: &mut Server) -> (SbcSocketAddr, StreamLoopContext) {
    server.bind_tls_listeners().await.unwrap();
    let listener = Arc::clone(&server.tls_listeners.read().await[0]);
    let addr = *listener.local_addr();
    let mut ctx = stream_test_ctx(short_timeouts());
    ctx.conn_limiter = Arc::new(crate::conn_limit::ConnLimiter::new(16, 64));
    ctx.conn_semaphore = Arc::new(tokio::sync::Semaphore::new(16));
    ctx.total_conns = Arc::new(tokio::sync::Semaphore::new(16));
    tokio::spawn(Server::tls_accept_loop(listener, ctx.clone()));
    (addr, ctx)
}

// V1 / integration: a REGISTER over TLS with a revoked client certificate
// never reaches the SIP stack (no message counted, no answer); the same
// REGISTER with a good certificate is answered. The rejection is counted.
#[cfg(unix)]
#[tokio::test]
async fn register_with_revoked_client_cert_never_reaches_the_registrar() {
    let dir = tempfile::tempdir().unwrap();
    let client_ca = TestCa::new("client-ca");
    let config = mtls_config(dir.path(), &client_ca, &client_ca.crl_pem(&[70], false));
    let mut server = Server::new(config.clone(), ShutdownSignal::new(), None).unwrap();
    let capture = uc_audit::capture::start();
    let (addr, ctx) = serve_tls(&mut server).await;
    let loaded = capture
        .events()
        .iter()
        .filter(|e| {
            matches!(e, uc_audit::AuditEvent::TlsRevocationListLoaded(l) if l.role == "sip_tls")
        })
        .count();
    assert_eq!(loaded, 1, "startup audit for sip_tls");

    let before = rejections(Role::SipTls, RevocationFailure::Revoked);
    let revoked = client_ca.leaf(70, &["alice.example.test"]);
    assert!(
        register_over_tls(addr, sip_client(&config, &revoked))
            .await
            .is_none(),
        "no answer to a revoked client"
    );
    assert_eq!(ctx.stats.messages_received.load(Ordering::Relaxed), 0);
    // The rejection is counted once the server's handshake task ran.
    let t0 = std::time::Instant::now();
    while rejections(Role::SipTls, RevocationFailure::Revoked) == before
        && t0.elapsed() < std::time::Duration::from_secs(5)
    {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(rejections(Role::SipTls, RevocationFailure::Revoked) > before);
    // current_thread runtime: the spawned handshake ran on this thread.
    assert!(
        rejected(&capture.events())
            .iter()
            .any(|r| r.role == "sip_tls" && r.reason == "revoked"),
        "rejection audited"
    );

    let good = client_ca.leaf(71, &["bob.example.test"]);
    let answer = register_over_tls(addr, sip_client(&config, &good))
        .await
        .expect("a good client is answered");
    assert!(
        answer.starts_with(b"SIP/2.0 "),
        "{:?}",
        String::from_utf8_lossy(&answer)
    );
}

// V1: a client CA with no CRL from its issuer is denied by default
// (client_unknown = "deny") and accepted with "allow".
#[cfg(unix)]
#[tokio::test]
async fn sip_listener_unknown_client_status_follows_policy() {
    let dir = tempfile::tempdir().unwrap();
    let client_ca = TestCa::new("client-ca");
    let other = TestCa::new("other");
    let mut config = mtls_config(dir.path(), &client_ca, &other.crl_pem(&[], false));
    let good = client_ca.leaf(71, &["bob.example.test"]);
    let mut server = Server::new(config.clone(), ShutdownSignal::new(), None).unwrap();
    let (addr, _ctx) = serve_tls(&mut server).await;
    assert!(
        register_over_tls(addr, sip_client(&config, &good))
            .await
            .is_none()
    );

    config.security.revocation.client_unknown = sbc_config::schema::RevocationUnknown::Allow;
    let mut server = Server::new(config.clone(), ShutdownSignal::new(), None).unwrap();
    let (addr, _ctx) = serve_tls(&mut server).await;
    assert!(
        register_over_tls(addr, sip_client(&config, &good))
            .await
            .is_some()
    );
}

// V1: a CRL file that does not parse fails bind_tls_listeners, as a bad
// CA bundle does.
#[cfg(unix)]
#[tokio::test]
async fn bad_crl_file_fails_bind_tls_listeners() {
    let dir = tempfile::tempdir().unwrap();
    let client_ca = TestCa::new("client-ca");
    let config = mtls_config(dir.path(), &client_ca, "not a crl\n");
    let mut server = Server::new(config, ShutdownSignal::new(), None).unwrap();
    let err = server.bind_tls_listeners().await.unwrap_err().to_string();
    assert!(err.contains("CRL"), "{err}");
    assert!(server.tls_listeners.read().await.is_empty());
}

// Without a CRL the listener is built exactly as before: a client from
// the CA connects whatever its serial.
#[cfg(unix)]
#[tokio::test]
async fn no_crl_configured_keeps_the_previous_behaviour() {
    let dir = tempfile::tempdir().unwrap();
    let client_ca = TestCa::new("client-ca");
    let mut config = mtls_config(dir.path(), &client_ca, "");
    config.security.tls_crl_path = None;
    let mut server = Server::new(config.clone(), ShutdownSignal::new(), None).unwrap();
    let (addr, _ctx) = serve_tls(&mut server).await;
    let leaf = client_ca.leaf(70, &["alice.example.test"]);
    assert!(
        register_over_tls(addr, sip_client(&config, &leaf))
            .await
            .is_some()
    );
}

/// A TLS trunk at 127.0.0.1 presenting `leaf`; accepts one connection and
/// returns the bytes it received (empty on a failed handshake).
async fn trunk_server(leaf: &TestLeaf) -> (SbcSocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
    let cfg =
        uc_transport::tls::create_server_config(leaf.chain.clone(), leaf.key.clone_key()).unwrap();
    let listener = TlsListener::bind(
        ListenerConfig::new(
            SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0),
            TransportType::Tls,
        ),
        Arc::new(cfg),
    )
    .await
    .unwrap();
    let addr = *listener.local_addr();
    let task = tokio::spawn(async move {
        match listener.accept().await {
            Ok((conn, _)) => conn
                .recv()
                .await
                .map_or_else(|_| Vec::new(), |m| m.data.to_vec()),
            Err(_) => Vec::new(),
        }
    });
    (addr, task)
}

// V2 / integration: an INVITE to a TLS trunk whose certificate is revoked
// fails the send; nothing goes out over UDP; the rejection is counted and
// the startup audit names trunk_tls. A good trunk certificate gets the
// INVITE.
#[tokio::test]
async fn invite_to_revoked_tls_trunk_fails_with_no_udp_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let trunk_ca = TestCa::new("trunk-ca");
    let mut config = SbcConfig::default();
    config.security.trunk_tls_ca_path = Some(write(dir.path(), "trunk-ca.pem", &trunk_ca.pem()));
    config.security.trunk_tls_crl_path = Some(write(
        dir.path(),
        "trunk-crl.pem",
        &trunk_ca.crl_pem(&[7], false),
    ));
    let server = Server::new(config, ShutdownSignal::new(), None).unwrap();
    let capture = uc_audit::capture::start();
    server.load_trunk_tls_clients().unwrap();
    assert!(
        capture.events().iter().any(
            |e| matches!(e, uc_audit::AuditEvent::TlsRevocationListLoaded(l) if l.role == "trunk_tls")
        ),
        "startup audit for trunk_tls"
    );
    let watcher = UdpTransport::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let sbc_udp = Arc::new(
        UdpTransport::bind(SbcSocketAddr::new_v4(Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap(),
    );
    server.flows().set_default_udp(Arc::clone(&sbc_udp));
    let before = rejections(Role::TrunkTls, RevocationFailure::Revoked);

    let (dest, _task) = trunk_server(&trunk_ca.leaf(7, &["trunk.example.test"])).await;
    let flow = LegFlow::trunk(uc_routing::TrunkProtocol::Tls, "trunk.example.test", false);
    let err = server
        .flows()
        .send(&flow, &dest, b"INVITE", Some(&sbc_udp))
        .await
        .unwrap_err();
    assert!(
        matches!(err, crate::flows::FlowError::Handshake(_)),
        "{err}"
    );
    assert!(rejections(Role::TrunkTls, RevocationFailure::Revoked) > before);
    assert!(
        rejected(&capture.events())
            .iter()
            .any(|r| r.role == "trunk_tls" && r.reason == "revoked")
    );
    let none = tokio::time::timeout(std::time::Duration::from_millis(100), watcher.recv()).await;
    assert!(none.is_err(), "no UDP datagram after a revocation failure");

    let (dest, task) = trunk_server(&trunk_ca.leaf(8, &["trunk.example.test"])).await;
    server
        .flows()
        .send(&flow, &dest, b"INVITE", Some(&sbc_udp))
        .await
        .unwrap();
    assert_eq!(&task.await.unwrap()[..], b"INVITE");
}

// V2: a bad trunk CRL fails loading the trunk TLS clients.
#[test]
fn bad_trunk_crl_fails_load_trunk_tls_clients() {
    let dir = tempfile::tempdir().unwrap();
    let trunk_ca = TestCa::new("trunk-ca");
    let mut config = SbcConfig::default();
    config.security.trunk_tls_ca_path = Some(write(dir.path(), "trunk-ca.pem", &trunk_ca.pem()));
    config.security.trunk_tls_crl_path = Some(write(dir.path(), "bad.crl", "garbage"));
    let server = Server::new(config, ShutdownSignal::new(), None).unwrap();
    let err = server.load_trunk_tls_clients().unwrap_err().to_string();
    assert!(err.contains("CRL"), "{err}");
}

// V4: a recorder whose certificate is revoked is not connected (the RS
// INVITE fails closed; the recording policy then applies), and the
// startup audit names srs_tls.
#[cfg(unix)]
#[tokio::test]
async fn revoked_srs_certificate_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let srs_ca = TestCa::new("srs-ca");
    let ca = write(dir.path(), "srs-ca.pem", &srs_ca.pem());
    let mut config = recording_config(dir.path(), "sips:127.0.0.1:59", &ca);
    let crl = write(dir.path(), "srs-crl.pem", &srs_ca.crl_pem(&[9], false));
    config.recording.srs_tls_crl_file = Some(crl.to_string_lossy().into_owned());
    let mut server = Server::new(config, ShutdownSignal::new(), None).unwrap();
    let capture = uc_audit::capture::start();
    server.wire_recording().await.unwrap();
    assert!(
        capture.events().iter().any(
            |e| matches!(e, uc_audit::AuditEvent::TlsRevocationListLoaded(l) if l.role == "srs_tls")
        ),
        "startup audit for srs_tls"
    );
    let before = rejections(Role::SrsTls, RevocationFailure::Revoked);
    let (dest, _task) = trunk_server(&srs_ca.leaf(9, &["127.0.0.1"])).await;
    let name: Arc<str> = Arc::from("127.0.0.1");
    let err = server
        .flows()
        .send(&LegFlow::recorder(&name), &dest, b"INVITE", None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, crate::flows::FlowError::Handshake(_)),
        "{err}"
    );
    assert!(
        server
            .flows()
            .dial_failed_in_handshake(&LegFlow::recorder(&name), &dest)
    );
    assert!(rejections(Role::SrsTls, RevocationFailure::Revoked) > before);
}

// V4: an unloadable SRS CRL refuses startup.
#[cfg(unix)]
#[tokio::test]
async fn bad_srs_crl_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let srs_ca = TestCa::new("srs-ca");
    let ca = write(dir.path(), "srs-ca.pem", &srs_ca.pem());
    let mut config = recording_config(dir.path(), "sips:127.0.0.1:59", &ca);
    let bad = write(dir.path(), "bad.crl", "garbage");
    config.recording.srs_tls_crl_file = Some(bad.to_string_lossy().into_owned());
    let mut server = Server::new(config, ShutdownSignal::new(), None).unwrap();
    let err = startup_error(server.wire_recording().await);
    assert!(err.contains("recording.srs_tls_crl_file"), "{err}");
    assert!(!server.sip_stack().recording_enabled());
}

// V3: trunk mTLS (tls_client_cert = true) uses the same CRL-checking
// verifier as trunk TLS: a revoked trunk certificate fails the mTLS flow
// too.
#[cfg(unix)]
#[tokio::test]
async fn trunk_mtls_profile_shares_the_crl_verifier() {
    let dir = tempfile::tempdir().unwrap();
    let trunk_ca = TestCa::new("trunk-ca");
    let (cert, key) = write_cert_and_key(dir.path());
    let mut config = SbcConfig::default();
    config.security.tls_cert_path = Some(cert);
    config.security.tls_key_path = Some(key);
    config.security.trunk_tls_ca_path = Some(write(dir.path(), "trunk-ca.pem", &trunk_ca.pem()));
    config.security.trunk_tls_crl_path = Some(write(
        dir.path(),
        "trunk-crl.pem",
        &trunk_ca.crl_pem(&[7], false),
    ));
    config.trunk_groups.push(sbc_config::TrunkGroupConfig {
        id: "carriers".to_string(),
        name: "carriers".to_string(),
        strategy: "priority".to_string(),
        trunks: vec![sbc_config::TrunkConfigSchema {
            id: "t1".to_string(),
            host: "trunk.example.test".to_string(),
            port: 5061,
            protocol: "tls".to_string(),
            tls_client_cert: true,
            ..Default::default()
        }],
        zone: None,
        require_tls: false,
        trust_domain: false,
    });
    let server = Server::new(config, ShutdownSignal::new(), None).unwrap();
    server.load_trunk_tls_clients().unwrap();
    let flow = LegFlow::trunk(uc_routing::TrunkProtocol::Tls, "trunk.example.test", true);
    let (dest, _task) = trunk_server(&trunk_ca.leaf(7, &["trunk.example.test"])).await;
    let err = server
        .flows()
        .send(&flow, &dest, b"INVITE", None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, crate::flows::FlowError::Handshake(_)),
        "{err}"
    );
    let (dest, task) = trunk_server(&trunk_ca.leaf(8, &["trunk.example.test"])).await;
    server
        .flows()
        .send(&flow, &dest, b"INVITE", None)
        .await
        .unwrap();
    assert_eq!(&task.await.unwrap()[..], b"INVITE");
}
