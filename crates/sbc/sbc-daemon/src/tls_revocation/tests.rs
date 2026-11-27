//! Tests of the daemon's CRL wiring (SR-29). The PKI helpers are shared
//! with the server and flow tests.

use super::*;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::path::PathBuf;

const ALG: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P384_SHA384;

/// A CRL-signing P-384 CA.
pub struct TestCa {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

/// A P-384 leaf certificate and key.
pub struct TestLeaf {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    pub cert_pem: String,
    pub key_pem: String,
}

impl TestCa {
    pub fn new(name: &str) -> Self {
        let key = rcgen::KeyPair::generate_for(ALG).unwrap();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name
            .push(rcgen::DnType::CommonName, name.to_string());
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        p.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let cert = p.self_signed(&key).unwrap();
        Self { cert, key }
    }

    pub fn pem(&self) -> String {
        self.cert.pem()
    }

    pub fn roots(&self) -> rustls::RootCertStore {
        let mut r = rustls::RootCertStore::empty();
        r.add(self.cert.der().clone()).unwrap();
        r
    }

    /// A leaf for `names` with serial `serial`.
    pub fn leaf(&self, serial: u64, names: &[&str]) -> TestLeaf {
        let key = rcgen::KeyPair::generate_for(ALG).unwrap();
        let mut p = rcgen::CertificateParams::new(
            names.iter().map(|n| (*n).to_string()).collect::<Vec<_>>(),
        )
        .unwrap();
        p.serial_number = Some(rcgen::SerialNumber::from(serial));
        let cert = p.signed_by(&key, &self.cert, &self.key).unwrap();
        TestLeaf {
            chain: vec![cert.der().clone()],
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    /// A PEM CRL revoking `revoked`; `expired` puts `nextUpdate` in the
    /// past.
    pub fn crl_pem(&self, revoked: &[u64], expired: bool) -> String {
        let next = if expired {
            rcgen::date_time_ymd(2020, 2, 1)
        } else {
            rcgen::date_time_ymd(2090, 1, 1)
        };
        rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1),
            next_update: next,
            crl_number: rcgen::SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: revoked
                .iter()
                .map(|s| rcgen::RevokedCertParams {
                    serial_number: rcgen::SerialNumber::from(*s),
                    revocation_time: rcgen::date_time_ymd(2020, 1, 1),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&self.cert, &self.key)
        .unwrap()
        .pem()
        .unwrap()
    }
}

/// Writes `contents` to `dir/name`.
pub fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, contents).unwrap();
    p
}

fn loaded(events: &[uc_audit::AuditEvent]) -> Vec<uc_audit::event::TlsRevocationListLoaded> {
    events
        .iter()
        .filter_map(|e| match e {
            uc_audit::AuditEvent::TlsRevocationListLoaded(l) => Some(l.clone()),
            _ => None,
        })
        .collect()
}

pub fn rejected(
    events: &[uc_audit::AuditEvent],
) -> Vec<uc_audit::event::TlsPeerCertificateRejected> {
    events
        .iter()
        .filter_map(|e| match e {
            uc_audit::AuditEvent::TlsPeerCertificateRejected(r) => Some(r.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn policy_maps_client_and_server_unknown_separately() {
    let cfg = RevocationConfig {
        check_depth: RevocationCheckDepth::EndEntity,
        client_unknown: RevocationUnknown::Deny,
        server_unknown: RevocationUnknown::Allow,
        expired_crl: ExpiredCrlPolicy::Ignore,
        require: false,
    };
    let client = policy_for(Role::SipTls, cfg);
    assert_eq!(client.unknown, UnknownStatus::Deny);
    assert_eq!(client.depth, CheckDepth::EndEntity);
    assert_eq!(client.expired, ExpiredCrl::Ignore);
    for role in [Role::TrunkTls, Role::SrsTls, Role::CdrSyslog] {
        assert_eq!(policy_for(role, cfg).unknown, UnknownStatus::Allow);
    }
    // Defaults (D1, D2, D4): chain, deny, reject.
    assert_eq!(
        policy_for(Role::TrunkTls, RevocationConfig::default()),
        RevocationPolicy::default()
    );
}

#[test]
fn load_audits_per_role_and_accepts_an_expired_crl() {
    let ca = TestCa::new("ca");
    let dir = tempfile::tempdir().unwrap();
    let good = write(dir.path(), "good.pem", &ca.crl_pem(&[1, 2], false));
    let other = TestCa::new("other");
    let old = write(dir.path(), "old.pem", &other.crl_pem(&[], true));
    let capture = uc_audit::capture::start();
    let rev = load(Role::SrsTls, &good, RevocationConfig::default()).unwrap();
    assert_eq!(rev.crls.entries(), 2);
    assert!(enabled(Role::SrsTls));
    // D1: an expired CRL loads (the daemon starts); handshakes needing it
    // fail.
    let rev = load(Role::CdrSyslog, &old, RevocationConfig::default()).unwrap();
    assert_eq!(rev.policy.expired, ExpiredCrl::Reject);
    let events = loaded(&capture.events());
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0].role, "srs_tls");
    assert_eq!(events[0].crl_count, 1);
    assert_eq!(events[0].revoked_entries, 2);
    assert_eq!(events[0].expired_count, 0);
    assert_eq!(events[0].policy, "chain,deny,reject");
    assert_eq!(events[1].role, "cdr_syslog");
    assert_eq!(events[1].expired_count, 1);
    assert_eq!(events[1].next_update, Some(1_580_515_200));
}

#[test]
fn load_rejects_a_bad_crl_and_none_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let bad = write(
        dir.path(),
        "bad.pem",
        "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n",
    );
    assert!(load(Role::TrunkTls, &bad, RevocationConfig::default()).is_err());
    assert!(
        load_opt(Role::TrunkTls, None, RevocationConfig::default())
            .unwrap()
            .is_none()
    );
}

#[test]
fn rejection_audit_is_aggregated_per_role_and_reason() {
    let agg = FailureAggregator::new(AUDIT_WINDOW);
    let capture = uc_audit::capture::start();
    let t0 = Instant::now();
    let peer = Some(IpAddr::from([192, 0, 2, 7]));
    for _ in 0..5 {
        audit_rejection(&agg, Role::SipTls, RevocationFailure::Revoked, peer, t0);
    }
    audit_rejection(
        &agg,
        Role::SipTls,
        RevocationFailure::UnknownStatus,
        peer,
        t0,
    );
    let now = rejected(&capture.events());
    assert_eq!(now.len(), 2, "first of each reason at once: {now:?}");
    assert!(now.iter().all(|r| r.count == 1 && r.role == "sip_tls"));
    flush_from(&agg, t0 + AUDIT_WINDOW + Duration::from_secs(1));
    let all = rejected(&capture.events());
    assert_eq!(all.len(), 3, "{all:?}");
    assert_eq!(all[2].reason, "revoked");
    assert_eq!(all[2].count, 4, "the four suppressed ones, with a count");
    assert_eq!(all[2].peer, peer);
}

#[test]
fn note_transport_error_counts_only_revocation_failures() {
    let before = rejections(Role::SrsTls, RevocationFailure::CrlExpired);
    let e = uc_transport::TransportError::TlsPeerCertificateRejected {
        reason: RevocationFailure::CrlExpired,
        detail: String::new(),
    };
    assert!(note_transport_error(Role::SrsTls, &e, None));
    let other = uc_transport::TransportError::TlsHandshakeFailed {
        reason: "x".to_string(),
    };
    assert!(!note_transport_error(Role::SrsTls, &other, None));
    assert!(rejections(Role::SrsTls, RevocationFailure::CrlExpired) > before);
    let io = std::io::Error::other("not tls");
    assert!(!note_io_error(Role::CdrSyslog, &io, None));
}

#[test]
fn metrics_export_bounded_labelled_series() {
    let mut m = uc_metrics::SbcMetrics::standard();
    register_metrics(&mut m);
    note_rejection(Role::CdrSyslog, RevocationFailure::CrlInvalid, None);
    refresh_metrics(&m);
    let out = m.export();
    let line = out
        .lines()
        .find(|l| {
            l.contains("tls_revocation_rejections_total{")
                && l.contains("role=\"cdr_syslog\"")
                && l.contains("reason=\"crl_invalid\"")
        })
        .unwrap_or_else(|| panic!("{out}"));
    let v: i64 = line.rsplit(' ').next().unwrap().parse().unwrap();
    assert!(v >= 1, "{line}");
    let series = out
        .lines()
        .filter(|l| l.contains("tls_revocation_rejections_total{"))
        .count();
    assert_eq!(series, 16, "4 roles x 4 reasons");
    assert_eq!(
        out.lines()
            .filter(|l| l.contains("tls_revocation_enabled{"))
            .count(),
        4
    );
    assert_eq!(
        out.lines()
            .filter(|l| l.contains("tls_crl_next_update_seconds{"))
            .count(),
        4
    );
}

// --- V5: CDR syslog collector -------------------------------------------

/// One-shot blocking TLS collector presenting `leaf`; returns its port
/// and whether its handshake completed.
fn collector(leaf: &TestLeaf) -> (u16, std::thread::JoinHandle<bool>) {
    let server =
        uc_transport::tls::create_server_config(leaf.chain.clone(), leaf.key.clone_key()).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut conn = rustls::ServerConnection::new(Arc::new(server)).unwrap();
        while conn.is_handshaking() {
            if conn.complete_io(&mut tcp).is_err() {
                return false;
            }
        }
        true
    });
    (port, handle)
}

#[test]
fn revoked_syslog_collector_is_not_connected() {
    use uc_cdr::SyslogConnector as _;
    let ca = TestCa::new("collector-ca");
    let dir = tempfile::tempdir().unwrap();
    let ca_file = write(dir.path(), "ca.pem", &ca.pem());
    let crl_file = write(dir.path(), "crl.pem", &ca.crl_pem(&[7], false));
    let rev = load(Role::CdrSyslog, &crl_file, RevocationConfig::default()).unwrap();
    let before = rejections(Role::CdrSyslog, RevocationFailure::Revoked);

    let (port, server) = collector(&ca.leaf(7, &["127.0.0.1"]));
    let mut c = crate::cdr::TlsSyslogConnector::with_revocation(
        &format!("tls://127.0.0.1:{port}"),
        &ca_file,
        Some(&rev),
    )
    .unwrap();
    let err = c.connect().err().unwrap();
    assert!(err.to_string().contains("Revoked"), "{err}");
    assert!(!server.join().unwrap());
    assert!(rejections(Role::CdrSyslog, RevocationFailure::Revoked) > before);

    let (port, server) = collector(&ca.leaf(8, &["127.0.0.1"]));
    let mut c = crate::cdr::TlsSyslogConnector::with_revocation(
        &format!("tls://127.0.0.1:{port}"),
        &ca_file,
        Some(&rev),
    )
    .unwrap();
    assert!(c.connect().is_ok());
    assert!(server.join().unwrap());
}

#[test]
fn cdr_pipeline_fails_to_start_on_a_bad_syslog_crl() {
    let dir = tempfile::tempdir().unwrap();
    let ca = TestCa::new("collector-ca");
    let ca_file = write(dir.path(), "ca.pem", &ca.pem());
    let bad = write(dir.path(), "bad.crl", "garbage");
    let mut cfg = sbc_config::schema::CdrConfig::default();
    cfg.enabled = true;
    cfg.directory = dir.path().join("cdr");
    cfg.syslog.enabled = true;
    cfg.syslog.target = "tls://127.0.0.1:6514".to_string();
    cfg.syslog.ca_path = Some(ca_file);
    cfg.syslog.crl_path = Some(bad);
    let err = crate::cdr::start_from_config_with_revocation(
        &cfg,
        "sbc1",
        None,
        RevocationConfig::default(),
    )
    .err()
    .unwrap();
    assert!(err.contains("cdr.syslog.crl_path"), "{err}");
}
