//! Tests for CRL loading, the DER metadata walk and CRL-checked handshakes
//! (SR-29 phase (a)). CRLs are generated with rcgen 0.13.

use super::*;
use crate::tls::{
    MinTlsVersion, TlsServerOptions, create_client_config_verified,
    create_server_config_with_revocation,
};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateRevocationListParams, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, RevokedCertParams, SerialNumber, date_time_ymd,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

const ALG: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P384_SHA384;

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

fn ca_params(name: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name
        .push(rcgen::DnType::CommonName, name.to_string());
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    p
}

fn root(name: &str) -> Ca {
    let key = KeyPair::generate_for(ALG).unwrap();
    let cert = ca_params(name).self_signed(&key).unwrap();
    Ca { cert, key }
}

fn intermediate(name: &str, serial: u64, issuer: &Ca) -> Ca {
    let key = KeyPair::generate_for(ALG).unwrap();
    let mut p = ca_params(name);
    p.serial_number = Some(SerialNumber::from(serial));
    let cert = p.signed_by(&key, &issuer.cert, &issuer.key).unwrap();
    Ca { cert, key }
}

struct Leaf {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn leaf(serial: u64, issuer: &Ca, extra_chain: &[&Ca]) -> Leaf {
    let key = KeyPair::generate_for(ALG).unwrap();
    let mut p = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    p.serial_number = Some(SerialNumber::from(serial));
    let cert = p.signed_by(&key, &issuer.cert, &issuer.key).unwrap();
    let mut chain = vec![cert.der().clone()];
    chain.extend(extra_chain.iter().map(|c| c.cert.der().clone()));
    Leaf {
        chain,
        key: PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    }
}

/// A CRL from `issuer` revoking `serials`; `expired` puts `nextUpdate` in
/// the past.
fn crl(issuer: &Ca, serials: &[u64], expired: bool) -> rcgen::CertificateRevocationList {
    let (this_update, next_update) = if expired {
        (date_time_ymd(2020, 1, 1), date_time_ymd(2020, 2, 1))
    } else {
        (date_time_ymd(2020, 1, 1), date_time_ymd(2090, 1, 1))
    };
    CertificateRevocationListParams {
        this_update,
        next_update,
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: serials
            .iter()
            .map(|s| RevokedCertParams {
                serial_number: SerialNumber::from(*s),
                revocation_time: date_time_ymd(2020, 1, 1),
                reason_code: None,
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&issuer.cert, &issuer.key)
    .unwrap()
}

fn set_of(crls: &[&rcgen::CertificateRevocationList]) -> CrlSet {
    CrlSet::from_bytes(Path::new("test"), crls.iter().map(|c| c.der().as_ref())).unwrap()
}

fn revocation(crls: &[&rcgen::CertificateRevocationList], policy: RevocationPolicy) -> Revocation {
    Revocation {
        crls: Arc::new(set_of(crls)),
        policy,
    }
}

fn roots_of(ca: &Ca) -> Arc<RootCertStore> {
    let mut r = RootCertStore::empty();
    r.add(ca.cert.der().clone()).unwrap();
    Arc::new(r)
}

fn plain_server(l: &Leaf) -> ServerConfig {
    crate::tls::create_server_config(l.chain.clone(), l.key.clone_key()).unwrap()
}

fn crl_client(ca: &Ca, rev: &Revocation) -> ClientConfig {
    create_client_config_verified(
        rev.server_verifier(roots_of(ca)).unwrap(),
        MinTlsVersion::V1_3,
        None,
    )
    .unwrap()
}

/// Drives a handshake in memory. Returns the client's or server's error,
/// whichever side failed first.
fn handshake(client: ClientConfig, server: ServerConfig) -> Result<(), rustls::Error> {
    let mut c = ClientConnection::new(Arc::new(client), "localhost".try_into().unwrap())?;
    let mut s = ServerConnection::new(Arc::new(server))?;
    for _ in 0..16 {
        if !c.is_handshaking() && !s.is_handshaking() {
            return Ok(());
        }
        let mut buf = Vec::new();
        while c.wants_write() {
            c.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            s.read_tls(&mut &buf[..]).unwrap();
            s.process_new_packets()?;
        }
        let mut buf = Vec::new();
        while s.wants_write() {
            s.write_tls(&mut buf).unwrap();
        }
        if !buf.is_empty() {
            c.read_tls(&mut &buf[..]).unwrap();
            c.process_new_packets()?;
        }
    }
    panic!("handshake did not finish");
}

fn verdict(r: &Result<(), rustls::Error>) -> Option<RevocationFailure> {
    r.as_ref().err().and_then(classify)
}

// --- V2 (server certificates, client side) --------------------------------

#[test]
fn server_cert_revoked_leaf_rejected_good_leaf_accepted() {
    let ca = root("ca");
    let bad = leaf(7, &ca, &[]);
    let good = leaf(8, &ca, &[]);
    let rev = revocation(&[&crl(&ca, &[7], false)], RevocationPolicy::default());
    let r = handshake(crl_client(&ca, &rev), plain_server(&bad));
    assert_eq!(verdict(&r), Some(RevocationFailure::Revoked), "{r:?}");
    handshake(crl_client(&ca, &rev), plain_server(&good)).unwrap();
}

#[test]
fn server_cert_unknown_issuer_denied_or_allowed() {
    let ca = root("ca");
    let other = root("other");
    let good = leaf(8, &ca, &[]);
    let crls = [&crl(&other, &[], false)];
    let deny = revocation(&crls, RevocationPolicy::default());
    let r = handshake(crl_client(&ca, &deny), plain_server(&good));
    assert_eq!(verdict(&r), Some(RevocationFailure::UnknownStatus), "{r:?}");
    let allow = revocation(
        &crls,
        RevocationPolicy {
            unknown: UnknownStatus::Allow,
            ..RevocationPolicy::default()
        },
    );
    handshake(crl_client(&ca, &allow), plain_server(&good)).unwrap();
}

#[test]
fn server_cert_expired_crl_rejected_or_ignored() {
    let ca = root("ca");
    let good = leaf(8, &ca, &[]);
    let crls = [&crl(&ca, &[7], true)];
    let reject = revocation(&crls, RevocationPolicy::default());
    let r = handshake(crl_client(&ca, &reject), plain_server(&good));
    assert_eq!(verdict(&r), Some(RevocationFailure::CrlExpired), "{r:?}");
    let ignore = revocation(
        &crls,
        RevocationPolicy {
            expired: ExpiredCrl::Ignore,
            ..RevocationPolicy::default()
        },
    );
    handshake(crl_client(&ca, &ignore), plain_server(&good)).unwrap();
    // Ignoring expiry never un-revokes a listed certificate.
    let bad = leaf(7, &ca, &[]);
    let r = handshake(crl_client(&ca, &ignore), plain_server(&bad));
    assert_eq!(verdict(&r), Some(RevocationFailure::Revoked), "{r:?}");
}

#[test]
fn revoked_intermediate_depends_on_check_depth() {
    let ca = root("root");
    let int = intermediate("int", 42, &ca);
    let srv = leaf(9, &int, &[&int]);
    // The root's ARL revokes the intermediate; the intermediate's CRL is
    // empty.
    let crls = [&crl(&ca, &[42], false), &crl(&int, &[], false)];
    let chain = revocation(&crls, RevocationPolicy::default());
    let r = handshake(crl_client(&ca, &chain), plain_server(&srv));
    assert_eq!(verdict(&r), Some(RevocationFailure::Revoked), "{r:?}");
    let ee = revocation(
        &crls,
        RevocationPolicy {
            depth: CheckDepth::EndEntity,
            ..RevocationPolicy::default()
        },
    );
    handshake(crl_client(&ca, &ee), plain_server(&srv)).unwrap();
}

#[test]
fn chain_depth_with_deny_needs_the_roots_arl() {
    let ca = root("root");
    let int = intermediate("int", 42, &ca);
    let srv = leaf(9, &int, &[&int]);
    let rev = revocation(&[&crl(&int, &[], false)], RevocationPolicy::default());
    let r = handshake(crl_client(&ca, &rev), plain_server(&srv));
    assert_eq!(verdict(&r), Some(RevocationFailure::UnknownStatus), "{r:?}");
}

#[test]
fn crl_with_a_bad_signature_is_crl_invalid() {
    let ca = root("ca");
    // Same subject name, different key: the CRL names the CA as issuer but
    // its signature does not verify with the CA's key.
    let impostor = root("ca");
    let good = leaf(8, &ca, &[]);
    let rev = revocation(&[&crl(&impostor, &[], false)], RevocationPolicy::default());
    let r = handshake(crl_client(&ca, &rev), plain_server(&good));
    assert_eq!(verdict(&r), Some(RevocationFailure::CrlInvalid), "{r:?}");
}

#[test]
fn crl_checked_configs_stay_fips() {
    let ca = root("ca");
    let l = leaf(8, &ca, &[]);
    let rev = revocation(&[&crl(&ca, &[], false)], RevocationPolicy::default());
    assert!(crl_client(&ca, &rev).fips());
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert.der().clone()).unwrap();
    let server = create_server_config_with_revocation(
        l.chain.clone(),
        l.key.clone_key(),
        TlsServerOptions {
            min_version: MinTlsVersion::V1_3,
            client_ca: Some(roots),
        },
        Some(&rev),
    )
    .unwrap();
    assert!(server.fips());
}

// --- V1 (client certificates, server side) --------------------------------

fn mtls_server(server_ca: &Ca, client_ca: &Ca, rev: &Revocation) -> ServerConfig {
    let l = leaf(1, server_ca, &[]);
    let mut roots = RootCertStore::empty();
    roots.add(client_ca.cert.der().clone()).unwrap();
    create_server_config_with_revocation(
        l.chain,
        l.key,
        TlsServerOptions {
            min_version: MinTlsVersion::V1_3,
            client_ca: Some(roots),
        },
        Some(rev),
    )
    .unwrap()
}

fn mtls_client(server_ca: &Ca, client: &Leaf) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(server_ca.cert.der().clone()).unwrap();
    crate::tls::create_client_config_with(crate::tls::TlsClientOptions {
        roots,
        min_version: MinTlsVersion::V1_3,
        client_auth: Some((client.chain.clone(), client.key.clone_key())),
    })
    .unwrap()
}

#[test]
fn client_cert_revoked_rejected_good_accepted() {
    let server_ca = root("server-ca");
    let client_ca = root("client-ca");
    let bad = leaf(70, &client_ca, &[]);
    let good = leaf(71, &client_ca, &[]);
    let rev = revocation(
        &[&crl(&client_ca, &[70], false)],
        RevocationPolicy::default(),
    );
    let r = handshake(
        mtls_client(&server_ca, &bad),
        mtls_server(&server_ca, &client_ca, &rev),
    );
    assert_eq!(verdict(&r), Some(RevocationFailure::Revoked), "{r:?}");
    handshake(
        mtls_client(&server_ca, &good),
        mtls_server(&server_ca, &client_ca, &rev),
    )
    .unwrap();
}

#[test]
fn client_cert_unknown_status_and_expiry() {
    let server_ca = root("server-ca");
    let client_ca = root("client-ca");
    let other = root("other");
    let good = leaf(71, &client_ca, &[]);
    let unknown = revocation(&[&crl(&other, &[], false)], RevocationPolicy::default());
    let r = handshake(
        mtls_client(&server_ca, &good),
        mtls_server(&server_ca, &client_ca, &unknown),
    );
    assert_eq!(verdict(&r), Some(RevocationFailure::UnknownStatus), "{r:?}");
    let allow = Revocation {
        policy: RevocationPolicy {
            unknown: UnknownStatus::Allow,
            ..RevocationPolicy::default()
        },
        ..unknown
    };
    handshake(
        mtls_client(&server_ca, &good),
        mtls_server(&server_ca, &client_ca, &allow),
    )
    .unwrap();
    let expired = revocation(&[&crl(&client_ca, &[], true)], RevocationPolicy::default());
    let r = handshake(
        mtls_client(&server_ca, &good),
        mtls_server(&server_ca, &client_ca, &expired),
    );
    assert_eq!(verdict(&r), Some(RevocationFailure::CrlExpired), "{r:?}");
}

#[test]
fn client_cert_revoked_intermediate_depends_on_check_depth() {
    let server_ca = root("server-ca");
    let client_ca = root("client-root");
    let int = intermediate("client-int", 43, &client_ca);
    let client = leaf(72, &int, &[&int]);
    let crls = [&crl(&client_ca, &[43], false), &crl(&int, &[], false)];
    let chain = revocation(&crls, RevocationPolicy::default());
    let r = handshake(
        mtls_client(&server_ca, &client),
        mtls_server(&server_ca, &client_ca, &chain),
    );
    assert_eq!(verdict(&r), Some(RevocationFailure::Revoked), "{r:?}");
    let ee = revocation(
        &crls,
        RevocationPolicy {
            depth: CheckDepth::EndEntity,
            ..RevocationPolicy::default()
        },
    );
    handshake(
        mtls_client(&server_ca, &client),
        mtls_server(&server_ca, &client_ca, &ee),
    )
    .unwrap();
}

// --- Loopback over sockets: the transport error variant -------------------

#[tokio::test]
async fn loopback_revoked_server_maps_to_peer_certificate_rejected() {
    use crate::listener::ListenerConfig;
    use crate::tls::{TlsListener, TlsTransport};
    use uc_types::address::{SbcSocketAddr, TransportType};
    let ca = root("ca");
    let bad = leaf(7, &ca, &[]);
    let rev = revocation(&[&crl(&ca, &[7], false)], RevocationPolicy::default());
    let addr = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 0);
    let listener = TlsListener::bind(
        ListenerConfig::new(addr, TransportType::Tls),
        Arc::new(plain_server(&bad)),
    )
    .await
    .unwrap();
    let local = *listener.local_addr();
    let server = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
    let err = TlsTransport::connect(local, "localhost", Arc::new(crl_client(&ca, &rev)))
        .await
        .err()
        .unwrap();
    assert!(
        matches!(
            err,
            TransportError::TlsPeerCertificateRejected {
                reason: RevocationFailure::Revoked,
                ..
            }
        ),
        "{err:?}"
    );
    let _ = server.await;
}

#[tokio::test]
async fn loopback_revoked_client_maps_to_peer_certificate_rejected() {
    use crate::listener::ListenerConfig;
    use crate::tls::{TlsListener, TlsTransport};
    use uc_types::address::{SbcSocketAddr, TransportType};
    let server_ca = root("server-ca");
    let client_ca = root("client-ca");
    let bad = leaf(70, &client_ca, &[]);
    let rev = revocation(
        &[&crl(&client_ca, &[70], false)],
        RevocationPolicy::default(),
    );
    let addr = SbcSocketAddr::new_v4(std::net::Ipv4Addr::LOCALHOST, 0);
    let listener = TlsListener::bind(
        ListenerConfig::new(addr, TransportType::Tls),
        Arc::new(mtls_server(&server_ca, &client_ca, &rev)),
    )
    .await
    .unwrap();
    let local = *listener.local_addr();
    let server = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
    // TLS 1.3: the client may finish before the server checks its
    // certificate, so the server's error is the one under test.
    let _client =
        TlsTransport::connect(local, "localhost", Arc::new(mtls_client(&server_ca, &bad))).await;
    let err = server.await.unwrap().err().unwrap();
    assert!(
        matches!(
            err,
            TransportError::TlsPeerCertificateRejected {
                reason: RevocationFailure::Revoked,
                ..
            }
        ),
        "{err:?}"
    );
}

// --- Loader ---------------------------------------------------------------

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

#[test]
fn loads_pem_der_multi_pem_and_directory() {
    let (ca, cb, cc) = (
        crl(&root("a"), &[1, 2], false),
        crl(&root("b"), &[], false),
        crl(&root("c"), &[3], false),
    );
    let dir = tempfile::tempdir().unwrap();
    let pem = write(dir.path(), "a.pem", ca.pem().unwrap().as_bytes());
    let der = write(dir.path(), "b.der", cb.der().as_ref());
    let set = CrlSet::load(&pem).unwrap();
    assert_eq!((set.len(), set.entries()), (1, 2));
    assert_eq!(CrlSet::load(&der).unwrap().len(), 1);
    let multi = format!("{}\n{}", ca.pem().unwrap(), cc.pem().unwrap());
    let multi_dir = tempfile::tempdir().unwrap();
    let m = write(multi_dir.path(), "m.pem", multi.as_bytes());
    let set = CrlSet::load(&m).unwrap();
    assert_eq!((set.len(), set.entries()), (2, 3));
    // Directory: a.pem, b.der, c.crl; dotfiles skipped.
    write(dir.path(), "c.crl", cc.der().as_ref());
    write(dir.path(), ".hidden.pem", b"garbage");
    let set = CrlSet::load(dir.path()).unwrap();
    assert_eq!((set.len(), set.entries()), (3, 3));
    assert!(set.der_bytes() > 0);
    // Any other name is refused, never skipped.
    write(dir.path(), "issuing-ca", cb.der().as_ref());
    let e = CrlSet::load(dir.path()).unwrap_err().to_string();
    assert!(e.contains("not a *.pem"), "{e}");
    assert_eq!(set.earliest_next_update(), Some(3_786_912_000)); // 2090-01-01
    assert_eq!(set.expired_at(0).count(), 0);
    assert_eq!(set.expired_at(4_000_000_000).count(), 3);
}

#[test]
fn rejects_empty_garbage_and_non_crl_pem() {
    let dir = tempfile::tempdir().unwrap();
    let empty = write(dir.path(), "empty.pem", b"");
    assert!(CrlSet::load(&empty).is_err());
    let garbage = write(dir.path(), "g.der", b"\x30\x03\x02\x01\x01");
    assert!(CrlSet::load(&garbage).is_err());
    let a = root("a");
    let cert_only = write(dir.path(), "cert.pem", a.cert.pem().as_bytes());
    let e = CrlSet::load(&cert_only).unwrap_err().to_string();
    assert!(e.contains("no X509 CRL"), "{e}");
    let empty_dir = tempfile::tempdir().unwrap();
    assert!(CrlSet::load(empty_dir.path()).is_err());
    assert!(CrlSet::load(&dir.path().join("missing.pem")).is_err());
}

#[test]
fn rejects_duplicate_issuer() {
    let a = root("a");
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), "1.der", crl(&a, &[], false).der().as_ref());
    write(dir.path(), "2.der", crl(&a, &[5], false).der().as_ref());
    let e = CrlSet::load(dir.path()).unwrap_err().to_string();
    assert!(e.contains("same issuer"), "{e}");
}

#[test]
fn rejects_oversize_file() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("big.der");
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(MAX_CRL_FILE_BYTES + 1).unwrap();
    let e = CrlSet::load(&p).unwrap_err().to_string();
    assert!(e.contains("larger than"), "{e}");
}

#[test]
fn rejects_too_many_files() {
    let a = root("a");
    let der = crl(&a, &[], false);
    let dir = tempfile::tempdir().unwrap();
    for i in 0..=MAX_CRL_FILES {
        write(dir.path(), &format!("{i:04}.der"), der.der().as_ref());
    }
    let e = CrlSet::load(dir.path()).unwrap_err().to_string();
    assert!(e.contains("more than"), "{e}");
}

#[cfg(unix)]
#[test]
fn symlinks_followed_only_inside_the_directory() {
    let a = root("a");
    let der = crl(&a, &[], false);
    let outside = tempfile::tempdir().unwrap();
    let target = write(outside.path(), "x.der", der.der().as_ref());
    // Top-level symlink: refused.
    let link_dir = tempfile::tempdir().unwrap();
    let top = link_dir.path().join("top.der");
    std::os::unix::fs::symlink(&target, &top).unwrap();
    assert!(CrlSet::load(&top).is_err());
    // Symlink out of the directory: refused.
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(&target, dir.path().join("out.der")).unwrap();
    let e = CrlSet::load(dir.path()).unwrap_err().to_string();
    assert!(e.contains("outside"), "{e}");
    // ConfigMap layout: key -> ..data/key inside the directory: loaded.
    let cm = tempfile::tempdir().unwrap();
    std::fs::create_dir(cm.path().join("..data")).unwrap();
    write(&cm.path().join("..data"), "ca.der", der.der().as_ref());
    std::os::unix::fs::symlink("..data/ca.der", cm.path().join("ca.der")).unwrap();
    assert_eq!(CrlSet::load(cm.path()).unwrap().len(), 1);
}

// Hand-built DER for structures rcgen cannot produce. The signature is
// garbage: parsing does not verify it.
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let len = body.len();
    if len < 0x80 {
        v.push(u8::try_from(len).unwrap());
    } else {
        let bytes = u16::try_from(len).unwrap().to_be_bytes();
        v.push(0x82);
        v.extend_from_slice(&bytes);
    }
    v.extend_from_slice(body);
    v
}

fn crl_with_extension(oid: &[u8], value: &[u8]) -> Vec<u8> {
    let alg = tlv(
        0x30,
        &tlv(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]),
    );
    let name = tlv(
        0x30,
        &tlv(
            0x31,
            &tlv(
                0x30,
                &[tlv(0x06, &[0x55, 0x04, 0x03]), tlv(0x0c, b"x")].concat(),
            ),
        ),
    );
    let ext = tlv(0x30, &[tlv(0x06, oid), tlv(0x04, value)].concat());
    let exts = tlv(0xa0, &tlv(0x30, &ext));
    let tbs = tlv(
        0x30,
        &[
            tlv(0x02, &[1]),
            alg.clone(),
            name,
            tlv(0x17, b"200101000000Z"),
            tlv(0x17, b"400101000000Z"),
            exts,
        ]
        .concat(),
    );
    tlv(0x30, &[tbs, alg, tlv(0x03, &[0, 1, 2, 3])].concat())
}

#[test]
fn rejects_delta_and_indirect_crls() {
    // deltaCRLIndicator (2.5.29.27), BaseCRLNumber 1.
    let delta = crl_with_extension(&[0x55, 0x1d, 0x1b], &tlv(0x02, &[1]));
    assert!(CrlInfo::parse(&delta, PathBuf::new()).is_some());
    let e = CrlSet::from_bytes(Path::new("delta"), [delta.as_slice()]).unwrap_err();
    assert!(e.to_string().contains("Delta"), "{e}");
    // issuingDistributionPoint (2.5.29.28) with indirectCRL [4] TRUE.
    let indirect = crl_with_extension(&[0x55, 0x1d, 0x1c], &tlv(0x30, &[0x84, 0x01, 0xff]));
    let e = CrlSet::from_bytes(Path::new("indirect"), [indirect.as_slice()]).unwrap_err();
    assert!(e.to_string().contains("Indirect"), "{e}");
}

// --- DER metadata walk ----------------------------------------------------

#[test]
fn der_walk_reads_times_issuer_and_entries() {
    let a = root("a");
    let c = crl(&a, &[1, 2, 3], false);
    let info = CrlInfo::parse(c.der().as_ref(), PathBuf::from("x")).unwrap();
    assert_eq!(info.this_update, 1_577_836_800); // 2020-01-01 (UTCTime)
    assert_eq!(info.next_update, Some(3_786_912_000)); // 2090-01-01 (GeneralizedTime)
    assert_eq!(info.entries, 3);
    // The issuer is the CA's subject Name TLV.
    let other = CrlInfo::parse(crl(&a, &[], true).der().as_ref(), PathBuf::new()).unwrap();
    assert_eq!(info.issuer, other.issuer);
    assert_eq!(other.next_update, Some(1_580_515_200)); // 2020-02-01
    assert_eq!(other.entries, 0);
}

#[test]
fn der_walk_rejects_truncated_overlong_and_wrong_tags() {
    let a = root("a");
    let c = crl(&a, &[1], false);
    let der = c.der().as_ref();
    for n in 0..der.len() {
        assert!(
            CrlInfo::parse(&der[..n], PathBuf::new()).is_none(),
            "prefix {n}"
        );
    }
    // Trailing bytes after the CertificateList.
    let mut long = der.to_vec();
    long.push(0);
    assert!(CrlInfo::parse(&long, PathBuf::new()).is_none());
    // Outer length larger than the input.
    let mut over = der.to_vec();
    over[1] = 0x84;
    assert!(CrlInfo::parse(&over, PathBuf::new()).is_none());
    // Wrong outer tag.
    let mut wrong = der.to_vec();
    wrong[0] = 0x31;
    assert!(CrlInfo::parse(&wrong, PathBuf::new()).is_none());
    // Indefinite length.
    assert!(CrlInfo::parse(&[0x30, 0x80, 0, 0], PathBuf::new()).is_none());
    // High tag number form.
    assert!(CrlInfo::parse(&[0x1f, 0x01, 0x00], PathBuf::new()).is_none());
}

#[test]
fn der_walk_rejects_bad_times() {
    let bad = |t: &[u8], tag: u8| {
        let mut d = Der::new(&[]);
        let enc = tlv(tag, t);
        d.rest = &enc;
        read_time(&mut d)
    };
    assert_eq!(bad(b"200101000000Z", 0x17), Some(1_577_836_800));
    assert_eq!(bad(b"990101000000Z", 0x17), Some(915_148_800)); // 1999
    assert_eq!(bad(b"20200101000000Z", 0x18), Some(1_577_836_800));
    assert!(bad(b"201301000000Z", 0x17).is_none()); // month 13
    assert!(bad(b"2001010000000", 0x17).is_none()); // no Z
    assert!(bad(b"20010100000Z", 0x17).is_none()); // short
    assert!(bad(b"2020010100000+", 0x18).is_none());
    assert!(bad(b"20a10100000Z", 0x17).is_none());
}

proptest::proptest! {
    #[test]
    fn der_walk_never_panics(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..512)) {
        let _ = CrlInfo::parse(&bytes, PathBuf::new());
    }

    #[test]
    fn der_walk_never_panics_on_mutated_crl(idx in 0usize..4096, byte in proptest::num::u8::ANY) {
        static DER: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
        let der = DER.get_or_init(|| crl(&root("p"), &[1, 2], false).der().as_ref().to_vec());
        let mut m = der.clone();
        let i = idx % m.len();
        m[i] = byte;
        let _ = CrlInfo::parse(&m, PathBuf::new());
    }
}
