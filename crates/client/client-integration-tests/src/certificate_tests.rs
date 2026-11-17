//! Certificate integration tests.
//!
//! Tests the certificate flow from store access through `ClientApp`
//! configuration. The store lists only real certificates (none are
//! fabricated outside client-core unit tests), and smart-card signing has
//! no card-backed implementation yet, so card-only paths fail closed.
// NIST 800-53 Rev5: IA-2(2), IA-2(12) (not met: fails closed), IA-5(2)
// POAM: POA&M-371

use crate::test_utils::{allocate_test_addr, init_test_tracing, test_certificate_info};
use client_core::{AppEvent, CertStoreError, CertificateStore, ClientApp};
use client_types::{CertificateConfig, CertificateSelectionMode};
use tokio::sync::mpsc;

/// Tests that the certificate store lists certificates and never returns
/// the fabricated development certificate.
#[tokio::test]
async fn test_certificate_store_list() {
    init_test_tracing();

    let store = CertificateStore::open_personal();
    let certs = store.list_certificates();
    assert!(certs.is_ok());

    let fabricated = test_certificate_info();
    let certs = certs.unwrap();
    assert!(
        !certs.iter().any(|c| c.thumbprint == fabricated.thumbprint),
        "fabricated certificate listed"
    );
}

/// Tests that auto-select prefers a valid P-384 certificate when one is
/// listed.
#[tokio::test]
async fn test_certificate_auto_select_prefers_cnsa() {
    init_test_tracing();

    let config = CertificateConfig::new();
    let store = CertificateStore::open_personal();
    let certs = store.list_certificates().unwrap();
    let has_p384 = certs
        .iter()
        .any(|c| c.is_valid && c.key_algorithm.contains("P-384"));

    match store.select_certificate(&config) {
        Ok(cert) => {
            assert!(cert.is_valid, "Selected certificate should be valid");
            if has_p384 {
                assert!(
                    cert.key_algorithm.contains("P-384"),
                    "Should select P-384 certificate, got: {}",
                    cert.key_algorithm
                );
            }
        }
        Err(e) => assert!(
            !certs.iter().any(|c| c.is_valid),
            "valid certificate listed but selection failed: {e}"
        ),
    }
}

/// Tests finding a certificate by thumbprint.
#[tokio::test]
async fn test_certificate_find_by_thumbprint() {
    init_test_tracing();

    let store = CertificateStore::open_personal();

    for cert in store.list_certificates().unwrap() {
        let found = store.find_by_thumbprint(&cert.thumbprint).unwrap();
        assert_eq!(found.thumbprint, cert.thumbprint);
    }

    let fabricated = test_certificate_info();
    assert!(matches!(
        store.find_by_thumbprint(&fabricated.thumbprint),
        Err(CertStoreError::CertificateNotFound(_))
    ));
}

/// Tests that selecting a specific certificate works for listed
/// certificates and fails for an unknown one.
#[tokio::test]
async fn test_certificate_specific_selection() {
    init_test_tracing();

    let store = CertificateStore::open_personal();

    for cert in store.list_certificates().unwrap() {
        let config = CertificateConfig::new().with_thumbprint(&cert.thumbprint);
        let selected = store.select_certificate(&config).unwrap();
        assert_eq!(selected.thumbprint, cert.thumbprint);
    }

    let fabricated = test_certificate_info();
    let config = CertificateConfig::new().with_thumbprint(&fabricated.thumbprint);
    assert!(store.select_certificate(&config).is_err());
}

/// Tests that expired certificates are filtered in auto-select.
#[tokio::test]
async fn test_certificate_filters_expired() {
    init_test_tracing();

    let mut config = CertificateConfig::new();
    config.selection_mode = CertificateSelectionMode::AutoSelect;

    let store = CertificateStore::open_personal();

    if let Ok(cert) = store.select_certificate(&config) {
        assert!(cert.is_valid);
    }
}

/// Tests getting the certificate chain (DER-encoded): a returned chain is
/// the certificate itself; an unknown thumbprint has none.
#[tokio::test]
async fn test_certificate_get_chain() {
    init_test_tracing();

    let store = CertificateStore::open_personal();

    for cert in store.list_certificates().unwrap() {
        if let Ok(chain) = store.get_certificate_chain(&cert.thumbprint) {
            assert!(!chain.is_empty(), "Should return at least one certificate");
            assert!(!chain[0].is_empty(), "Certificate should not be empty");
            // DER-encoded certificate starts with a SEQUENCE tag
            assert_eq!(chain[0][0], 0x30, "Should start with ASN.1 SEQUENCE tag");
        }
    }

    let fabricated = test_certificate_info();
    assert!(store.get_certificate_chain(&fabricated.thumbprint).is_err());
}

/// Off Windows no card-backed signer exists: no listed certificate claims a
/// usable private key, signing and PIN checks report `NotSupported`.
#[cfg(not(windows))]
#[tokio::test]
async fn test_certificate_has_private_key() {
    use client_core::SignatureAlgorithm;
    use client_types::SmartCardPin;

    init_test_tracing();

    let store = CertificateStore::open_personal();
    let pin = SmartCardPin::new("123456");

    for cert in store.list_certificates().unwrap() {
        assert!(!matches!(store.has_private_key(&cert.thumbprint), Ok(true)));
        assert!(matches!(
            store.sign_data(
                &cert.thumbprint,
                b"data",
                SignatureAlgorithm::EcdsaSha384,
                Some(&pin)
            ),
            Err(CertStoreError::NotSupported)
        ));
        assert!(matches!(
            store.verify_pin(&cert.thumbprint, &pin),
            Err(CertStoreError::NotSupported)
        ));
    }

    let fabricated = test_certificate_info();
    assert!(store.has_private_key(&fabricated.thumbprint).is_err());
}

/// A smart-card certificate (no key) is refused by `ClientApp` and leaves
/// no certificate configured.
#[tokio::test]
async fn test_client_app_certificate_configuration() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<AppEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    // Create client app - may fail if config directories don't exist
    let result = ClientApp::new(sip_addr, media_addr, tx);

    // Skip test if ClientApp creation fails (e.g., in CI without home dir)
    let Ok(mut app) = result else {
        println!("Skipping test - ClientApp creation failed (expected in CI)");
        return;
    };

    assert!(!app.has_client_certificate());
    assert!(app.client_certificate_thumbprint().is_none());

    let store = CertificateStore::open_personal();
    let chains: Vec<(String, Vec<Vec<u8>>)> = store
        .list_certificates()
        .unwrap()
        .into_iter()
        .filter_map(|c| {
            store
                .get_certificate_chain(&c.thumbprint)
                .ok()
                .map(|chain| (c.thumbprint, chain))
        })
        .collect();

    // A placeholder chain stands in when the host lists none.
    let candidates = if chains.is_empty() {
        vec![(test_certificate_info().thumbprint, vec![vec![0x30, 0x00]])]
    } else {
        chains
    };

    for (thumbprint, chain) in candidates {
        assert!(app.set_client_certificate(chain, &thumbprint).is_err());
        assert!(!app.has_client_certificate());
        assert!(app.client_certificate_thumbprint().is_none());
    }
}

/// A refused card certificate does not register an mTLS account.
#[tokio::test]
async fn test_client_app_mtls_refused_without_key() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<AppEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let result = ClientApp::new(sip_addr, media_addr, tx);
    let Ok(mut app) = result else {
        println!("Skipping test - ClientApp creation failed");
        return;
    };

    let fabricated = test_certificate_info();
    assert!(
        app.set_client_certificate(vec![vec![0x30, 0x00]], &fabricated.thumbprint)
            .is_err()
    );

    let account = crate::test_utils::test_account();
    assert_eq!(account.auth_mode, client_types::SipAuthMode::Mtls);
    let state_before = app.state();
    let error = app.register_account(&account).await.unwrap_err();
    assert!(error.to_string().contains("certificate"), "{error}");
    assert_eq!(app.state(), state_before);
}

/// Tests listing smart card readers: no fabricated reader names.
#[tokio::test]
async fn test_certificate_list_smart_card_readers() {
    init_test_tracing();

    let store = CertificateStore::open_personal();
    let readers = store.list_smart_card_readers();
    assert!(readers.is_ok());

    let fabricated = test_certificate_info().reader_name.unwrap();
    assert!(!readers.unwrap().contains(&fabricated));
}

/// Tests certificate store refresh.
#[tokio::test]
async fn test_certificate_store_refresh() {
    init_test_tracing();

    let mut store = CertificateStore::open_personal();

    let certs_before = store.list_certificates().unwrap();
    store.refresh().unwrap();
    let certs_after = store.list_certificates().unwrap();

    assert_eq!(certs_before.len(), certs_after.len());
}

/// Certificate-store flow with a real card: needs a card with a CNSA
/// certificate (Windows CNG). Covers the store only; SIP TLS still refuses
/// a card certificate (POA&M-371).
#[cfg(windows)]
#[tokio::test]
#[ignore = "requires a smart card"]
async fn test_card_certificate_store_flow() {
    init_test_tracing();

    let store = CertificateStore::open_personal();
    let config = CertificateConfig::new();
    let selected = store.select_certificate(&config).unwrap();

    assert!(selected.is_valid);
    assert!(
        selected.key_algorithm.contains("P-384"),
        "Should select CNSA 2.0 compliant certificate"
    );
    assert!(store.has_private_key(&selected.thumbprint).unwrap());
    let chain = store.get_certificate_chain(&selected.thumbprint).unwrap();
    assert!(!chain.is_empty());
}
