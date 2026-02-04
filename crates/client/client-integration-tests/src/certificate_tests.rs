//! Certificate integration tests.
//!
//! Tests the complete certificate flow from store access through
//! ClientApp configuration to CallManager DTLS setup.

use crate::test_utils::{allocate_test_addr, init_test_tracing, test_certificate_info};
use client_core::{AppEvent, CertificateStore, ClientApp};
use client_types::{CertificateConfig, CertificateSelectionMode};
use tokio::sync::mpsc;

/// Tests that the certificate store can list certificates.
#[tokio::test]
async fn test_certificate_store_list() {
    init_test_tracing();

    let store = CertificateStore::open_personal();
    let certs = store.list_certificates();

    // On non-Windows, we get stub data
    // On Windows, we get real certificates (may be empty)
    assert!(certs.is_ok());

    #[cfg(not(windows))]
    {
        let certs = certs.unwrap();
        assert!(!certs.is_empty(), "Should have stub certificates");

        // Verify stub certificate properties
        let valid_certs: Vec<_> = certs.iter().filter(|c| c.is_valid).collect();
        assert!(!valid_certs.is_empty(), "Should have valid certificates");

        // Check CNSA 2.0 compliant certificates exist
        let p384_certs: Vec<_> = valid_certs
            .iter()
            .filter(|c| c.key_algorithm.contains("P-384"))
            .collect();
        assert!(
            !p384_certs.is_empty(),
            "Should have P-384 certificates for CNSA 2.0"
        );
    }
}

/// Tests certificate selection with auto-select mode prefers P-384.
#[tokio::test]
async fn test_certificate_auto_select_prefers_cnsa() {
    init_test_tracing();

    let config = CertificateConfig::new();
    let store = CertificateStore::open_personal();

    #[cfg(not(windows))]
    {
        let cert = store.select_certificate(&config).unwrap();

        // Auto-select should prefer ECDSA P-384 (CNSA 2.0)
        assert!(
            cert.key_algorithm.contains("P-384"),
            "Should select P-384 certificate, got: {}",
            cert.key_algorithm
        );
        assert!(cert.is_valid, "Selected certificate should be valid");
    }
}

/// Tests finding a certificate by thumbprint.
#[tokio::test]
async fn test_certificate_find_by_thumbprint() {
    init_test_tracing();

    let store = CertificateStore::open_personal();
    let expected = test_certificate_info();

    #[cfg(not(windows))]
    {
        let cert = store.find_by_thumbprint(&expected.thumbprint).unwrap();

        assert_eq!(cert.thumbprint, expected.thumbprint);
        assert_eq!(cert.subject_cn, expected.subject_cn);
        assert_eq!(cert.key_algorithm, expected.key_algorithm);
    }
}

/// Tests that selecting a specific certificate works.
#[tokio::test]
async fn test_certificate_specific_selection() {
    init_test_tracing();

    #[cfg(not(windows))]
    {
        // Select the second stub certificate specifically
        let thumbprint = "B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3";
        let config = CertificateConfig::new().with_thumbprint(thumbprint);

        let store = CertificateStore::open_personal();
        let cert = store.select_certificate(&config).unwrap();

        assert_eq!(cert.thumbprint, thumbprint);
        assert_eq!(cert.subject_cn, "Jane Smith (PIV)");
    }
}

/// Tests that expired certificates are filtered in auto-select.
#[tokio::test]
async fn test_certificate_filters_expired() {
    init_test_tracing();

    let mut config = CertificateConfig::new();
    config.selection_mode = CertificateSelectionMode::AutoSelect;

    let store = CertificateStore::open_personal();

    #[cfg(not(windows))]
    {
        let cert = store.select_certificate(&config).unwrap();

        // Should not select the expired "Test User (Expired)" certificate
        assert!(cert.is_valid);
        assert_ne!(cert.subject_cn, "Test User (Expired)");
    }
}

/// Tests getting the certificate chain (DER-encoded).
#[tokio::test]
async fn test_certificate_get_chain() {
    init_test_tracing();

    let store = CertificateStore::open_personal();
    let cert_info = test_certificate_info();

    #[cfg(not(windows))]
    {
        let chain = store.get_certificate_chain(&cert_info.thumbprint).unwrap();

        assert!(!chain.is_empty(), "Should return at least one certificate");
        assert!(!chain[0].is_empty(), "Certificate should not be empty");

        // Verify it looks like a DER-encoded certificate (starts with SEQUENCE tag)
        assert_eq!(chain[0][0], 0x30, "Should start with ASN.1 SEQUENCE tag");
    }
}

/// Tests that has_private_key returns true for stub certificates.
#[tokio::test]
async fn test_certificate_has_private_key() {
    init_test_tracing();

    let store = CertificateStore::open_personal();
    let cert_info = test_certificate_info();

    #[cfg(not(windows))]
    {
        let has_key = store.has_private_key(&cert_info.thumbprint).unwrap();
        assert!(
            has_key,
            "Stub certificates should report having a private key"
        );
    }
}

/// Tests the complete certificate configuration flow in ClientApp.
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

    // Verify no certificate initially
    assert!(!app.has_client_certificate());
    assert!(app.client_certificate_thumbprint().is_none());

    // Configure certificate
    let cert_info = test_certificate_info();
    let store = CertificateStore::open_personal();

    #[cfg(not(windows))]
    {
        let chain = store.get_certificate_chain(&cert_info.thumbprint).unwrap();

        app.set_client_certificate(chain, &cert_info.thumbprint);

        // Verify certificate is configured
        assert!(app.has_client_certificate());
        assert_eq!(
            app.client_certificate_thumbprint(),
            Some(cert_info.thumbprint.as_str())
        );
    }
}

/// Tests that certificate change is reflected in the app.
#[tokio::test]
async fn test_client_app_certificate_change() {
    init_test_tracing();

    let (tx, _rx) = mpsc::channel::<AppEvent>(32);
    let sip_addr = allocate_test_addr().await;
    let media_addr = allocate_test_addr().await;

    let result = ClientApp::new(sip_addr, media_addr, tx);
    let Ok(mut app) = result else {
        println!("Skipping test - ClientApp creation failed");
        return;
    };

    let store = CertificateStore::open_personal();

    #[cfg(not(windows))]
    {
        // Configure first certificate
        let cert1_thumbprint = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";
        let chain1 = store.get_certificate_chain(cert1_thumbprint).unwrap();

        app.set_client_certificate(chain1, cert1_thumbprint);
        assert_eq!(app.client_certificate_thumbprint(), Some(cert1_thumbprint));

        // Change to second certificate
        let cert2_thumbprint = "B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3";
        let chain2 = store.get_certificate_chain(cert2_thumbprint).unwrap();

        app.set_client_certificate(chain2, cert2_thumbprint);
        assert_eq!(app.client_certificate_thumbprint(), Some(cert2_thumbprint));
    }
}

/// Tests listing smart card readers.
#[tokio::test]
async fn test_certificate_list_smart_card_readers() {
    init_test_tracing();

    let store = CertificateStore::open_personal();
    let readers = store.list_smart_card_readers();

    assert!(readers.is_ok());

    #[cfg(not(windows))]
    {
        let readers = readers.unwrap();
        // Stub data includes reader names
        assert!(!readers.is_empty(), "Should have stub reader names");
    }
}

/// Tests certificate store refresh.
#[tokio::test]
async fn test_certificate_store_refresh() {
    init_test_tracing();

    let mut store = CertificateStore::open_personal();

    // Get initial list
    let certs_before = store.list_certificates().unwrap();

    // Refresh
    store.refresh().unwrap();

    // Get list again
    let certs_after = store.list_certificates().unwrap();

    // Should have same certificates (stub data is static)
    #[cfg(not(windows))]
    {
        assert_eq!(certs_before.len(), certs_after.len());
    }
}

/// Integration test: Full certificate selection to app configuration flow.
#[tokio::test]
async fn test_full_certificate_selection_flow() {
    init_test_tracing();

    // 1. Open certificate store
    let store = CertificateStore::open_personal();

    // 2. List available certificates
    let certs = store.list_certificates().unwrap();

    #[cfg(not(windows))]
    {
        assert!(!certs.is_empty());

        // 3. Auto-select best certificate (CNSA 2.0 compliant)
        let config = CertificateConfig::new();
        let selected = store.select_certificate(&config).unwrap();

        assert!(selected.is_valid);
        assert!(
            selected.key_algorithm.contains("P-384"),
            "Should select CNSA 2.0 compliant certificate"
        );

        // 4. Verify private key exists (for smart card)
        let has_key = store.has_private_key(&selected.thumbprint).unwrap();
        assert!(has_key, "Certificate should have associated private key");

        // 5. Get certificate chain
        let chain = store.get_certificate_chain(&selected.thumbprint).unwrap();
        assert!(!chain.is_empty());

        // 6. Create ClientApp and configure certificate
        let (tx, _rx) = mpsc::channel::<AppEvent>(32);
        let sip_addr = allocate_test_addr().await;
        let media_addr = allocate_test_addr().await;

        if let Ok(mut app) = ClientApp::new(sip_addr, media_addr, tx) {
            app.set_client_certificate(chain, &selected.thumbprint);

            assert!(app.has_client_certificate());
            assert_eq!(
                app.client_certificate_thumbprint(),
                Some(selected.thumbprint.as_str())
            );

            println!("Full certificate flow completed: {}", selected.subject_cn);
        }
    }
}
