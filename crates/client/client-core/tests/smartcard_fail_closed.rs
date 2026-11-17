//! SR-46: smart-card access fails closed in a normal build.
//!
//! An integration test links the library as built without `cfg(test)`,
//! the same view a release build has. In that view the certificate store
//! must never hand out the fabricated development certificates (their
//! thumbprints, subjects and reader names are listed below), never report
//! a key or a signature for them, and never accept a PIN where no
//! card-backed PIN check exists (every platform except Windows).
//!
//! Real certificates found on the test host (Keychain, a `YubiKey`) are
//! allowed in the list; only fabricated ones are not.
// NIST 800-53 Rev5: IA-2(2), IA-2(12) (not met: fails closed), IA-5(2), CM-7.
// POAM: POA&M-371
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

use client_core::{CertStoreError, CertificateStore, SignatureAlgorithm};
use client_types::{CertificateConfig, CertificateInfo, CertificateSelectionMode, SmartCardPin};

/// Thumbprints of the fabricated development certificates.
const STUB_THUMBPRINTS: [&str; 3] = [
    "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
    "B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3",
    "C3D4E5F6G7H8C3D4E5F6G7H8C3D4E5F6G7H8C3D4E5F6G7H8C3D4E5F6G7H8C3D4",
];

/// Subject CNs of the fabricated development certificates.
const STUB_SUBJECTS: [&str; 3] = ["John Doe (CAC)", "Jane Smith (PIV)", "Test User (Expired)"];

/// Reader names attached to the fabricated development certificates.
const STUB_READERS: [&str; 3] = [
    "SCM Microsystems Inc. SCR331 0",
    "Gemalto IDBridge CT30 0",
    "Virtual Smart Card",
];

fn is_fabricated(cert: &CertificateInfo) -> bool {
    STUB_THUMBPRINTS
        .iter()
        .any(|t| cert.thumbprint.eq_ignore_ascii_case(t))
        || STUB_SUBJECTS.contains(&cert.subject_cn.as_str())
}

#[test]
fn list_certificates_never_returns_fabricated_certificates() {
    let store = CertificateStore::open_personal();
    // An error or an empty list is fine; fabricated entries are not.
    if let Ok(certs) = store.list_certificates() {
        let fabricated: Vec<_> = certs.iter().filter(|c| is_fabricated(c)).collect();
        assert!(
            fabricated.is_empty(),
            "fabricated certificates listed: {:?}",
            fabricated
                .iter()
                .map(|c| (&c.thumbprint, &c.subject_cn))
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn list_certificates_filtered_never_returns_fabricated_certificates() {
    let store = CertificateStore::open_personal();
    let filter = client_core::CertificateFilterSettings::default();
    if let Ok(certs) = store.list_certificates_filtered(&filter) {
        assert!(
            !certs.iter().any(is_fabricated),
            "fabricated certificate passed the filter"
        );
    }
}

#[test]
fn refresh_does_not_bring_back_fabricated_certificates() {
    let mut store = CertificateStore::open_personal();
    let _ = store.refresh();
    if let Ok(certs) = store.list_certificates() {
        assert!(!certs.iter().any(is_fabricated));
    }
}

#[test]
fn selection_never_picks_a_fabricated_certificate() {
    let store = CertificateStore::open_personal();

    for mode in [
        CertificateSelectionMode::AutoSelect,
        CertificateSelectionMode::PromptUser,
    ] {
        let mut config = CertificateConfig::new();
        config.selection_mode = mode;
        if let Ok(cert) = store.select_certificate(&config) {
            assert!(
                !is_fabricated(&cert),
                "{mode:?} selected fabricated certificate {}",
                cert.subject_cn
            );
        }
    }

    for thumbprint in STUB_THUMBPRINTS {
        let config = CertificateConfig::new().with_thumbprint(thumbprint);
        let result = store.select_certificate(&config);
        assert!(
            result.is_err(),
            "specific selection of a fabricated thumbprint succeeded: {result:?}"
        );
    }
}

#[test]
fn fabricated_thumbprints_are_not_found() {
    let store = CertificateStore::open_personal();
    for thumbprint in STUB_THUMBPRINTS {
        let result = store.find_by_thumbprint(thumbprint);
        assert!(result.is_err(), "{thumbprint}: {result:?}");
    }
}

#[test]
fn fabricated_thumbprints_have_no_chain_key_or_signature() {
    let store = CertificateStore::open_personal();
    let pin = SmartCardPin::new("123456");

    for thumbprint in STUB_THUMBPRINTS {
        assert!(
            store.get_certificate_chain(thumbprint).is_err(),
            "{thumbprint}: a certificate chain was returned"
        );
        assert!(
            !matches!(store.has_private_key(thumbprint), Ok(true)),
            "{thumbprint}: reported a private key"
        );
        for algorithm in [
            SignatureAlgorithm::EcdsaSha384,
            SignatureAlgorithm::EcdsaSha256,
            SignatureAlgorithm::RsaSha384,
            SignatureAlgorithm::RsaSha256,
        ] {
            for pin in [None, Some(&pin)] {
                let result = store.sign_data(thumbprint, b"data", algorithm, pin);
                assert!(
                    result.is_err(),
                    "{thumbprint} {algorithm:?}: produced a signature"
                );
            }
        }
    }
}

#[test]
fn no_fabricated_reader_names() {
    let store = CertificateStore::open_personal();
    if let Ok(readers) = store.list_smart_card_readers() {
        for reader in &readers {
            assert!(
                !STUB_READERS.contains(&reader.as_str()),
                "fabricated reader listed: {reader}"
            );
        }
    }
}

/// No card-backed PIN check exists off Windows: every PIN, for every
/// thumbprint (fabricated, listed, unknown, empty), is refused with
/// `NotSupported`.
#[cfg(not(windows))]
#[test]
fn verify_pin_is_not_supported_off_windows() {
    let store = CertificateStore::open_personal();
    let listed: Vec<String> = store.list_certificates().map_or_else(
        |_| Vec::new(),
        |certs| certs.into_iter().map(|c| c.thumbprint).collect(),
    );

    let thumbprints: Vec<&str> = STUB_THUMBPRINTS
        .iter()
        .copied()
        .chain(["INVALID", "", "00"])
        .chain(listed.iter().map(String::as_str))
        .collect();

    for thumbprint in thumbprints {
        for pin in ["0000", "1234", "123456", "12345678", "123", ""] {
            let result = store.verify_pin(thumbprint, &SmartCardPin::new(pin));
            assert!(
                matches!(result, Err(CertStoreError::NotSupported)),
                "thumbprint {thumbprint:?}, PIN of length {}: {result:?}",
                pin.len()
            );
        }
    }
}

/// No card-backed signer exists off Windows: a certificate found on the
/// host (Keychain, `YubiKey`) must not get a made-up signature.
#[cfg(not(windows))]
#[test]
fn sign_data_never_fabricates_a_signature_off_windows() {
    let store = CertificateStore::open_personal();
    let pin = SmartCardPin::new("123456");
    let listed: Vec<String> = store.list_certificates().map_or_else(
        |_| Vec::new(),
        |certs| certs.into_iter().map(|c| c.thumbprint).collect(),
    );

    for thumbprint in listed.iter().map(String::as_str).chain(["INVALID", ""]) {
        let result = store.sign_data(
            thumbprint,
            b"data",
            SignatureAlgorithm::EcdsaSha384,
            Some(&pin),
        );
        assert!(
            result.is_err(),
            "{thumbprint:?}: a signature was produced without a card-backed signer"
        );
    }
}

/// CN carried by the fabricated DER certificate the development path
/// returns as a "chain".
const STUB_DER_CN: &[u8] = b"Test User (Stub CAC)";

/// A certificate found on the host must come back as its own DER, never
/// as the fabricated placeholder certificate.
#[test]
fn certificate_chain_is_never_the_fabricated_der() {
    let store = CertificateStore::open_personal();
    let listed = store.list_certificates().unwrap_or_default();

    for cert in &listed {
        if let Ok(chain) = store.get_certificate_chain(&cert.thumbprint) {
            for der in &chain {
                assert!(
                    !der.windows(STUB_DER_CN.len()).any(|w| w == STUB_DER_CN),
                    "{}: chain contains the fabricated certificate",
                    cert.thumbprint
                );
            }
        }
    }
}

/// Off Windows nothing can sign with a listed certificate's key, so the
/// store must not claim a usable private key for it.
#[cfg(not(windows))]
#[test]
fn has_private_key_is_not_claimed_off_windows() {
    let store = CertificateStore::open_personal();
    let listed = store.list_certificates().unwrap_or_default();

    for cert in &listed {
        let result = store.has_private_key(&cert.thumbprint);
        assert!(
            !matches!(result, Ok(true)),
            "{}: private key claimed without a card-backed signer",
            cert.thumbprint
        );
    }
}
