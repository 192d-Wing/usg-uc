//! Certificate store access for smart card authentication.
//!
//! Provides access to certificates from various sources:
//! - Windows: Windows Certificate Store (CryptoAPI)
//! - macOS: Keychain + PKCS#11 (for YubiKey, etc.)
//! - Linux: PKCS#11 (for YubiKey, etc.)
//!
//! CAC/PIV smart cards are supported on all platforms through
//! platform-native APIs or PKCS#11.

use crate::settings::CertificateFilterSettings;
use client_types::{CertificateConfig, CertificateInfo, CertificateSelectionMode, SmartCardPin};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Signature algorithm for signing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA with SHA-384 (CNSA 2.0 compliant).
    EcdsaSha384,
    /// ECDSA with SHA-256.
    EcdsaSha256,
    /// RSA with SHA-384 (CNSA 2.0 compliant).
    RsaSha384,
    /// RSA with SHA-256.
    RsaSha256,
}

/// Errors that can occur when accessing the certificate store.
#[derive(Debug, Error)]
pub enum CertStoreError {
    /// Certificate store not available.
    #[error("Certificate store not available: {0}")]
    StoreNotAvailable(String),

    /// No certificates found.
    #[error("No valid certificates found matching criteria")]
    NoCertificatesFound,

    /// Certificate not found.
    #[error("Certificate with thumbprint '{0}' not found")]
    CertificateNotFound(String),

    /// Certificate expired.
    #[error("Certificate has expired")]
    CertificateExpired,

    /// Smart card not present.
    #[error("Smart card not present - please insert your CAC/PIV card")]
    SmartCardNotPresent,

    /// PIN required.
    #[error("Smart card PIN required")]
    PinRequired,

    /// PIN incorrect.
    #[error("Smart card PIN incorrect")]
    PinIncorrect,

    /// Windows API error.
    #[error("Windows API error: {0}")]
    WindowsError(String),

    /// Not supported on this platform.
    #[error("Certificate store access not supported on this platform")]
    NotSupported,
}

/// Result type for certificate store operations.
pub type CertStoreResult<T> = Result<T, CertStoreError>;

/// Certificate store manager for accessing smart card certificates.
///
/// On Windows, this uses the Windows Certificate Store APIs.
/// On other platforms, it provides stub data for development.
pub struct CertificateStore {
    /// Store name (e.g., "MY" for personal certificates).
    store_name: String,
    /// Cached certificates (for stub mode or caching).
    #[allow(dead_code)]
    cached_certs: Vec<CertificateInfo>,
}

impl CertificateStore {
    /// Creates a new certificate store accessor.
    pub fn new(store_name: &str) -> Self {
        let cached_certs = if cfg!(windows) {
            // On Windows, start with empty cache - will be populated on first list
            Vec::new()
        } else {
            // On non-Windows, use stub data
            Self::create_stub_certificates()
        };

        Self {
            store_name: store_name.to_string(),
            cached_certs,
        }
    }

    /// Opens the default personal certificate store ("MY").
    pub fn open_personal() -> Self {
        Self::new("MY")
    }

    /// Lists all valid client authentication certificates.
    pub fn list_certificates(&self) -> CertStoreResult<Vec<CertificateInfo>> {
        info!("Listing certificates from store: {}", self.store_name);

        #[cfg(windows)]
        {
            self.list_certificates_windows()
        }

        #[cfg(not(windows))]
        {
            self.list_certificates_stub()
        }
    }

    /// Lists certificates filtered by the given settings.
    pub fn list_certificates_filtered(
        &self,
        filter: &CertificateFilterSettings,
    ) -> CertStoreResult<Vec<CertificateInfo>> {
        let all_certs = self.list_certificates()?;
        let total_count = all_certs.len();

        let filtered: Vec<CertificateInfo> = all_certs
            .into_iter()
            .filter(|cert| {
                // Filter by trusted issuers (if list is not empty)
                if !filter.trusted_issuers.is_empty() {
                    let issuer_matches = filter.trusted_issuers.iter().any(|trusted| {
                        // Match against issuer CN (case-insensitive)
                        cert.issuer_cn.to_uppercase().contains(&trusted.to_uppercase())
                    });
                    if !issuer_matches {
                        debug!(
                            "Filtering out cert '{}': issuer '{}' not in trusted list",
                            cert.subject_cn, cert.issuer_cn
                        );
                        return false;
                    }
                }

                // Filter by Smart Card Logon EKU
                if filter.require_smart_card_logon_eku && !cert.has_smart_card_logon {
                    debug!(
                        "Filtering out cert '{}': missing Smart Card Logon EKU",
                        cert.subject_cn
                    );
                    return false;
                }

                // Filter by Client Auth EKU
                if filter.require_client_auth_eku && !cert.has_client_auth {
                    debug!(
                        "Filtering out cert '{}': missing Client Auth EKU",
                        cert.subject_cn
                    );
                    return false;
                }

                // Filter expired certificates
                if filter.hide_expired && !cert.is_valid {
                    debug!("Filtering out cert '{}': expired", cert.subject_cn);
                    return false;
                }

                // Filter by smart card only
                if filter.smart_card_only && cert.reader_name.is_none() {
                    debug!(
                        "Filtering out cert '{}': not from smart card",
                        cert.subject_cn
                    );
                    return false;
                }

                // Filter out numeric-only CNs (Card Authentication certs like "33952358")
                if filter.exclude_numeric_cn {
                    let cn_is_numeric = cert.subject_cn.chars().all(|c| c.is_ascii_digit());
                    if cn_is_numeric {
                        debug!(
                            "Filtering out cert '{}': numeric-only CN (Card Authentication cert)",
                            cert.subject_cn
                        );
                        return false;
                    }
                }

                true
            })
            .collect();

        info!(
            "Certificate filter: {} total -> {} after filtering",
            total_count,
            filtered.len()
        );
        for cert in &filtered {
            info!(
                "  Kept: {} (issuer: {}, smart_card_logon: {}, client_auth: {})",
                cert.subject_cn, cert.issuer_cn, cert.has_smart_card_logon, cert.has_client_auth
            );
        }

        Ok(filtered)
    }

    /// Selects a certificate based on the configuration.
    pub fn select_certificate(
        &self,
        config: &CertificateConfig,
    ) -> CertStoreResult<CertificateInfo> {
        info!(
            "Selecting certificate with mode: {:?}",
            config.selection_mode
        );

        match config.selection_mode {
            CertificateSelectionMode::SpecificCertificate => {
                let thumbprint = config.certificate_thumbprint.as_ref().ok_or_else(|| {
                    CertStoreError::CertificateNotFound("No thumbprint specified".to_string())
                })?;

                self.find_by_thumbprint(thumbprint)
            }
            CertificateSelectionMode::AutoSelect => self.auto_select_certificate(config),
            CertificateSelectionMode::PromptUser => {
                // Return first certificate - GUI should handle actual selection
                let certs = self.list_certificates()?;
                certs
                    .into_iter()
                    .find(|c| c.is_valid)
                    .ok_or(CertStoreError::NoCertificatesFound)
            }
        }
    }

    /// Finds a certificate by thumbprint.
    pub fn find_by_thumbprint(&self, thumbprint: &str) -> CertStoreResult<CertificateInfo> {
        debug!("Finding certificate by thumbprint: {}", thumbprint);

        let certs = self.list_certificates()?;
        certs
            .into_iter()
            .find(|c| c.thumbprint.eq_ignore_ascii_case(thumbprint))
            .ok_or_else(|| CertStoreError::CertificateNotFound(thumbprint.to_string()))
    }

    /// Auto-selects the best available certificate for client authentication.
    fn auto_select_certificate(
        &self,
        config: &CertificateConfig,
    ) -> CertStoreResult<CertificateInfo> {
        let certs = self.list_certificates()?;

        // Filter by validity and key usage
        let valid_certs: Vec<_> = certs
            .into_iter()
            .filter(|c| {
                if !c.is_valid {
                    return false;
                }

                // Check key usage if specified
                if let Some(ref required_usage) = config.required_key_usage {
                    // Check if the key algorithm indicates a signing key
                    if required_usage == "Client Authentication" {
                        return c.key_algorithm.contains("ECDSA")
                            || c.key_algorithm.contains("RSA");
                    }
                }

                true
            })
            .collect();

        // Prefer ECDSA P-384 certificates (CNSA 2.0 preferred)
        valid_certs
            .iter()
            .find(|c| c.key_algorithm.contains("P-384"))
            .cloned()
            .or_else(|| valid_certs.into_iter().next())
            .ok_or(CertStoreError::NoCertificatesFound)
    }

    /// Creates stub certificates for development and testing.
    fn create_stub_certificates() -> Vec<CertificateInfo> {
        vec![
            CertificateInfo {
                thumbprint: "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2"
                    .to_string(),
                subject_cn: "John Doe (CAC)".to_string(),
                subject_dn: "CN=John Doe, OU=Users, O=US Government, C=US".to_string(),
                issuer_cn: "DOD ID CA-59".to_string(),
                issuer_dn: "CN=DOD ID CA-59, OU=PKI, OU=DoD, O=U.S. Government, C=US".to_string(),
                not_before: "2024-01-01".to_string(),
                not_after: "2027-01-01".to_string(),
                is_valid: true,
                reader_name: Some("SCM Microsystems Inc. SCR331 0".to_string()),
                key_algorithm: "ECDSA P-384".to_string(),
                extended_key_usage: vec![
                    "1.3.6.1.4.1.311.20.2.2".to_string(), // Smart Card Logon
                    "1.3.6.1.5.5.7.3.2".to_string(),      // Client Auth
                ],
                has_smart_card_logon: true,
                has_client_auth: true,
            },
            CertificateInfo {
                thumbprint: "B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3"
                    .to_string(),
                subject_cn: "Jane Smith (PIV)".to_string(),
                subject_dn: "CN=Jane Smith, OU=Contractors, O=Example Corp, C=US".to_string(),
                issuer_cn: "Federal Bridge CA G4".to_string(),
                issuer_dn: "CN=Federal Bridge CA G4, OU=FPKI, O=U.S. Government, C=US".to_string(),
                not_before: "2024-06-01".to_string(),
                not_after: "2026-06-01".to_string(),
                is_valid: true,
                reader_name: Some("Gemalto IDBridge CT30 0".to_string()),
                key_algorithm: "ECDSA P-384".to_string(),
                extended_key_usage: vec![
                    "1.3.6.1.4.1.311.20.2.2".to_string(), // Smart Card Logon
                    "1.3.6.1.5.5.7.3.2".to_string(),      // Client Auth
                ],
                has_smart_card_logon: true,
                has_client_auth: true,
            },
            CertificateInfo {
                thumbprint: "C3D4E5F6G7H8C3D4E5F6G7H8C3D4E5F6G7H8C3D4E5F6G7H8C3D4E5F6G7H8C3D4"
                    .to_string(),
                subject_cn: "Test User (Expired)".to_string(),
                subject_dn: "CN=Test User, OU=Testing, O=Test Org, C=US".to_string(),
                issuer_cn: "Test CA".to_string(),
                issuer_dn: "CN=Test CA, O=Test Org, C=US".to_string(),
                not_before: "2020-01-01".to_string(),
                not_after: "2022-01-01".to_string(),
                is_valid: false,
                reader_name: Some("Virtual Smart Card".to_string()),
                key_algorithm: "RSA 2048".to_string(),
                extended_key_usage: vec![],
                has_smart_card_logon: false,
                has_client_auth: false,
            },
        ]
    }

    /// Lists certificates on macOS from Keychain and PKCS#11.
    #[cfg(target_os = "macos")]
    fn list_certificates_stub(&self) -> CertStoreResult<Vec<CertificateInfo>> {
        use std::collections::HashSet;

        let mut certificates = Vec::new();
        let mut seen_thumbprints: HashSet<String> = HashSet::new();

        // List certificates from YubiKey first (preferred source for smart card certs)
        // YubiKey certs have more accurate metadata from yubico-piv-tool
        match self.list_certificates_yubikey() {
            Ok(yubikey_certs) => {
                info!("Found {} certificates from YubiKey", yubikey_certs.len());
                for cert in yubikey_certs {
                    seen_thumbprints.insert(cert.thumbprint.clone());
                    certificates.push(cert);
                }
            }
            Err(e) => {
                debug!("No YubiKey certificates found: {}", e);
            }
        }

        // List certificates from macOS Keychain (skip duplicates already found on YubiKey)
        match self.list_certificates_macos_keychain() {
            Ok(keychain_certs) => {
                let mut added = 0;
                let mut skipped = 0;
                for cert in keychain_certs {
                    if seen_thumbprints.contains(&cert.thumbprint) {
                        skipped += 1;
                        debug!(
                            "Skipping duplicate Keychain cert: {} ({})",
                            cert.subject_cn, cert.thumbprint
                        );
                    } else {
                        seen_thumbprints.insert(cert.thumbprint.clone());
                        certificates.push(cert);
                        added += 1;
                    }
                }
                info!(
                    "Found {} certificates in macOS Keychain ({} added, {} duplicates skipped)",
                    added + skipped,
                    added,
                    skipped
                );
            }
            Err(e) => {
                warn!("Failed to list Keychain certificates: {}", e);
            }
        }

        // PKCS#11 is disabled by default due to segfaults with libykcs11.dylib
        // Enable with ENABLE_PKCS11=1 environment variable if needed
        if std::env::var("ENABLE_PKCS11").is_ok() {
            match self.list_certificates_pkcs11() {
                Ok(pkcs11_certs) => {
                    let mut added = 0;
                    for cert in pkcs11_certs {
                        if !seen_thumbprints.contains(&cert.thumbprint) {
                            seen_thumbprints.insert(cert.thumbprint.clone());
                            certificates.push(cert);
                            added += 1;
                        }
                    }
                    info!("Found {} new certificates via PKCS#11", added);
                }
                Err(e) => {
                    warn!("Failed to list PKCS#11 certificates: {}", e);
                }
            }
        }

        if certificates.is_empty() {
            info!("No certificates found - returning stub data for testing");
            return Ok(Self::create_stub_certificates());
        }

        Ok(certificates)
    }

    /// Lists certificates on Linux from PKCS#11 only.
    #[cfg(all(not(windows), not(target_os = "macos")))]
    fn list_certificates_stub(&self) -> CertStoreResult<Vec<CertificateInfo>> {
        warn!("Certificate store using stub data - not on Windows or macOS");
        Ok(Self::create_stub_certificates())
    }

    /// Lists certificates from YubiKey using yubico-piv-tool (subprocess).
    /// This is more stable than PKCS#11 which can cause segfaults.
    #[cfg(target_os = "macos")]
    fn list_certificates_yubikey(&self) -> CertStoreResult<Vec<CertificateInfo>> {
        use std::process::Command;

        info!("Checking for YubiKey certificates via yubico-piv-tool");

        let mut certificates = Vec::new();

        // Try common paths for yubico-piv-tool since Tauri apps may not have full PATH
        let yubico_paths = [
            "yubico-piv-tool",
            "/opt/homebrew/bin/yubico-piv-tool",
            "/usr/local/bin/yubico-piv-tool",
        ];

        let mut output = None;
        for path in &yubico_paths {
            match Command::new(path).args(["-a", "status"]).output() {
                Ok(o) => {
                    debug!("Found yubico-piv-tool at: {}", path);
                    output = Some(o);
                    break;
                }
                Err(e) => {
                    debug!("yubico-piv-tool not found at {}: {}", path, e);
                }
            }
        }

        let output = output.ok_or_else(|| {
            CertStoreError::StoreNotAvailable(
                "yubico-piv-tool not found in PATH or common locations".to_string(),
            )
        })?;

        if !output.status.success() {
            return Err(CertStoreError::SmartCardNotPresent);
        }

        let status_output = String::from_utf8_lossy(&output.stdout);
        debug!("yubico-piv-tool status output:\n{}", status_output);

        // Parse the status output to find certificate slots
        // The output format is like:
        // Slot 9a:
        //     Subject DN:    CN=...
        //     Issuer DN:     CN=...
        //     Fingerprint:   abc123...
        //     Not Before:    ...
        //     Not After:     ...

        let mut current_slot: Option<String> = None;
        let mut current_subject: Option<String> = None;
        let mut current_issuer: Option<String> = None;
        let mut current_fingerprint: Option<String> = None;
        let mut current_not_before: Option<String> = None;
        let mut current_not_after: Option<String> = None;
        let mut current_algorithm: Option<String> = None;

        for line in status_output.lines() {
            let trimmed = line.trim();

            if trimmed.starts_with("Slot ") && trimmed.ends_with(':') {
                // Save previous slot if complete
                if let (Some(slot), Some(subject), Some(fingerprint)) =
                    (&current_slot, &current_subject, &current_fingerprint)
                {
                    // Determine EKU based on PIV slot
                    // Slot 9a = PIV Authentication (Smart Card Logon + Client Auth)
                    // Slot 9c = Digital Signature
                    // Slot 9d = Key Management
                    // Slot 9e = Card Authentication
                    let (has_smart_card_logon, has_client_auth) = match slot.as_str() {
                        "Slot 9a" => (true, true),   // PIV Authentication
                        "Slot 9e" => (true, true),   // Card Authentication
                        _ => (false, false),
                    };

                    let issuer_dn = current_issuer.clone().unwrap_or_default();
                    let cert_info = CertificateInfo {
                        thumbprint: fingerprint.to_uppercase().replace(' ', ""),
                        subject_cn: extract_cn_from_dn(subject),
                        subject_dn: subject.clone(),
                        issuer_cn: current_issuer
                            .as_ref()
                            .map(|i| extract_cn_from_dn(i))
                            .unwrap_or_else(|| "Unknown".to_string()),
                        issuer_dn,
                        not_before: current_not_before
                            .clone()
                            .unwrap_or_else(|| "Unknown".to_string()),
                        not_after: current_not_after
                            .clone()
                            .unwrap_or_else(|| "Unknown".to_string()),
                        is_valid: check_yubikey_validity(
                            current_not_before.as_deref(),
                            current_not_after.as_deref(),
                        ),
                        reader_name: Some(format!("YubiKey ({})", slot)),
                        key_algorithm: current_algorithm
                            .clone()
                            .unwrap_or_else(|| "Unknown".to_string()),
                        extended_key_usage: if has_smart_card_logon {
                            vec![
                                "1.3.6.1.4.1.311.20.2.2".to_string(), // Smart Card Logon
                                "1.3.6.1.5.5.7.3.2".to_string(),      // Client Auth
                            ]
                        } else {
                            vec![]
                        },
                        has_smart_card_logon,
                        has_client_auth,
                    };
                    debug!("Found YubiKey certificate: {} in {}", cert_info.subject_cn, slot);
                    certificates.push(cert_info);
                }

                // Start new slot
                current_slot = Some(trimmed.trim_end_matches(':').to_string());
                current_subject = None;
                current_issuer = None;
                current_fingerprint = None;
                current_not_before = None;
                current_not_after = None;
                current_algorithm = None;
            } else if trimmed.starts_with("Subject DN:") {
                current_subject = Some(trimmed.trim_start_matches("Subject DN:").trim().to_string());
            } else if trimmed.starts_with("Issuer DN:") {
                current_issuer = Some(trimmed.trim_start_matches("Issuer DN:").trim().to_string());
            } else if trimmed.starts_with("Fingerprint:") {
                current_fingerprint =
                    Some(trimmed.trim_start_matches("Fingerprint:").trim().to_string());
            } else if trimmed.starts_with("Not Before:") {
                current_not_before =
                    Some(trimmed.trim_start_matches("Not Before:").trim().to_string());
            } else if trimmed.starts_with("Not After:") {
                current_not_after = Some(trimmed.trim_start_matches("Not After:").trim().to_string());
            } else if trimmed.starts_with("Private Key Algorithm:") || trimmed.starts_with("Public Key Algorithm:") {
                if current_algorithm.is_none() {
                    let alg = trimmed.split(':').nth(1).map(|s| s.trim().to_string());
                    current_algorithm = alg;
                }
            }
        }

        // Don't forget the last slot
        if let (Some(slot), Some(subject), Some(fingerprint)) =
            (&current_slot, &current_subject, &current_fingerprint)
        {
            // Determine EKU based on PIV slot
            let (has_smart_card_logon, has_client_auth) = match slot.as_str() {
                "Slot 9a" => (true, true),   // PIV Authentication
                "Slot 9e" => (true, true),   // Card Authentication
                _ => (false, false),
            };

            let issuer_dn = current_issuer.clone().unwrap_or_default();
            let cert_info = CertificateInfo {
                thumbprint: fingerprint.to_uppercase().replace(' ', ""),
                subject_cn: extract_cn_from_dn(subject),
                subject_dn: subject.clone(),
                issuer_cn: current_issuer
                    .as_ref()
                    .map(|i| extract_cn_from_dn(i))
                    .unwrap_or_else(|| "Unknown".to_string()),
                issuer_dn,
                not_before: current_not_before
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
                not_after: current_not_after
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
                is_valid: check_yubikey_validity(
                    current_not_before.as_deref(),
                    current_not_after.as_deref(),
                ),
                reader_name: Some(format!("YubiKey ({})", slot)),
                key_algorithm: current_algorithm
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string()),
                extended_key_usage: if has_smart_card_logon {
                    vec![
                        "1.3.6.1.4.1.311.20.2.2".to_string(), // Smart Card Logon
                        "1.3.6.1.5.5.7.3.2".to_string(),      // Client Auth
                    ]
                } else {
                    vec![]
                },
                has_smart_card_logon,
                has_client_auth,
            };
            debug!("Found YubiKey certificate (last): {} in {}", cert_info.subject_cn, slot);
            certificates.push(cert_info);
        }

        info!("Found {} certificates on YubiKey", certificates.len());
        Ok(certificates)
    }

    /// Lists certificates from the macOS Keychain.
    #[cfg(target_os = "macos")]
    fn list_certificates_macos_keychain(&self) -> CertStoreResult<Vec<CertificateInfo>> {
        use security_framework::item::{ItemClass, ItemSearchOptions, Reference, SearchResult};

        info!("Listing certificates from macOS Keychain");

        let mut certificates = Vec::new();

        // Search for identities (certificates with private keys)
        let search_results = ItemSearchOptions::new()
            .class(ItemClass::identity())
            .load_refs(true)
            .limit(100)
            .search();

        match search_results {
            Ok(results) => {
                for result in results {
                    if let SearchResult::Ref(Reference::Identity(identity)) = result {
                        if let Ok(cert) = identity.certificate() {
                            let der_data = cert.to_der();
                            if let Some(cert_info) =
                                self.parse_der_certificate(&der_data, Some("macOS Keychain".to_string()), None)
                            {
                                // Update the subject_cn with the actual value from Security Framework
                                let mut cert_info = cert_info;
                                cert_info.subject_cn = cert.subject_summary();
                                cert_info.subject_dn = cert.subject_summary();
                                certificates.push(cert_info);
                            }
                        }
                    }
                }
                info!("Found {} identities in Keychain", certificates.len());
            }
            Err(e) => {
                debug!("Failed to search Keychain for identities: {}", e);
            }
        }

        Ok(certificates)
    }

    /// Lists certificates from PKCS#11 tokens (YubiKey, smart cards, etc.).
    #[cfg(target_os = "macos")]
    fn list_certificates_pkcs11(&self) -> CertStoreResult<Vec<CertificateInfo>> {
        info!("Listing certificates from PKCS#11 tokens");

        let mut certificates = Vec::new();

        // Common PKCS#11 library paths on macOS
        let pkcs11_paths = [
            // YubiKey
            "/usr/local/lib/libykcs11.dylib",
            "/opt/homebrew/lib/libykcs11.dylib",
            // OpenSC (general smart card support)
            "/usr/local/lib/opensc-pkcs11.so",
            "/opt/homebrew/lib/opensc-pkcs11.so",
            "/Library/OpenSC/lib/opensc-pkcs11.so",
            // macOS native PKCS#11 (if available)
            "/usr/lib/pkcs11/pkcs11-module.so",
        ];

        for path in &pkcs11_paths {
            if !std::path::Path::new(path).exists() {
                debug!("PKCS#11 library not found: {}", path);
                continue;
            }

            info!("Trying PKCS#11 library: {}", path);

            match self.list_certificates_from_pkcs11_module(path) {
                Ok(certs) => {
                    info!("Found {} certificates from {}", certs.len(), path);
                    certificates.extend(certs);
                }
                Err(e) => {
                    debug!("Failed to list certificates from {}: {}", path, e);
                }
            }
        }

        Ok(certificates)
    }

    /// Lists certificates from a specific PKCS#11 module.
    #[cfg(target_os = "macos")]
    fn list_certificates_from_pkcs11_module(
        &self,
        module_path: &str,
    ) -> CertStoreResult<Vec<CertificateInfo>> {
        use cryptoki::context::{CInitializeArgs, Pkcs11};
        use cryptoki::object::{Attribute, AttributeType, ObjectClass};
        use std::panic;

        let mut certificates = Vec::new();

        // Wrap PKCS#11 operations in catch_unwind to prevent crashes
        let module_path_owned = module_path.to_string();
        let result = panic::catch_unwind(|| {
            // Initialize PKCS#11 library
            let pkcs11 = Pkcs11::new(&module_path_owned).map_err(|e| {
                CertStoreError::StoreNotAvailable(format!("Failed to load PKCS#11 library: {}", e))
            })?;

            // Try to initialize - some libraries may already be initialized
            match pkcs11.initialize(CInitializeArgs::OsThreads) {
                Ok(_) => {}
                Err(cryptoki::error::Error::Pkcs11(cryptoki::error::RvError::CryptokiAlreadyInitialized, _)) => {
                    // Library already initialized, that's fine
                }
                Err(e) => {
                    return Err(CertStoreError::StoreNotAvailable(format!(
                        "Failed to initialize PKCS#11: {}",
                        e
                    )));
                }
            }

            Ok(pkcs11)
        });

        let pkcs11 = match result {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                return Err(CertStoreError::StoreNotAvailable(
                    "PKCS#11 library crashed during initialization".to_string(),
                ));
            }
        };

        // Get all slots with tokens
        let slots = pkcs11.get_slots_with_token().map_err(|e| {
            CertStoreError::StoreNotAvailable(format!("Failed to get PKCS#11 slots: {}", e))
        })?;

        for slot in slots {
            let slot_info = pkcs11.get_slot_info(slot).ok();
            let token_info = pkcs11.get_token_info(slot).ok();

            let reader_name = token_info
                .as_ref()
                .map(|ti| ti.label().trim().to_string())
                .or_else(|| slot_info.as_ref().map(|si| si.slot_description().trim().to_string()));

            debug!(
                "Found PKCS#11 slot: {:?} with token: {:?}",
                slot_info.as_ref().map(|s| s.slot_description()),
                token_info.as_ref().map(|t| t.label())
            );

            // Open a read-only session (no PIN needed for certificate listing)
            let session = match pkcs11.open_ro_session(slot) {
                Ok(s) => s,
                Err(e) => {
                    debug!("Failed to open session for slot: {}", e);
                    continue;
                }
            };

            // Find certificate objects
            let template = vec![Attribute::Class(ObjectClass::CERTIFICATE)];

            let cert_handles = match session.find_objects(&template) {
                Ok(handles) => handles,
                Err(e) => {
                    debug!("Failed to find certificates in slot: {}", e);
                    continue;
                }
            };

            for handle in cert_handles {
                // Get certificate attributes
                let attrs = match session.get_attributes(
                    handle,
                    &[
                        AttributeType::Value,
                        AttributeType::Label,
                    ],
                ) {
                    Ok(a) => a,
                    Err(e) => {
                        debug!("Failed to get certificate attributes: {}", e);
                        continue;
                    }
                };

                let mut cert_der: Option<Vec<u8>> = None;
                let mut label: Option<String> = None;

                for attr in attrs {
                    match attr {
                        Attribute::Value(v) => cert_der = Some(v),
                        Attribute::Label(l) => label = Some(String::from_utf8_lossy(&l).to_string()),
                        _ => {}
                    }
                }

                if let Some(der) = cert_der {
                    if let Some(cert_info) =
                        self.parse_der_certificate(&der, reader_name.clone(), label)
                    {
                        certificates.push(cert_info);
                    }
                }
            }
        }

        Ok(certificates)
    }

    /// Parses a DER-encoded certificate into CertificateInfo.
    #[cfg(target_os = "macos")]
    fn parse_der_certificate(
        &self,
        der: &[u8],
        reader_name: Option<String>,
        label: Option<String>,
    ) -> Option<CertificateInfo> {
        // Calculate SHA-1 thumbprint of DER certificate
        let thumbprint = {
            // Simple hash for now - in production use actual SHA-1
            let mut hash: u64 = 0xcbf29ce484222325; // FNV offset basis
            for byte in der {
                hash ^= *byte as u64;
                hash = hash.wrapping_mul(0x100000001b3); // FNV prime
            }
            format!("{:016X}{:016X}{:016X}{:016X}", hash, hash.rotate_left(16), hash.rotate_left(32), hash.rotate_left(48))
        };

        // Parse X.509 certificate structure (simplified)
        // A full implementation would use x509-parser or similar
        let (subject_cn, issuer_cn, not_before, not_after, key_algorithm) =
            parse_x509_basic_info(der);

        let subject_cn = label.unwrap_or(subject_cn);
        let subject_dn = subject_cn.clone();
        let issuer_dn = issuer_cn.clone();

        // Check if certificate is valid based on dates
        let is_valid = check_certificate_validity(&not_before, &not_after);

        // For Keychain certs, we assume they may have client auth EKU
        // In a full implementation, we'd parse the EKU extension from the DER
        Some(CertificateInfo {
            thumbprint,
            subject_cn,
            subject_dn,
            issuer_cn,
            issuer_dn,
            not_before,
            not_after,
            is_valid,
            reader_name,
            key_algorithm,
            extended_key_usage: vec![],  // Would need to parse from DER
            has_smart_card_logon: false, // Unknown without parsing EKU
            has_client_auth: false,      // Unknown without parsing EKU
        })
    }

    /// Lists certificates using Windows CryptoAPI.
    #[cfg(windows)]
    fn list_certificates_windows(&self) -> CertStoreResult<Vec<CertificateInfo>> {
        use windows::Win32::Security::Cryptography::{
            CERT_CONTEXT, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
            CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER, CertCloseStore,
            CertEnumCertificatesInStore, CertOpenStore, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        };

        info!(
            "Enumerating certificates from Windows Certificate Store: {}",
            self.store_name
        );

        let mut certificates = Vec::new();

        // Convert store name to wide string
        let store_name_wide: Vec<u16> = self
            .store_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        #[allow(unsafe_code)]
        #[allow(unsafe_code)]
        unsafe {
            // Open the certificate store
            let store = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0),
                None,
                CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER),
                Some(store_name_wide.as_ptr().cast()),
            );

            let store = store.map_err(|e| {
                CertStoreError::StoreNotAvailable(format!(
                    "Failed to open certificate store '{}': {}",
                    self.store_name, e
                ))
            })?;

            // Enumerate certificates
            let mut cert_context: *const CERT_CONTEXT = std::ptr::null();

            loop {
                cert_context = CertEnumCertificatesInStore(store, Some(cert_context));

                if cert_context.is_null() {
                    break;
                }

                // Parse the certificate
                if let Some(cert_info) = self.parse_certificate_context(cert_context) {
                    certificates.push(cert_info);
                }
            }

            // Close the store
            let _ = CertCloseStore(Some(store), 0);
        }

        debug!("Found {} certificates in store", certificates.len());
        Ok(certificates)
    }

    /// Parses a certificate context into `CertificateInfo`.
    #[cfg(windows)]
    fn parse_certificate_context(
        &self,
        cert_context: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
    ) -> Option<CertificateInfo> {
        #[allow(unsafe_code)]
        unsafe {
            let cert = &*cert_context;
            let cert_info_ptr = cert.pCertInfo;
            if cert_info_ptr.is_null() {
                return None;
            }

            // Get subject CN
            let subject_cn = self.get_cert_name_string(cert_context, true);

            // Get issuer CN
            let issuer_cn = self.get_cert_name_string(cert_context, false);

            // Get validity dates
            let cert_info = &*cert_info_ptr;
            let not_before = filetime_to_string(&cert_info.NotBefore);
            let not_after = filetime_to_string(&cert_info.NotAfter);

            // Check if certificate is currently valid
            let is_valid = self.check_certificate_validity(cert_context);

            // Get thumbprint (SHA-1 hash of certificate)
            let thumbprint = self.get_certificate_thumbprint(cert_context);

            // Get key algorithm
            let key_algorithm = self.get_key_algorithm(cert_context);

            // Get smart card reader name if available
            let reader_name = self.get_reader_name(cert_context);

            // Get full subject DN
            let subject_dn = self.get_cert_dn_string(cert_context, true);

            Some(CertificateInfo {
                thumbprint,
                subject_cn,
                subject_dn,
                issuer_cn,
                not_before,
                not_after,
                is_valid,
                reader_name,
                key_algorithm,
            })
        }
    }

    /// Gets the certificate name string (subject or issuer CN).
    #[cfg(windows)]
    fn get_cert_name_string(
        &self,
        cert_context: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
        is_subject: bool,
    ) -> String {
        use windows::Win32::Security::Cryptography::{
            CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW,
        };

        #[allow(unsafe_code)]
        unsafe {
            let mut buffer = vec![0u16; 256];
            let name_type = if is_subject { 0 } else { 1 }; // Subject or Issuer

            let len = CertGetNameStringW(
                cert_context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                name_type,
                None,
                Some(&mut buffer),
            );

            if len > 1 {
                String::from_utf16_lossy(&buffer[..len as usize - 1])
            } else {
                String::from("Unknown")
            }
        }
    }

    /// Gets the full DN string.
    #[cfg(windows)]
    fn get_cert_dn_string(
        &self,
        cert_context: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
        is_subject: bool,
    ) -> String {
        use windows::Win32::Security::Cryptography::{
            CERT_X500_NAME_STR, CertNameToStrW, X509_ASN_ENCODING,
        };

        #[allow(unsafe_code)]
        unsafe {
            let cert = &*cert_context;
            let cert_info_ptr = cert.pCertInfo;
            if cert_info_ptr.is_null() {
                return String::from("Unknown");
            }
            let cert_info = &*cert_info_ptr;

            let name_blob = if is_subject {
                &cert_info.Subject
            } else {
                &cert_info.Issuer
            };

            let mut buffer = vec![0u16; 512];

            let len = CertNameToStrW(
                X509_ASN_ENCODING,
                name_blob,
                CERT_X500_NAME_STR,
                Some(&mut buffer),
            );

            if len > 1 {
                String::from_utf16_lossy(&buffer[..len as usize - 1])
            } else {
                String::from("Unknown")
            }
        }
    }

    /// Gets the certificate thumbprint (SHA-1 hash).
    #[cfg(windows)]
    fn get_certificate_thumbprint(
        &self,
        cert_context: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
    ) -> String {
        use windows::Win32::Security::Cryptography::{
            CERT_HASH_PROP_ID, CertGetCertificateContextProperty,
        };

        #[allow(unsafe_code)]
        unsafe {
            let mut hash = vec![0u8; 20]; // SHA-1 is 20 bytes
            let mut hash_size = hash.len() as u32;

            let result = CertGetCertificateContextProperty(
                cert_context,
                CERT_HASH_PROP_ID,
                Some(hash.as_mut_ptr().cast()),
                &mut hash_size,
            );

            if result.is_ok() {
                hash.iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join("")
            } else {
                String::from("Unknown")
            }
        }
    }

    /// Gets the key algorithm description.
    #[cfg(windows)]
    fn get_key_algorithm(
        &self,
        cert_context: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
    ) -> String {
        #[allow(unsafe_code)]
        unsafe {
            let cert = &*cert_context;
            let cert_info_ptr = cert.pCertInfo;
            if cert_info_ptr.is_null() {
                return String::from("Unknown");
            }
            let cert_info = &*cert_info_ptr;

            // Get the public key algorithm OID
            let oid_ptr = cert_info.SubjectPublicKeyInfo.Algorithm.pszObjId.0;
            if oid_ptr.is_null() {
                return String::from("Unknown");
            }

            let alg_oid = std::ffi::CStr::from_ptr(oid_ptr as *const i8)
                .to_string_lossy()
                .to_string();

            // Map common OIDs to friendly names
            match alg_oid.as_str() {
                "1.2.840.10045.2.1" => {
                    // EC public key - check curve
                    let params = &cert_info.SubjectPublicKeyInfo.Algorithm.Parameters;
                    if params.cbData > 0 && !params.pbData.is_null() {
                        // Parse curve OID from parameters
                        let curve =
                            self.parse_ec_curve_from_params(params.pbData, params.cbData as usize);
                        format!("ECDSA {curve}")
                    } else {
                        String::from("ECDSA")
                    }
                }
                "1.2.840.113549.1.1.1" => {
                    // RSA - get approximate key size
                    let key_bits = cert_info.SubjectPublicKeyInfo.PublicKey.cbData * 8;
                    format!("RSA {key_bits}")
                }
                _ => alg_oid,
            }
        }
    }

    /// Parses EC curve from algorithm parameters.
    #[cfg(windows)]
    fn parse_ec_curve_from_params(&self, data: *const u8, len: usize) -> String {
        if data.is_null() || len == 0 {
            return String::from("Unknown");
        }

        #[allow(unsafe_code)]
        unsafe {
            // The parameters typically contain the curve OID
            // Common curves:
            // P-256: 1.2.840.10045.3.1.7
            // P-384: 1.3.132.0.34
            // P-521: 1.3.132.0.35

            let params = std::slice::from_raw_parts(data, len);

            // Simple OID detection (actual parsing would need ASN.1 decoder)
            if params.len() >= 7 {
                // Check for P-384 OID (1.3.132.0.34 = 06 05 2B 81 04 00 22)
                if params.contains(&0x22) && params.contains(&0x04) {
                    return String::from("P-384");
                }
                // Check for P-521 OID (1.3.132.0.35 = 06 05 2B 81 04 00 23)
                if params.contains(&0x23) && params.contains(&0x04) {
                    return String::from("P-521");
                }
                // Check for P-256 OID (1.2.840.10045.3.1.7)
                if params.contains(&0x07) && params.contains(&0x03) {
                    return String::from("P-256");
                }
            }

            String::from("Unknown")
        }
    }

    /// Gets the smart card reader name if the certificate is on a smart card.
    #[cfg(windows)]
    fn get_reader_name(
        &self,
        cert_context: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
    ) -> Option<String> {
        use windows::Win32::Security::Cryptography::{
            CERT_KEY_PROV_INFO_PROP_ID, CRYPT_KEY_PROV_INFO, CertGetCertificateContextProperty,
        };

        #[allow(unsafe_code)]
        unsafe {
            // First, get the size needed
            let mut prov_info_size = 0u32;
            let result = CertGetCertificateContextProperty(
                cert_context,
                CERT_KEY_PROV_INFO_PROP_ID,
                None,
                &mut prov_info_size,
            );

            if result.is_err() || prov_info_size == 0 {
                return None;
            }

            // Allocate buffer and get the property
            let mut prov_info_buf = vec![0u8; prov_info_size as usize];
            let result = CertGetCertificateContextProperty(
                cert_context,
                CERT_KEY_PROV_INFO_PROP_ID,
                Some(prov_info_buf.as_mut_ptr().cast()),
                &mut prov_info_size,
            );

            if result.is_err() {
                return None;
            }

            let prov_info = &*(prov_info_buf.as_ptr().cast::<CRYPT_KEY_PROV_INFO>());

            // Get container name which often contains reader info
            if !prov_info.pwszContainerName.is_null() {
                let container = widestring_to_string(prov_info.pwszContainerName.0);
                // Smart card containers often include reader name
                if container.contains("\\\\") {
                    // Format: \\.\<reader>\<container>
                    if let Some(reader_end) = container.rfind('\\') {
                        let reader = &container[4..reader_end];
                        return Some(reader.to_string());
                    }
                }
            }

            // Check provider name for smart card indication
            if !prov_info.pwszProvName.is_null() {
                let provider = widestring_to_string(prov_info.pwszProvName.0);
                if provider.contains("Smart Card") || provider.contains("Minidriver") {
                    return Some(provider);
                }
            }

            None
        }
    }

    /// Checks if the certificate is currently valid (not expired, not yet valid).
    #[cfg(windows)]
    fn check_certificate_validity(
        &self,
        cert_context: *const windows::Win32::Security::Cryptography::CERT_CONTEXT,
    ) -> bool {
        use windows::Win32::Security::Cryptography::CertVerifyTimeValidity;

        #[allow(unsafe_code)]
        unsafe {
            let cert = &*cert_context;
            // NULL for current time
            let result = CertVerifyTimeValidity(None, cert.pCertInfo);
            result == 0 // 0 means valid, -1 means not yet valid, 1 means expired
        }
    }

    /// Refreshes the certificate list from the store.
    pub fn refresh(&mut self) -> CertStoreResult<()> {
        info!("Refreshing certificate list");

        #[cfg(windows)]
        {
            // Re-enumerate certificates - the list_certificates_windows
            // function already returns fresh data
            let _ = self.list_certificates_windows()?;
        }

        Ok(())
    }

    /// Returns the store name.
    pub fn store_name(&self) -> &str {
        &self.store_name
    }

    /// Lists unique smart card reader names from certificates.
    ///
    /// Returns a list of reader names where certificates are stored on smart cards.
    pub fn list_smart_card_readers(&self) -> CertStoreResult<Vec<String>> {
        let certs = self.list_certificates()?;

        let mut readers: Vec<String> = certs.iter().filter_map(|c| c.reader_name.clone()).collect();

        // Remove duplicates while preserving order
        readers.sort();
        readers.dedup();

        debug!(count = readers.len(), "Found smart card readers");
        Ok(readers)
    }

    /// Gets the DER-encoded certificate chain for a certificate.
    ///
    /// Returns the certificate and its issuer chain as DER-encoded bytes.
    /// The first element is the end-entity certificate, followed by any
    /// intermediate certificates.
    pub fn get_certificate_chain(&self, thumbprint: &str) -> CertStoreResult<Vec<Vec<u8>>> {
        info!(thumbprint = %thumbprint, "Getting certificate chain");

        #[cfg(windows)]
        {
            self.get_certificate_chain_windows(thumbprint)
        }

        #[cfg(not(windows))]
        {
            // Return stub certificate for non-Windows
            self.get_certificate_chain_stub(thumbprint)
        }
    }

    /// Gets the DER-encoded certificate chain on Windows.
    #[cfg(windows)]
    fn get_certificate_chain_windows(&self, thumbprint: &str) -> CertStoreResult<Vec<Vec<u8>>> {
        use windows::Win32::Security::Cryptography::{
            CERT_CONTEXT, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
            CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER, CertCloseStore,
            CertEnumCertificatesInStore, CertOpenStore, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        };

        let store_name_wide: Vec<u16> = self
            .store_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        #[allow(unsafe_code)]
        unsafe {
            let store = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0),
                None,
                CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER),
                Some(store_name_wide.as_ptr().cast()),
            )
            .map_err(|e| CertStoreError::StoreNotAvailable(e.to_string()))?;

            let mut cert_context: *const CERT_CONTEXT = std::ptr::null();
            let mut found_cert: Option<*const CERT_CONTEXT> = None;

            // Find the certificate by thumbprint
            loop {
                cert_context = CertEnumCertificatesInStore(store, Some(cert_context));
                if cert_context.is_null() {
                    break;
                }

                let cert_thumbprint = self.get_certificate_thumbprint(cert_context);
                if cert_thumbprint.eq_ignore_ascii_case(thumbprint) {
                    found_cert = Some(cert_context);
                    break;
                }
            }

            let cert_ctx = found_cert.ok_or_else(|| {
                let _ = CertCloseStore(Some(store), 0);
                CertStoreError::CertificateNotFound(thumbprint.to_string())
            })?;

            // Get the DER-encoded certificate
            let cert = &*cert_ctx;
            let cert_der =
                std::slice::from_raw_parts(cert.pbCertEncoded, cert.cbCertEncoded as usize)
                    .to_vec();

            let _ = CertCloseStore(Some(store), 0);

            // Return just the end-entity cert for now
            // A full implementation would build the chain using CertGetCertificateChain
            Ok(vec![cert_der])
        }
    }

    /// Gets a stub certificate chain for non-Windows platforms.
    #[cfg(not(windows))]
    fn get_certificate_chain_stub(&self, thumbprint: &str) -> CertStoreResult<Vec<Vec<u8>>> {
        // Verify the certificate exists in our stub data
        let _ = self.find_by_thumbprint(thumbprint)?;

        // Return a self-signed test certificate (DER-encoded)
        // This is a minimal X.509 v3 certificate for testing
        // In production, this would come from the actual certificate store
        let stub_cert = create_stub_der_certificate();
        Ok(vec![stub_cert])
    }

    /// Checks if a certificate has an associated private key.
    ///
    /// For smart card certificates, this verifies the card is present.
    pub fn has_private_key(&self, thumbprint: &str) -> CertStoreResult<bool> {
        #[cfg(windows)]
        {
            self.has_private_key_windows(thumbprint)
        }

        #[cfg(not(windows))]
        {
            // Stub always has a "private key"
            let _ = self.find_by_thumbprint(thumbprint)?;
            Ok(true)
        }
    }

    /// Checks for private key on Windows.
    #[cfg(windows)]
    fn has_private_key_windows(&self, thumbprint: &str) -> CertStoreResult<bool> {
        use windows::Win32::Security::Cryptography::{
            CERT_CONTEXT, CERT_KEY_PROV_INFO_PROP_ID, CERT_OPEN_STORE_FLAGS,
            CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
            CertCloseStore, CertEnumCertificatesInStore, CertGetCertificateContextProperty,
            CertOpenStore, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        };

        let store_name_wide: Vec<u16> = self
            .store_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        #[allow(unsafe_code)]
        unsafe {
            let store = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0),
                None,
                CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER),
                Some(store_name_wide.as_ptr().cast()),
            )
            .map_err(|e| CertStoreError::StoreNotAvailable(e.to_string()))?;

            let mut cert_context: *const CERT_CONTEXT = std::ptr::null();

            loop {
                cert_context = CertEnumCertificatesInStore(store, Some(cert_context));
                if cert_context.is_null() {
                    break;
                }

                let cert_thumbprint = self.get_certificate_thumbprint(cert_context);
                if cert_thumbprint.eq_ignore_ascii_case(thumbprint) {
                    // Check if it has a private key by querying CERT_KEY_PROV_INFO_PROP_ID
                    let mut size: u32 = 0;
                    let has_key = CertGetCertificateContextProperty(
                        cert_context,
                        CERT_KEY_PROV_INFO_PROP_ID,
                        None,
                        &mut size,
                    )
                    .is_ok();

                    let _ = CertCloseStore(Some(store), 0);
                    return Ok(has_key && size > 0);
                }
            }

            let _ = CertCloseStore(Some(store), 0);
            Err(CertStoreError::CertificateNotFound(thumbprint.to_string()))
        }
    }

    /// Signs data using a certificate's private key with PIN authentication.
    ///
    /// This method acquires the private key from the smart card using the provided PIN,
    /// then signs the data using the specified algorithm.
    ///
    /// # Arguments
    /// * `thumbprint` - Certificate thumbprint to use for signing
    /// * `data` - Data to sign (typically a hash)
    /// * `algorithm` - Signature algorithm to use
    /// * `pin` - Smart card PIN for key access
    ///
    /// # Returns
    /// The digital signature bytes, or an error if signing fails.
    pub fn sign_data(
        &self,
        thumbprint: &str,
        data: &[u8],
        algorithm: SignatureAlgorithm,
        pin: Option<&SmartCardPin>,
    ) -> CertStoreResult<Vec<u8>> {
        info!(thumbprint = %thumbprint, algorithm = ?algorithm, "Signing data with certificate");

        #[cfg(windows)]
        {
            self.sign_data_windows(thumbprint, data, algorithm, pin)
        }

        #[cfg(not(windows))]
        {
            self.sign_data_stub(thumbprint, data, algorithm, pin)
        }
    }

    /// Signs data using Windows CryptoNG (NCrypt) APIs.
    #[cfg(windows)]
    fn sign_data_windows(
        &self,
        thumbprint: &str,
        data: &[u8],
        algorithm: SignatureAlgorithm,
        pin: Option<&SmartCardPin>,
    ) -> CertStoreResult<Vec<u8>> {
        use windows::Win32::Security::Cryptography::{
            BCRYPT_PAD_PKCS1, CERT_CONTEXT, CERT_OPEN_STORE_FLAGS,
            CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER,
            CRYPT_ACQUIRE_SILENT_FLAG, CertCloseStore, CertEnumCertificatesInStore, CertOpenStore,
            CryptAcquireCertificatePrivateKey, NCRYPT_KEY_HANDLE, NCRYPT_SILENT_FLAG,
            NCryptFreeObject, NCryptSignHash, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        };
        use windows::core::PCWSTR;

        let store_name_wide: Vec<u16> = self
            .store_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        #[allow(unsafe_code)]
        unsafe {
            // Open certificate store
            let store = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0),
                None,
                CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER),
                Some(store_name_wide.as_ptr().cast()),
            )
            .map_err(|e| CertStoreError::StoreNotAvailable(e.to_string()))?;

            // Find certificate by thumbprint
            let mut cert_context: *const CERT_CONTEXT = std::ptr::null();
            let mut found_cert: Option<*const CERT_CONTEXT> = None;

            loop {
                cert_context = CertEnumCertificatesInStore(store, Some(cert_context));
                if cert_context.is_null() {
                    break;
                }

                let cert_thumbprint = self.get_certificate_thumbprint(cert_context);
                if cert_thumbprint.eq_ignore_ascii_case(thumbprint) {
                    found_cert = Some(cert_context);
                    break;
                }
            }

            let cert_ctx = found_cert.ok_or_else(|| {
                let _ = CertCloseStore(Some(store), 0);
                CertStoreError::CertificateNotFound(thumbprint.to_string())
            })?;

            // Acquire private key handle
            let mut key_handle = NCRYPT_KEY_HANDLE::default();
            let mut key_spec = 0u32;
            let mut caller_free_key = false;

            // Set flags - try silent first, which may trigger PIN dialog
            let acquire_flags = if pin.is_some() {
                // If we have a PIN, we'll set it after acquiring
                CRYPT_ACQUIRE_SILENT_FLAG
            } else {
                // No PIN provided - allow Windows to show PIN dialog
                windows::Win32::Security::Cryptography::CRYPT_ACQUIRE_FLAGS(0u32)
            };

            let result = CryptAcquireCertificatePrivateKey(
                cert_ctx,
                acquire_flags,
                None,
                &mut key_handle.0 as *mut usize as *mut _,
                Some(&mut key_spec as *mut u32 as *mut _),
                Some(&mut caller_free_key as *mut bool as *mut _),
            );

            if result.is_err() {
                let _ = CertCloseStore(Some(store), 0);
                let err = std::io::Error::last_os_error();
                // Check for PIN-related errors
                let error_code = err.raw_os_error().unwrap_or(0) as u32;
                // NTE_USER_CANCELLED (0x80090036) or SCARD_W_CANCELLED_BY_USER (0x8010006E)
                if error_code == 0x80090036 || error_code == 0x8010006E {
                    return Err(CertStoreError::PinRequired);
                }
                // SCARD_W_WRONG_CHV (0x8010006B) - wrong PIN
                if error_code == 0x8010006B {
                    return Err(CertStoreError::PinIncorrect);
                }
                return Err(CertStoreError::WindowsError(format!(
                    "Failed to acquire private key: {}",
                    err
                )));
            }

            // If PIN was provided, set it on the key (for NCrypt keys)
            if let Some(pin_value) = pin {
                // Convert PIN to wide string
                let pin_wide: Vec<u16> = pin_value
                    .as_str()
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();

                // NCryptSetProperty for PIN
                use windows::Win32::Security::Cryptography::NCryptSetProperty;
                let ncrypt_pin_property: Vec<u16> = "SmartCardPin"
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();

                let pin_result = NCryptSetProperty(
                    key_handle.into(),
                    PCWSTR::from_raw(ncrypt_pin_property.as_ptr()),
                    std::slice::from_raw_parts(
                        pin_wide.as_ptr() as *const u8,
                        pin_wide.len() * 2,
                    ),
                    NCRYPT_SILENT_FLAG,
                );

                if pin_result.is_err() {
                    if caller_free_key {
                        let _ = NCryptFreeObject(key_handle.into());
                    }
                    let _ = CertCloseStore(Some(store), 0);
                    return Err(CertStoreError::PinIncorrect);
                }
            }

            // Determine padding and algorithm info based on algorithm
            let (padding_info, padding_flags) = match algorithm {
                SignatureAlgorithm::EcdsaSha384 | SignatureAlgorithm::EcdsaSha256 => {
                    // ECDSA doesn't use padding
                    (std::ptr::null(), 0u32)
                }
                SignatureAlgorithm::RsaSha384 | SignatureAlgorithm::RsaSha256 => {
                    // RSA uses PKCS#1 padding
                    (std::ptr::null(), BCRYPT_PAD_PKCS1.0)
                }
            };

            // Get signature size
            let mut signature_size = 0u32;
            let size_result = NCryptSignHash(
                key_handle,
                Some(padding_info as *const _),
                data,
                None,
                &mut signature_size,
                windows::Win32::Security::Cryptography::NCRYPT_FLAGS(padding_flags),
            );

            if size_result.is_err() {
                if caller_free_key {
                    let _ = NCryptFreeObject(key_handle.into());
                }
                let _ = CertCloseStore(Some(store), 0);
                return Err(CertStoreError::WindowsError(
                    "Failed to get signature size".to_string(),
                ));
            }

            // Allocate signature buffer and sign
            let mut signature = vec![0u8; signature_size as usize];
            let sign_result = NCryptSignHash(
                key_handle,
                Some(padding_info as *const _),
                data,
                Some(&mut signature),
                &mut signature_size,
                windows::Win32::Security::Cryptography::NCRYPT_FLAGS(padding_flags),
            );

            // Clean up
            if caller_free_key {
                let _ = NCryptFreeObject(key_handle.into());
            }
            let _ = CertCloseStore(Some(store), 0);

            if sign_result.is_err() {
                let err = std::io::Error::last_os_error();
                let error_code = err.raw_os_error().unwrap_or(0) as u32;
                // Check for PIN-related errors
                if error_code == 0x8010006B {
                    return Err(CertStoreError::PinIncorrect);
                }
                return Err(CertStoreError::WindowsError(format!(
                    "Failed to sign data: {}",
                    err
                )));
            }

            signature.truncate(signature_size as usize);
            info!(signature_len = signature.len(), "Data signed successfully");
            Ok(signature)
        }
    }

    /// Stub signing implementation for non-Windows platforms.
    #[cfg(not(windows))]
    fn sign_data_stub(
        &self,
        thumbprint: &str,
        data: &[u8],
        algorithm: SignatureAlgorithm,
        _pin: Option<&SmartCardPin>,
    ) -> CertStoreResult<Vec<u8>> {
        // Verify certificate exists
        let _ = self.find_by_thumbprint(thumbprint)?;

        warn!("Using stub signing - not for production use");

        // Return a fake signature based on algorithm
        let sig_size = match algorithm {
            SignatureAlgorithm::EcdsaSha384 => 96, // P-384 signature
            SignatureAlgorithm::EcdsaSha256 => 64, // P-256 signature
            SignatureAlgorithm::RsaSha384 | SignatureAlgorithm::RsaSha256 => 256, // RSA 2048
        };

        // Create deterministic fake signature from data hash
        let mut signature = vec![0u8; sig_size];
        for (i, byte) in data.iter().cycle().take(sig_size).enumerate() {
            signature[i] = byte.wrapping_add(i as u8);
        }

        Ok(signature)
    }

    /// Verifies that a certificate's private key is accessible with the given PIN.
    ///
    /// This attempts to acquire the private key without actually signing anything,
    /// which validates that the PIN is correct and the smart card is present.
    ///
    /// # Arguments
    /// * `thumbprint` - Certificate thumbprint
    /// * `pin` - Smart card PIN to verify
    ///
    /// # Returns
    /// Ok(true) if the PIN is correct and key is accessible,
    /// Err(PinIncorrect) if the PIN is wrong,
    /// Err(SmartCardNotPresent) if the card is not inserted.
    pub fn verify_pin(&self, thumbprint: &str, pin: &SmartCardPin) -> CertStoreResult<bool> {
        info!(thumbprint = %thumbprint, "Verifying smart card PIN");

        #[cfg(windows)]
        {
            self.verify_pin_windows(thumbprint, pin)
        }

        #[cfg(not(windows))]
        {
            self.verify_pin_stub(thumbprint, pin)
        }
    }

    /// Verifies PIN on Windows using CryptoNG.
    #[cfg(windows)]
    fn verify_pin_windows(&self, thumbprint: &str, pin: &SmartCardPin) -> CertStoreResult<bool> {
        use windows::Win32::Security::Cryptography::{
            CERT_CONTEXT, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
            CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_CURRENT_USER, CRYPT_ACQUIRE_SILENT_FLAG,
            CertCloseStore, CertEnumCertificatesInStore, CertOpenStore,
            CryptAcquireCertificatePrivateKey, NCRYPT_KEY_HANDLE, NCRYPT_SILENT_FLAG,
            NCryptFreeObject, NCryptSetProperty, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
        };
        use windows::core::PCWSTR;

        let store_name_wide: Vec<u16> = self
            .store_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        #[allow(unsafe_code)]
        unsafe {
            let store = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0),
                None,
                CERT_OPEN_STORE_FLAGS(CERT_SYSTEM_STORE_CURRENT_USER),
                Some(store_name_wide.as_ptr().cast()),
            )
            .map_err(|e| CertStoreError::StoreNotAvailable(e.to_string()))?;

            let mut cert_context: *const CERT_CONTEXT = std::ptr::null();
            let mut found_cert: Option<*const CERT_CONTEXT> = None;

            loop {
                cert_context = CertEnumCertificatesInStore(store, Some(cert_context));
                if cert_context.is_null() {
                    break;
                }

                let cert_thumbprint = self.get_certificate_thumbprint(cert_context);
                if cert_thumbprint.eq_ignore_ascii_case(thumbprint) {
                    found_cert = Some(cert_context);
                    break;
                }
            }

            let cert_ctx = found_cert.ok_or_else(|| {
                let _ = CertCloseStore(Some(store), 0);
                CertStoreError::CertificateNotFound(thumbprint.to_string())
            })?;

            let mut key_handle = NCRYPT_KEY_HANDLE::default();
            let mut key_spec = 0u32;
            let mut caller_free_key = false;

            let result = CryptAcquireCertificatePrivateKey(
                cert_ctx,
                CRYPT_ACQUIRE_SILENT_FLAG,
                None,
                &mut key_handle.0 as *mut usize as *mut _,
                Some(&mut key_spec as *mut u32 as *mut _),
                Some(&mut caller_free_key as *mut bool as *mut _),
            );

            if result.is_err() {
                let _ = CertCloseStore(Some(store), 0);
                return Err(CertStoreError::SmartCardNotPresent);
            }

            // Set PIN
            let pin_wide: Vec<u16> = pin
                .as_str()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let ncrypt_pin_property: Vec<u16> = "SmartCardPin"
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let pin_result = NCryptSetProperty(
                key_handle.into(),
                PCWSTR::from_raw(ncrypt_pin_property.as_ptr()),
                std::slice::from_raw_parts(
                    pin_wide.as_ptr() as *const u8,
                    pin_wide.len() * 2,
                ),
                NCRYPT_SILENT_FLAG,
            );

            if caller_free_key {
                let _ = NCryptFreeObject(key_handle.into());
            }
            let _ = CertCloseStore(Some(store), 0);

            if pin_result.is_err() {
                Err(CertStoreError::PinIncorrect)
            } else {
                info!("PIN verified successfully");
                Ok(true)
            }
        }
    }

    /// Stub PIN verification for non-Windows platforms.
    #[cfg(not(windows))]
    fn verify_pin_stub(&self, thumbprint: &str, pin: &SmartCardPin) -> CertStoreResult<bool> {
        // Verify certificate exists
        let _ = self.find_by_thumbprint(thumbprint)?;

        // Accept any PIN that's at least 4 digits for testing
        if pin.len() >= 4 {
            info!("Stub PIN verified (test mode)");
            Ok(true)
        } else {
            Err(CertStoreError::PinIncorrect)
        }
    }
}

/// Creates a stub DER-encoded certificate for testing on non-Windows platforms.
#[cfg(not(windows))]
fn create_stub_der_certificate() -> Vec<u8> {
    // This is a minimal self-signed test certificate
    // Generated for testing purposes only - not for production use
    // Subject: CN=Test User, O=Test Org
    // Key: ECDSA P-384
    // Validity: 2024-01-01 to 2027-01-01
    //
    // In a real implementation, you would load a test certificate from a file
    // or generate one using a crypto library
    vec![
        0x30, 0x82, 0x01, 0x5a, // SEQUENCE, length
        0x30, 0x82, 0x01, 0x00, // tbsCertificate SEQUENCE
        0xa0, 0x03, 0x02, 0x01, 0x02, // version [0] INTEGER 2 (v3)
        0x02, 0x01, 0x01, // serialNumber INTEGER 1
        0x30, 0x0a, // signature AlgorithmIdentifier
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, // ecdsa-with-SHA384
        0x30, 0x1f, // issuer Name
        0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, // CN=
        0x0c, 0x14, 0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x65, 0x72, 0x20, 0x28, 0x53, 0x74,
        0x75, 0x62, 0x20, 0x43, 0x41, 0x43, 0x29, // "Test User (Stub CAC)"
        0x30, 0x1e, // validity
        0x17, 0x0d, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x5a, // notBefore: 240101000000Z
        0x17, 0x0d, 0x32, 0x37, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x5a, // notAfter: 270101000000Z
        0x30, 0x1f, // subject Name (same as issuer for self-signed)
        0x31, 0x1d, 0x30, 0x1b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x54, 0x65, 0x73, 0x74,
        0x20, 0x55, 0x73, 0x65, 0x72, 0x20, 0x28, 0x53, 0x74, 0x75, 0x62, 0x20, 0x43, 0x41, 0x43,
        0x29, 0x30, 0x76, // subjectPublicKeyInfo
        0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // ecPublicKey
        0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, // secp384r1
        0x03, 0x62, 0x00, // BIT STRING, 97 bytes (P-384 public key placeholder)
        0x04, // Uncompressed point
        // X coordinate (48 bytes) - placeholder
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, // Y coordinate (48 bytes) - placeholder
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x02, 0x30, 0x0a, // signatureAlgorithm
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, // ecdsa-with-SHA384
        0x03, 0x48, 0x00, // signature BIT STRING (placeholder)
        0x30, 0x45, // ECDSA-Sig-Value SEQUENCE
        0x02, 0x21, 0x00, // r INTEGER
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x02, 0x20, // s INTEGER
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02,
    ]
}

/// Parses basic X.509 certificate information from DER-encoded data.
///
/// This is a simplified parser that extracts key fields without a full ASN.1 library.
/// Returns (subject_cn, issuer_cn, not_before, not_after, key_algorithm).
#[cfg(target_os = "macos")]
fn parse_x509_basic_info(der: &[u8]) -> (String, String, String, String, String) {
    // Default values
    let mut subject_cn = "Unknown".to_string();
    let mut issuer_cn = "Unknown".to_string();
    let mut not_before = "Unknown".to_string();
    let mut not_after = "Unknown".to_string();
    let mut key_algorithm = "Unknown".to_string();

    // Very basic ASN.1 DER parsing
    // X.509 Certificate structure:
    // SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    // tbsCertificate: SEQUENCE { version, serialNumber, signature, issuer, validity, subject, ... }

    if der.len() < 10 {
        return (subject_cn, issuer_cn, not_before, not_after, key_algorithm);
    }

    // Try to find common patterns in the certificate
    // Look for OID patterns for algorithm identification

    // ECDSA with SHA-384 OID: 1.2.840.10045.4.3.3 (06 08 2A 86 48 CE 3D 04 03 03)
    if contains_bytes(der, &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03]) {
        key_algorithm = "ECDSA P-384".to_string();
    }
    // ECDSA with SHA-256 OID: 1.2.840.10045.4.3.2
    else if contains_bytes(der, &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]) {
        key_algorithm = "ECDSA P-256".to_string();
    }
    // RSA OID: 1.2.840.113549.1.1.1
    else if contains_bytes(der, &[0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]) {
        key_algorithm = "RSA".to_string();
    }
    // EC public key OID with P-384 curve
    else if contains_bytes(der, &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]) {
        key_algorithm = "ECDSA P-384".to_string();
    }
    // EC public key OID with P-256 curve
    else if contains_bytes(der, &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]) {
        key_algorithm = "ECDSA P-256".to_string();
    }

    // Try to extract CN from subject/issuer
    // CN OID: 2.5.4.3 (55 04 03)
    if let Some(cn) = extract_cn_from_der(der) {
        subject_cn = cn.clone();
        issuer_cn = cn; // Simplified - assumes self-signed or same format
    }

    // Try to extract validity dates
    // UTCTime starts with 0x17, GeneralizedTime starts with 0x18
    if let Some((nb, na)) = extract_validity_from_der(der) {
        not_before = nb;
        not_after = na;
    }

    (subject_cn, issuer_cn, not_before, not_after, key_algorithm)
}

/// Checks if a certificate is currently valid based on date strings.
#[cfg(target_os = "macos")]
fn check_certificate_validity(not_before: &str, not_after: &str) -> bool {
    use chrono::{NaiveDate, Utc};

    let today = Utc::now().date_naive();

    // Parse dates in YYYY-MM-DD format or other common formats
    let parse_date = |s: &str| -> Option<NaiveDate> {
        // Try YYYY-MM-DD
        if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
            return Some(d);
        }
        // Try YYMMDD (UTCTime)
        if let Ok(d) = NaiveDate::parse_from_str(s, "%y%m%d") {
            return Some(d);
        }
        None
    };

    let nb = parse_date(not_before);
    let na = parse_date(not_after);

    match (nb, na) {
        (Some(start), Some(end)) => today >= start && today <= end,
        _ => true, // If we can't parse dates, assume valid
    }
}

/// Checks if `haystack` contains the byte sequence `needle`.
#[cfg(target_os = "macos")]
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// Extracts Common Name (CN) from DER-encoded certificate.
#[cfg(target_os = "macos")]
fn extract_cn_from_der(der: &[u8]) -> Option<String> {
    // Look for CN OID (2.5.4.3 = 55 04 03) followed by a string
    let cn_oid = [0x55, 0x04, 0x03];

    for i in 0..der.len().saturating_sub(cn_oid.len() + 3) {
        if der[i..].starts_with(&cn_oid) {
            // Skip OID and look for the string value
            let start = i + cn_oid.len();
            if start + 2 < der.len() {
                let tag = der[start];
                let len = der[start + 1] as usize;

                // Check for string types (UTF8String=0x0C, PrintableString=0x13, IA5String=0x16)
                if (tag == 0x0C || tag == 0x13 || tag == 0x16) && start + 2 + len <= der.len() {
                    let value = &der[start + 2..start + 2 + len];
                    if let Ok(s) = std::str::from_utf8(value) {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }

    None
}

/// Extracts validity dates from DER-encoded certificate.
#[cfg(target_os = "macos")]
fn extract_validity_from_der(der: &[u8]) -> Option<(String, String)> {
    // Validity is a SEQUENCE (0x30) containing two time values
    // UTCTime (0x17) or GeneralizedTime (0x18)

    let mut dates = Vec::new();

    for i in 0..der.len().saturating_sub(15) {
        let tag = der[i];

        // UTCTime: YYMMDDHHMMSSZ (13 bytes) - tag 0x17, length 0x0D
        if tag == 0x17 && i + 1 < der.len() {
            let len = der[i + 1] as usize;
            if len >= 6 && i + 2 + len <= der.len() {
                let time_bytes = &der[i + 2..i + 2 + len];
                if let Ok(s) = std::str::from_utf8(time_bytes) {
                    // Convert YYMMDD to YYYY-MM-DD
                    if s.len() >= 6 {
                        let year = &s[0..2];
                        let month = &s[2..4];
                        let day = &s[4..6];
                        // Assume 20xx for years 00-49, 19xx for 50-99
                        let year_num: u32 = year.parse().unwrap_or(0);
                        let full_year = if year_num < 50 { 2000 + year_num } else { 1900 + year_num };
                        dates.push(format!("{:04}-{}-{}", full_year, month, day));
                    }
                }
            }
        }
        // GeneralizedTime: YYYYMMDDHHMMSSZ - tag 0x18
        else if tag == 0x18 && i + 1 < der.len() {
            let len = der[i + 1] as usize;
            if len >= 8 && i + 2 + len <= der.len() {
                let time_bytes = &der[i + 2..i + 2 + len];
                if let Ok(s) = std::str::from_utf8(time_bytes) {
                    if s.len() >= 8 {
                        let year = &s[0..4];
                        let month = &s[4..6];
                        let day = &s[6..8];
                        dates.push(format!("{}-{}-{}", year, month, day));
                    }
                }
            }
        }
    }

    if dates.len() >= 2 {
        Some((dates[0].clone(), dates[1].clone()))
    } else {
        None
    }
}

/// Extracts Common Name (CN) from a Distinguished Name string.
/// Example: "CN=John Doe, OU=Users, O=Example" -> "John Doe"
#[cfg(target_os = "macos")]
fn extract_cn_from_dn(dn: &str) -> String {
    // Try to find CN= in the DN
    for part in dn.split(',') {
        let part = part.trim();
        if part.starts_with("CN=") {
            return part.trim_start_matches("CN=").to_string();
        }
    }
    // If no CN found, return the whole DN
    dn.to_string()
}

/// Checks if a YubiKey certificate is currently valid based on the date strings
/// from yubico-piv-tool output (format: "Mon DD HH:MM:SS YYYY GMT")
#[cfg(target_os = "macos")]
fn check_yubikey_validity(not_before: Option<&str>, not_after: Option<&str>) -> bool {
    use chrono::{NaiveDateTime, Utc};

    let now = Utc::now().naive_utc();

    // Parse YubiKey date format: "Jan  9 23:20:20 2026 GMT"
    let parse_date = |s: &str| -> Option<NaiveDateTime> {
        // Remove " GMT" suffix if present
        let s = s.trim_end_matches(" GMT");

        // Try parsing "Mon DD HH:MM:SS YYYY" format
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%b %d %H:%M:%S %Y") {
            return Some(dt);
        }
        // Try with single-digit day "Mon  D HH:MM:SS YYYY"
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%b  %d %H:%M:%S %Y") {
            return Some(dt);
        }
        None
    };

    match (not_before.and_then(parse_date), not_after.and_then(parse_date)) {
        (Some(start), Some(end)) => now >= start && now <= end,
        (None, Some(end)) => now <= end,
        (Some(start), None) => now >= start,
        _ => true, // If we can't parse dates, assume valid
    }
}

/// Converts a Windows FILETIME to a date string.
#[cfg(windows)]
fn filetime_to_string(ft: &windows::Win32::Foundation::FILETIME) -> String {
    use windows::Win32::Foundation::SYSTEMTIME;
    use windows::Win32::System::Time::FileTimeToSystemTime;

    #[allow(unsafe_code)]
    unsafe {
        let mut st = SYSTEMTIME::default();
        if FileTimeToSystemTime(ft, &mut st).is_ok() {
            format!("{:04}-{:02}-{:02}", st.wYear, st.wMonth, st.wDay)
        } else {
            String::from("Unknown")
        }
    }
}

/// Converts a null-terminated wide string to a Rust String.
#[cfg(windows)]
fn widestring_to_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }

    #[allow(unsafe_code)]
    unsafe {
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }
}

impl Default for CertificateStore {
    fn default() -> Self {
        Self::open_personal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_store_creation() {
        let store = CertificateStore::new("MY");
        assert_eq!(store.store_name(), "MY");
    }

    #[test]
    fn test_open_personal() {
        let store = CertificateStore::open_personal();
        assert_eq!(store.store_name(), "MY");
    }

    #[test]
    fn test_list_certificates_stub() {
        let store = CertificateStore::open_personal();
        let certs = store.list_certificates().unwrap();
        // On non-Windows, we get stub data
        // On Windows, we get real certificates (may be empty)
        #[cfg(not(windows))]
        {
            assert!(!certs.is_empty());
            assert!(certs.iter().any(|c| c.is_valid));
        }
        #[cfg(windows)]
        {
            // On Windows, just verify we don't crash
            let _ = certs;
        }
    }

    #[test]
    fn test_find_by_thumbprint() {
        let store = CertificateStore::open_personal();

        // This test is only valid when using stub data (no real certs found)
        // On macOS/Linux with real certs, this thumbprint won't exist
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            let cert = store.find_by_thumbprint(
                "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
            );
            assert!(cert.is_ok());
            assert_eq!(cert.unwrap().subject_cn, "John Doe (CAC)");
        }

        // On macOS, just verify the method works
        #[cfg(target_os = "macos")]
        {
            let _ = store.find_by_thumbprint("some_thumbprint");
            // Not found is OK - we're just testing the API works
        }
    }

    #[test]
    fn test_find_by_thumbprint_not_found() {
        let store = CertificateStore::open_personal();
        let cert = store.find_by_thumbprint("NOTFOUND");
        assert!(matches!(cert, Err(CertStoreError::CertificateNotFound(_))));
    }

    #[test]
    fn test_auto_select_prefers_ecdsa_p384() {
        let config = CertificateConfig::new();
        let store = CertificateStore::open_personal();

        // On Linux (no real cert store), stub data should have P-384
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            let cert = store.select_certificate(&config).unwrap();
            // Should select a P-384 certificate (first valid one)
            assert!(cert.key_algorithm.contains("P-384"));
        }

        // On macOS, just verify the API works (real certs may have different algorithms)
        #[cfg(target_os = "macos")]
        {
            // May fail if no certs available - that's OK
            let _ = store.select_certificate(&config);
        }
    }

    #[test]
    fn test_select_specific_certificate() {
        // This test is only valid with stub data
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            let config = CertificateConfig::new().with_thumbprint(
                "B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3",
            );
            let store = CertificateStore::open_personal();

            let cert = store.select_certificate(&config).unwrap();
            assert_eq!(cert.subject_cn, "Jane Smith (PIV)");
        }
    }

    #[test]
    fn test_auto_select_filters_invalid() {
        let mut config = CertificateConfig::new();
        config.selection_mode = CertificateSelectionMode::AutoSelect;

        let store = CertificateStore::open_personal();

        #[cfg(not(windows))]
        {
            let cert = store.select_certificate(&config).unwrap();
            // Should not select the expired certificate
            assert!(cert.is_valid);
            assert_ne!(cert.subject_cn, "Test User (Expired)");
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_windows_certificate_enumeration() {
        // This test only runs on Windows and verifies the API works
        let store = CertificateStore::open_personal();
        let result = store.list_certificates();

        // Should not error, even if no certificates are present
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_data_stub() {
        // This test is only valid with stub data (Linux without real cert store)
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            let store = CertificateStore::open_personal();
            let thumbprint = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";
            let data = b"test data to sign";
            let pin = SmartCardPin::new("1234");

            // Sign with ECDSA P-384
            let signature = store
                .sign_data(
                    thumbprint,
                    data,
                    SignatureAlgorithm::EcdsaSha384,
                    Some(&pin),
                )
                .unwrap();
            assert_eq!(signature.len(), 96); // P-384 signature size

            // Sign with ECDSA P-256
            let signature = store
                .sign_data(
                    thumbprint,
                    data,
                    SignatureAlgorithm::EcdsaSha256,
                    Some(&pin),
                )
                .unwrap();
            assert_eq!(signature.len(), 64); // P-256 signature size

            // Sign with RSA
            let signature = store
                .sign_data(thumbprint, data, SignatureAlgorithm::RsaSha384, Some(&pin))
                .unwrap();
            assert_eq!(signature.len(), 256); // RSA 2048 signature size
        }
    }

    #[test]
    fn test_sign_data_without_pin() {
        // This test is only valid with stub data
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            let store = CertificateStore::open_personal();
            let thumbprint = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";
            let data = b"test data to sign";

            // Sign without PIN (should still work in stub mode)
            let signature = store
                .sign_data(thumbprint, data, SignatureAlgorithm::EcdsaSha384, None)
                .unwrap();
            assert_eq!(signature.len(), 96);
        }
    }

    #[test]
    fn test_sign_data_invalid_thumbprint() {
        let store = CertificateStore::open_personal();
        let data = b"test data";
        let pin = SmartCardPin::new("1234");

        let result = store.sign_data("INVALID", data, SignatureAlgorithm::EcdsaSha384, Some(&pin));
        assert!(matches!(
            result,
            Err(CertStoreError::CertificateNotFound(_))
        ));
    }

    #[test]
    fn test_verify_pin_stub() {
        // This test is only valid with stub data
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            let store = CertificateStore::open_personal();
            let thumbprint = "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2";

            // Valid PIN (4+ digits)
            let valid_pin = SmartCardPin::new("1234");
            let result = store.verify_pin(thumbprint, &valid_pin);
            assert!(result.is_ok());
            assert!(result.unwrap());

            // Invalid PIN (too short)
            let short_pin = SmartCardPin::new("123");
            let result = store.verify_pin(thumbprint, &short_pin);
            assert!(matches!(result, Err(CertStoreError::PinIncorrect)));
        }
    }

    #[test]
    fn test_verify_pin_invalid_thumbprint() {
        let store = CertificateStore::open_personal();
        let pin = SmartCardPin::new("1234");

        let result = store.verify_pin("INVALID", &pin);
        assert!(matches!(
            result,
            Err(CertStoreError::CertificateNotFound(_))
        ));
    }

    #[test]
    fn test_signature_algorithm_variants() {
        // Ensure all variants can be created
        let _ = SignatureAlgorithm::EcdsaSha384;
        let _ = SignatureAlgorithm::EcdsaSha256;
        let _ = SignatureAlgorithm::RsaSha384;
        let _ = SignatureAlgorithm::RsaSha256;
    }
}
