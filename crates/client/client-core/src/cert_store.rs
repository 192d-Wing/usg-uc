//! Certificate store access for Windows smart card authentication.
//!
//! Provides access to certificates in the Windows Certificate Store,
//! particularly for CAC/PIV smart cards.
//!
//! On non-Windows platforms, this module provides stub implementations
//! for development and testing purposes.

use client_types::{CertificateConfig, CertificateInfo, CertificateSelectionMode};
use thiserror::Error;
use tracing::{debug, info, warn};

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
    /// Cached certificates (for stub mode).
    cached_certs: Vec<CertificateInfo>,
}

impl CertificateStore {
    /// Creates a new certificate store accessor.
    pub fn new(store_name: &str) -> Self {
        Self {
            store_name: store_name.to_string(),
            cached_certs: Self::create_stub_certificates(),
        }
    }

    /// Opens the default personal certificate store ("MY").
    pub fn open_personal() -> Self {
        Self::new("MY")
    }

    /// Lists all valid client authentication certificates.
    pub fn list_certificates(&self) -> CertStoreResult<Vec<CertificateInfo>> {
        info!("Listing certificates from store: {}", self.store_name);

        // TODO: On Windows, use CryptoAPI to enumerate real certificates
        // For now, return stub data for cross-platform development
        self.list_certificates_stub()
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
                not_before: "2024-01-01".to_string(),
                not_after: "2027-01-01".to_string(),
                is_valid: true,
                reader_name: Some("SCM Microsystems Inc. SCR331 0".to_string()),
                key_algorithm: "ECDSA P-384".to_string(),
            },
            CertificateInfo {
                thumbprint: "B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3"
                    .to_string(),
                subject_cn: "Jane Smith (PIV)".to_string(),
                subject_dn: "CN=Jane Smith, OU=Contractors, O=Example Corp, C=US".to_string(),
                issuer_cn: "Federal Bridge CA G4".to_string(),
                not_before: "2024-06-01".to_string(),
                not_after: "2026-06-01".to_string(),
                is_valid: true,
                reader_name: Some("Gemalto IDBridge CT30 0".to_string()),
                key_algorithm: "ECDSA P-384".to_string(),
            },
            CertificateInfo {
                thumbprint: "C3D4E5F6G7H8C3D4E5F6G7H8C3D4E5F6G7H8C3D4E5F6G7H8C3D4E5F6G7H8C3D4"
                    .to_string(),
                subject_cn: "Test User (Expired)".to_string(),
                subject_dn: "CN=Test User, OU=Testing, O=Test Org, C=US".to_string(),
                issuer_cn: "Test CA".to_string(),
                not_before: "2020-01-01".to_string(),
                not_after: "2022-01-01".to_string(),
                is_valid: false,
                reader_name: Some("Virtual Smart Card".to_string()),
                key_algorithm: "RSA 2048".to_string(),
            },
        ]
    }

    /// Lists certificates using stub data (for development).
    fn list_certificates_stub(&self) -> CertStoreResult<Vec<CertificateInfo>> {
        warn!("Certificate store using stub data - Windows CryptoAPI not available");
        Ok(self.cached_certs.clone())
    }

    /// Refreshes the certificate list from the store.
    pub fn refresh(&mut self) -> CertStoreResult<()> {
        info!("Refreshing certificate list");
        // In real Windows implementation, this would re-enumerate certificates
        // For stub mode, the cached data is already populated
        Ok(())
    }

    /// Returns the store name.
    pub fn store_name(&self) -> &str {
        &self.store_name
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
        assert!(!certs.is_empty());
        // Should have at least one valid certificate
        assert!(certs.iter().any(|c| c.is_valid));
    }

    #[test]
    fn test_find_by_thumbprint() {
        let store = CertificateStore::open_personal();
        let cert = store.find_by_thumbprint(
            "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
        );
        assert!(cert.is_ok());
        assert_eq!(cert.unwrap().subject_cn, "John Doe (CAC)");
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

        let cert = store.select_certificate(&config).unwrap();
        // Should select a P-384 certificate (first valid one)
        assert!(cert.key_algorithm.contains("P-384"));
    }

    #[test]
    fn test_select_specific_certificate() {
        let config = CertificateConfig::new().with_thumbprint(
            "B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3D4E5F6G7B2C3",
        );
        let store = CertificateStore::open_personal();

        let cert = store.select_certificate(&config).unwrap();
        assert_eq!(cert.subject_cn, "Jane Smith (PIV)");
    }

    #[test]
    fn test_auto_select_filters_invalid() {
        let mut config = CertificateConfig::new();
        config.selection_mode = CertificateSelectionMode::AutoSelect;

        let store = CertificateStore::open_personal();
        let cert = store.select_certificate(&config).unwrap();

        // Should not select the expired certificate
        assert!(cert.is_valid);
        assert_ne!(cert.subject_cn, "Test User (Expired)");
    }
}
