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

    /// Lists certificates using stub data (for development on non-Windows).
    #[cfg(not(windows))]
    fn list_certificates_stub(&self) -> CertStoreResult<Vec<CertificateInfo>> {
        warn!("Certificate store using stub data - Windows CryptoAPI not available");
        Ok(Self::create_stub_certificates())
    }

    /// Lists certificates using Windows CryptoAPI.
    #[cfg(windows)]
    fn list_certificates_windows(&self) -> CertStoreResult<Vec<CertificateInfo>> {
        use windows::Win32::Security::Cryptography::{
            CertCloseStore, CertEnumCertificatesInStore, CertOpenStore, CERT_CONTEXT,
            CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE, CERT_STORE_PROV_SYSTEM_W,
            CERT_SYSTEM_STORE_CURRENT_USER, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
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
            let _ = CertCloseStore(store, 0);
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
            CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
        };

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
            CertNameToStrW, CERT_X500_NAME_STR, X509_ASN_ENCODING,
        };

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
            CertGetCertificateContextProperty, CERT_HASH_PROP_ID,
        };

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

            let alg_oid = std::ffi::CStr::from_ptr(oid_ptr)
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
            CertGetCertificateContextProperty, CERT_KEY_PROV_INFO_PROP_ID, CRYPT_KEY_PROV_INFO,
        };

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

        let mut readers: Vec<String> = certs
            .iter()
            .filter_map(|c| c.reader_name.clone())
            .collect();

        // Remove duplicates while preserving order
        readers.sort();
        readers.dedup();

        debug!(count = readers.len(), "Found smart card readers");
        Ok(readers)
    }
}

/// Converts a Windows FILETIME to a date string.
#[cfg(windows)]
fn filetime_to_string(ft: &windows::Win32::Foundation::FILETIME) -> String {
    use windows::Win32::Foundation::SYSTEMTIME;
    use windows::Win32::System::Time::FileTimeToSystemTime;

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

        #[cfg(not(windows))]
        {
            let cert = store.find_by_thumbprint(
                "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2",
            );
            assert!(cert.is_ok());
            assert_eq!(cert.unwrap().subject_cn, "John Doe (CAC)");
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

        #[cfg(not(windows))]
        {
            let cert = store.select_certificate(&config).unwrap();
            // Should select a P-384 certificate (first valid one)
            assert!(cert.key_algorithm.contains("P-384"));
        }
    }

    #[test]
    fn test_select_specific_certificate() {
        #[cfg(not(windows))]
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
}
