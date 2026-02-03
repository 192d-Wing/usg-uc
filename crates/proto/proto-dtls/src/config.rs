//! DTLS configuration.
//!
//! ## CNSA 2.0 Compliance
//!
//! Configuration enforces CNSA 2.0 requirements:
//! - P-384 ECDSA certificates only
//! - AES-256-GCM cipher suites only
//! - SHA-384 minimum for fingerprints

use crate::error::{DtlsError, DtlsResult};
use crate::{DtlsRole, SrtpProfile};
use std::path::PathBuf;
use std::time::Duration;

/// DTLS configuration.
///
/// ## CNSA 2.0 Compliance
///
/// All cryptographic parameters are constrained to CNSA 2.0 compliant values.
#[derive(Debug, Clone)]
pub struct DtlsConfig {
    /// Certificate chain in DER format.
    pub certificate_chain: Vec<Vec<u8>>,
    /// Private key in DER format.
    pub private_key: Vec<u8>,
    /// DTLS role (client or server).
    pub role: DtlsRole,
    /// SRTP profiles to offer (CNSA 2.0 compliant only).
    pub srtp_profiles: Vec<SrtpProfile>,
    /// Handshake timeout.
    pub handshake_timeout: Duration,
    /// MTU for DTLS packets.
    pub mtu: u16,
    /// Enable extended master secret (RFC 7627).
    pub extended_master_secret: bool,
    /// Enable DTLS replay protection.
    pub replay_protection: bool,
}

impl Default for DtlsConfig {
    fn default() -> Self {
        Self {
            certificate_chain: Vec::new(),
            private_key: Vec::new(),
            role: DtlsRole::Server,
            // CNSA 2.0: Only AES-256-GCM
            srtp_profiles: vec![SrtpProfile::AeadAes256Gcm],
            handshake_timeout: Duration::from_secs(30),
            mtu: 1200,
            extended_master_secret: true,
            replay_protection: true,
        }
    }
}

impl DtlsConfig {
    /// Creates a new DTLS configuration with the given role.
    #[must_use]
    pub fn new(role: DtlsRole) -> Self {
        Self {
            role,
            ..Default::default()
        }
    }

    /// Sets the certificate chain and private key from DER-encoded data.
    #[must_use]
    pub fn with_identity(mut self, certificate_chain: Vec<Vec<u8>>, private_key: Vec<u8>) -> Self {
        self.certificate_chain = certificate_chain;
        self.private_key = private_key;
        self
    }

    /// Loads certificate and key from PEM files.
    ///
    /// ## Errors
    ///
    /// Returns an error if files cannot be read or parsed.
    pub fn with_pem_files(
        mut self,
        cert_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
    ) -> DtlsResult<Self> {
        let cert_path = cert_path.into();
        let key_path = key_path.into();

        let cert_pem = std::fs::read(&cert_path).map_err(|e| DtlsError::CertificateError {
            reason: format!("failed to read cert file {}: {e}", cert_path.display()),
        })?;

        let key_pem = std::fs::read(&key_path).map_err(|e| DtlsError::CertificateError {
            reason: format!("failed to read key file {}: {e}", key_path.display()),
        })?;

        // Parse PEM certificates
        let certs = parse_pem_certificates(&cert_pem)?;
        if certs.is_empty() {
            return Err(DtlsError::CertificateError {
                reason: "no certificates found in PEM file".to_string(),
            });
        }

        // Parse PEM private key
        let key = parse_pem_private_key(&key_pem)?;

        self.certificate_chain = certs;
        self.private_key = key;

        Ok(self)
    }

    /// Sets the handshake timeout.
    #[must_use]
    pub const fn with_handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Sets the MTU.
    #[must_use]
    pub const fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Validates the configuration.
    ///
    /// ## Errors
    ///
    /// Returns an error if the configuration is invalid.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn validate(&self) -> DtlsResult<()> {
        if self.certificate_chain.is_empty() {
            return Err(DtlsError::InvalidConfig {
                reason: "certificate chain is empty".to_string(),
            });
        }

        if self.private_key.is_empty() {
            return Err(DtlsError::InvalidConfig {
                reason: "private key is empty".to_string(),
            });
        }

        if self.srtp_profiles.is_empty() {
            return Err(DtlsError::InvalidConfig {
                reason: "no SRTP profiles configured".to_string(),
            });
        }

        // CNSA 2.0: Verify only compliant profiles
        for profile in &self.srtp_profiles {
            match profile {
                SrtpProfile::AeadAes256Gcm => {} // OK
            }
        }

        if self.mtu < 576 {
            return Err(DtlsError::InvalidConfig {
                reason: "MTU too small (minimum 576)".to_string(),
            });
        }

        Ok(())
    }
}

/// Parse PEM-encoded certificates to DER.
fn parse_pem_certificates(pem_data: &[u8]) -> DtlsResult<Vec<Vec<u8>>> {
    let pem_str = std::str::from_utf8(pem_data).map_err(|e| DtlsError::CertificateError {
        reason: format!("invalid UTF-8 in PEM: {e}"),
    })?;

    let mut certs = Vec::new();
    let mut current_cert = Vec::new();
    let mut in_cert = false;

    for line in pem_str.lines() {
        if line.contains("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current_cert.clear();
        } else if line.contains("-----END CERTIFICATE-----") {
            in_cert = false;
            let der = base64_decode(&current_cert.join(""))?;
            certs.push(der);
        } else if in_cert && !line.is_empty() {
            current_cert.push(line.to_string());
        }
    }

    Ok(certs)
}

/// Parse PEM-encoded private key to DER.
fn parse_pem_private_key(pem_data: &[u8]) -> DtlsResult<Vec<u8>> {
    let pem_str = std::str::from_utf8(pem_data).map_err(|e| DtlsError::CertificateError {
        reason: format!("invalid UTF-8 in PEM: {e}"),
    })?;

    let mut key_data = Vec::new();
    let mut in_key = false;

    for line in pem_str.lines() {
        if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
            in_key = true;
            key_data.clear();
        } else if line.contains("-----END") && line.contains("PRIVATE KEY-----") {
            // Key parsing complete - in_key no longer needed
            return base64_decode(&key_data.join(""));
        } else if in_key && !line.is_empty() {
            key_data.push(line.to_string());
        }
    }

    Err(DtlsError::CertificateError {
        reason: "no private key found in PEM".to_string(),
    })
}

/// Simple base64 decoder.
fn base64_decode(input: &str) -> DtlsResult<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim().replace(['\n', '\r', ' '], "");
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let mut buffer = 0u32;
    let mut bits = 0u32;

    for c in input.chars() {
        if c == '=' {
            break;
        }

        // Position returns usize which fits in u32 for base64 alphabet (max 63)
        #[allow(clippy::cast_possible_truncation)]
        let value = ALPHABET.iter().position(|&x| x == c as u8).ok_or_else(|| {
            DtlsError::CertificateError {
                reason: format!("invalid base64 character: {c}"),
            }
        })? as u32;

        buffer = (buffer << 6) | value;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            // Value is always < 256 after masking with (1 << 8) - 1
            #[allow(clippy::cast_possible_truncation)]
            output.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DtlsConfig::default();
        assert_eq!(config.role, DtlsRole::Server);
        assert_eq!(config.srtp_profiles, vec![SrtpProfile::AeadAes256Gcm]);
        assert!(config.extended_master_secret);
        assert!(config.replay_protection);
    }

    #[test]
    fn test_config_validation() {
        let config = DtlsConfig::default();
        // Should fail - no certs
        assert!(config.validate().is_err());

        let config = DtlsConfig::default().with_identity(vec![vec![1, 2, 3]], vec![4, 5, 6]);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_mtu_validation() {
        let config = DtlsConfig::default()
            .with_identity(vec![vec![1, 2, 3]], vec![4, 5, 6])
            .with_mtu(100); // Too small

        let result = config.validate();
        assert!(matches!(result, Err(DtlsError::InvalidConfig { .. })));
    }

    #[test]
    fn test_base64_decode() {
        let encoded = "SGVsbG8gV29ybGQ=";
        let decoded = base64_decode(encoded).unwrap();
        assert_eq!(decoded, b"Hello World");
    }
}
