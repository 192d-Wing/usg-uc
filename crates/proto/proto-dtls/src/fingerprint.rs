//! Certificate fingerprint handling.
//!
//! ## CNSA 2.0 Compliance
//!
//! Only SHA-384 fingerprints are supported per CNSA 2.0 requirements.
//! SHA-256 fingerprints are not available.
//!
//! ## RFC 4572
//!
//! Certificate fingerprints are used in SDP for DTLS-SRTP.

use crate::error::{DtlsError, DtlsResult};

/// Maximum accepted length of one SDP `a=fingerprint` value (bounded parsing).
///
/// A sha-512 fingerprint is `sha-512 ` plus 64 * 3 - 1 = 199 bytes, so 256
/// leaves headroom for whitespace while bounding hostile input.
pub const MAX_SDP_FINGERPRINT_LEN: usize = 256;

/// Hash algorithm for certificate fingerprints.
///
/// ## CNSA 2.0 Compliance
///
/// Only SHA-384 and SHA-512 are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintAlgorithm {
    /// SHA-384 (CNSA 2.0 minimum).
    Sha384,
    /// SHA-512.
    Sha512,
}

impl FingerprintAlgorithm {
    /// Returns the SDP attribute name for this algorithm.
    #[must_use]
    pub const fn sdp_name(&self) -> &'static str {
        match self {
            Self::Sha384 => "sha-384",
            Self::Sha512 => "sha-512",
        }
    }

    /// Returns the output length in bytes.
    #[must_use]
    pub const fn output_len(&self) -> usize {
        match self {
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

/// Certificate fingerprint for DTLS identity verification.
///
/// ## Usage in SDP
///
/// The fingerprint is included in SDP as:
/// ```text
/// a=fingerprint:sha-384 AA:BB:CC:...
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct CertificateFingerprint {
    /// Hash algorithm used.
    algorithm: FingerprintAlgorithm,
    /// Fingerprint bytes.
    bytes: Vec<u8>,
}

impl CertificateFingerprint {
    /// Creates a fingerprint from raw bytes.
    ///
    /// ## Errors
    ///
    /// Returns an error if the byte length doesn't match the algorithm.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn new(algorithm: FingerprintAlgorithm, bytes: Vec<u8>) -> DtlsResult<Self> {
        if bytes.len() != algorithm.output_len() {
            return Err(DtlsError::InvalidConfig {
                reason: format!(
                    "fingerprint length {} doesn't match {} ({} bytes)",
                    bytes.len(),
                    algorithm.sdp_name(),
                    algorithm.output_len()
                ),
            });
        }

        Ok(Self { algorithm, bytes })
    }

    /// Computes a SHA-384 fingerprint of a DER-encoded certificate.
    ///
    /// ## CNSA 2.0 Compliance
    ///
    /// Uses SHA-384 as the minimum compliant hash algorithm.
    #[must_use]
    pub fn from_certificate_sha384(cert_der: &[u8]) -> Self {
        let hash = uc_crypto::hash::sha384(cert_der);
        Self {
            algorithm: FingerprintAlgorithm::Sha384,
            bytes: hash.to_vec(),
        }
    }

    /// Computes a SHA-512 fingerprint of a DER-encoded certificate.
    #[must_use]
    pub fn from_certificate_sha512(cert_der: &[u8]) -> Self {
        let hash = uc_crypto::hash::sha512(cert_der);
        Self {
            algorithm: FingerprintAlgorithm::Sha512,
            bytes: hash.to_vec(),
        }
    }

    /// Parses a fingerprint from SDP format.
    ///
    /// ## Format
    ///
    /// `sha-384 AA:BB:CC:DD:...`
    ///
    /// ## Errors
    ///
    /// Returns an error if parsing fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn from_sdp(sdp: &str) -> DtlsResult<Self> {
        let parts: Vec<&str> = sdp.splitn(2, ' ').collect();
        if parts.len() != 2 {
            return Err(DtlsError::InvalidConfig {
                reason: "invalid fingerprint format".to_string(),
            });
        }

        let algorithm = match parts[0].to_lowercase().as_str() {
            "sha-384" => FingerprintAlgorithm::Sha384,
            "sha-512" => FingerprintAlgorithm::Sha512,
            other => {
                return Err(DtlsError::InvalidConfig {
                    reason: format!("unsupported fingerprint algorithm: {other}"),
                });
            }
        };

        let hex_str = parts[1].replace(':', "");
        let bytes = hex_decode(&hex_str).map_err(|e| DtlsError::InvalidConfig {
            reason: format!("invalid fingerprint hex: {e}"),
        })?;

        Self::new(algorithm, bytes)
    }

    /// Parses an SDP `a=fingerprint` value strictly (RFC 8122 §5 grammar).
    ///
    /// Unlike [`Self::from_sdp`] this enforces the wire grammar on hostile
    /// input: the value is capped at [`MAX_SDP_FINGERPRINT_LEN`] bytes, the hash
    /// name is matched case-insensitively and must be `sha-384` or `sha-512`
    /// (CNSA 2.0; RFC 8122 §5 permits rejecting unsupported hash functions, so
    /// `sha-1`, `sha-224`, `sha-256` and `md5` are refused), and the
    /// fingerprint must be colon-separated pairs of hex digits with exactly the
    /// algorithm's output length.
    ///
    /// NIST 800-53 Rev5: SI-10 (input validation), SC-13 (CNSA 2.0 hashes only)
    ///
    /// # Errors
    /// Returns [`DtlsError::InvalidConfig`] on any grammar, length or
    /// algorithm violation.
    pub fn from_sdp_strict(value: &str) -> DtlsResult<Self> {
        let invalid = |reason: &str| DtlsError::InvalidConfig {
            reason: reason.to_string(),
        };
        if value.len() > MAX_SDP_FINGERPRINT_LEN {
            return Err(invalid("fingerprint attribute too long"));
        }
        let value = value.trim();
        let (hash_name, hex) = value
            .split_once(' ')
            .ok_or_else(|| invalid("invalid fingerprint format"))?;
        let algorithm = if hash_name.eq_ignore_ascii_case("sha-384") {
            FingerprintAlgorithm::Sha384
        } else if hash_name.eq_ignore_ascii_case("sha-512") {
            FingerprintAlgorithm::Sha512
        } else {
            return Err(invalid("unsupported fingerprint algorithm (CNSA 2.0)"));
        };

        let mut bytes = Vec::with_capacity(algorithm.output_len());
        for group in hex.trim().split(':') {
            let g = group.as_bytes();
            if g.len() != 2 || !g.iter().all(u8::is_ascii_hexdigit) {
                return Err(invalid("invalid fingerprint hex"));
            }
            if bytes.len() == algorithm.output_len() {
                return Err(invalid("fingerprint too long for algorithm"));
            }
            let byte =
                u8::from_str_radix(group, 16).map_err(|_| invalid("invalid fingerprint hex"))?;
            bytes.push(byte);
        }
        Self::new(algorithm, bytes)
    }

    /// Verifies that a certificate matches at least one of `expected`.
    ///
    /// RFC 8122 §5: when several fingerprints are signalled, the certificate
    /// MUST match at least one of them. An empty set never matches (fail
    /// closed).
    ///
    /// NIST 800-53 Rev5: SC-23 (session authenticity)
    ///
    /// # Errors
    /// Returns [`DtlsError::FingerprintMismatch`] if no fingerprint matches.
    pub fn verify_any(expected: &[Self], cert_der: &[u8]) -> DtlsResult<()> {
        if expected.iter().any(|fp| fp.verify(cert_der).is_ok()) {
            return Ok(());
        }
        Err(DtlsError::FingerprintMismatch {
            expected: expected
                .first()
                .map_or_else(|| "<none signalled>".to_string(), Self::to_sdp),
            actual: Self::from_certificate_sha384(cert_der).to_sdp(),
        })
    }

    /// Returns the hash algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> FingerprintAlgorithm {
        self.algorithm
    }

    /// Returns the fingerprint bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Formats the fingerprint for SDP.
    ///
    /// ## Format
    ///
    /// `sha-384 AA:BB:CC:DD:...`
    #[must_use]
    pub fn to_sdp(&self) -> String {
        let hex = self
            .bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":");
        format!("{} {hex}", self.algorithm.sdp_name())
    }

    /// Verifies this fingerprint matches a certificate.
    ///
    /// ## Errors
    ///
    /// Returns an error if the fingerprint doesn't match.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn verify(&self, cert_der: &[u8]) -> DtlsResult<()> {
        let computed = match self.algorithm {
            FingerprintAlgorithm::Sha384 => Self::from_certificate_sha384(cert_der),
            FingerprintAlgorithm::Sha512 => Self::from_certificate_sha512(cert_der),
        };

        if self.bytes != computed.bytes {
            return Err(DtlsError::FingerprintMismatch {
                expected: self.to_sdp(),
                actual: computed.to_sdp(),
            });
        }

        Ok(())
    }
}

impl std::fmt::Debug for CertificateFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateFingerprint")
            .field("algorithm", &self.algorithm)
            .field("fingerprint", &self.to_sdp())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for CertificateFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_sdp())
    }
}

/// Decode hex string to bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("odd length hex string".to_string());
    }

    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let s = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
            u8::from_str_radix(s, 16).map_err(|e| e.to_string())
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_from_certificate() {
        let cert_data = b"test certificate data";
        let fp = CertificateFingerprint::from_certificate_sha384(cert_data);

        assert_eq!(fp.algorithm(), FingerprintAlgorithm::Sha384);
        assert_eq!(fp.bytes().len(), 48);
    }

    #[test]
    fn test_fingerprint_sdp_roundtrip() {
        let cert_data = b"test certificate data";
        let fp = CertificateFingerprint::from_certificate_sha384(cert_data);

        let sdp = fp.to_sdp();
        assert!(sdp.starts_with("sha-384 "));

        let parsed = CertificateFingerprint::from_sdp(&sdp).unwrap();
        assert_eq!(fp.bytes(), parsed.bytes());
    }

    #[test]
    fn test_fingerprint_verify() {
        let cert_data = b"test certificate data";
        let fp = CertificateFingerprint::from_certificate_sha384(cert_data);

        // Should succeed
        fp.verify(cert_data).unwrap();

        // Should fail with different data
        let result = fp.verify(b"different data");
        assert!(matches!(result, Err(DtlsError::FingerprintMismatch { .. })));
    }

    #[test]
    fn test_algorithm_properties() {
        assert_eq!(FingerprintAlgorithm::Sha384.sdp_name(), "sha-384");
        assert_eq!(FingerprintAlgorithm::Sha384.output_len(), 48);
        assert_eq!(FingerprintAlgorithm::Sha512.sdp_name(), "sha-512");
        assert_eq!(FingerprintAlgorithm::Sha512.output_len(), 64);
    }

    #[test]
    fn strict_parse_round_trip_and_case() {
        for fp in [
            CertificateFingerprint::from_certificate_sha384(b"a"),
            CertificateFingerprint::from_certificate_sha512(b"b"),
        ] {
            let sdp = fp.to_sdp();
            assert_eq!(CertificateFingerprint::from_sdp_strict(&sdp).unwrap(), fp);
            assert_eq!(
                CertificateFingerprint::from_sdp_strict(&sdp.to_lowercase()).unwrap(),
                fp
            );
            assert_eq!(
                CertificateFingerprint::from_sdp_strict(&sdp.to_uppercase()).unwrap(),
                fp
            );
        }
    }

    #[test]
    fn strict_parse_rejects_bad_input() {
        let good = CertificateFingerprint::from_certificate_sha384(b"a").to_sdp();
        let hex = good.trim_start_matches("sha-384 ");
        for bad in [
            format!("sha-256 {hex}"),
            format!("sha-1 {hex}"),
            format!("md5 {hex}"),
            "sha-384".to_string(),
            "sha-384 AA:BB".to_string(),
            format!("sha-384 {hex}:AA"),
            format!("sha-384 {}", hex.replace(':', "")),
            format!("sha-384 +{}", &hex[1..]),
            format!("sha-384 {}G", &hex[..hex.len() - 1]),
            format!("sha-384 {hex}{}", " ".repeat(300)),
        ] {
            assert!(
                CertificateFingerprint::from_sdp_strict(&bad).is_err(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn verify_any_matches_one_of_set() {
        let a = CertificateFingerprint::from_certificate_sha384(b"cert-a");
        let b = CertificateFingerprint::from_certificate_sha512(b"cert-b");
        let set = [a, b];
        CertificateFingerprint::verify_any(&set, b"cert-a").unwrap();
        CertificateFingerprint::verify_any(&set, b"cert-b").unwrap();
        assert!(matches!(
            CertificateFingerprint::verify_any(&set, b"cert-c"),
            Err(DtlsError::FingerprintMismatch { .. })
        ));
        assert!(CertificateFingerprint::verify_any(&[], b"cert-a").is_err());
    }

    #[test]
    fn test_invalid_algorithm() {
        let result = CertificateFingerprint::from_sdp("sha-256 AA:BB:CC");
        assert!(matches!(result, Err(DtlsError::InvalidConfig { .. })));
    }
}
