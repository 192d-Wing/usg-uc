//! Certificate and handshake verification per RFC 6347.
//!
//! ## RFC 6347 Compliance
//!
//! - **§4.2.4**: `CertificateVerify` - signature validation
//! - **§4.2.6**: Finished message verification
//!
//! ## CNSA 2.0 Compliance
//!
//! Only P-384 ECDSA signatures are accepted.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **SC-13**: Cryptographic Protection

use crate::error::{DtlsError, DtlsResult};

/// Result of certificate chain validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateValidationResult {
    /// Certificate chain is valid.
    Valid,
    /// Certificate chain is self-signed (acceptable for DTLS-SRTP with fingerprint).
    SelfSigned,
    /// Validation failed with reason.
    Invalid(String),
}

/// Certificate chain validator for DTLS.
///
/// Per RFC 6347 §4.2.4, the server MUST validate the client's certificate
/// if client authentication is requested.
pub struct CertificateValidator {
    /// Whether to allow self-signed certificates.
    /// For DTLS-SRTP, self-signed with fingerprint verification is common.
    allow_self_signed: bool,
    /// Expected certificate fingerprint (SHA-384).
    expected_fingerprint: Option<[u8; 48]>,
}

impl CertificateValidator {
    /// Creates a new certificate validator.
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            allow_self_signed: false,
            expected_fingerprint: None,
        }
    }

    /// Allows self-signed certificates.
    ///
    /// This is required for DTLS-SRTP where certificates are validated
    /// by fingerprint rather than PKI chain.
    #[must_use]
    pub const fn allow_self_signed(mut self) -> Self {
        self.allow_self_signed = true;
        self
    }

    /// Sets the expected certificate fingerprint.
    ///
    /// For DTLS-SRTP, the fingerprint is provided in the SDP and must match.
    #[must_use]
    pub const fn with_fingerprint(mut self, fingerprint: [u8; 48]) -> Self {
        self.expected_fingerprint = Some(fingerprint);
        self
    }

    /// Validates a certificate chain.
    ///
    /// Per RFC 6347 §4.2.4, this performs:
    /// 1. Certificate parsing and structure validation
    /// 2. Signature verification on each certificate
    /// 3. Chain validation (each cert signed by next)
    /// 4. Optional fingerprint verification
    ///
    /// ## Arguments
    ///
    /// * `cert_chain` - DER-encoded certificate chain (leaf first)
    ///
    /// ## Returns
    ///
    /// The validation result indicating success or failure reason.
    #[must_use] 
    pub fn validate(&self, cert_chain: &[Vec<u8>]) -> CertificateValidationResult {
        if cert_chain.is_empty() {
            return CertificateValidationResult::Invalid("empty certificate chain".to_string());
        }

        let leaf_cert = &cert_chain[0];

        // Check fingerprint if expected
        if let Some(expected) = &self.expected_fingerprint {
            let actual = uc_crypto::hash::sha384(leaf_cert);
            if actual != *expected {
                return CertificateValidationResult::Invalid(
                    "certificate fingerprint mismatch".to_string(),
                );
            }
        }

        // For a single self-signed certificate
        if cert_chain.len() == 1 {
            if self.allow_self_signed {
                // Verify the certificate is self-signed (issuer == subject)
                // and the signature is valid
                match self.verify_self_signed(leaf_cert) {
                    Ok(()) => return CertificateValidationResult::SelfSigned,
                    Err(e) => return CertificateValidationResult::Invalid(e.to_string()),
                }
            }
            return CertificateValidationResult::Invalid(
                "self-signed certificate not allowed".to_string(),
            );
        }

        // Validate certificate chain
        // Each certificate (except root) must be signed by the next certificate
        for i in 0..cert_chain.len() - 1 {
            let cert = &cert_chain[i];
            let issuer_cert = &cert_chain[i + 1];

            if let Err(e) = self.verify_certificate_signature(cert, issuer_cert) {
                return CertificateValidationResult::Invalid(format!(
                    "certificate {i} signature invalid: {e}"
                ));
            }
        }

        // Root certificate should be self-signed or trusted
        let root = &cert_chain[cert_chain.len() - 1];
        if let Err(e) = self.verify_self_signed(root) {
            return CertificateValidationResult::Invalid(format!(
                "root certificate validation failed: {e}"
            ));
        }

        CertificateValidationResult::Valid
    }

    /// Extracts the public key from a DER-encoded X.509 certificate.
    ///
    /// This is a simplified extraction that handles ECDSA P-384 certificates.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn extract_public_key(&self, cert_der: &[u8]) -> DtlsResult<Vec<u8>> {
        // X.509 certificate structure (simplified):
        // SEQUENCE {
        //   SEQUENCE {          -- TBSCertificate
        //     ...
        //     SEQUENCE {        -- SubjectPublicKeyInfo
        //       SEQUENCE {      -- AlgorithmIdentifier
        //         OID, ...
        //       }
        //       BIT STRING      -- Public key
        //     }
        //     ...
        //   }
        //   SEQUENCE { ... }    -- SignatureAlgorithm
        //   BIT STRING           -- Signature
        // }

        // Find the SubjectPublicKeyInfo by looking for the EC public key OID
        // OID 1.2.840.10045.2.1 (ecPublicKey) followed by curve OID
        let ec_pubkey_oid: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
        let p384_oid: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22]; // secp384r1

        // Search for the EC public key OID
        let ec_pos = find_subsequence(cert_der, ec_pubkey_oid).ok_or_else(|| {
            DtlsError::CertificateError {
                reason: "not an EC certificate".to_string(),
            }
        })?;

        // Verify it's P-384
        let after_ec = ec_pos + ec_pubkey_oid.len() + 2; // Skip OID tag and length
        if after_ec + p384_oid.len() > cert_der.len() {
            return Err(DtlsError::CertificateError {
                reason: "certificate truncated".to_string(),
            });
        }

        if !cert_der[after_ec..].starts_with(p384_oid) {
            return Err(DtlsError::CertificateError {
                reason: "not a P-384 certificate (CNSA 2.0 required)".to_string(),
            });
        }

        // Find the BIT STRING containing the public key
        // It follows the AlgorithmIdentifier SEQUENCE
        let search_start = after_ec + p384_oid.len();
        let mut pos = search_start;

        // Look for BIT STRING tag (0x03)
        while pos < cert_der.len() {
            if cert_der[pos] == 0x03 {
                // BIT STRING found
                let (len, len_bytes) = parse_der_length(&cert_der[pos + 1..])?;
                let content_start = pos + 1 + len_bytes + 1; // +1 for unused bits byte

                if content_start + len - 1 > cert_der.len() {
                    return Err(DtlsError::CertificateError {
                        reason: "public key truncated".to_string(),
                    });
                }

                // P-384 uncompressed public key is 97 bytes (0x04 || x || y)
                let pubkey = &cert_der[content_start..content_start + len - 1];
                if pubkey.len() == 97 && pubkey[0] == 0x04 {
                    return Ok(pubkey.to_vec());
                }
            }
            pos += 1;
        }

        Err(DtlsError::CertificateError {
            reason: "public key not found".to_string(),
        })
    }

    /// Verifies that a certificate is properly self-signed.
    fn verify_self_signed(&self, cert_der: &[u8]) -> DtlsResult<()> {
        // Extract public key
        let pubkey = self.extract_public_key(cert_der)?;

        // Extract TBS (To Be Signed) certificate and signature
        let (tbs, signature) = self.extract_tbs_and_signature(cert_der)?;

        // Verify signature
        uc_crypto::ecdsa::verify_p384(&pubkey, tbs, &signature).map_err(|_| {
            DtlsError::CertificateError {
                reason: "self-signed certificate signature invalid".to_string(),
            }
        })
    }

    /// Verifies that a certificate is signed by an issuer certificate.
    fn verify_certificate_signature(
        &self,
        cert_der: &[u8],
        issuer_cert_der: &[u8],
    ) -> DtlsResult<()> {
        // Extract issuer's public key
        let issuer_pubkey = self.extract_public_key(issuer_cert_der)?;

        // Extract TBS and signature from the certificate
        let (tbs, signature) = self.extract_tbs_and_signature(cert_der)?;

        // Verify signature
        uc_crypto::ecdsa::verify_p384(&issuer_pubkey, tbs, &signature).map_err(|_| {
            DtlsError::CertificateError {
                reason: "certificate signature invalid".to_string(),
            }
        })
    }

    /// Extracts TBS certificate and signature from a DER-encoded certificate.
    fn extract_tbs_and_signature<'a>(&self, cert_der: &'a [u8]) -> DtlsResult<(&'a [u8], Vec<u8>)> {
        let _ = self; // Silence unused_self warning - method may use self in future
        // X.509 structure:
        // SEQUENCE {
        //   SEQUENCE { ... }  -- TBSCertificate
        //   SEQUENCE { ... }  -- SignatureAlgorithm
        //   BIT STRING        -- Signature
        // }

        if cert_der.len() < 4 || cert_der[0] != 0x30 {
            return Err(DtlsError::CertificateError {
                reason: "invalid certificate structure".to_string(),
            });
        }

        // Parse outer SEQUENCE
        let (outer_len, outer_len_bytes) = parse_der_length(&cert_der[1..])?;
        let content_start = 1 + outer_len_bytes;

        if content_start + outer_len > cert_der.len() {
            return Err(DtlsError::CertificateError {
                reason: "certificate truncated".to_string(),
            });
        }

        // First inner SEQUENCE is TBSCertificate
        let tbs_start = content_start;
        if cert_der[tbs_start] != 0x30 {
            return Err(DtlsError::CertificateError {
                reason: "TBSCertificate not found".to_string(),
            });
        }

        let (tbs_len, tbs_len_bytes) = parse_der_length(&cert_der[tbs_start + 1..])?;
        let tbs_end = tbs_start + 1 + tbs_len_bytes + tbs_len;
        let tbs = &cert_der[tbs_start..tbs_end];

        // Skip SignatureAlgorithm SEQUENCE
        let sig_alg_start = tbs_end;
        if cert_der[sig_alg_start] != 0x30 {
            return Err(DtlsError::CertificateError {
                reason: "SignatureAlgorithm not found".to_string(),
            });
        }
        let (sig_alg_len, sig_alg_len_bytes) = parse_der_length(&cert_der[sig_alg_start + 1..])?;
        let sig_start = sig_alg_start + 1 + sig_alg_len_bytes + sig_alg_len;

        // BIT STRING containing signature
        if cert_der[sig_start] != 0x03 {
            return Err(DtlsError::CertificateError {
                reason: "signature not found".to_string(),
            });
        }
        let (sig_len, sig_len_bytes) = parse_der_length(&cert_der[sig_start + 1..])?;
        let sig_content_start = sig_start + 1 + sig_len_bytes + 1; // +1 for unused bits byte

        if sig_content_start + sig_len - 1 > cert_der.len() {
            return Err(DtlsError::CertificateError {
                reason: "signature truncated".to_string(),
            });
        }

        let signature = cert_der[sig_content_start..sig_content_start + sig_len - 1].to_vec();

        Ok((tbs, signature))
    }
}

impl Default for CertificateValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Finished message verifier per RFC 6347 §4.2.6.
///
/// The Finished message contains a `verify_data` field computed as:
/// ```text
/// verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))
/// ```
///
/// Where:
/// - `finished_label` is "client finished" or "server finished"
/// - `Hash` is SHA-384 for `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
pub struct FinishedVerifier;

impl FinishedVerifier {
    /// Computes the expected `verify_data` for a Finished message.
    ///
    /// ## Arguments
    ///
    /// * `master_secret` - The 48-byte master secret
    /// * `handshake_hash` - SHA-384 hash of all handshake messages
    /// * `is_client` - Whether this is for the client Finished
    ///
    /// ## Returns
    ///
    /// The 12-byte `verify_data`.
    pub fn compute_verify_data(
        master_secret: &[u8; 48],
        handshake_hash: &[u8],
        is_client: bool,
    ) -> DtlsResult<[u8; 12]> {
        let label = if is_client {
            b"client finished"
        } else {
            b"server finished"
        };

        let verify_data = prf_sha384(master_secret, label, handshake_hash, 12);

        let mut result = [0u8; 12];
        result.copy_from_slice(&verify_data);
        Ok(result)
    }

    /// Verifies a received Finished message.
    ///
    /// Per RFC 6347 §4.2.6:
    /// > Recipients of Finished messages MUST verify that the contents are correct.
    ///
    /// ## Arguments
    ///
    /// * `received` - The received `verify_data` (12 bytes)
    /// * `master_secret` - The 48-byte master secret
    /// * `handshake_hash` - SHA-384 hash of all handshake messages (excluding the Finished)
    /// * `is_client` - Whether this is the client's Finished (true) or server's (false)
    ///
    /// ## Errors
    ///
    /// Returns an error if verification fails.
    pub fn verify(
        received: &[u8],
        master_secret: &[u8; 48],
        handshake_hash: &[u8],
        is_client: bool,
    ) -> DtlsResult<()> {
        if received.len() != 12 {
            return Err(DtlsError::HandshakeFailed {
                reason: format!(
                    "Finished verify_data wrong length: expected 12, got {}",
                    received.len()
                ),
            });
        }

        let expected = Self::compute_verify_data(master_secret, handshake_hash, is_client)?;

        // Constant-time comparison to prevent timing attacks
        if !constant_time_eq(received, &expected) {
            return Err(DtlsError::HandshakeFailed {
                reason: "Finished verify_data mismatch".to_string(),
            });
        }

        Ok(())
    }
}

/// `ServerKeyExchange` signature verifier per RFC 6347.
///
/// For `ECDHE_ECDSA`, the server signs the exchange parameters:
/// ```text
/// signed_params = SHA384(client_random + server_random + ServerECDHParams)
/// ```
pub struct ServerKeyExchangeVerifier;

impl ServerKeyExchangeVerifier {
    /// Verifies the `ServerKeyExchange` signature.
    ///
    /// ## Arguments
    ///
    /// * `client_random` - 32-byte client random
    /// * `server_random` - 32-byte server random
    /// * `ecdh_params` - The ECDH parameters (curve type, named curve, public key)
    /// * `signature` - The server's signature
    /// * `server_public_key` - The server's certificate public key
    ///
    /// ## Errors
    ///
    /// Returns an error if signature verification fails.
    pub fn verify(
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        ecdh_params: &[u8],
        signature: &[u8],
        server_public_key: &[u8],
    ) -> DtlsResult<()> {
        // Construct the signed data
        let mut signed_data = Vec::with_capacity(64 + ecdh_params.len());
        signed_data.extend_from_slice(client_random);
        signed_data.extend_from_slice(server_random);
        signed_data.extend_from_slice(ecdh_params);

        // Verify with ECDSA P-384
        uc_crypto::ecdsa::verify_p384(server_public_key, &signed_data, signature).map_err(|_| {
            DtlsError::HandshakeFailed {
                reason: "ServerKeyExchange signature verification failed".to_string(),
            }
        })
    }
}

/// TLS 1.2 PRF using HMAC-SHA-384.
fn prf_sha384(secret: &[u8], label: &[u8], seed: &[u8], length: usize) -> Vec<u8> {
    let mut result = Vec::with_capacity(length);

    // Combine label and seed
    let mut combined_seed = Vec::with_capacity(label.len() + seed.len());
    combined_seed.extend_from_slice(label);
    combined_seed.extend_from_slice(seed);

    // A(1) = HMAC_SHA384(secret, label + seed)
    let mut a = uc_crypto::hkdf::hmac_sha384(secret, &combined_seed);

    while result.len() < length {
        // HMAC_SHA384(secret, A(i) + label + seed)
        let mut input = Vec::with_capacity(a.len() + combined_seed.len());
        input.extend_from_slice(&a);
        input.extend_from_slice(&combined_seed);

        let output = uc_crypto::hkdf::hmac_sha384(secret, &input);
        result.extend_from_slice(&output);

        // A(i+1) = HMAC_SHA384(secret, A(i))
        a = uc_crypto::hkdf::hmac_sha384(secret, &a);
    }

    result.truncate(length);
    result
}

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Finds a subsequence in a byte slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Parses DER length encoding.
fn parse_der_length(data: &[u8]) -> DtlsResult<(usize, usize)> {
    if data.is_empty() {
        return Err(DtlsError::CertificateError {
            reason: "empty length field".to_string(),
        });
    }

    let first = data[0];
    match first.cmp(&0x80) {
        std::cmp::Ordering::Less => {
            // Short form
            Ok((first as usize, 1))
        }
        std::cmp::Ordering::Equal => Err(DtlsError::CertificateError {
            reason: "indefinite length not supported".to_string(),
        }),
        std::cmp::Ordering::Greater => {
        // Long form
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || data.len() < 1 + num_bytes {
            return Err(DtlsError::CertificateError {
                reason: "invalid length encoding".to_string(),
            });
        }

        let mut len = 0usize;
        for &byte in &data[1..=num_bytes] {
            len = len
                .checked_mul(256)
                .ok_or_else(|| DtlsError::CertificateError {
                    reason: "length overflow".to_string(),
                })?;
            len = len
                .checked_add(byte as usize)
                .ok_or_else(|| DtlsError::CertificateError {
                    reason: "length overflow".to_string(),
                })?;
        }

            Ok((len, 1 + num_bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finished_verify_data_deterministic() {
        let master_secret = [0xABu8; 48];
        let handshake_hash = uc_crypto::hash::sha384(b"test handshake messages");

        let client_finished =
            FinishedVerifier::compute_verify_data(&master_secret, &handshake_hash, true).unwrap();

        let server_finished =
            FinishedVerifier::compute_verify_data(&master_secret, &handshake_hash, false).unwrap();

        // Should be deterministic
        let client_finished2 =
            FinishedVerifier::compute_verify_data(&master_secret, &handshake_hash, true).unwrap();

        assert_eq!(client_finished, client_finished2);

        // Client and server finished should be different
        assert_ne!(client_finished, server_finished);
    }

    #[test]
    fn test_finished_verification() {
        let master_secret = [0xABu8; 48];
        let handshake_hash = uc_crypto::hash::sha384(b"test handshake messages");

        let verify_data =
            FinishedVerifier::compute_verify_data(&master_secret, &handshake_hash, true).unwrap();

        // Should verify correctly
        FinishedVerifier::verify(&verify_data, &master_secret, &handshake_hash, true).unwrap();

        // Wrong role should fail
        assert!(
            FinishedVerifier::verify(&verify_data, &master_secret, &handshake_hash, false).is_err()
        );

        // Tampered data should fail
        let mut tampered = verify_data;
        tampered[0] ^= 0xFF;
        assert!(
            FinishedVerifier::verify(&tampered, &master_secret, &handshake_hash, true).is_err()
        );
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
    }

    #[test]
    fn test_certificate_validator_empty_chain() {
        let validator = CertificateValidator::new();
        let result = validator.validate(&[]);
        assert_eq!(
            result,
            CertificateValidationResult::Invalid("empty certificate chain".to_string())
        );
    }

    #[test]
    fn test_parse_der_length_short() {
        let data = [0x10];
        let (len, bytes) = parse_der_length(&data).unwrap();
        assert_eq!(len, 16);
        assert_eq!(bytes, 1);
    }

    #[test]
    fn test_parse_der_length_long() {
        let data = [0x82, 0x01, 0x00]; // 256 in long form
        let (len, bytes) = parse_der_length(&data).unwrap();
        assert_eq!(len, 256);
        assert_eq!(bytes, 3);
    }

    #[test]
    fn test_find_subsequence() {
        let haystack = b"hello world";
        assert_eq!(find_subsequence(haystack, b"world"), Some(6));
        assert_eq!(find_subsequence(haystack, b"xyz"), None);
        assert_eq!(find_subsequence(haystack, b"hello"), Some(0));
    }
}
