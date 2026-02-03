//! Protocol-level types and constants.
//!
//! ## CNSA 2.0 Compliance
//!
//! This module defines cryptographic algorithm types that enforce CNSA 2.0
//! restrictions at the type level. Non-compliant algorithms are not representable.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// CNSA 2.0 compliant hash algorithms.
///
/// Per CNSA 2.0, SHA-256 and below are **forbidden**.
/// Only SHA-384 and SHA-512 are permitted.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CnsaHash {
    /// SHA-384 (minimum required by CNSA 2.0).
    #[default]
    Sha384,
    /// SHA-512.
    Sha512,
}

impl CnsaHash {
    /// Returns the digest length in bytes.
    #[must_use]
    pub const fn digest_len(&self) -> usize {
        match self {
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Returns the algorithm name for protocol use (e.g., SDP fingerprint).
    #[must_use]
    pub const fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Sha384 => "sha-384",
            Self::Sha512 => "sha-512",
        }
    }
}

impl std::fmt::Display for CnsaHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.algorithm_name())
    }
}

/// CNSA 2.0 compliant elliptic curves.
///
/// Per CNSA 2.0, P-256 and below are **forbidden**.
/// Only P-384 and P-521 are permitted.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CnsaCurve {
    /// NIST P-384 (secp384r1) - minimum required by CNSA 2.0.
    #[default]
    P384,
    /// NIST P-521 (secp521r1).
    P521,
}

impl CnsaCurve {
    /// Returns the key size in bits.
    #[must_use]
    pub const fn key_bits(&self) -> u32 {
        match self {
            Self::P384 => 384,
            Self::P521 => 521,
        }
    }

    /// Returns the curve name for protocol use.
    #[must_use]
    pub const fn curve_name(&self) -> &'static str {
        match self {
            Self::P384 => "P-384",
            Self::P521 => "P-521",
        }
    }

    /// Returns the OID for this curve.
    #[must_use]
    pub const fn oid(&self) -> &'static str {
        match self {
            Self::P384 => "1.3.132.0.34",
            Self::P521 => "1.3.132.0.35",
        }
    }
}

impl std::fmt::Display for CnsaCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.curve_name())
    }
}

/// CNSA 2.0 compliant symmetric cipher.
///
/// Per CNSA 2.0, only AES-256 is permitted.
/// AES-128 and AES-192 are **forbidden**.
///
/// ## NIST 800-53 Rev5: SC-13 (Cryptographic Protection)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CnsaCipher {
    /// AES-256-GCM (AEAD mode).
    #[default]
    Aes256Gcm,
}

impl CnsaCipher {
    /// Returns the key size in bytes.
    #[must_use]
    pub const fn key_len(&self) -> usize {
        match self {
            Self::Aes256Gcm => 32,
        }
    }

    /// Returns the nonce/IV size in bytes.
    #[must_use]
    pub const fn nonce_len(&self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
        }
    }

    /// Returns the authentication tag size in bytes.
    #[must_use]
    pub const fn tag_len(&self) -> usize {
        match self {
            Self::Aes256Gcm => 16,
        }
    }
}

/// CNSA 2.0 compliant JWT/JWS signing algorithms.
///
/// Per CNSA 2.0:
/// - ES256, RS256, PS256, HS256 are **forbidden**
/// - Only ES384, ES512, RS384, RS512, PS384, PS512 are permitted
///
/// For this implementation, we focus on ECDSA with P-384.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CnsaJwtAlgorithm {
    /// ECDSA using P-384 and SHA-384.
    #[default]
    Es384,
    /// ECDSA using P-521 and SHA-512.
    Es512,
}

impl CnsaJwtAlgorithm {
    /// Returns the algorithm identifier for JWT headers.
    #[must_use]
    pub const fn alg_id(&self) -> &'static str {
        match self {
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
        }
    }

    /// Returns the curve used by this algorithm.
    #[must_use]
    pub const fn curve(&self) -> CnsaCurve {
        match self {
            Self::Es384 => CnsaCurve::P384,
            Self::Es512 => CnsaCurve::P521,
        }
    }

    /// Returns the hash algorithm used.
    #[must_use]
    pub const fn hash(&self) -> CnsaHash {
        match self {
            Self::Es384 => CnsaHash::Sha384,
            Self::Es512 => CnsaHash::Sha512,
        }
    }
}

impl std::fmt::Display for CnsaJwtAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.alg_id())
    }
}

/// SRTP protection profile for CNSA 2.0 compliance.
///
/// Per RFC 7714, only `AEAD_AES_256_GCM` is permitted for CNSA 2.0.
/// Traditional SRTP profiles using HMAC-SHA1 are **forbidden**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CnsaSrtpProfile {
    /// `AEAD_AES_256_GCM` per RFC 7714.
    #[default]
    AeadAes256Gcm,
}

impl CnsaSrtpProfile {
    /// Returns the DTLS-SRTP protection profile identifier.
    ///
    /// Per RFC 7714, this is 0x0007.
    #[must_use]
    pub const fn profile_id(&self) -> u16 {
        match self {
            Self::AeadAes256Gcm => 0x0007,
        }
    }

    /// Returns the profile name for SDP.
    #[must_use]
    pub const fn profile_name(&self) -> &'static str {
        match self {
            Self::AeadAes256Gcm => "AEAD_AES_256_GCM",
        }
    }

    /// Returns the master key length in bytes.
    #[must_use]
    pub const fn master_key_len(&self) -> usize {
        match self {
            Self::AeadAes256Gcm => 32,
        }
    }

    /// Returns the master salt length in bytes.
    #[must_use]
    pub const fn master_salt_len(&self) -> usize {
        match self {
            Self::AeadAes256Gcm => 12,
        }
    }
}

/// TLS cipher suite for CNSA 2.0 compliance.
///
/// Per CNSA 2.0, only TLS 1.3 with AES-256-GCM is permitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CnsaTlsCipherSuite {
    /// `TLS_AES_256_GCM_SHA384` (TLS 1.3).
    #[default]
    Tls13Aes256GcmSha384,
}

impl CnsaTlsCipherSuite {
    /// Returns the IANA cipher suite value.
    #[must_use]
    pub const fn iana_value(&self) -> u16 {
        match self {
            Self::Tls13Aes256GcmSha384 => 0x1302,
        }
    }

    /// Returns the cipher suite name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Tls13Aes256GcmSha384 => "TLS_AES_256_GCM_SHA384",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cnsa_hash() {
        assert_eq!(CnsaHash::Sha384.digest_len(), 48);
        assert_eq!(CnsaHash::Sha512.digest_len(), 64);
        assert_eq!(CnsaHash::default(), CnsaHash::Sha384);
    }

    #[test]
    fn test_cnsa_curve() {
        assert_eq!(CnsaCurve::P384.key_bits(), 384);
        assert_eq!(CnsaCurve::P521.key_bits(), 521);
        assert_eq!(CnsaCurve::default(), CnsaCurve::P384);
    }

    #[test]
    fn test_cnsa_jwt_algorithm() {
        assert_eq!(CnsaJwtAlgorithm::Es384.alg_id(), "ES384");
        assert_eq!(CnsaJwtAlgorithm::Es384.curve(), CnsaCurve::P384);
        assert_eq!(CnsaJwtAlgorithm::Es384.hash(), CnsaHash::Sha384);
    }

    #[test]
    fn test_cnsa_srtp_profile() {
        assert_eq!(CnsaSrtpProfile::AeadAes256Gcm.profile_id(), 0x0007);
        assert_eq!(CnsaSrtpProfile::AeadAes256Gcm.master_key_len(), 32);
        assert_eq!(CnsaSrtpProfile::AeadAes256Gcm.master_salt_len(), 12);
    }

    #[test]
    fn test_cnsa_cipher() {
        assert_eq!(CnsaCipher::Aes256Gcm.key_len(), 32);
        assert_eq!(CnsaCipher::Aes256Gcm.nonce_len(), 12);
        assert_eq!(CnsaCipher::Aes256Gcm.tag_len(), 16);
    }
}
