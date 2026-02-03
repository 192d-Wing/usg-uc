//! SRTP-SDES (Security Descriptions) for SDP.
//!
//! This module implements RFC 4568 - Security Descriptions for Media Streams
//! which provides key exchange for SRTP using SDP crypto attributes.
//!
//! ## RFC Compliance
//!
//! - **RFC 4568**: SDP Security Descriptions for Media Streams
//! - **RFC 3711**: The Secure Real-time Transport Protocol (SRTP)
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-8**: Transmission Confidentiality and Integrity
//! - **SC-13**: Cryptographic Protection
//!
//! ## Example Usage
//!
//! ```text
//! a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^20
//! ```
//!
//! ## Security Considerations
//!
//! SDES transmits keys in plaintext within SDP, so SDES should only be used
//! when the signaling path is protected (e.g., via TLS/SIPS). DTLS-SRTP is
//! generally preferred for end-to-end security when possible.

use crate::error::{SdpError, SdpResult};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::fmt;
use std::str::FromStr;

/// SRTP cipher suite per RFC 4568 §6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CipherSuite {
    /// AES Counter Mode with 128-bit key, HMAC-SHA1 with 80-bit auth tag.
    /// Master key: 128 bits, Master salt: 112 bits.
    AesCm128HmacSha1_80,
    /// AES Counter Mode with 128-bit key, HMAC-SHA1 with 32-bit auth tag.
    /// Master key: 128 bits, Master salt: 112 bits.
    AesCm128HmacSha1_32,
    /// F8 mode with 128-bit key, HMAC-SHA1 with 80-bit auth tag.
    /// Master key: 128 bits, Master salt: 112 bits.
    F8128HmacSha1_80,
    /// AES-256 Counter Mode with HMAC-SHA1 80-bit auth (RFC 6188).
    /// Master key: 256 bits, Master salt: 112 bits.
    AeadAes128Gcm,
    /// AEAD AES-256 GCM (RFC 7714).
    /// Master key: 256 bits, Master salt: 96 bits.
    AeadAes256Gcm,
}

impl CipherSuite {
    /// Returns the master key length in bytes for this cipher suite.
    #[must_use]
    pub fn master_key_length(&self) -> usize {
        match self {
            Self::AesCm128HmacSha1_80 | Self::AesCm128HmacSha1_32 | Self::F8128HmacSha1_80 => 16,
            Self::AeadAes128Gcm => 16,
            Self::AeadAes256Gcm => 32,
        }
    }

    /// Returns the master salt length in bytes for this cipher suite.
    #[must_use]
    pub fn master_salt_length(&self) -> usize {
        match self {
            Self::AesCm128HmacSha1_80
            | Self::AesCm128HmacSha1_32
            | Self::F8128HmacSha1_80
            | Self::AeadAes128Gcm => 14, // 112 bits
            Self::AeadAes256Gcm => 12, // 96 bits
        }
    }

    /// Returns the total keying material length (key + salt) in bytes.
    #[must_use]
    pub fn keying_material_length(&self) -> usize {
        self.master_key_length() + self.master_salt_length()
    }

    /// Returns the authentication tag length in bits.
    #[must_use]
    pub fn auth_tag_bits(&self) -> usize {
        match self {
            Self::AesCm128HmacSha1_80 | Self::F8128HmacSha1_80 => 80,
            Self::AesCm128HmacSha1_32 => 32,
            Self::AeadAes128Gcm | Self::AeadAes256Gcm => 128, // GCM tag
        }
    }

    /// Returns true if this is an AEAD cipher suite.
    #[must_use]
    pub fn is_aead(&self) -> bool {
        matches!(self, Self::AeadAes128Gcm | Self::AeadAes256Gcm)
    }
}

impl fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AesCm128HmacSha1_80 => "AES_CM_128_HMAC_SHA1_80",
            Self::AesCm128HmacSha1_32 => "AES_CM_128_HMAC_SHA1_32",
            Self::F8128HmacSha1_80 => "F8_128_HMAC_SHA1_80",
            Self::AeadAes128Gcm => "AEAD_AES_128_GCM",
            Self::AeadAes256Gcm => "AEAD_AES_256_GCM",
        };
        write!(f, "{s}")
    }
}

impl FromStr for CipherSuite {
    type Err = SdpError;

    fn from_str(s: &str) -> SdpResult<Self> {
        match s.to_uppercase().as_str() {
            "AES_CM_128_HMAC_SHA1_80" => Ok(Self::AesCm128HmacSha1_80),
            "AES_CM_128_HMAC_SHA1_32" => Ok(Self::AesCm128HmacSha1_32),
            "F8_128_HMAC_SHA1_80" => Ok(Self::F8128HmacSha1_80),
            "AEAD_AES_128_GCM" => Ok(Self::AeadAes128Gcm),
            "AEAD_AES_256_GCM" => Ok(Self::AeadAes256Gcm),
            _ => Err(SdpError::InvalidAttribute {
                name: "crypto".to_string(),
                reason: format!("unknown cipher suite: {s}"),
            }),
        }
    }
}

/// SRTP key parameters from the inline key method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyParams {
    /// Base64-encoded keying material (master key + master salt concatenated).
    key_material: Vec<u8>,
    /// Key lifetime (maximum number of packets using this key).
    /// Format: 2^n where n is the exponent.
    lifetime: Option<u64>,
    /// Master Key Identifier length in bytes (0-255).
    mki_length: Option<u8>,
    /// Master Key Identifier value.
    mki_value: Option<u32>,
}

impl KeyParams {
    /// Creates new key parameters from raw keying material.
    ///
    /// The keying material should be the concatenation of master key and master salt.
    #[must_use]
    pub fn new(key_material: Vec<u8>) -> Self {
        Self {
            key_material,
            lifetime: None,
            mki_length: None,
            mki_value: None,
        }
    }

    /// Creates key parameters from base64-encoded keying material.
    pub fn from_base64(encoded: &str) -> SdpResult<Self> {
        let key_material = BASE64.decode(encoded).map_err(|e| SdpError::InvalidAttribute {
            name: "crypto".to_string(),
            reason: format!("invalid base64 key material: {e}"),
        })?;
        Ok(Self::new(key_material))
    }

    /// Sets the key lifetime.
    #[must_use]
    pub fn with_lifetime(mut self, lifetime: u64) -> Self {
        self.lifetime = Some(lifetime);
        self
    }

    /// Sets the MKI (Master Key Identifier).
    #[must_use]
    pub fn with_mki(mut self, value: u32, length: u8) -> Self {
        self.mki_value = Some(value);
        self.mki_length = Some(length);
        self
    }

    /// Returns the raw keying material.
    #[must_use]
    pub fn key_material(&self) -> &[u8] {
        &self.key_material
    }

    /// Returns the master key portion of the keying material.
    ///
    /// Returns None if the keying material is too short for the cipher suite.
    #[must_use]
    pub fn master_key(&self, cipher: CipherSuite) -> Option<&[u8]> {
        let key_len = cipher.master_key_length();
        if self.key_material.len() >= key_len {
            Some(&self.key_material[..key_len])
        } else {
            None
        }
    }

    /// Returns the master salt portion of the keying material.
    ///
    /// Returns None if the keying material is too short for the cipher suite.
    #[must_use]
    pub fn master_salt(&self, cipher: CipherSuite) -> Option<&[u8]> {
        let key_len = cipher.master_key_length();
        let salt_len = cipher.master_salt_length();
        let total = key_len + salt_len;
        if self.key_material.len() >= total {
            Some(&self.key_material[key_len..total])
        } else {
            None
        }
    }

    /// Returns the key lifetime in packets.
    #[must_use]
    pub fn lifetime(&self) -> Option<u64> {
        self.lifetime
    }

    /// Returns the MKI value if present.
    #[must_use]
    pub fn mki_value(&self) -> Option<u32> {
        self.mki_value
    }

    /// Returns the MKI length in bytes if present.
    #[must_use]
    pub fn mki_length(&self) -> Option<u8> {
        self.mki_length
    }

    /// Returns the keying material as base64.
    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64.encode(&self.key_material)
    }

    /// Validates the keying material length against a cipher suite.
    pub fn validate_for_cipher(&self, cipher: CipherSuite) -> SdpResult<()> {
        let expected = cipher.keying_material_length();
        let actual = self.key_material.len();
        if actual < expected {
            return Err(SdpError::InvalidAttribute {
                name: "crypto".to_string(),
                reason: format!(
                    "keying material too short for {cipher}: expected {expected} bytes, got {actual}"
                ),
            });
        }
        Ok(())
    }
}

impl fmt::Display for KeyParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "inline:{}", self.to_base64())?;

        if let Some(lifetime) = self.lifetime {
            // Find the power of 2 representation
            let log2 = (lifetime as f64).log2();
            if (log2.fract().abs() < 0.001) && log2 >= 1.0 {
                write!(f, "|2^{}", log2 as u32)?;
            } else {
                write!(f, "|{lifetime}")?;
            }
        }

        if let (Some(value), Some(length)) = (self.mki_value, self.mki_length) {
            if self.lifetime.is_none() {
                write!(f, "|")?;
            }
            write!(f, "|{value}:{length}")?;
        }

        Ok(())
    }
}

/// Session parameters for SRTP.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionParams {
    /// Key Derivation Rate (KDR).
    /// Specifies how often to re-derive session keys.
    pub kdr: Option<u32>,
    /// Unencrypted SRTP packets allowed.
    pub unencrypted_srtp: bool,
    /// Unencrypted SRTCP packets allowed.
    pub unencrypted_srtcp: bool,
    /// Unauthenticated SRTP packets allowed.
    pub unauthenticated_srtp: bool,
    /// Forward Error Correction (FEC) order.
    pub fec_order: Option<FecOrder>,
    /// FEC key method.
    pub fec_key: Option<String>,
    /// Window Size Hint for replay protection.
    pub wsh: Option<u32>,
}

/// FEC ordering relative to SRTP encryption/authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecOrder {
    /// FEC applied before SRTP (FEC_SRTP).
    FecSrtp,
    /// SRTP applied before FEC (SRTP_FEC).
    SrtpFec,
}

impl fmt::Display for FecOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FecSrtp => write!(f, "FEC_SRTP"),
            Self::SrtpFec => write!(f, "SRTP_FEC"),
        }
    }
}

impl FromStr for FecOrder {
    type Err = SdpError;

    fn from_str(s: &str) -> SdpResult<Self> {
        match s.to_uppercase().as_str() {
            "FEC_SRTP" => Ok(Self::FecSrtp),
            "SRTP_FEC" => Ok(Self::SrtpFec),
            _ => Err(SdpError::InvalidAttribute {
                name: "crypto".to_string(),
                reason: format!("unknown FEC order: {s}"),
            }),
        }
    }
}

impl SessionParams {
    /// Creates empty session parameters (all defaults).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses session parameters from a space-separated string.
    pub fn parse(s: &str) -> SdpResult<Self> {
        let mut params = Self::new();

        for part in s.split_whitespace() {
            if let Some(kdr_str) = part.strip_prefix("KDR=") {
                params.kdr = Some(kdr_str.parse().map_err(|_| SdpError::InvalidAttribute {
                    name: "crypto".to_string(),
                    reason: format!("invalid KDR value: {kdr_str}"),
                })?);
            } else if part == "UNENCRYPTED_SRTP" {
                params.unencrypted_srtp = true;
            } else if part == "UNENCRYPTED_SRTCP" {
                params.unencrypted_srtcp = true;
            } else if part == "UNAUTHENTICATED_SRTP" {
                params.unauthenticated_srtp = true;
            } else if let Some(fec_str) = part.strip_prefix("FEC_ORDER=") {
                params.fec_order = Some(fec_str.parse()?);
            } else if let Some(fec_key) = part.strip_prefix("FEC_KEY=") {
                params.fec_key = Some(fec_key.to_string());
            } else if let Some(wsh_str) = part.strip_prefix("WSH=") {
                params.wsh = Some(wsh_str.parse().map_err(|_| SdpError::InvalidAttribute {
                    name: "crypto".to_string(),
                    reason: format!("invalid WSH value: {wsh_str}"),
                })?);
            }
            // Unknown parameters are ignored per RFC 4568
        }

        Ok(params)
    }

    /// Returns true if any non-default session parameters are set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.kdr.is_none()
            && !self.unencrypted_srtp
            && !self.unencrypted_srtcp
            && !self.unauthenticated_srtp
            && self.fec_order.is_none()
            && self.fec_key.is_none()
            && self.wsh.is_none()
    }
}

impl fmt::Display for SessionParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();

        if let Some(kdr) = self.kdr {
            parts.push(format!("KDR={kdr}"));
        }
        if self.unencrypted_srtp {
            parts.push("UNENCRYPTED_SRTP".to_string());
        }
        if self.unencrypted_srtcp {
            parts.push("UNENCRYPTED_SRTCP".to_string());
        }
        if self.unauthenticated_srtp {
            parts.push("UNAUTHENTICATED_SRTP".to_string());
        }
        if let Some(ref order) = self.fec_order {
            parts.push(format!("FEC_ORDER={order}"));
        }
        if let Some(ref key) = self.fec_key {
            parts.push(format!("FEC_KEY={key}"));
        }
        if let Some(wsh) = self.wsh {
            parts.push(format!("WSH={wsh}"));
        }

        write!(f, "{}", parts.join(" "))
    }
}

/// Parsed crypto attribute per RFC 4568.
///
/// Format: `crypto:tag crypto-suite key-params [session-params]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoAttribute {
    /// Tag identifying this crypto attribute (1-9 digits).
    pub tag: u32,
    /// Cipher suite.
    pub cipher_suite: CipherSuite,
    /// Key parameters (inline key).
    pub key_params: KeyParams,
    /// Optional session parameters.
    pub session_params: SessionParams,
}

impl CryptoAttribute {
    /// Creates a new crypto attribute.
    #[must_use]
    pub fn new(tag: u32, cipher_suite: CipherSuite, key_params: KeyParams) -> Self {
        Self {
            tag,
            cipher_suite,
            key_params,
            session_params: SessionParams::default(),
        }
    }

    /// Sets session parameters.
    #[must_use]
    pub fn with_session_params(mut self, params: SessionParams) -> Self {
        self.session_params = params;
        self
    }

    /// Parses a crypto attribute value (without the "crypto:" prefix).
    pub fn parse(value: &str) -> SdpResult<Self> {
        let parts: Vec<&str> = value.splitn(4, ' ').collect();

        if parts.len() < 3 {
            return Err(SdpError::InvalidAttribute {
                name: "crypto".to_string(),
                reason: "crypto attribute requires tag, cipher-suite, and key-params".to_string(),
            });
        }

        // Parse tag
        let tag: u32 = parts[0].parse().map_err(|_| SdpError::InvalidAttribute {
            name: "crypto".to_string(),
            reason: format!("invalid tag: {}", parts[0]),
        })?;

        // Parse cipher suite
        let cipher_suite: CipherSuite = parts[1].parse()?;

        // Parse key params
        let key_params = Self::parse_key_params(parts[2], cipher_suite)?;

        // Parse optional session params
        let session_params = if parts.len() > 3 {
            SessionParams::parse(parts[3])?
        } else {
            SessionParams::default()
        };

        Ok(Self {
            tag,
            cipher_suite,
            key_params,
            session_params,
        })
    }

    /// Parses inline key parameters.
    fn parse_key_params(s: &str, cipher: CipherSuite) -> SdpResult<KeyParams> {
        // Format: inline:base64|lifetime|mki:mki_length
        let inline_prefix = "inline:";
        if !s.to_lowercase().starts_with(inline_prefix) {
            return Err(SdpError::InvalidAttribute {
                name: "crypto".to_string(),
                reason: format!("unsupported key method (only inline supported): {s}"),
            });
        }

        let rest = &s[inline_prefix.len()..];
        let parts: Vec<&str> = rest.split('|').collect();

        if parts.is_empty() {
            return Err(SdpError::InvalidAttribute {
                name: "crypto".to_string(),
                reason: "missing key material in inline key".to_string(),
            });
        }

        // Parse base64 key material
        let mut key_params = KeyParams::from_base64(parts[0])?;

        // Validate key length
        key_params.validate_for_cipher(cipher)?;

        // Parse optional lifetime
        if parts.len() > 1 && !parts[1].is_empty() {
            let lifetime_str = parts[1];
            let lifetime = if let Some(exp_str) = lifetime_str.strip_prefix("2^") {
                let exp: u32 = exp_str.parse().map_err(|_| SdpError::InvalidAttribute {
                    name: "crypto".to_string(),
                    reason: format!("invalid lifetime exponent: {exp_str}"),
                })?;
                2u64.pow(exp)
            } else {
                lifetime_str.parse().map_err(|_| SdpError::InvalidAttribute {
                    name: "crypto".to_string(),
                    reason: format!("invalid lifetime: {lifetime_str}"),
                })?
            };
            key_params.lifetime = Some(lifetime);
        }

        // Parse optional MKI
        if parts.len() > 2 && !parts[2].is_empty() {
            let mki_parts: Vec<&str> = parts[2].split(':').collect();
            if mki_parts.len() == 2 {
                let mki_value: u32 = mki_parts[0].parse().map_err(|_| SdpError::InvalidAttribute {
                    name: "crypto".to_string(),
                    reason: format!("invalid MKI value: {}", mki_parts[0]),
                })?;
                let mki_length: u8 = mki_parts[1].parse().map_err(|_| SdpError::InvalidAttribute {
                    name: "crypto".to_string(),
                    reason: format!("invalid MKI length: {}", mki_parts[1]),
                })?;
                key_params.mki_value = Some(mki_value);
                key_params.mki_length = Some(mki_length);
            }
        }

        Ok(key_params)
    }

    /// Validates this crypto attribute.
    pub fn validate(&self) -> SdpResult<()> {
        // Tag must be 1-9 digits
        if self.tag > 999_999_999 {
            return Err(SdpError::InvalidAttribute {
                name: "crypto".to_string(),
                reason: "tag must be 1-9 digits".to_string(),
            });
        }

        // Validate key material length
        self.key_params.validate_for_cipher(self.cipher_suite)?;

        Ok(())
    }

    /// Returns the formatted attribute line (including "a=crypto:").
    #[must_use]
    pub fn to_sdp_line(&self) -> String {
        format!("a=crypto:{self}")
    }
}

impl fmt::Display for CryptoAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.tag, self.cipher_suite, self.key_params
        )?;

        if !self.session_params.is_empty() {
            write!(f, " {}", self.session_params)?;
        }

        Ok(())
    }
}

impl FromStr for CryptoAttribute {
    type Err = SdpError;

    fn from_str(s: &str) -> SdpResult<Self> {
        Self::parse(s)
    }
}

/// Negotiates SRTP parameters between offer and answer.
#[derive(Debug, Clone)]
pub struct SrtpNegotiator {
    /// Preferred cipher suites in order of preference.
    preferred_ciphers: Vec<CipherSuite>,
}

impl Default for SrtpNegotiator {
    fn default() -> Self {
        Self {
            preferred_ciphers: vec![
                CipherSuite::AeadAes256Gcm,
                CipherSuite::AeadAes128Gcm,
                CipherSuite::AesCm128HmacSha1_80,
                CipherSuite::AesCm128HmacSha1_32,
            ],
        }
    }
}

impl SrtpNegotiator {
    /// Creates a new negotiator with default preferences.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the preferred cipher suites.
    #[must_use]
    pub fn with_preferred_ciphers(mut self, ciphers: Vec<CipherSuite>) -> Self {
        self.preferred_ciphers = ciphers;
        self
    }

    /// Selects the best matching crypto attribute from an offer.
    ///
    /// Returns the selected offer attribute that should be echoed in the answer.
    #[must_use]
    pub fn select_crypto<'a>(&self, offer_cryptos: &'a [CryptoAttribute]) -> Option<&'a CryptoAttribute> {
        // Find the first offer cipher that matches our preferences (in preference order)
        for preferred in &self.preferred_ciphers {
            for crypto in offer_cryptos {
                if crypto.cipher_suite == *preferred {
                    return Some(crypto);
                }
            }
        }

        // If no preferred match, accept the first valid offer
        offer_cryptos.first()
    }

    /// Generates keying material for a cipher suite.
    #[must_use]
    pub fn generate_keying_material(cipher: CipherSuite) -> Vec<u8> {
        use std::time::{SystemTime, UNIX_EPOCH};

        let length = cipher.keying_material_length();
        let mut material = vec![0u8; length];

        // Use timestamp-based pseudo-random generation
        // Note: In production, use a proper CSPRNG
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        for (i, byte) in material.iter_mut().enumerate() {
            // Use modulo to prevent shift overflow (128 bits in u128)
            let shift = (i * 8) % 128;
            *byte = ((timestamp >> shift) ^ (i as u128).wrapping_mul(17)) as u8;
        }

        material
    }
}

/// Extracts crypto attributes from SDP media description.
pub fn extract_crypto_attributes(sdp_lines: &[&str]) -> Vec<CryptoAttribute> {
    let mut cryptos = Vec::new();

    for line in sdp_lines {
        if let Some(crypto_value) = line.strip_prefix("a=crypto:") {
            if let Ok(crypto) = CryptoAttribute::parse(crypto_value) {
                cryptos.push(crypto);
            }
        }
    }

    cryptos
}

/// Checks if a transport protocol supports SDES.
#[must_use]
pub fn supports_sdes(protocol: &str) -> bool {
    let p = protocol.to_uppercase();
    p == "RTP/SAVP" || p == "RTP/SAVPF"
}

/// Checks if a transport protocol uses DTLS-SRTP.
#[must_use]
pub fn uses_dtls_srtp(protocol: &str) -> bool {
    let p = protocol.to_uppercase();
    p == "UDP/TLS/RTP/SAVP" || p == "UDP/TLS/RTP/SAVPF"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite_parsing() {
        assert_eq!(
            "AES_CM_128_HMAC_SHA1_80".parse::<CipherSuite>().unwrap(),
            CipherSuite::AesCm128HmacSha1_80
        );
        assert_eq!(
            "aes_cm_128_hmac_sha1_32".parse::<CipherSuite>().unwrap(),
            CipherSuite::AesCm128HmacSha1_32
        );
        assert_eq!(
            "AEAD_AES_256_GCM".parse::<CipherSuite>().unwrap(),
            CipherSuite::AeadAes256Gcm
        );
    }

    #[test]
    fn test_cipher_suite_display() {
        assert_eq!(
            CipherSuite::AesCm128HmacSha1_80.to_string(),
            "AES_CM_128_HMAC_SHA1_80"
        );
        assert_eq!(
            CipherSuite::AeadAes128Gcm.to_string(),
            "AEAD_AES_128_GCM"
        );
    }

    #[test]
    fn test_cipher_suite_properties() {
        let cipher = CipherSuite::AesCm128HmacSha1_80;
        assert_eq!(cipher.master_key_length(), 16);
        assert_eq!(cipher.master_salt_length(), 14);
        assert_eq!(cipher.keying_material_length(), 30);
        assert_eq!(cipher.auth_tag_bits(), 80);
        assert!(!cipher.is_aead());

        let gcm = CipherSuite::AeadAes256Gcm;
        assert_eq!(gcm.master_key_length(), 32);
        assert_eq!(gcm.master_salt_length(), 12);
        assert!(gcm.is_aead());
    }

    #[test]
    fn test_key_params_creation() {
        let key_material = vec![0u8; 30]; // 16 + 14 for AES_CM_128
        let params = KeyParams::new(key_material.clone())
            .with_lifetime(1 << 20)
            .with_mki(1, 4);

        assert_eq!(params.key_material(), &key_material);
        assert_eq!(params.lifetime(), Some(1 << 20));
        assert_eq!(params.mki_value(), Some(1));
        assert_eq!(params.mki_length(), Some(4));
    }

    #[test]
    fn test_key_params_base64() {
        // 30 bytes of keying material for AES_CM_128_HMAC_SHA1_80
        let base64_key = "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj";
        let params = KeyParams::from_base64(base64_key).unwrap();

        assert_eq!(params.key_material().len(), 30);
        assert!(params.validate_for_cipher(CipherSuite::AesCm128HmacSha1_80).is_ok());
    }

    #[test]
    fn test_key_params_master_key_salt() {
        let key_material = vec![1u8; 30];
        let params = KeyParams::new(key_material);

        let cipher = CipherSuite::AesCm128HmacSha1_80;
        let key = params.master_key(cipher).unwrap();
        let salt = params.master_salt(cipher).unwrap();

        assert_eq!(key.len(), 16);
        assert_eq!(salt.len(), 14);
    }

    #[test]
    fn test_crypto_attribute_parsing() {
        let attr_str = "1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^20";
        let crypto = CryptoAttribute::parse(attr_str).unwrap();

        assert_eq!(crypto.tag, 1);
        assert_eq!(crypto.cipher_suite, CipherSuite::AesCm128HmacSha1_80);
        assert_eq!(crypto.key_params.lifetime(), Some(1 << 20));
    }

    #[test]
    fn test_crypto_attribute_parsing_with_mki() {
        let attr_str = "2 AES_CM_128_HMAC_SHA1_32 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^31|1:4";
        let crypto = CryptoAttribute::parse(attr_str).unwrap();

        assert_eq!(crypto.tag, 2);
        assert_eq!(crypto.cipher_suite, CipherSuite::AesCm128HmacSha1_32);
        assert_eq!(crypto.key_params.lifetime(), Some(1 << 31));
        assert_eq!(crypto.key_params.mki_value(), Some(1));
        assert_eq!(crypto.key_params.mki_length(), Some(4));
    }

    #[test]
    fn test_crypto_attribute_display() {
        let key_material = vec![0u8; 30];
        let params = KeyParams::new(key_material);
        let crypto = CryptoAttribute::new(1, CipherSuite::AesCm128HmacSha1_80, params);

        let formatted = crypto.to_string();
        assert!(formatted.starts_with("1 AES_CM_128_HMAC_SHA1_80 inline:"));
    }

    #[test]
    fn test_crypto_attribute_validation() {
        let key_material = vec![0u8; 30];
        let params = KeyParams::new(key_material);
        let crypto = CryptoAttribute::new(1, CipherSuite::AesCm128HmacSha1_80, params);

        assert!(crypto.validate().is_ok());
    }

    #[test]
    fn test_crypto_attribute_validation_short_key() {
        let key_material = vec![0u8; 10]; // Too short
        let params = KeyParams::new(key_material);
        let crypto = CryptoAttribute::new(1, CipherSuite::AesCm128HmacSha1_80, params);

        assert!(crypto.validate().is_err());
    }

    #[test]
    fn test_session_params_parsing() {
        let params = SessionParams::parse("KDR=1 UNENCRYPTED_SRTCP WSH=64").unwrap();

        assert_eq!(params.kdr, Some(1));
        assert!(params.unencrypted_srtcp);
        assert!(!params.unencrypted_srtp);
        assert_eq!(params.wsh, Some(64));
    }

    #[test]
    fn test_session_params_display() {
        let mut params = SessionParams::new();
        params.kdr = Some(2);
        params.unencrypted_srtp = true;

        let formatted = params.to_string();
        assert!(formatted.contains("KDR=2"));
        assert!(formatted.contains("UNENCRYPTED_SRTP"));
    }

    #[test]
    fn test_srtp_negotiator_selection() {
        let negotiator = SrtpNegotiator::new();

        let key1 = KeyParams::new(vec![0u8; 30]);
        let key2 = KeyParams::new(vec![0u8; 30]);

        let offer = vec![
            CryptoAttribute::new(1, CipherSuite::AesCm128HmacSha1_32, key1),
            CryptoAttribute::new(2, CipherSuite::AesCm128HmacSha1_80, key2),
        ];

        // Should prefer AES_CM_128_HMAC_SHA1_80 over _32
        let selected = negotiator.select_crypto(&offer).unwrap();
        assert_eq!(selected.cipher_suite, CipherSuite::AesCm128HmacSha1_80);
    }

    #[test]
    fn test_extract_crypto_attributes() {
        let lines = vec![
            "m=audio 5000 RTP/SAVP 0",
            "a=rtpmap:0 PCMU/8000",
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj",
            "a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj",
        ];

        let cryptos = extract_crypto_attributes(&lines);
        assert_eq!(cryptos.len(), 2);
        assert_eq!(cryptos[0].tag, 1);
        assert_eq!(cryptos[1].tag, 2);
    }

    #[test]
    fn test_supports_sdes() {
        assert!(supports_sdes("RTP/SAVP"));
        assert!(supports_sdes("RTP/SAVPF"));
        assert!(supports_sdes("rtp/savp"));
        assert!(!supports_sdes("RTP/AVP"));
        assert!(!supports_sdes("UDP/TLS/RTP/SAVP"));
    }

    #[test]
    fn test_uses_dtls_srtp() {
        assert!(uses_dtls_srtp("UDP/TLS/RTP/SAVP"));
        assert!(uses_dtls_srtp("UDP/TLS/RTP/SAVPF"));
        assert!(!uses_dtls_srtp("RTP/SAVP"));
        assert!(!uses_dtls_srtp("RTP/AVP"));
    }

    #[test]
    fn test_keying_material_generation() {
        let material1 = SrtpNegotiator::generate_keying_material(CipherSuite::AesCm128HmacSha1_80);
        let material2 = SrtpNegotiator::generate_keying_material(CipherSuite::AeadAes256Gcm);

        assert_eq!(material1.len(), 30); // 16 + 14
        assert_eq!(material2.len(), 44); // 32 + 12
    }

    #[test]
    fn test_fec_order() {
        assert_eq!("FEC_SRTP".parse::<FecOrder>().unwrap(), FecOrder::FecSrtp);
        assert_eq!("SRTP_FEC".parse::<FecOrder>().unwrap(), FecOrder::SrtpFec);
        assert_eq!(FecOrder::FecSrtp.to_string(), "FEC_SRTP");
    }
}
