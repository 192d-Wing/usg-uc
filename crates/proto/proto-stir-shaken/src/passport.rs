//! PASSporT (Personal Assertion Token) implementation.
//!
//! Per RFC 8225, a PASSporT is a JWT-like token containing caller identity claims.

use crate::PASSPORT_ALGORITHM;
use crate::error::{StirShakenError, StirShakenResult};
use std::time::{SystemTime, UNIX_EPOCH};

/// Attestation level per SHAKEN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attestation {
    /// Full attestation (A).
    ///
    /// The originating service provider (OSP):
    /// - Has a direct authenticated relationship with the customer
    /// - Has verified the customer is authorized to use the calling number
    Full,

    /// Partial attestation (B).
    ///
    /// The OSP:
    /// - Has a direct authenticated relationship with the customer
    /// - Has NOT verified authorization for the calling number
    Partial,

    /// Gateway attestation (C).
    ///
    /// The OSP:
    /// - Has received the call from a gateway
    /// - Cannot authenticate the originator
    Gateway,
}

impl Attestation {
    /// Returns the attestation indicator string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "A",
            Self::Partial => "B",
            Self::Gateway => "C",
        }
    }

    /// Parses from string.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(s: &str) -> StirShakenResult<Self> {
        match s.to_uppercase().as_str() {
            "A" => Ok(Self::Full),
            "B" => Ok(Self::Partial),
            "C" => Ok(Self::Gateway),
            _ => Err(StirShakenError::AttestationError {
                reason: format!("Unknown attestation level: {s}"),
            }),
        }
    }
}

impl std::fmt::Display for Attestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Origination identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrigId(String);

impl OrigId {
    /// Creates a new origination ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generates a unique origination ID.
    pub fn generate() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Self(format!("{timestamp:x}"))
    }

    /// Returns the ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for OrigId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// PASSporT header.
#[derive(Debug, Clone)]
pub struct PASSporTHeader {
    /// Algorithm (must be ES384 for CNSA 2.0).
    pub alg: String,
    /// Type (always "passport").
    pub typ: String,
    /// PPT extension (e.g., "shaken").
    pub ppt: Option<String>,
    /// X.509 URL for certificate.
    pub x5u: Option<String>,
}

impl PASSporTHeader {
    /// Creates a new header with CNSA 2.0 compliant defaults.
    pub fn new() -> Self {
        Self {
            alg: PASSPORT_ALGORITHM.to_string(),
            typ: "passport".to_string(),
            ppt: Some("shaken".to_string()),
            x5u: None,
        }
    }

    /// Sets the certificate URL.
    #[must_use]
    pub fn with_x5u(mut self, url: impl Into<String>) -> Self {
        self.x5u = Some(url.into());
        self
    }

    /// Validates the header.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn validate(&self) -> StirShakenResult<()> {
        // CNSA 2.0: Only ES384 is allowed
        if self.alg != PASSPORT_ALGORITHM {
            return Err(StirShakenError::InvalidAlgorithm {
                algorithm: self.alg.clone(),
            });
        }

        if self.typ != "passport" {
            return Err(StirShakenError::InvalidPASSporT {
                reason: format!("Invalid type: expected 'passport', got '{}'", self.typ),
            });
        }

        Ok(())
    }
}

impl Default for PASSporTHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// Telephone number identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelephoneNumber {
    /// Number in E.164 format (without '+' prefix).
    number: String,
}

impl TelephoneNumber {
    /// Creates a new telephone number.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn new(number: impl Into<String>) -> StirShakenResult<Self> {
        let number = number.into();
        let normalized = Self::normalize(&number);

        // Basic validation
        if normalized.is_empty() {
            return Err(StirShakenError::InvalidPhoneNumber {
                number,
                reason: "Empty number".to_string(),
            });
        }

        if !normalized.chars().all(|c| c.is_ascii_digit()) {
            return Err(StirShakenError::InvalidPhoneNumber {
                number,
                reason: "Contains non-digit characters".to_string(),
            });
        }

        Ok(Self { number: normalized })
    }

    /// Normalizes a phone number.
    fn normalize(number: &str) -> String {
        number.chars().filter(char::is_ascii_digit).collect()
    }

    /// Returns the number.
    pub fn as_str(&self) -> &str {
        &self.number
    }

    /// Returns as URI format.
    pub fn to_uri(&self) -> String {
        format!("tel:+{}", self.number)
    }
}

impl std::fmt::Display for TelephoneNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "+{}", self.number)
    }
}

/// PASSporT claims.
#[derive(Debug, Clone)]
pub struct PASSporTClaims {
    /// Attestation level.
    pub attest: Attestation,
    /// Destination telephone numbers.
    pub dest: Vec<TelephoneNumber>,
    /// Issued at time (Unix timestamp).
    pub iat: u64,
    /// Originating telephone number.
    pub orig: TelephoneNumber,
    /// Origination ID (unique per call).
    pub origid: OrigId,
}

impl PASSporTClaims {
    /// Creates new claims.
    pub fn new(orig: TelephoneNumber, dest: Vec<TelephoneNumber>, attest: Attestation) -> Self {
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            attest,
            dest,
            iat,
            orig,
            origid: OrigId::generate(),
        }
    }

    /// Sets the origination ID.
    #[must_use]
    pub fn with_origid(mut self, origid: OrigId) -> Self {
        self.origid = origid;
        self
    }

    /// Sets the issued-at time.
    #[must_use]
    pub fn with_iat(mut self, iat: u64) -> Self {
        self.iat = iat;
        self
    }

    /// Validates the claims.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn validate(&self, max_age_seconds: u64) -> StirShakenResult<()> {
        // Check expiration
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now > self.iat {
            let age = now - self.iat;
            if age > max_age_seconds {
                return Err(StirShakenError::Expired {
                    age_seconds: age,
                    max_age: max_age_seconds,
                });
            }
        }

        // Must have at least one destination
        if self.dest.is_empty() {
            return Err(StirShakenError::MissingField {
                field: "dest".to_string(),
            });
        }

        Ok(())
    }

    /// Returns the age in seconds.
    pub fn age_seconds(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now.saturating_sub(self.iat)
    }
}

/// PASSporT token.
#[derive(Debug, Clone)]
pub struct PASSporT {
    /// Header.
    header: PASSporTHeader,
    /// Claims.
    claims: PASSporTClaims,
    /// Signature (base64url encoded).
    signature: Option<String>,
}

impl PASSporT {
    /// Creates a new unsigned PASSporT.
    pub fn new(header: PASSporTHeader, claims: PASSporTClaims) -> Self {
        Self {
            header,
            claims,
            signature: None,
        }
    }

    /// Creates a PASSporT with default header.
    #[must_use]
    pub fn with_claims(claims: PASSporTClaims) -> Self {
        Self::new(PASSporTHeader::new(), claims)
    }

    /// Returns the header.
    pub fn header(&self) -> &PASSporTHeader {
        &self.header
    }

    /// Returns the claims.
    pub fn claims(&self) -> &PASSporTClaims {
        &self.claims
    }

    /// Returns the signature.
    pub fn signature(&self) -> Option<&str> {
        self.signature.as_deref()
    }

    /// Sets the signature.
    pub fn set_signature(&mut self, signature: impl Into<String>) {
        self.signature = Some(signature.into());
    }

    /// Returns whether the PASSporT is signed.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Validates the PASSporT structure.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn validate(&self, max_age_seconds: u64) -> StirShakenResult<()> {
        self.header.validate()?;
        self.claims.validate(max_age_seconds)?;
        Ok(())
    }

    /// Returns the originating number.
    pub fn orig(&self) -> &TelephoneNumber {
        &self.claims.orig
    }

    /// Returns the destination numbers.
    pub fn dest(&self) -> &[TelephoneNumber] {
        &self.claims.dest
    }

    /// Returns the attestation level.
    pub fn attestation(&self) -> Attestation {
        self.claims.attest
    }

    /// Returns the origination ID.
    pub fn origid(&self) -> &OrigId {
        &self.claims.origid
    }

    /// Returns the certificate URL.
    pub fn certificate_url(&self) -> Option<&str> {
        self.header.x5u.as_deref()
    }

    /// Encodes header for signing (base64url without padding).
    pub fn encode_header(&self) -> String {
        // Simplified JSON encoding for header
        let json = self.header.ppt.as_ref().map_or_else(
            || {
                format!(
                    r#"{{"alg":"{}","typ":"{}"}}"#,
                    self.header.alg, self.header.typ
                )
            },
            |ppt| {
                format!(
                    r#"{{"alg":"{}","typ":"{}","ppt":"{}"}}"#,
                    self.header.alg, self.header.typ, ppt
                )
            },
        );

        base64url_encode(json.as_bytes())
    }

    /// Encodes claims for signing (base64url without padding).
    pub fn encode_claims(&self) -> String {
        // Build dest array
        let dest_json: Vec<String> = self
            .claims
            .dest
            .iter()
            .map(|d| format!(r#"{{"tn":"{}"}}"#, d.as_str()))
            .collect();

        let json = format!(
            r#"{{"attest":"{}","dest":{{"tn":[{}]}},"iat":{},"orig":{{"tn":"{}"}},"origid":"{}"}}"#,
            self.claims.attest,
            dest_json.join(","),
            self.claims.iat,
            self.claims.orig.as_str(),
            self.claims.origid
        );

        base64url_encode(json.as_bytes())
    }

    /// Returns the signing input (header.claims).
    pub fn signing_input(&self) -> String {
        format!("{}.{}", self.encode_header(), self.encode_claims())
    }

    /// Encodes as compact serialization (header.claims.signature).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn to_compact(&self) -> StirShakenResult<String> {
        let signature = self
            .signature
            .as_ref()
            .ok_or_else(|| StirShakenError::MissingField {
                field: "signature".to_string(),
            })?;

        Ok(format!("{}.{}", self.signing_input(), signature))
    }
}

/// Base64url encodes data without padding.
fn base64url_encode(data: &[u8]) -> String {
    use std::collections::HashMap;

    // Standard base64 alphabet
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL_SAFE: &[(u8, u8)] = &[(b'+', b'-'), (b'/', b'_')];

    let url_map: HashMap<u8, u8> = URL_SAFE.iter().copied().collect();

    let mut result = String::new();

    for chunk in data.chunks(3) {
        let mut n = 0u32;
        for (i, &byte) in chunk.iter().enumerate() {
            n |= (byte as u32) << (16 - 8 * i);
        }

        let padding = 3 - chunk.len();
        let output_len = 4 - padding;

        for i in 0..output_len {
            let idx = ((n >> (18 - 6 * i)) & 0x3f) as usize;
            let mut c = ALPHABET[idx];
            if let Some(&replacement) = url_map.get(&c) {
                c = replacement;
            }
            result.push(c as char);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation() {
        assert_eq!(Attestation::Full.as_str(), "A");
        assert_eq!(Attestation::Partial.as_str(), "B");
        assert_eq!(Attestation::Gateway.as_str(), "C");

        assert_eq!(Attestation::parse("a").unwrap(), Attestation::Full);
        assert_eq!(Attestation::parse("B").unwrap(), Attestation::Partial);
        assert!(Attestation::parse("X").is_err());
    }

    #[test]
    fn test_telephone_number() {
        let num = TelephoneNumber::new("+1-555-123-4567").unwrap();
        assert_eq!(num.as_str(), "15551234567");
        assert_eq!(num.to_uri(), "tel:+15551234567");

        // Invalid: empty
        assert!(TelephoneNumber::new("").is_err());

        // Invalid: letters
        assert!(TelephoneNumber::new("abc").is_err());
    }

    #[test]
    fn test_origid() {
        let id = OrigId::new("test-id");
        assert_eq!(id.as_str(), "test-id");

        let generated = OrigId::generate();
        assert!(!generated.as_str().is_empty());
    }

    #[test]
    fn test_passport_header() {
        let header = PASSporTHeader::new();
        assert_eq!(header.alg, "ES384");
        assert_eq!(header.typ, "passport");
        header.validate().unwrap();

        // Invalid algorithm
        let mut bad_header = PASSporTHeader::new();
        bad_header.alg = "ES256".to_string();
        assert!(bad_header.validate().is_err());
    }

    #[test]
    fn test_passport_claims() {
        let orig = TelephoneNumber::new("15551234567").unwrap();
        let dest = vec![TelephoneNumber::new("15559876543").unwrap()];
        let claims = PASSporTClaims::new(orig, dest, Attestation::Full);

        assert_eq!(claims.attest, Attestation::Full);
        assert!(claims.iat > 0);
        claims.validate(60).unwrap();
    }

    #[test]
    fn test_passport_creation() {
        let orig = TelephoneNumber::new("15551234567").unwrap();
        let dest = vec![TelephoneNumber::new("15559876543").unwrap()];
        let claims = PASSporTClaims::new(orig, dest, Attestation::Full);

        let passport = PASSporT::with_claims(claims);
        assert!(!passport.is_signed());
        assert_eq!(passport.attestation(), Attestation::Full);
    }

    #[test]
    fn test_passport_encoding() {
        let orig = TelephoneNumber::new("15551234567").unwrap();
        let dest = vec![TelephoneNumber::new("15559876543").unwrap()];
        let claims = PASSporTClaims::new(orig, dest, Attestation::Full)
            .with_iat(1234567890)
            .with_origid(OrigId::new("test-origid"));

        let passport = PASSporT::with_claims(claims);

        let header_enc = passport.encode_header();
        assert!(!header_enc.is_empty());
        assert!(!header_enc.contains('=')); // No padding

        let claims_enc = passport.encode_claims();
        assert!(!claims_enc.is_empty());

        let signing_input = passport.signing_input();
        assert!(signing_input.contains('.'));
    }

    #[test]
    fn test_passport_compact() {
        let orig = TelephoneNumber::new("15551234567").unwrap();
        let dest = vec![TelephoneNumber::new("15559876543").unwrap()];
        let claims = PASSporTClaims::new(orig, dest, Attestation::Full);

        let mut passport = PASSporT::with_claims(claims);

        // Without signature, compact should fail
        assert!(passport.to_compact().is_err());

        // With signature
        passport.set_signature("test-signature");
        let compact = passport.to_compact().unwrap();
        assert_eq!(compact.matches('.').count(), 2); // header.claims.signature
    }

    #[test]
    fn test_base64url_encode() {
        let result = base64url_encode(b"hello");
        assert!(!result.contains('+'));
        assert!(!result.contains('/'));
        assert!(!result.contains('='));
    }

    #[test]
    fn test_passport_header_with_x5u() {
        let header = PASSporTHeader::new().with_x5u("https://cert.example.com/cert.pem");

        assert_eq!(
            header.x5u.as_deref(),
            Some("https://cert.example.com/cert.pem")
        );
    }
}
