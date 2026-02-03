//! SIP Identity header handling per RFC 8224.

use crate::error::{StirShakenError, StirShakenResult};
use crate::passport::PASSporT;

/// Identity info parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityInfo {
    /// URL to retrieve the signing certificate.
    Url(String),
}

impl std::fmt::Display for IdentityInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Url(url) => write!(f, "<{}>", url),
        }
    }
}

/// SIP Identity header value.
#[derive(Debug, Clone)]
pub struct IdentityHeader {
    /// PASSporT token (base64url encoded).
    token: String,
    /// Info parameter (certificate URL).
    info: IdentityInfo,
    /// Algorithm parameter.
    alg: String,
    /// PPT extension.
    ppt: String,
}

impl IdentityHeader {
    /// Creates a new Identity header.
    pub fn new(token: impl Into<String>, info: IdentityInfo) -> Self {
        Self {
            token: token.into(),
            info,
            alg: "ES384".to_string(),
            ppt: "shaken".to_string(),
        }
    }

    /// Creates from a PASSporT.
    pub fn from_passport(passport: &PASSporT) -> StirShakenResult<Self> {
        let token = passport.to_compact()?;

        let info = passport
            .certificate_url()
            .map(|url| IdentityInfo::Url(url.to_string()))
            .ok_or(StirShakenError::MissingField {
                field: "x5u".to_string(),
            })?;

        Ok(Self::new(token, info))
    }

    /// Returns the token.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Returns the info parameter.
    pub fn info(&self) -> &IdentityInfo {
        &self.info
    }

    /// Returns the algorithm.
    pub fn alg(&self) -> &str {
        &self.alg
    }

    /// Returns the PPT extension.
    pub fn ppt(&self) -> &str {
        &self.ppt
    }

    /// Formats as SIP header value.
    pub fn to_header_value(&self) -> String {
        format!(
            "{};info={};alg={};ppt={}",
            self.token, self.info, self.alg, self.ppt
        )
    }

    /// Parses from SIP header value.
    pub fn parse(value: &str) -> StirShakenResult<Self> {
        // Find the token (everything before first ';')
        let parts: Vec<&str> = value.splitn(2, ';').collect();
        if parts.is_empty() {
            return Err(StirShakenError::InvalidPASSporT {
                reason: "Empty Identity header".to_string(),
            });
        }

        let token = parts[0].trim().to_string();

        // Parse parameters
        let mut info: Option<IdentityInfo> = None;
        let mut alg = "ES384".to_string();
        let mut ppt = "shaken".to_string();

        if parts.len() > 1 {
            for param in parts[1].split(';') {
                let param = param.trim();
                if let Some(pos) = param.find('=') {
                    let name = param[..pos].trim().to_lowercase();
                    let value = param[pos + 1..].trim();

                    match name.as_str() {
                        "info" => {
                            // Remove angle brackets if present
                            let url = value.trim_start_matches('<').trim_end_matches('>');
                            info = Some(IdentityInfo::Url(url.to_string()));
                        }
                        "alg" => {
                            alg = value.to_string();
                        }
                        "ppt" => {
                            ppt = value.to_string();
                        }
                        _ => {} // Ignore unknown parameters
                    }
                }
            }
        }

        let info = info.ok_or(StirShakenError::MissingField {
            field: "info".to_string(),
        })?;

        // Validate algorithm (CNSA 2.0)
        if alg != "ES384" {
            return Err(StirShakenError::InvalidAlgorithm { algorithm: alg });
        }

        Ok(Self {
            token,
            info,
            alg,
            ppt,
        })
    }
}

/// Full identity information combining header and parsed PASSporT.
#[derive(Debug)]
pub struct Identity {
    /// The Identity header.
    header: IdentityHeader,
    /// Certificate URL.
    certificate_url: String,
}

impl Identity {
    /// Creates a new identity.
    pub fn new(header: IdentityHeader) -> Self {
        let certificate_url = match &header.info {
            IdentityInfo::Url(url) => url.clone(),
        };

        Self {
            header,
            certificate_url,
        }
    }

    /// Returns the Identity header.
    pub fn header(&self) -> &IdentityHeader {
        &self.header
    }

    /// Returns the certificate URL.
    pub fn certificate_url(&self) -> &str {
        &self.certificate_url
    }

    /// Returns the token.
    pub fn token(&self) -> &str {
        self.header.token()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passport::{Attestation, OrigId, PASSporTClaims, PASSporTHeader, TelephoneNumber};

    #[test]
    fn test_identity_info() {
        let info = IdentityInfo::Url("https://cert.example.com/cert.pem".to_string());
        assert_eq!(info.to_string(), "<https://cert.example.com/cert.pem>");
    }

    #[test]
    fn test_identity_header_creation() {
        let header = IdentityHeader::new(
            "test-token",
            IdentityInfo::Url("https://cert.example.com/cert.pem".to_string()),
        );

        assert_eq!(header.token(), "test-token");
        assert_eq!(header.alg(), "ES384");
        assert_eq!(header.ppt(), "shaken");
    }

    #[test]
    fn test_identity_header_format() {
        let header = IdentityHeader::new(
            "test.token.signature",
            IdentityInfo::Url("https://cert.example.com/cert.pem".to_string()),
        );

        let value = header.to_header_value();
        assert!(value.contains("test.token.signature"));
        assert!(value.contains("info="));
        assert!(value.contains("alg=ES384"));
        assert!(value.contains("ppt=shaken"));
    }

    #[test]
    fn test_identity_header_parse() {
        let value =
            "header.claims.sig;info=<https://cert.example.com/cert.pem>;alg=ES384;ppt=shaken";
        let header = IdentityHeader::parse(value).unwrap();

        assert_eq!(header.token(), "header.claims.sig");
        assert_eq!(header.alg(), "ES384");
        assert_eq!(header.ppt(), "shaken");

        let IdentityInfo::Url(url) = header.info();
        assert_eq!(url, "https://cert.example.com/cert.pem");
    }

    #[test]
    fn test_identity_header_parse_invalid_alg() {
        let value = "token;info=<https://example.com>;alg=ES256;ppt=shaken";
        assert!(IdentityHeader::parse(value).is_err());
    }

    #[test]
    fn test_identity_header_parse_missing_info() {
        let value = "token;alg=ES384";
        assert!(IdentityHeader::parse(value).is_err());
    }

    #[test]
    fn test_identity_from_passport() {
        let orig = TelephoneNumber::new("15551234567").unwrap();
        let dest = vec![TelephoneNumber::new("15559876543").unwrap()];
        let claims = PASSporTClaims::new(orig, dest, Attestation::Full)
            .with_iat(1234567890)
            .with_origid(OrigId::new("test-id"));

        let header = PASSporTHeader::new().with_x5u("https://cert.example.com/cert.pem");

        let mut passport = PASSporT::new(header, claims);
        passport.set_signature("test-signature");

        let identity_header = IdentityHeader::from_passport(&passport).unwrap();
        assert!(!identity_header.token().is_empty());
    }

    #[test]
    fn test_identity() {
        let header = IdentityHeader::new(
            "test-token",
            IdentityInfo::Url("https://cert.example.com/cert.pem".to_string()),
        );

        let identity = Identity::new(header);
        assert_eq!(
            identity.certificate_url(),
            "https://cert.example.com/cert.pem"
        );
        assert_eq!(identity.token(), "test-token");
    }
}
