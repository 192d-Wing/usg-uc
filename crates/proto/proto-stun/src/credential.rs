//! RFC 5389 §10.2 Long-Term Credential Mechanism.
//!
//! This module implements the long-term credential mechanism for STUN
//! authentication, which uses username, password, realm, and nonce.
//!
//! ## RFC 5389 Compliance
//!
//! - **§10.2**: Long-Term Credential Mechanism
//! - **§15.4**: MESSAGE-INTEGRITY Computation
//!
//! ## Authentication Flow
//!
//! 1. Client sends request without credentials
//! 2. Server responds with 401 Unauthorized containing REALM and NONCE
//! 3. Client computes key from username:realm:password
//! 4. Client retries with USERNAME, REALM, NONCE, and MESSAGE-INTEGRITY
//! 5. Server validates MESSAGE-INTEGRITY using the same key derivation
//!
//! ## CNSA 2.0 Compliance
//!
//! This implementation uses SHA-384 for key derivation instead of MD5
//! as specified in RFC 5389 §15.4. This is a security-conscious deviation
//! for CNSA 2.0 compliance. Both endpoints must use this implementation
//! for interoperability.
//!
//! Key derivation: `SHA384(username ":" realm ":" password)`
//! MESSAGE-INTEGRITY: HMAC-SHA384 truncated to 20 bytes

use crate::attribute::StunAttribute;
use crate::error::{StunError, StunResult};
use crate::message::StunMessage;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default nonce validity duration (10 minutes per RFC 5389 recommendation).
pub const DEFAULT_NONCE_LIFETIME: Duration = Duration::from_secs(600);

/// Minimum nonce validity (should be at least one transaction round-trip).
pub const MIN_NONCE_LIFETIME: Duration = Duration::from_secs(30);

/// Long-term credentials for STUN authentication.
#[derive(Debug, Clone)]
pub struct LongTermCredentials {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
    /// Realm (optional, provided by server).
    pub realm: Option<String>,
    /// Nonce (optional, provided by server).
    pub nonce: Option<String>,
}

impl LongTermCredentials {
    /// Creates new long-term credentials.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            realm: None,
            nonce: None,
        }
    }

    /// Sets the realm (typically from server challenge).
    pub fn with_realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into());
        self
    }

    /// Sets the nonce (typically from server challenge).
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Updates credentials from a 401 challenge response.
    ///
    /// ## RFC 5389 §10.2.2 Receiving a 401 Response
    ///
    /// When receiving a 401, the client MUST look for REALM and NONCE
    /// attributes and use them in the retry.
    pub fn update_from_challenge(&mut self, response: &StunMessage) -> StunResult<()> {
        let mut found_realm = false;
        let mut found_nonce = false;

        for attr in &response.attributes {
            match attr {
                StunAttribute::Realm(realm) => {
                    self.realm = Some(realm.clone());
                    found_realm = true;
                }
                StunAttribute::Nonce(nonce) => {
                    self.nonce = Some(nonce.clone());
                    found_nonce = true;
                }
                _ => {}
            }
        }

        if !found_realm {
            return Err(StunError::AuthenticationFailed {
                reason: "401 response missing REALM attribute".to_string(),
            });
        }

        if !found_nonce {
            return Err(StunError::AuthenticationFailed {
                reason: "401 response missing NONCE attribute".to_string(),
            });
        }

        Ok(())
    }

    /// Computes the authentication key.
    ///
    /// ## CNSA 2.0 Key Derivation
    ///
    /// Instead of RFC 5389's MD5-based key derivation, this implementation
    /// uses SHA-384 for CNSA 2.0 compliance:
    /// `key = SHA384(username ":" realm ":" password)`
    ///
    /// Note: SASLprep is simplified here; full RFC 4013 compliance
    /// would require more complex Unicode normalization.
    pub fn compute_key(&self) -> StunResult<Vec<u8>> {
        let realm = self
            .realm
            .as_ref()
            .ok_or_else(|| StunError::AuthenticationFailed {
                reason: "realm required for long-term credential key".to_string(),
            })?;

        // SHA384(username:realm:password) for CNSA 2.0 compliance
        let input = format!("{}:{}:{}", self.username, realm, self.password);
        let key = uc_crypto::hash::sha384(input.as_bytes());

        Ok(key.to_vec())
    }

    /// Adds authentication attributes to a message.
    ///
    /// ## RFC 5389 §10.2.1 Forming a Request
    ///
    /// The request MUST include USERNAME, REALM, NONCE, and
    /// MESSAGE-INTEGRITY attributes.
    pub fn add_to_message(&self, msg: &mut StunMessage) -> StunResult<()> {
        let realm = self
            .realm
            .as_ref()
            .ok_or_else(|| StunError::AuthenticationFailed {
                reason: "realm required".to_string(),
            })?;

        let nonce = self
            .nonce
            .as_ref()
            .ok_or_else(|| StunError::AuthenticationFailed {
                reason: "nonce required".to_string(),
            })?;

        msg.add_attribute(StunAttribute::Username(self.username.clone()));
        msg.add_attribute(StunAttribute::Realm(realm.clone()));
        msg.add_attribute(StunAttribute::Nonce(nonce.clone()));

        Ok(())
    }
}

/// Result of authentication validation.
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication succeeded.
    Success,
    /// Authentication required (send 401).
    ChallengeRequired {
        /// Realm to send in challenge.
        realm: String,
        /// Nonce to send in challenge.
        nonce: String,
    },
    /// Authentication failed (send 401).
    Failed {
        /// Reason for failure.
        reason: String,
    },
    /// Stale nonce (send 438 Stale Nonce).
    StaleNonce {
        /// New nonce to send.
        new_nonce: String,
    },
}

/// Long-term credential validator for servers.
///
/// ## RFC 5389 §10.2.3 Receiving a Request
///
/// Server validates:
/// 1. MESSAGE-INTEGRITY is present
/// 2. USERNAME, REALM, NONCE are present
/// 3. Nonce is valid and not stale
/// 4. MESSAGE-INTEGRITY is correct
#[derive(Debug)]
pub struct LongTermCredentialValidator {
    /// Server realm.
    realm: String,
    /// Nonce lifetime.
    nonce_lifetime: Duration,
    /// Nonce secret for generating/validating nonces.
    nonce_secret: [u8; 32],
}

impl LongTermCredentialValidator {
    /// Creates a new validator with the given realm.
    pub fn new(realm: impl Into<String>) -> StunResult<Self> {
        let mut nonce_secret = [0u8; 32];
        uc_crypto::random::fill_random(&mut nonce_secret).map_err(|_| {
            StunError::AuthenticationFailed {
                reason: "failed to generate nonce secret".to_string(),
            }
        })?;

        Ok(Self {
            realm: realm.into(),
            nonce_lifetime: DEFAULT_NONCE_LIFETIME,
            nonce_secret,
        })
    }

    /// Creates a validator with a specific nonce secret (for testing or clustering).
    pub fn with_nonce_secret(realm: impl Into<String>, secret: [u8; 32]) -> Self {
        Self {
            realm: realm.into(),
            nonce_lifetime: DEFAULT_NONCE_LIFETIME,
            nonce_secret: secret,
        }
    }

    /// Sets the nonce lifetime.
    pub fn with_nonce_lifetime(mut self, lifetime: Duration) -> Self {
        self.nonce_lifetime = lifetime.max(MIN_NONCE_LIFETIME);
        self
    }

    /// Returns the realm.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Generates a new nonce.
    ///
    /// ## Nonce Format
    ///
    /// The nonce encodes the creation timestamp and a signature:
    /// `{timestamp}:{signature}`
    ///
    /// Where signature = HMAC-SHA256(secret, timestamp)[:16] (hex)
    pub fn generate_nonce(&self) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let timestamp_str = timestamp.to_string();
        let sig = self.compute_nonce_signature(&timestamp_str);

        format!("{}:{}", timestamp_str, sig)
    }

    /// Validates a nonce and checks if it's stale.
    ///
    /// Returns `Ok(true)` if valid and not stale,
    /// `Ok(false)` if stale (signature valid but expired),
    /// `Err` if invalid signature.
    pub fn validate_nonce(&self, nonce: &str) -> StunResult<bool> {
        let (timestamp_str, sig) =
            nonce
                .split_once(':')
                .ok_or_else(|| StunError::AuthenticationFailed {
                    reason: "invalid nonce format".to_string(),
                })?;

        // Verify signature
        let expected_sig = self.compute_nonce_signature(timestamp_str);
        if sig != expected_sig {
            return Err(StunError::AuthenticationFailed {
                reason: "invalid nonce signature".to_string(),
            });
        }

        // Check timestamp
        let timestamp: u64 =
            timestamp_str
                .parse()
                .map_err(|_| StunError::AuthenticationFailed {
                    reason: "invalid nonce timestamp".to_string(),
                })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let age = now.saturating_sub(timestamp);
        Ok(age < self.nonce_lifetime.as_secs())
    }

    fn compute_nonce_signature(&self, timestamp: &str) -> String {
        let hmac = uc_crypto::hash::hmac_sha384(&self.nonce_secret, timestamp.as_bytes());
        hex_encode(&hmac[..8])
    }

    /// Validates a request message.
    ///
    /// ## RFC 5389 §10.2.3 Receiving a Request
    ///
    /// 1. Check for MESSAGE-INTEGRITY
    /// 2. Check for USERNAME, REALM, NONCE
    /// 3. Validate nonce
    /// 4. Look up user's password
    /// 5. Validate MESSAGE-INTEGRITY
    pub fn validate_request<F>(
        &self,
        msg: &StunMessage,
        raw_data: &[u8],
        password_lookup: F,
    ) -> AuthResult
    where
        F: FnOnce(&str) -> Option<String>,
    {
        // Check for MESSAGE-INTEGRITY
        let integrity = msg.attributes.iter().find_map(|a| {
            if let StunAttribute::MessageIntegrity(data) = a {
                Some(data.clone())
            } else {
                None
            }
        });

        let Some(received_integrity) = integrity else {
            // No authentication - require challenge
            return AuthResult::ChallengeRequired {
                realm: self.realm.clone(),
                nonce: self.generate_nonce(),
            };
        };

        // Extract credentials from message
        let username = msg.attributes.iter().find_map(|a| {
            if let StunAttribute::Username(u) = a {
                Some(u.clone())
            } else {
                None
            }
        });

        let realm = msg.attributes.iter().find_map(|a| {
            if let StunAttribute::Realm(r) = a {
                Some(r.clone())
            } else {
                None
            }
        });

        let nonce = msg.attributes.iter().find_map(|a| {
            if let StunAttribute::Nonce(n) = a {
                Some(n.clone())
            } else {
                None
            }
        });

        // Validate required attributes
        let Some(username) = username else {
            return AuthResult::Failed {
                reason: "missing USERNAME attribute".to_string(),
            };
        };

        let Some(realm) = realm else {
            return AuthResult::Failed {
                reason: "missing REALM attribute".to_string(),
            };
        };

        let Some(nonce) = nonce else {
            return AuthResult::Failed {
                reason: "missing NONCE attribute".to_string(),
            };
        };

        // Validate realm matches
        if realm != self.realm {
            return AuthResult::Failed {
                reason: format!("realm mismatch: expected '{}', got '{}'", self.realm, realm),
            };
        }

        // Validate nonce
        match self.validate_nonce(&nonce) {
            Ok(true) => {}
            Ok(false) => {
                // Stale nonce
                return AuthResult::StaleNonce {
                    new_nonce: self.generate_nonce(),
                };
            }
            Err(_) => {
                return AuthResult::Failed {
                    reason: "invalid nonce".to_string(),
                };
            }
        }

        // Look up password
        let Some(password) = password_lookup(&username) else {
            return AuthResult::Failed {
                reason: "unknown user".to_string(),
            };
        };

        // Compute expected MESSAGE-INTEGRITY
        let creds = LongTermCredentials::new(&username, &password)
            .with_realm(&realm)
            .with_nonce(&nonce);

        let key = match creds.compute_key() {
            Ok(k) => k,
            Err(_) => {
                return AuthResult::Failed {
                    reason: "failed to compute key".to_string(),
                };
            }
        };

        // Verify MESSAGE-INTEGRITY
        if verify_message_integrity(raw_data, &key, &received_integrity) {
            AuthResult::Success
        } else {
            AuthResult::Failed {
                reason: "MESSAGE-INTEGRITY validation failed".to_string(),
            }
        }
    }

    /// Creates a 401 Unauthorized response with REALM and NONCE.
    pub fn create_challenge_response(&self, request: &StunMessage) -> StunMessage {
        let mut response = StunMessage::binding_error(request, 401, "Unauthorized");
        response.add_attribute(StunAttribute::Realm(self.realm.clone()));
        response.add_attribute(StunAttribute::Nonce(self.generate_nonce()));
        response
    }

    /// Creates a 438 Stale Nonce response.
    pub fn create_stale_nonce_response(&self, request: &StunMessage) -> StunMessage {
        let mut response = StunMessage::binding_error(request, 438, "Stale Nonce");
        response.add_attribute(StunAttribute::Realm(self.realm.clone()));
        response.add_attribute(StunAttribute::Nonce(self.generate_nonce()));
        response
    }
}

/// Verifies MESSAGE-INTEGRITY against the raw message data.
///
/// ## RFC 5389 §15.4
///
/// The MESSAGE-INTEGRITY is computed over the STUN message, starting
/// with the header, up to (but not including) the MESSAGE-INTEGRITY
/// attribute. The length field in the header is adjusted to point to
/// the end of the MESSAGE-INTEGRITY attribute.
fn verify_message_integrity(raw_data: &[u8], key: &[u8], received: &[u8]) -> bool {
    // Find MESSAGE-INTEGRITY attribute offset
    // The MESSAGE-INTEGRITY should be at the end (before optional FINGERPRINT)
    if raw_data.len() < 20 {
        return false;
    }

    // MESSAGE-INTEGRITY is 24 bytes (4 header + 20 value)
    // We need to find where it starts
    let integrity_attr_size = 24;

    // Check if there's a FINGERPRINT after MESSAGE-INTEGRITY
    let has_fingerprint = raw_data.len() >= 20 + integrity_attr_size + 8;

    let integrity_offset = if has_fingerprint {
        raw_data.len() - integrity_attr_size - 8
    } else {
        raw_data.len() - integrity_attr_size
    };

    if integrity_offset < 20 {
        return false;
    }

    // Create message copy with adjusted length
    let mut adjusted = raw_data[..integrity_offset].to_vec();

    // Adjust length to include MESSAGE-INTEGRITY but not FINGERPRINT
    let new_len = (integrity_offset - 20 + integrity_attr_size) as u16;
    adjusted[2] = (new_len >> 8) as u8;
    adjusted[3] = new_len as u8;

    // Compute HMAC
    let hmac = uc_crypto::hash::hmac_sha384(key, &adjusted);

    // Compare (truncated to 20 bytes for compatibility)
    if received.len() != 20 {
        return false;
    }

    // Constant-time comparison
    let mut result = 0u8;
    for (a, b) in hmac[..20].iter().zip(received.iter()) {
        result |= a ^ b;
    }
    result == 0
}

/// Encodes bytes as lowercase hex.
fn hex_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 2);
    for byte in data {
        use std::fmt::Write;
        let _ = write!(result, "{:02x}", byte);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::StunMessageType;

    #[test]
    fn test_long_term_credentials_key() {
        let creds = LongTermCredentials::new("user", "password").with_realm("realm.example.com");

        let key = creds.compute_key().unwrap();
        // SHA384("user:realm.example.com:password") - CNSA 2.0 compliant
        assert_eq!(key.len(), 48); // SHA384 produces 48 bytes
    }

    #[test]
    fn test_credentials_require_realm() {
        let creds = LongTermCredentials::new("user", "password");
        assert!(creds.compute_key().is_err());
    }

    #[test]
    fn test_update_from_challenge() {
        let mut creds = LongTermCredentials::new("user", "password");

        // Create 401 response with REALM and NONCE
        let mut response = StunMessage::new(StunMessageType::binding_error(), [0u8; 12]);
        response.add_attribute(StunAttribute::ErrorCode {
            code: 401,
            reason: "Unauthorized".to_string(),
        });
        response.add_attribute(StunAttribute::Realm("example.com".to_string()));
        response.add_attribute(StunAttribute::Nonce("abc123".to_string()));

        creds.update_from_challenge(&response).unwrap();

        assert_eq!(creds.realm.as_deref(), Some("example.com"));
        assert_eq!(creds.nonce.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_update_from_challenge_missing_realm() {
        let mut creds = LongTermCredentials::new("user", "password");

        let mut response = StunMessage::new(StunMessageType::binding_error(), [0u8; 12]);
        response.add_attribute(StunAttribute::Nonce("abc123".to_string()));

        let result = creds.update_from_challenge(&response);
        assert!(result.is_err());
    }

    #[test]
    fn test_validator_generate_nonce() {
        let validator = LongTermCredentialValidator::with_nonce_secret("example.com", [0u8; 32]);

        let nonce = validator.generate_nonce();
        assert!(nonce.contains(':'));

        // Nonce should be valid
        assert!(validator.validate_nonce(&nonce).unwrap());
    }

    #[test]
    fn test_validator_invalid_nonce_signature() {
        let validator = LongTermCredentialValidator::with_nonce_secret("example.com", [0u8; 32]);

        // Create nonce with wrong signature
        let fake_nonce = "12345:badsignature";
        assert!(validator.validate_nonce(fake_nonce).is_err());
    }

    #[test]
    fn test_validator_stale_nonce() {
        let validator = LongTermCredentialValidator::with_nonce_secret("example.com", [0u8; 32])
            .with_nonce_lifetime(Duration::from_secs(1));

        // Create nonce with old timestamp
        let old_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(100);

        let timestamp_str = old_timestamp.to_string();
        let sig = uc_crypto::hash::hmac_sha384(&[0u8; 32], timestamp_str.as_bytes());
        let old_nonce = format!("{}:{}", timestamp_str, hex_encode(&sig[..8]));

        // Should be stale (valid signature but expired)
        let result = validator.validate_nonce(&old_nonce);
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_validator_challenge_response() {
        let validator = LongTermCredentialValidator::with_nonce_secret("example.com", [0u8; 32]);

        let request = StunMessage::new(StunMessageType::binding_request(), [0u8; 12]);

        let response = validator.create_challenge_response(&request);

        // Should have REALM and NONCE
        let has_realm = response
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::Realm(_)));
        let has_nonce = response
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::Nonce(_)));

        assert!(has_realm);
        assert!(has_nonce);
    }

    #[test]
    fn test_validate_request_no_integrity() {
        let validator = LongTermCredentialValidator::with_nonce_secret("example.com", [0u8; 32]);

        let request = StunMessage::new(StunMessageType::binding_request(), [0u8; 12]);

        let result = validator.validate_request(&request, &[], |_| Some("password".to_string()));

        assert!(matches!(result, AuthResult::ChallengeRequired { .. }));
    }

    #[test]
    fn test_add_to_message() {
        let creds = LongTermCredentials::new("user", "password")
            .with_realm("example.com")
            .with_nonce("abc123");

        let mut msg = StunMessage::new(StunMessageType::binding_request(), [0u8; 12]);

        creds.add_to_message(&mut msg).unwrap();

        // Should have USERNAME, REALM, NONCE
        let has_username = msg
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::Username(_)));
        let has_realm = msg
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::Realm(_)));
        let has_nonce = msg
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::Nonce(_)));

        assert!(has_username);
        assert!(has_realm);
        assert!(has_nonce);
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
    }
}
