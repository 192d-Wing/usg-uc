//! Sensitive data types with automatic memory zeroization.
//!
//! These types ensure that sensitive credentials and secrets are securely
//! erased from memory when they go out of scope, preventing memory disclosure
//! attacks.

use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A PIN for smart card authentication.
///
/// The PIN is automatically zeroed from memory when dropped.
/// This type does not implement `Debug` or `Display` to prevent
/// accidental logging of the PIN.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SmartCardPin {
    pin: String,
}

impl SmartCardPin {
    /// Creates a new PIN from a string.
    pub fn new(pin: impl Into<String>) -> Self {
        Self { pin: pin.into() }
    }

    /// Returns the PIN value.
    ///
    /// # Security
    /// Be careful when using this method - the returned reference should
    /// not be logged or stored in non-zeroized storage.
    pub fn as_str(&self) -> &str {
        &self.pin
    }

    /// Returns the length of the PIN.
    pub const fn len(&self) -> usize {
        self.pin.len()
    }

    /// Returns whether the PIN is empty.
    pub const fn is_empty(&self) -> bool {
        self.pin.is_empty()
    }
}

impl fmt::Debug for SmartCardPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SmartCardPin([REDACTED, len={}])", self.pin.len())
    }
}

/// A session token for SIP/SRTP sessions.
///
/// Automatically zeroed from memory when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionToken {
    token: Vec<u8>,
}

impl SessionToken {
    /// Creates a new session token from bytes.
    pub fn new(token: impl Into<Vec<u8>>) -> Self {
        Self {
            token: token.into(),
        }
    }

    /// Creates an empty session token.
    pub const fn empty() -> Self {
        Self { token: Vec::new() }
    }

    /// Returns the token bytes.
    ///
    /// # Security
    /// Be careful when using this method - the returned slice should
    /// not be logged or stored in non-zeroized storage.
    pub fn as_bytes(&self) -> &[u8] {
        &self.token
    }

    /// Returns the length of the token.
    pub const fn len(&self) -> usize {
        self.token.len()
    }

    /// Returns whether the token is empty.
    pub const fn is_empty(&self) -> bool {
        self.token.is_empty()
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SessionToken([REDACTED, len={}])", self.token.len())
    }
}

impl Default for SessionToken {
    fn default() -> Self {
        Self::empty()
    }
}

/// SRTP keying material that is automatically zeroed when dropped.
///
/// Contains the master key and salt for SRTP encryption.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SrtpKeyMaterial {
    /// Master key (32 bytes for AES-256).
    master_key: Vec<u8>,
    /// Master salt (12 bytes).
    master_salt: Vec<u8>,
}

impl SrtpKeyMaterial {
    /// Creates new SRTP keying material.
    pub fn new(master_key: impl Into<Vec<u8>>, master_salt: impl Into<Vec<u8>>) -> Self {
        Self {
            master_key: master_key.into(),
            master_salt: master_salt.into(),
        }
    }

    /// Returns the master key.
    ///
    /// # Security
    /// This is sensitive cryptographic material. Handle with care.
    pub fn master_key(&self) -> &[u8] {
        &self.master_key
    }

    /// Returns the master salt.
    ///
    /// # Security
    /// This is sensitive cryptographic material. Handle with care.
    pub fn master_salt(&self) -> &[u8] {
        &self.master_salt
    }

    /// Returns the key length.
    pub const fn key_len(&self) -> usize {
        self.master_key.len()
    }

    /// Returns the salt length.
    pub const fn salt_len(&self) -> usize {
        self.master_salt.len()
    }

    /// Validates that the key material has correct sizes for AES-256-GCM.
    pub const fn is_valid_aes256(&self) -> bool {
        self.master_key.len() == 32 && self.master_salt.len() == 12
    }
}

impl fmt::Debug for SrtpKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SrtpKeyMaterial([REDACTED, key_len={}, salt_len={}])",
            self.master_key.len(),
            self.master_salt.len()
        )
    }
}

/// A sensitive string that is zeroed on drop.
///
/// Use this for any string that might contain sensitive data
/// that should not persist in memory.
#[derive(Clone, Default, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveString {
    #[serde(skip)]
    value: String,
}

impl SensitiveString {
    /// Creates a new sensitive string.
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Returns the string value.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Returns whether the string is empty.
    pub const fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// Returns the length of the string.
    pub const fn len(&self) -> usize {
        self.value.len()
    }
}

impl fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SensitiveString([REDACTED, len={}])", self.value.len())
    }
}

impl fmt::Display for SensitiveString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl From<String> for SensitiveString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SensitiveString {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smart_card_pin_redacted_debug() {
        let pin = SmartCardPin::new("1234");
        let debug = format!("{:?}", pin);
        assert!(!debug.contains("1234"));
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("len=4"));
    }

    #[test]
    fn test_smart_card_pin_access() {
        let pin = SmartCardPin::new("5678");
        assert_eq!(pin.as_str(), "5678");
        assert_eq!(pin.len(), 4);
        assert!(!pin.is_empty());
    }

    #[test]
    fn test_session_token_redacted_debug() {
        let token = SessionToken::new(vec![1, 2, 3, 4, 5]);
        let debug = format!("{:?}", token);
        assert!(!debug.contains("1"));
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("len=5"));
    }

    #[test]
    fn test_srtp_key_material_redacted_debug() {
        let key_material = SrtpKeyMaterial::new(vec![0u8; 32], vec![0u8; 12]);
        let debug = format!("{:?}", key_material);
        assert!(debug.contains("REDACTED"));
        assert!(debug.contains("key_len=32"));
        assert!(debug.contains("salt_len=12"));
    }

    #[test]
    fn test_srtp_key_material_validation() {
        let valid = SrtpKeyMaterial::new(vec![0u8; 32], vec![0u8; 12]);
        assert!(valid.is_valid_aes256());

        let invalid_key = SrtpKeyMaterial::new(vec![0u8; 16], vec![0u8; 12]);
        assert!(!invalid_key.is_valid_aes256());

        let invalid_salt = SrtpKeyMaterial::new(vec![0u8; 32], vec![0u8; 8]);
        assert!(!invalid_salt.is_valid_aes256());
    }

    #[test]
    fn test_sensitive_string_redacted_display() {
        let secret = SensitiveString::new("my_secret_value");
        assert_eq!(format!("{}", secret), "[REDACTED]");
        assert_eq!(secret.as_str(), "my_secret_value");
    }

    #[test]
    fn test_sensitive_string_from() {
        let from_string: SensitiveString = String::from("test").into();
        let from_str: SensitiveString = "test".into();

        assert_eq!(from_string.as_str(), "test");
        assert_eq!(from_str.as_str(), "test");
    }
}
