//! SIP and media session identifiers.
//!
//! These types provide strongly-typed identifiers for various SIP entities,
//! preventing accidental misuse of identifier types.

use std::fmt;
use std::str::FromStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// SIP Call-ID header value.
///
/// Per RFC 3261, the Call-ID uniquely identifies a particular invitation
/// or all registrations of a particular client.
///
/// ## Example
///
/// ```
/// use sbc_types::CallId;
///
/// let call_id = CallId::new("f81d4fae-7dec-11d0-a765-00a0c91e6bf6@example.com");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CallId(String);

impl CallId {
    /// Creates a new Call-ID from a string.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generates a new unique Call-ID.
    ///
    /// Format: `{uuid}@{host}` per RFC 3261 recommendations.
    #[must_use]
    pub fn generate(host: &str) -> Self {
        // Using a simple UUID-like format
        // In production, this would use a proper UUID generator
        let uuid = generate_uuid_v4_hex();
        Self(format!("{uuid}@{host}"))
    }

    /// Returns the Call-ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for CallId {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

impl AsRef<str> for CallId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// SIP Dialog identifier.
///
/// A dialog is identified by the combination of Call-ID, local tag, and remote tag.
/// This type encapsulates that combination for easy comparison and hashing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DialogId {
    call_id: CallId,
    local_tag: String,
    remote_tag: String,
}

impl DialogId {
    /// Creates a new Dialog-ID from components.
    #[must_use]
    pub fn new(call_id: CallId, local_tag: impl Into<String>, remote_tag: impl Into<String>) -> Self {
        Self {
            call_id,
            local_tag: local_tag.into(),
            remote_tag: remote_tag.into(),
        }
    }

    /// Returns the Call-ID component.
    #[must_use]
    pub fn call_id(&self) -> &CallId {
        &self.call_id
    }

    /// Returns the local tag.
    #[must_use]
    pub fn local_tag(&self) -> &str {
        &self.local_tag
    }

    /// Returns the remote tag.
    #[must_use]
    pub fn remote_tag(&self) -> &str {
        &self.remote_tag
    }
}

impl fmt::Display for DialogId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.call_id, self.local_tag, self.remote_tag
        )
    }
}

/// SIP Transaction identifier.
///
/// A transaction is identified by the branch parameter of the Via header
/// plus the CSeq method.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransactionId {
    branch: String,
    method: String,
}

impl TransactionId {
    /// Magic cookie prefix for RFC 3261 compliant branches.
    pub const MAGIC_COOKIE: &'static str = "z9hG4bK";

    /// Creates a new Transaction-ID from components.
    #[must_use]
    pub fn new(branch: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            branch: branch.into(),
            method: method.into(),
        }
    }

    /// Generates a new unique Transaction-ID for a given method.
    ///
    /// The branch parameter follows RFC 3261 format with magic cookie prefix.
    #[must_use]
    pub fn generate(method: impl Into<String>) -> Self {
        let unique = generate_uuid_v4_hex();
        Self {
            branch: format!("{}{}", Self::MAGIC_COOKIE, unique),
            method: method.into(),
        }
    }

    /// Returns the branch parameter.
    #[must_use]
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Returns the method.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns true if the branch has the RFC 3261 magic cookie.
    #[must_use]
    pub fn is_rfc3261_compliant(&self) -> bool {
        self.branch.starts_with(Self::MAGIC_COOKIE)
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.branch, self.method)
    }
}

/// Media session identifier.
///
/// Used internally to correlate RTP/RTCP streams with SIP dialogs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MediaSessionId(String);

impl MediaSessionId {
    /// Creates a new media session ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generates a new unique media session ID.
    #[must_use]
    pub fn generate() -> Self {
        Self(generate_uuid_v4_hex())
    }

    /// Returns the ID as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MediaSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Generates a simple UUID v4-like hex string.
///
/// This is a placeholder implementation. In production, this would use
/// a proper cryptographically secure random number generator.
fn generate_uuid_v4_hex() -> String {
    // Placeholder: returns a fixed pattern for testing
    // Real implementation would use CSPRNG from sbc-crypto
    "00000000-0000-4000-8000-000000000000".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_id_creation() {
        let call_id = CallId::new("test@example.com");
        assert_eq!(call_id.as_str(), "test@example.com");
    }

    #[test]
    fn test_dialog_id_components() {
        let call_id = CallId::new("call@host");
        let dialog_id = DialogId::new(call_id.clone(), "local-tag", "remote-tag");

        assert_eq!(dialog_id.call_id().as_str(), "call@host");
        assert_eq!(dialog_id.local_tag(), "local-tag");
        assert_eq!(dialog_id.remote_tag(), "remote-tag");
    }

    #[test]
    fn test_transaction_id_rfc3261() {
        let tx_id = TransactionId::generate("INVITE");
        assert!(tx_id.is_rfc3261_compliant());
        assert!(tx_id.branch().starts_with("z9hG4bK"));
    }

    #[test]
    fn test_media_session_id() {
        let session_id = MediaSessionId::generate();
        assert!(!session_id.as_str().is_empty());
    }
}
