//! Data models for user management.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Default page size for [`UserFilter::limit`] at API layers.
pub const DEFAULT_PAGE_SIZE: u32 = 100;
/// Hard cap on rows returned by one `list_users` call. Stores clamp
/// `limit` to this and apply it when `limit` is `None`.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection)
pub const MAX_PAGE_SIZE: u32 = 1000;

/// A managed user account.
///
/// `Debug` is implemented by hand so `digest_ha1` (password-equivalent)
/// never reaches logs.
///
/// ## NIST 800-53 Rev5: IA-5(1)(c), SI-11
#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique user identifier (UUID).
    pub id: String,
    /// Login username (unique).
    pub username: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Email address.
    pub email: String,
    /// SIP Address of Record (e.g. `sip:user@example.mil`).
    pub sip_uri: String,
    /// Authentication method for this user.
    pub auth_type: AuthType,
    /// Pre-computed HA1 for SIP digest authentication.
    ///
    /// Never serialized: the HA1 is password-equivalent for SIP digest auth,
    /// and `User` is returned directly in sbc-api responses. Stores persist
    /// this via explicit column binding, not serde, so skipping it here is
    /// safe.
    #[serde(skip_serializing)]
    pub digest_ha1: Option<String>,
    /// X.509 Subject Distinguished Name for mTLS/PKI authentication.
    pub certificate_dn: Option<String>,
    /// X.509 Subject Alternative Name for mTLS/PKI authentication.
    pub certificate_san: Option<String>,
    /// Calling search space identifier for call routing.
    pub calling_search_space: Option<String>,
    /// Device identifiers associated with this user.
    pub device_ids: Vec<String>,
    /// Partition for multi-tenant isolation.
    pub partition: Option<String>,
    /// Whether the account is enabled.
    pub enabled: bool,
    /// Unix timestamp of account creation.
    pub created_at: i64,
    /// Unix timestamp of last account update.
    pub updated_at: i64,
    /// Unix timestamp of last successful login.
    pub last_login: Option<i64>,
    /// Arbitrary key-value metadata.
    pub metadata: HashMap<String, String>,
}

impl fmt::Debug for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("display_name", &self.display_name)
            .field("email", &self.email)
            .field("sip_uri", &self.sip_uri)
            .field("auth_type", &self.auth_type)
            .field(
                "digest_ha1",
                &self.digest_ha1.as_ref().map(|_| "<redacted>"),
            )
            .field("certificate_dn", &self.certificate_dn)
            .field("certificate_san", &self.certificate_san)
            .field("calling_search_space", &self.calling_search_space)
            .field("device_ids", &self.device_ids)
            .field("partition", &self.partition)
            .field("enabled", &self.enabled)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("last_login", &self.last_login)
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Authentication method for a user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthType {
    /// SIP digest authentication (username/password HA1).
    Digest,
    /// Mutual TLS with DoD PKI certificate.
    MtlsPki,
    /// Both digest and mTLS/PKI are accepted.
    Both,
}

/// A stored credential for a user.
///
/// `Debug` redacts `value` (it may be an HA1).
#[derive(Clone, Serialize, Deserialize)]
pub struct UserCredential {
    /// User this credential belongs to.
    pub user_id: String,
    /// Type of credential.
    pub credential_type: CredentialType,
    /// Credential value (HA1 hash, certificate fingerprint, or DN).
    pub value: String,
    /// SIP realm for digest credentials.
    pub realm: String,
    /// Unix timestamp of credential creation.
    pub created_at: i64,
}

impl fmt::Debug for UserCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserCredential")
            .field("user_id", &self.user_id)
            .field("credential_type", &self.credential_type)
            .field("value", &"<redacted>")
            .field("realm", &self.realm)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Type of stored credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialType {
    /// SHA-256 based HA1 digest hash.
    DigestHA1,
    /// X.509 certificate SHA-256 fingerprint.
    CertificateFingerprint,
    /// X.509 Subject Distinguished Name.
    CertificateDN,
}

/// Filter criteria for listing users.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserFilter {
    /// Substring match on username.
    pub username_contains: Option<String>,
    /// Filter by authentication type.
    pub auth_type: Option<AuthType>,
    /// Filter by calling search space.
    pub css_id: Option<String>,
    /// Filter by enabled/disabled status.
    pub enabled: Option<bool>,
    /// Maximum number of results to return; clamped to [`MAX_PAGE_SIZE`],
    /// which also applies when `None`.
    pub limit: Option<u32>,
    /// Number of results to skip (for pagination).
    pub offset: Option<u32>,
}

impl UserFilter {
    /// Effective `LIMIT` for a store query (SC-5 bound).
    #[must_use]
    pub fn effective_limit(&self) -> i64 {
        i64::from(self.limit.unwrap_or(MAX_PAGE_SIZE).min(MAX_PAGE_SIZE))
    }

    /// Effective `OFFSET` for a store query.
    #[must_use]
    pub fn effective_offset(&self) -> i64 {
        i64::from(self.offset.unwrap_or(0))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_ha1() {
        let u = User {
            id: "u-1".into(),
            username: "alice".into(),
            display_name: String::new(),
            email: String::new(),
            sip_uri: String::new(),
            auth_type: AuthType::Digest,
            digest_ha1: Some("deadbeefcafe".into()),
            certificate_dn: None,
            certificate_san: None,
            calling_search_space: None,
            device_ids: Vec::new(),
            partition: None,
            enabled: true,
            created_at: 0,
            updated_at: 0,
            last_login: None,
            metadata: HashMap::new(),
        };
        let d = format!("{u:?}");
        assert!(!d.contains("deadbeefcafe"), "{d}");
        assert!(d.contains("<redacted>") && d.contains("alice"), "{d}");
        let c = UserCredential {
            user_id: "u-1".into(),
            credential_type: CredentialType::DigestHA1,
            value: "deadbeefcafe".into(),
            realm: "r".into(),
            created_at: 0,
        };
        assert!(!format!("{c:?}").contains("deadbeefcafe"));
    }

    #[test]
    fn page_bounds() {
        let f = UserFilter::default();
        assert_eq!(f.effective_limit(), i64::from(MAX_PAGE_SIZE));
        assert_eq!(f.effective_offset(), 0);
        let f = UserFilter {
            limit: Some(u32::MAX),
            offset: Some(u32::MAX),
            ..UserFilter::default()
        };
        assert_eq!(f.effective_limit(), i64::from(MAX_PAGE_SIZE));
        assert_eq!(f.effective_offset(), i64::from(u32::MAX));
    }
}
