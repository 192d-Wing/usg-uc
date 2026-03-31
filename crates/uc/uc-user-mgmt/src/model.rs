//! Data models for user management.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A managed user account.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Maximum number of results to return.
    pub limit: Option<u32>,
    /// Number of results to skip (for pagination).
    pub offset: Option<u32>,
}
