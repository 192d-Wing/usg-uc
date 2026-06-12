//! Wire types for the discovery document, OIDC metadata, client-config, and
//! token responses.
//!
//! These deliberately mirror the `Serialize` shapes emitted by
//! `sbc-client-config-server` (`crates/sbc/sbc-client-config-server/src/handlers.rs`)
//! and the IdP. Optional/forward-compat fields use `#[serde(default)]` and we
//! never `deny_unknown_fields`, so a newer server can add fields without
//! breaking older clients.

use serde::Deserialize;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------
// discovery.v1 — GET /.well-known/sip-client-config
// ---------------------------------------------------------------------

/// The discovery document a POP serves at `/.well-known/sip-client-config`.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryDoc {
    /// Schema version (currently `1`).
    pub schema_version: u32,
    /// Human-readable service name, shown on the sign-in screen.
    #[serde(default)]
    pub service_name: String,
    /// Point-of-presence identifier.
    pub pop_id: String,
    /// OIDC parameters the client uses to authenticate.
    pub oidc: DiscoveryOidc,
    /// Where to fetch the per-user config after authenticating.
    pub provisioning: DiscoveryProvisioning,
    /// Minimum client versions per platform (advisory).
    #[serde(default)]
    pub minimum_client_version: BTreeMap<String, String>,
}

/// OIDC block of the discovery document.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryOidc {
    /// OIDC issuer URL; the client fetches `{issuer}/.well-known/openid-configuration`.
    pub issuer: String,
    /// Public client id for the Authorization Code + PKCE flow.
    pub client_id: String,
    /// Scopes to request (e.g. `openid profile offline_access sip`).
    pub scopes: Vec<String>,
}

/// Provisioning block of the discovery document.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryProvisioning {
    /// Absolute URL of the per-user `/v1/client-config` endpoint.
    pub config_endpoint: String,
}

// ---------------------------------------------------------------------
// OIDC discovery metadata — {issuer}/.well-known/openid-configuration
// ---------------------------------------------------------------------

/// Subset of the OIDC provider metadata the client needs.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcMetadata {
    /// The issuer (must round-trip with the requested issuer).
    pub issuer: String,
    /// Authorization endpoint (browser).
    pub authorization_endpoint: String,
    /// Token endpoint (code exchange + refresh).
    pub token_endpoint: String,
    /// End-session endpoint, used on sign-out when present.
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    /// Token revocation endpoint (RFC 7009), used on sign-out when present.
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
}

// ---------------------------------------------------------------------
// Token endpoint response
// ---------------------------------------------------------------------

/// Response from the OIDC token endpoint (code exchange or refresh).
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    /// The access token (JWT) used as the SIP bearer credential.
    pub access_token: String,
    /// Refresh token (when `offline_access` was granted); may rotate.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// ID token (JWT); used to verify the `nonce`.
    #[serde(default)]
    pub id_token: Option<String>,
    /// Access-token lifetime in seconds.
    #[serde(default)]
    pub expires_in: Option<u64>,
    /// Token type (`Bearer`).
    #[serde(default)]
    pub token_type: Option<String>,
}

// ---------------------------------------------------------------------
// client-config.v1 — GET /v1/client-config
// ---------------------------------------------------------------------

/// Per-user SIP configuration returned by the provisioning endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// Schema version (currently `1`).
    pub schema_version: u32,
    /// User identity (display name / email), if provided.
    #[serde(default)]
    pub user: Option<UserInfo>,
    /// SIP identity and auth mode.
    pub sip: SipIdentity,
    /// Registration parameters.
    pub registration: Registration,
    /// Media policy (codecs/DTMF/SRTP), advisory.
    #[serde(default)]
    pub media: Option<Media>,
    /// Feature flags (voicemail URI, MWI, …), opaque here.
    #[serde(default)]
    pub features: Option<serde_json::Value>,
    /// When to re-fetch this config without re-authenticating, seconds.
    pub ttl_seconds: u32,
}

/// User identity block.
#[derive(Debug, Clone, Deserialize)]
pub struct UserInfo {
    /// Display name.
    #[serde(default)]
    pub display_name: String,
    /// Email address.
    #[serde(default)]
    pub email: Option<String>,
}

/// SIP identity block.
#[derive(Debug, Clone, Deserialize)]
pub struct SipIdentity {
    /// SIP URI (`sip:<dn>@<domain>`).
    pub uri: String,
    /// Directory number (the AOR user part).
    pub dn: String,
    /// Short extension, if any.
    #[serde(default)]
    pub extension: Option<String>,
    /// SIP domain.
    pub domain: String,
    /// Authentication mode + optional ephemeral digest creds.
    pub auth: SipAuth,
}

/// Auth block of the SIP identity.
#[derive(Debug, Clone, Deserialize)]
pub struct SipAuth {
    /// `"bearer"` or `"ephemeral-digest"`.
    pub mode: String,
    /// Populated only when `mode == "ephemeral-digest"`.
    #[serde(default)]
    pub digest: Option<DigestCreds>,
}

/// Short-lived digest credentials (ephemeral-digest mode).
#[derive(Debug, Clone, Deserialize)]
pub struct DigestCreds {
    /// Digest username.
    pub username: String,
    /// One-time digest password.
    pub password: String,
    /// Digest realm.
    pub realm: String,
    /// RFC 3339 expiry.
    pub expires_at: String,
}

/// Registration parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct Registration {
    /// REGISTER `Expires`, seconds.
    pub expires_seconds: u32,
    /// POP-scoped registrar domain (resolved via RFC 3263 NAPTR/SRV).
    pub registrar_domain: String,
}

/// Media policy block.
#[derive(Debug, Clone, Deserialize)]
pub struct Media {
    /// Preferred codecs, in order.
    #[serde(default)]
    pub codecs: Vec<String>,
    /// DTMF mode (`rfc4733` / `inband` / `info`).
    #[serde(default)]
    pub dtmf: Option<String>,
    /// SRTP mode (`none` / `sdes` / `dtls`).
    #[serde(default)]
    pub srtp: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The exact JSON `sbc-client-config-server` emits must deserialize.
    /// Keep this fixture in sync with that server's handler tests.
    #[test]
    fn client_config_matches_server_shape() {
        let json = serde_json::json!({
            "schema_version": 1,
            "user": { "display_name": "Jane Doe", "email": "jdoe@example.mil" },
            "sip": {
                "uri": "sip:1455550100@example.mil",
                "dn": "1455550100",
                "domain": "example.mil",
                "auth": { "mode": "bearer", "digest": null }
            },
            "registration": { "expires_seconds": 300, "registrar_domain": "us-east-1.reg.example.mil" },
            "media": { "codecs": ["opus", "pcmu"], "dtmf": "rfc4733", "srtp": "none" },
            "features": { "voicemail_uri": "sip:*97@example.mil", "mwi": true },
            "ttl_seconds": 3600
        });
        let cfg: ClientConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.sip.dn, "1455550100");
        assert_eq!(cfg.sip.uri, "sip:1455550100@example.mil");
        assert_eq!(cfg.sip.auth.mode, "bearer");
        assert!(cfg.sip.auth.digest.is_none());
        assert_eq!(cfg.registration.expires_seconds, 300);
        assert_eq!(
            cfg.registration.registrar_domain,
            "us-east-1.reg.example.mil"
        );
        assert_eq!(cfg.ttl_seconds, 3600);
    }

    #[test]
    fn discovery_matches_server_shape() {
        let json = serde_json::json!({
            "schema_version": 1,
            "service_name": "USG UC",
            "pop_id": "oopl-001",
            "oidc": {
                "issuer": "https://icam.oopl.dev.mil/realms/dcim",
                "client_id": "usg-uc-softclient",
                "scopes": ["openid", "profile", "offline_access", "sip"]
            },
            "provisioning": { "config_endpoint": "https://sbc.oopl.dev.mil/v1/client-config" },
            "minimum_client_version": { "desktop": "0.4.0" }
        });
        let doc: DiscoveryDoc = serde_json::from_value(json).unwrap();
        assert_eq!(doc.oidc.issuer, "https://icam.oopl.dev.mil/realms/dcim");
        assert_eq!(doc.oidc.client_id, "usg-uc-softclient");
        assert_eq!(
            doc.provisioning.config_endpoint,
            "https://sbc.oopl.dev.mil/v1/client-config"
        );
        assert_eq!(
            doc.minimum_client_version
                .get("desktop")
                .map(String::as_str),
            Some("0.4.0")
        );
    }
}
