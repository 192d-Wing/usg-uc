//! Error type for the provisioning / sign-in flow.

use thiserror::Error;

/// Failures across discovery, OIDC, and config fetch.
#[derive(Debug, Error)]
pub enum ProvisioningError {
    /// Generic HTTP/transport failure (client build, discovery GETs).
    #[error("http error: {0}")]
    Http(String),
    /// Discovery document fetch/validation failed.
    #[error("discovery failed: {0}")]
    Discovery(String),
    /// The discovery document's issuer is not trusted for the entered domain.
    #[error("issuer not trusted: {0}")]
    IssuerNotTrusted(String),
    /// Sign-in was not completed in time (the device code expired).
    #[error("timed out: {0}")]
    Timeout(String),
    /// The `state` returned by the IdP did not match what we sent (possible
    /// CSRF / mix-up).
    #[error("oauth state mismatch")]
    StateMismatch,
    /// Authorization failed: the user denied the device grant, the IdP
    /// lacks the device authorization endpoint, or (code flow) the IdP
    /// redirected with an `error` parameter.
    #[error("authorization failed: {0}")]
    Authorization(String),
    /// Token exchange or refresh failed.
    #[error("token exchange failed: {0}")]
    TokenExchange(String),
    /// `/v1/client-config` returned 401 — the access token is expired or
    /// invalid; refresh and retry once.
    #[error("config endpoint returned 401 (token expired/invalid)")]
    Unauthorized,
    /// `/v1/client-config` failed for a non-401 reason.
    #[error("client-config fetch failed: {0}")]
    Config(String),
    /// A response body did not match the expected JSON schema.
    #[error("invalid response body: {0}")]
    Json(String),
}

impl ProvisioningError {
    /// Re-labels a generic [`ProvisioningError::Http`]/[`ProvisioningError::Json`]
    /// from a discovery-phase GET as a [`ProvisioningError::Discovery`], so the
    /// UI can show a phase-specific message. Other variants pass through.
    #[must_use]
    pub fn into_discovery(self) -> Self {
        match self {
            Self::Http(m) | Self::Json(m) => Self::Discovery(m),
            other => other,
        }
    }
}
