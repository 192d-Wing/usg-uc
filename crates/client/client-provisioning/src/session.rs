//! Sign-in session state — the in-memory machine plus the small non-secret
//! slice that is persisted to `settings.toml`.
//!
//! Secrets (access/refresh tokens) live only in memory here, wrapped in
//! [`zeroize::Zeroizing`]; the refresh token is persisted separately in the OS
//! keychain by `client-core`, never in this struct's serialized form.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::wire::{ClientConfig, DiscoveryDoc, OidcMetadata};

/// The client's sign-in lifecycle (mirrors the design doc state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    /// No service domain yet — show the sign-in screen.
    #[default]
    NeedsDomain,
    /// Fetching the discovery document.
    Discovering,
    /// Browser auth in progress (waiting on the loopback redirect).
    Authenticating,
    /// Fetching `/v1/client-config` with the access token.
    Provisioning,
    /// Provisioned and (attempting to) register.
    Registered,
    /// Silently refreshing the access token.
    Refreshing,
    /// A terminal error the UI should surface.
    Error,
}

/// In-memory session, owned by the app state. Not serialized wholesale.
#[derive(Default)]
pub struct ProvisionedSession {
    /// Current lifecycle state.
    pub state: SessionState,
    /// Service domain the user entered.
    pub service_domain: String,
    /// Cached discovery document.
    pub discovery: Option<DiscoveryDoc>,
    /// Cached OIDC provider metadata.
    pub oidc_meta: Option<OidcMetadata>,
    /// Current access token (JWT).
    pub access_token: Option<Zeroizing<String>>,
    /// Current refresh token (memory only; zeroized on drop).
    pub refresh_token: Option<Zeroizing<String>>,
    /// Absolute access-token expiry.
    pub access_expires_at: Option<DateTime<Utc>>,
    /// Access-token lifetime in seconds (for the half-life refresh policy).
    pub access_lifetime_secs: Option<u64>,
    /// Last fetched per-user config.
    pub config: Option<ClientConfig>,
    /// When the config was fetched (for `ttl_seconds` re-fetch).
    pub config_fetched_at: Option<DateTime<Utc>>,
    /// Last error message, when `state == Error`.
    pub error: Option<String>,
    /// The user accepted the untrusted-CA warning for this app run;
    /// provisioning HTTP skips server-certificate verification. Never
    /// persisted — reset on sign-out and at every launch.
    pub accept_untrusted_ca: bool,
}

impl ProvisionedSession {
    /// True when the access token is missing or within `skew` seconds of
    /// expiry — i.e. a refresh is due.
    #[must_use]
    pub fn needs_refresh(&self, now: DateTime<Utc>, skew_secs: i64) -> bool {
        self.access_expires_at.map_or_else(
            || self.access_token.is_some(),
            |exp| now + chrono::Duration::seconds(skew_secs) >= exp,
        )
    }

    /// Skew for the half-life refresh policy: half the access-token
    /// lifetime, floored at 30 seconds (defaults to half of 300s when the
    /// IdP didn't report `expires_in`).
    #[must_use]
    pub fn refresh_skew_secs(&self) -> i64 {
        let half = self.access_lifetime_secs.unwrap_or(300) / 2;
        i64::try_from(half.max(30)).unwrap_or(150)
    }

    /// True when the cached config is older than its TTL and should be
    /// re-fetched (no browser needed).
    #[must_use]
    pub fn config_expired(&self, now: DateTime<Utc>) -> bool {
        match (self.config.as_ref(), self.config_fetched_at) {
            (Some(cfg), Some(at)) => {
                now >= at + chrono::Duration::seconds(i64::from(cfg.ttl_seconds))
            }
            _ => false,
        }
    }
}

/// Non-secret session slice persisted in `settings.toml`. The refresh token
/// itself is NOT here — only a flag noting it lives in the keychain.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedProvisioning {
    /// Service domain to resume from on next launch.
    #[serde(default)]
    pub service_domain: String,
    /// Whether a refresh token is stored in the OS keychain for silent resume.
    #[serde(default)]
    pub refresh_token_persisted: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn needs_refresh_within_skew() {
        let now = DateTime::<Utc>::from_timestamp(1_000_000, 0).unwrap();
        let mut s = ProvisionedSession {
            access_token: Some(Zeroizing::new("t".into())),
            ..Default::default()
        };
        s.access_expires_at = Some(now + chrono::Duration::seconds(20));
        assert!(s.needs_refresh(now, 30), "20s left, 30s skew → refresh");
        assert!(!s.needs_refresh(now, 10), "20s left, 10s skew → ok");
    }
}
