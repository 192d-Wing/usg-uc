//! JWKS fetch + cache for OIDC bearer-token validation.
//!
//! Key handling follows docs/CLIENT-PROVISIONING-OIDC.md: cache the key
//! set, refresh when an unknown `kid` shows up (rate-limited), and keep
//! serving with the cached set if the `IdP` is briefly unreachable — `IdP`
//! downtime must not take down config fetches for already-signed tokens.

use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{Jwk, JwkSet};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Floor between consecutive fetch attempts, so a flood of bogus-`kid`
/// tokens can't turn this pod into an `IdP` load generator.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Errors raised while resolving a signing key.
#[derive(Debug, Error)]
pub enum JwksError {
    /// The `IdP` could not be reached (or answered non-2xx) and there is no
    /// usable cached key set.
    #[error("jwks unavailable: {0}")]
    Unavailable(String),
    /// The OIDC discovery document was malformed or for the wrong issuer.
    #[error("oidc metadata invalid: {0}")]
    Metadata(String),
    /// No key with the requested `kid`, even after a refresh.
    #[error("no signing key with kid `{0}`")]
    UnknownKid(String),
}

/// Subset of the OIDC discovery document we consume.
#[derive(serde::Deserialize)]
struct OidcMetadata {
    issuer: String,
    jwks_uri: String,
}

#[derive(Default)]
struct CacheState {
    keys: Option<JwkSet>,
    last_attempt: Option<Instant>,
}

/// Cached JWKS for one OIDC issuer.
pub struct JwksCache {
    http: reqwest::Client,
    issuer: String,
    state: RwLock<CacheState>,
}

impl JwksCache {
    /// New cache for `issuer`; nothing is fetched until first use (or
    /// [`JwksCache::refresh`] at startup).
    pub fn new(http: reqwest::Client, issuer: impl Into<String>) -> Self {
        Self {
            http,
            issuer: issuer.into(),
            state: RwLock::new(CacheState::default()),
        }
    }

    /// Cache preloaded with a static key set and no issuer to fetch from.
    /// Intended for tests in this crate and in downstream consumers.
    #[must_use]
    pub fn with_static(keys: JwkSet) -> Self {
        Self {
            http: reqwest::Client::new(),
            issuer: String::new(),
            state: RwLock::new(CacheState {
                keys: Some(keys),
                last_attempt: Some(Instant::now()),
            }),
        }
    }

    /// True once a key set is cached. Used by `/readyz`.
    pub async fn ready(&self) -> bool {
        self.state.read().await.keys.is_some()
    }

    /// Returns the JWK for `kid`, refreshing the cached set (rate-limited)
    /// when the kid is unknown — that's what a routine `IdP` key rotation
    /// looks like from here.
    ///
    /// # Errors
    /// [`JwksError::UnknownKid`] if no key matches even after a refresh, or
    /// [`JwksError::Unavailable`] / [`JwksError::Metadata`] if the refresh
    /// itself failed and no key set is cached.
    pub async fn get_key(&self, kid: &str) -> Result<Jwk, JwksError> {
        if let Some(jwk) = self.find(kid).await {
            return Ok(jwk);
        }
        self.refresh().await?;
        self.find(kid)
            .await
            .ok_or_else(|| JwksError::UnknownKid(kid.to_string()))
    }

    async fn find(&self, kid: &str) -> Option<Jwk> {
        let state = self.state.read().await;
        state.keys.as_ref().and_then(|set| set.find(kid)).cloned()
    }

    /// Fetches OIDC metadata + JWKS from the issuer. On failure the cached
    /// set (if any) stays in service. Rate-limited to one attempt per
    /// [`MIN_REFRESH_INTERVAL`].
    ///
    /// # Errors
    /// [`JwksError::Unavailable`] or [`JwksError::Metadata`] when the fetch
    /// fails and there is no cached key set to fall back on.
    pub async fn refresh(&self) -> Result<(), JwksError> {
        if self.issuer.is_empty() {
            return Ok(()); // static cache — nothing to fetch
        }
        let mut state = self.state.write().await;
        if let Some(at) = state.last_attempt
            && at.elapsed() < MIN_REFRESH_INTERVAL
        {
            // Someone just tried; don't hammer the IdP again. That's fine
            // when a key set is cached, but with an empty cache this must
            // stay an error — otherwise /readyz reports ready for the
            // whole rate-limit window after a failed startup prefetch.
            return if state.keys.is_some() {
                Ok(())
            } else {
                Err(JwksError::Unavailable(
                    "fetch recently failed; retry pending".to_string(),
                ))
            };
        }
        state.last_attempt = Some(Instant::now());

        match self.fetch().await {
            Ok(set) => {
                info!(issuer = %self.issuer, keys = set.keys.len(), "JWKS refreshed");
                state.keys = Some(set);
                Ok(())
            }
            Err(e) => {
                if state.keys.is_some() {
                    warn!(issuer = %self.issuer, error = %e, "JWKS refresh failed; serving cached set");
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn fetch(&self) -> Result<JwkSet, JwksError> {
        let metadata_url = format!("{}/.well-known/openid-configuration", self.issuer);
        let metadata: OidcMetadata = self
            .http
            .get(&metadata_url)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| JwksError::Unavailable(e.to_string()))?
            .json()
            .await
            .map_err(|e| JwksError::Metadata(e.to_string()))?;

        // The metadata's issuer claim must round-trip exactly (OIDC
        // Discovery 1.0 §4.3) — a mismatch means we're being pointed at
        // someone else's keys.
        if metadata.issuer.trim_end_matches('/') != self.issuer {
            return Err(JwksError::Metadata(format!(
                "issuer mismatch: expected {}, metadata says {}",
                self.issuer, metadata.issuer
            )));
        }

        self.http
            .get(&metadata.jwks_uri)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| JwksError::Unavailable(e.to_string()))?
            .json()
            .await
            .map_err(|e| JwksError::Metadata(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Regression: a rate-limited refresh with an empty cache must stay an
    /// error. Returning Ok(()) here made /readyz report ready for the whole
    /// rate-limit window after a failed startup prefetch (caught by the
    /// first container smoke test against an unreachable `IdP`).
    #[tokio::test]
    async fn rate_limited_refresh_without_keys_stays_an_error() {
        // Nothing listens on port 1 — connection refused, immediately.
        let cache = JwksCache::new(reqwest::Client::new(), "https://127.0.0.1:1");

        assert!(cache.refresh().await.is_err(), "real fetch failure");
        // Second call lands inside MIN_REFRESH_INTERVAL: rate-limited, and
        // with no cached key set it must still be an error.
        assert!(cache.refresh().await.is_err(), "rate-limited + empty cache");
        assert!(!cache.ready().await);
    }
}
