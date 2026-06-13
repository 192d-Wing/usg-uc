//! Access-token acquisition for the central API.
//!
//! The agent authenticates to `central-config-api` with an OIDC bearer
//! token carrying the `config-sync` scope and this site's `site_code`
//! claim. Two sources are supported:
//!
//! - [`Auth::Static`] — a pre-issued token from the environment. Simple,
//!   but the token expires and rotation means a pod restart. Used in tests
//!   and for break-glass.
//! - [`Auth::Oidc`] — the `OAuth2` **client-credentials** grant: the agent
//!   exchanges a per-site client id/secret for an access token at the
//!   token endpoint and refreshes it before expiry. This is the
//!   production path — secret rotation in Keycloak takes effect without a
//!   restart.

use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::Mutex;

use crate::error::{SyncError, SyncResult};

/// Refresh this long before the token actually expires, to avoid using a
/// token that lapses mid-request.
const REFRESH_MARGIN: Duration = Duration::from_secs(30);

/// How the agent obtains its bearer token for the central API.
pub enum Auth {
    /// A fixed, pre-issued token (env `SYNC_BEARER_TOKEN`).
    Static(String),
    /// Client-credentials: fetch and refresh from the token endpoint.
    Oidc(TokenProvider),
}

impl Auth {
    /// The current bearer token to present on a request.
    ///
    /// # Errors
    /// [`SyncError::Central`] if a token fetch fails.
    pub async fn bearer(&self) -> SyncResult<String> {
        match self {
            Self::Static(t) => Ok(t.clone()),
            Self::Oidc(p) => p.token().await,
        }
    }
}

/// `OAuth2` client-credentials token provider with a refresh-ahead cache.
pub struct TokenProvider {
    http: reqwest::Client,
    token_url: String,
    client_id: String,
    client_secret: String,
    scope: String,
    cached: Mutex<Option<Cached>>,
}

struct Cached {
    token: String,
    /// When this cached token should be considered stale (already minus the
    /// refresh margin).
    refresh_at: Instant,
}

/// The token endpoint's success response (RFC 6749 §5.1).
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl TokenProvider {
    /// New provider against `token_url` using the given client credentials
    /// and scope.
    #[must_use]
    pub fn new(
        http: reqwest::Client,
        token_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            http,
            token_url: token_url.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scope: scope.into(),
            cached: Mutex::new(None),
        }
    }

    /// A valid token, fetching or refreshing if the cache is empty/stale.
    /// The lock is held across the fetch so concurrent callers don't
    /// stampede the token endpoint.
    ///
    /// # Errors
    /// [`SyncError::Central`] if the token endpoint is unreachable or
    /// returns a non-2xx / malformed body.
    #[allow(clippy::significant_drop_tightening)] // guard held across the
    // fetch on purpose, to serialize concurrent refreshes
    pub async fn token(&self) -> SyncResult<String> {
        let mut guard = self.cached.lock().await;
        if let Some(c) = guard.as_ref()
            && Instant::now() < c.refresh_at
        {
            return Ok(c.token.clone());
        }
        let (token, ttl) = self.fetch().await?;
        // Refresh a margin before expiry; clamp so a tiny ttl still caches
        // briefly rather than refetching every call.
        let lifetime = ttl.saturating_sub(REFRESH_MARGIN).max(Duration::from_secs(5));
        *guard = Some(Cached { token: token.clone(), refresh_at: Instant::now() + lifetime });
        Ok(token)
    }

    async fn fetch(&self) -> SyncResult<(String, Duration)> {
        let resp = self
            .http
            .post(&self.token_url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("scope", self.scope.as_str()),
            ])
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(SyncError::Central(format!("token endpoint {status}: {body}")));
        }
        let body: TokenResponse = resp.json().await?;
        // Default to 5 min if the IdP omits expires_in.
        let ttl = Duration::from_secs(body.expires_in.unwrap_or(300));
        Ok((body.access_token, ttl))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::unchecked_time_subtraction)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::extract::State;
    use axum::routing::post;
    use axum::{Json, Router};

    use super::*;

    /// Boot a mock token endpoint that counts how many times it's hit and
    /// returns a token whose value encodes the hit count.
    async fn mock_token_server(expires_in: u64) -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let state = (hits.clone(), expires_in);
        let app = Router::new()
            .route(
                "/token",
                post(|State((hits, exp)): State<(Arc<AtomicUsize>, u64)>| async move {
                    let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
                    Json(serde_json::json!({
                        "access_token": format!("tok-{n}"),
                        "expires_in": exp,
                        "token_type": "Bearer",
                    }))
                }),
            )
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}/token"), hits)
    }

    #[tokio::test]
    async fn fetches_caches_and_refreshes() {
        // Long expiry → the second call must hit the cache, not the server.
        let (url, hits) = mock_token_server(3600).await;
        let p = TokenProvider::new(reqwest::Client::new(), url, "svc", "secret", "config-sync");
        assert_eq!(p.token().await.expect("t1"), "tok-1");
        assert_eq!(p.token().await.expect("t2"), "tok-1", "served from cache");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "endpoint hit once");
    }

    #[tokio::test]
    async fn short_ttl_forces_refresh() {
        // expires_in below the refresh margin → cache lifetime is the 5s
        // floor; force expiry by overwriting refresh_at in the past.
        let (url, hits) = mock_token_server(1).await;
        let p = TokenProvider::new(reqwest::Client::new(), url, "svc", "secret", "config-sync");
        assert_eq!(p.token().await.expect("t1"), "tok-1");
        // Simulate the cached token going stale.
        p.cached.lock().await.as_mut().unwrap().refresh_at =
            Instant::now() - Duration::from_secs(1);
        assert_eq!(p.token().await.expect("t2"), "tok-2", "refetched after expiry");
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }
}
