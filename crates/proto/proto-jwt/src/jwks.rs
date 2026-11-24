//! JWKS fetch + cache for OIDC bearer-token validation.
//!
//! Key handling follows docs/CLIENT-PROVISIONING-OIDC.md: cache the key
//! set, refresh when an unknown `kid` shows up (rate-limited), and keep
//! serving with the cached set if the `IdP` is briefly unreachable — `IdP`
//! downtime must not take down config fetches for already-signed tokens.
//!
//! Refreshes are single-flight: one async mutex serialises them, the fetch
//! runs in a detached task with no lock on the key set, and the new set is
//! swapped in under a short write lock. Lookups of cached keys never wait
//! on the `IdP`, and a cancelled caller does not abort the fetch.

use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{Jwk, JwkSet};
use serde::de::DeserializeOwned;
use thiserror::Error;
use tokio::sync::{Mutex, OwnedMutexGuard, RwLock};
use tracing::{info, warn};

/// Floor between consecutive fetch attempts, so a flood of bogus-`kid`
/// tokens can't turn this pod into an `IdP` load generator.
// NIST 800-53 Rev5: SC-5 (one IdP fetch per window per process)
// POAM: POA&M-423 any token, including one with a made-up kid, can use up
// the window, delaying a genuine key rotation by up to this interval.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Default bound on one refresh: metadata and JWKS requests, bodies
/// included, together.
// NIST 800-53 Rev5: SC-5 (a slow IdP cannot stall a refresh indefinitely)
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Largest accepted OIDC discovery document.
const MAX_METADATA_BYTES: usize = 64 * 1024;

/// Largest accepted JWKS document.
const MAX_JWKS_BYTES: usize = 256 * 1024;

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

/// Single-flight refresh gate. Held by the detached refresh task across
/// the fetch; only callers that need a refresh ever wait on it.
#[derive(Default)]
struct RefreshState {
    last_attempt: Option<Instant>,
}

/// What a detached refresh task needs to reach the `IdP`.
struct Fetcher {
    http: reqwest::Client,
    issuer: String,
}

/// Shared slot holding the current key set.
type KeySlot = Arc<RwLock<Option<Arc<JwkSet>>>>;

/// Cached JWKS for one OIDC issuer.
pub struct JwksCache {
    fetcher: Arc<Fetcher>,
    fetch_timeout: Duration,
    /// Current key set. Never held across an await.
    keys: KeySlot,
    /// Lock order: `refresh` before `keys`, never the reverse.
    refresh: Arc<Mutex<RefreshState>>,
}

impl JwksCache {
    /// New cache for `issuer`; nothing is fetched until first use (or
    /// [`JwksCache::refresh`] at startup). Each refresh is bounded by
    /// [`DEFAULT_FETCH_TIMEOUT`] (10 s) unless overridden with
    /// [`JwksCache::with_fetch_timeout`].
    pub fn new(http: reqwest::Client, issuer: impl Into<String>) -> Self {
        Self {
            fetcher: Arc::new(Fetcher {
                http,
                issuer: issuer.into(),
            }),
            fetch_timeout: DEFAULT_FETCH_TIMEOUT,
            keys: Arc::new(RwLock::new(None)),
            refresh: Arc::new(Mutex::new(RefreshState::default())),
        }
    }

    /// Cache preloaded with a static key set and no issuer to fetch from.
    /// Intended for tests in this crate and in downstream consumers.
    #[must_use]
    pub fn with_static(keys: JwkSet) -> Self {
        Self {
            fetcher: Arc::new(Fetcher {
                http: reqwest::Client::new(),
                issuer: String::new(),
            }),
            fetch_timeout: DEFAULT_FETCH_TIMEOUT,
            keys: Arc::new(RwLock::new(Some(Arc::new(keys)))),
            refresh: Arc::new(Mutex::new(RefreshState {
                last_attempt: Some(Instant::now()),
            })),
        }
    }

    /// Overrides the bound on one refresh (metadata + JWKS, bodies
    /// included).
    #[must_use]
    pub const fn with_fetch_timeout(mut self, timeout: Duration) -> Self {
        self.fetch_timeout = timeout;
        self
    }

    /// True once a key set is cached. Used by `/readyz`.
    pub async fn ready(&self) -> bool {
        self.keys.read().await.is_some()
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
        let keys = self.keys.read().await;
        keys.as_deref().and_then(|set| set.find(kid)).cloned()
    }

    /// Fetches OIDC metadata + JWKS from the issuer. On failure the cached
    /// set (if any) stays in service. Rate-limited to one attempt per
    /// [`MIN_REFRESH_INTERVAL`]; concurrent callers coalesce into a single
    /// fetch and all see its result.
    ///
    /// The fetch runs in a detached task bounded by the fetch timeout, so
    /// dropping this future (e.g. a client disconnecting mid-request) does
    /// not abort it: the result is still stored and the window is not
    /// spent for nothing. Must be called inside a Tokio runtime.
    ///
    /// # Errors
    /// [`JwksError::Unavailable`] or [`JwksError::Metadata`] when the fetch
    /// fails (or times out) and there is no cached key set to fall back on.
    pub async fn refresh(&self) -> Result<(), JwksError> {
        if self.fetcher.issuer.is_empty() {
            return Ok(()); // static cache — nothing to fetch
        }
        // NIST 800-53 Rev5: SC-5 (single flight; the key set is not locked
        // during the fetch, so known-kid validation and /readyz never wait)
        let gate = Arc::clone(&self.refresh).lock_owned().await;
        let Some(gate) = claim_window(gate) else {
            // Someone just tried (possibly the holder we queued behind);
            // don't hammer the IdP again. That's fine when a key set is
            // cached, but with an empty cache this must stay an error —
            // otherwise /readyz reports ready for the whole rate-limit
            // window after a failed startup prefetch.
            return if self.ready().await {
                Ok(())
            } else {
                Err(JwksError::Unavailable(
                    "fetch recently failed; retry pending".to_string(),
                ))
            };
        };
        // The task owns the gate (it stamps the attempt first) and releases
        // it after storing the result, so queued callers see the new set
        // when they get the gate.
        let task = tokio::spawn(refresh_task(
            Arc::clone(&self.fetcher),
            Arc::clone(&self.keys),
            self.fetch_timeout,
            gate,
        ));
        task.await
            .unwrap_or_else(|e| Err(JwksError::Unavailable(format!("refresh task failed: {e}"))))
    }
}

/// Returns the gate if a fetch may start now; drops it (releasing the
/// gate) when inside [`MIN_REFRESH_INTERVAL`] of the last attempt.
fn claim_window(gate: OwnedMutexGuard<RefreshState>) -> Option<OwnedMutexGuard<RefreshState>> {
    match gate.last_attempt {
        Some(at) if at.elapsed() < MIN_REFRESH_INTERVAL => None,
        _ => Some(gate),
    }
}

/// One bounded fetch, store on success, then release the gate.
async fn refresh_task(
    fetcher: Arc<Fetcher>,
    keys: KeySlot,
    fetch_timeout: Duration,
    mut gate: OwnedMutexGuard<RefreshState>,
) -> Result<(), JwksError> {
    gate.last_attempt = Some(Instant::now());
    let outcome = tokio::time::timeout(fetch_timeout, fetcher.fetch())
        .await
        .unwrap_or_else(|_| Err(JwksError::Unavailable("fetch timed out".to_string())));

    let result = match outcome {
        Ok(set) => {
            info!(issuer = %fetcher.issuer, keys = set.keys.len(), "JWKS refreshed");
            *keys.write().await = Some(Arc::new(set));
            Ok(())
        }
        Err(e) => {
            if keys.read().await.is_some() {
                warn!(issuer = %fetcher.issuer, error = %e, "JWKS refresh failed; serving cached set");
                Ok(())
            } else {
                Err(e)
            }
        }
    };
    // The window runs from the end of the fetch too, so callers queued
    // behind a slow fetch coalesce even when the fetch timeout is close to
    // or above MIN_REFRESH_INTERVAL.
    gate.last_attempt = Some(Instant::now());
    drop(gate);
    result
}

impl Fetcher {
    async fn fetch(&self) -> Result<JwkSet, JwksError> {
        let issuer = reqwest::Url::parse(&self.issuer)
            .map_err(|e| JwksError::Metadata(format!("invalid issuer {}: {e}", self.issuer)))?;
        let metadata_url = format!("{}/.well-known/openid-configuration", self.issuer);
        let metadata: OidcMetadata = self.get_json(&metadata_url, MAX_METADATA_BYTES).await?;

        // The metadata's issuer claim must round-trip exactly (OIDC
        // Discovery 1.0 §4.3) — a mismatch means we're being pointed at
        // someone else's keys.
        if metadata.issuer.trim_end_matches('/') != self.issuer {
            return Err(JwksError::Metadata(format!(
                "issuer mismatch: expected {}, metadata says {}",
                self.issuer, metadata.issuer
            )));
        }

        let jwks_uri = reqwest::Url::parse(&metadata.jwks_uri).map_err(|e| {
            JwksError::Metadata(format!("invalid jwks_uri {}: {e}", metadata.jwks_uri))
        })?;
        check_jwks_uri_scheme(&issuer, &jwks_uri)?;
        self.get_json(jwks_uri.as_str(), MAX_JWKS_BYTES).await
    }

    /// GETs `url` and parses a JSON body of at most `max_bytes`. Refuses a
    /// redirected or non-2xx response. Oversized or unparsable bodies are
    /// [`JwksError::Metadata`], as JWKS parse failures have always been.
    // NIST 800-53 Rev5: SC-5 (body size capped while reading)
    // POAM: POA&M-424 a caller-supplied client that follows redirects still
    // requests the redirect target before the response is refused here.
    async fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        max_bytes: usize,
    ) -> Result<T, JwksError> {
        let requested = reqwest::Url::parse(url)
            .map_err(|e| JwksError::Metadata(format!("invalid url {url}: {e}")))?;
        let mut resp = self
            .http
            .get(requested.clone())
            .send()
            .await
            .map_err(|e| JwksError::Unavailable(e.to_string()))?;
        if resp.url() != &requested {
            return Err(JwksError::Unavailable(format!(
                "{url} redirected to {}; redirects are not followed",
                resp.url()
            )));
        }
        // error_for_status() lets 3xx through; only 2xx is a key source.
        if !resp.status().is_success() {
            return Err(JwksError::Unavailable(format!(
                "{url} answered {}",
                resp.status()
            )));
        }
        let too_large = || JwksError::Metadata(format!("{url} body exceeds {max_bytes} bytes"));
        if resp
            .content_length()
            .is_some_and(|len| len > max_bytes as u64)
        {
            return Err(too_large());
        }
        let mut body = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| JwksError::Unavailable(e.to_string()))?
        {
            if body.len().saturating_add(chunk.len()) > max_bytes {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|e| JwksError::Metadata(e.to_string()))
    }
}

/// Keys are fetched over https; a plain-http `jwks_uri` is accepted only
/// when the issuer itself is http (local test `IdP`s).
// NIST 800-53 Rev5: SC-8 (signing keys not fetched in clear from an https
// issuer's metadata)
fn check_jwks_uri_scheme(issuer: &reqwest::Url, jwks_uri: &reqwest::Url) -> Result<(), JwksError> {
    if jwks_uri.scheme() == "https" || jwks_uri.scheme() == issuer.scheme() {
        Ok(())
    } else {
        Err(JwksError::Metadata(format!(
            "jwks_uri scheme {} not allowed for issuer scheme {}",
            jwks_uri.scheme(),
            issuer.scheme()
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;
    use std::fmt::Write as _;
    use std::sync::{Arc, Mutex as StdMutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    const METADATA_PATH: &str = "/.well-known/openid-configuration";
    const JWKS_PATH: &str = "/jwks";

    /// What the stub `IdP` does for one path.
    #[derive(Clone)]
    enum Route {
        /// 200 with a JSON body and Content-Length, after `delay`.
        Json { body: String, delay: Duration },
        /// 200, no Content-Length, body streamed then the connection closed.
        Stream { body: String },
        /// Read the request, never answer.
        Hang,
        /// Send 200 headers announcing a body, never send the body.
        HangAfterHeaders,
        /// 302 to `location` (a path on this stub).
        Redirect { location: String },
    }

    /// Minimal HTTP/1.1 `IdP` on 127.0.0.1. One request per connection
    /// (responses carry `Connection: close`); records each request path.
    struct StubIdp {
        issuer: String,
        routes: Arc<StdMutex<HashMap<String, Route>>>,
        requests: Arc<StdMutex<Vec<String>>>,
    }

    impl StubIdp {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let issuer = format!("http://{}", listener.local_addr().unwrap());
            let routes: Arc<StdMutex<HashMap<String, Route>>> = Arc::default();
            let requests: Arc<StdMutex<Vec<String>>> = Arc::default();
            let (r, q) = (routes.clone(), requests.clone());
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(serve_conn(sock, r.clone(), q.clone()));
                }
            });
            Self {
                issuer,
                routes,
                requests,
            }
        }

        fn set(&self, path: &str, route: Route) {
            self.routes.lock().unwrap().insert(path.to_string(), route);
        }

        /// Metadata pointing at this stub's `/jwks`, returned immediately.
        fn serve_metadata(&self) {
            self.set(
                METADATA_PATH,
                Route::Json {
                    body: metadata_json(&self.issuer, JWKS_PATH),
                    delay: Duration::ZERO,
                },
            );
        }

        fn serve_jwks(&self, kids: &[&str], delay: Duration) {
            self.set(
                JWKS_PATH,
                Route::Json {
                    body: jwks_json(kids),
                    delay,
                },
            );
        }

        fn hang_everything(&self) {
            self.set(METADATA_PATH, Route::Hang);
            self.set(JWKS_PATH, Route::Hang);
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }

        fn requests_for(&self, path: &str) -> usize {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .filter(|p| *p == path)
                .count()
        }

        /// Waits (bounded) until the stub has seen at least `n` requests.
        async fn wait_for_requests(&self, n: usize) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.request_count() < n {
                assert!(
                    Instant::now() < deadline,
                    "stub saw {} requests, wanted {n}",
                    self.request_count()
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }

    async fn serve_conn(
        mut sock: TcpStream,
        routes: Arc<StdMutex<HashMap<String, Route>>>,
        requests: Arc<StdMutex<Vec<String>>>,
    ) {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            match sock.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let path = head
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_string();
        let route = routes.lock().unwrap().get(&path).cloned();
        requests.lock().unwrap().push(path);
        match route {
            None => {
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            }
            Some(Route::Json { body, delay }) => {
                tokio::time::sleep(delay).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
            Some(Route::Stream { body }) => {
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                for part in body.as_bytes().chunks(16 * 1024) {
                    if sock.write_all(part).await.is_err() {
                        return;
                    }
                }
                let _ = sock.shutdown().await;
            }
            Some(Route::Hang) => std::future::pending::<()>().await,
            Some(Route::HangAfterHeaders) => {
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n{\"keys\":[",
                    )
                    .await;
                std::future::pending::<()>().await;
            }
            Some(Route::Redirect { location }) => {
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        }
    }

    fn metadata_json(issuer: &str, jwks_path: &str) -> String {
        serde_json::json!({ "issuer": issuer, "jwks_uri": format!("{issuer}{jwks_path}") })
            .to_string()
    }

    /// RSA public JWK with a placeholder modulus; only the `kid` matters
    /// for cache lookups.
    fn jwk_json(kid: &str) -> serde_json::Value {
        serde_json::json!({
            "kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
            "e": "AQAB"
        })
    }

    fn jwks_json(kids: &[&str]) -> String {
        serde_json::json!({ "keys": kids.iter().map(|k| jwk_json(k)).collect::<Vec<_>>() })
            .to_string()
    }

    /// A valid JWKS document whose serialised size is at least `min_bytes`.
    fn big_jwks_json(min_bytes: usize) -> String {
        let mut kids = vec!["k1".to_string()];
        let one = jwk_json("k-000000").to_string().len() + 1;
        for i in 0..=(min_bytes / one) {
            kids.push(format!("k-{i:06}"));
        }
        let refs: Vec<&str> = kids.iter().map(String::as_str).collect();
        let body = jwks_json(&refs);
        assert!(body.len() >= min_bytes);
        body
    }

    /// Valid metadata padded with an ignored member to at least `min_bytes`.
    fn big_metadata_json(issuer: &str, min_bytes: usize) -> String {
        let mut pad = String::with_capacity(min_bytes);
        while pad.len() < min_bytes {
            let _ = write!(pad, "x");
        }
        serde_json::json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}{JWKS_PATH}"),
            "x_padding": pad,
        })
        .to_string()
    }

    /// Moves the refresh window into the past so the next unknown-kid
    /// lookup may fetch. Written against the layout plan.md names
    /// (`refresh: Mutex<RefreshState { last_attempt }>`).
    async fn expire_refresh_window(cache: &JwksCache) {
        cache.refresh.lock().await.last_attempt =
            Instant::now().checked_sub(MIN_REFRESH_INTERVAL * 2);
    }

    /// Cache holding `k1` from one served refresh, window expired, and the
    /// stub switched to `hang` for every path.
    async fn primed_cache_then_hang(timeout: Option<Duration>) -> (StubIdp, Arc<JwksCache>) {
        let stub = StubIdp::start().await;
        stub.serve_metadata();
        stub.serve_jwks(&["k1"], Duration::ZERO);
        let mut cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone());
        if let Some(t) = timeout {
            cache = cache.with_fetch_timeout(t);
        }
        cache.refresh().await.expect("priming refresh");
        assert!(cache.get_key("k1").await.is_ok());
        expire_refresh_window(&cache).await;
        stub.hang_everything();
        (stub, Arc::new(cache))
    }

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

    /// An unknown-kid refresh stuck on a slow `IdP` must not delay lookups
    /// of keys already cached, nor `/readyz`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn known_kid_resolves_while_unknown_kid_refresh_is_blocked() {
        let (stub, cache) = primed_cache_then_hang(None).await;
        let before = stub.request_count();

        let c = cache.clone();
        let blocked = tokio::spawn(async move { c.get_key("unknown").await });
        stub.wait_for_requests(before + 1).await;

        let known = tokio::time::timeout(Duration::from_millis(200), cache.get_key("k1"))
            .await
            .expect("known-kid lookup waited on the unknown-kid fetch");
        assert!(known.is_ok());
        let ready = tokio::time::timeout(Duration::from_millis(200), cache.ready())
            .await
            .expect("ready() waited on the unknown-kid fetch");
        assert!(ready);
        assert!(!blocked.is_finished());
        blocked.abort();
    }

    /// A burst of lookups for a kid that needs a refresh triggers one
    /// metadata GET and one JWKS GET, and every caller sees the new key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_unknown_kid_refreshes_coalesce_into_one_fetch() {
        let stub = StubIdp::start().await;
        stub.serve_metadata();
        stub.serve_jwks(&["rotated"], Duration::from_millis(100));
        let cache = Arc::new(JwksCache::new(reqwest::Client::new(), stub.issuer.clone()));

        let tasks: Vec<_> = (0..16)
            .map(|_| {
                let c = cache.clone();
                tokio::spawn(async move { c.get_key("rotated").await })
            })
            .collect();
        for t in tasks {
            assert!(
                t.await.unwrap().is_ok(),
                "every caller sees the refreshed set"
            );
        }
        assert_eq!(stub.requests_for(METADATA_PATH), 1);
        assert_eq!(stub.requests_for(JWKS_PATH), 1);
        assert_eq!(stub.request_count(), 2);
    }

    #[tokio::test]
    async fn fetch_timeout_bounds_refresh() {
        let stub = StubIdp::start().await;
        stub.hang_everything();
        let cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone())
            .with_fetch_timeout(Duration::from_millis(200));

        let res = tokio::time::timeout(Duration::from_secs(1), cache.refresh())
            .await
            .expect("refresh not bounded by fetch timeout");
        assert!(matches!(res, Err(JwksError::Unavailable(_))), "{res:?}");
        assert!(!cache.ready().await);
    }

    #[tokio::test]
    async fn fetch_timeout_keeps_cached_set() {
        let (_stub, cache) = primed_cache_then_hang(Some(Duration::from_millis(200))).await;

        let res = tokio::time::timeout(Duration::from_secs(1), cache.refresh())
            .await
            .expect("refresh not bounded by fetch timeout");
        assert!(res.is_ok(), "cached set stays in service: {res:?}");
        assert!(cache.get_key("k1").await.is_ok());
        assert!(cache.ready().await);
    }

    /// The bound is on the whole fetch (metadata + JWKS), not per request.
    #[tokio::test]
    async fn fetch_timeout_covers_both_requests_together() {
        let stub = StubIdp::start().await;
        stub.set(
            METADATA_PATH,
            Route::Json {
                body: metadata_json(&stub.issuer, JWKS_PATH),
                delay: Duration::from_millis(300),
            },
        );
        stub.serve_jwks(&["k1"], Duration::from_millis(300));
        let cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone())
            .with_fetch_timeout(Duration::from_millis(450));

        let res = tokio::time::timeout(Duration::from_secs(2), cache.refresh())
            .await
            .expect("refresh not bounded");
        assert!(matches!(res, Err(JwksError::Unavailable(_))), "{res:?}");
        assert!(!cache.ready().await);
    }

    /// The bound also covers reading the body, not just the headers.
    #[tokio::test]
    async fn fetch_timeout_covers_body_read() {
        let stub = StubIdp::start().await;
        stub.serve_metadata();
        stub.set(JWKS_PATH, Route::HangAfterHeaders);
        let cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone())
            .with_fetch_timeout(Duration::from_millis(200));

        let res = tokio::time::timeout(Duration::from_secs(1), cache.refresh())
            .await
            .expect("body read not bounded by fetch timeout");
        assert!(res.is_err(), "{res:?}");
        assert!(!cache.ready().await);
    }

    #[test]
    fn default_fetch_timeout_is_ten_seconds() {
        assert_eq!(DEFAULT_FETCH_TIMEOUT, Duration::from_secs(10));
        let cache = JwksCache::new(reqwest::Client::new(), "https://idp.example");
        assert_eq!(cache.fetch_timeout, DEFAULT_FETCH_TIMEOUT);
        let cache = cache.with_fetch_timeout(Duration::from_secs(3));
        assert_eq!(cache.fetch_timeout, Duration::from_secs(3));
    }

    // --- decisions.md Q2: body cap and no redirects ---

    /// Guard against a cap set so low that a realistic key set is refused.
    #[tokio::test]
    async fn jwks_body_within_cap_is_accepted() {
        let stub = StubIdp::start().await;
        stub.serve_metadata();
        stub.set(
            JWKS_PATH,
            Route::Json {
                body: big_jwks_json(48 * 1024),
                delay: Duration::ZERO,
            },
        );
        let cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone());
        cache.refresh().await.expect("48 KiB key set accepted");
        assert!(cache.get_key("k1").await.is_ok());
    }

    #[tokio::test]
    async fn oversized_jwks_body_is_rejected() {
        let stub = StubIdp::start().await;
        stub.serve_metadata();
        stub.set(
            JWKS_PATH,
            Route::Json {
                body: big_jwks_json(512 * 1024),
                delay: Duration::ZERO,
            },
        );
        let cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone());
        assert!(
            cache.refresh().await.is_err(),
            "512 KiB JWKS must be refused"
        );
        assert!(!cache.ready().await);
    }

    /// Cap is enforced while reading, not only from Content-Length.
    #[tokio::test]
    async fn oversized_jwks_body_without_content_length_is_rejected() {
        let stub = StubIdp::start().await;
        stub.serve_metadata();
        stub.set(
            JWKS_PATH,
            Route::Stream {
                body: big_jwks_json(1024 * 1024),
            },
        );
        let cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone());
        assert!(
            cache.refresh().await.is_err(),
            "1 MiB streamed JWKS must be refused"
        );
        assert!(!cache.ready().await);
    }

    #[tokio::test]
    async fn oversized_metadata_body_is_rejected() {
        let stub = StubIdp::start().await;
        stub.set(
            METADATA_PATH,
            Route::Json {
                body: big_metadata_json(&stub.issuer, 512 * 1024),
                delay: Duration::ZERO,
            },
        );
        stub.serve_jwks(&["k1"], Duration::ZERO);
        let cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone());
        assert!(
            cache.refresh().await.is_err(),
            "512 KiB metadata must be refused"
        );
        assert!(!cache.ready().await);
        assert_eq!(
            stub.requests_for(JWKS_PATH),
            0,
            "JWKS fetched after bad metadata"
        );
    }

    /// A failed oversized refresh leaves an already cached set in service.
    #[tokio::test]
    async fn oversized_jwks_body_keeps_cached_set() {
        let (stub, cache) = primed_cache_then_hang(None).await;
        stub.serve_metadata();
        stub.set(
            JWKS_PATH,
            Route::Json {
                body: big_jwks_json(512 * 1024),
                delay: Duration::ZERO,
            },
        );
        assert!(
            cache.get_key("k-000001").await.is_err(),
            "oversized set not adopted"
        );
        assert!(cache.get_key("k1").await.is_ok());
    }

    /// The caller's client follows redirects by default; the cache must
    /// still refuse a redirected discovery document.
    #[tokio::test]
    async fn redirected_metadata_is_rejected() {
        let stub = StubIdp::start().await;
        stub.set(
            METADATA_PATH,
            Route::Redirect {
                location: "/elsewhere".to_string(),
            },
        );
        stub.set(
            "/elsewhere",
            Route::Json {
                body: metadata_json(&stub.issuer, JWKS_PATH),
                delay: Duration::ZERO,
            },
        );
        stub.serve_jwks(&["k1"], Duration::ZERO);
        let cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone());
        assert!(
            cache.refresh().await.is_err(),
            "redirected metadata must be refused"
        );
        assert!(!cache.ready().await);
        assert_eq!(stub.requests_for(JWKS_PATH), 0);
    }

    #[tokio::test]
    async fn redirected_jwks_is_rejected() {
        let stub = StubIdp::start().await;
        stub.serve_metadata();
        stub.set(
            JWKS_PATH,
            Route::Redirect {
                location: "/elsewhere".to_string(),
            },
        );
        stub.set(
            "/elsewhere",
            Route::Json {
                body: jwks_json(&["k1"]),
                delay: Duration::ZERO,
            },
        );
        let cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone());
        assert!(
            cache.refresh().await.is_err(),
            "redirected JWKS must be refused"
        );
        assert!(!cache.ready().await);
    }

    /// With a no-redirect client (how callers are expected to build it) a
    /// 3xx is a failure, not an empty or partial key set.
    #[tokio::test]
    async fn unfollowed_redirect_is_an_error() {
        let stub = StubIdp::start().await;
        stub.serve_metadata();
        stub.set(
            JWKS_PATH,
            Route::Redirect {
                location: "/elsewhere".to_string(),
            },
        );
        stub.set(
            "/elsewhere",
            Route::Json {
                body: jwks_json(&["k1"]),
                delay: Duration::ZERO,
            },
        );
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let cache = JwksCache::new(http, stub.issuer.clone());
        assert!(cache.refresh().await.is_err());
        assert!(!cache.ready().await);
        assert_eq!(stub.requests_for("/elsewhere"), 0);
    }

    // --- fix round 1 ---

    /// A caller dropped mid-fetch (client disconnect) must not abort the
    /// refresh: the set is still stored once the `IdP` answers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_caller_does_not_abort_refresh() {
        let stub = StubIdp::start().await;
        stub.serve_metadata();
        stub.serve_jwks(&["rotated"], Duration::from_millis(300));
        let cache = Arc::new(JwksCache::new(reqwest::Client::new(), stub.issuer.clone()));

        let c = cache.clone();
        let caller = tokio::spawn(async move { c.get_key("rotated").await });
        stub.wait_for_requests(1).await;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());

        let deadline = Instant::now() + Duration::from_secs(3);
        while !cache.ready().await {
            assert!(Instant::now() < deadline, "set never stored after cancel");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(cache.find("rotated").await.is_some());
        assert_eq!(stub.requests_for(JWKS_PATH), 1);
    }

    /// The rate-limit window restarts when the fetch ends, so callers queued
    /// behind a fetch as long as the window still coalesce.
    #[tokio::test]
    async fn refresh_window_restarts_after_fetch() {
        let stub = StubIdp::start().await;
        stub.serve_metadata();
        stub.serve_jwks(&["k1"], Duration::from_millis(300));
        let cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone());

        let before = Instant::now();
        cache.refresh().await.expect("refresh");
        let at = cache.refresh.lock().await.last_attempt.expect("stamped");
        assert!(
            at.duration_since(before) >= Duration::from_millis(300),
            "last_attempt not re-stamped after the fetch"
        );
    }

    #[test]
    fn plain_http_jwks_uri_is_rejected_for_https_issuer() {
        let https = reqwest::Url::parse("https://idp.example").unwrap();
        let http = reqwest::Url::parse("http://idp.example").unwrap();
        let jwks_http = reqwest::Url::parse("http://idp.example/jwks").unwrap();
        let jwks_https = reqwest::Url::parse("https://idp.example/jwks").unwrap();
        assert!(matches!(
            check_jwks_uri_scheme(&https, &jwks_http),
            Err(JwksError::Metadata(_))
        ));
        assert!(check_jwks_uri_scheme(&https, &jwks_https).is_ok());
        assert!(check_jwks_uri_scheme(&http, &jwks_http).is_ok());
        assert!(check_jwks_uri_scheme(&http, &jwks_https).is_ok());
    }

    #[tokio::test]
    async fn jwks_uri_with_other_scheme_is_rejected() {
        let stub = StubIdp::start().await;
        let host = stub.issuer.trim_start_matches("http://").to_string();
        stub.set(
            METADATA_PATH,
            Route::Json {
                body: serde_json::json!({
                    "issuer": stub.issuer,
                    "jwks_uri": format!("ws://{host}{JWKS_PATH}"),
                })
                .to_string(),
                delay: Duration::ZERO,
            },
        );
        stub.serve_jwks(&["k1"], Duration::ZERO);
        let cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone());
        let res = cache.refresh().await;
        assert!(matches!(res, Err(JwksError::Metadata(_))), "{res:?}");
        assert_eq!(stub.requests_for(JWKS_PATH), 0);
    }

    // --- SEC-006 ---

    /// Dropping the last handle to the cache mid-fetch is safe: the
    /// detached task owns its own references, finishes the fetch, stores
    /// the set, releases the gate and then drops its references.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_cache_mid_fetch_lets_task_finish() {
        let stub = StubIdp::start().await;
        stub.serve_metadata();
        stub.serve_jwks(&["rotated"], Duration::from_millis(300));
        let cache = Arc::new(JwksCache::new(reqwest::Client::new(), stub.issuer.clone()));
        let keys = Arc::clone(&cache.keys);
        let gate = Arc::clone(&cache.refresh);

        let c = cache.clone();
        let caller = tokio::spawn(async move { c.get_key("rotated").await });
        stub.wait_for_requests(1).await;
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        drop(cache);

        let held = tokio::time::timeout(Duration::from_secs(3), gate.lock_owned())
            .await
            .expect("gate never released after the cache was dropped");
        drop(held);
        assert!(
            keys.read()
                .await
                .as_deref()
                .and_then(|set| set.find("rotated"))
                .is_some(),
            "set not stored after the cache was dropped"
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while Arc::strong_count(&keys) > 1 {
            assert!(Instant::now() < deadline, "refresh task kept the key slot");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(stub.requests_for(JWKS_PATH), 1);
    }

    /// A failed fetch releases the gate: it can be retaken at once, and
    /// the next refresh after the window fetches again.
    #[tokio::test]
    async fn gate_is_retaken_after_failed_fetch() {
        let stub = StubIdp::start().await;
        stub.hang_everything();
        let cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone())
            .with_fetch_timeout(Duration::from_millis(100));

        assert!(matches!(
            cache.refresh().await,
            Err(JwksError::Unavailable(_))
        ));
        assert!(cache.refresh.try_lock().is_ok(), "gate still held");

        expire_refresh_window(&cache).await;
        stub.serve_metadata();
        stub.serve_jwks(&["k1"], Duration::ZERO);
        cache.refresh().await.expect("refresh after a failed fetch");
        assert!(cache.get_key("k1").await.is_ok());
    }

    /// A task that panics while holding the gate (the `JoinError` path in
    /// `refresh`) releases it on unwind; tokio's mutex does not poison, so
    /// later refreshes still run.
    #[tokio::test]
    async fn gate_is_retaken_after_holder_panics() {
        let stub = StubIdp::start().await;
        stub.serve_metadata();
        stub.serve_jwks(&["k1"], Duration::ZERO);
        let cache = JwksCache::new(reqwest::Client::new(), stub.issuer.clone());

        let gate = Arc::clone(&cache.refresh);
        let holder = tokio::spawn(async move {
            let _held = gate.lock_owned().await;
            panic!("refresh task panicked while holding the gate");
        });
        assert!(holder.await.unwrap_err().is_panic());

        let res = tokio::time::timeout(Duration::from_secs(2), cache.refresh())
            .await
            .expect("gate not released by the panicking holder");
        assert!(res.is_ok(), "{res:?}");
        assert!(cache.get_key("k1").await.is_ok());
    }
}
