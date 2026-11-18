//! Authentication endpoints: admin login, logout, and session check.
//!
//! Tokens are stateless (signed by [`uc_auth`]), so "logout" only clears
//! the browser cookie — there is no server-side session to destroy. The
//! `/auth/login` and `/auth/session` routes are exempt from the
//! deny-by-default middleware; everything else under `/api/v1` requires a
//! valid bearer token or API key.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tracing::warn;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

const MAX_LOGIN_ATTEMPTS: u32 = 5;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Per-client-IP login attempt counters: (`attempt_count`, `window_start`).
pub type LoginRateLimiter =
    std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (u32, Instant)>>;

/// `POST /api/v1/auth/login` — verify admin credentials, mint a token.
///
/// Returns the token in the body (for `Authorization: Bearer` clients) and
/// as an `HttpOnly; Secure; SameSite=Strict` cookie (for the dashboard).
pub async fn login(
    State(state): State<Arc<AppState>>,
    connect_info: axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Response {
    login_with(
        &state.auth,
        &state.login_rate_limiter,
        &state.trusted_proxies,
        connect_info.0.ip(),
        &headers,
        body,
    )
    .await
}

/// The login logic over its parts (authenticator, limiter, trusted proxy
/// networks), so it can be exercised without a full [`AppState`].
///
/// ## NIST 800-53 Rev5: AC-7 (Unsuccessful Logon Attempts), IA-2
pub async fn login_with(
    auth: &Arc<uc_auth::Authenticator>,
    login_rate_limiter: &LoginRateLimiter,
    trusted_proxies: &[ipnet::IpNet],
    peer: std::net::IpAddr,
    headers: &axum::http::HeaderMap,
    body: LoginRequest,
) -> Response {
    // Resolve the real client IP: honor nginx's X-Real-IP only when the
    // TCP peer is a trusted proxy, so a direct caller can't forge it and
    // evade (or poison) the per-IP rate limiter. With no trusted proxies
    // the key is the TCP peer.
    let client_ip = sbc_http_util::resolve_client_ip(headers, peer, trusted_proxies);

    // Rate-limit: reject if this IP has exceeded MAX_LOGIN_ATTEMPTS
    // within the sliding window.  Also evict stale entries to prevent
    // unbounded growth of the rate-limiter map.
    {
        let mut limiter = login_rate_limiter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        limiter.retain(|_, (_, window_start)| window_start.elapsed() < RATE_LIMIT_WINDOW * 2);
        if let Some(&(count, window_start)) = limiter.get(&client_ip)
            && window_start.elapsed() < RATE_LIMIT_WINDOW
            && count >= MAX_LOGIN_ATTEMPTS
        {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({"error": "too many login attempts, try again later"})),
            )
                .into_response();
        }
    }

    // argon2 verification is deliberately slow; keep it off the async
    // executor threads.
    let verifier = Arc::clone(auth);
    let username = body.username.clone();
    let password = body.password;
    let token = tokio::task::spawn_blocking(move || verifier.login(&username, &password))
        .await
        .ok()
        .flatten();

    let Some(token) = token else {
        warn!(user = %body.username, "failed admin login");
        // Increment rate-limit counter for this IP.
        {
            let mut limiter = login_rate_limiter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entry = limiter
                .entry(client_ip)
                .or_insert_with(|| (0, Instant::now()));
            if entry.1.elapsed() >= RATE_LIMIT_WINDOW {
                *entry = (1, Instant::now());
            } else {
                entry.0 += 1;
            }
            drop(limiter);
        }
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid credentials" })),
        )
            .into_response();
    };

    // Successful login — reset rate-limit counter for this IP.
    {
        let mut limiter = login_rate_limiter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        limiter.remove(&client_ip);
    }

    let max_age = auth.token_ttl_secs();
    // Secure: TLS terminates at the ingress, so the browser connection is
    // HTTPS even though this pod speaks HTTP behind it.
    let cookie = format!(
        "sbc_session={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"
    );
    let mut resp = Json(serde_json::json!({
        "token": token,
        "expires_in_secs": max_age,
    }))
    .into_response();
    if let Ok(v) = cookie.parse() {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// `POST /api/v1/auth/logout` — clear the session cookie (stateless tokens
/// can't be server-revoked; this just unsets the browser cookie).
pub async fn logout() -> Response {
    let mut resp = Json(serde_json::json!({ "success": true })).into_response();
    if let Ok(v) = "sbc_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0".parse() {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// `GET /api/v1/auth/session` — report whether the presented credential is
/// valid (the dashboard uses this to decide whether to show login).
pub async fn session(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Legacy cookie / HMAC / API key.
    let legacy_ok = uc_auth::extract_credential(&headers).is_some_and(|c| state.auth.authorize(&c));

    // OIDC bearer token (operator SSO via Keycloak).
    let oidc_ok = if legacy_ok {
        false
    } else if let Some(validator) = &state.oidc {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|t| t.trim().to_string());
        match token {
            Some(t) => validator.validate(&t).await.is_ok(),
            None => false,
        }
    } else {
        false
    };

    if legacy_ok || oidc_ok {
        Json(serde_json::json!({ "authenticated": true })).into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "authenticated": false })),
        )
            .into_response()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;
    use std::net::IpAddr;

    fn authenticator() -> Arc<uc_auth::Authenticator> {
        // A hash that does not parse: every login fails fast, without argon2.
        Arc::new(uc_auth::Authenticator::new("admin", "not-a-phc-hash", vec![7u8; 48]).unwrap())
    }

    fn real_ip(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", v.parse().unwrap());
        h
    }

    fn bad_login() -> LoginRequest {
        LoginRequest {
            username: "admin".to_string(),
            // Generated per run: any value fails against the unparseable hash.
            password: format!("invalid-{}", std::process::id()),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// With no trusted proxies, a client-supplied `X-Real-IP` does not pick
    /// the rate-limit key: attempts from one peer count together even when
    /// the header changes on every request.
    #[tokio::test]
    async fn qa_login_limiter_keys_on_peer_without_trusted_proxies() {
        let auth = authenticator();
        let limiter = LoginRateLimiter::default();
        let peer = ip("10.42.0.9");

        for i in 0..MAX_LOGIN_ATTEMPTS {
            let headers = real_ip(&format!("198.51.100.{}", i + 1));
            let resp = login_with(&auth, &limiter, &[], peer, &headers, bad_login()).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "attempt {}", i + 1);
        }
        {
            let map = limiter.lock().unwrap();
            assert_eq!(
                map.keys().copied().collect::<Vec<_>>(),
                vec![peer],
                "limiter must be keyed on the TCP peer only"
            );
            assert_eq!(map.get(&peer).map(|e| e.0), Some(MAX_LOGIN_ATTEMPTS));
            drop(map);
        }

        let resp = login_with(
            &auth,
            &limiter,
            &[],
            peer,
            &real_ip("198.51.100.200"),
            bad_login(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // A different peer is not affected.
        let resp = login_with(
            &auth,
            &limiter,
            &[],
            ip("10.42.0.10"),
            &HeaderMap::new(),
            bad_login(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Control: when the peer is a trusted proxy, the header it relays is
    /// the key, so distinct clients behind the proxy are counted apart.
    #[tokio::test]
    async fn qa_login_limiter_keys_on_relayed_ip_from_trusted_proxy() {
        let auth = authenticator();
        let limiter = LoginRateLimiter::default();
        let proxy = ip("10.42.0.9");
        let trusted: Vec<ipnet::IpNet> = vec!["10.42.0.0/24".parse().unwrap()];

        for _ in 0..MAX_LOGIN_ATTEMPTS {
            let resp = login_with(
                &auth,
                &limiter,
                &trusted,
                proxy,
                &real_ip("198.51.100.1"),
                bad_login(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        let blocked = login_with(
            &auth,
            &limiter,
            &trusted,
            proxy,
            &real_ip("198.51.100.1"),
            bad_login(),
        )
        .await;
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);

        let other = login_with(
            &auth,
            &limiter,
            &trusted,
            proxy,
            &real_ip("198.51.100.2"),
            bad_login(),
        )
        .await;
        assert_eq!(other.status(), StatusCode::UNAUTHORIZED);
        let map = limiter.lock().unwrap();
        assert!(
            !map.contains_key(&proxy),
            "proxy address must not be the key"
        );
        drop(map);
    }
}
