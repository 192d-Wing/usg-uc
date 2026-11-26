//! Authentication endpoints: admin login, logout, and session check.
//!
//! Tokens are stateless (signed by [`uc_auth`]), so "logout" only clears
//! the browser cookie — there is no server-side session to destroy. The
//! `/auth/login` and `/auth/session` routes are exempt from the
//! deny-by-default middleware; everything else under `/api/v1` requires a
//! valid bearer token or API key.

use std::sync::Arc;

use axum::Json;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::MethodRouter;
use serde::Deserialize;
use tracing::warn;

use crate::login_guard::{Admission, LoginGuard};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

/// Longest accepted username, in bytes (checked before anything is counted
/// or hashed).
const MAX_USERNAME_LEN: usize = 256;
/// Longest accepted password, in bytes.
const MAX_PASSWORD_LEN: usize = 1024;
/// Characters of a submitted username kept in the failed-login log line.
const LOG_USERNAME_CHARS: usize = 64;
/// Request body limit for `/auth/login`: the 256 + 1024 byte fields plus
/// JSON framing. Larger bodies get 413 before they are buffered (instead
/// of axum's 2 MB default).
pub const LOGIN_BODY_LIMIT: usize = 4 * 1024;

/// Applies [`LOGIN_BODY_LIMIT`] to the login route.
///
/// ## NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection), SI-10
pub fn with_login_body_limit<S>(route: MethodRouter<S>) -> MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    route.layer(DefaultBodyLimit::max(LOGIN_BODY_LIMIT))
}

/// The credential check behind [`login_with`]: the real
/// [`uc_auth::Authenticator`] in production, a counting stub in tests.
pub trait LoginVerifier: Send + Sync + 'static {
    /// Verifies the credentials (blocking: argon2) and mints a token.
    fn login(&self, username: &str, password: &str) -> Option<String>;
    /// Token lifetime in seconds (cookie `Max-Age`).
    fn token_ttl_secs(&self) -> u64;
    /// True if `name` is the configured admin username (audit records
    /// name only that, else `unknown`).
    fn is_admin_user(&self, _name: &str) -> bool {
        false
    }
}

impl LoginVerifier for uc_auth::Authenticator {
    fn login(&self, username: &str, password: &str) -> Option<String> {
        Self::login(self, username, password)
    }
    fn token_ttl_secs(&self) -> u64 {
        Self::token_ttl_secs(self)
    }
    fn is_admin_user(&self, name: &str) -> bool {
        Self::is_admin_user(self, name)
    }
}

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
        &state.login_guard,
        &state.trusted_proxies,
        connect_info.0.ip(),
        &headers,
        body,
    )
    .await
}

/// 429 with `Retry-After` (RFC 6585 §4, RFC 9110 §10.2.3 delay-seconds).
fn too_many(retry_after_secs: u64, error: &str) -> Response {
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({ "error": error })),
    )
        .into_response();
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
    resp
}

/// The first `LOG_USERNAME_CHARS` characters of `s`.
fn log_prefix(s: &str) -> &str {
    s.char_indices()
        .nth(LOG_USERNAME_CHARS)
        .and_then(|(i, _)| s.get(..i))
        .unwrap_or(s)
}

/// The login logic over its parts (verifier, guard, trusted proxy
/// networks), so it can be exercised without a full [`AppState`].
///
/// Order: input bounds, then [`LoginGuard::admit`] (verify slot, lock
/// check, failure reserved before hashing), then the verification with the
/// slot held, then refund on success.
///
/// ## NIST 800-53 Rev5: AC-7 (Unsuccessful Logon Attempts), SC-5, SI-10, IA-2
pub async fn login_with<V: LoginVerifier>(
    auth: &Arc<V>,
    guard: &LoginGuard,
    trusted_proxies: &[ipnet::IpNet],
    peer: std::net::IpAddr,
    headers: &axum::http::HeaderMap,
    body: LoginRequest,
) -> Response {
    // NIST 800-53 Rev5: SI-10 — bound input before it is counted or hashed.
    if body.username.len() > MAX_USERNAME_LEN || body.password.len() > MAX_PASSWORD_LEN {
        // SR-40: audited (aggregated) as a failure.
        let ip = sbc_http_util::resolve_client_ip(headers, peer, trusted_proxies);
        crate::auth_audit::login_invalid_format(ip);
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "invalid credentials format" })),
        )
            .into_response();
    }

    // Resolve the real client IP: honor nginx's X-Real-IP only when the
    // TCP peer is a trusted proxy, so a direct caller can't forge it and
    // evade (or poison) the per-IP limit. With no trusted proxies the key
    // is the TCP peer.
    let client_ip = sbc_http_util::resolve_client_ip(headers, peer, trusted_proxies);

    let slot = match guard.admit(client_ip) {
        Admission::Admitted(slot) => slot,
        // IP and account locks share one body. Retry-After is the time
        // left in the longest active lock, so it can differ between them;
        // neither depends on the submitted username.
        Admission::Locked { retry_after_secs } => {
            crate::auth_audit::login_rate_limited(client_ip);
            return too_many(retry_after_secs, "too many login attempts, try again later");
        }
        Admission::Busy => {
            crate::auth_audit::login_busy(client_ip);
            return too_many(1, "login busy, retry shortly");
        }
    };

    // argon2 verification is deliberately slow; keep it off the async
    // executor threads. The slot moves into the closure so it stays taken
    // until the hash finishes, even if this request is dropped.
    let verifier = Arc::clone(auth);
    let username = body.username.clone();
    let password = body.password;
    let token = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        verifier.login(&username, &password)
    })
    .await
    .ok()
    .flatten();

    // Failure (or a verifier panic): the reservation stands.
    let Some(token) = token else {
        warn!(user = %log_prefix(&body.username), "failed admin login");
        crate::auth_audit::login_failed(auth, client_ip, &body.username);
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid credentials" })),
        )
            .into_response();
    };

    // Success: refund the reservation and reset the failure counts.
    guard.on_success(client_ip);
    crate::auth_audit::login_succeeded(auth, client_ip, &body.username);

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
    connect_info: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
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
        // SR-40: a presented credential that failed is audited
        // (aggregated); none at all is not.
        if let Some(cred) = uc_auth::extract_credential(&headers) {
            let ip = connect_info.map_or(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                |axum::Extension(axum::extract::ConnectInfo(peer))| {
                    sbc_http_util::resolve_client_ip(&headers, peer.ip(), &state.trusted_proxies)
                },
            );
            crate::auth_audit::session_rejected(ip, &cred, &headers);
        }
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "authenticated": false })),
        )
            .into_response()
    }
}

#[cfg(test)]
// Test code: unwrap/expect/panic are the assertions.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::login_guard::{
        ACCOUNT_MAX_FAILURES, IP_MAX_FAILURES, LOCKOUT_WINDOW, LoginGuard, LoginGuardConfig,
    };
    use axum::http::HeaderMap;
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    use std::time::Duration;

    const LOCKED: &str = "too many login attempts, try again later";
    const BUSY: &str = "login busy, retry shortly";
    /// Real-time bound for the gated concurrency tests.
    const WAIT: Duration = Duration::from_secs(10);

    fn authenticator() -> Arc<uc_auth::Authenticator> {
        // A hash that does not parse: every login fails fast, without argon2.
        Arc::new(uc_auth::Authenticator::new("admin", "not-a-phc-hash", vec![7u8; 48]).unwrap())
    }

    /// Test verifier: counts calls, optionally parks each call until
    /// released, and accepts only `good` (if set).
    struct Gated {
        calls: AtomicUsize,
        open: Mutex<bool>,
        cv: Condvar,
        good: Option<String>,
    }

    impl Gated {
        fn build(open: bool, good: Option<&str>) -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                open: Mutex::new(open),
                cv: Condvar::new(),
                good: good.map(str::to_string),
            })
        }
        /// Never blocks; rejects every password.
        fn rejecting() -> Arc<Self> {
            Self::build(true, None)
        }
        /// Parks every call until [`Gated::release`]; then rejects.
        fn closed() -> Arc<Self> {
            Self::build(false, None)
        }
        fn accepting(pw: &str) -> Arc<Self> {
            Self::build(true, Some(pw))
        }
        fn release(&self) {
            *self.open.lock().unwrap() = true;
            self.cv.notify_all();
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl LoginVerifier for Gated {
        fn login(&self, _username: &str, password: &str) -> Option<String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.cv.wait(open).unwrap();
            }
            drop(open);
            (self.good.as_deref() == Some(password)).then(|| "qa-token".to_string())
        }
        fn token_ttl_secs(&self) -> u64 {
            3600
        }
    }

    /// Opens the gate on drop, so a failed assertion does not leave
    /// blocking threads parked (the runtime waits for them on shutdown).
    struct ReleaseOnDrop(Arc<Gated>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    fn real_ip(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", v.parse().unwrap());
        h
    }

    fn req(username: &str, password: &str) -> LoginRequest {
        LoginRequest {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    fn bad_login() -> LoginRequest {
        // Generated per run: any value fails against the test verifiers.
        req("admin", &format!("invalid-{}", std::process::id()))
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn nth_ip(n: u32) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::from(0xC612_0000 + n)) // 198.18.0.0/15
    }

    fn guard_with(f: impl FnOnce(&mut LoginGuardConfig)) -> Arc<LoginGuard> {
        let mut cfg = LoginGuardConfig::default();
        f(&mut cfg);
        Arc::new(LoginGuard::new(cfg))
    }

    async fn attempt<V: LoginVerifier>(v: &Arc<V>, g: &LoginGuard, peer: IpAddr) -> Response {
        login_with(v, g, &[], peer, &HeaderMap::new(), bad_login()).await
    }

    fn retry_after(resp: &Response) -> Option<String> {
        resp.headers()
            .get(header::RETRY_AFTER)
            .map(|v| v.to_str().unwrap().to_string())
    }

    /// (status, Retry-After, `error` field of the JSON body).
    async fn parts(resp: Response) -> (StatusCode, Option<String>, String) {
        let status = resp.status();
        let ra = retry_after(&resp);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        let err = v["error"].as_str().unwrap_or_default().to_string();
        (status, ra, err)
    }

    async fn wait_until(mut cond: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + WAIT;
        while !cond() && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn ip_max() -> usize {
        usize::try_from(IP_MAX_FAILURES).unwrap()
    }

    // ---- 1. reservation under concurrency ---------------------------------

    /// N concurrent bad logins from one IP: at most `IP_MAX_FAILURES` reach
    /// the verifier; the rest get 429 + Retry-After without waiting for
    /// the in-flight hashes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn qa_concurrent_bad_logins_reserve_before_hashing() {
        let v = Gated::closed();
        let _rel = ReleaseOnDrop(Arc::clone(&v));
        let guard = guard_with(|c| c.max_concurrent_verify = 64);
        let peer = ip("203.0.113.7");
        let done = Arc::new(AtomicUsize::new(0));
        let total = 32usize;

        let mut tasks = Vec::new();
        for _ in 0..total {
            let (v, g, done) = (Arc::clone(&v), Arc::clone(&guard), Arc::clone(&done));
            tasks.push(tokio::spawn(async move {
                let r = attempt(&v, &g, peer).await;
                done.fetch_add(1, Ordering::SeqCst);
                parts(r).await
            }));
        }
        // A reserving guard answers the surplus while the reserved logins
        // are still parked in the verifier.
        wait_until(|| {
            (done.load(Ordering::SeqCst) >= total - ip_max() && v.calls() >= ip_max())
                || v.calls() > ip_max()
        })
        .await;
        let calls_while_parked = v.calls();
        let done_while_parked = done.load(Ordering::SeqCst);
        v.release();

        let mut unauthorized = 0;
        let mut locked = 0;
        for t in tasks {
            let (status, ra, err) = t.await.unwrap();
            match status {
                StatusCode::UNAUTHORIZED => unauthorized += 1,
                StatusCode::TOO_MANY_REQUESTS => {
                    locked += 1;
                    let secs: u64 = ra.expect("429 carries Retry-After").parse().unwrap();
                    assert!(secs >= 1, "Retry-After {secs}");
                    assert_eq!(err, LOCKED);
                }
                other => panic!("unexpected status {other}"),
            }
        }
        assert_eq!(
            calls_while_parked,
            ip_max(),
            "verifications while the first batch was in flight"
        );
        assert_eq!(
            done_while_parked,
            total - ip_max(),
            "surplus must be rejected before the hashes finish"
        );
        assert_eq!(v.calls(), ip_max(), "total verifications");
        assert_eq!(unauthorized, ip_max());
        assert_eq!(locked, total - ip_max());
        assert_eq!(guard.ip_failures(peer), Some(IP_MAX_FAILURES));
    }

    // ---- 2. refund on success --------------------------------------------

    #[tokio::test]
    async fn qa_success_refunds_reservation() {
        let v = Gated::accepting("correct horse battery staple");
        let guard = LoginGuard::default();
        let peer = ip("203.0.113.8");

        for i in 0..IP_MAX_FAILURES - 1 {
            let r = attempt(&v, &guard, peer).await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "attempt {}", i + 1);
        }
        assert_eq!(guard.ip_failures(peer), Some(IP_MAX_FAILURES - 1));
        assert_eq!(guard.account_failures(), IP_MAX_FAILURES - 1);

        let ok = login_with(
            &v,
            &guard,
            &[],
            peer,
            &HeaderMap::new(),
            req("admin", "correct horse battery staple"),
        )
        .await;
        assert_eq!(ok.status(), StatusCode::OK);
        assert!(ok.headers().contains_key(header::SET_COOKIE));
        assert_eq!(guard.ip_failures(peer).unwrap_or(0), 0, "IP count reset");
        assert_eq!(guard.account_failures(), 0, "account count reset");

        let r = attempt(&v, &guard, peer).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(guard.ip_failures(peer), Some(1));
    }

    // ---- 3. verify slots full --------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn qa_verify_slots_full_is_429_retry_after_1() {
        let v = Gated::closed();
        let _rel = ReleaseOnDrop(Arc::clone(&v));
        let guard = guard_with(|c| c.max_concurrent_verify = 2);

        let mut inflight = Vec::new();
        for peer in [ip("192.0.2.1"), ip("192.0.2.2")] {
            let (v, g) = (Arc::clone(&v), Arc::clone(&guard));
            inflight.push(tokio::spawn(
                async move { attempt(&v, &g, peer).await.status() },
            ));
        }
        wait_until(|| v.calls() >= 2).await;
        assert_eq!(v.calls(), 2);
        let account_before = guard.account_failures();

        let third = ip("192.0.2.3");
        let r = tokio::time::timeout(WAIT, attempt(&v, &guard, third))
            .await
            .expect("no free slot must answer at once, not queue");
        let (status, ra, err) = parts(r).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(ra.as_deref(), Some("1"));
        assert_eq!(err, BUSY);
        assert_eq!(guard.ip_failures(third), None, "busy is not counted");
        assert_eq!(guard.account_failures(), account_before);
        assert_eq!(v.calls(), 2, "busy never reaches the verifier");

        v.release();
        for t in inflight {
            assert_eq!(t.await.unwrap(), StatusCode::UNAUTHORIZED);
        }
    }

    // ---- 4. slot outlives a dropped request ------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn qa_slot_held_until_hash_finishes_after_client_drop() {
        let v = Gated::closed();
        let _rel = ReleaseOnDrop(Arc::clone(&v));
        let guard = guard_with(|c| c.max_concurrent_verify = 1);
        let first = ip("192.0.2.10");

        let task = {
            let (v, g) = (Arc::clone(&v), Arc::clone(&guard));
            tokio::spawn(async move { attempt(&v, &g, first).await })
        };
        wait_until(|| v.calls() >= 1).await;
        assert_eq!(v.calls(), 1);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());

        // argon2 is still running for the dropped request: the slot is taken.
        let r = tokio::time::timeout(WAIT, attempt(&v, &guard, ip("192.0.2.11")))
            .await
            .expect("no free slot must answer at once");
        let (status, ra, err) = parts(r).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(ra.as_deref(), Some("1"));
        assert_eq!(err, BUSY);
        assert_eq!(
            guard.ip_failures(first),
            Some(1),
            "a dropped request keeps its reservation (fail closed)"
        );

        v.release();
        // Once the verifier returns, the slot frees.
        let deadline = std::time::Instant::now() + WAIT;
        let mut n = 0u32;
        let freed = loop {
            n += 1;
            let r = attempt(&v, &guard, nth_ip(1000 + n)).await;
            if r.status() == StatusCode::UNAUTHORIZED {
                break true;
            }
            if std::time::Instant::now() >= deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        assert!(freed, "slot never released after the verifier returned");
    }

    // ---- 5-7. account bucket ---------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn qa_account_lockout_across_ips() {
        let v = Gated::rejecting();
        let guard = LoginGuard::default();
        for i in 0..ACCOUNT_MAX_FAILURES {
            let src = nth_ip(i / IP_MAX_FAILURES);
            let r = attempt(&v, &guard, src).await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "failure {}", i + 1);
        }
        assert!(
            ACCOUNT_MAX_FAILURES.div_ceil(IP_MAX_FAILURES) >= 2,
            "needs 2+ sources"
        );
        assert_eq!(guard.account_failures(), ACCOUNT_MAX_FAILURES);
        let calls = v.calls();

        let fresh = ip("198.51.100.77");
        let r = login_with(
            &v,
            &guard,
            &[],
            fresh,
            &HeaderMap::new(),
            req("someone-else", "x"),
        )
        .await;
        let (status, ra, err) = parts(r).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(ra.is_some(), "429 carries Retry-After");
        assert_eq!(err, LOCKED);
        assert_eq!(v.calls(), calls, "locked account: no verification");

        tokio::time::advance(LOCKOUT_WINDOW).await;
        let r = attempt(&v, &guard, fresh).await;
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "lock ends with its window"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn qa_single_ip_cannot_lock_account() {
        let v = Gated::rejecting();
        let guard = LoginGuard::default();
        let attacker = ip("198.51.100.1");
        let admin = ip("198.51.100.2");
        let step = Duration::from_secs(30);

        let mut unauthorized = 0u32;
        let mut locked = 0u32;
        let mut elapsed = Duration::ZERO;
        // Keep hammering for the whole window (stop just short of its end).
        while elapsed + step < LOCKOUT_WINDOW {
            let (status, _, err) = parts(attempt(&v, &guard, attacker).await).await;
            match status {
                StatusCode::UNAUTHORIZED => unauthorized += 1,
                StatusCode::TOO_MANY_REQUESTS => {
                    assert_eq!(err, LOCKED);
                    locked += 1;
                }
                other => panic!("unexpected status {other}"),
            }
            tokio::time::advance(step).await;
            elapsed += step;
        }
        assert_eq!(unauthorized, IP_MAX_FAILURES);
        assert!(locked > 0);
        assert!(guard.account_failures() < ACCOUNT_MAX_FAILURES);

        let r = attempt(&v, &guard, admin).await;
        assert_eq!(
            r.status(),
            StatusCode::UNAUTHORIZED,
            "one source must not lock the account"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn qa_account_lock_independent_of_username() {
        let v = Gated::rejecting();
        let guard = LoginGuard::default();
        let long = "u".repeat(64);
        let users = ["admin", "root", "Admin", "nobody", long.as_str()];
        for i in 0..ACCOUNT_MAX_FAILURES {
            let src = nth_ip(100 + i / IP_MAX_FAILURES);
            let user = users[usize::try_from(i).unwrap() % users.len()];
            let r = login_with(&v, &guard, &[], src, &HeaderMap::new(), req(user, "x")).await;
            assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "failure {}", i + 1);
        }
        assert_eq!(guard.account_failures(), ACCOUNT_MAX_FAILURES);

        let real = login_with(
            &v,
            &guard,
            &[],
            ip("198.51.100.50"),
            &HeaderMap::new(),
            req("admin", "x"),
        )
        .await;
        let wrong = login_with(
            &v,
            &guard,
            &[],
            ip("198.51.100.51"),
            &HeaderMap::new(),
            req("not-the-admin", "x"),
        )
        .await;
        let real = parts(real).await;
        let wrong = parts(wrong).await;
        assert_eq!(real.0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(real, wrong, "lock response must not depend on the username");
    }

    // ---- 8. IP window ----------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn qa_ip_window_expires_after_15_min() {
        assert_eq!(LOCKOUT_WINDOW, Duration::from_mins(15));
        let v = Gated::rejecting();
        let guard = LoginGuard::default();
        let peer = ip("198.51.100.9");
        for _ in 0..IP_MAX_FAILURES {
            assert_eq!(
                attempt(&v, &guard, peer).await.status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let (status, ra, err) = parts(attempt(&v, &guard, peer).await).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(err, LOCKED);
        assert_eq!(
            ra.as_deref(),
            Some(LOCKOUT_WINDOW.as_secs().to_string().as_str()),
            "Retry-After is the time left in the window"
        );

        tokio::time::advance(LOCKOUT_WINDOW.saturating_sub(Duration::from_secs(1))).await;
        let (status, ra, _) = parts(attempt(&v, &guard, peer).await).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(ra.as_deref(), Some("1"));

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            attempt(&v, &guard, peer).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(v.calls(), ip_max() + 1);
    }

    // ---- 9. input bounds -------------------------------------------------

    #[tokio::test]
    async fn qa_oversize_fields_rejected_uncounted() {
        let v = Gated::rejecting();
        let guard = LoginGuard::default();
        let peer = ip("198.51.100.10");
        for (u, p) in [
            ("a".repeat(257), "pw".to_string()),
            ("admin".to_string(), "p".repeat(1025)),
        ] {
            let r = login_with(&v, &guard, &[], peer, &HeaderMap::new(), req(&u, &p)).await;
            let (status, _, err) = parts(r).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "len {}/{}",
                u.len(),
                p.len()
            );
            assert_eq!(err, "invalid credentials format");
        }
        assert_eq!(v.calls(), 0, "oversize input never reaches argon2");
        assert_eq!(guard.ip_failures(peer), None);
        assert_eq!(guard.account_failures(), 0);

        // Boundary: 256 / 1024 bytes are accepted and counted.
        let r = login_with(
            &v,
            &guard,
            &[],
            peer,
            &HeaderMap::new(),
            req(&"a".repeat(256), &"p".repeat(1024)),
        )
        .await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(v.calls(), 1);
        assert_eq!(guard.ip_failures(peer), Some(1));
    }

    // ---- 10. trusted-proxy key (ported) ----------------------------------

    /// With no trusted proxies, a client-supplied `X-Real-IP` does not pick
    /// the rate-limit key: attempts from one peer count together even when
    /// the header changes on every request.
    #[tokio::test]
    async fn qa_login_limiter_keys_on_peer_without_trusted_proxies() {
        let auth = authenticator();
        let guard = LoginGuard::default();
        let peer = ip("10.42.0.9");

        for i in 0..IP_MAX_FAILURES {
            let headers = real_ip(&format!("198.51.100.{}", i + 1));
            let resp = login_with(&auth, &guard, &[], peer, &headers, bad_login()).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "attempt {}", i + 1);
        }
        assert_eq!(guard.tracked_ips(), 1, "keyed on the TCP peer only");
        assert_eq!(guard.ip_failures(peer), Some(IP_MAX_FAILURES));
        assert_eq!(guard.ip_failures(ip("198.51.100.1")), None);

        let resp = login_with(
            &auth,
            &guard,
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
            &guard,
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
        let guard = LoginGuard::default();
        let proxy = ip("10.42.0.9");
        let trusted: Vec<ipnet::IpNet> = vec!["10.42.0.0/24".parse().unwrap()];

        for _ in 0..IP_MAX_FAILURES {
            let resp = login_with(
                &auth,
                &guard,
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
            &guard,
            &trusted,
            proxy,
            &real_ip("198.51.100.1"),
            bad_login(),
        )
        .await;
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);

        let other = login_with(
            &auth,
            &guard,
            &trusted,
            proxy,
            &real_ip("198.51.100.2"),
            bad_login(),
        )
        .await;
        assert_eq!(other.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(guard.ip_failures(ip("198.51.100.1")), Some(IP_MAX_FAILURES));
        assert_eq!(guard.ip_failures(ip("198.51.100.2")), Some(1));
        assert_eq!(
            guard.ip_failures(proxy),
            None,
            "proxy address must not be the key"
        );
    }

    // ---- fix round 1: body limit (PERF-002) --------------------------------

    async fn login_status_for_body(body: String) -> StatusCode {
        use tower::ServiceExt;
        async fn stub(Json(_body): Json<LoginRequest>) -> StatusCode {
            StatusCode::OK
        }
        let app = axum::Router::new().route(
            "/auth/login",
            with_login_body_limit(axum::routing::post(stub)),
        );
        let req = axum::http::Request::post("/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(body))
            .unwrap();
        app.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn login_body_over_limit_is_413() {
        let max_fields = serde_json::json!({
            "username": "a".repeat(256),
            "password": "p".repeat(1024),
        })
        .to_string();
        assert!(max_fields.len() < LOGIN_BODY_LIMIT);
        assert_eq!(login_status_for_body(max_fields).await, StatusCode::OK);

        let oversize = serde_json::json!({
            "username": "admin",
            "password": "p".repeat(LOGIN_BODY_LIMIT),
        })
        .to_string();
        assert_eq!(
            login_status_for_body(oversize).await,
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
