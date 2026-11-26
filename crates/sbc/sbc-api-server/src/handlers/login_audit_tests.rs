//! SR-40: admin logins are audited. Success per event; failures (bad
//! password, rate-limited) aggregated per (client IP, reason) through the
//! shared `mgmt_audit` aggregator. Kept out of `auth.rs` (SR-38 owns its
//! body); drives `login_with` with SR-38's signature and the
//! `crate::auth_audit` helpers directly.
//!
//! Each test uses its own IPv6 documentation-range /64: the aggregator is
//! process-global, keys on the /64 (round 1, SEC-002), and other login
//! tests share the binary.
//!
//! ## NIST 800-53 Rev5: AU-2, AU-3, AC-7, IA-2, SC-5

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, StatusCode};
use uc_audit::AuditEvent;
use uc_audit::event::{AuthMethod, AuthenticationAttempt};

use super::auth::{LoginRequest, login_with};
use crate::login_guard::{IP_MAX_FAILURES, LoginGuard};

/// Orders tests that count aggregated auth-failure records against tests
/// that flush the process-global aggregator. A flush at a future instant
/// closes every key's window, so a parallel counting test would see its
/// suppressed failures re-emitted. A bin crate cannot split these into
/// separate test binaries (as sbc-http-util does), so they share this lock:
/// counting tests read, flushing tests write.
pub(crate) static AGGREGATOR: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());

const PW: &str = "sr40-login-password";

/// Real argon2 hash, so a correct password succeeds.
fn authenticator() -> Arc<uc_auth::Authenticator> {
    static AUTH: std::sync::OnceLock<Arc<uc_auth::Authenticator>> = std::sync::OnceLock::new();
    Arc::clone(AUTH.get_or_init(|| {
        let hash = uc_auth::hash_password(PW).unwrap();
        Arc::new(uc_auth::Authenticator::new("admin", &hash, vec![5u8; 48]).unwrap())
    }))
}

fn req(username: &str, password: &str) -> LoginRequest {
    serde_json::from_value(serde_json::json!({ "username": username, "password": password }))
        .unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn attempts(events: &[AuditEvent], from: IpAddr) -> Vec<AuthenticationAttempt> {
    events
        .iter()
        .filter_map(|e| match e {
            AuditEvent::AuthenticationAttempt(a) if a.source_ip == from => Some(a.clone()),
            _ => None,
        })
        .collect()
}

fn reason(a: &AuthenticationAttempt) -> String {
    a.failure_reason.clone().unwrap_or_default()
}

#[tokio::test]
async fn login_success_is_audited() {
    let cap = uc_audit::capture::start();
    let from = ip("2001:db8:9:1::1");
    let guard = LoginGuard::default();
    let resp = login_with(
        &authenticator(),
        &guard,
        &[],
        from,
        &HeaderMap::new(),
        req("admin", PW),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let a = attempts(&cap.events(), from);
    assert_eq!(a.len(), 1, "{a:?}");
    assert!(a[0].success);
    assert_eq!(a[0].identity, "admin");
    assert_eq!(a[0].method, AuthMethod::Password);
    assert_eq!(a[0].failure_reason, None);
    let all = serde_json::to_string(&cap.events()).unwrap();
    assert!(!all.contains(PW), "password never logged");

    // A second success is a second record (successes are not aggregated).
    let resp = login_with(
        &authenticator(),
        &guard,
        &[],
        from,
        &HeaderMap::new(),
        req("admin", PW),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(attempts(&cap.events(), from).len(), 2);
}

#[tokio::test]
async fn login_failure_is_audited_with_source_ip() {
    let cap = uc_audit::capture::start();
    let guard = LoginGuard::default();
    // Behind the trusted nginx: the relayed client IP is the source.
    let proxy = ip("10.42.0.9");
    let client = ip("2001:db8:9:2::1");
    let trusted: Vec<ipnet::IpNet> = vec!["10.42.0.0/24".parse().unwrap()];
    let mut h = HeaderMap::new();
    h.insert("x-real-ip", client.to_string().parse().unwrap());
    let bad = format!("wrong-{}", std::process::id());
    let resp = login_with(
        &authenticator(),
        &guard,
        &trusted,
        proxy,
        &h,
        req("admin", &bad),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let a = attempts(&cap.events(), client);
    assert_eq!(a.len(), 1, "{:?}", cap.events());
    assert!(!a[0].success);
    assert_eq!(a[0].identity, "admin");
    assert_eq!(a[0].method, AuthMethod::Password);
    assert!(
        reason(&a[0]).starts_with("invalid_credentials"),
        "{}",
        reason(&a[0])
    );
    assert!(
        attempts(&cap.events(), proxy).is_empty(),
        "not the proxy address"
    );
    let all = serde_json::to_string(&cap.events()).unwrap();
    assert!(!all.contains(&bad), "password never logged");
}

#[tokio::test]
async fn login_failure_unknown_user_records_unknown() {
    let cap = uc_audit::capture::start();
    let from = ip("2001:db8:9:3::1");
    let guard = LoginGuard::default();
    // An operator who typed the password into the username field.
    let typed = format!("Tr0ub4dor&3-{}", std::process::id());
    let resp = login_with(
        &authenticator(),
        &guard,
        &[],
        from,
        &HeaderMap::new(),
        req(&typed, PW),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let a = attempts(&cap.events(), from);
    assert_eq!(a.len(), 1, "{a:?}");
    assert_eq!(a[0].identity, "unknown");
    let all = serde_json::to_string(&cap.events()).unwrap();
    assert!(!all.contains(&typed), "unknown usernames are never stored");

    // The helper applies the same rule.
    let cap = uc_audit::capture::start();
    let from = ip("2001:db8:9:13::1");
    crate::auth_audit::login_failed(&authenticator(), from, "Admin");
    let a = attempts(&cap.events(), from);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].identity, "unknown", "match is exact");
}

#[tokio::test]
async fn login_failures_from_one_ip_are_aggregated() {
    let _agg = AGGREGATOR.write().await;
    let cap = uc_audit::capture::start();
    let from = ip("2001:db8:9:4::1");
    // Stay under the per-IP lockout so every attempt reaches the verifier.
    let n = IP_MAX_FAILURES.min(4);
    assert!(n >= 3, "need a few attempts under the lockout");
    for _ in 0..n {
        let guard = LoginGuard::default();
        let resp = login_with(
            &authenticator(),
            &guard,
            &[],
            from,
            &HeaderMap::new(),
            req("admin", "nope"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    let a = attempts(&cap.events(), from);
    assert_eq!(a.len(), 1, "one record per window: {a:?}");

    sbc_http_util::mgmt_audit::flush_auth_failures(Instant::now() + Duration::from_secs(61));
    let a = attempts(&cap.events(), from);
    assert_eq!(a.len(), 2, "{a:?}");
    assert!(reason(&a[1]).starts_with("invalid_credentials"));
    assert!(
        reason(&a[1]).ends_with(&format!("count={}", n - 1)),
        "{}",
        reason(&a[1])
    );
}

#[tokio::test]
async fn rate_limited_login_is_audited() {
    let _agg = AGGREGATOR.read().await;
    let cap = uc_audit::capture::start();
    let from = ip("2001:db8:9:5::1");
    let guard = LoginGuard::default();
    for _ in 0..IP_MAX_FAILURES {
        let resp = login_with(
            &authenticator(),
            &guard,
            &[],
            from,
            &HeaderMap::new(),
            req("admin", "nope"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    for _ in 0..3 {
        let resp = login_with(
            &authenticator(),
            &guard,
            &[],
            from,
            &HeaderMap::new(),
            req("admin", PW),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    let a = attempts(&cap.events(), from);
    let limited: Vec<_> = a
        .iter()
        .filter(|e| reason(e).starts_with("rate_limited"))
        .collect();
    assert_eq!(limited.len(), 1, "429s aggregated too: {a:?}");
    assert!(!limited[0].success);
    assert_eq!(limited[0].method, AuthMethod::Password);
    assert!(
        a.iter().all(|e| !e.success),
        "a locked-out correct password is not a success"
    );

    // The helper is callable at the 429 return with only the client IP.
    let cap = uc_audit::capture::start();
    let other = ip("2001:db8:9:15::1");
    crate::auth_audit::login_rate_limited(other);
    let a = attempts(&cap.events(), other);
    assert_eq!(a.len(), 1);
    assert!(reason(&a[0]).starts_with("rate_limited"));
}

#[tokio::test]
async fn login_succeeded_helper_records_admin() {
    let cap = uc_audit::capture::start();
    let from = ip("2001:db8:9:6::1");
    crate::auth_audit::login_succeeded(&authenticator(), from, "admin");
    let a = attempts(&cap.events(), from);
    assert_eq!(a.len(), 1);
    assert!(a[0].success);
    assert_eq!(a[0].identity, "admin");
    assert_eq!(a[0].method, AuthMethod::Password);
}

/// SR-40 (decision): an oversize body (400) and a busy refusal (429) are
/// aggregated failures; the first lock of a bucket emits one
/// lockout-engaged record naming its scope.
#[tokio::test]
async fn invalid_format_busy_and_lockout_engaged_are_audited() {
    use crate::login_guard::LoginGuardConfig;

    let _agg = AGGREGATOR.read().await;

    let cap = uc_audit::capture::start();
    let from = ip("2001:db8:9:7::1");
    let long = "u".repeat(4096);
    let resp = login_with(
        &authenticator(),
        &LoginGuard::default(),
        &[],
        from,
        &HeaderMap::new(),
        req(&long, "x"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let a = attempts(&cap.events(), from);
    assert_eq!(a.len(), 1, "{a:?}");
    assert!(reason(&a[0]).starts_with("invalid_format"));
    assert_eq!(a[0].identity, "unknown");
    assert!(
        !serde_json::to_string(&cap.events())
            .unwrap()
            .contains(&long)
    );

    // No verify slots: every login is Busy.
    let from = ip("2001:db8:9:7::2");
    let busy = LoginGuard::new(LoginGuardConfig {
        max_concurrent_verify: 0,
        ..LoginGuardConfig::default()
    });
    for _ in 0..3 {
        let resp = login_with(
            &authenticator(),
            &busy,
            &[],
            from,
            &HeaderMap::new(),
            req("admin", PW),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }
    let a = attempts(&cap.events(), from);
    assert_eq!(a.len(), 1, "aggregated: {a:?}");
    assert!(reason(&a[0]).starts_with("busy"));

    // Lockout engaged once when the per-IP bucket reaches its threshold.
    let from = ip("2001:db8:9:7::3");
    let guard = LoginGuard::default();
    for _ in 0..IP_MAX_FAILURES + 2 {
        let _ = login_with(
            &authenticator(),
            &guard,
            &[],
            from,
            &HeaderMap::new(),
            req("admin", "nope"),
        )
        .await;
    }
    let engaged: Vec<_> = cap
        .events()
        .into_iter()
        .filter_map(|e| match e {
            AuditEvent::RateLimitTriggered(r) if r.source_ip == from => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(engaged.len(), 1, "{engaged:?}");
    assert_eq!(engaged[0].limit_name, "admin-login-lockout:ip");
    assert_eq!(engaged[0].threshold, u64::from(IP_MAX_FAILURES));
}
