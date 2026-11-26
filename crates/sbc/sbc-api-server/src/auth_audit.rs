//! Admin login audit (local password path).
//!
//! Successes are recorded per event. Failures (bad credentials, oversize
//! or malformed input, lockout 429, busy 429, bad session token) go through
//! the shared, bounded `mgmt_audit` aggregator, keyed by (client IP,
//! reason). The submitted username is recorded only when it is the
//! configured admin name, else `unknown`, so a password typed into the
//! username field is never stored. Passwords are never logged.
//!
//! ## NIST 800-53 Rev5: AC-7, AU-2, AU-3, IA-2, SC-5

use std::net::IpAddr;
use std::sync::Arc;

use sbc_http_util::mgmt_audit;
use uc_audit::event::AuthMethod;

use crate::handlers::auth::LoginVerifier;

/// Identity recorded for a username that is not the configured admin.
const UNKNOWN: &str = "unknown";

/// `user` if it is the configured admin name, else `unknown`.
fn identity<'a, V: LoginVerifier + ?Sized>(auth: &V, user: &'a str) -> &'a str {
    if auth.is_admin_user(user) {
        user
    } else {
        UNKNOWN
    }
}

/// A local admin login succeeded (after the token is minted).
pub fn login_succeeded<V: LoginVerifier + ?Sized>(auth: &Arc<V>, ip: IpAddr, user: &str) {
    mgmt_audit::auth_success(identity(auth.as_ref(), user), ip, AuthMethod::Password);
}

/// A local admin login failed verification.
pub fn login_failed<V: LoginVerifier + ?Sized>(auth: &Arc<V>, ip: IpAddr, user: &str) {
    mgmt_audit::auth_failure(
        identity(auth.as_ref(), user),
        ip,
        AuthMethod::Password,
        "invalid_credentials",
    );
}

/// A login was refused because the client IP or the account is locked
/// (429).
pub fn login_rate_limited(ip: IpAddr) {
    mgmt_audit::auth_failure(UNKNOWN, ip, AuthMethod::Password, "rate_limited");
}

/// A login was refused because every verify slot was taken (429).
pub fn login_busy(ip: IpAddr) {
    mgmt_audit::auth_failure(UNKNOWN, ip, AuthMethod::Password, "busy");
}

/// A login body failed the input bounds (400).
pub fn login_invalid_format(ip: IpAddr) {
    mgmt_audit::auth_failure(UNKNOWN, ip, AuthMethod::Password, "invalid_format");
}

/// `/auth/session` was given a credential that did not validate.
pub fn session_rejected(ip: IpAddr, credential: &str, headers: &axum::http::HeaderMap) {
    // `extract_credential` prefers the bearer header; without one the
    // credential came from the session cookie.
    let from_cookie = !headers.contains_key(axum::http::header::AUTHORIZATION);
    let method = mgmt_audit::credential_method(credential, from_cookie);
    mgmt_audit::auth_failure(UNKNOWN, ip, method, "invalid_token");
}

/// A lockout bucket (`ip`, `ip-overflow` or `account`) just reached its
/// threshold. Emitted once per bucket per window (bounded by the guard's
/// tables).
///
/// ## NIST 800-53 Rev5: AC-7, AU-2
pub fn lockout_engaged(ip: IpAddr, scope: &'static str, failures: u32, threshold: u32) {
    uc_audit::log_event(uc_audit::AuditEvent::RateLimitTriggered(
        uc_audit::event::RateLimitTriggered {
            source_ip: ip,
            limit_name: format!("admin-login-lockout:{scope}"),
            request_count: u64::from(failures),
            threshold: u64::from(threshold),
        },
    ));
}
