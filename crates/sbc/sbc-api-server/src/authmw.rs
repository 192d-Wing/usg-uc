//! Auth middleware accepting either the legacy admin credential or an
//! operator OIDC bearer token.
//!
//! sbc-api historically authenticated with a `uc-auth` cookie/HMAC admin
//! login. To unify the dashboard on a single sign-in, this middleware also
//! accepts the same operator OIDC tokens the central config API takes
//! (scope `config-admin`). A request is allowed if EITHER check passes:
//!
//! 1. the legacy path — `uc_auth::Authenticator::authorize` (HMAC session
//!    token or API key, from the `Authorization: Bearer` header or the
//!    `sbc_session` cookie), or
//! 2. the OIDC path — a bearer token that validates against the configured
//!    issuer/audience with the `config-admin` scope.
//!
//! The legacy check runs first (cheap, sync); OIDC is only tried when it
//! fails, and only when an OIDC validator is configured.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use proto_jwt::Validator;

/// The OIDC scope an operator token must carry to use the management API —
/// the same scope the central config API requires for writes.
pub const ADMIN_SCOPE: &str = "config-admin";

/// Shared state for [`require_auth`].
#[derive(Clone)]
pub struct AuthState {
    /// Legacy cookie/HMAC/API-key authenticator.
    pub authenticator: Arc<uc_auth::Authenticator>,
    /// Optional operator OIDC validator (config-admin scope).
    pub oidc: Option<Arc<Validator>>,
    /// Paths exempt from auth (exact match).
    pub public_paths: Arc<HashSet<String>>,
}

impl AuthState {
    /// Build from the authenticator, optional validator, and exempt paths.
    pub fn new(
        authenticator: Arc<uc_auth::Authenticator>,
        oidc: Option<Arc<Validator>>,
        public_paths: &[&str],
    ) -> Self {
        Self {
            authenticator,
            oidc,
            public_paths: Arc::new(public_paths.iter().map(|s| (*s).to_string()).collect()),
        }
    }
}

/// Pull a `Bearer` token from the `Authorization` header (OIDC tokens only
/// arrive there, never as a cookie).
fn bearer(headers: &header::HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|t| t.trim().to_string())
}

/// Deny-by-default middleware accepting the legacy credential or an OIDC
/// operator token.
///
/// ## NIST 800-53 Rev5: AC-3 (Access Enforcement)
pub async fn require_auth(State(auth): State<AuthState>, req: Request, next: Next) -> Response {
    if auth.public_paths.contains(req.uri().path()) {
        return next.run(req).await;
    }

    // 1. Legacy cookie / HMAC token / API key.
    if let Some(cred) = uc_auth::extract_credential(req.headers())
        && auth.authenticator.authorize(&cred)
    {
        return next.run(req).await;
    }

    // 2. OIDC operator token (config-admin), if configured.
    if let Some(validator) = &auth.oidc
        && let Some(token) = bearer(req.headers())
        && validator.validate(&token).await.is_ok()
    {
        return next.run(req).await;
    }

    (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({ "error": "authentication required" })),
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::bearer;
    use axum::http::{HeaderMap, header};

    #[test]
    fn bearer_parses_only_the_bearer_scheme() {
        let mut h = HeaderMap::new();
        assert_eq!(bearer(&h), None, "no header");

        h.insert(
            header::AUTHORIZATION,
            "Bearer  abc.def.ghi ".parse().unwrap(),
        );
        assert_eq!(bearer(&h).as_deref(), Some("abc.def.ghi"), "trimmed token");

        h.insert(header::AUTHORIZATION, "Basic dXNlcjpwYXNz".parse().unwrap());
        assert_eq!(bearer(&h), None, "non-Bearer scheme ignored");
    }
}
