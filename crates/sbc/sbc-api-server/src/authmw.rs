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

/// Permission to read CDRs (list, show, stats).
pub const PERM_CDR_READ: &str = "cdr:read";
/// Permission to export CDRs in bulk.
pub const PERM_CDR_EXPORT: &str = "cdr:export";

/// OIDC roles granting CDR read access (CDRs carry PII, so `config-admin`
/// alone does not grant it: AC-6 least privilege).
const CDR_READ_ROLES: &[&str] = &["fleet-admin", "auditor", "cdr-reader", "cdr-exporter"];
/// OIDC roles granting CDR export.
const CDR_EXPORT_ROLES: &[&str] = &["fleet-admin", "cdr-exporter"];

/// The authenticated caller, inserted as a request extension by
/// [`require_auth`] and checked by per-route permission layers.
///
/// ## NIST 800-53 Rev5: AC-3 (Access Enforcement), AC-6 (Least Privilege)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Identity for audit records.
    pub user: String,
    /// Granted CDR read.
    pub cdr_read: bool,
    /// Granted CDR export.
    pub cdr_export: bool,
}

impl Principal {
    /// The legacy admin credential (single administrator / API key): all
    /// permissions.
    #[must_use]
    pub fn admin() -> Self {
        Self {
            user: "admin".to_string(),
            cdr_read: true,
            cdr_export: true,
        }
    }

    /// An OIDC operator: CDR permissions from roles or explicit scopes.
    #[must_use]
    pub fn from_claims(c: &proto_jwt::Claims) -> Self {
        let role = |set: &[&str]| c.roles.iter().any(|r| set.contains(&r.as_str()));
        let cdr_export = role(CDR_EXPORT_ROLES) || c.has_scope(PERM_CDR_EXPORT);
        Self {
            user: c
                .preferred_username
                .clone()
                .unwrap_or_else(|| c.sub.clone()),
            cdr_read: cdr_export || role(CDR_READ_ROLES) || c.has_scope(PERM_CDR_READ),
            cdr_export,
        }
    }

    /// Whether `perm` is granted.
    #[must_use]
    pub fn has(&self, perm: &str) -> bool {
        match perm {
            PERM_CDR_READ => self.cdr_read,
            PERM_CDR_EXPORT => self.cdr_export,
            _ => false,
        }
    }
}

/// Whether the authenticated principal holds `perm`; logs a denial.
fn permitted(req: &Request, perm: &str) -> bool {
    let ok = req
        .extensions()
        .get::<Principal>()
        .is_some_and(|p| p.has(perm));
    if !ok {
        let user = req
            .extensions()
            .get::<Principal>()
            .map_or_else(|| "anonymous".to_string(), |p| p.user.clone());
        tracing::warn!(permission = perm, path = %req.uri().path(), %user, "permission denied");
        audit_denied(&user, req.uri().path(), perm);
    }
    ok
}

/// Records a CDR permission denial (a refused bulk-PII access).
///
/// ## NIST 800-53 Rev5: AU-2 (Event Logging), AC-3 (Access Enforcement)
fn audit_denied(user: &str, path: &str, perm: &str) {
    uc_audit::log_event(uc_audit::AuditEvent::AuthorizationDecision(
        uc_audit::event::AuthorizationDecision {
            identity: user.to_string(),
            resource: path.to_string(),
            action: perm.to_string(),
            granted: false,
            policy: "cdr-rbac".to_string(),
            source_ip: None,
        },
    ));
}

fn forbidden(perm: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        axum::Json(serde_json::json!({ "error": format!("permission {perm} required") })),
    )
        .into_response()
}

/// Route layer: requires `cdr:read`.
///
/// ## NIST 800-53 Rev5: AC-3, AC-6
pub async fn require_cdr_read(req: Request, next: Next) -> Response {
    if permitted(&req, PERM_CDR_READ) {
        next.run(req).await
    } else {
        forbidden(PERM_CDR_READ)
    }
}

/// Route layer: requires `cdr:export`.
///
/// ## NIST 800-53 Rev5: AC-3, AC-6
pub async fn require_cdr_export(req: Request, next: Next) -> Response {
    if permitted(&req, PERM_CDR_EXPORT) {
        next.run(req).await
    } else {
        forbidden(PERM_CDR_EXPORT)
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
pub async fn require_auth(State(auth): State<AuthState>, mut req: Request, next: Next) -> Response {
    if auth.public_paths.contains(req.uri().path()) {
        return next.run(req).await;
    }

    // 1. Legacy cookie / HMAC token / API key.
    if let Some(cred) = uc_auth::extract_credential(req.headers())
        && auth.authenticator.authorize(&cred)
    {
        req.extensions_mut().insert(Principal::admin());
        return next.run(req).await;
    }

    // 2. OIDC operator token (config-admin), if configured.
    if let Some(validator) = &auth.oidc
        && let Some(token) = bearer(req.headers())
        && let Ok(claims) = validator.validate(&token).await
    {
        req.extensions_mut().insert(Principal::from_claims(&claims));
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
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::http::{HeaderMap, header};
    use axum::routing::get;
    use tower::ServiceExt;

    fn claims(roles: &[&str], scope: &str) -> proto_jwt::Claims {
        serde_json::from_value(serde_json::json!({
            "sub": "s-1",
            "preferred_username": "op1",
            "roles": roles,
            "scope": scope,
        }))
        .unwrap()
    }

    #[test]
    fn cdr_permissions_from_claims() {
        let p = Principal::from_claims(&claims(&[], "config-admin"));
        assert!(!p.has(PERM_CDR_READ) && !p.has(PERM_CDR_EXPORT));
        assert_eq!(p.user, "op1");
        let p = Principal::from_claims(&claims(&["auditor"], "config-admin"));
        assert!(p.has(PERM_CDR_READ) && !p.has(PERM_CDR_EXPORT));
        let p = Principal::from_claims(&claims(&[], "config-admin cdr:export"));
        assert!(p.has(PERM_CDR_READ) && p.has(PERM_CDR_EXPORT));
        assert!(Principal::admin().has(PERM_CDR_EXPORT));
        assert!(!Principal::admin().has("cdr:admin"));
    }

    async fn status_with(principal: Option<Principal>, path: &str) -> StatusCode {
        let app = Router::new()
            .route(
                "/cdrs",
                get(|| async { "ok" }).route_layer(axum::middleware::from_fn(require_cdr_read)),
            )
            .route(
                "/cdrs/export",
                get(|| async { "ok" }).route_layer(axum::middleware::from_fn(require_cdr_export)),
            );
        let mut req = axum::http::Request::get(path).body(Body::empty()).unwrap();
        if let Some(p) = principal {
            req.extensions_mut().insert(p);
        }
        app.oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn cdr_routes_deny_without_permission() {
        let reader = Principal::from_claims(&claims(&["cdr-reader"], "config-admin"));
        let nobody = Principal::from_claims(&claims(&[], "config-admin"));
        assert_eq!(status_with(None, "/cdrs").await, StatusCode::FORBIDDEN);
        assert_eq!(
            status_with(Some(nobody), "/cdrs").await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status_with(Some(reader.clone()), "/cdrs").await,
            StatusCode::OK
        );
        assert_eq!(
            status_with(Some(reader), "/cdrs/export").await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status_with(Some(Principal::admin()), "/cdrs/export").await,
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn cdr_denial_is_audited_with_user() {
        let capture = uc_audit::capture::start();
        let reader = Principal::from_claims(&claims(&["cdr-reader"], "config-admin"));
        assert_eq!(
            status_with(Some(reader), "/cdrs/export").await,
            StatusCode::FORBIDDEN
        );
        let denials: Vec<_> = capture
            .events()
            .into_iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::AuthorizationDecision(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].identity, "op1");
        assert_eq!(denials[0].action, PERM_CDR_EXPORT);
        assert_eq!(denials[0].resource, "/cdrs/export");
        assert!(!denials[0].granted);
    }

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
