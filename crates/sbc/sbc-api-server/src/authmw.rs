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
//!    issuer/audience with the `config-admin` scope **and** whose claims make
//!    the caller a fleet admin: role `fleet-admin` and `sites` containing
//!    `"*"`. A client may request a scope, so the scope is only a coarse
//!    gate; a valid token without the role and site grant gets 403.
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

/// The OIDC scope an operator token must carry to reach the management API.
/// It is a coarse gate only and authorizes nothing by itself: the caller
/// also needs role `fleet-admin` on sites `"*"` (see [`Principal::is_config_admin`]).
pub const ADMIN_SCOPE: &str = "config-admin";

/// OIDC role that makes a caller a config admin on sbc-api (together with
/// the `"*"` site grant).
const CONFIG_ADMIN_ROLE: &str = "fleet-admin";

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

/// Permission to list/read managed SIP user accounts.
pub const PERM_USERS_READ: &str = "users:read";
/// Permission to create, modify or delete managed SIP user accounts.
pub const PERM_USERS_ADMIN: &str = "users:admin";

/// OIDC roles granting user-account read (`config-admin` alone does not:
/// SIP accounts are a toll-fraud entry point, AC-6).
const USERS_READ_ROLES: &[&str] = &["fleet-admin", "auditor", "users-admin", "users-reader"];
/// OIDC roles granting user-account administration.
const USERS_ADMIN_ROLES: &[&str] = &["fleet-admin", "users-admin"];

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
    /// Token issuer for OIDC principals (`None` for the legacy credential).
    pub issuer: Option<String>,
    /// Granted permissions (bit set of `GRANT_*`).
    grants: u8,
}

const GRANT_CDR_READ: u8 = 1 << 0;
const GRANT_CDR_EXPORT: u8 = 1 << 1;
const GRANT_USERS_READ: u8 = 1 << 2;
const GRANT_USERS_ADMIN: u8 = 1 << 3;
const GRANT_CONFIG_ADMIN: u8 = 1 << 4;

impl Principal {
    /// The legacy admin credential (single administrator / API key): all
    /// permissions.
    #[must_use]
    pub fn admin() -> Self {
        Self {
            user: "admin".to_string(),
            issuer: None,
            grants: GRANT_CDR_READ
                | GRANT_CDR_EXPORT
                | GRANT_USERS_READ
                | GRANT_USERS_ADMIN
                | GRANT_CONFIG_ADMIN,
        }
    }

    /// An OIDC operator: permissions from roles only (scopes grant nothing).
    #[must_use]
    pub fn from_claims(c: &proto_jwt::Claims) -> Self {
        let role = |set: &[&str]| c.roles.iter().any(|r| set.contains(&r.as_str()));
        // NIST 800-53 Rev5: AC-3, AC-6 — every grant comes from roles (and
        // sites), never from requested scopes: a client chooses its scopes.
        let cdr_export = role(CDR_EXPORT_ROLES);
        let cdr_read = cdr_export || role(CDR_READ_ROLES);
        let users_admin = role(USERS_ADMIN_ROLES);
        let users_read = users_admin || role(USERS_READ_ROLES);
        // NIST 800-53 Rev5: AC-3, AC-6 — config admin from claims only (role
        // and fleet site grant), never from the requested scope.
        let config_admin = role(&[CONFIG_ADMIN_ROLE]) && c.sites.iter().any(|s| s == "*");
        let bit = |b: u8, on: bool| if on { b } else { 0 };
        Self {
            user: c
                .preferred_username
                .clone()
                .unwrap_or_else(|| c.sub.clone()),
            issuer: None,
            grants: bit(GRANT_CDR_READ, cdr_read)
                | bit(GRANT_CDR_EXPORT, cdr_export)
                | bit(GRANT_USERS_READ, users_read)
                | bit(GRANT_USERS_ADMIN, users_admin)
                | bit(GRANT_CONFIG_ADMIN, config_admin),
        }
    }

    /// Whether this principal may use the management API: the legacy admin
    /// credential, or an OIDC operator with role `fleet-admin` on sites
    /// `"*"`.
    ///
    /// ## NIST 800-53 Rev5: AC-3, AC-6
    #[must_use]
    pub const fn is_config_admin(&self) -> bool {
        self.grants & GRANT_CONFIG_ADMIN != 0
    }

    /// Record the (validated) issuer that vouched for this principal.
    #[must_use]
    pub fn with_issuer(mut self, issuer: &str) -> Self {
        self.issuer = Some(issuer.to_string());
        self
    }

    /// Whether `perm` is granted.
    #[must_use]
    pub fn has(&self, perm: &str) -> bool {
        let bit = match perm {
            PERM_CDR_READ => GRANT_CDR_READ,
            PERM_CDR_EXPORT => GRANT_CDR_EXPORT,
            PERM_USERS_READ => GRANT_USERS_READ,
            PERM_USERS_ADMIN => GRANT_USERS_ADMIN,
            _ => return false,
        };
        self.grants & bit != 0
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

/// Records a permission denial (a refused bulk-PII access or account
/// change).
///
/// ## NIST 800-53 Rev5: AU-2 (Event Logging), AC-3 (Access Enforcement)
fn audit_denied(user: &str, path: &str, perm: &str) {
    let policy = if perm.starts_with("users:") {
        "users-rbac"
    } else {
        "cdr-rbac"
    };
    audit_deny(user, path, perm, policy);
}

/// One `AuthorizationDecision` deny record.
// POAM: POA&M-386 (AU-3) `source_ip` is not recorded on these denials.
fn audit_deny(user: &str, path: &str, action: &str, policy: &str) {
    uc_audit::log_event(uc_audit::AuditEvent::AuthorizationDecision(
        uc_audit::event::AuthorizationDecision {
            identity: user.to_string(),
            resource: path.to_string(),
            action: action.to_string(),
            granted: false,
            policy: policy.to_string(),
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

/// Route layer: requires `users:read`.
///
/// ## NIST 800-53 Rev5: AC-3, AC-6
pub async fn require_users_read(req: Request, next: Next) -> Response {
    if permitted(&req, PERM_USERS_READ) {
        next.run(req).await
    } else {
        forbidden(PERM_USERS_READ)
    }
}

/// Route layer: requires `users:admin`.
///
/// ## NIST 800-53 Rev5: AC-2, AC-3, AC-6
pub async fn require_users_admin(req: Request, next: Next) -> Response {
    if permitted(&req, PERM_USERS_ADMIN) {
        next.run(req).await
    } else {
        forbidden(PERM_USERS_ADMIN)
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

    // 2. OIDC operator token (config-admin scope), if configured. A valid
    // token is authenticated, but only a fleet admin is authorized.
    // NIST 800-53 Rev5: AC-3, AC-6, AU-2
    if let Some(validator) = &auth.oidc
        && let Some(token) = bearer(req.headers())
        && let Ok(claims) = validator.validate(&token).await
    {
        let principal = Principal::from_claims(&claims).with_issuer(validator.issuer());
        if !principal.is_config_admin() {
            tracing::warn!(path = %req.uri().path(), user = %principal.user, "OIDC principal lacks fleet-admin on all sites");
            audit_deny(
                &principal.user,
                req.uri().path(),
                CONFIG_ADMIN_ROLE,
                "sbc-api-oidc",
            );
            return (
                StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({ "error": "insufficient role" })),
            )
                .into_response();
        }
        req.extensions_mut().insert(principal);
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
        // A requested permission scope grants nothing; only roles do.
        let p = Principal::from_claims(&claims(&[], "config-admin cdr:read cdr:export"));
        assert!(!p.has(PERM_CDR_READ) && !p.has(PERM_CDR_EXPORT));
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
    fn users_permissions_from_claims() {
        let p = Principal::from_claims(&claims(&[], "config-admin"));
        assert!(!p.has(PERM_USERS_READ) && !p.has(PERM_USERS_ADMIN));
        let p = Principal::from_claims(&claims(&["users-reader"], "config-admin"));
        assert!(p.has(PERM_USERS_READ) && !p.has(PERM_USERS_ADMIN));
        let p = Principal::from_claims(&claims(&["auditor"], "config-admin"));
        assert!(p.has(PERM_USERS_READ) && !p.has(PERM_USERS_ADMIN));
        let p = Principal::from_claims(&claims(&["cdr-exporter"], "config-admin"));
        assert!(!p.has(PERM_USERS_READ));
        for r in ["users-admin", "fleet-admin"] {
            let p = Principal::from_claims(&claims(&[r], "config-admin"));
            assert!(p.has(PERM_USERS_READ) && p.has(PERM_USERS_ADMIN), "{r}");
        }
        // A requested permission scope grants nothing; only roles do.
        let p = Principal::from_claims(&claims(&[], "config-admin users:read users:admin"));
        assert!(!p.has(PERM_USERS_READ) && !p.has(PERM_USERS_ADMIN));
        assert!(Principal::admin().has(PERM_USERS_ADMIN));
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
    // --- QA: OIDC access to sbc-api needs a fleet admin ---------

    fn claims_sites(roles: &[&str], sites: &[&str], scope: &str) -> proto_jwt::Claims {
        serde_json::from_value(serde_json::json!({
            "sub": "s-1",
            "preferred_username": "op1",
            "roles": roles,
            "sites": sites,
            "scope": scope,
        }))
        .unwrap()
    }

    #[test]
    fn qa_scope_only_oidc_principal_is_not_config_admin() {
        let p = Principal::from_claims(&claims_sites(&[], &[], "config config-admin"));
        assert!(!p.is_config_admin());
        let p = Principal::from_claims(&claims_sites(&["auditor"], &["*"], "config-admin"));
        assert!(!p.is_config_admin(), "a read role is not config admin");
        let p = Principal::from_claims(&claims_sites(&["fleet-admin"], &["*"], "config-admin"));
        assert!(p.is_config_admin());
        assert!(Principal::admin().is_config_admin(), "legacy credential");
    }

    #[test]
    fn qa_fleet_admin_without_star_site_is_not_config_admin() {
        for sites in [&[][..], &["MUHJ"][..], &["MUHJ", "MPLS"][..]] {
            let p = Principal::from_claims(&claims_sites(&["fleet-admin"], sites, "config-admin"));
            assert!(!p.is_config_admin(), "sites={sites:?}");
        }
    }

    const QA_KID: &str = "qa-es384";
    const QA_ISSUER: &str = "https://idp.example/realms/qa";
    const QA_AUD: &str = "sbc-api";

    /// A fresh P-384 key: (JWT signing key, static JWKS).
    fn qa_key() -> (jsonwebtoken::EncodingKey, jsonwebtoken::jwk::JwkSet) {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &SystemRandom::new())
                .unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let point = pair.public_key().as_ref();
        let jwks = serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "EC", "crv": "P-384", "kid": QA_KID, "alg": "ES384", "use": "sig",
                "x": URL_SAFE_NO_PAD.encode(&point[1..49]),
                "y": URL_SAFE_NO_PAD.encode(&point[49..97]),
            }]
        }))
        .unwrap();
        (jsonwebtoken::EncodingKey::from_ec_der(pkcs8.as_ref()), jwks)
    }

    fn qa_token(key: &jsonwebtoken::EncodingKey, roles: &[&str], sites: &[&str]) -> String {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES384);
        header.kid = Some(QA_KID.to_string());
        let claims = serde_json::json!({
            "sub": "s-qa", "preferred_username": "qa-op", "iss": QA_ISSUER, "aud": QA_AUD,
            "exp": exp, "scope": "openid config-admin", "roles": roles, "sites": sites,
        });
        jsonwebtoken::encode(&header, &claims, key).unwrap()
    }

    fn qa_app(jwks: jsonwebtoken::jwk::JwkSet) -> Router {
        let validator = Arc::new(Validator::new(
            Arc::new(proto_jwt::JwksCache::with_static(jwks)),
            proto_jwt::ValidatorConfig {
                issuer: QA_ISSUER.to_string(),
                audiences: vec![QA_AUD.to_string()],
                required_scope: ADMIN_SCOPE,
                leeway_secs: 30,
            },
        ));
        let authenticator = Arc::new(
            uc_auth::Authenticator::new("admin", "not-a-phc-hash", vec![7u8; 48]).unwrap(),
        );
        let auth = AuthState::new(authenticator, Some(validator), &["/healthz"]);
        Router::new()
            .route("/api/v1/trunkgroups", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(auth, require_auth))
    }

    async fn qa_get(app: &Router, token: &str) -> StatusCode {
        let req = axum::http::Request::get("/api/v1/trunkgroups")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        app.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn qa_require_auth_forbids_non_admin_oidc_principal() {
        let (key, jwks) = qa_key();
        let app = qa_app(jwks);

        // Control: a fleet admin on every site gets through.
        assert_eq!(
            qa_get(&app, &qa_token(&key, &["fleet-admin"], &["*"])).await,
            StatusCode::OK
        );

        let capture = uc_audit::capture::start();
        // A validly signed token carrying the scope but no admin role.
        assert_eq!(
            qa_get(&app, &qa_token(&key, &[], &[])).await,
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
        assert_eq!(denials.len(), 1, "{denials:?}");
        assert!(!denials[0].granted);
        assert_eq!(denials[0].policy, "sbc-api-oidc");
        assert_eq!(denials[0].resource, "/api/v1/trunkgroups");

        // A fleet admin restricted to one site is not a fleet admin here.
        assert_eq!(
            qa_get(&app, &qa_token(&key, &["fleet-admin"], &["MUHJ"])).await,
            StatusCode::FORBIDDEN
        );
    }
}
