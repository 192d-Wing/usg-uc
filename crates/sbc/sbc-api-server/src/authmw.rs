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
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use proto_jwt::Validator;
use sbc_http_util::mgmt_audit::{self, Actor};
use uc_auth::CredentialId;

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
    /// Proxies whose `X-Real-IP` is trusted when resolving the client IP
    /// recorded on the principal (empty: the TCP peer).
    pub trusted_proxies: Arc<Vec<ipnet::IpNet>>,
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
            trusted_proxies: Arc::new(Vec::new()),
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
    /// Display name: `preferred_username` (or `sub`) for OIDC, the token
    /// subject or API-key id for the legacy credential. IdP-mutable, so
    /// never the audit actor (see [`Self::actor_id`]).
    pub user: String,
    /// Stable subject: OIDC `sub`, the session token's subject, or the
    /// API-key id.
    pub subject: String,
    /// Token issuer for OIDC principals (`None` for the legacy credential).
    pub issuer: Option<String>,
    /// Resolved client IP (trusted-proxy aware), when known.
    pub source_ip: Option<IpAddr>,
    /// Which credential authenticated the caller.
    kind: PrincipalKind,
    /// Granted permissions (bit set of `GRANT_*`).
    grants: u8,
}

/// Credential type behind a [`Principal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrincipalKind {
    Session,
    ApiKey,
    Oidc,
}

const GRANT_CDR_READ: u8 = 1 << 0;
const GRANT_CDR_EXPORT: u8 = 1 << 1;
const GRANT_USERS_READ: u8 = 1 << 2;
const GRANT_USERS_ADMIN: u8 = 1 << 3;
const GRANT_CONFIG_ADMIN: u8 = 1 << 4;

impl Principal {
    /// The legacy admin credential (session token or API key): all
    /// permissions.
    // POAM: POA&M-429 (IA-2, AC-2, AU-3) the legacy admin credential and API
    // keys are shared identities: records name `admin:<subject>` or
    // `apikey:<id>`, not an individual operator.
    #[must_use]
    pub fn legacy(cred: CredentialId, source_ip: Option<IpAddr>) -> Self {
        let (subject, kind) = match cred {
            CredentialId::Session { subject } => (subject, PrincipalKind::Session),
            CredentialId::ApiKey { key_id } => (key_id, PrincipalKind::ApiKey),
        };
        Self {
            user: subject.clone(),
            subject,
            issuer: None,
            source_ip,
            kind,
            grants: GRANT_CDR_READ
                | GRANT_CDR_EXPORT
                | GRANT_USERS_READ
                | GRANT_USERS_ADMIN
                | GRANT_CONFIG_ADMIN,
        }
    }

    /// Test shorthand: the legacy session principal for `admin`.
    #[cfg(test)]
    #[must_use]
    pub fn admin() -> Self {
        Self::legacy(
            CredentialId::Session {
                subject: "admin".to_string(),
            },
            None,
        )
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
            subject: c.sub.clone(),
            issuer: None,
            source_ip: None,
            kind: PrincipalKind::Oidc,
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

    /// Canonical actor id for audit records and `updated_by`:
    /// `oidc:<sub>@<iss>`, `admin:<subject>` or `apikey:<id>`.
    ///
    /// ## NIST 800-53 Rev5: AU-3, IA-2
    #[must_use]
    pub fn actor_id(&self) -> String {
        match self.kind {
            PrincipalKind::Oidc => format!(
                "oidc:{}@{}",
                self.subject,
                self.issuer.as_deref().unwrap_or_default()
            ),
            PrincipalKind::Session => format!("admin:{}", self.subject),
            PrincipalKind::ApiKey => format!("apikey:{}", self.subject),
        }
    }

    /// The audit actor (id, issuer, display name for OIDC, source IP).
    #[must_use]
    pub fn actor(&self) -> Actor {
        Actor {
            id: self.actor_id(),
            issuer: self.issuer.clone(),
            display: (self.kind == PrincipalKind::Oidc).then(|| self.user.clone()),
            source_ip: self.source_ip,
        }
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
        let p = req.extensions().get::<Principal>();
        // NIST 800-53 Rev5: AU-3 — the stable actor id, never the
        // IdP-mutable display name.
        let user = p.map_or_else(|| "anonymous".to_string(), Principal::actor_id);
        tracing::warn!(permission = perm, path = %req.uri().path(), %user, "permission denied");
        audit_denied(&user, req.uri().path(), perm, p.and_then(|p| p.source_ip));
    }
    ok
}

/// Records a permission denial (a refused bulk-PII access or account
/// change).
///
/// ## NIST 800-53 Rev5: AU-2 (Event Logging), AC-3 (Access Enforcement)
fn audit_denied(user: &str, path: &str, perm: &str, source_ip: Option<IpAddr>) {
    let policy = if perm.starts_with("users:") {
        "users-rbac"
    } else {
        "cdr-rbac"
    };
    audit_deny(user, path, perm, policy, source_ip);
}

/// One `AuthorizationDecision` deny record, with the resolved client IP.
fn audit_deny(user: &str, path: &str, action: &str, policy: &str, source_ip: Option<IpAddr>) {
    uc_audit::log_event(uc_audit::AuditEvent::AuthorizationDecision(
        uc_audit::event::AuthorizationDecision {
            // NIST 800-53 Rev5: AU-3, SI-10 — same sanitising and 250 B cap
            // as the `ConfigurationChange` actor (round 2, SEC-011).
            identity: mgmt_audit::actor_field(user),
            resource: path.to_string(),
            action: action.to_string(),
            granted: false,
            policy: policy.to_string(),
            source_ip,
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
    // NIST 800-53 Rev5: AU-3 — the client IP recorded on the principal is
    // resolved through the trusted-proxy list, never a raw X-Real-IP.
    let source_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| {
            sbc_http_util::resolve_client_ip(req.headers(), peer.ip(), &auth.trusted_proxies)
        });

    // 1. Legacy cookie / HMAC token / API key.
    let cred = uc_auth::extract_credential(req.headers());
    if let Some(id) = cred.as_deref().and_then(|c| auth.authenticator.identify(c)) {
        req.extensions_mut()
            .insert(Principal::legacy(id, source_ip));
        return next.run(req).await;
    }

    // 2. OIDC operator token (config-admin scope), if configured. A valid
    // token is authenticated, but only a fleet admin is authorized.
    // NIST 800-53 Rev5: AC-3, AC-6, AU-2
    if let Some(validator) = &auth.oidc
        && let Some(token) = bearer(req.headers())
        && let Ok(claims) = validator.validate(&token).await
    {
        let mut principal = Principal::from_claims(&claims).with_issuer(validator.issuer());
        principal.source_ip = source_ip;
        if !principal.is_config_admin() {
            tracing::warn!(path = %req.uri().path(), user = %principal.user, "OIDC principal lacks fleet-admin on all sites");
            audit_deny(
                &principal.actor_id(),
                req.uri().path(),
                CONFIG_ADMIN_ROLE,
                "sbc-api-oidc",
                source_ip,
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

    // A credential was presented and rejected: audited, aggregated per
    // (client bucket, reason). No credential at all is not audited (scanner
    // noise; still a 401).
    // NIST 800-53 Rev5: AU-2, AU-3, SC-5
    if let Some(c) = cred.as_deref() {
        let ip = source_ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let from_cookie = bearer(req.headers()).is_none();
        let method = mgmt_audit::credential_method(c, from_cookie);
        mgmt_audit::auth_failure("unknown", ip, method, "invalid_token");
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
        // SR-40 round 1 (SEC-001): the stable actor id, not preferred_username.
        assert_eq!(denials[0].identity, "oidc:s-1@");
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
        let validator = Arc::new(
            Validator::new(
                Arc::new(proto_jwt::JwksCache::with_static(jwks)),
                proto_jwt::ValidatorConfig {
                    issuer: QA_ISSUER.to_string(),
                    audiences: vec![QA_AUD.to_string()],
                    required_scope: ADMIN_SCOPE,
                    leeway_secs: 30,
                },
            )
            .unwrap(),
        );
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod sr40_tests {
    //! SR-40: the principal carries a stable subject and source IP for
    //! audit attribution; bad credentials are audited (aggregated), absent
    //! ones are not. Each test uses its own documentation-range source IP:
    //! the auth-failure aggregator is process-global.
    //!
    //! ## NIST 800-53 Rev5: AU-2, AU-3, AC-3, IA-2, SC-5

    use std::net::{IpAddr, SocketAddr};
    use std::time::{Duration, Instant};

    use axum::Router;
    use axum::body::Body;
    use axum::extract::{ConnectInfo, Extension};
    use axum::http::StatusCode;
    use axum::routing::get;
    use tower::ServiceExt;
    use uc_audit::AuditEvent;
    use uc_auth::CredentialId;

    use super::*;

    const QA_KID: &str = "sr40-es384";
    const QA_ISSUER: &str = "https://idp.example/realms/sr40";
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

    fn qa_validator(jwks: jsonwebtoken::jwk::JwkSet) -> Arc<Validator> {
        Arc::new(Validator::new(
            Arc::new(proto_jwt::JwksCache::with_static(jwks)),
            proto_jwt::ValidatorConfig {
                issuer: QA_ISSUER.to_string(),
                audiences: vec![QA_AUD.to_string()],
                required_scope: ADMIN_SCOPE,
                leeway_secs: 30,
            },
        ))
    }

    const PW: &str = "sr40-qa-password";

    fn authenticator() -> Arc<uc_auth::Authenticator> {
        let hash = uc_auth::hash_password(PW).unwrap();
        Arc::new(uc_auth::Authenticator::new("admin", &hash, vec![9u8; 48]).unwrap())
    }

    async fn whoami(Extension(p): Extension<Principal>) -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({
            "subject": p.subject,
            "actor_id": p.actor_id(),
            "user": p.user,
            "issuer": p.issuer,
            "source_ip": p.source_ip.map(|i| i.to_string()),
        }))
    }

    fn app(
        authn: Arc<uc_auth::Authenticator>,
        oidc: Option<Arc<Validator>>,
        trusted: &[&str],
    ) -> Router {
        let mut auth = AuthState::new(authn, oidc, &["/healthz"]);
        auth.trusted_proxies = Arc::new(trusted.iter().map(|s| s.parse().unwrap()).collect());
        Router::new()
            .route("/api/v1/whoami", get(whoami).post(whoami))
            .layer(axum::middleware::from_fn_with_state(auth, require_auth))
    }

    async fn call(
        app: &Router,
        peer: &str,
        headers: &[(&str, String)],
    ) -> (StatusCode, serde_json::Value) {
        let mut req = axum::http::Request::get("/api/v1/whoami");
        for (k, v) in headers {
            req = req.header(*k, v);
        }
        let mut req = req.body(Body::empty()).unwrap();
        let peer: SocketAddr = peer.parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(peer));
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    fn auth_events(
        events: &[AuditEvent],
        from: IpAddr,
    ) -> Vec<uc_audit::event::AuthenticationAttempt> {
        events
            .iter()
            .filter_map(|e| match e {
                AuditEvent::AuthenticationAttempt(a) if a.source_ip == from => Some(a.clone()),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn legacy_session_principal_carries_token_subject() {
        let authn = authenticator();
        let token = authn.login("admin", PW).unwrap();
        let app = app(authn, None, &[]);
        let (s, b) = call(
            &app,
            "192.0.2.41:5000",
            &[("authorization", format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["subject"], "admin");
        assert_eq!(b["actor_id"], "admin:admin");
        assert_eq!(b["issuer"], serde_json::Value::Null);
        assert_eq!(b["source_ip"], "192.0.2.41");
        // The cookie path yields the same principal.
        let (s, b) = call(
            &app,
            "192.0.2.41:5000",
            &[("cookie", format!("sbc_session={token}"))],
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["actor_id"], "admin:admin");

        let p = Principal::legacy(
            CredentialId::Session {
                subject: "admin".to_string(),
            },
            None,
        );
        assert_eq!(p.subject, "admin");
        assert_eq!(p.actor_id(), "admin:admin");
        assert!(p.is_config_admin() && p.has(PERM_USERS_ADMIN) && p.has(PERM_CDR_EXPORT));
    }

    #[test]
    fn api_key_principal_carries_key_id() {
        let ip: IpAddr = "192.0.2.42".parse().unwrap();
        let p = Principal::legacy(
            CredentialId::ApiKey {
                key_id: "0123456789abcdef".to_string(),
            },
            Some(ip),
        );
        assert_eq!(p.subject, "0123456789abcdef");
        assert_eq!(p.actor_id(), "apikey:0123456789abcdef");
        assert_eq!(p.source_ip, Some(ip));
        assert!(p.is_config_admin(), "API keys keep full legacy grants");
        let a = p.actor();
        assert_eq!(a.id, "apikey:0123456789abcdef");
        assert_eq!(a.issuer, None);
        assert_eq!(a.source_ip, Some(ip));
    }

    #[tokio::test]
    async fn oidc_principal_subject_is_sub_not_preferred_username() {
        let (key, jwks) = qa_key();
        let app = app(authenticator(), Some(qa_validator(jwks)), &[]);
        let t = qa_token(&key, &["fleet-admin"], &["*"]);
        let (s, b) = call(
            &app,
            "192.0.2.43:5000",
            &[("authorization", format!("Bearer {t}"))],
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["subject"], "s-qa");
        assert_eq!(b["actor_id"], format!("oidc:s-qa@{QA_ISSUER}"));
        assert_eq!(b["user"], "qa-op", "display name kept for humans");
        assert_eq!(b["issuer"], QA_ISSUER);

        let c: proto_jwt::Claims = serde_json::from_value(serde_json::json!({
            "sub": "s-1", "preferred_username": "admin", "roles": ["fleet-admin"], "sites": ["*"],
        }))
        .unwrap();
        let p = Principal::from_claims(&c).with_issuer(QA_ISSUER);
        assert_eq!(p.subject, "s-1");
        // A user who names themselves "admin" in the IdP is not the legacy admin.
        assert_eq!(p.actor_id(), format!("oidc:s-1@{QA_ISSUER}"));
        let a = p.actor();
        assert_eq!(a.issuer.as_deref(), Some(QA_ISSUER));
        assert_eq!(a.display.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn invalid_bearer_is_audited_and_aggregated() {
        let _agg = crate::handlers::login_audit_tests::AGGREGATOR.write().await;
        let (_, jwks) = qa_key();
        let app = app(authenticator(), Some(qa_validator(jwks)), &[]);
        let cap = uc_audit::capture::start();
        let from: IpAddr = "2001:db8:8:1::1".parse().unwrap();
        for i in 0..5 {
            let (s, _) = call(
                &app,
                "[2001:db8:8:1::1]:5000",
                &[("authorization", format!("Bearer not-a-token-{i}"))],
            )
            .await;
            assert_eq!(s, StatusCode::UNAUTHORIZED);
        }
        // A bad session cookie from the same source counts as well.
        let (s, _) = call(
            &app,
            "[2001:db8:8:1::1]:5000",
            &[("cookie", "sbc_session=v2.forged.token".to_string())],
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);

        let a = auth_events(&cap.events(), from);
        assert_eq!(a.len(), 1, "aggregated: {a:?}");
        assert!(!a[0].success);
        let r = a[0].failure_reason.clone().unwrap_or_default();
        assert!(r.starts_with("invalid_token"), "{r}");
        let all = serde_json::to_string(&cap.events()).unwrap();
        assert!(
            !all.contains("not-a-token") && !all.contains("forged"),
            "credentials never logged"
        );

        sbc_http_util::mgmt_audit::flush_auth_failures(Instant::now() + Duration::from_secs(61));
        let a = auth_events(&cap.events(), from);
        assert_eq!(a.len(), 2, "{a:?}");
        let r = a[1].failure_reason.clone().unwrap_or_default();
        assert!(r.ends_with("count=5"), "{r}");
    }

    #[tokio::test]
    async fn missing_credential_is_not_audited() {
        let (_, jwks) = qa_key();
        let app = app(authenticator(), Some(qa_validator(jwks)), &[]);
        let cap = uc_audit::capture::start();
        let from: IpAddr = "2001:db8:8:2::1".parse().unwrap();
        let (s, _) = call(&app, "[2001:db8:8:2::1]:5000", &[]).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let (s, _) = call(
            &app,
            "[2001:db8:8:2::1]:5000",
            &[("authorization", "Basic dXNlcjpwYXNz".to_string())],
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert!(auth_events(&cap.events(), from).is_empty());
        // Public paths never audit.
        assert!(cap.events().is_empty(), "{:?}", cap.events());
    }

    #[tokio::test]
    async fn denial_carries_resolved_source_ip() {
        let (key, jwks) = qa_key();
        let app = app(authenticator(), Some(qa_validator(jwks)), &["10.42.0.0/24"]);
        let t = qa_token(&key, &[], &[]);
        let cap = uc_audit::capture::start();

        // Through the trusted proxy: the relayed client IP is recorded.
        let (s, _) = call(
            &app,
            "10.42.0.9:5000",
            &[
                ("authorization", format!("Bearer {t}")),
                ("x-real-ip", "198.51.100.77".to_string()),
            ],
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        // Direct caller forging X-Real-IP: the TCP peer is recorded.
        let (s, _) = call(
            &app,
            "203.0.113.40:5000",
            &[
                ("authorization", format!("Bearer {t}")),
                ("x-real-ip", "198.51.100.78".to_string()),
            ],
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);

        let ips: Vec<Option<IpAddr>> = cap
            .events()
            .into_iter()
            .filter_map(|e| match e {
                AuditEvent::AuthorizationDecision(d) => Some(d.source_ip),
                _ => None,
            })
            .collect();
        assert_eq!(
            ips,
            vec![
                Some("198.51.100.77".parse().unwrap()),
                Some("203.0.113.40".parse().unwrap())
            ]
        );

        // Route-level RBAC denials use the principal's source IP too.
        let cap = uc_audit::capture::start();
        let mut p = Principal::from_claims(
            &serde_json::from_value(serde_json::json!({
                "sub": "s-2", "roles": ["cdr-reader"]
            }))
            .unwrap(),
        );
        p.source_ip = Some("192.0.2.44".parse().unwrap());
        let rbac = Router::new().route(
            "/cdrs/export",
            get(|| async { "ok" }).route_layer(axum::middleware::from_fn(require_cdr_export)),
        );
        let mut req = axum::http::Request::get("/cdrs/export")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(p);
        assert_eq!(
            rbac.oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let d: Vec<_> = cap
            .events()
            .into_iter()
            .filter_map(|e| match e {
                AuditEvent::AuthorizationDecision(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].source_ip, Some("192.0.2.44".parse().unwrap()));
    }
}

#[cfg(test)]
mod sr40_round2_tests {
    /// SR-40 round 2 (SEC-011): a deny identity is sanitised and capped at
    /// the actor cap.
    #[test]
    fn deny_identity_uses_actor_field() {
        let cap = uc_audit::capture::start();
        let long = format!("oidc:{}\r\n", "s".repeat(400));
        super::audit_deny(&long, "/api/v1/cdrs", "cdr:read", "cdr-rbac", None);
        let ids: Vec<String> = cap
            .events()
            .into_iter()
            .filter_map(|e| match e {
                uc_audit::AuditEvent::AuthorizationDecision(d) => Some(d.identity),
                _ => None,
            })
            .collect();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].len(), sbc_http_util::mgmt_audit::MAX_ACTOR_BYTES);
        assert!(ids[0].starts_with("oidc:s") && !ids[0].contains('\r'));
    }
}
