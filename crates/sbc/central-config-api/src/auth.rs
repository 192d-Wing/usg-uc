//! Site-scoped authorization for the sync surface.
//!
//! A request to `/v1/sync/{site_code}/...` must present a bearer token
//! that (1) validates against the configured OIDC issuer/audience, (2)
//! carries the `config-sync` scope, and (3) has a `site_code` claim equal
//! to the `{site_code}` in the path. The third check is the security
//! boundary: a base's credential can only ever pull its own shard, so a
//! compromised or misconfigured site cannot read another's config.

use std::net::{IpAddr, Ipv4Addr};

use axum::Json;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use proto_jwt::{Claims, ValidateError, Validator};
use sbc_http_util::mgmt_audit;
use serde_json::json;
use uc_audit::event::AuthMethod;

use crate::policy::{Action, Subject};

tokio::task_local! {
    /// Client IP of the request being served, scoped by the router's
    /// `peer_ip` middleware (trusted-proxy aware), so the `authorize_*`
    /// helpers can audit a reject without a signature change.
    pub static PEER_IP: IpAddr;
}

/// The current request's client IP, or `0.0.0.0` outside a request scope.
pub fn peer_ip() -> IpAddr {
    PEER_IP
        .try_with(|ip| *ip)
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

/// Canonical audit actor id for a validated operator token.
pub fn actor_id(claims: &Claims, validator: &Validator) -> String {
    format!("oidc:{}@{}", claims.sub, validator.issuer())
}

/// Records a rejected token (aggregated per (client /64, reason)). A
/// request with no bearer is not audited (scanner noise; still a 401). No
/// attempt limit is enforced here.
///
/// ## NIST 800-53 Rev5: AU-2, AU-3, SC-5
fn audit_reject(identity: &str, reason: &'static str) {
    mgmt_audit::auth_failure(identity, peer_ip(), AuthMethod::Jwt, reason);
}

/// Maps a validation error to its rejection, auditing it.
fn rejected(e: ValidateError) -> AuthRejection {
    match e {
        ValidateError::InsufficientScope => {
            audit_reject("unknown", "insufficient_scope");
            AuthRejection::InsufficientScope
        }
        other => {
            audit_reject("unknown", "invalid_token");
            AuthRejection::Unauthorized(other.to_string())
        }
    }
}

/// Why a sync request was refused. Maps to RFC 6750 challenge semantics.
#[derive(Debug)]
pub enum AuthRejection {
    /// No/garbled token, bad signature, wrong issuer/audience/expiry →
    /// 401 with a `WWW-Authenticate: Bearer` challenge.
    Unauthorized(String),
    /// Token is valid but lacks the `config-sync` scope → 403.
    InsufficientScope,
    /// Token is valid but its `site_code` claim doesn't match the path
    /// (or is absent) → 403. The token simply isn't for this shard.
    WrongSite,
    /// Token is valid but the subject's roles/sites don't grant the
    /// requested action on the target site (ABAC) → 403.
    Forbidden,
}

impl IntoResponse for AuthRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthorized(detail) => (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")],
                Json(json!({ "error": "unauthorized", "detail": detail })),
            )
                .into_response(),
            Self::InsufficientScope => (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "insufficient_scope" })),
            )
                .into_response(),
            Self::WrongSite => (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "wrong_site",
                    "detail": "token site_code does not match the requested site" })),
            )
                .into_response(),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                Json(json!({ "error": "forbidden",
                    "detail": "the token's roles/sites do not grant this action" })),
            )
                .into_response(),
        }
    }
}

/// Extract the `Bearer` token from an `Authorization` header.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// Validate the request's token and confirm it is scoped to `site_code`.
/// Returns the validated [`Claims`] on success.
///
/// # Errors
/// [`AuthRejection`] for a missing/invalid token, missing scope, or a
/// token scoped to a different site.
pub async fn authorize_site(
    validator: &Validator,
    headers: &HeaderMap,
    site_code: &str,
) -> Result<Claims, AuthRejection> {
    let token = bearer(headers)
        .ok_or_else(|| AuthRejection::Unauthorized("missing bearer token".to_string()))?;
    let claims = validator.validate(token).await.map_err(rejected)?;
    if claims.site_code.as_deref() == Some(site_code) {
        Ok(claims)
    } else {
        audit_reject(&actor_id(&claims, validator), "wrong_site");
        Err(AuthRejection::WrongSite)
    }
}

/// Validate an operator token and authorize a single ABAC [`Action`] on a
/// target site. The `admin_validator` first enforces the coarse
/// [`OPERATOR_SCOPE`](crate::state::OPERATOR_SCOPE) gate; then the token's
/// `roles`/`sites` claims must grant `action` on `site` (see
/// [`crate::policy`]). For fleet-level entities (the site registry,
/// templates) pass `site = None`.
///
/// Returns the validated [`Claims`] on success so a handler can attribute
/// the change to `claims.sub`.
///
/// # Errors
/// [`AuthRejection`] for a missing/invalid token, a token lacking the
/// operator scope, or one whose roles/sites don't grant the action.
pub async fn authorize_action(
    validator: &Validator,
    headers: &HeaderMap,
    action: Action,
    site: Option<&str>,
) -> Result<Claims, AuthRejection> {
    let token = bearer(headers)
        .ok_or_else(|| AuthRejection::Unauthorized("missing bearer token".to_string()))?;
    let claims = validator.validate(token).await.map_err(rejected)?;
    if Subject::from_claims(&claims).permits(action, site) {
        crate::write_audit::set_actor(&claims, validator);
        Ok(claims)
    } else {
        // An authenticated operator: one record per refusal, with sub@iss.
        // NIST 800-53 Rev5: AC-3, AU-2, AU-3
        uc_audit::log_event(uc_audit::AuditEvent::AuthorizationDecision(
            uc_audit::event::AuthorizationDecision {
                // Round 2 (SEC-011): the actor cap, as on the change record.
                identity: mgmt_audit::actor_field(&actor_id(&claims, validator)),
                resource: site.map_or_else(|| "fleet".to_string(), mgmt_audit::audit_field),
                action: action.label(),
                granted: false,
                policy: "central-abac".to_string(),
                source_ip: Some(peer_ip()),
            },
        ));
        Err(AuthRejection::Forbidden)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod audit_tests {
    //! SR-40: rejected operator/sync tokens are audited, aggregated per
    //! (peer /64, reason). The peer IP comes from the [`PEER_IP`] task-local
    //! the router's middleware scopes. Every test uses its own source /64:
    //! the aggregator is process-global. No attempt limit is enforced here.
    //!
    //! ## NIST 800-53 Rev5: AU-2, AU-3, IA-2, SC-5

    use std::net::IpAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use axum::http::{HeaderMap, header};
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use proto_jwt::{JwksCache, Validator, ValidatorConfig};
    use serde_json::json;
    use uc_audit::AuditEvent;

    use super::{AuthRejection, PEER_IP, authorize_action, authorize_site};
    use crate::policy::{Action, Entity, Verb};
    use crate::state::{OPERATOR_SCOPE, SYNC_SCOPE};

    const KID: &str = "sr40-key";
    const ISS: &str = "https://idp.example.mil/realms/config";
    const AUD: &str = "usg-uc-config-sync";

    fn key() -> &'static (EncodingKey, JwkSet) {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        static KEY: std::sync::OnceLock<(EncodingKey, JwkSet)> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P384_SHA384_FIXED_SIGNING,
                &SystemRandom::new(),
            )
            .unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
            let point = pair.public_key().as_ref();
            let jwks = serde_json::from_value(json!({
                "keys": [{
                    "kty": "EC", "crv": "P-384", "kid": KID, "alg": "ES384", "use": "sig",
                    "x": URL_SAFE_NO_PAD.encode(&point[1..49]),
                    "y": URL_SAFE_NO_PAD.encode(&point[49..97]),
                }]
            }))
            .unwrap();
            (EncodingKey::from_ec_der(pkcs8.as_ref()), jwks)
        })
    }

    fn validator(scope: &'static str) -> Validator {
        Validator::new(
            Arc::new(JwksCache::with_static(key().1.clone())),
            ValidatorConfig {
                issuer: ISS.to_string(),
                audiences: vec![AUD.to_string()],
                required_scope: scope,
                leeway_secs: 30,
            },
        )
        .expect("validator config")
    }

    fn token(
        sub: &str,
        scope: &str,
        site_code: Option<&str>,
        roles: &[&str],
        sites: &[&str],
    ) -> String {
        let exp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        let mut c = json!({
            "sub": sub, "iss": ISS, "aud": AUD, "scope": scope, "exp": exp,
            "roles": roles, "sites": sites,
        });
        if let Some(s) = site_code {
            c["site_code"] = json!(s);
        }
        let mut h = Header::new(jsonwebtoken::Algorithm::ES384);
        h.kid = Some(KID.to_string());
        encode(&h, &c, &key().0).unwrap()
    }

    fn bearer(t: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Bearer {t}").parse().unwrap(),
        );
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Audit records (authentication or authorization) naming `from`.
    fn records_from(events: &[AuditEvent], from: IpAddr) -> Vec<AuditEvent> {
        events
            .iter()
            .filter(|e| match e {
                AuditEvent::AuthenticationAttempt(a) => a.source_ip == from,
                AuditEvent::AuthorizationDecision(d) => d.source_ip == Some(from),
                _ => false,
            })
            .cloned()
            .collect()
    }

    fn failure_reason(e: &AuditEvent) -> String {
        match e {
            AuditEvent::AuthenticationAttempt(a) => {
                assert!(!a.success);
                a.failure_reason.clone().unwrap_or_default()
            }
            AuditEvent::AuthorizationDecision(d) => {
                assert!(!d.granted);
                d.action.clone()
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_token_is_audited_aggregated() {
        let cap = uc_audit::capture::start();
        let from = ip("2001:db8:7:1::1");
        let v = validator(SYNC_SCOPE);
        for _ in 0..5 {
            let r = PEER_IP
                .scope(from, authorize_site(&v, &bearer("not-a-jwt"), "MUHJ"))
                .await;
            assert!(matches!(r, Err(AuthRejection::Unauthorized(_))));
        }
        let recs = records_from(&cap.events(), from);
        assert_eq!(recs.len(), 1, "aggregated per (ip, reason): {recs:?}");
        assert!(failure_reason(&recs[0]).starts_with("invalid_token"));
        if let AuditEvent::AuthenticationAttempt(a) = &recs[0] {
            assert_eq!(a.method, uc_audit::event::AuthMethod::Jwt);
            assert!(!a.identity.contains("not-a-jwt"), "token never logged");
        } else {
            panic!("a bad bearer is an authentication failure: {recs:?}");
        }

        // The operator surface shares the key: same IP, same reason.
        let op = validator(OPERATOR_SCOPE);
        let r = PEER_IP
            .scope(
                from,
                authorize_action(
                    &op,
                    &bearer("x.y.z"),
                    Action::new(Entity::Phones, Verb::Write),
                    Some("MUHJ"),
                ),
            )
            .await;
        assert!(matches!(r, Err(AuthRejection::Unauthorized(_))));
        assert_eq!(records_from(&cap.events(), from).len(), 1);

        sbc_http_util::mgmt_audit::flush_auth_failures(Instant::now() + Duration::from_secs(61));
        let recs = records_from(&cap.events(), from);
        assert_eq!(recs.len(), 2, "{recs:?}");
        let r = failure_reason(&recs[1]);
        assert!(
            r.starts_with("invalid_token") && r.ends_with("count=5"),
            "{r}"
        );
    }

    #[tokio::test]
    async fn missing_bearer_is_not_audited() {
        let cap = uc_audit::capture::start();
        let from = ip("2001:db8:7:2::1");
        let r = PEER_IP
            .scope(
                from,
                authorize_site(&validator(SYNC_SCOPE), &HeaderMap::new(), "MUHJ"),
            )
            .await;
        assert!(matches!(r, Err(AuthRejection::Unauthorized(_))));
        assert!(records_from(&cap.events(), from).is_empty());
    }

    #[tokio::test]
    async fn insufficient_scope_wrong_site_forbidden_are_audited() {
        let cap = uc_audit::capture::start();
        let sync = validator(SYNC_SCOPE);
        let op = validator(OPERATOR_SCOPE);

        // Valid token, wrong scope.
        let from = ip("2001:db8:7:3::1");
        let t = token("svc-a", OPERATOR_SCOPE, Some("MUHJ"), &[], &[]);
        let r = PEER_IP
            .scope(from, authorize_site(&sync, &bearer(&t), "MUHJ"))
            .await;
        assert!(matches!(r, Err(AuthRejection::InsufficientScope)));
        let recs = records_from(&cap.events(), from);
        assert_eq!(recs.len(), 1, "{recs:?}");
        assert!(failure_reason(&recs[0]).starts_with("insufficient_scope"));

        // Valid sync token for another site.
        let from = ip("2001:db8:7:3::2");
        let t = token("svc-mpls", SYNC_SCOPE, Some("MPLS"), &[], &[]);
        let r = PEER_IP
            .scope(from, authorize_site(&sync, &bearer(&t), "MUHJ"))
            .await;
        assert!(matches!(r, Err(AuthRejection::WrongSite)));
        let recs = records_from(&cap.events(), from);
        assert_eq!(recs.len(), 1, "{recs:?}");
        assert!(failure_reason(&recs[0]).starts_with("wrong_site"));
        if let AuditEvent::AuthenticationAttempt(a) = &recs[0] {
            assert!(
                a.identity.contains("svc-mpls"),
                "validated sub named: {a:?}"
            );
        }

        // Valid operator token whose roles do not grant the action.
        let from = ip("2001:db8:7:3::3");
        let t = token("op-reader", OPERATOR_SCOPE, None, &["auditor"], &["MUHJ"]);
        let r = PEER_IP
            .scope(
                from,
                authorize_action(
                    &op,
                    &bearer(&t),
                    Action::new(Entity::Phones, Verb::Write),
                    Some("MUHJ"),
                ),
            )
            .await;
        assert!(matches!(r, Err(AuthRejection::Forbidden)));
        let recs = records_from(&cap.events(), from);
        assert_eq!(recs.len(), 1, "{recs:?}");
        let ident = match &recs[0] {
            AuditEvent::AuthenticationAttempt(a) => a.identity.clone(),
            AuditEvent::AuthorizationDecision(d) => d.identity.clone(),
            _ => unreachable!(),
        };
        assert!(ident.contains("op-reader"), "{ident}");
        assert!(ident.contains(ISS), "actor is sub@iss: {ident}");

        // A granted action is not a reject record.
        let from = ip("2001:db8:7:3::4");
        let t = token("op-admin", OPERATOR_SCOPE, None, &["fleet-admin"], &["*"]);
        let r = PEER_IP
            .scope(
                from,
                authorize_action(
                    &op,
                    &bearer(&t),
                    Action::new(Entity::Phones, Verb::Write),
                    Some("MUHJ"),
                ),
            )
            .await;
        assert!(r.is_ok());
        assert!(records_from(&cap.events(), from).is_empty());
    }
}
