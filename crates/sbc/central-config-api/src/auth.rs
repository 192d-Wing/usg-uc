//! Site-scoped authorization for the sync surface.
//!
//! A request to `/v1/sync/{site_code}/...` must present a bearer token
//! that (1) validates against the configured OIDC issuer/audience, (2)
//! carries the `config-sync` scope, and (3) has a `site_code` claim equal
//! to the `{site_code}` in the path. The third check is the security
//! boundary: a base's credential can only ever pull its own shard, so a
//! compromised or misconfigured site cannot read another's config.

use axum::Json;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use proto_jwt::{Claims, ValidateError, Validator};
use serde_json::json;

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
    let claims = validator.validate(token).await.map_err(|e| match e {
        ValidateError::InsufficientScope => AuthRejection::InsufficientScope,
        other => AuthRejection::Unauthorized(other.to_string()),
    })?;
    if claims.site_code.as_deref() == Some(site_code) {
        Ok(claims)
    } else {
        Err(AuthRejection::WrongSite)
    }
}
