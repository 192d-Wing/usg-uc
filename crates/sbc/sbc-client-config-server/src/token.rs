//! OIDC bearer-token verification for `/v1/client-config`.
//!
//! Validates signature (against the `IdP`'s JWKS), `iss`, `aud`, `exp`, and
//! the `sip` scope, then exposes the voice-specific claims (`dn`,
//! `sip_domain`) the provisioning response is built from.
//!
//! ## NIST 800-53 Rev5: IA-2, IA-5(2) (PKI-based authentication)

use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use thiserror::Error;

use crate::jwks::{JwksCache, JwksError};

/// Signature algorithms accepted from the `IdP`. Symmetric algorithms are
/// deliberately absent — a shared HMAC secret would let any relying party
/// mint tokens.
pub const ALLOWED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::PS256,
    Algorithm::ES256,
    Algorithm::ES384,
];

/// Clock skew tolerated on `exp` / `nbf`, seconds.
const LEEWAY_SECS: u64 = 30;

/// Claims consumed from a validated access token. Mirrors the `sip`
/// client-scope mappers in docs/CLIENT-PROVISIONING-OIDC.md.
#[derive(Debug, serde::Deserialize)]
pub struct VoiceClaims {
    /// Stable subject identifier.
    pub sub: String,
    /// Login name, used as a display-name fallback.
    #[serde(default)]
    pub preferred_username: Option<String>,
    /// Full display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Email address.
    #[serde(default)]
    pub email: Option<String>,
    /// Directory number — the claim that makes a user a voice user.
    #[serde(default)]
    pub dn: Option<String>,
    /// SIP domain override; falls back to this POP's configured domain.
    #[serde(default)]
    pub sip_domain: Option<String>,
    /// Space-separated OAuth scopes.
    #[serde(default)]
    pub scope: Option<String>,
}

impl VoiceClaims {
    /// True when the space-separated `scope` claim contains `wanted`.
    pub fn has_scope(&self, wanted: &str) -> bool {
        self.scope
            .as_deref()
            .is_some_and(|s| s.split_ascii_whitespace().any(|t| t == wanted))
    }
}

/// Authentication / authorization failures, mapped to HTTP in `handlers`.
#[derive(Debug, Error)]
pub enum AuthError {
    /// No `Authorization: Bearer` header on the request.
    #[error("missing bearer token")]
    MissingToken,
    /// Signature, structure, `iss`/`aud`/`exp`, or algorithm rejected.
    #[error("invalid token: {0}")]
    InvalidToken(String),
    /// Token is valid but does not carry the `sip` scope.
    #[error("token lacks required scope `sip`")]
    InsufficientScope,
    /// Token is valid but has no `dn` claim — authenticated, yet not a
    /// provisioned voice user.
    #[error("no `dn` claim — user is not provisioned for voice")]
    NotProvisioned,
    /// Keys could not be obtained to validate the token at all.
    #[error(transparent)]
    Jwks(#[from] JwksError),
}

/// Verifies bearer tokens for one issuer/audience pair.
pub struct Verifier {
    jwks: Arc<JwksCache>,
    issuer: String,
    audience: String,
}

impl Verifier {
    /// New verifier requiring `iss == issuer` and `aud` containing
    /// `audience`.
    pub fn new(jwks: Arc<JwksCache>, issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            jwks,
            issuer: issuer.into(),
            audience: audience.into(),
        }
    }

    /// Shared JWKS cache, for readiness probing.
    pub const fn jwks(&self) -> &Arc<JwksCache> {
        &self.jwks
    }

    /// Fully validates `token` and returns its voice claims.
    pub async fn verify(&self, token: &str) -> Result<VoiceClaims, AuthError> {
        let header = decode_header(token).map_err(|e| AuthError::InvalidToken(e.to_string()))?;
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(AuthError::InvalidToken(format!(
                "algorithm {:?} not accepted",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| AuthError::InvalidToken("token header has no kid".to_string()))?;

        let jwk = match self.jwks.get_key(&kid).await {
            Ok(jwk) => jwk,
            // Unknown kid after refresh = token we'll never be able to
            // validate → 401, not 503.
            Err(JwksError::UnknownKid(k)) => {
                return Err(AuthError::InvalidToken(format!("unknown signing key `{k}`")));
            }
            Err(e) => return Err(AuthError::Jwks(e)),
        };
        let key =
            DecodingKey::from_jwk(&jwk).map_err(|e| AuthError::InvalidToken(e.to_string()))?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.leeway = LEEWAY_SECS;

        let claims = decode::<VoiceClaims>(token, &key, &validation)
            .map_err(|e| AuthError::InvalidToken(e.to_string()))?
            .claims;

        if !claims.has_scope("sip") {
            return Err(AuthError::InsufficientScope);
        }
        Ok(claims)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn scope_membership_is_token_exact() {
        let claims = VoiceClaims {
            sub: "x".into(),
            preferred_username: None,
            name: None,
            email: None,
            dn: None,
            sip_domain: None,
            scope: Some("openid sipping profile".into()),
        };
        assert!(!claims.has_scope("sip"));
        assert!(claims.has_scope("sipping"));
    }
}
