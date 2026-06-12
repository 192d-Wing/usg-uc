//! OIDC bearer-token validation.
//!
//! Validates signature (against the `IdP`'s JWKS), `iss`, `aud`, `exp`, and
//! a required scope, then exposes the voice-specific claims (`dn`,
//! `sip_domain`) downstream services authorize on. Shared by
//! `sbc-client-config-server` (audience `usg-uc-provisioning`) and the SIP
//! registrar (audience `sbc`).
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

/// Claims consumed from a validated access token. Mirrors the `sip`
/// client-scope mappers in docs/CLIENT-PROVISIONING-OIDC.md.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Claims {
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
    /// SIP domain override; falls back to the relying party's configured
    /// domain.
    #[serde(default)]
    pub sip_domain: Option<String>,
    /// Space-separated OAuth scopes.
    #[serde(default)]
    pub scope: Option<String>,
}

impl Claims {
    /// True when the space-separated `scope` claim contains `wanted`.
    #[must_use]
    pub fn has_scope(&self, wanted: &str) -> bool {
        self.scope
            .as_deref()
            .is_some_and(|s| s.split_ascii_whitespace().any(|t| t == wanted))
    }
}

/// Authentication / authorization failures. Relying parties map these to
/// their transport (HTTP for the provisioning pod, SIP for the registrar).
#[derive(Debug, Error)]
pub enum ValidateError {
    /// No bearer token was presented.
    #[error("missing bearer token")]
    MissingToken,
    /// Signature, structure, `iss`/`aud`/`exp`, or algorithm rejected.
    #[error("invalid token: {0}")]
    InvalidToken(String),
    /// Token is valid but does not carry the required scope.
    #[error("token lacks the required scope")]
    InsufficientScope,
    /// Token is valid but has no `dn` claim — authenticated, yet not a
    /// provisioned voice user.
    #[error("no `dn` claim — user is not provisioned for voice")]
    NotProvisioned,
    /// Keys could not be obtained to validate the token at all.
    #[error(transparent)]
    Jwks(#[from] JwksError),
}

/// Validation policy for one issuer / audience set.
#[derive(Debug, Clone)]
pub struct ValidatorConfig {
    /// Required `iss` — must round-trip exactly with the `IdP` discovery doc.
    pub issuer: String,
    /// Accepted audiences. A token passes when its `aud` contains any of
    /// these (e.g. the registrar wants tokens whose `aud` includes `sbc`).
    /// Must be non-empty, otherwise audience checking is disabled.
    pub audiences: Vec<String>,
    /// Scope the token must carry (e.g. `sip`).
    pub required_scope: &'static str,
    /// Clock skew tolerated on `exp` / `nbf`, seconds.
    pub leeway_secs: u64,
}

impl ValidatorConfig {
    /// Convenience constructor with the standard `sip` scope and 30s leeway.
    #[must_use]
    pub fn new(issuer: impl Into<String>, audiences: Vec<String>) -> Self {
        Self {
            issuer: issuer.into(),
            audiences,
            required_scope: "sip",
            leeway_secs: 30,
        }
    }
}

/// Validates bearer tokens for one issuer/audience policy against a shared
/// JWKS cache.
pub struct Validator {
    jwks: Arc<JwksCache>,
    cfg: ValidatorConfig,
}

impl Validator {
    /// New validator over `jwks` enforcing `cfg`.
    #[must_use]
    pub const fn new(jwks: Arc<JwksCache>, cfg: ValidatorConfig) -> Self {
        Self { jwks, cfg }
    }

    /// Shared JWKS cache, for readiness probing.
    #[must_use]
    pub const fn jwks(&self) -> &Arc<JwksCache> {
        &self.jwks
    }

    /// Fully validates `token` and returns its claims (signature, algorithm
    /// allow-list, `iss`, `aud`, `exp`, and the required scope). The `dn`
    /// claim is **not** required here — that is the relying party's
    /// authorization decision (config pod vs. registrar AOR binding).
    ///
    /// # Errors
    /// [`ValidateError::InvalidToken`] for a bad signature, disallowed
    /// algorithm, or failed `iss`/`aud`/`exp` check;
    /// [`ValidateError::InsufficientScope`] when the required scope is
    /// absent; [`ValidateError::Jwks`] when signing keys cannot be obtained.
    pub async fn validate(&self, token: &str) -> Result<Claims, ValidateError> {
        let header = decode_header(token).map_err(|e| ValidateError::InvalidToken(e.to_string()))?;
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(ValidateError::InvalidToken(format!(
                "algorithm {:?} not accepted",
                header.alg
            )));
        }
        let kid = header
            .kid
            .ok_or_else(|| ValidateError::InvalidToken("token header has no kid".to_string()))?;

        let jwk = match self.jwks.get_key(&kid).await {
            Ok(jwk) => jwk,
            // Unknown kid after refresh = token we'll never be able to
            // validate → reject as invalid, not "keys unavailable".
            Err(JwksError::UnknownKid(k)) => {
                return Err(ValidateError::InvalidToken(format!(
                    "unknown signing key `{k}`"
                )));
            }
            Err(e) => return Err(ValidateError::Jwks(e)),
        };
        let key =
            DecodingKey::from_jwk(&jwk).map_err(|e| ValidateError::InvalidToken(e.to_string()))?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[&self.cfg.issuer]);
        if self.cfg.audiences.is_empty() {
            validation.validate_aud = false;
        } else {
            validation.set_audience(&self.cfg.audiences);
        }
        validation.leeway = self.cfg.leeway_secs;

        let claims = decode::<Claims>(token, &key, &validation)
            .map_err(|e| ValidateError::InvalidToken(e.to_string()))?
            .claims;

        if !claims.has_scope(self.cfg.required_scope) {
            return Err(ValidateError::InsufficientScope);
        }
        Ok(claims)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{EncodingKey, Header, encode};

    use super::*;

    const TEST_KID: &str = "test-key-1";
    const TEST_ISSUER: &str = "https://idp.example.mil/realms/voice";

    struct TestKey {
        encoding: EncodingKey,
        jwks: JwkSet,
    }

    /// Fresh ES256 keypair per test run — no private key material lives in
    /// the tree.
    fn test_key() -> &'static TestKey {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        static KEY: std::sync::OnceLock<TestKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                    .expect("generate test key");
            let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
                .expect("parse test key");
            let point = pair.public_key().as_ref();
            assert_eq!(point[0], 4, "expected uncompressed EC point");
            let jwks = serde_json::from_value(serde_json::json!({
                "keys": [{
                    "kty": "EC", "crv": "P-256", "kid": TEST_KID, "alg": "ES256", "use": "sig",
                    "x": URL_SAFE_NO_PAD.encode(&point[1..33]),
                    "y": URL_SAFE_NO_PAD.encode(&point[33..65]),
                }]
            }))
            .expect("test jwks");
            TestKey {
                encoding: EncodingKey::from_ec_der(pkcs8.as_ref()),
                jwks,
            }
        })
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs()
    }

    fn sign_with_kid(claims: &serde_json::Value, kid: &str) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(kid.to_string());
        encode(&header, claims, &test_key().encoding).expect("sign")
    }

    fn sign(claims: &serde_json::Value) -> String {
        sign_with_kid(claims, TEST_KID)
    }

    fn valid_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": TEST_ISSUER,
            "aud": ["usg-uc-provisioning", "sbc"],
            "sub": "f3a9-test",
            "exp": now_secs() + 300,
            "scope": "openid profile sip",
            "dn": "1455550100",
            "sip_domain": "example.mil",
        })
    }

    fn validator(audiences: &[&str]) -> Validator {
        Validator::new(
            Arc::new(JwksCache::with_static(test_key().jwks.clone())),
            ValidatorConfig::new(
                TEST_ISSUER,
                audiences.iter().map(|s| (*s).to_string()).collect(),
            ),
        )
    }

    #[test]
    fn scope_membership_is_token_exact() {
        let claims = Claims {
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

    #[tokio::test]
    async fn valid_token_yields_claims() {
        let claims = validator(&["sbc"])
            .validate(&sign(&valid_claims()))
            .await
            .expect("valid");
        assert_eq!(claims.dn.as_deref(), Some("1455550100"));
        assert_eq!(claims.sip_domain.as_deref(), Some("example.mil"));
    }

    #[tokio::test]
    async fn expired_token_is_invalid() {
        let mut c = valid_claims();
        c["exp"] = serde_json::json!(now_secs() - 600);
        let err = validator(&["sbc"]).validate(&sign(&c)).await.unwrap_err();
        assert!(matches!(err, ValidateError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn wrong_audience_is_invalid() {
        // Validator wants `sbc`; token carries only the provisioning aud.
        let mut c = valid_claims();
        c["aud"] = serde_json::json!(["usg-uc-provisioning"]);
        let err = validator(&["sbc"]).validate(&sign(&c)).await.unwrap_err();
        assert!(matches!(err, ValidateError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn wrong_issuer_is_invalid() {
        let mut c = valid_claims();
        c["iss"] = serde_json::json!("https://evil.example.com/realms/voice");
        let err = validator(&["sbc"]).validate(&sign(&c)).await.unwrap_err();
        assert!(matches!(err, ValidateError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn missing_dn_still_validates_at_this_layer() {
        // The validator does not enforce `dn` — that is the relying party's
        // authorization step. A token without `dn` must still validate.
        let mut c = valid_claims();
        c.as_object_mut().expect("object").remove("dn");
        let claims = validator(&["sbc"]).validate(&sign(&c)).await.expect("valid");
        assert!(claims.dn.is_none());
    }

    #[tokio::test]
    async fn missing_scope_is_insufficient_scope() {
        let mut c = valid_claims();
        c["scope"] = serde_json::json!("openid profile");
        let err = validator(&["sbc"]).validate(&sign(&c)).await.unwrap_err();
        assert!(matches!(err, ValidateError::InsufficientScope));
    }

    #[tokio::test]
    async fn unknown_kid_is_invalid_not_unavailable() {
        let token = sign_with_kid(&valid_claims(), "rotated-away");
        let err = validator(&["sbc"]).validate(&token).await.unwrap_err();
        assert!(matches!(err, ValidateError::InvalidToken(_)));
    }

    #[tokio::test]
    async fn hs256_symmetric_alg_is_rejected() {
        // Forge an HS256 token; the alg allow-list must reject it before any
        // key lookup.
        let header = Header::new(Algorithm::HS256);
        let token = encode(
            &header,
            &valid_claims(),
            &EncodingKey::from_secret(b"attacker-shared-secret"),
        )
        .expect("sign hs256");
        let err = validator(&["sbc"]).validate(&token).await.unwrap_err();
        assert!(matches!(err, ValidateError::InvalidToken(_)));
    }
}
