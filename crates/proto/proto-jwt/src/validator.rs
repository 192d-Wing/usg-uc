//! OIDC bearer-token validation.
//!
//! Validates signature (against the `IdP`'s JWKS), `iss`, `aud`, `exp`,
//! `nbf` (when present), and a required scope, then exposes the
//! voice-specific claims (`dn`, `sip_domain`) downstream services authorize
//! on. Shared by `sbc-client-config-server` (audience `usg-uc-provisioning`)
//! and the SIP registrar (audience `sbc`).
//!
//! CNSA 2.0: ES384 (ECDSA P-384 / SHA-384) is the only accepted signature
//! algorithm, and the signing JWK must be an EC P-384 key. The `IdP` realm
//! must sign access tokens with ES384.
//!
//! ## NIST 800-53 Rev5: IA-2, IA-5(2), AC-3, SC-13 (PKI-based authentication, CNSA 2.0 signatures)

use std::sync::Arc;

use jsonwebtoken::jwk::{
    AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm, KeyOperations, PublicKeyUse,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use thiserror::Error;

use crate::jwks::{JwksCache, JwksError};

/// Signature algorithms accepted from the `IdP`: ES384 only (CNSA 2.0).
/// RSA, PS, ES256 and symmetric algorithms are rejected before key lookup.
// NIST 800-53 Rev5: SC-13 (CNSA 2.0: ECDSA P-384 / SHA-384 only)
pub const ALLOWED_ALGS: &[Algorithm] = &[Algorithm::ES384];

/// Registered claims every accepted token must carry. `nbf` is checked when
/// present but not required: Keycloak access tokens do not always carry it.
// NIST 800-53 Rev5: IA-2, AC-3
const REQUIRED_SPEC_CLAIMS: &[&str] = &["exp", "iss", "aud"];

/// Largest clock-skew allowance [`Validator::new`] accepts, seconds.
pub const MAX_LEEWAY_SECS: u64 = 300;

/// JOSE header `typ` values accepted (compared case-insensitively). Absent
/// is also accepted. RFC 7515 §4.1.9 allows the `application/` prefix to be
/// omitted, so both forms are listed. Keycloak emits `JWT`.
const ALLOWED_HEADER_TYPS: &[&str] = &["JWT", "at+jwt", "application/jwt", "application/at+jwt"];

/// Keycloak's body `typ` claim for an access token. ID, refresh and logout
/// tokens carry other values and are refused when presented as bearer.
const KEYCLOAK_ACCESS_TOKEN_TYP: &str = "Bearer";

/// Decoded body: [`Claims`] plus the Keycloak `typ` claim, which is checked
/// here and not exposed.
#[derive(serde::Deserialize)]
struct TokenBody {
    #[serde(flatten)]
    claims: Claims,
    #[serde(default)]
    typ: Option<String>,
}

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
    /// Canonical site code this token is scoped to. Present on the
    /// per-site `config-sync` service-account tokens the central config
    /// API authorizes; absent on voice-user tokens (registrar /
    /// provisioning ignore it). The central API requires it to equal the
    /// `{site_code}` in the request path.
    #[serde(default)]
    pub site_code: Option<String>,
    /// Operator capability roles (central config ABAC). Granular roles
    /// like `fleet-admin`, `phones-admin`, `auditor`; each maps to a set
    /// of allowed actions. Empty on non-operator tokens.
    #[serde(default)]
    pub roles: Vec<String>,
    /// Operator site allowlist (central config ABAC): the canonical site
    /// codes this operator's roles apply to, or `["*"]` for the whole
    /// fleet. Empty grants no sites.
    #[serde(default)]
    pub sites: Vec<String>,
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
    /// Must be non-empty with no blank entries; [`Validator::new`] refuses
    /// anything else, so audience checking cannot be disabled.
    pub audiences: Vec<String>,
    /// Scope the token must carry (e.g. `sip`).
    pub required_scope: &'static str,
    /// Clock skew tolerated on `exp` / `nbf`, seconds. At most
    /// [`MAX_LEEWAY_SECS`].
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

/// A [`ValidatorConfig`] refused by [`Validator::new`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// `issuer` is empty, so `iss` could never be checked meaningfully.
    #[error("OIDC issuer is empty")]
    EmptyIssuer,
    /// `audiences` is empty: audience checking cannot be disabled.
    #[error("OIDC audience set is empty; audience checking cannot be disabled")]
    EmptyAudiences,
    /// An entry in `audiences` is empty or whitespace.
    #[error("OIDC audience set contains a blank entry")]
    BlankAudience,
    /// `leeway_secs` exceeds [`MAX_LEEWAY_SECS`].
    #[error("OIDC clock-skew leeway {0}s exceeds the {MAX_LEEWAY_SECS}s maximum")]
    Leeway(u64),
}

/// Validates bearer tokens for one issuer/audience policy against a shared
/// JWKS cache.
pub struct Validator {
    jwks: Arc<JwksCache>,
    cfg: ValidatorConfig,
}

impl Validator {
    /// New validator over `jwks` enforcing `cfg`.
    ///
    /// The issuer and audience entries are trimmed of surrounding
    /// whitespace.
    ///
    /// # Errors
    /// [`ConfigError`] when the issuer is empty, the audience set is empty
    /// or has a blank entry, or the leeway exceeds [`MAX_LEEWAY_SECS`].
    /// Fails closed so no caller can turn off `aud`.
    // NIST 800-53 Rev5: IA-2, AC-3
    pub fn new(jwks: Arc<JwksCache>, mut cfg: ValidatorConfig) -> Result<Self, ConfigError> {
        cfg.issuer = cfg.issuer.trim().to_string();
        if cfg.issuer.is_empty() {
            return Err(ConfigError::EmptyIssuer);
        }
        if cfg.audiences.is_empty() {
            return Err(ConfigError::EmptyAudiences);
        }
        for aud in &mut cfg.audiences {
            *aud = aud.trim().to_string();
            if aud.is_empty() {
                return Err(ConfigError::BlankAudience);
            }
        }
        if cfg.leeway_secs > MAX_LEEWAY_SECS {
            return Err(ConfigError::Leeway(cfg.leeway_secs));
        }
        Ok(Self { jwks, cfg })
    }

    /// The issuer this validator enforces (every accepted token's `iss`).
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.cfg.issuer
    }

    /// Shared JWKS cache, for readiness probing.
    #[must_use]
    pub const fn jwks(&self) -> &Arc<JwksCache> {
        &self.jwks
    }

    /// Fully validates `token` and returns its claims (signature, algorithm
    /// allow-list, header `crit`/`typ`, signing-key type and usage, `iss`,
    /// `aud`, `exp`, `nbf` when present, the Keycloak `typ` claim when
    /// present, and the required scope). The `dn`
    /// claim is **not** required here — that is the relying party's
    /// authorization decision (config pod vs. registrar AOR binding).
    ///
    /// Header `jwk`, `jku`, `x5u` and `x5c` are never used: the key comes
    /// only from the configured JWKS by `kid`.
    ///
    /// # Errors
    /// [`ValidateError::InvalidToken`] for a bad signature, disallowed
    /// algorithm, a `crit` header, an unexpected header `typ` or body `typ`,
    /// a JWK that is not an EC P-384 signature key or whose `alg` differs
    /// from the token's, or a missing or failed `iss`/`aud`/`exp` (or `nbf`)
    /// check; [`ValidateError::InsufficientScope`] when the required scope
    /// is absent; [`ValidateError::Jwks`] when signing keys cannot be
    /// obtained.
    // NIST 800-53 Rev5: IA-2, AC-3 (audience and scope enforced)
    pub async fn validate(&self, token: &str) -> Result<Claims, ValidateError> {
        let header =
            decode_header(token).map_err(|e| ValidateError::InvalidToken(e.to_string()))?;
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(ValidateError::InvalidToken(format!(
                "algorithm {:?} not accepted",
                header.alg
            )));
        }
        // RFC 7515 §4.1.11: no extensions are understood, so any `crit`
        // header must be refused.
        if header.crit.is_some() {
            return Err(ValidateError::InvalidToken(
                "token header has unsupported crit parameters".to_string(),
            ));
        }
        if let Some(typ) = header.typ.as_deref()
            && !ALLOWED_HEADER_TYPS
                .iter()
                .any(|t| t.eq_ignore_ascii_case(typ))
        {
            return Err(ValidateError::InvalidToken(
                "token header typ not accepted".to_string(),
            ));
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
        check_jwk(header.alg, &jwk)?;
        let key =
            DecodingKey::from_jwk(&jwk).map_err(|e| ValidateError::InvalidToken(e.to_string()))?;

        let mut validation = Validation::new(header.alg);
        validation.set_required_spec_claims(REQUIRED_SPEC_CLAIMS);
        validation.set_issuer(&[&self.cfg.issuer]);
        // `new` refuses an empty set; never fall back to validate_aud = false.
        validation.set_audience(&self.cfg.audiences);
        validation.validate_nbf = true;
        validation.leeway = self.cfg.leeway_secs;

        let body = decode::<TokenBody>(token, &key, &validation)
            .map_err(|e| ValidateError::InvalidToken(e.to_string()))?
            .claims;
        if body
            .typ
            .as_deref()
            .is_some_and(|t| t != KEYCLOAK_ACCESS_TOKEN_TYP)
        {
            return Err(ValidateError::InvalidToken(
                "token is not an access token".to_string(),
            ));
        }
        let claims = body.claims;

        if !claims.has_scope(self.cfg.required_scope) {
            return Err(ValidateError::InsufficientScope);
        }
        Ok(claims)
    }
}

/// Rejects a JWK that does not fit the token's (already allow-listed)
/// algorithm: ES384 needs an EC P-384 key, and a JWK `alg`, when present,
/// must equal the header `alg` (RFC 7517 §4.4). `use`, when present, must
/// be `sig` (§4.2), and `key_ops`, when present, must include `verify`
/// (§4.3). `DecodingKey::from_jwk` checks none of these.
// NIST 800-53 Rev5: IA-5(2), SC-13 (CNSA 2.0: P-384 signing keys only)
fn check_jwk(alg: Algorithm, jwk: &Jwk) -> Result<(), ValidateError> {
    let (want_alg, want_curve) = match alg {
        Algorithm::ES384 => (KeyAlgorithm::ES384, EllipticCurve::P384),
        other => {
            return Err(ValidateError::InvalidToken(format!(
                "algorithm {other:?} not accepted"
            )));
        }
    };
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(ec) if ec.curve == want_curve => {}
        _ => {
            return Err(ValidateError::InvalidToken(format!(
                "signing key is not an EC {want_curve:?} key"
            )));
        }
    }
    if let Some(key_alg) = jwk.common.key_algorithm
        && key_alg != want_alg
    {
        return Err(ValidateError::InvalidToken(format!(
            "signing key alg {key_alg} does not match token alg {alg:?}"
        )));
    }
    if jwk
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|u| *u != PublicKeyUse::Signature)
    {
        return Err(ValidateError::InvalidToken(
            "signing key use is not sig".to_string(),
        ));
    }
    if jwk
        .common
        .key_operations
        .as_ref()
        .is_some_and(|ops| !ops.contains(&KeyOperations::Verify))
    {
        return Err(ValidateError::InvalidToken(
            "signing key key_ops lacks verify".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{EncodingKey, Header, encode};

    use super::*;

    const TEST_KID: &str = "test-key-1";
    const ES256_KID: &str = "test-es256";
    const RS256_KID: &str = "test-rs256";
    const PS256_KID: &str = "test-ps256";
    const TEST_ISSUER: &str = "https://idp.example.mil/realms/voice";

    struct TestKeys {
        /// P-384, published as ES384 under `TEST_KID`.
        es384: EncodingKey,
        /// P-256, published as ES256 under `ES256_KID`.
        es256: EncodingKey,
        /// RSA-2048, published as RS256 and PS256 under separate kids.
        rsa: EncodingKey,
        jwks: JwkSet,
    }

    /// Reads one DER TLV (short or long definite length); returns
    /// (tag, contents, rest).
    fn der_tlv(input: &[u8]) -> (u8, &[u8], &[u8]) {
        let tag = input[0];
        let (len, hdr) = if input[1] & 0x80 == 0 {
            (usize::from(input[1]), 2)
        } else {
            let n = usize::from(input[1] & 0x7f);
            let len = input[2..2 + n]
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
            (len, 2 + n)
        };
        (tag, &input[hdr..hdr + len], &input[hdr + len..])
    }

    /// Fresh EC keypair: (signing key, base64url x, base64url y).
    fn ec(
        alg: &'static aws_lc_rs::signature::EcdsaSigningAlgorithm,
        coord: usize,
    ) -> (EncodingKey, String, String) {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair as _};
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &SystemRandom::new()).expect("gen ec");
        let pair = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref()).expect("parse ec");
        let point = pair.public_key().as_ref();
        assert_eq!(point[0], 4, "expected uncompressed EC point");
        assert_eq!(point.len(), 1 + 2 * coord);
        (
            EncodingKey::from_ec_der(pkcs8.as_ref()),
            URL_SAFE_NO_PAD.encode(&point[1..=coord]),
            URL_SAFE_NO_PAD.encode(&point[1 + coord..]),
        )
    }

    /// Fresh keypairs per test run — no private key material lives in the
    /// tree.
    fn test_keys() -> &'static TestKeys {
        use aws_lc_rs::encoding::AsDer as _;
        use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
        use aws_lc_rs::signature::{
            ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED_SIGNING, KeyPair as _,
        };
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        static KEYS: std::sync::OnceLock<TestKeys> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| {
            let (es384, x384, y384) = ec(&ECDSA_P384_SHA384_FIXED_SIGNING, 48);
            let (es256, x256, y256) = ec(&ECDSA_P256_SHA256_FIXED_SIGNING, 32);

            let rsa = RsaKeyPair::generate(KeySize::Rsa2048).expect("gen rsa");
            // PKCS#8 PrivateKeyInfo -> inner RFC 8017 RSAPrivateKey, which
            // is what jsonwebtoken's aws-lc backend expects.
            let pkcs8 = rsa.as_der().expect("rsa pkcs8");
            let (_, info, _) = der_tlv(pkcs8.as_ref());
            let (_, _, info) = der_tlv(info); // version
            let (_, _, info) = der_tlv(info); // algorithm
            let (tag, rsa_priv, _) = der_tlv(info);
            assert_eq!(tag, 0x04, "expected OCTET STRING privateKey");
            // RFC 8017 RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }
            let (_, rsa_pub, _) = der_tlv(rsa.public_key().as_ref());
            let (_, n, rest) = der_tlv(rsa_pub);
            let (_, e, _) = der_tlv(rest);
            let n = n.strip_prefix(&[0u8]).unwrap_or(n);
            let (n, e) = (URL_SAFE_NO_PAD.encode(n), URL_SAFE_NO_PAD.encode(e));

            let jwks = serde_json::from_value(serde_json::json!({
                "keys": [
                    { "kty": "EC", "crv": "P-384", "kid": TEST_KID, "alg": "ES384", "use": "sig",
                      "x": x384, "y": y384 },
                    { "kty": "EC", "crv": "P-256", "kid": ES256_KID, "alg": "ES256", "use": "sig",
                      "x": x256, "y": y256 },
                    { "kty": "RSA", "kid": RS256_KID, "alg": "RS256", "use": "sig",
                      "n": n, "e": e },
                    { "kty": "RSA", "kid": PS256_KID, "alg": "PS256", "use": "sig",
                      "n": n, "e": e },
                ]
            }))
            .expect("test jwks");
            TestKeys {
                es384,
                es256,
                rsa: EncodingKey::from_rsa_der(rsa_priv),
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

    fn sign_as(claims: &serde_json::Value, alg: Algorithm, kid: &str) -> String {
        let keys = test_keys();
        let key = match alg {
            Algorithm::ES384 => &keys.es384,
            Algorithm::ES256 => &keys.es256,
            Algorithm::RS256 | Algorithm::PS256 => &keys.rsa,
            other => unreachable!("no test key for {other:?}"),
        };
        let mut header = Header::new(alg);
        header.kid = Some(kid.to_string());
        encode(&header, claims, key).expect("sign")
    }

    fn sign_with_kid(claims: &serde_json::Value, kid: &str) -> String {
        sign_as(claims, Algorithm::ES384, kid)
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

    fn try_validator(jwks: JwkSet, audiences: &[&str]) -> Result<Validator, ConfigError> {
        Validator::new(
            Arc::new(JwksCache::with_static(jwks)),
            ValidatorConfig::new(
                TEST_ISSUER,
                audiences.iter().map(|s| (*s).to_string()).collect(),
            ),
        )
    }

    fn validator(audiences: &[&str]) -> Validator {
        try_validator(test_keys().jwks.clone(), audiences).expect("valid config")
    }

    /// Copy of the published JWK `from_kid`, re-published as `kid` with
    /// `alg` set to `alg` (`None` drops it).
    fn relabelled_jwk(from_kid: &str, kid: &str, alg: Option<KeyAlgorithm>) -> Jwk {
        let mut jwk = test_keys().jwks.find(from_kid).expect("jwk").clone();
        jwk.common.key_id = Some(kid.to_string());
        jwk.common.key_algorithm = alg;
        jwk
    }

    /// Asserts `err` is `InvalidToken` whose message contains `cause`.
    fn assert_invalid(err: &ValidateError, cause: &str) {
        assert!(
            matches!(err, ValidateError::InvalidToken(m) if m.contains(cause)),
            "expected InvalidToken containing {cause:?}, got {err:?}"
        );
    }

    /// Signs `claims` as ES384 with `key` and an arbitrary header.
    fn sign_header(header: &Header, claims: &serde_json::Value, key: &EncodingKey) -> String {
        encode(header, claims, key).expect("sign")
    }

    fn es384_header() -> Header {
        let mut header = Header::new(Algorithm::ES384);
        header.kid = Some(TEST_KID.to_string());
        header
    }

    /// Validator whose JWKS holds only `jwk`.
    fn validator_with(jwk: Jwk) -> Validator {
        try_validator(JwkSet { keys: vec![jwk] }, &["sbc"]).expect("valid config")
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
            site_code: None,
            roles: Vec::new(),
            sites: Vec::new(),
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
        assert_invalid(&err, "ExpiredSignature");
    }

    #[tokio::test]
    async fn wrong_audience_is_invalid() {
        // Validator wants `sbc`; token carries only the provisioning aud.
        let mut c = valid_claims();
        c["aud"] = serde_json::json!(["usg-uc-provisioning"]);
        let err = validator(&["sbc"]).validate(&sign(&c)).await.unwrap_err();
        assert_invalid(&err, "InvalidAudience");
    }

    #[tokio::test]
    async fn wrong_issuer_is_invalid() {
        let mut c = valid_claims();
        c["iss"] = serde_json::json!("https://evil.example.com/realms/voice");
        let err = validator(&["sbc"]).validate(&sign(&c)).await.unwrap_err();
        assert_invalid(&err, "InvalidIssuer");
    }

    #[tokio::test]
    async fn missing_dn_still_validates_at_this_layer() {
        // The validator does not enforce `dn` — that is the relying party's
        // authorization step. A token without `dn` must still validate.
        let mut c = valid_claims();
        c.as_object_mut().expect("object").remove("dn");
        let claims = validator(&["sbc"])
            .validate(&sign(&c))
            .await
            .expect("valid");
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

    // SR-30: CNSA 2.0 — ES384 (P-384) is the only accepted signature
    // algorithm.

    #[tokio::test]
    async fn es384_p384_token_is_accepted() {
        let token = sign_as(&valid_claims(), Algorithm::ES384, TEST_KID);
        let claims = validator(&["sbc"]).validate(&token).await.expect("valid");
        assert_eq!(claims.sub, "f3a9-test");
    }

    #[tokio::test]
    async fn es256_token_is_rejected() {
        let token = sign_as(&valid_claims(), Algorithm::ES256, ES256_KID);
        let err = validator(&["sbc"]).validate(&token).await.unwrap_err();
        assert!(matches!(err, ValidateError::InvalidToken(_)), "{err:?}");
    }

    #[tokio::test]
    async fn rs256_token_is_rejected() {
        let token = sign_as(&valid_claims(), Algorithm::RS256, RS256_KID);
        let err = validator(&["sbc"]).validate(&token).await.unwrap_err();
        assert!(matches!(err, ValidateError::InvalidToken(_)), "{err:?}");
    }

    #[tokio::test]
    async fn ps256_token_is_rejected() {
        let token = sign_as(&valid_claims(), Algorithm::PS256, PS256_KID);
        let err = validator(&["sbc"]).validate(&token).await.unwrap_err();
        assert!(matches!(err, ValidateError::InvalidToken(_)), "{err:?}");
    }

    #[test]
    fn allowed_algs_is_es384_only() {
        assert_eq!(ALLOWED_ALGS, &[Algorithm::ES384]);
    }

    // SR-34: exp, iss, aud required; nbf checked when present; audience
    // checking cannot be disabled.

    #[tokio::test]
    async fn missing_aud_is_invalid() {
        let mut c = valid_claims();
        c.as_object_mut().expect("object").remove("aud");
        let err = validator(&["sbc"]).validate(&sign(&c)).await.unwrap_err();
        assert_invalid(&err, "Missing required claim: aud");
    }

    #[tokio::test]
    async fn missing_iss_is_invalid() {
        let mut c = valid_claims();
        c.as_object_mut().expect("object").remove("iss");
        let err = validator(&["sbc"]).validate(&sign(&c)).await.unwrap_err();
        assert_invalid(&err, "Missing required claim: iss");
    }

    #[tokio::test]
    async fn missing_exp_is_invalid() {
        let mut c = valid_claims();
        c.as_object_mut().expect("object").remove("exp");
        let err = validator(&["sbc"]).validate(&sign(&c)).await.unwrap_err();
        assert_invalid(&err, "Missing required claim: exp");
    }

    #[tokio::test]
    async fn future_nbf_beyond_leeway_is_invalid() {
        // Default leeway is 30s; nbf 10 minutes ahead must be rejected.
        let mut c = valid_claims();
        c["nbf"] = serde_json::json!(now_secs() + 600);
        let err = validator(&["sbc"]).validate(&sign(&c)).await.unwrap_err();
        assert_invalid(&err, "ImmatureSignature");
    }

    #[tokio::test]
    async fn past_nbf_is_accepted() {
        let mut c = valid_claims();
        c["nbf"] = serde_json::json!(now_secs() - 60);
        validator(&["sbc"])
            .validate(&sign(&c))
            .await
            .expect("valid");
    }

    #[test]
    fn empty_audiences_fails_closed() {
        // An empty audience list must not disable audience checking: the
        // validator refuses to be built.
        let err = try_validator(test_keys().jwks.clone(), &[]).err();
        assert_eq!(err, Some(ConfigError::EmptyAudiences));
    }

    #[test]
    fn blank_audience_entry_is_refused() {
        let err = try_validator(test_keys().jwks.clone(), &["sbc", " "]).err();
        assert_eq!(err, Some(ConfigError::BlankAudience));
    }

    #[test]
    fn empty_issuer_is_refused() {
        let err = Validator::new(
            Arc::new(JwksCache::with_static(test_keys().jwks.clone())),
            ValidatorConfig::new("", vec!["sbc".to_string()]),
        )
        .err();
        assert_eq!(err, Some(ConfigError::EmptyIssuer));
    }

    // SR-30: the signing JWK must be EC P-384, and its `alg` (when present)
    // must match the token header.

    #[tokio::test]
    async fn p256_jwk_labelled_es384_is_rejected() {
        // A P-256 key published as ES384; the ES384 token is signed by the
        // real P-384 key, so only the curve check stands between them.
        let kid = "p256-as-es384";
        let v = validator_with(relabelled_jwk(ES256_KID, kid, Some(KeyAlgorithm::ES384)));
        let token = sign_as(&valid_claims(), Algorithm::ES384, kid);
        let err = v.validate(&token).await.unwrap_err();
        assert!(
            matches!(&err, ValidateError::InvalidToken(m) if m.contains("not an EC")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn rsa_jwk_for_es384_token_is_rejected() {
        let kid = "rsa-as-es384";
        let v = validator_with(relabelled_jwk(RS256_KID, kid, Some(KeyAlgorithm::ES384)));
        let token = sign_as(&valid_claims(), Algorithm::ES384, kid);
        let err = v.validate(&token).await.unwrap_err();
        assert!(
            matches!(&err, ValidateError::InvalidToken(m) if m.contains("not an EC")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn jwk_alg_differing_from_header_alg_is_rejected() {
        // The real P-384 key, but published with `alg: ES256`. The ES384
        // signature would verify; the alg mismatch must still reject it.
        let kid = "p384-as-es256";
        let v = validator_with(relabelled_jwk(TEST_KID, kid, Some(KeyAlgorithm::ES256)));
        let token = sign_as(&valid_claims(), Algorithm::ES384, kid);
        let err = v.validate(&token).await.unwrap_err();
        assert!(
            matches!(&err, ValidateError::InvalidToken(m) if m.contains("does not match")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn p384_jwk_without_alg_is_accepted() {
        // JWK `alg` is optional (RFC 7517 §4.4); the curve check suffices.
        let kid = "p384-no-alg";
        let v = validator_with(relabelled_jwk(TEST_KID, kid, None));
        let token = sign_as(&valid_claims(), Algorithm::ES384, kid);
        v.validate(&token).await.expect("valid");
    }

    // SEC-005: signature and key-source checks.

    #[tokio::test]
    async fn attacker_p384_key_under_published_kid_is_rejected() {
        use aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED_SIGNING;
        let (attacker, _, _) = ec(&ECDSA_P384_SHA384_FIXED_SIGNING, 48);
        let token = sign_header(&es384_header(), &valid_claims(), &attacker);
        let err = validator(&["sbc"]).validate(&token).await.unwrap_err();
        assert_invalid(&err, "InvalidSignature");
    }

    #[tokio::test]
    async fn header_jwk_and_jku_are_ignored() {
        // The token embeds the attacker's own public key and a JWKS URL;
        // neither may be used. Only the configured JWKS is consulted.
        use aws_lc_rs::signature::ECDSA_P384_SHA384_FIXED_SIGNING;
        let (attacker, x, y) = ec(&ECDSA_P384_SHA384_FIXED_SIGNING, 48);
        let attacker_jwk: Jwk = serde_json::from_value(serde_json::json!({
            "kty": "EC", "crv": "P-384", "kid": TEST_KID, "alg": "ES384", "use": "sig",
            "x": x, "y": y,
        }))
        .expect("attacker jwk");
        let mut header = es384_header();
        header.jwk = Some(attacker_jwk);
        header.jku = Some("https://attacker.example.test/jwks".to_string());
        let token = sign_header(&header, &valid_claims(), &attacker);
        let err = validator(&["sbc"]).validate(&token).await.unwrap_err();
        assert_invalid(&err, "InvalidSignature");
    }

    // SEC-005: audience forms.

    #[tokio::test]
    async fn aud_as_single_string_is_accepted() {
        let mut c = valid_claims();
        c["aud"] = serde_json::json!("sbc");
        validator(&["sbc"])
            .validate(&sign(&c))
            .await
            .expect("valid");
    }

    #[tokio::test]
    async fn aud_single_string_mismatch_is_invalid() {
        let mut c = valid_claims();
        c["aud"] = serde_json::json!("usg-uc-provisioning");
        let err = validator(&["sbc"]).validate(&sign(&c)).await.unwrap_err();
        assert_invalid(&err, "InvalidAudience");
    }

    #[tokio::test]
    async fn empty_aud_array_is_invalid() {
        let mut c = valid_claims();
        c["aud"] = serde_json::json!([]);
        let err = validator(&["sbc"]).validate(&sign(&c)).await.unwrap_err();
        assert_invalid(&err, "InvalidAudience");
    }

    #[tokio::test]
    async fn any_configured_audience_matches() {
        let mut c = valid_claims();
        c["aud"] = serde_json::json!(["sbc"]);
        let v = validator(&["usg-uc-provisioning", "sbc"]);
        v.validate(&sign(&c)).await.expect("valid");
        c["aud"] = serde_json::json!(["other-rp"]);
        let err = v.validate(&sign(&c)).await.unwrap_err();
        assert_invalid(&err, "InvalidAudience");
    }

    // SEC-002: RFC 7515 §4.1.11 crit.

    #[tokio::test]
    async fn crit_header_is_rejected() {
        let mut header = es384_header();
        header.crit = Some(vec!["exp".to_string()]);
        let token = sign_header(&header, &valid_claims(), &test_keys().es384);
        let err = validator(&["sbc"]).validate(&token).await.unwrap_err();
        assert_invalid(&err, "crit");
    }

    // SEC-003: header typ and Keycloak body typ.

    #[tokio::test]
    async fn accepted_header_typs() {
        let v = validator(&["sbc"]);
        for typ in [
            None,
            Some("JWT"),
            Some("jwt"),
            Some("at+jwt"),
            Some("AT+JWT"),
        ] {
            let mut header = es384_header();
            header.typ = typ.map(str::to_string);
            let token = sign_header(&header, &valid_claims(), &test_keys().es384);
            v.validate(&token).await.expect("valid typ");
        }
    }

    #[tokio::test]
    async fn other_header_typs_are_rejected() {
        let v = validator(&["sbc"]);
        for typ in ["logout+jwt", "dpop+jwt", "JOSE", ""] {
            let mut header = es384_header();
            header.typ = Some(typ.to_string());
            let token = sign_header(&header, &valid_claims(), &test_keys().es384);
            let err = v.validate(&token).await.unwrap_err();
            assert_invalid(&err, "typ not accepted");
        }
    }

    #[tokio::test]
    async fn keycloak_bearer_typ_claim_is_accepted() {
        let mut c = valid_claims();
        c["typ"] = serde_json::json!("Bearer");
        validator(&["sbc"])
            .validate(&sign(&c))
            .await
            .expect("valid");
    }

    #[tokio::test]
    async fn keycloak_non_access_typ_claim_is_rejected() {
        let v = validator(&["sbc"]);
        for typ in ["ID", "Refresh", "Logout", "bearer"] {
            let mut c = valid_claims();
            c["typ"] = serde_json::json!(typ);
            let err = v.validate(&sign(&c)).await.unwrap_err();
            assert_invalid(&err, "not an access token");
        }
    }

    // SEC-004: leeway bound.

    #[test]
    fn leeway_above_maximum_is_refused() {
        let jwks = || Arc::new(JwksCache::with_static(test_keys().jwks.clone()));
        let mut cfg = ValidatorConfig::new(TEST_ISSUER, vec!["sbc".to_string()]);
        cfg.leeway_secs = MAX_LEEWAY_SECS;
        assert!(Validator::new(jwks(), cfg.clone()).is_ok());
        cfg.leeway_secs = MAX_LEEWAY_SECS + 1;
        assert_eq!(
            Validator::new(jwks(), cfg).err(),
            Some(ConfigError::Leeway(MAX_LEEWAY_SECS + 1))
        );
    }

    // NIST-08: issuer and audiences are trimmed.

    #[tokio::test]
    async fn issuer_and_audiences_are_trimmed() {
        let v = Validator::new(
            Arc::new(JwksCache::with_static(test_keys().jwks.clone())),
            ValidatorConfig::new(format!(" {TEST_ISSUER}\n"), vec![" sbc ".to_string()]),
        )
        .expect("valid config");
        assert_eq!(v.issuer(), TEST_ISSUER);
        v.validate(&sign(&valid_claims())).await.expect("valid");
    }

    // SEC-006 / NIST-06: JWK use and key_ops.

    fn jwk_with_usage(kid: &str, usage: &serde_json::Value) -> Jwk {
        let mut value = serde_json::to_value(relabelled_jwk(TEST_KID, kid, None)).expect("jwk");
        let obj = value.as_object_mut().expect("object");
        obj.remove("use");
        for (k, v) in usage.as_object().expect("object") {
            obj.insert(k.clone(), v.clone());
        }
        serde_json::from_value(value).expect("jwk")
    }

    #[tokio::test]
    async fn jwk_use_enc_is_rejected() {
        let kid = "p384-enc";
        let v = validator_with(jwk_with_usage(kid, &serde_json::json!({ "use": "enc" })));
        let err = v
            .validate(&sign_with_kid(&valid_claims(), kid))
            .await
            .unwrap_err();
        assert_invalid(&err, "use is not sig");
    }

    #[tokio::test]
    async fn jwk_key_ops_without_verify_is_rejected() {
        let kid = "p384-sign-only";
        let v = validator_with(jwk_with_usage(
            kid,
            &serde_json::json!({ "key_ops": ["sign"] }),
        ));
        let err = v
            .validate(&sign_with_kid(&valid_claims(), kid))
            .await
            .unwrap_err();
        assert_invalid(&err, "key_ops lacks verify");
    }

    #[tokio::test]
    async fn jwk_key_ops_verify_or_no_usage_is_accepted() {
        for (kid, usage) in [
            ("p384-verify", serde_json::json!({ "key_ops": ["verify"] })),
            ("p384-no-usage", serde_json::json!({})),
        ] {
            let v = validator_with(jwk_with_usage(kid, &usage));
            v.validate(&sign_with_kid(&valid_claims(), kid))
                .await
                .expect("valid");
        }
    }
}
