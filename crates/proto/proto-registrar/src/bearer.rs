//! RFC 8898 Bearer-token authorization for SIP REGISTER.
//!
//! The registrar's digest path ([`crate::authentication`]) authenticates a
//! shared secret. Bearer mode instead validates an OIDC access token (JWT)
//! against the `IdP`'s JWKS via [`proto_jwt`] and binds the authenticated
//! identity to the registered AOR: the `dn` claim MUST equal the To-URI
//! user part (RFC 8898 §3). Token validation is async (it may refresh the
//! JWKS), so it runs ahead of the synchronous binding logic — the daemon
//! calls [`BearerAuthenticator::authorize`] first and only proceeds to
//! [`crate::registrar::Registrar::process_register`] on
//! [`BearerResult::Authorized`].
//!
//! ## NIST 800-53 Rev5: IA-2, IA-5(2) (PKI-based authentication)
//! ## RFC 8898 (Third-Party Token-Based Auth for SIP), RFC 6750 (Bearer)

use std::sync::Arc;

use proto_jwt::{ValidateError, Validator};

/// A specific Bearer challenge reason, surfaced as the `error` parameter of
/// the `WWW-Authenticate: Bearer` header (RFC 6750 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerError {
    /// No token, an expired/forged token, or an unknown signing key.
    InvalidToken,
    /// The `Authorization` header was malformed (not `Bearer <token>`).
    InvalidRequest,
    /// The token is valid but lacks the required scope.
    InsufficientScope,
}

impl BearerError {
    /// The RFC 6750 `error` parameter value for this challenge.
    #[must_use]
    pub const fn as_param(self) -> &'static str {
        match self {
            Self::InvalidToken => "invalid_token",
            Self::InvalidRequest => "invalid_request",
            Self::InsufficientScope => "insufficient_scope",
        }
    }
}

/// Outcome of authorizing a REGISTER with a Bearer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BearerResult {
    /// Token valid and bound to the AOR. Carries the claims the registrar /
    /// daemon may want to log or propagate.
    Authorized {
        /// The `dn` claim (== the AOR user part).
        dn: String,
        /// The `sip_domain` claim, if present.
        sip_domain: Option<String>,
    },
    /// Reject with `401 Unauthorized` + a `WWW-Authenticate: Bearer`
    /// challenge. The client should (re)authenticate or refresh its token.
    Challenge {
        /// Why the token was rejected.
        error: BearerError,
    },
    /// Reject with `403 Forbidden`: the token authenticated successfully but
    /// is not authorized for this AOR (no `dn` claim, or `dn` ≠ AOR user).
    /// No challenge would help, so none is sent.
    Forbidden {
        /// Operator-facing reason (logged; not sent verbatim to the client).
        reason: String,
    },
}

/// Authorizes REGISTER requests carrying an OIDC Bearer token.
pub struct BearerAuthenticator {
    validator: Arc<Validator>,
    realm: String,
}

impl std::fmt::Debug for BearerAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerAuthenticator")
            .field("realm", &self.realm)
            .finish_non_exhaustive()
    }
}

impl BearerAuthenticator {
    /// New authenticator validating tokens with `validator` and advertising
    /// `realm` in its challenges.
    pub fn new(validator: Arc<Validator>, realm: impl Into<String>) -> Self {
        Self {
            validator,
            realm: realm.into(),
        }
    }

    /// Authorizes a REGISTER.
    ///
    /// `authorization` is the raw `Authorization` header value (e.g.
    /// `"Bearer eyJ…"`), `None` when absent. `aor_user` is the user part of
    /// the To-URI (the AOR being registered). The returned [`BearerResult`]
    /// tells the caller whether to bind, challenge (401), or forbid (403).
    pub async fn authorize(&self, authorization: Option<&str>, aor_user: &str) -> BearerResult {
        let Some(header) = authorization else {
            return BearerResult::Challenge {
                error: BearerError::InvalidToken,
            };
        };
        let Some(token) = parse_bearer(header) else {
            return BearerResult::Challenge {
                error: BearerError::InvalidRequest,
            };
        };

        match self.validator.validate(token).await {
            // The challenge sent to the client deliberately carries only the
            // RFC 6750 error code — log the underlying reason here or
            // operators see nothing but unexplained 401s.
            Err(ref e @ ValidateError::Jwks(_)) => {
                tracing::warn!(error = %e, "bearer REGISTER rejected: JWKS unavailable");
                BearerResult::Challenge {
                    error: BearerError::InvalidToken,
                }
            }
            Err(ValidateError::InsufficientScope) => BearerResult::Challenge {
                error: BearerError::InsufficientScope,
            },
            // Authenticated-but-unprovisioned never reaches here (validate()
            // does not enforce `dn`), but map it defensively to Forbidden.
            Err(ValidateError::NotProvisioned) => BearerResult::Forbidden {
                reason: "token not provisioned for voice".to_string(),
            },
            Err(ref e @ (ValidateError::MissingToken | ValidateError::InvalidToken(_))) => {
                tracing::debug!(error = %e, aor_user, "bearer REGISTER rejected: invalid token");
                BearerResult::Challenge {
                    error: BearerError::InvalidToken,
                }
            }
            Ok(claims) => {
                let Some(dn) = claims.dn else {
                    return BearerResult::Forbidden {
                        reason: "token has no `dn` claim — not a provisioned voice user"
                            .to_string(),
                    };
                };
                // RFC 8898 §3: the authenticated identity must own the AOR.
                if dn != aor_user {
                    return BearerResult::Forbidden {
                        reason: format!("token dn `{dn}` does not match AOR user `{aor_user}`"),
                    };
                }
                BearerResult::Authorized {
                    dn,
                    sip_domain: claims.sip_domain,
                }
            }
        }
    }

    /// Builds the `WWW-Authenticate` header value for a 401 challenge
    /// (RFC 6750 §3): `Bearer realm="<realm>", error="<error>"`.
    #[must_use]
    pub fn challenge_header(&self, error: BearerError) -> String {
        format!(
            r#"Bearer realm="{}", error="{}""#,
            self.realm,
            error.as_param()
        )
    }
}

/// Extracts the token from an `Authorization: Bearer <token>` value. The
/// auth-scheme is case-insensitive (RFC 9110 §11.1); surrounding whitespace
/// is trimmed and an empty token is rejected.
fn parse_bearer(header: &str) -> Option<&str> {
    let (scheme, rest) = header.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| rest.trim())
        .filter(|t| !t.is_empty())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use proto_jwt::{JwksCache, ValidatorConfig};

    use super::*;

    const TEST_KID: &str = "test-key-1";
    const TEST_ISSUER: &str = "https://idp.example.mil/realms/voice";

    struct TestKey {
        encoding: EncodingKey,
        jwks: JwkSet,
    }

    fn test_key() -> &'static TestKey {
        use aws_lc_rs::rand::SystemRandom;
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        static KEY: std::sync::OnceLock<TestKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                &SystemRandom::new(),
            )
            .expect("generate test key");
            let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
                .expect("parse test key");
            let point = pair.public_key().as_ref();
            assert_eq!(point[0], 4);
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

    fn sign(claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(TEST_KID.to_string());
        encode(&header, claims, &test_key().encoding).expect("sign")
    }

    fn claims_with_dn(dn: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": TEST_ISSUER,
            "aud": ["sbc"],
            "sub": "f3a9-test",
            "exp": now_secs() + 300,
            "scope": "openid sip",
            "dn": dn,
            "sip_domain": "example.mil",
        })
    }

    fn authenticator() -> BearerAuthenticator {
        let validator = Validator::new(
            Arc::new(JwksCache::with_static(test_key().jwks.clone())),
            ValidatorConfig::new(TEST_ISSUER, vec!["sbc".to_string()]),
        );
        BearerAuthenticator::new(Arc::new(validator), "sbc.example.mil")
    }

    #[tokio::test]
    async fn valid_token_matching_aor_is_authorized() {
        let token = sign(&claims_with_dn("1455550100"));
        let result = authenticator()
            .authorize(Some(&format!("Bearer {token}")), "1455550100")
            .await;
        assert!(matches!(
            result,
            BearerResult::Authorized { dn, .. } if dn == "1455550100"
        ));
    }

    #[tokio::test]
    async fn dn_not_matching_aor_is_forbidden() {
        let token = sign(&claims_with_dn("1455550100"));
        let result = authenticator()
            .authorize(Some(&format!("Bearer {token}")), "9999999999")
            .await;
        assert!(matches!(result, BearerResult::Forbidden { .. }));
    }

    #[tokio::test]
    async fn token_without_dn_is_forbidden() {
        let mut claims = claims_with_dn("x");
        claims.as_object_mut().expect("obj").remove("dn");
        let token = sign(&claims);
        let result = authenticator()
            .authorize(Some(&format!("Bearer {token}")), "1455550100")
            .await;
        assert!(matches!(result, BearerResult::Forbidden { .. }));
    }

    #[tokio::test]
    async fn missing_authorization_header_challenges_invalid_token() {
        let result = authenticator().authorize(None, "1455550100").await;
        assert_eq!(
            result,
            BearerResult::Challenge {
                error: BearerError::InvalidToken
            }
        );
    }

    #[tokio::test]
    async fn malformed_scheme_challenges_invalid_request() {
        let result = authenticator()
            .authorize(Some("Digest username=\"x\""), "1455550100")
            .await;
        assert_eq!(
            result,
            BearerResult::Challenge {
                error: BearerError::InvalidRequest
            }
        );
    }

    #[tokio::test]
    async fn expired_token_challenges_invalid_token() {
        let mut claims = claims_with_dn("1455550100");
        claims["exp"] = serde_json::json!(now_secs() - 600);
        let token = sign(&claims);
        let result = authenticator()
            .authorize(Some(&format!("Bearer {token}")), "1455550100")
            .await;
        assert_eq!(
            result,
            BearerResult::Challenge {
                error: BearerError::InvalidToken
            }
        );
    }

    #[test]
    fn challenge_header_is_rfc6750_shaped() {
        let h = authenticator().challenge_header(BearerError::InvalidToken);
        assert_eq!(
            h,
            r#"Bearer realm="sbc.example.mil", error="invalid_token""#
        );
    }
}
