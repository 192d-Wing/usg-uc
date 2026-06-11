//! HTTP routes: discovery document, per-user client config, probes.
//!
//! Response shapes are the wire contract from
//! docs/CLIENT-PROVISIONING-OIDC.md (`discovery.v1` / `client-config.v1`
//! schemas) — change them there first.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::config::Config;
use crate::jwks::JwksError;
use crate::token::{AuthError, Verifier};

/// Shared per-request state.
#[derive(Clone)]
pub struct AppState {
    /// Service config (env-derived, immutable after startup).
    pub cfg: Arc<Config>,
    /// Bearer-token verifier (owns the JWKS cache).
    pub verifier: Arc<Verifier>,
    /// Process start, for `/system/version` uptime.
    pub start_time: std::time::Instant,
}

/// Builds the service router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(liveness))
        .route("/readyz", get(readiness))
        .route("/system/version", get(version))
        .route("/.well-known/sip-client-config", get(discovery))
        .route("/v1/client-config", get(client_config))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

// ---------------------------------------------------------------------
// Wire types — discovery.v1
// ---------------------------------------------------------------------

#[derive(serde::Serialize)]
struct DiscoveryDoc {
    schema_version: u32,
    service_name: String,
    pop_id: String,
    oidc: DiscoveryOidc,
    provisioning: DiscoveryProvisioning,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    minimum_client_version: BTreeMap<&'static str, String>,
}

#[derive(serde::Serialize)]
struct DiscoveryOidc {
    issuer: String,
    client_id: String,
    scopes: Vec<String>,
}

#[derive(serde::Serialize)]
struct DiscoveryProvisioning {
    config_endpoint: String,
}

// ---------------------------------------------------------------------
// Wire types — client-config.v1
// ---------------------------------------------------------------------

#[derive(serde::Serialize)]
struct ClientConfig {
    schema_version: u32,
    user: UserInfo,
    sip: SipIdentity,
    registration: Registration,
    media: Media,
    features: Features,
    ttl_seconds: u32,
}

#[derive(serde::Serialize)]
struct UserInfo {
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

#[derive(serde::Serialize)]
struct SipIdentity {
    uri: String,
    dn: String,
    domain: String,
    auth: SipAuth,
}

#[derive(serde::Serialize)]
struct SipAuth {
    mode: &'static str,
    /// Always `null` in bearer mode; populated once ephemeral-digest
    /// minting (RFC 8760) lands.
    digest: Option<()>,
}

#[derive(serde::Serialize)]
struct Registration {
    expires_seconds: u32,
    registrar_domain: String,
}

#[derive(serde::Serialize)]
struct Media {
    codecs: Vec<String>,
    dtmf: &'static str,
    srtp: &'static str,
}

#[derive(serde::Serialize)]
struct Features {
    #[serde(skip_serializing_if = "Option::is_none")]
    voicemail_uri: Option<String>,
    mwi: bool,
}

// ---------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------

/// `GET /.well-known/sip-client-config` — unauthenticated discovery
/// document; the anycast first contact. Cacheable: contents are per-POP
/// but stable.
async fn discovery(State(state): State<AppState>) -> Response {
    let cfg = &state.cfg;
    let mut minimum_client_version = BTreeMap::new();
    if let Some(v) = &cfg.min_version_desktop {
        minimum_client_version.insert("desktop", v.clone());
    }
    if let Some(v) = &cfg.min_version_android {
        minimum_client_version.insert("android", v.clone());
    }
    let doc = DiscoveryDoc {
        schema_version: 1,
        service_name: cfg.service_name.clone(),
        pop_id: cfg.pop_id.clone(),
        oidc: DiscoveryOidc {
            issuer: cfg.oidc_issuer.clone(),
            client_id: cfg.oidc_client_id.clone(),
            scopes: cfg.oidc_scopes.clone(),
        },
        provisioning: DiscoveryProvisioning {
            config_endpoint: format!("{}/v1/client-config", cfg.public_url),
        },
        minimum_client_version,
    };
    ([(header::CACHE_CONTROL, "public, max-age=300")], Json(doc)).into_response()
}

/// `GET /v1/client-config` — per-user SIP configuration, authorized by an
/// OIDC bearer token carrying the `sip` scope and a `dn` claim.
async fn client_config(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let token = match bearer_token(&headers) {
        Ok(t) => t,
        Err(e) => return auth_error_response(&e),
    };
    let claims = match state.verifier.verify(token).await {
        Ok(c) => c,
        Err(e) => {
            info!(error = %e, "client-config request rejected");
            return auth_error_response(&e);
        }
    };
    let Some(dn) = claims.dn else {
        info!(sub = %claims.sub, "client-config request from user without dn claim");
        return auth_error_response(&AuthError::NotProvisioned);
    };
    // Provisioning event — who fetched a config, as which DN.
    info!(sub = %claims.sub, dn = %dn, "client config issued");

    let cfg = &state.cfg;
    let domain = claims.sip_domain.unwrap_or_else(|| cfg.sip_domain.clone());
    let display_name = claims
        .name
        .or(claims.preferred_username)
        .unwrap_or_else(|| dn.clone());

    let body = ClientConfig {
        schema_version: 1,
        user: UserInfo {
            display_name,
            email: claims.email,
        },
        sip: SipIdentity {
            uri: format!("sip:{dn}@{domain}"),
            dn,
            domain,
            auth: SipAuth {
                mode: "bearer",
                digest: None,
            },
        },
        registration: Registration {
            expires_seconds: cfg.reg_expires_secs,
            registrar_domain: cfg.registrar_domain.clone(),
        },
        media: Media {
            codecs: cfg.codecs.clone(),
            dtmf: "rfc4733",
            srtp: "none",
        },
        features: Features {
            voicemail_uri: cfg.voicemail_uri.clone(),
            mwi: cfg.voicemail_uri.is_some(),
        },
        ttl_seconds: cfg.ttl_secs,
    };

    // Identity material — never cache (design doc, Endpoint 2).
    ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

async fn liveness() -> impl IntoResponse {
    Json(serde_json::json!({"status": "ok"}))
}

/// Ready once the JWKS cache holds keys; tries one fetch when empty so a
/// pod becomes ready as soon as the `IdP` is reachable.
async fn readiness(State(state): State<AppState>) -> Response {
    let jwks = state.verifier.jwks();
    if !jwks.ready().await
        && let Err(e) = jwks.refresh().await
    {
        warn!(error = %e, "readiness: JWKS not yet available");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"status": "not_ready", "error": e.to_string()})),
        )
            .into_response();
    }
    Json(serde_json::json!({"status": "ready"})).into_response()
}

async fn version(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "service": "sbc-client-config-server",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_secs": state.start_time.elapsed().as_secs(),
    }))
}

// ---------------------------------------------------------------------
// Bearer plumbing
// ---------------------------------------------------------------------

fn bearer_token(headers: &HeaderMap) -> Result<&str, AuthError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            // RFC 9110 auth-scheme is case-insensitive.
            let (scheme, rest) = v.split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| rest.trim())
                .filter(|t| !t.is_empty())
        })
        .ok_or(AuthError::MissingToken)
}

/// Maps an [`AuthError`] to the RFC 6750 challenge responses the design
/// doc specifies.
fn auth_error_response(err: &AuthError) -> Response {
    let (status, challenge) = match err {
        AuthError::MissingToken => (
            StatusCode::UNAUTHORIZED,
            r#"Bearer realm="sip-client-config""#.to_string(),
        ),
        AuthError::InvalidToken(desc) => (
            StatusCode::UNAUTHORIZED,
            format!(
                r#"Bearer realm="sip-client-config", error="invalid_token", error_description="{}""#,
                sanitize(desc)
            ),
        ),
        AuthError::InsufficientScope => (
            StatusCode::FORBIDDEN,
            r#"Bearer realm="sip-client-config", error="insufficient_scope", scope="sip""#
                .to_string(),
        ),
        // Authenticated but not a voice user — no challenge would help.
        AuthError::NotProvisioned => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "not_provisioned",
                    "error_description": "no `dn` claim — user is not provisioned for voice",
                })),
            )
                .into_response();
        }
        // We couldn't obtain keys at all — the token may be fine.
        AuthError::Jwks(e @ (JwksError::Unavailable(_) | JwksError::Metadata(_))) => {
            warn!(error = %e, "cannot validate tokens: JWKS unavailable");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "temporarily_unavailable",
                    "error_description": "identity provider keys unavailable",
                })),
            )
                .into_response();
        }
        AuthError::Jwks(JwksError::UnknownKid(kid)) => (
            StatusCode::UNAUTHORIZED,
            format!(
                r#"Bearer realm="sip-client-config", error="invalid_token", error_description="unknown signing key {}""#,
                sanitize(kid)
            ),
        ),
    };

    let mut response =
        (status, Json(serde_json::json!({"error": err.to_string()}))).into_response();
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

/// Strips characters that would break out of a quoted-string in a
/// `WWW-Authenticate` header.
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use tower::ServiceExt;

    use super::*;
    use crate::jwks::JwksCache;

    const TEST_KID: &str = "test-key-1";

    struct TestKey {
        encoding: EncodingKey,
        jwks: JwkSet,
    }

    /// Fresh ES256 keypair per test run — no private key material lives
    /// in the tree.
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
            // Uncompressed SEC1 point: 0x04 || X (32 bytes) || Y (32 bytes).
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

    const TEST_ISSUER: &str = "https://idp.example.mil/realms/voice";
    const TEST_AUDIENCE: &str = "usg-uc-provisioning";

    fn test_config() -> Config {
        Config::from_lookup(|var| {
            match var {
                "SBC_CLIENT_CONFIG_POP_ID" => Some("us-east-1"),
                "SBC_CLIENT_CONFIG_PUBLIC_URL" => Some("https://us-east-1.pop.example.mil"),
                "SBC_CLIENT_CONFIG_OIDC_ISSUER" => Some(TEST_ISSUER),
                "SBC_CLIENT_CONFIG_OIDC_CLIENT_ID" => Some("usg-uc-softclient"),
                "SBC_CLIENT_CONFIG_SIP_DOMAIN" => Some("example.mil"),
                "SBC_CLIENT_CONFIG_REGISTRAR_DOMAIN" => Some("us-east-1.reg.example.mil"),
                "SBC_CLIENT_CONFIG_VOICEMAIL_URI" => Some("sip:*97@example.mil"),
                _ => None,
            }
            .map(str::to_string)
        })
        .expect("test config")
    }

    fn test_app() -> Router {
        let verifier = Verifier::new(
            Arc::new(JwksCache::with_static(test_key().jwks.clone())),
            TEST_ISSUER,
            TEST_AUDIENCE,
        );
        router(AppState {
            cfg: Arc::new(test_config()),
            verifier: Arc::new(verifier),
            start_time: std::time::Instant::now(),
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

    fn valid_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "sub": "f3a9-test",
            "exp": now_secs() + 300,
            "scope": "openid profile sip",
            "preferred_username": "jdoe",
            "name": "Jane Doe",
            "email": "jdoe@example.mil",
            "dn": "1455550100",
            "sip_domain": "example.mil",
        })
    }

    async fn get_json(
        app: Router,
        uri: &str,
        token: Option<&str>,
    ) -> (StatusCode, HeaderMap, serde_json::Value) {
        let mut req = Request::builder().uri(uri);
        if let Some(t) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let response = app
            .oneshot(req.body(Body::empty()).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json body")
        };
        (status, headers, json)
    }

    #[tokio::test]
    async fn discovery_is_public_and_cacheable() {
        let (status, headers, body) =
            get_json(test_app(), "/.well-known/sip-client-config", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=300")
        );
        assert_eq!(body["schema_version"], 1);
        assert_eq!(body["pop_id"], "us-east-1");
        assert_eq!(body["oidc"]["issuer"], TEST_ISSUER);
        assert_eq!(
            body["provisioning"]["config_endpoint"],
            "https://us-east-1.pop.example.mil/v1/client-config"
        );
    }

    #[tokio::test]
    async fn client_config_requires_token() {
        let (status, headers, _) = get_json(test_app(), "/v1/client-config", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let challenge = headers
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .expect("challenge");
        assert!(challenge.starts_with("Bearer "), "got: {challenge}");
    }

    #[tokio::test]
    async fn valid_token_yields_config() {
        let token = sign(&valid_claims());
        let (status, headers, body) = get_json(test_app(), "/v1/client-config", Some(&token)).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(body["schema_version"], 1);
        assert_eq!(body["sip"]["dn"], "1455550100");
        assert_eq!(body["sip"]["uri"], "sip:1455550100@example.mil");
        assert_eq!(body["sip"]["auth"]["mode"], "bearer");
        assert!(body["sip"]["auth"]["digest"].is_null());
        assert_eq!(
            body["registration"]["registrar_domain"],
            "us-east-1.reg.example.mil"
        );
        assert_eq!(body["registration"]["expires_seconds"], 300);
        assert_eq!(body["user"]["display_name"], "Jane Doe");
        assert_eq!(body["features"]["voicemail_uri"], "sip:*97@example.mil");
        assert_eq!(body["ttl_seconds"], 3600);
    }

    #[tokio::test]
    async fn expired_token_is_rejected() {
        let mut claims = valid_claims();
        claims["exp"] = serde_json::json!(now_secs() - 600);
        let token = sign(&claims);
        let (status, headers, _) = get_json(test_app(), "/v1/client-config", Some(&token)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let challenge = headers
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .expect("challenge");
        assert!(
            challenge.contains(r#"error="invalid_token""#),
            "got: {challenge}"
        );
    }

    #[tokio::test]
    async fn wrong_audience_is_rejected() {
        let mut claims = valid_claims();
        claims["aud"] = serde_json::json!("someone-else");
        let token = sign(&claims);
        let (status, _, _) = get_json(test_app(), "/v1/client-config", Some(&token)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_sip_scope_is_forbidden() {
        let mut claims = valid_claims();
        claims["scope"] = serde_json::json!("openid profile");
        let token = sign(&claims);
        let (status, headers, _) = get_json(test_app(), "/v1/client-config", Some(&token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let challenge = headers
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .expect("challenge");
        assert!(
            challenge.contains(r#"error="insufficient_scope""#),
            "got: {challenge}"
        );
    }

    #[tokio::test]
    async fn token_without_dn_is_not_provisioned() {
        let mut claims = valid_claims();
        claims.as_object_mut().expect("object").remove("dn");
        let token = sign(&claims);
        let (status, _, body) = get_json(test_app(), "/v1/client-config", Some(&token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "not_provisioned");
    }

    #[tokio::test]
    async fn unknown_kid_is_unauthorized() {
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("rotated-away".to_string());
        let token = encode(&header, &valid_claims(), &test_key().encoding).expect("sign");
        let (status, _, _) = get_json(test_app(), "/v1/client-config", Some(&token)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn probes_respond() {
        let (status, _, body) = get_json(test_app(), "/healthz", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ok");

        // readyz is ready immediately: the static JWKS cache holds keys.
        let (status, _, body) = get_json(test_app(), "/readyz", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ready");

        let (status, _, body) = get_json(test_app(), "/system/version", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["service"], "sbc-client-config-server");
    }
}
