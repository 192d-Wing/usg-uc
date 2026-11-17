//! Soft-client OIDC sign-in + auto-discovery.
//!
//! Implements the client half of docs/CLIENT-PROVISIONING-OIDC.md: from a
//! single service domain, fetch the discovery document, verify the issuer is
//! trusted, authenticate in the system browser, exchange/refresh tokens,
//! fetch the per-user SIP config, and map it onto a
//! [`client_types::SipAccount`].
//!
//! Two browser flows are provided:
//! - **Device Authorization Grant (RFC 8628)** — the desktop flow: no
//!   listening socket, no redirect URI. See
//!   [`ProvisioningClient::start_device_authorization`] /
//!   [`ProvisioningClient::poll_device_token`].
//! - **Authorization Code + PKCE (RFC 8252)** — for platforms with a claimed
//!   HTTPS redirect (Android App Links). See
//!   [`ProvisioningClient::build_authorization_url`] /
//!   [`ProvisioningClient::exchange_code`].
//!
//! This crate is platform-agnostic: it does NOT open the browser itself (the
//! Tauri/Android shell does). All secrets are held in [`zeroize::Zeroizing`].

// Docs are RFC/acronym-heavy (OAuth2, OIDC, PKCE, IdP, JWT, AOR); backticking
// every term hurts readability more than it helps. Matches proto-registrar.
#![allow(clippy::doc_markdown)]

pub mod discovery;
mod error;
pub mod http;
pub mod mapping;
pub mod pkce;
pub mod session;
pub mod wire;

pub use discovery::{
    ServiceDomain, parse_service_domain, verify_client_config, verify_device_authorization,
    verify_discovery, verify_issuer_pinned, verify_oidc_endpoints,
};
pub use error::ProvisioningError;
pub use http::{CaTrust, build_http_client};
pub use pkce::{PkcePair, generate_pkce, random_token};
pub use session::{PersistedProvisioning, ProvisionedSession, SessionState};
pub use wire::{ClientConfig, DeviceAuthorization, DiscoveryDoc, OidcMetadata, TokenResponse};

use wire::DiscoveryOidc;

/// Response-body cap for discovery, OIDC metadata, device and token
/// responses (and error bodies).
///
/// NIST 800-53 Rev5: SC-5 (bounded resource use).
const MAX_SMALL_BODY: usize = 64 * 1024;

/// Response-body cap for the per-user client config.
const MAX_CONFIG_BODY: usize = 256 * 1024;

/// Extracts the `nonce` claim from an ID token's payload WITHOUT verifying
/// the signature.
///
/// Used only to bind the token response to this sign-in attempt (OIDC Core
/// §3.1.3.7). The access token's authenticity is enforced server-side by the
/// POP/SBC validators; the nonce here defends the client against
/// authorization-response injection.
#[must_use]
pub fn id_token_nonce(id_token: &str) -> Option<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = id_token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json.get("nonce")?.as_str().map(str::to_string)
}

/// Orchestrates the HTTP side of discovery, OIDC, and provisioning.
pub struct ProvisioningClient {
    http: reqwest::Client,
}

impl ProvisioningClient {
    /// New client trusting CAs per `trust`.
    ///
    /// # Errors
    /// [`ProvisioningError::Http`] if the HTTP client cannot be built.
    pub fn new(trust: &CaTrust) -> Result<Self, ProvisioningError> {
        Ok(Self {
            http: build_http_client(trust)?,
        })
    }

    /// Fetches `https://{service}/.well-known/sip-client-config` and
    /// validates it with [`discovery::verify_discovery`] before returning.
    ///
    /// NIST 800-53 Rev5: IA-5, SC-23, SI-10.
    ///
    /// # Errors
    /// [`ProvisioningError::Discovery`] on a transport or non-2xx error,
    /// [`ProvisioningError::Json`] if the body doesn't match the schema, or
    /// [`ProvisioningError::IssuerNotTrusted`] /
    /// [`ProvisioningError::UntrustedEndpoint`] if the document names an
    /// issuer or config endpoint outside the service's trust scope.
    pub async fn fetch_discovery(
        &self,
        service: &ServiceDomain,
    ) -> Result<DiscoveryDoc, ProvisioningError> {
        let doc: DiscoveryDoc = self
            .get_json(&service.discovery_url(), None)
            .await
            .map_err(ProvisioningError::into_discovery)?;
        discovery::verify_discovery(service, &doc)?;
        Ok(doc)
    }

    /// Fetches `{issuer}/.well-known/openid-configuration`.
    ///
    /// # Errors
    /// [`ProvisioningError::IssuerNotTrusted`] before any I/O when `issuer`
    /// is not https or carries userinfo, a query or a fragment;
    /// [`ProvisioningError::Discovery`] on a transport, non-2xx or body error;
    /// also errors when the metadata's `issuer` doesn't round-trip, and
    /// [`ProvisioningError::UntrustedEndpoint`] when an endpoint is outside
    /// the issuer's registrable domain ([`discovery::verify_oidc_endpoints`]).
    ///
    /// NIST 800-53 Rev5: IA-5, SC-23, SI-10.
    pub async fn fetch_oidc_metadata(
        &self,
        issuer: &str,
    ) -> Result<OidcMetadata, ProvisioningError> {
        discovery::verify_issuer_url(issuer)?;
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let meta: OidcMetadata = self
            .get_json(&url, None)
            .await
            .map_err(ProvisioningError::into_discovery)?;
        if meta.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
            return Err(ProvisioningError::Discovery(format!(
                "OIDC issuer mismatch: expected {issuer}, metadata says {}",
                meta.issuer
            )));
        }
        discovery::verify_oidc_endpoints(&meta)?;
        Ok(meta)
    }

    /// Builds the browser authorization URL (Authorization Code + PKCE S256).
    #[must_use]
    pub fn build_authorization_url(
        meta: &OidcMetadata,
        oidc: &DiscoveryOidc,
        redirect_uri: &str,
        challenge: &str,
        state: &str,
        nonce: &str,
    ) -> String {
        // Endpoint comes from validated metadata; fall back to the raw
        // string if it somehow won't parse (it will fail the request
        // later with a clear error).
        let Ok(mut url) = url::Url::parse(&meta.authorization_endpoint) else {
            return meta.authorization_endpoint.clone();
        };
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &oidc.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &oidc.scopes.join(" "))
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        url.to_string()
    }

    /// Exchanges an authorization `code` for tokens (public client + PKCE).
    ///
    /// # Errors
    /// [`ProvisioningError::TokenExchange`] on a transport/HTTP error or a
    /// non-OK token response.
    pub async fn exchange_code(
        &self,
        meta: &OidcMetadata,
        client_id: &str,
        redirect_uri: &str,
        code: &str,
        verifier: &str,
    ) -> Result<TokenResponse, ProvisioningError> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", verifier),
        ];
        self.post_token(&meta.token_endpoint, &form).await
    }

    /// Starts a Device Authorization Grant (RFC 8628 §3.1) — the desktop
    /// sign-in flow. The caller opens `verification_uri_complete` (falling
    /// back to `verification_uri`) in the system browser, shows `user_code`
    /// to the user, and then [`Self::poll_device_token`]s. Both verification
    /// URLs are checked with [`discovery::verify_device_authorization`]
    /// before this returns.
    ///
    /// NIST 800-53 Rev5: IA-5, SC-23, SI-10.
    ///
    /// # Errors
    /// [`ProvisioningError::Authorization`] when the IdP advertises no
    /// device authorization endpoint, [`ProvisioningError::TokenExchange`]
    /// on a transport/HTTP error, [`ProvisioningError::Json`] on a bad or
    /// oversized body, [`ProvisioningError::UntrustedEndpoint`] when a
    /// verification URL is outside the issuer's registrable domain.
    pub async fn start_device_authorization(
        &self,
        meta: &OidcMetadata,
        oidc: &DiscoveryOidc,
        pkce_challenge: &str,
    ) -> Result<DeviceAuthorization, ProvisioningError> {
        let endpoint = meta
            .device_authorization_endpoint
            .as_deref()
            .ok_or_else(|| {
                ProvisioningError::Authorization(
                    "the IdP does not advertise a device_authorization_endpoint — enable the \
                 OAuth 2.0 Device Authorization Grant on the OIDC client"
                        .to_string(),
                )
            })?;
        let scope = oidc.scopes.join(" ");
        // PKCE on the device grant (RFC 8628 + RFC 7636): Keycloak clients
        // with an enforced code-challenge method reject device authorization
        // requests that omit it ("Missing parameter: code_challenge_method").
        let form = [
            ("client_id", oidc.client_id.as_str()),
            ("scope", scope.as_str()),
            ("code_challenge", pkce_challenge),
            ("code_challenge_method", "S256"),
        ];
        let resp = self
            .http
            .post(endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| ProvisioningError::TokenExchange(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = error_body(resp).await;
            return Err(ProvisioningError::TokenExchange(format!(
                "device authorization endpoint returned {status}: {body}"
            )));
        }
        let device: DeviceAuthorization = read_json(resp, MAX_SMALL_BODY).await?;
        discovery::verify_device_authorization(meta, &device)?;
        Ok(device)
    }

    /// Polls the token endpoint until the user approves the device grant
    /// (RFC 8628 §3.4–3.5): sleeps `interval` between attempts, backs off
    /// +5 s on `slow_down`, and gives up when `expires_in` passes.
    ///
    /// Cancellable by dropping the future (e.g. inside `tokio::select!`).
    ///
    /// # Errors
    /// [`ProvisioningError::Timeout`] when the code expires before the user
    /// completes sign-in, [`ProvisioningError::Authorization`] when the user
    /// denies, [`ProvisioningError::TokenExchange`]/[`ProvisioningError::Json`]
    /// on transport or protocol errors.
    pub async fn poll_device_token(
        &self,
        meta: &OidcMetadata,
        client_id: &str,
        device: &DeviceAuthorization,
        pkce_verifier: &str,
    ) -> Result<TokenResponse, ProvisioningError> {
        use std::time::Duration;
        let mut interval = Duration::from_secs(device.interval.unwrap_or(5).max(1));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(device.expires_in);
        loop {
            tokio::time::sleep(interval).await;
            if tokio::time::Instant::now() >= deadline {
                return Err(ProvisioningError::Timeout(
                    "sign-in was not completed before the code expired".to_string(),
                ));
            }
            let form = [
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("device_code", device.device_code.as_str()),
                ("client_id", client_id),
                ("code_verifier", pkce_verifier),
            ];
            let resp = self
                .http
                .post(&meta.token_endpoint)
                .form(&form)
                .send()
                .await
                .map_err(|e| ProvisioningError::TokenExchange(e.to_string()))?;
            if resp.status().is_success() {
                return read_json(resp, MAX_SMALL_BODY).await;
            }
            let status = resp.status();
            let body = error_body(resp).await;
            match classify_device_poll(&body) {
                DevicePoll::Pending => {}
                DevicePoll::SlowDown => interval += Duration::from_secs(5),
                DevicePoll::Denied => {
                    return Err(ProvisioningError::Authorization(
                        "sign-in was denied".to_string(),
                    ));
                }
                DevicePoll::Expired => {
                    return Err(ProvisioningError::Timeout(
                        "the sign-in code expired".to_string(),
                    ));
                }
                DevicePoll::Fatal => {
                    return Err(ProvisioningError::TokenExchange(format!(
                        "token endpoint returned {status}: {body}"
                    )));
                }
            }
        }
    }

    /// Refreshes the access token using a refresh token.
    ///
    /// # Errors
    /// [`ProvisioningError::TokenExchange`] as above; the caller should treat
    /// this as "refresh failed → re-run the browser flow".
    pub async fn refresh_token(
        &self,
        meta: &OidcMetadata,
        client_id: &str,
        refresh_token: &str,
    ) -> Result<TokenResponse, ProvisioningError> {
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ];
        self.post_token(&meta.token_endpoint, &form).await
    }

    /// Best-effort revocation of a refresh token at the IdP (RFC 7009),
    /// used on sign-out. No-op when the IdP advertises no revocation
    /// endpoint; failures are returned but callers typically only log them.
    ///
    /// # Errors
    /// [`ProvisioningError::TokenExchange`] when the revocation request
    /// itself fails.
    pub async fn revoke_refresh_token(
        &self,
        meta: &OidcMetadata,
        client_id: &str,
        refresh_token: &str,
    ) -> Result<(), ProvisioningError> {
        let Some(endpoint) = meta.revocation_endpoint.as_deref() else {
            return Ok(());
        };
        self.http
            .post(endpoint)
            .form(&[
                ("token", refresh_token),
                ("token_type_hint", "refresh_token"),
                ("client_id", client_id),
            ])
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| ProvisioningError::TokenExchange(format!("revocation failed: {e}")))?;
        Ok(())
    }

    /// Fetches the per-user config with `Authorization: Bearer`.
    ///
    /// `config_endpoint` is checked against `service` before any I/O (https,
    /// no userinfo, inside the service's registrable domain), and the
    /// returned config is checked with [`discovery::verify_client_config`]
    /// before it is returned.
    ///
    /// NIST 800-53 Rev5: IA-5, SC-23, SI-10, AC-4.
    ///
    /// # Errors
    /// [`ProvisioningError::UntrustedEndpoint`] when the endpoint or the
    /// provisioned registrar/SIP identity is out of scope;
    /// [`ProvisioningError::Unauthorized`] on a 401 (token expired/invalid →
    /// refresh and retry once); [`ProvisioningError::Json`] on a bad or
    /// oversized body; [`ProvisioningError::Config`] otherwise, including a
    /// 3xx (redirects are not followed).
    pub async fn fetch_client_config(
        &self,
        service: &ServiceDomain,
        config_endpoint: &str,
        access_token: &str,
    ) -> Result<ClientConfig, ProvisioningError> {
        // The bearer token is only sent to an endpoint in the service scope.
        discovery::verify_endpoint_in_scope(
            "config_endpoint",
            config_endpoint,
            service.registrable(),
        )?;
        let resp = self
            .http
            .get(config_endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ProvisioningError::Config(e.to_string()))?;
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(ProvisioningError::Unauthorized);
        }
        check_success(resp.status()).map_err(ProvisioningError::Config)?;
        let cfg: ClientConfig = read_json(resp, MAX_CONFIG_BODY).await?;
        discovery::verify_client_config(service, &cfg)?;
        Ok(cfg)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        bearer: Option<&str>,
    ) -> Result<T, ProvisioningError> {
        let mut req = self.http.get(url);
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ProvisioningError::Http(e.to_string()))?;
        check_success(resp.status()).map_err(ProvisioningError::Http)?;
        read_json(resp, MAX_SMALL_BODY).await
    }

    async fn post_token(
        &self,
        token_endpoint: &str,
        form: &[(&str, &str)],
    ) -> Result<TokenResponse, ProvisioningError> {
        let resp = self
            .http
            .post(token_endpoint)
            .form(form)
            .send()
            .await
            .map_err(|e| ProvisioningError::TokenExchange(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = error_body(resp).await;
            return Err(ProvisioningError::TokenExchange(format!(
                "token endpoint returned {status}: {body}"
            )));
        }
        read_json(resp, MAX_SMALL_BODY).await
    }
}

/// Requires a 2xx status. A 3xx is reported as not followed (the HTTP
/// client has redirects disabled).
///
/// NIST 800-53 Rev5: AC-4.
fn check_success(status: reqwest::StatusCode) -> Result<(), String> {
    if status.is_success() {
        Ok(())
    } else if status.is_redirection() {
        Err(format!("server returned {status}; redirect not followed"))
    } else {
        Err(format!("server returned {status}"))
    }
}

/// Reads at most `limit` body bytes; a longer body is an error.
///
/// NIST 800-53 Rev5: SC-5, SI-10.
async fn read_capped(mut resp: reqwest::Response, limit: usize) -> Result<Vec<u8>, String> {
    let too_large = || format!("response body exceeds {limit} bytes");
    if resp
        .content_length()
        .is_some_and(|len| usize::try_from(len).map_or(true, |len| len > limit))
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Capped read + JSON decode.
async fn read_json<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
    limit: usize,
) -> Result<T, ProvisioningError> {
    let body = read_capped(resp, limit)
        .await
        .map_err(ProvisioningError::Json)?;
    serde_json::from_slice(&body).map_err(|e| ProvisioningError::Json(e.to_string()))
}

/// Capped error body for diagnostics; empty when unreadable or oversized.
async fn error_body(resp: reqwest::Response) -> String {
    read_capped(resp, MAX_SMALL_BODY).await.map_or_else(
        |_| String::new(),
        |b| String::from_utf8_lossy(&b).into_owned(),
    )
}

/// How a non-2xx token-endpoint response should steer the device-grant
/// polling loop (RFC 8628 §3.5).
#[derive(Debug, PartialEq, Eq)]
enum DevicePoll {
    /// `authorization_pending` — keep polling at the current interval.
    Pending,
    /// `slow_down` — keep polling, interval +5 s.
    SlowDown,
    /// `access_denied` — the user declined.
    Denied,
    /// `expired_token` — the device code lapsed before approval.
    Expired,
    /// Anything else is a hard protocol/config error.
    Fatal,
}

fn classify_device_poll(body: &str) -> DevicePoll {
    let error = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string));
    match error.as_deref() {
        Some("authorization_pending") => DevicePoll::Pending,
        Some("slow_down") => DevicePoll::SlowDown,
        Some("access_denied") => DevicePoll::Denied,
        Some("expired_token") => DevicePoll::Expired,
        _ => DevicePoll::Fatal,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn authorization_url_has_pkce_and_state() {
        let meta = OidcMetadata {
            issuer: "https://idp.example.mil/realms/voice".into(),
            authorization_endpoint:
                "https://idp.example.mil/realms/voice/protocol/openid-connect/auth".into(),
            token_endpoint: "https://idp.example.mil/token".into(),
            device_authorization_endpoint: None,
            end_session_endpoint: None,
            revocation_endpoint: None,
        };
        let oidc = DiscoveryOidc {
            issuer: meta.issuer.clone(),
            client_id: "usg-uc-softclient".into(),
            scopes: vec!["openid".into(), "sip".into()],
        };
        let url = ProvisioningClient::build_authorization_url(
            &meta,
            &oidc,
            "http://127.0.0.1:54321/",
            "CHALLENGE",
            "STATE",
            "NONCE",
        );
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=usg-uc-softclient"));
        assert!(url.contains("code_challenge=CHALLENGE"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state=STATE"));
        assert!(url.contains("nonce=NONCE"));
        // scope space-joined and percent-encoded
        assert!(url.contains("scope=openid+sip") || url.contains("scope=openid%20sip"));
    }

    #[test]
    fn device_poll_classifies_rfc8628_errors() {
        let body = |e: &str| format!(r#"{{"error":"{e}","error_description":"x"}}"#);
        assert_eq!(
            classify_device_poll(&body("authorization_pending")),
            DevicePoll::Pending
        );
        assert_eq!(
            classify_device_poll(&body("slow_down")),
            DevicePoll::SlowDown
        );
        assert_eq!(
            classify_device_poll(&body("access_denied")),
            DevicePoll::Denied
        );
        assert_eq!(
            classify_device_poll(&body("expired_token")),
            DevicePoll::Expired
        );
        assert_eq!(
            classify_device_poll(&body("invalid_grant")),
            DevicePoll::Fatal
        );
        assert_eq!(classify_device_poll("not json"), DevicePoll::Fatal);
        assert_eq!(classify_device_poll("{}"), DevicePoll::Fatal);
    }

    #[test]
    fn id_token_nonce_extracts_claim() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"x","nonce":"NONCE-42"}"#);
        let token = format!("eyJhbGciOiJFUzI1NiJ9.{payload}.sig");
        assert_eq!(id_token_nonce(&token).as_deref(), Some("NONCE-42"));
        assert!(id_token_nonce("not-a-jwt").is_none());
    }

    #[test]
    fn check_success_reports_redirect_not_followed() {
        use reqwest::StatusCode;
        assert!(check_success(StatusCode::OK).is_ok());
        assert!(check_success(StatusCode::NO_CONTENT).is_ok());
        for s in [
            StatusCode::MOVED_PERMANENTLY,
            StatusCode::FOUND,
            StatusCode::TEMPORARY_REDIRECT,
        ] {
            let err = check_success(s).unwrap_err();
            assert!(err.contains("redirect not followed"), "{s}: {err}");
        }
        for s in [
            StatusCode::NOT_MODIFIED,
            StatusCode::NOT_FOUND,
            StatusCode::BAD_GATEWAY,
        ] {
            assert!(check_success(s).is_err(), "{s}");
        }
    }

    /// Answers one request with `response` on a fresh listener; returns the URL.
    async fn serve_once(response: Vec<u8>) -> String {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match sock.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = sock.write_all(&response).await;
            let _ = sock.shutdown().await;
        });
        format!("http://127.0.0.1:{port}/.well-known/openid-configuration")
    }

    /// Plaintext client so status/body handling can be exercised without a
    /// TLS fixture; production clients are https-only.
    fn plaintext_client() -> ProvisioningClient {
        ProvisioningClient {
            http: http::build_http_client_with(&CaTrust::System, false).unwrap(),
        }
    }

    #[tokio::test]
    async fn get_json_redirect_is_discovery_error_not_followed() {
        let url = serve_once(
            b"HTTP/1.1 302 Found\r\nLocation: https://example.com/x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec(),
        )
        .await;
        let err = plaintext_client()
            .get_json::<serde_json::Value>(&url, None)
            .await
            .map_err(ProvisioningError::into_discovery)
            .unwrap_err();
        assert!(
            matches!(&err, ProvisioningError::Discovery(m) if m.contains("redirect not followed")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn get_json_accepts_small_body() {
        let body = br#"{"ok":true}"#;
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        resp.extend_from_slice(body);
        let url = serve_once(resp).await;
        let v: serde_json::Value = plaintext_client().get_json(&url, None).await.unwrap();
        assert_eq!(v["ok"], serde_json::Value::Bool(true));
    }

    #[tokio::test]
    async fn get_json_rejects_oversized_body_by_length() {
        let body = vec![b' '; MAX_SMALL_BODY + 1];
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        resp.extend_from_slice(&body);
        let url = serve_once(resp).await;
        let err = plaintext_client()
            .get_json::<serde_json::Value>(&url, None)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ProvisioningError::Json(m) if m.contains("exceeds")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn get_json_rejects_oversized_body_without_length() {
        // No Content-Length: body is delimited by connection close, so the
        // cap must be enforced while streaming.
        let mut resp = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        resp.extend(std::iter::repeat_n(b' ', MAX_SMALL_BODY + 1));
        let url = serve_once(resp).await;
        let err = plaintext_client()
            .get_json::<serde_json::Value>(&url, None)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, ProvisioningError::Json(m) if m.contains("exceeds")),
            "{err:?}"
        );
    }
}
