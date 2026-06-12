//! Soft-client OIDC sign-in + auto-discovery.
//!
//! Implements the client half of docs/CLIENT-PROVISIONING-OIDC.md: from a
//! single service domain, fetch the discovery document, verify the issuer is
//! trusted, run OAuth2 Authorization Code + PKCE (RFC 8252) in the system
//! browser via a loopback redirect, exchange/refresh tokens, fetch the
//! per-user SIP config, and map it onto a [`client_types::SipAccount`].
//!
//! This crate is platform-agnostic: it does NOT open the browser itself (the
//! Tauri/Android shell does, with the URL from [`ProvisioningClient::build_authorization_url`]).
//! All secrets are held in [`zeroize::Zeroizing`].

// Docs are RFC/acronym-heavy (OAuth2, OIDC, PKCE, IdP, JWT, AOR); backticking
// every term hurts readability more than it helps. Matches proto-registrar.
#![allow(clippy::doc_markdown)]

pub mod discovery;
mod error;
pub mod http;
pub mod loopback;
pub mod mapping;
pub mod pkce;
pub mod session;
pub mod wire;

pub use discovery::verify_issuer_pinned;
pub use error::ProvisioningError;
pub use http::{CaTrust, build_http_client};
pub use loopback::{AuthCallback, LoopbackServer, start_loopback};
pub use pkce::{PkcePair, generate_pkce, random_token};
pub use session::{PersistedProvisioning, ProvisionedSession, SessionState};
pub use wire::{ClientConfig, DiscoveryDoc, OidcMetadata, TokenResponse};

use wire::DiscoveryOidc;

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

    /// Fetches `https://{service_domain}/.well-known/sip-client-config`.
    ///
    /// # Errors
    /// [`ProvisioningError::Discovery`] on a transport or non-2xx error, or
    /// [`ProvisioningError::Json`] if the body doesn't match the schema.
    pub async fn fetch_discovery(
        &self,
        service_domain: &str,
    ) -> Result<DiscoveryDoc, ProvisioningError> {
        let host = service_domain
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        let url = format!("https://{host}/.well-known/sip-client-config");
        self.get_json(&url, None)
            .await
            .map_err(ProvisioningError::into_discovery)
    }

    /// Fetches `{issuer}/.well-known/openid-configuration`.
    ///
    /// # Errors
    /// [`ProvisioningError::Discovery`]/[`ProvisioningError::Json`] as above;
    /// also errors when the metadata's `issuer` doesn't round-trip.
    pub async fn fetch_oidc_metadata(
        &self,
        issuer: &str,
    ) -> Result<OidcMetadata, ProvisioningError> {
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
    /// # Errors
    /// [`ProvisioningError::Unauthorized`] on a 401 (token expired/invalid →
    /// refresh and retry once); [`ProvisioningError::Config`] otherwise.
    pub async fn fetch_client_config(
        &self,
        config_endpoint: &str,
        access_token: &str,
    ) -> Result<ClientConfig, ProvisioningError> {
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
        let resp = resp
            .error_for_status()
            .map_err(|e| ProvisioningError::Config(e.to_string()))?;
        resp.json()
            .await
            .map_err(|e| ProvisioningError::Json(e.to_string()))
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
            .map_err(|e| ProvisioningError::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| ProvisioningError::Http(e.to_string()))?;
        resp.json()
            .await
            .map_err(|e| ProvisioningError::Json(e.to_string()))
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
            let body = resp.text().await.unwrap_or_default();
            return Err(ProvisioningError::TokenExchange(format!(
                "token endpoint returned {status}: {body}"
            )));
        }
        resp.json()
            .await
            .map_err(|e| ProvisioningError::Json(e.to_string()))
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
    fn id_token_nonce_extracts_claim() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let payload = URL_SAFE_NO_PAD.encode(r#"{"sub":"x","nonce":"NONCE-42"}"#);
        let token = format!("eyJhbGciOiJFUzI1NiJ9.{payload}.sig");
        assert_eq!(id_token_nonce(&token).as_deref(), Some("NONCE-42"));
        assert!(id_token_nonce("not-a-jwt").is_none());
    }
}
