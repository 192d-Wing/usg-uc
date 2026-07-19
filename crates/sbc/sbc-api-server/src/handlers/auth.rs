//! Authentication endpoints: admin login, logout, and session check.
//!
//! Tokens are stateless (signed by [`uc_auth`]), so "logout" only clears
//! the browser cookie — there is no server-side session to destroy. The
//! `/auth/login` and `/auth/session` routes are exempt from the
//! deny-by-default middleware; everything else under `/api/v1` requires a
//! valid bearer token or API key.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use tracing::warn;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

/// `POST /api/v1/auth/login` — verify admin credentials, mint a token.
///
/// Returns the token in the body (for `Authorization: Bearer` clients) and
/// as an `HttpOnly; Secure; SameSite=Strict` cookie (for the dashboard).
pub async fn login(State(state): State<Arc<AppState>>, Json(body): Json<LoginRequest>) -> Response {
    // argon2 verification is deliberately slow; keep it off the async
    // executor threads.
    let auth = Arc::clone(&state.auth);
    let username = body.username.clone();
    let password = body.password;
    let token = tokio::task::spawn_blocking(move || auth.login(&username, &password))
        .await
        .ok()
        .flatten();

    let Some(token) = token else {
        warn!(user = %body.username, "failed admin login");
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid credentials" })),
        )
            .into_response();
    };

    let max_age = state.auth.token_ttl_secs();
    // Secure: TLS terminates at the ingress, so the browser connection is
    // HTTPS even though this pod speaks HTTP behind it.
    let cookie = format!(
        "sbc_session={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}"
    );
    let mut resp = Json(serde_json::json!({
        "token": token,
        "expires_in_secs": max_age,
    }))
    .into_response();
    if let Ok(v) = cookie.parse() {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// `POST /api/v1/auth/logout` — clear the session cookie (stateless tokens
/// can't be server-revoked; this just unsets the browser cookie).
pub async fn logout() -> Response {
    let mut resp = Json(serde_json::json!({ "success": true })).into_response();
    if let Ok(v) = "sbc_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0".parse() {
        resp.headers_mut().insert(header::SET_COOKIE, v);
    }
    resp
}

/// `GET /api/v1/auth/session` — report whether the presented credential is
/// valid (the dashboard uses this to decide whether to show login).
pub async fn session(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Legacy cookie / HMAC / API key.
    let legacy_ok = uc_auth::extract_credential(&headers).is_some_and(|c| state.auth.authorize(&c));

    // OIDC bearer token (operator SSO via Keycloak).
    let oidc_ok = if !legacy_ok {
        if let Some(validator) = &state.oidc {
            let token = headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|t| t.trim().to_string());
            match token {
                Some(t) => validator.validate(&t).await.is_ok(),
                None => false,
            }
        } else {
            false
        }
    } else {
        false
    };

    if legacy_ok || oidc_ok {
        Json(serde_json::json!({ "authenticated": true })).into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "authenticated": false })),
        )
            .into_response()
    }
}
