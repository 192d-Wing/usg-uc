//! Reverse-proxy fallback to the sbc-daemon for endpoints sbc-api
//! doesn't own.
//!
//! sbc-api owns config entities (phones, DIDs, trunk groups, dial-plan
//! writes), users (PR10), SBC routing CRUD (PR11), SIP-state reads
//! (PR7), and trunk runtime state (PR9). What's left for the proxy is
//! the read-only `/cdrs` and `/dialplans` views, which still live on
//! the daemon — they're cheap to expose locally there and have no
//! Postgres or gRPC equivalent yet. The dashboard hits sbc-api as the
//! single front door, so the catch-all forwards anything it doesn't
//! own.
//!
//! Body forwarding uses reqwest's streaming-buffered shape (bytes in,
//! bytes out). Headers are mostly stripped — the daemon will set its
//! own Content-Type, Length, etc. We do carry a couple of
//! trace-friendly ones (User-Agent, X-Request-Id) for correlation.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use std::collections::HashMap;
use tracing::warn;

use crate::state::AppState;

pub async fn proxy_get(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    proxy(
        state,
        reqwest::Method::GET,
        &path,
        &query,
        &headers,
        Bytes::new(),
    )
    .await
}

pub async fn proxy_post(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    proxy(state, reqwest::Method::POST, &path, &query, &headers, body).await
}

pub async fn proxy_put(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    proxy(state, reqwest::Method::PUT, &path, &query, &headers, body).await
}

pub async fn proxy_delete(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    proxy(
        state,
        reqwest::Method::DELETE,
        &path,
        &query,
        &headers,
        Bytes::new(),
    )
    .await
}

async fn proxy(
    state: Arc<AppState>,
    method: reqwest::Method,
    path: &str,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    // Reject path-traversal attempts: Axum percent-decodes the captured
    // segment, so `%2e%2e` arrives here as `..`.  If we interpolate it
    // into the upstream URL, reqwest's RFC 3986 resolution collapses the
    // dot-segments and escapes the /api/v1/ prefix.
    if path.split('/').any(|seg| seg == "." || seg == "..") {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "invalid path"})),
        )
            .into_response();
    }
    let url = format!("{}/api/v1/{}", state.daemon_http_base, path);
    let mut req = state.http_client.request(method.clone(), &url);
    if !query.is_empty() {
        req = req.query(&query);
    }
    if let Some(ua) = headers.get(axum::http::header::USER_AGENT)
        && let Ok(v) = ua.to_str()
    {
        req = req.header(reqwest::header::USER_AGENT, v);
    }
    if let Some(rid) = headers.get("x-request-id")
        && let Ok(v) = rid.to_str()
    {
        req = req.header("x-request-id", v);
    }
    if let Some(ct) = headers.get(axum::http::header::CONTENT_TYPE)
        && let Ok(v) = ct.to_str()
    {
        req = req.header(reqwest::header::CONTENT_TYPE, v);
    }
    if let Some(ref token) = state.daemon_api_token {
        req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    if !body.is_empty() {
        req = req.body(body);
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let ct = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            match resp.bytes().await {
                Ok(bytes) => {
                    let mut builder = Response::builder().status(status.as_u16());
                    if let Some(ct) = ct {
                        builder = builder.header(axum::http::header::CONTENT_TYPE, ct);
                    }
                    builder
                        .body(axum::body::Body::from(bytes))
                        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
                }
                Err(e) => {
                    warn!(url, error = %e, "proxy body read failed");
                    StatusCode::BAD_GATEWAY.into_response()
                }
            }
        }
        Err(e) => {
            warn!(url, error = %e, "proxy upstream failed");
            (
                StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "error": "upstream daemon unreachable",
                })),
            )
                .into_response()
        }
    }
}
