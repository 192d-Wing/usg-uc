//! Reverse-proxy fallback to the sbc-daemon for endpoints sbc-api
//! doesn't own.
//!
//! sbc-api owns config entities (phones, DIDs, trunk groups, dial-plan
//! writes), users (PR10), SBC routing CRUD (PR11), SIP-state reads
//! (PR7), and trunk runtime state (PR9). What's left for the proxy is
//! the read-only `/dialplans` views, which still live on
//! the daemon (`/cdrs` moved to the gRPC `CdrService`) — they're cheap to expose locally there and have no
//! Postgres or gRPC equivalent yet. The dashboard hits sbc-api as the
//! single front door, so the catch-all forwards reads it doesn't own.
//!
//! Writes are never forwarded: no in-repo client writes through the
//! catch-all, and a forwarded write would reach the daemon under
//! sbc-api's service identity, not the operator's. POST/PUT/DELETE answer
//! 405 (the router backstop audits the refusal).
//! NIST 800-53 Rev5: AC-3, AU-2, CM-5
//!
//! Body forwarding uses reqwest's streaming-buffered shape (bytes in,
//! bytes out). Headers are mostly stripped — the daemon will set its
//! own Content-Type, Length, etc. We do carry a couple of
//! trace-friendly ones (User-Agent, X-Request-Id) for correlation.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
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
    proxy(state, reqwest::Method::GET, &path, &query, &headers).await
}

/// POST/PUT/DELETE on a path sbc-api does not own: 405, never forwarded.
pub async fn refuse_write() -> Response {
    let mut resp = (
        StatusCode::METHOD_NOT_ALLOWED,
        axum::Json(serde_json::json!({"error": "method not allowed"})),
    )
        .into_response();
    resp.headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static("GET"));
    resp
}

async fn proxy(
    state: Arc<AppState>,
    method: reqwest::Method,
    path: &str,
    query: &HashMap<String, String>,
    headers: &HeaderMap,
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
