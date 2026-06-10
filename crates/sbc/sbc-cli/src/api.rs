//! HTTP client for the SBC daemon REST API.
//!
//! All commands that report daemon state go through this client; the CLI
//! never fabricates results. The daemon serves HTTPS with a self-signed
//! bootstrap certificate by default, so the client supports a custom CA
//! (`--ca-cert`) and, as a last resort, disabled verification
//! (`--insecure`, with a stderr warning).

use crate::args::Args;
use std::time::Duration;
use ureq::Agent;
use ureq::tls::{Certificate, RootCerts, TlsConfig};

/// Error returned by API operations.
#[derive(Debug)]
pub struct ApiError {
    /// Human-readable description of the failure.
    pub message: String,
}

impl ApiError {
    /// Creates a new API error.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ApiError {}

/// A response from the daemon API.
#[derive(Debug)]
pub struct ApiResponse {
    /// HTTP status code.
    pub status: u16,
    /// Raw response body.
    pub body: String,
}

impl ApiResponse {
    /// Whether the HTTP status indicates success.
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Parses the body as JSON.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the body is not valid JSON.
    pub fn json(&self) -> Result<serde_json::Value, ApiError> {
        serde_json::from_str(&self.body)
            .map_err(|e| ApiError::new(format!("daemon returned a non-JSON response: {e}")))
    }
}

/// Synchronous client for the daemon REST API.
pub struct ApiClient {
    agent: Agent,
    base_url: String,
    token: Option<String>,
}

impl ApiClient {
    /// Builds a client from parsed CLI arguments.
    ///
    /// The bearer token comes from `--token`, falling back to the
    /// `SBC_API_TOKEN` environment variable.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] when the CA certificate cannot be read or
    /// parsed.
    pub fn from_args(args: &Args) -> Result<Self, ApiError> {
        let tls = build_tls_config(args)?;
        let agent = Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(10)))
            .tls_config(tls)
            .build()
            .new_agent();

        let token = args
            .token
            .clone()
            .or_else(|| std::env::var("SBC_API_TOKEN").ok());

        Ok(Self {
            agent,
            base_url: args.api_url.trim_end_matches('/').to_string(),
            token,
        })
    }

    /// Returns the absolute URL for an API path (e.g. `/api/v1/calls`).
    pub fn endpoint_url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    /// Performs a GET request and requires a success status.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] on connection failure, on `401 Unauthorized`
    /// (with a login hint), or on any other non-success HTTP status.
    pub fn get(&self, path: &str) -> Result<ApiResponse, ApiError> {
        let resp = self.get_any_status(path)?;
        if resp.is_success() {
            Ok(resp)
        } else {
            Err(self.status_error(path, &resp))
        }
    }

    /// Performs a GET request, returning the response for any HTTP status.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] only on connection-level failures.
    pub fn get_any_status(&self, path: &str) -> Result<ApiResponse, ApiError> {
        let url = self.endpoint_url(path);
        let mut request = self.agent.get(&url);
        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let response = request.call().map_err(|e| connection_error(&url, &e))?;
        read_response(response)
    }

    /// Performs a POST request, returning the response for any HTTP status.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] only on connection-level failures.
    pub fn post_json_any_status(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<ApiResponse, ApiError> {
        let url = self.endpoint_url(path);
        let payload = body.to_string();
        let mut request = self
            .agent
            .post(&url)
            .header("Content-Type", "application/json");
        if let Some(token) = &self.token {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let response = request
            .send(payload.as_bytes())
            .map_err(|e| connection_error(&url, &e))?;
        read_response(response)
    }

    /// Builds an actionable error for a non-success HTTP response.
    pub fn status_error(&self, path: &str, resp: &ApiResponse) -> ApiError {
        let url = self.endpoint_url(path);
        if resp.status == 401 {
            let hint = if self.token.is_some() {
                "the provided token was rejected; run 'sbc-cli login' to obtain a fresh token \
                 and set SBC_API_TOKEN"
            } else {
                "no API token provided; run 'sbc-cli login' and set SBC_API_TOKEN (or pass --token)"
            };
            return ApiError::new(format!("authentication required by {url}: {hint}"));
        }
        ApiError::new(format!(
            "daemon returned HTTP {} for {url}: {}",
            resp.status,
            summarize_body(&resp.body)
        ))
    }
}

/// Builds the TLS configuration from CLI arguments.
fn build_tls_config(args: &Args) -> Result<TlsConfig, ApiError> {
    let mut builder = TlsConfig::builder();

    if args.insecure {
        eprintln!(
            "warning: --insecure given; TLS certificate verification is DISABLED for {}",
            args.api_url
        );
        builder = builder.disable_verification(true);
    } else if let Some(ca_path) = &args.ca_cert {
        let pem = std::fs::read(ca_path)
            .map_err(|e| ApiError::new(format!("failed to read CA cert {ca_path}: {e}")))?;
        let cert = Certificate::from_pem(&pem)
            .map_err(|e| ApiError::new(format!("failed to parse CA cert {ca_path}: {e}")))?;
        builder = builder.root_certs(RootCerts::new_with_certs(&[cert]));
    }

    Ok(builder.build())
}

/// Reads the response body, preserving the HTTP status.
fn read_response(mut response: ureq::http::Response<ureq::Body>) -> Result<ApiResponse, ApiError> {
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .read_to_string()
        .map_err(|e| ApiError::new(format!("failed to read response body: {e}")))?;
    Ok(ApiResponse { status, body })
}

/// Builds a connection-failure error with a hint about the daemon.
fn connection_error(url: &str, err: &ureq::Error) -> ApiError {
    ApiError::new(format!(
        "failed to reach the SBC daemon at {url}: {err} \
         (is sbc-daemon running? use --api-url, and --ca-cert or --insecure for self-signed certs)"
    ))
}

/// Trims a response body for inclusion in an error message.
fn summarize_body(body: &str) -> &str {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        "<empty body>"
    } else if let Some((idx, _)) = trimmed.char_indices().nth(200) {
        &trimmed[..idx]
    } else {
        trimmed
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::args::Args;

    #[test]
    fn test_response_success_predicate() {
        let ok = ApiResponse {
            status: 200,
            body: String::new(),
        };
        assert!(ok.is_success());
        let unauthorized = ApiResponse {
            status: 401,
            body: String::new(),
        };
        assert!(!unauthorized.is_success());
    }

    #[test]
    fn test_response_json_parsing() {
        let resp = ApiResponse {
            status: 200,
            body: r#"{"calls_active": 3}"#.to_string(),
        };
        let value = resp.json().unwrap();
        assert_eq!(value["calls_active"], 3);

        let bad = ApiResponse {
            status: 200,
            body: "<html>".to_string(),
        };
        assert!(bad.json().is_err());
    }

    #[test]
    fn test_unauthorized_maps_to_login_hint() {
        // Pass an explicit token so the result does not depend on whether
        // SBC_API_TOKEN happens to be set in the test environment.
        let args = Args {
            token: Some("expired".to_string()),
            ..Default::default()
        };
        let client = ApiClient::from_args(&args).unwrap();
        let resp = ApiResponse {
            status: 401,
            body: String::new(),
        };
        let err = client.status_error("/api/v1/calls", &resp);
        assert!(err.message.contains("authentication required"));
        assert!(err.message.contains("sbc-cli login"));
        assert!(err.message.contains("SBC_API_TOKEN"));
    }

    #[test]
    fn test_http_error_includes_status_and_body() {
        let client = ApiClient::from_args(&Args::default()).unwrap();
        let resp = ApiResponse {
            status: 500,
            body: "boom".to_string(),
        };
        let err = client.status_error("/api/v1/calls", &resp);
        assert!(err.message.contains("HTTP 500"));
        assert!(err.message.contains("boom"));
        assert!(err.message.contains("https://localhost:8443/api/v1/calls"));
    }

    #[test]
    fn test_base_url_trailing_slash_trimmed() {
        let args = Args {
            api_url: "https://sbc:8443/".to_string(),
            ..Default::default()
        };
        let client = ApiClient::from_args(&args).unwrap();
        assert_eq!(
            client.endpoint_url("/api/v1/calls"),
            "https://sbc:8443/api/v1/calls"
        );
    }

    #[test]
    fn test_bad_ca_cert_path_is_error() {
        let args = Args {
            ca_cert: Some("/nonexistent/ca.pem".to_string()),
            ..Default::default()
        };
        assert!(ApiClient::from_args(&args).is_err());
    }

    #[test]
    fn test_summarize_body() {
        assert_eq!(summarize_body("  "), "<empty body>");
        assert_eq!(summarize_body("short"), "short");
        let long = "x".repeat(500);
        assert_eq!(summarize_body(&long).len(), 200);
    }
}
