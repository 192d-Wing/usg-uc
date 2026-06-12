//! Loopback redirect listener for the OAuth Authorization Code flow
//! (RFC 8252 §7.3).
//!
//! Binds `127.0.0.1` on an ephemeral port, hands the resulting
//! `http://127.0.0.1:<port>/` back as the `redirect_uri`, then waits for the
//! single browser redirect carrying `?code=…&state=…`. It serves one short
//! HTML page and shuts down — it is not a general HTTP server.

use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use url::Url;

use crate::error::ProvisioningError;

/// A bound loopback listener awaiting the OAuth redirect.
pub struct LoopbackServer {
    listener: TcpListener,
    /// The `http://127.0.0.1:<port>/` URI to register as `redirect_uri`.
    pub redirect_uri: String,
}

/// The parameters captured from the browser redirect.
#[derive(Debug)]
pub struct AuthCallback {
    /// The authorization `code` (present on success).
    pub code: Option<String>,
    /// The `state` echoed by the IdP (validated by the caller).
    pub state: Option<String>,
    /// An `error` code, when the IdP redirected with a failure.
    pub error: Option<String>,
}

/// Binds `127.0.0.1:0` and returns the server plus its redirect URI.
///
/// # Errors
/// [`ProvisioningError::Loopback`] if the socket cannot be bound.
pub async fn start_loopback() -> Result<LoopbackServer, ProvisioningError> {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|e| ProvisioningError::Loopback(format!("bind failed: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| ProvisioningError::Loopback(format!("local_addr failed: {e}")))?
        .port();
    Ok(LoopbackServer {
        listener,
        redirect_uri: format!("http://127.0.0.1:{port}/"),
    })
}

impl LoopbackServer {
    /// Waits up to `timeout` for the browser to hit the redirect URI, then
    /// returns the captured query parameters.
    ///
    /// # Errors
    /// [`ProvisioningError::Timeout`] if no redirect arrives in time, or
    /// [`ProvisioningError::Loopback`] on a socket error.
    pub async fn wait_for_code(self, timeout: Duration) -> Result<AuthCallback, ProvisioningError> {
        let accept = async {
            loop {
                let (mut stream, _) = self
                    .listener
                    .accept()
                    .await
                    .map_err(|e| ProvisioningError::Loopback(format!("accept failed: {e}")))?;

                // Read the request line (we only need the first line's path).
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let Some(target) = request
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                else {
                    // Not a well-formed request line; ignore and keep waiting.
                    let _ = stream.write_all(EMPTY_PAGE.as_bytes()).await;
                    continue;
                };

                // Favicon and other stray probes shouldn't end the wait.
                if target.starts_with("/favicon") {
                    let _ = stream.write_all(EMPTY_PAGE.as_bytes()).await;
                    continue;
                }

                let parsed = Url::parse(&format!("http://127.0.0.1{target}")).ok();
                let mut code = None;
                let mut state = None;
                let mut error = None;
                if let Some(u) = parsed {
                    for (k, v) in u.query_pairs() {
                        match k.as_ref() {
                            "code" => code = Some(v.into_owned()),
                            "state" => state = Some(v.into_owned()),
                            "error" => error = Some(v.into_owned()),
                            _ => {}
                        }
                    }
                }

                let page = if error.is_some() {
                    FAILURE_PAGE
                } else {
                    SUCCESS_PAGE
                };
                let _ = stream.write_all(page.as_bytes()).await;
                let _ = stream.flush().await;

                return Ok(AuthCallback { code, state, error });
            }
        };

        match tokio::time::timeout(timeout, accept).await {
            Ok(result) => result,
            Err(_) => Err(ProvisioningError::Timeout(
                "no OAuth redirect received before timeout".to_string(),
            )),
        }
    }
}

const SUCCESS_PAGE: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n<!doctype html><meta charset=utf-8><title>Signed in</title><body style=\"font-family:sans-serif;text-align:center;margin-top:4rem\"><h2>Sign-in complete</h2><p>You may close this window and return to the app.</p></body>";
const FAILURE_PAGE: &str = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n<!doctype html><meta charset=utf-8><title>Sign-in failed</title><body style=\"font-family:sans-serif;text-align:center;margin-top:4rem\"><h2>Sign-in failed</h2><p>You may close this window and return to the app.</p></body>";
const EMPTY_PAGE: &str =
    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n";

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captures_code_and_state() {
        let server = start_loopback().await.unwrap();
        let uri = server.redirect_uri.clone();
        // Drive a fake browser redirect concurrently.
        let client = tokio::spawn(async move {
            let url = format!("{uri}?code=abc123&state=xyz789");
            let _ = reqwest::Client::new().get(&url).send().await;
        });
        let cb = server.wait_for_code(Duration::from_secs(5)).await.unwrap();
        let _ = client.await;
        assert_eq!(cb.code.as_deref(), Some("abc123"));
        assert_eq!(cb.state.as_deref(), Some("xyz789"));
        assert!(cb.error.is_none());
    }

    #[tokio::test]
    async fn times_out_without_redirect() {
        let server = start_loopback().await.unwrap();
        let err = server
            .wait_for_code(Duration::from_millis(150))
            .await
            .unwrap_err();
        assert!(matches!(err, ProvisioningError::Timeout(_)));
    }
}
