//! Bounded HTTPS fetch of STI certificates.
//!
//! One GET per call over a fresh TLS connection to an SSRF-vetted address:
//! no redirects (hyper's client does not follow them; any non-200 is an
//! error), a body cap, and an overall deadline. Transport TLS is validated
//! against the system web PKI; the STI-CR anchors validate the fetched
//! certificate chain separately (see [`crate::cache`]).
//!
//! ## NIST 800-53 Rev5: SC-7, SC-8 (Transmission Confidentiality), SC-5

use crate::error::FetchError;
use crate::ssrf::{X5uUrl, is_forbidden_ip};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

/// A fetched certificate document.
#[derive(Debug, Clone)]
pub struct Fetched {
    /// Response body (PEM chain).
    pub body: Bytes,
    /// `Cache-Control: max-age`, if present.
    pub max_age_secs: Option<u64>,
}

/// Source of certificate documents (real HTTPS, or a test double).
pub trait CertSource: Send + Sync + 'static {
    /// Fetches `url` within `timeout`.
    fn fetch<'a>(
        &'a self,
        url: &'a X5uUrl,
        timeout: Duration,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Fetched, FetchError>> + Send + 'a>>;
}

/// Resolves a host name to addresses (injectable for tests).
pub trait Resolve: Send + Sync + 'static {
    /// Resolves `host:port`.
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>>;
}

/// System resolver (`tokio::net::lookup_host`).
#[derive(Debug, Default)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) })
    }
}

/// HTTPS certificate fetcher.
pub struct HttpsFetcher {
    tls: tokio_rustls::TlsConnector,
    resolver: Arc<dyn Resolve>,
    max_bytes: usize,
    /// Test hook: permit loopback targets (local test server).
    #[cfg(test)]
    pub(crate) allow_loopback: bool,
}

impl std::fmt::Debug for HttpsFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsFetcher")
            .field("max_bytes", &self.max_bytes)
            .finish_non_exhaustive()
    }
}

impl HttpsFetcher {
    /// Creates a fetcher with the given TLS client config.
    #[must_use]
    pub fn new(
        tls: Arc<rustls::ClientConfig>,
        resolver: Arc<dyn Resolve>,
        max_bytes: usize,
    ) -> Self {
        Self {
            tls: tokio_rustls::TlsConnector::from(tls),
            resolver,
            max_bytes,
            #[cfg(test)]
            allow_loopback: false,
        }
    }

    /// TLS client config trusting the platform web PKI roots.
    ///
    /// # Errors
    /// If no usable root certificate is found.
    pub fn system_tls_config() -> Result<Arc<rustls::ClientConfig>, String> {
        let mut roots = rustls::RootCertStore::empty();
        let loaded = rustls_native_certs::load_native_certs();
        for cert in loaded.certs {
            let _ = roots.add(cert);
        }
        if roots.is_empty() {
            return Err("no system root certificates for x5u TLS".into());
        }
        Self::tls_config(roots)
    }

    /// TLS 1.2/1.3 client config on the aws-lc (FIPS) provider, explicitly
    /// selected so a process with several rustls providers compiled in does
    /// not fall back to ambiguity. TLS 1.2 stays enabled because public STI
    /// certificate repositories are not all TLS 1.3; the cert chain itself is
    /// validated against the STI-CR anchors regardless.
    ///
    /// # Errors
    /// If the provider rejects the protocol versions.
    pub fn tls_config(roots: rustls::RootCertStore) -> Result<Arc<rustls::ClientConfig>, String> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        Ok(Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|e| format!("x5u TLS config: {e}"))?
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ))
    }

    fn vet(&self, ip: IpAddr) -> bool {
        #[cfg(test)]
        if self.allow_loopback && ip.is_loopback() {
            return true;
        }
        let _ = self;
        !is_forbidden_ip(ip)
    }

    async fn fetch_inner(&self, url: &X5uUrl) -> Result<Fetched, FetchError> {
        let addrs = self
            .resolver
            .resolve(&url.host, url.port)
            .await
            .map_err(|_| FetchError::Transport("dns"))?;
        // Refuse the whole answer if any address is internal: a mixed answer
        // is a rebinding/SSRF signal, not a fallback opportunity.
        if addrs.is_empty() {
            return Err(FetchError::Transport("dns-empty"));
        }
        if addrs.iter().any(|a| !self.vet(a.ip())) {
            return Err(FetchError::Policy("address"));
        }
        let addr = *addrs.first().ok_or(FetchError::Transport("dns-empty"))?;
        let tcp = tokio::net::TcpStream::connect(addr)
            .await
            .map_err(|_| FetchError::Transport("connect"))?;
        let _ = tcp.set_nodelay(true);
        let server_name = match url.host.parse::<IpAddr>() {
            Ok(ip) => ServerName::IpAddress(ip.into()),
            Err(_) => {
                ServerName::try_from(url.host.clone()).map_err(|_| FetchError::Policy("host"))?
            }
        };
        let tls = self
            .tls
            .connect(server_name, tcp)
            .await
            .map_err(|_| FetchError::Transport("tls"))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| FetchError::Transport("http-handshake"))?;
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let host_header = if url.port == 443 {
            url.host.clone()
        } else {
            format!("{}:{}", url.host, url.port)
        };
        let req = http::Request::get(url.path.as_str())
            .header(http::header::HOST, host_header)
            .header(http::header::ACCEPT, "application/pem-certificate-chain")
            .header(http::header::USER_AGENT, "usg-sbc-sti/1")
            .header(http::header::CONNECTION, "close")
            .body(Empty::<Bytes>::new())
            .map_err(|_| FetchError::Policy("request"))?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|_| FetchError::Transport("http"));
        let result = async {
            let resp = resp?;
            let status = resp.status().as_u16();
            if status != 200 {
                return Err(FetchError::Status(status));
            }
            if let Some(len) = resp
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
                && len > self.max_bytes
            {
                return Err(FetchError::TooLarge);
            }
            let max_age_secs = resp
                .headers()
                .get(http::header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok())
                .and_then(parse_max_age);
            let body = Limited::new(resp.into_body(), self.max_bytes)
                .collect()
                .await
                .map_err(|e| {
                    if e.downcast_ref::<http_body_util::LengthLimitError>()
                        .is_some()
                    {
                        FetchError::TooLarge
                    } else {
                        FetchError::Transport("body")
                    }
                })?
                .to_bytes();
            Ok(Fetched { body, max_age_secs })
        }
        .await;
        driver.abort();
        result
    }
}

impl CertSource for HttpsFetcher {
    fn fetch<'a>(
        &'a self,
        url: &'a X5uUrl,
        timeout: Duration,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Fetched, FetchError>> + Send + 'a>> {
        Box::pin(async move {
            tokio::time::timeout(timeout, self.fetch_inner(url))
                .await
                .map_err(|_| FetchError::Timeout)?
        })
    }
}

/// Parses `max-age=N` from a Cache-Control value. `no-store`/`no-cache`
/// yield `Some(0)`.
fn parse_max_age(v: &str) -> Option<u64> {
    let mut out = None;
    for d in v.split(',') {
        let d = d.trim();
        if d.eq_ignore_ascii_case("no-store") || d.eq_ignore_ascii_case("no-cache") {
            return Some(0);
        }
        if let Some((k, val)) = d.split_once('=')
            && k.trim().eq_ignore_ascii_case("max-age")
        {
            out = val.trim().trim_matches('"').parse().ok();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_control() {
        assert_eq!(parse_max_age("public, max-age=600"), Some(600));
        assert_eq!(parse_max_age("no-store"), Some(0));
        assert_eq!(parse_max_age("private"), None);
        assert_eq!(parse_max_age("max-age=abc"), None);
    }

    struct FixedResolver(Vec<SocketAddr>);
    impl Resolve for FixedResolver {
        fn resolve<'a>(
            &'a self,
            _h: &'a str,
            _p: u16,
        ) -> std::pin::Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'a>>
        {
            let v = self.0.clone();
            Box::pin(async move { Ok(v) })
        }
    }

    fn tls() -> Arc<rustls::ClientConfig> {
        Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
        )
    }

    /// DNS rebinding: a public-looking host that resolves to an internal
    /// address (or a mixed answer) is refused before any connect.
    #[tokio::test]
    async fn rebinding_resolver_is_refused() {
        for answer in [
            vec!["127.0.0.1:443".parse().unwrap()],
            vec![
                "8.8.8.8:443".parse().unwrap(),
                "10.0.0.1:443".parse().unwrap(),
            ],
            vec!["[::ffff:169.254.169.254]:443".parse().unwrap()],
        ] {
            let f = HttpsFetcher::new(tls(), Arc::new(FixedResolver(answer)), 16384);
            let url = X5uUrl::parse("https://cert.example.com/a.pem", &[]).unwrap();
            assert_eq!(
                f.fetch(&url, Duration::from_secs(1)).await.unwrap_err(),
                FetchError::Policy("address")
            );
        }
    }
}
