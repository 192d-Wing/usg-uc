//! Bounded HTTPS fetch of STI certificates.
//!
//! One GET per call over a fresh TLS connection to an SSRF-vetted address:
//! no redirects (hyper's client does not follow them; any non-200 is an
//! error), a body cap, and an overall deadline. Transport TLS is validated
//! against the system web PKI; the STI-CR anchors validate the fetched
//! certificate chain separately (see [`crate::cache`]).
//!
//! ## NIST 800-53 Rev5: SC-7, SC-8 (Transmission Confidentiality), SC-5, SC-13, IA-9

use crate::error::FetchError;
use crate::ssrf::{X5uUrl, is_forbidden_ip};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Minimum seconds between TLS profile warnings from one fetcher.
const TLS_POLICY_WARN_INTERVAL_SECS: u64 = 60;

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
    /// Monotonic base for the warning rate limit.
    started: Instant,
    /// Seconds since `started` (+1) of the last TLS profile warning; 0 = never.
    last_tls_policy_warn: AtomicU64,
    /// TLS profile refusals not logged since the last warning.
    tls_policy_suppressed: AtomicU64,
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
            started: Instant::now(),
            last_tls_policy_warn: AtomicU64::new(0),
            tls_policy_suppressed: AtomicU64::new(0),
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

    /// TLS 1.2/1.3 client config on the CNSA 2.0 provider
    /// (`uc_transport::tls::cnsa_provider`: aws-lc FIPS, AES-256-GCM only,
    /// ML-KEM-1024 or P-384 only), explicitly selected so a process with
    /// several rustls providers compiled in does not fall back to
    /// ambiguity. TLS 1.2 stays enabled because public STI certificate
    /// repositories are not all TLS 1.3; on 1.2 only
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` is offered. On either
    /// version the repository's TLS certificate and its chain must be
    /// ECDSA P-384 / SHA-384 (SR-14). The fetched STI certificate is
    /// validated separately against the STI-CR anchors.
    ///
    /// ## NIST 800-53 Rev5: SC-8, SC-13, IA-9
    ///
    /// # Errors
    /// If the provider rejects the protocol versions.
    // POAM: POA&M-404: the strict profile refuses STI repositories on RSA or
    // P-256 web-PKI chains; ISSO decision pending (strict vs scoped provider).
    pub fn tls_config(roots: rustls::RootCertStore) -> Result<Arc<rustls::ClientConfig>, String> {
        let provider = Arc::new(uc_transport::tls::cnsa_provider());
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

    /// Classifies a TLS connect failure. Refusals by the CNSA profile get
    /// their own bounded label and a rate-limited warning naming the host,
    /// so operators can tell them from network faults.
    ///
    /// NIST 800-53 Rev5: SI-11 (Error Handling), AU-12
    fn tls_error(&self, host: &str, e: &std::io::Error) -> FetchError {
        let (err, cause) = match tls_cause(e) {
            Some(
                rustls::Error::InvalidCertificate(_)
                | rustls::Error::PeerIncompatible(_)
                | rustls::Error::PeerMisbehaved(
                    rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
                ),
            ) => (FetchError::TlsCertPolicy, "certificate or signature"),
            // The server found nothing it could negotiate with the CNSA
            // offer (suite, group or a P-384 signing key); the client cannot
            // tell which.
            Some(rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure)) => (
                FetchError::Transport("tls-peer-refused"),
                "server refused the CNSA offer",
            ),
            _ => return FetchError::Transport("tls"),
        };
        self.warn_tls_policy(host, cause);
        err
    }

    /// At most one warning per [`TLS_POLICY_WARN_INTERVAL_SECS`]; refusals
    /// in between are counted and reported with the next warning.
    fn warn_tls_policy(&self, host: &str, cause: &'static str) {
        let now = self.started.elapsed().as_secs().saturating_add(1);
        let last = self.last_tls_policy_warn.load(Ordering::Relaxed);
        if (last != 0 && now.saturating_sub(last) < TLS_POLICY_WARN_INTERVAL_SECS)
            || self
                .last_tls_policy_warn
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            self.tls_policy_suppressed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let suppressed = self.tls_policy_suppressed.swap(0, Ordering::Relaxed);
        // Host is limited to [a-z0-9.-] or an IP literal by `X5uUrl::parse`.
        tracing::warn!(
            host,
            cause,
            suppressed,
            "x5u TLS refused: repository must use an ECDSA P-384 / SHA-384 certificate chain (SR-14)"
        );
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
            .map_err(|e| self.tls_error(&url.host, &e))?;
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

/// The rustls error behind a `tokio-rustls` connect failure, if any.
fn tls_cause(e: &std::io::Error) -> Option<&rustls::Error> {
    let mut next: Option<&(dyn std::error::Error + 'static)> = e
        .get_ref()
        .map(|inner| inner as &(dyn std::error::Error + 'static));
    while let Some(err) = next {
        if let Some(tls) = err.downcast_ref::<rustls::Error>() {
            return Some(tls);
        }
        next = err.source();
    }
    None
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

    /// The TLS profile warning is logged at most once per interval; the
    /// rest are counted for the next warning.
    #[test]
    fn tls_policy_warning_is_rate_limited() {
        let f = HttpsFetcher::new(tls(), Arc::new(FixedResolver(Vec::new())), 16384);
        for _ in 0..3 {
            f.warn_tls_policy("cert.example.com", "certificate or signature");
        }
        assert_ne!(f.last_tls_policy_warn.load(Ordering::Relaxed), 0);
        assert_eq!(f.tls_policy_suppressed.load(Ordering::Relaxed), 2);
    }

    /// A non-rustls I/O error is a plain transport failure, not logged.
    #[test]
    fn non_tls_connect_error_is_transport() {
        let f = HttpsFetcher::new(tls(), Arc::new(FixedResolver(Vec::new())), 16384);
        let e = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        assert_eq!(
            f.tls_error("cert.example.com", &e),
            FetchError::Transport("tls")
        );
        assert_eq!(f.last_tls_policy_warn.load(Ordering::Relaxed), 0);
        let e = std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        );
        assert_eq!(
            f.tls_error("cert.example.com", &e),
            FetchError::TlsCertPolicy
        );
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
