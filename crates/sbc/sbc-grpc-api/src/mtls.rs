//! mTLS for the SBC's internal gRPC channels (feature `mtls`).
//!
//! **Listener side.** A service without per-RPC authorization is reachable
//! either on loopback only, or off loopback with mutual TLS: the client
//! certificate must chain to the configured client CA and carry a SAN DNS
//! name or SAN URI from the configured allow-list on every RPC. There is no
//! plaintext opt-in off loopback. Each binary passes its own variable names
//! ([`MtlsEnvNames`]) so error messages name the variables the operator set.
//!
//! **Client side.** [`ClientTls`] holds the CA, client certificate and key;
//! [`check_client_url`] requires `https://` with TLS and loopback without;
//! [`client_endpoint`] / [`client_channel`] build the tonic endpoint or a
//! lazy channel, reading the PEM files on every call so rotated files are
//! picked up. [`client_channel`] connects through [`PreTlsConnector`], so a
//! caller can tell a DNS / TCP failure from a TLS or certificate failure
//! ([`is_pre_tls_failure`]).
//!
//! **Crypto.** tonic's server TLS uses the process-default rustls provider.
//! A binary that installs [`cnsa_provider`] as the default serves TLS 1.3
//! with `TLS_AES_256_GCM_SHA384` and ML-KEM-1024 / P-384 only.
//!
//! The client certificate is peer-supplied DER: it is parsed by `webpki` and
//! a malformed one is refused, never a panic.
//!
//! ## NIST 800-53 Rev5: IA-3, SC-8, AC-3, SC-7, SC-13
// POAM: POA&M-16 (SC-13) clients built here, and listeners of binaries that
// do not install `cnsa_provider`, use the process-default rustls provider
// (aws-lc default suites), not the CNSA 2.0 profile.

use std::future::Future;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use rustls_pki_types::CertificateDer;
use tokio::net::TcpStream;
use tonic::codegen::http::Uri;
use tonic::service::Interceptor;
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, ServerTlsConfig,
};
use tonic::{Request, Status};
use tracing::warn;

/// Longest TLS handshake a listener waits for (slow-handshake bound).
///
/// ## NIST 800-53 Rev5: SC-5
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Most resolved addresses [`PreTlsConnector`] tries.
const MAX_CONNECT_ADDRS: usize = 8;

/// The CNSA 2.0 rustls provider for these channels.
///
/// TLS 1.3 `TLS_AES_256_GCM_SHA384` only, ML-KEM-1024 and P-384 key
/// exchange (the TLS 1.3 subset of `uc_transport::tls::cnsa_provider`), and
/// ECDSA P-384 / SHA-384 peer signatures only. With no TLS 1.2
/// suite, a TLS 1.2 peer cannot negotiate. Install it as the process
/// default before any TLS config is built.
///
/// ## NIST 800-53 Rev5: SC-13, SC-8
/// CNSA 2.0: AES-256, SHA-384, ML-KEM-1024, ECDH P-384, ECDSA P-384
/// signatures (docs/CNSA-2-COMPLIANCE.md)
#[must_use]
pub fn cnsa_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs::{cipher_suite, kx_group};
    rustls::crypto::CryptoProvider {
        cipher_suites: vec![cipher_suite::TLS13_AES_256_GCM_SHA384],
        kx_groups: vec![kx_group::MLKEM1024, kx_group::SECP384R1],
        signature_verification_algorithms: CNSA_SIGNATURE_ALGORITHMS,
        ..rustls::crypto::aws_lc_rs::default_provider()
    }
}

/// Peer signatures a [`cnsa_provider`] endpoint verifies: ECDSA P-384 with
/// SHA-384 only, both on certificate chains and on the TLS 1.3
/// `CertificateVerify`. The chart's certificates (cert-manager ECDSA 384, the
/// DEPLOYING.md `openssl ec_paramgen_curve:P-384` examples, a P-384 CA) need
/// nothing else, so no RSA-PSS entry is included.
///
/// ## NIST 800-53 Rev5: SC-13, IA-3
static CNSA_SIGNATURE_ALGORITHMS: rustls::crypto::WebPkiSupportedAlgorithms =
    rustls::crypto::WebPkiSupportedAlgorithms {
        all: &[webpki::aws_lc_rs::ECDSA_P384_SHA384],
        mapping: &[(
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            &[webpki::aws_lc_rs::ECDSA_P384_SHA384],
        )],
    };

/// Most entries accepted in a client-name allow-list.
pub const MAX_ALLOWED_CLIENT_NAMES: usize = 64;

/// Longest allow-list entry (DNS name limit).
pub const MAX_CLIENT_NAME_LEN: usize = 253;

/// Most names taken from one client certificate.
const MAX_CERT_NAMES: usize = 32;

/// The environment variable names one listener is configured through, used
/// in error messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtlsEnvNames {
    /// Listen address variable (e.g. `SBC_MEDIA_GRPC_LISTEN`).
    pub listen: &'static str,
    /// Prefix of the `<prefix>_{CERT,KEY,CLIENT_CA}_FILE` variables.
    pub tls_prefix: &'static str,
    /// Client-name allow-list variable.
    pub allowed: &'static str,
}

impl MtlsEnvNames {
    fn tls_vars(&self) -> String {
        format!("{}_{{CERT,KEY,CLIENT_CA}}_FILE", self.tls_prefix)
    }
}

/// Server mTLS material (PEM file paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerTls {
    /// Server certificate chain.
    pub cert: PathBuf,
    /// Server private key.
    pub key: PathBuf,
    /// CA that client certificates must chain to.
    pub client_ca: PathBuf,
}

/// An empty or whitespace-only value counts as unset.
fn set(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

/// `<prefix>_{CERT,KEY,CLIENT_CA}_FILE`: all three or none; an empty value
/// counts as unset.
///
/// # Errors
/// A message naming the variables when only some are set.
pub fn server_tls_from(
    names: &MtlsEnvNames,
    cert: Option<String>,
    key: Option<String>,
    client_ca: Option<String>,
) -> Result<Option<ServerTls>, String> {
    match (set(cert), set(key), set(client_ca)) {
        (None, None, None) => Ok(None),
        (Some(cert), Some(key), Some(client_ca)) => Ok(Some(ServerTls {
            cert: cert.into(),
            key: key.into(),
            client_ca: client_ca.into(),
        })),
        _ => Err(format!("{}: set all three or none", names.tls_vars())),
    }
}

/// The client-name allow-list: comma-separated SAN DNS names or URIs; each
/// 1..=253 printable ASCII characters, at most 64 entries.
///
/// # Errors
/// A message naming the variable and the offending entry.
pub fn parse_allowed_client_names(
    names: &MtlsEnvNames,
    raw: Option<&str>,
) -> Result<Vec<String>, String> {
    let list: Vec<String> = raw
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if list.len() > MAX_ALLOWED_CLIENT_NAMES {
        return Err(format!(
            "{} has more than {MAX_ALLOWED_CLIENT_NAMES} entries",
            names.allowed
        ));
    }
    for n in &list {
        let printable = n.bytes().all(|b| (0x21..=0x7e).contains(&b));
        if n.len() > MAX_CLIENT_NAME_LEN || !printable {
            return Err(format!(
                "{} entry {n:?} must be 1..={MAX_CLIENT_NAME_LEN} printable ASCII characters",
                names.allowed
            ));
        }
    }
    Ok(list)
}

/// The listener rule: off loopback only with mTLS and a non-empty client
/// allow-list; an allow-list without mTLS is refused rather than ignored.
///
/// # Errors
/// A message naming the listen variable and what is missing.
pub fn check_listener(
    names: &MtlsEnvNames,
    addr: SocketAddr,
    tls: Option<&ServerTls>,
    allowed: &[String],
) -> Result<(), String> {
    if tls.is_none() && !allowed.is_empty() {
        return Err(format!(
            "{} is only enforced with {}",
            names.allowed,
            names.tls_vars()
        ));
    }
    if addr.ip().is_loopback() {
        return Ok(());
    }
    if tls.is_none() {
        return Err(format!(
            "{} {addr} must be a loopback address unless {} are set (mTLS)",
            names.listen,
            names.tls_vars()
        ));
    }
    if allowed.is_empty() {
        return Err(format!(
            "{} {addr} is not a loopback address: {} must list the permitted client names",
            names.listen, names.allowed
        ));
    }
    Ok(())
}

/// Builds the tonic server TLS config for an mTLS listener.
///
/// Server identity plus a required client certificate chaining to the
/// client CA, and a [`TLS_HANDSHAKE_TIMEOUT`] per handshake. Called once at startup: the
/// files are read then, so a renewed certificate needs a restart (see
/// [`wait_for_tls_change`]).
///
/// # Errors
/// The unreadable file.
pub fn load_server_tls(tls: &ServerTls) -> Result<ServerTlsConfig, String> {
    load_server_tls_fingerprinted(tls).map(|(cfg, _)| cfg)
}

/// [`load_server_tls`], plus the fingerprint of the exact bytes it loaded,
/// for [`wait_for_tls_change`]: a renewal between loading and watching is
/// still seen as a change.
///
/// # Errors
/// The unreadable file.
pub fn load_server_tls_fingerprinted(
    tls: &ServerTls,
) -> Result<(ServerTlsConfig, TlsFingerprint), String> {
    let read =
        |p: &PathBuf| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
    let (cert, key, ca) = (read(&tls.cert)?, read(&tls.key)?, read(&tls.client_ca)?);
    let fingerprint = TlsFingerprint([
        Some(fingerprint_bytes(cert.as_bytes())),
        Some(fingerprint_bytes(key.as_bytes())),
        Some(fingerprint_bytes(ca.as_bytes())),
    ]);
    let cfg = ServerTlsConfig::new()
        .identity(Identity::from_pem(cert, key))
        .client_ca_root(Certificate::from_pem(ca))
        .timeout(TLS_HANDSHAKE_TIMEOUT);
    Ok((cfg, fingerprint))
}

/// Content fingerprints of a listener's certificate, key and client CA, in
/// that order (change detection only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsFingerprint([Option<u64>; 3]);

impl TlsFingerprint {
    /// Fingerprints the files as they are now (`None` for an unreadable one).
    pub async fn read(tls: &ServerTls) -> Self {
        let mut out = [None; 3];
        for (slot, p) in out.iter_mut().zip([&tls.cert, &tls.key, &tls.client_ca]) {
            *slot = file_fingerprint(p).await;
        }
        Self(out)
    }
}

/// Fingerprint of some bytes for change detection only (not a security
/// check; std `DefaultHasher`).
fn fingerprint_bytes(bytes: &[u8]) -> u64 {
    let mut h = std::hash::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

/// [`fingerprint_bytes`] of one file, `None` when unreadable.
async fn file_fingerprint(p: &Path) -> Option<u64> {
    Some(fingerprint_bytes(&tokio::fs::read(p).await.ok()?))
}

/// Resolves once the certificate, key or client CA file content differs
/// from `loaded`.
///
/// `loaded` is what the listener loaded ([`load_server_tls_fingerprinted`]);
/// the files are checked every `every`. A listener that read its files once
/// at start (tonic cannot reload them) exits on this so the orchestrator
/// restarts it with the renewed certificate. A file that is momentarily
/// unreadable (Secret volume update in progress) is not a change; the next
/// check decides.
///
/// ## NIST 800-53 Rev5: IA-3, SC-12
pub async fn wait_for_tls_change(tls: &ServerTls, loaded: TlsFingerprint, every: Duration) {
    let paths = [&tls.cert, &tls.key, &tls.client_ca];
    let initial = loaded.0;
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tick.tick().await;
        for (before, p) in initial.iter().zip(paths) {
            if let Some(now) = file_fingerprint(p).await
                && Some(now) != *before
            {
                return;
            }
        }
    }
}

/// One name from a client certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertName {
    /// SAN DNS name.
    Dns(String),
    /// SAN URI.
    Uri(String),
}

impl CertName {
    fn as_str(&self) -> &str {
        match self {
            Self::Dns(s) | Self::Uri(s) => s,
        }
    }

    /// DNS names compare ASCII case-insensitively (RFC 5280 §4.2.1.6), URIs
    /// exactly.
    #[must_use]
    pub fn matches(&self, allowed: &str) -> bool {
        match self {
            Self::Dns(s) => s.eq_ignore_ascii_case(allowed),
            Self::Uri(s) => s == allowed,
        }
    }
}

/// SAN DNS names and URIs of a client leaf certificate, or `None` if it
/// does not parse.
fn cert_names(der: &CertificateDer<'_>) -> Option<Vec<CertName>> {
    let cert = webpki::EndEntityCert::try_from(der).ok()?;
    let short = |n: &&str| n.len() <= MAX_CLIENT_NAME_LEN;
    Some(
        cert.valid_dns_names()
            .filter(short)
            .map(|n| CertName::Dns(n.to_string()))
            .chain(
                cert.valid_uri_names()
                    .filter(short)
                    .map(|n| CertName::Uri(n.to_string())),
            )
            .take(MAX_CERT_NAMES)
            .collect(),
    )
}

/// Decides one RPC: `Ok` when the leaf has an allow-listed name. An empty
/// list admits any certificate that chained to the client CA (loopback
/// listeners only, see [`check_listener`]).
///
/// # Errors
/// The reason, for the log only (never sent to the peer).
pub fn authorize(certs: Option<&[CertificateDer<'_>]>, allowed: &[String]) -> Result<(), String> {
    let leaf = certs
        .and_then(<[_]>::first)
        .ok_or_else(|| "no client certificate".to_string())?;
    let names = cert_names(leaf).ok_or_else(|| "unparseable client certificate".to_string())?;
    if allowed.is_empty() {
        return Ok(());
    }
    if names.iter().any(|n| allowed.iter().any(|a| n.matches(a))) {
        return Ok(());
    }
    let shown: Vec<&str> = names.iter().map(CertName::as_str).take(4).collect();
    Err(format!(
        "client certificate {shown:?} not in the client allow-list"
    ))
}

/// Interceptor enforcing the client allow-list under mTLS. Without TLS it
/// passes requests through (the listener is then loopback-only).
// POAM: POA&M-383, POA&M-434 denials are logged, not written to the
// uc-audit trail (the pods using this gate have no audit sink).
#[derive(Debug, Clone)]
pub struct ClientNameGate {
    enforce: bool,
    allowed: Arc<[String]>,
    service: &'static str,
}

impl ClientNameGate {
    /// `enforce` is true when the listener runs mTLS. `service` names the
    /// gRPC service in the refusal log.
    #[must_use]
    pub fn new(enforce: bool, allowed: &[String], service: &'static str) -> Self {
        Self {
            enforce,
            allowed: allowed.into(),
            service,
        }
    }
}

impl Interceptor for ClientNameGate {
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        if !self.enforce {
            return Ok(req);
        }
        let certs = req.peer_certs();
        match authorize(certs.as_deref().map(Vec::as_slice), &self.allowed) {
            Ok(()) => Ok(req),
            Err(reason) => {
                warn!(
                    service = self.service,
                    peer = ?req.remote_addr(),
                    %reason,
                    "gRPC call refused"
                );
                Err(Status::permission_denied(
                    "client certificate is not allowed on this listener",
                ))
            }
        }
    }
}

/// Client mTLS material (PEM file paths), from
/// `<prefix>_{CA,CERT,KEY}_FILE` plus the optional `<prefix>_DOMAIN`
/// server-name override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientTls {
    /// CA that signs the server certificate.
    pub ca: PathBuf,
    /// This client's certificate.
    pub cert: PathBuf,
    /// This client's private key.
    pub key: PathBuf,
    /// Server name to verify instead of the URL host (DNS name or IP).
    pub domain: Option<String>,
}

impl ClientTls {
    /// All three files or none; an empty value counts as unset. `domain` is
    /// only meaningful with the files.
    ///
    /// # Errors
    /// A message naming `<prefix>_*` when only some files are set, or a
    /// domain override without them.
    pub fn from_parts(
        prefix: &str,
        ca: Option<String>,
        cert: Option<String>,
        key: Option<String>,
        domain: Option<String>,
    ) -> Result<Option<Self>, String> {
        let domain = set(domain);
        match (set(ca), set(cert), set(key)) {
            (None, None, None) if domain.is_none() => Ok(None),
            (Some(ca), Some(cert), Some(key)) => Ok(Some(Self {
                ca: ca.into(),
                cert: cert.into(),
                key: key.into(),
                domain,
            })),
            _ => Err(format!(
                "{prefix}_{{CA,CERT,KEY}}_FILE: set all three or none \
                 ({prefix}_DOMAIN needs them)"
            )),
        }
    }
}

/// Checks a server URL against the client TLS setting.
///
/// With client TLS the URL must be `https://`, so the channel cannot fall
/// back to plaintext. Without TLS the server must be on loopback
/// (`127.0.0.0/8`, `[::1]` or `localhost`).
///
/// # Errors
/// A message naming the URL and `<prefix>_*`.
///
/// ## NIST 800-53 Rev5: SC-8, SC-7
pub fn check_client_url(prefix: &str, url: &str, tls: Option<&ClientTls>) -> Result<(), String> {
    let https = url
        .get(..8)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"));
    if tls.is_some() {
        if !https {
            return Err(format!(
                "URL {url:?} must use https:// when {prefix}_{{CA,CERT,KEY}}_FILE are set"
            ));
        }
        return Ok(());
    }
    let loopback = url
        .parse::<Uri>()
        .ok()
        .and_then(|u| u.host().map(str::to_ascii_lowercase))
        .is_some_and(|h| {
            let h = h.trim_start_matches('[').trim_end_matches(']');
            h == "localhost" || h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
        });
    if !loopback {
        return Err(format!(
            "URL {url:?} is not a loopback address: set {prefix}_{{CA,CERT,KEY}}_FILE \
             (mTLS) for a remote server"
        ));
    }
    Ok(())
}

/// Builds the endpoint for `url`: timeouts, plus client mTLS when `tls` is set.
///
/// The PEM files are read on every call, so a reconnect picks up rotated
/// files. The caller checks the URL against the TLS setting first
/// ([`check_client_url`]).
///
/// # Errors
/// An invalid URL, an unreadable file or an invalid TLS config.
///
/// ## NIST 800-53 Rev5: IA-3, SC-8, SC-5
pub async fn client_endpoint(
    url: &str,
    tls: Option<&ClientTls>,
    connect_timeout: Duration,
    request_timeout: Duration,
) -> Result<Endpoint, String> {
    Ok(endpoint(url, tls, request_timeout)
        .await?
        .connect_timeout(connect_timeout))
}

/// A lazy channel to `url` through [`PreTlsConnector`].
///
/// It connects on first use and reconnects after a failure. Name resolution and TCP connect
/// are bounded by `tcp_connect_timeout` and their failures are tagged
/// [`PreTlsError`]; TLS (with `tls`) runs on top. Each RPC is bounded by
/// `request_timeout` until its response headers.
///
/// # Errors
/// An invalid URL, an unreadable PEM file or an invalid TLS config.
///
/// ## NIST 800-53 Rev5: IA-3, SC-8, SC-5
pub async fn client_channel(
    url: &str,
    tls: Option<&ClientTls>,
    tcp_connect_timeout: Duration,
    request_timeout: Duration,
) -> Result<Channel, String> {
    let endpoint = endpoint(url, tls, request_timeout).await?;
    Ok(endpoint.connect_with_connector_lazy(PreTlsConnector {
        timeout: tcp_connect_timeout,
    }))
}

async fn endpoint(
    url: &str,
    tls: Option<&ClientTls>,
    request_timeout: Duration,
) -> Result<Endpoint, String> {
    async fn read(p: &Path) -> Result<String, String> {
        tokio::fs::read_to_string(p)
            .await
            .map_err(|e| format!("{}: {e}", p.display()))
    }
    let mut endpoint = Endpoint::from_shared(url.to_string())
        .map_err(|e| format!("invalid URL {url:?}: {e}"))?
        .timeout(request_timeout);
    if let Some(tls) = tls {
        let mut cfg = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(read(&tls.ca).await?))
            .identity(Identity::from_pem(
                read(&tls.cert).await?,
                read(&tls.key).await?,
            ));
        if let Some(domain) = &tls.domain {
            cfg = cfg.domain_name(domain.clone());
        }
        endpoint = endpoint
            .tls_config(cfg)
            .map_err(|e| format!("TLS config for {url:?}: {e}"))?;
    }
    Ok(endpoint)
}

/// A connect failure before any TLS byte was exchanged.
#[derive(Debug)]
pub enum PreTlsError {
    /// The URL has no host.
    NoHost,
    /// Name resolution failed or returned no address.
    Resolve(std::io::Error),
    /// Every TCP connect attempt failed (refused, reset, unreachable,
    /// timed out).
    Connect(std::io::Error),
}

impl std::fmt::Display for PreTlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoHost => f.write_str("URL has no host"),
            Self::Resolve(e) => write!(f, "name resolution failed: {e}"),
            Self::Connect(e) => write!(f, "TCP connect failed: {e}"),
        }
    }
}

impl std::error::Error for PreTlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoHost => None,
            Self::Resolve(e) | Self::Connect(e) => Some(e),
        }
    }
}

/// Whether `err` was caused by a [`PreTlsError`] (peer never reached at TLS).
///
/// `err` is a tonic `Status` or transport error, with its source chain.
/// Anything else (TLS alert, certificate rejection, a
/// connection lost after TLS) is not.
#[must_use]
pub fn is_pre_tls_failure(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur = Some(err);
    while let Some(e) = cur {
        if e.is::<PreTlsError>() {
            return true;
        }
        cur = e.source();
    }
    false
}

/// tonic connector doing name resolution and TCP connect only (TLS is
/// layered by tonic), with failures tagged [`PreTlsError`].
#[derive(Debug, Clone, Copy)]
pub struct PreTlsConnector {
    /// Bound on resolution plus connect.
    pub timeout: Duration,
}

impl tower_service::Service<Uri> for PreTlsConnector {
    type Response = TokioIo<TcpStream>;
    type Error = PreTlsError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, PreTlsError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let timeout = self.timeout;
        Box::pin(async move {
            let host = uri
                .host()
                .ok_or(PreTlsError::NoHost)?
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_string();
            let https = uri.scheme_str() == Some("https");
            let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
            let connect = async {
                let addrs = tokio::net::lookup_host((host.as_str(), port))
                    .await
                    .map_err(PreTlsError::Resolve)?;
                let mut last = None;
                for addr in addrs.take(MAX_CONNECT_ADDRS) {
                    match TcpStream::connect(addr).await {
                        Ok(stream) => {
                            let _ = stream.set_nodelay(true);
                            return Ok(TokioIo::new(stream));
                        }
                        Err(e) => last = Some(e),
                    }
                }
                Err(last.map_or_else(
                    || {
                        PreTlsError::Resolve(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            "no address",
                        ))
                    },
                    PreTlsError::Connect,
                ))
            };
            tokio::time::timeout(timeout, connect).await.map_err(|_| {
                PreTlsError::Connect(std::io::Error::from(std::io::ErrorKind::TimedOut))
            })?
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod change_tests {
    use super::*;

    fn tls_in(dir: &Path) -> ServerTls {
        for n in ["c", "k", "ca"] {
            std::fs::write(dir.join(n), n).unwrap();
        }
        ServerTls {
            cert: dir.join("c"),
            key: dir.join("k"),
            client_ca: dir.join("ca"),
        }
    }

    #[tokio::test]
    async fn unchanged_files_do_not_resolve() {
        let dir = tempfile::tempdir().unwrap();
        let tls = tls_in(dir.path());
        let (_, loaded) = load_server_tls_fingerprinted(&tls).unwrap();
        // The load-time fingerprint matches the file bytes.
        assert_eq!(loaded, TlsFingerprint::read(&tls).await);
        let r = tokio::time::timeout(
            Duration::from_millis(300),
            wait_for_tls_change(&tls, loaded, Duration::from_millis(20)),
        )
        .await;
        assert!(r.is_err(), "no change, must keep waiting");
    }

    #[tokio::test]
    async fn rewritten_cert_or_key_resolves() {
        for victim in ["c", "k", "ca"] {
            let dir = tempfile::tempdir().unwrap();
            let tls = tls_in(dir.path());
            let path = dir.path().join(victim);
            let loaded = TlsFingerprint::read(&tls).await;
            let watch = wait_for_tls_change(&tls, loaded, Duration::from_millis(20));
            let edit = async {
                tokio::time::sleep(Duration::from_millis(60)).await;
                std::fs::write(&path, "renewed").unwrap();
            };
            let (r, ()) = tokio::join!(tokio::time::timeout(Duration::from_secs(2), watch), edit);
            assert!(r.is_ok(), "{victim}: change not detected");
        }
    }

    /// SEC-009: a renewal between loading and starting the watcher is seen.
    #[tokio::test]
    async fn change_between_load_and_watch_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let tls = tls_in(dir.path());
        let (_, loaded) = load_server_tls_fingerprinted(&tls).unwrap();
        std::fs::write(dir.path().join("c"), "renewed before the watch").unwrap();
        let r = tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_tls_change(&tls, loaded, Duration::from_millis(20)),
        )
        .await;
        assert!(r.is_ok(), "renewal before the watch was missed");
    }

    #[tokio::test]
    async fn missing_file_is_not_a_change() {
        let dir = tempfile::tempdir().unwrap();
        let tls = tls_in(dir.path());
        let loaded = TlsFingerprint::read(&tls).await;
        let watch = wait_for_tls_change(&tls, loaded, Duration::from_millis(20));
        let edit = async {
            tokio::time::sleep(Duration::from_millis(40)).await;
            std::fs::remove_file(dir.path().join("k")).unwrap();
        };
        let (r, ()) = tokio::join!(
            tokio::time::timeout(Duration::from_millis(300), watch),
            edit
        );
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn refused_connect_is_pre_tls_and_tagged() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let ch = client_channel(
            &format!("http://127.0.0.1:{port}"),
            None,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        let mut client = crate::health::health_client::HealthClient::new(ch);
        let st = client
            .check(crate::health::HealthCheckRequest {
                service: String::new(),
            })
            .await
            .unwrap_err();
        assert_eq!(st.code(), tonic::Code::Unavailable, "{st:?}");
        assert!(is_pre_tls_failure(&st), "{st:?}");
        assert!(!is_pre_tls_failure(&Status::unavailable("x")));
    }

    #[tokio::test]
    async fn unresolvable_host_is_pre_tls() {
        let ch = client_channel(
            "http://no-such-host.invalid:9095",
            None,
            Duration::from_secs(2),
            Duration::from_secs(3),
        )
        .await
        .unwrap();
        let mut client = crate::health::health_client::HealthClient::new(ch);
        let st = client
            .check(crate::health::HealthCheckRequest {
                service: String::new(),
            })
            .await
            .unwrap_err();
        assert!(is_pre_tls_failure(&st), "{st:?}");
    }

    #[test]
    fn cnsa_provider_lists() {
        let p = cnsa_provider();
        let suites: Vec<_> = p
            .cipher_suites
            .iter()
            .map(rustls::SupportedCipherSuite::suite)
            .collect();
        assert_eq!(suites, [rustls::CipherSuite::TLS13_AES_256_GCM_SHA384]);
        let groups: Vec<_> = p.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(
            groups,
            [rustls::NamedGroup::MLKEM1024, rustls::NamedGroup::secp384r1]
        );
        let schemes: Vec<_> = p
            .signature_verification_algorithms
            .mapping
            .iter()
            .map(|(s, _)| *s)
            .collect();
        assert_eq!(schemes, [rustls::SignatureScheme::ECDSA_NISTP384_SHA384]);
        assert_eq!(p.signature_verification_algorithms.all.len(), 1);
    }
}
