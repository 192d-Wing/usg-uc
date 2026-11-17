//! mTLS for the `MediaControllerService` listener.
//!
//! The controller service has no per-RPC authorization, so it is reachable
//! either on loopback only (the co-located daemon in the same pod), or off
//! loopback with mutual TLS: the client certificate must chain to
//! `SBC_MEDIA_GRPC_TLS_CLIENT_CA_FILE` and carry a SAN DNS name or SAN URI
//! listed in `SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES` on every RPC. There is no
//! plaintext opt-in off loopback.
//!
//! The certificate is peer-supplied DER: it is parsed by `webpki` and a
//! malformed one is refused, never a panic.
//!
//! ## NIST 800-53 Rev5: IA-3, SC-8, AC-3, SC-7

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use rustls_pki_types::CertificateDer;
use tonic::service::Interceptor;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tonic::{Request, Status};
use tracing::warn;

/// Most entries accepted in `SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES`.
pub const MAX_ALLOWED_CLIENT_NAMES: usize = 64;

/// Longest allow-list entry (DNS name limit).
pub const MAX_CLIENT_NAME_LEN: usize = 253;

/// Most names taken from one client certificate.
const MAX_CERT_NAMES: usize = 32;

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

/// `SBC_MEDIA_GRPC_TLS_{CERT,KEY,CLIENT_CA}_FILE`: all three or none; an
/// empty value counts as unset.
///
/// # Errors
/// A message naming the variables when only some are set.
pub fn server_tls_from(
    cert: Option<String>,
    key: Option<String>,
    client_ca: Option<String>,
) -> Result<Option<ServerTls>, String> {
    let set = |v: Option<String>| v.filter(|s| !s.trim().is_empty());
    match (set(cert), set(key), set(client_ca)) {
        (None, None, None) => Ok(None),
        (Some(cert), Some(key), Some(client_ca)) => Ok(Some(ServerTls {
            cert: cert.into(),
            key: key.into(),
            client_ca: client_ca.into(),
        })),
        _ => Err("SBC_MEDIA_GRPC_TLS_{CERT,KEY,CLIENT_CA}_FILE: set all three or none".to_string()),
    }
}

/// `SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES`: comma-separated SAN DNS names or
/// URIs; each 1..=253 printable ASCII characters, at most 64 entries.
///
/// # Errors
/// A message naming the offending entry.
pub fn parse_allowed_client_names(raw: Option<&str>) -> Result<Vec<String>, String> {
    let names: Vec<String> = raw
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if names.len() > MAX_ALLOWED_CLIENT_NAMES {
        return Err(format!(
            "SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES has more than {MAX_ALLOWED_CLIENT_NAMES} entries"
        ));
    }
    for n in &names {
        let printable = n.bytes().all(|b| (0x21..=0x7e).contains(&b));
        if n.len() > MAX_CLIENT_NAME_LEN || !printable {
            return Err(format!(
                "SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES entry {n:?} must be 1..={MAX_CLIENT_NAME_LEN} \
                 printable ASCII characters"
            ));
        }
    }
    Ok(names)
}

/// The listener rule: off loopback only with mTLS and a non-empty client
/// allow-list; an allow-list without mTLS is refused rather than ignored.
///
/// # Errors
/// A message naming `SBC_MEDIA_GRPC_LISTEN` and what is missing.
pub fn check_listener(
    addr: SocketAddr,
    tls: Option<&ServerTls>,
    allowed: &[String],
) -> Result<(), String> {
    if tls.is_none() && !allowed.is_empty() {
        return Err("SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES is only enforced with \
             SBC_MEDIA_GRPC_TLS_{CERT,KEY,CLIENT_CA}_FILE"
            .to_string());
    }
    if addr.ip().is_loopback() {
        return Ok(());
    }
    if tls.is_none() {
        return Err(format!(
            "SBC_MEDIA_GRPC_LISTEN {addr} must be a loopback address unless \
             SBC_MEDIA_GRPC_TLS_{{CERT,KEY,CLIENT_CA}}_FILE are set (mTLS)"
        ));
    }
    if allowed.is_empty() {
        return Err(format!(
            "SBC_MEDIA_GRPC_LISTEN {addr} is not a loopback address: \
             SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES must list the permitted client names"
        ));
    }
    Ok(())
}

/// Builds the tonic server TLS config: server identity plus a required
/// client certificate chaining to the client CA.
///
/// # Errors
/// The unreadable file.
pub fn load_server_tls(tls: &ServerTls) -> Result<ServerTlsConfig, String> {
    let read =
        |p: &PathBuf| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
    Ok(ServerTlsConfig::new()
        .identity(Identity::from_pem(read(&tls.cert)?, read(&tls.key)?))
        .client_ca_root(Certificate::from_pem(read(&tls.client_ca)?)))
}

/// One name from a client certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CertName {
    Dns(String),
    Uri(String),
}

impl CertName {
    fn as_str(&self) -> &str {
        match self {
            Self::Dns(s) | Self::Uri(s) => s,
        }
    }

    /// DNS names compare ASCII case-insensitively, URIs exactly.
    fn matches(&self, allowed: &str) -> bool {
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

/// Decides one RPC: `Ok` when the leaf has an allow-listed name (DNS names
/// compare ASCII case-insensitively, URIs exactly). An empty list admits any certificate
/// that chained to the client CA (loopback listeners only, see
/// [`check_listener`]).
fn authorize(certs: Option<&[CertificateDer<'_>]>, allowed: &[String]) -> Result<(), String> {
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
        "client certificate {shown:?} not in SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES"
    ))
}

/// Interceptor enforcing the client allow-list under mTLS. Without TLS it
/// passes requests through (the listener is then loopback-only).
// POAM: POA&M-383 denials are logged, not written to the uc-audit trail
// (sbc-media has no audit sink).
#[derive(Debug, Clone)]
pub struct ClientNameGate {
    enforce: bool,
    allowed: Arc<[String]>,
}

impl ClientNameGate {
    /// `enforce` is true when the listener runs mTLS.
    #[must_use]
    pub fn new(enforce: bool, allowed: &[String]) -> Self {
        Self {
            enforce,
            allowed: allowed.into(),
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
                warn!(peer = ?req.remote_addr(), %reason, "MediaController call refused");
                Err(Status::permission_denied(
                    "client certificate is not allowed on this listener",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        v.to_string().into()
    }

    fn tls() -> ServerTls {
        ServerTls {
            cert: "/t/c".into(),
            key: "/t/k".into(),
            client_ca: "/t/ca".into(),
        }
    }

    fn addr(a: &str) -> SocketAddr {
        a.parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)))
    }

    #[test]
    fn server_tls_all_or_none() {
        assert_eq!(server_tls_from(None, None, None), Ok(None));
        assert_eq!(server_tls_from(s(""), s(""), s(" ")), Ok(None));
        assert_eq!(
            server_tls_from(s("/t/c"), s("/t/k"), s("/t/ca")),
            Ok(Some(tls()))
        );
        for (c, k, ca) in [
            (s("/t/c"), None, None),
            (None, s("/t/k"), s("/t/ca")),
            (s("/t/c"), s("/t/k"), None),
        ] {
            let r = server_tls_from(c, k, ca);
            assert!(
                r.as_ref().is_err_and(|e| e.contains("SBC_MEDIA_GRPC_TLS")),
                "{r:?}"
            );
        }
    }

    #[test]
    fn allowed_names_parsed_and_bounded() {
        assert_eq!(parse_allowed_client_names(None), Ok(Vec::new()));
        assert_eq!(
            parse_allowed_client_names(Some(" sbc-daemon , spiffe://x/y ,")),
            Ok(vec!["sbc-daemon".to_string(), "spiffe://x/y".to_string()])
        );
        assert!(parse_allowed_client_names(Some("has space")).is_err());
        assert!(parse_allowed_client_names(Some(&"a".repeat(254))).is_err());
        let many: Vec<String> = (0..65).map(|i| format!("c{i}")).collect();
        assert!(parse_allowed_client_names(Some(&many.join(","))).is_err());
    }

    #[test]
    fn non_loopback_listener_needs_mtls_and_names() {
        let names = vec!["sbc-daemon".to_string()];
        // Plaintext: loopback only.
        assert!(check_listener(addr("127.0.0.1:9096"), None, &[]).is_ok());
        assert!(check_listener(addr("[::1]:9096"), None, &[]).is_ok());
        for a in ["0.0.0.0:9096", "[::]:9096", "172.28.2.11:9096"] {
            let r = check_listener(addr(a), None, &[]);
            assert!(
                r.as_ref()
                    .is_err_and(|e| e.contains("SBC_MEDIA_GRPC_LISTEN") && e.contains("loopback")),
                "{a}: {r:?}"
            );
            // mTLS without an allow-list is not enough off loopback.
            assert!(check_listener(addr(a), Some(&tls()), &[]).is_err(), "{a}");
            assert!(check_listener(addr(a), Some(&tls()), &names).is_ok(), "{a}");
        }
        // An allow-list without mTLS is refused, not ignored.
        assert!(check_listener(addr("127.0.0.1:9096"), None, &names).is_err());
        assert!(check_listener(addr("127.0.0.1:9096"), Some(&tls()), &[]).is_ok());
    }

    #[test]
    fn missing_or_garbage_cert_refused() {
        assert!(authorize(None, &[]).is_err());
        assert!(authorize(Some(&[]), &[]).is_err());
        let junk = CertificateDer::from(vec![0x30, 0x82, 0xff, 0xff, 0x01]);
        assert!(authorize(Some(&[junk]), &["x".to_string()]).is_err());
    }

    #[test]
    fn gate_without_tls_passes_through_and_with_tls_needs_cert() {
        let mut open = ClientNameGate::new(false, &[]);
        assert!(open.call(Request::new(())).is_ok());
        let mut gate = ClientNameGate::new(true, &["sbc-daemon".to_string()]);
        assert_eq!(
            gate.call(Request::new(())).err().map(|e| e.code()),
            Some(tonic::Code::PermissionDenied)
        );
    }

    #[test]
    fn dns_names_case_insensitive_uris_exact() {
        assert!(CertName::Dns("SBC-Daemon".into()).matches("sbc-daemon"));
        assert!(CertName::Uri("spiffe://sbc/daemon".into()).matches("spiffe://sbc/daemon"));
        assert!(!CertName::Uri("spiffe://SBC/daemon".into()).matches("spiffe://sbc/daemon"));
    }
}
