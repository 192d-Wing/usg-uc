//! mTLS for the `MediaControllerService` listener.
//!
//! The controller service has no per-RPC authorization, so it is reachable
//! either on loopback only (the co-located daemon in the same pod), or off
//! loopback with mutual TLS: the client certificate must chain to
//! `SBC_MEDIA_GRPC_TLS_CLIENT_CA_FILE` and carry a SAN DNS name or SAN URI
//! listed in `SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES` on every RPC. There is no
//! plaintext opt-in off loopback.
//!
//! A thin wrapper over the shared [`sbc_grpc_api::mtls`] helper that fixes
//! this binary's variable names.
//!
//! ## NIST 800-53 Rev5: IA-3, SC-8, AC-3, SC-7

use std::net::SocketAddr;

use sbc_grpc_api::mtls::{self, MtlsEnvNames};
use tonic::service::Interceptor;
use tonic::{Request, Status};

#[cfg(test)]
use rustls_pki_types::CertificateDer;
#[cfg(test)]
use sbc_grpc_api::mtls::{CertName, authorize};
pub use sbc_grpc_api::mtls::{ServerTls, load_server_tls};

/// The sbc-media listener variables.
const NAMES: MtlsEnvNames = MtlsEnvNames {
    listen: "SBC_MEDIA_GRPC_LISTEN",
    tls_prefix: "SBC_MEDIA_GRPC_TLS",
    allowed: "SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES",
};

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
    mtls::server_tls_from(&NAMES, cert, key, client_ca)
}

/// `SBC_MEDIA_GRPC_ALLOWED_CLIENT_NAMES`: comma-separated SAN DNS names or
/// URIs; each 1..=253 printable ASCII characters, at most 64 entries.
///
/// # Errors
/// A message naming the offending entry.
pub fn parse_allowed_client_names(raw: Option<&str>) -> Result<Vec<String>, String> {
    mtls::parse_allowed_client_names(&NAMES, raw)
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
    mtls::check_listener(&NAMES, addr, tls, allowed)
}

/// Interceptor enforcing the client allow-list under mTLS. Without TLS it
/// passes requests through (the listener is then loopback-only).
#[derive(Debug, Clone)]
pub struct ClientNameGate(mtls::ClientNameGate);

impl ClientNameGate {
    /// `enforce` is true when the listener runs mTLS.
    #[must_use]
    pub fn new(enforce: bool, allowed: &[String]) -> Self {
        Self(mtls::ClientNameGate::new(
            enforce,
            allowed,
            "MediaControllerService",
        ))
    }
}

impl Interceptor for ClientNameGate {
    fn call(&mut self, req: Request<()>) -> Result<Request<()>, Status> {
        self.0.call(req)
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
