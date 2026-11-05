//! gRPC client-certificate allow-list and authenticated principal.
//!
//! With `grpc.require_mtls`, rustls has already verified that the client
//! certificate chains to `grpc.tls_ca_path`. That alone admits any workload
//! the issuer will sign for, so [`ClientCertGate`] also checks the leaf
//! certificate's names (SAN DNS, SAN URI, subject CN) against
//! `grpc.allowed_client_names` on every RPC, for every service. The accepted
//! name is attached to the request as [`PeerPrincipal`] and is what the
//! audit trail records as the caller; `x-sbc-user` is only "on behalf of".
//!
//! The certificate is attacker-supplied DER: it is parsed by `webpki` and a
//! bounded tag-length walker for the CN, and a malformed certificate is
//! rejected, never a panic.
//!
//! ## NIST 800-53 Rev5: AC-3 (Access Enforcement), IA-3 (Device
//! Identification and Authentication), AU-3 (Content of Audit Records)

use rustls_pki_types::CertificateDer;
use std::sync::Arc;
use tonic::service::Interceptor;
use tonic::{Request, Status};

/// Most names taken from one certificate (SANs plus CN).
const MAX_CERT_NAMES: usize = 32;

/// Longest name kept (DNS name limit; matches sbc-config).
const MAX_NAME_LEN: usize = 253;

/// DER OID 2.5.4.3 (id-at-commonName), tag and length included.
const OID_CN: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];

/// The authenticated gRPC client, from its certificate: `cert:<name>`.
/// Present in request extensions only when the gate ran (mTLS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPrincipal(pub String);

/// One name from a client certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CertName {
    Dns(String),
    Uri(String),
    Cn(String),
}

impl CertName {
    fn as_str(&self) -> &str {
        match self {
            Self::Dns(s) | Self::Uri(s) | Self::Cn(s) => s,
        }
    }

    /// DNS names and CNs compare ASCII case-insensitively, URIs exactly.
    fn matches(&self, allowed: &str) -> bool {
        match self {
            Self::Dns(s) | Self::Cn(s) => s.eq_ignore_ascii_case(allowed),
            Self::Uri(s) => s == allowed,
        }
    }
}

/// Keeps printable-ASCII names only, capped.
fn clean(s: &str) -> Option<String> {
    (!s.is_empty() && s.len() <= MAX_NAME_LEN && s.bytes().all(|b| (0x21..=0x7e).contains(&b)))
        .then(|| s.to_string())
}

/// Reads one DER TLV from `input`: `(tag, value, rest)`. Single-byte tags
/// and lengths up to two octets only (a subject Name never needs more).
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0..=0x7f => (usize::from(first), rest),
        0x81 => {
            let (&b, rest) = rest.split_first()?;
            (usize::from(b), rest)
        }
        0x82 => {
            let hi = *rest.first()?;
            let lo = *rest.get(1)?;
            (usize::from(u16::from_be_bytes([hi, lo])), rest.get(2..)?)
        }
        _ => return None,
    };
    let value = rest.get(..len)?;
    Some((tag, value, rest.get(len..)?))
}

/// Subject CNs from a Name's content (RDNSequence without its outer tag).
fn subject_cns(mut name: &[u8], out: &mut Vec<CertName>) -> Option<()> {
    while !name.is_empty() && out.len() < MAX_CERT_NAMES {
        let (rdn_tag, mut set, rest) = tlv(name)?;
        name = rest;
        if rdn_tag != 0x31 {
            return None;
        }
        while !set.is_empty() {
            let (atv_tag, atv, tail) = tlv(set)?;
            set = tail;
            if atv_tag != 0x30 {
                return None;
            }
            let Some(value) = atv.strip_prefix(OID_CN) else {
                continue;
            };
            let (str_tag, s, _) = tlv(value)?;
            // UTF8String, PrintableString, IA5String.
            let cn = matches!(str_tag, 0x0c | 0x13 | 0x16)
                .then(|| std::str::from_utf8(s).ok().and_then(clean))
                .flatten();
            if let Some(cn) = cn {
                out.push(CertName::Cn(cn));
            }
        }
    }
    Some(())
}

/// Names in a client leaf certificate, SAN DNS first, then SAN URI, then
/// subject CN. `None` if the certificate does not parse.
fn cert_names(der: &CertificateDer<'_>) -> Option<Vec<CertName>> {
    let cert = webpki::EndEntityCert::try_from(der).ok()?;
    let mut out: Vec<CertName> = cert
        .valid_dns_names()
        .filter_map(clean)
        .map(CertName::Dns)
        .chain(cert.valid_uri_names().filter_map(clean).map(CertName::Uri))
        .take(MAX_CERT_NAMES)
        .collect();
    subject_cns(cert.subject(), &mut out)?;
    Some(out)
}

/// Decides one RPC: the principal on success, a short reason on refusal.
/// An empty `allowed` list admits any certificate (it already chained to
/// the configured CA); the principal is then its first name.
fn authorize(certs: Option<&[CertificateDer<'_>]>, allowed: &[String]) -> Result<String, String> {
    let leaf = certs
        .and_then(<[_]>::first)
        .ok_or_else(|| "no client certificate".to_string())?;
    let names = cert_names(leaf).ok_or_else(|| "unparseable client certificate".to_string())?;
    if allowed.is_empty() {
        let first = names.first().map_or("<unnamed>", CertName::as_str);
        return Ok(format!("cert:{first}"));
    }
    names
        .iter()
        .find_map(|n| allowed.iter().find(|a| n.matches(a)))
        .map(|a| format!("cert:{a}"))
        .ok_or_else(|| {
            // The presented names are the evidence for the denial.
            let shown: Vec<&str> = names.iter().map(CertName::as_str).take(4).collect();
            format!("client certificate {shown:?} not in grpc.allowed_client_names")
        })
}

/// Tonic interceptor enforcing `grpc.allowed_client_names` under
/// `grpc.require_mtls`. Without mTLS it passes requests through untouched
/// (no [`PeerPrincipal`]); sbc-config rejects an allow-list without mTLS.
///
/// ## NIST 800-53 Rev5: AC-3, IA-3, AU-2 (denials audited)
#[derive(Debug, Clone)]
pub struct ClientCertGate {
    enforce: bool,
    allowed: Arc<[String]>,
}

impl ClientCertGate {
    /// Builds the gate from `grpc.require_mtls` and the allow-list.
    pub fn new(require_mtls: bool, allowed: &[String]) -> Self {
        Self {
            enforce: require_mtls,
            allowed: allowed.into(),
        }
    }
}

impl Interceptor for ClientCertGate {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        if !self.enforce {
            return Ok(req);
        }
        let certs = req.peer_certs();
        match authorize(certs.as_deref().map(Vec::as_slice), &self.allowed) {
            Ok(principal) => {
                req.extensions_mut().insert(PeerPrincipal(principal));
                Ok(req)
            }
            Err(reason) => {
                let resource = req.extensions().get::<tonic::GrpcMethod>().map_or_else(
                    || "grpc".to_string(),
                    |m| format!("grpc:/{}/{}", m.service(), m.method()),
                );
                uc_audit::log_event(uc_audit::AuditEvent::AuthorizationDecision(
                    uc_audit::event::AuthorizationDecision {
                        identity: reason,
                        resource,
                        action: "call".to_string(),
                        granted: false,
                        policy: "grpc.allowed_client_names".to_string(),
                        source_ip: req.remote_addr().map(|a| a.ip()),
                    },
                ));
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

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn cert(cn: &str, dns: &[&str]) -> Result<CertificateDer<'static>, rcgen::Error> {
        let sans: Vec<String> = dns.iter().map(|s| (*s).to_string()).collect();
        let mut params = rcgen::CertificateParams::new(sans)?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)?;
        Ok(params.self_signed(&key)?.der().clone())
    }

    fn allow(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn allow_listed_cert_accepted_with_cert_principal() -> TestResult {
        let c = cert("sbc-api", &["rel-sbc-api.sbc.svc"])?;
        let chain = std::slice::from_ref(&c);
        // SAN DNS match (case-insensitive).
        let p = authorize(Some(chain), &allow(&["REL-SBC-API.sbc.svc"]))?;
        assert_eq!(p, "cert:REL-SBC-API.sbc.svc");
        // Subject CN match.
        let p = authorize(Some(chain), &allow(&["other", "sbc-api"]))?;
        assert_eq!(p, "cert:sbc-api");
        Ok(())
    }

    #[test]
    fn other_cert_rejected() -> TestResult {
        let c = cert("rogue-workload", &["rogue.default.svc"])?;
        let e = authorize(Some(&[c]), &allow(&["rel-sbc-api.sbc.svc"])).err();
        assert!(
            e.as_deref()
                .is_some_and(|e| e.contains("rogue.default.svc")),
            "{e:?}"
        );
        // A wildcard SAN does not match a concrete allow-list entry.
        let w = cert("x", &["*.sbc.svc"])?;
        assert!(authorize(Some(&[w]), &allow(&["rel-sbc-api.sbc.svc"])).is_err());
        Ok(())
    }

    #[test]
    fn missing_or_garbage_cert_rejected() {
        assert!(authorize(None, &[]).is_err());
        assert!(authorize(Some(&[]), &[]).is_err());
        let junk = CertificateDer::from(vec![0x30, 0x82, 0xff, 0xff, 0x01]);
        assert!(authorize(Some(&[junk]), &[]).is_err());
    }

    #[test]
    fn empty_allow_list_admits_chained_cert_named_by_subject() -> TestResult {
        let c = cert("sbc-cli-op", &[])?;
        assert_eq!(authorize(Some(&[c]), &[])?, "cert:sbc-cli-op");
        Ok(())
    }

    #[test]
    fn cn_walker_is_bounds_checked() {
        let mut out = Vec::new();
        // Truncated SET, bad tag, oversized length: all rejected, no panic.
        for bad in [
            &[0x31, 0x05, 0x30][..],
            &[0x30, 0x00],
            &[0x31, 0x83, 0, 0, 1],
        ] {
            assert!(subject_cns(bad, &mut out).is_none(), "{bad:?}");
        }
        assert_eq!(out, Vec::new());
    }

    #[test]
    fn gate_without_mtls_passes_through() -> TestResult {
        let mut g = ClientCertGate::new(false, &[]);
        let r = g.call(Request::new(()))?;
        assert!(r.extensions().get::<PeerPrincipal>().is_none());
        // With mTLS required, a request with no TLS info is refused.
        let mut g = ClientCertGate::new(true, &allow(&["sbc-api"]));
        assert_eq!(
            g.call(Request::new(())).err().map(|e| e.code()),
            Some(tonic::Code::PermissionDenied)
        );
        Ok(())
    }
}
