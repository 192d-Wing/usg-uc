//! Discovery trust bootstrap: service-domain parsing, issuer pinning, and
//! endpoint scope checks for the sign-in flow.
//!
//! Discovery is unauthenticated, so the values below are checked against the
//! service domain the user entered (or the issuer it names) before they are
//! contacted or used. Per the design doc (Security Considerations → "Issuer
//! pinning"):
//!
//! - the service domain is parsed into a bare DNS host ([`parse_service_domain`]);
//! - the discovery `issuer` is https with no userinfo, query or fragment, and
//!   shares the service domain's registrable domain or matches a pin scoped to
//!   that registrable domain ([`PINNED_ISSUERS`]);
//! - `provisioning.config_endpoint` is https inside the service's registrable
//!   domain ([`verify_discovery`]);
//! - the OIDC metadata `issuer` and its authorization, token,
//!   device_authorization, end_session and revocation endpoints are https
//!   inside the issuer's registrable domain ([`verify_oidc_endpoints`]);
//! - the device grant's `verification_uri` / `verification_uri_complete` are
//!   https inside the issuer's registrable domain
//!   ([`verify_device_authorization`]);
//! - the provisioned `registration.registrar_domain`, `sip.uri` and
//!   `sip.domain` are inside the service's registrable domain
//!   ([`verify_client_config`]). `features` is opaque and not consumed, so it
//!   is not checked.
//!
//! The library fetchers run these checks before returning, so a value that
//! fails is never handed to the browser, the token endpoint or the SIP UA,
//! and the bearer token is only sent to an in-scope `config_endpoint`.
//!
//! NIST 800-53 Rev5: IA-5 (authenticator protection), SC-23 (session
//! authenticity), SI-10 (input validation), AC-4 (information flow).

use url::{Host, Url};

use crate::error::ProvisioningError;
use crate::wire::{ClientConfig, DeviceAuthorization, DiscoveryDoc, OidcMetadata};

/// Service-domain issuer pins: `(service registrable domain, issuer host)`.
/// A pin applies only when the entered service domain's registrable domain
/// equals the key. Keep this short and exact.
pub const PINNED_ISSUERS: &[(&str, &str)] = &[("oopl.dev.mil", "icam.oopl.dev.mil")];

/// Multi-label public suffixes this fleet uses. A host's registrable domain
/// is one label plus the longest matching entry; hosts matching no entry use
/// their single-label TLD as the suffix.
// POAM: POA&M-370 built-in fleet suffix list, not the full Public Suffix
// List; hosts under unlisted multi-label suffixes are scoped one or more
// levels too wide.
const PUBLIC_SUFFIXES: &[&str] = &["dev.mil"];

/// Upper bound on the user-entered service domain (scheme + host + port).
const MAX_SERVICE_INPUT_LEN: usize = 300;

/// Maximum DNS name length (RFC 1035 §2.3.4).
const MAX_DNS_NAME_LEN: usize = 253;

/// Maximum DNS label length (RFC 1035 §2.3.4).
const MAX_DNS_LABEL_LEN: usize = 63;

/// Upper bound on a provisioned SIP URI.
const MAX_SIP_URI_LEN: usize = 512;

/// A parsed, normalized service domain (lowercase DNS host, optional
/// non-default port) and its registrable domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceDomain {
    host: String,
    port: Option<u16>,
    registrable: String,
}

impl ServiceDomain {
    /// Normalized lowercase DNS host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Explicit non-default port (`None` for absent or `:443`).
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// Registrable domain (one label + longest matching built-in suffix).
    #[must_use]
    pub fn registrable(&self) -> &str {
        &self.registrable
    }

    /// `https://{host}[:{port}]/.well-known/sip-client-config`.
    #[must_use]
    pub fn discovery_url(&self) -> String {
        format!("https://{self}/.well-known/sip-client-config")
    }
}

impl std::fmt::Display for ServiceDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.port {
            Some(port) => write!(f, "{}:{port}", self.host),
            None => f.write_str(&self.host),
        }
    }
}

/// Parses a user-entered service domain.
///
/// Accepts `host`, `host:port`, `https://host[:port]`, each with an optional
/// trailing `/`; surrounding whitespace is trimmed and the host lowercased.
/// Port 443 normalizes to `None`.
///
/// NIST 800-53 Rev5: SI-10 (input validation).
///
/// # Errors
/// [`ProvisioningError::InvalidServiceDomain`] for anything else: another
/// scheme, userinfo, a path, query or fragment, control characters or inner
/// whitespace, a backslash, an IP literal, a non-LDH label, port 0 or an
/// unparseable port, or a host that is itself a public suffix / single label.
pub fn parse_service_domain(input: &str) -> Result<ServiceDomain, ProvisioningError> {
    let bad = |why: &str| ProvisioningError::InvalidServiceDomain(why.to_string());

    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(bad("empty"));
    }
    if trimmed.len() > MAX_SERVICE_INPUT_LEN {
        return Err(bad("too long"));
    }
    // Checked before URL parsing: the URL parser strips tab/CR/LF silently.
    if trimmed
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return Err(bad("contains control characters, whitespace or `\\`"));
    }

    let rest = match trimmed.get(..8) {
        Some(prefix) if prefix.eq_ignore_ascii_case("https://") => trimmed.get(8..).unwrap_or(""),
        _ => trimmed,
    };
    if rest.contains("://") {
        return Err(bad("only https is supported"));
    }
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority
        .chars()
        .any(|c| matches!(c, '/' | '?' | '#' | '@' | '[' | ']'))
    {
        return Err(bad(
            "must be a host name with an optional port (no path, query, fragment, userinfo or IP literal)",
        ));
    }

    let (host_part, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(parse_port(p).ok_or_else(|| bad("invalid port"))?)),
        None => (authority, None),
    };
    let host = dns_host(host_part).map_err(bad)?;

    // Cross-check with the URL parser: it must see the same DNS host (not an
    // IPv4 form such as a numeric or hex shorthand).
    let url = Url::parse(&format!("https://{authority}/")).map_err(|_| bad("not a valid host"))?;
    if url.host() != Some(Host::Domain(host.as_str())) {
        return Err(bad("not a DNS host name"));
    }

    let registrable =
        registrable_domain(&host).ok_or_else(|| bad("is a public suffix, not a service domain"))?;

    Ok(ServiceDomain {
        host,
        port: port.filter(|p| *p != 443),
        registrable,
    })
}

/// Verifies that `issuer` is trustworthy for a client that entered
/// `service_domain`. Compatibility wrapper: parses `service_domain` with
/// [`parse_service_domain`] and applies the issuer half of
/// [`verify_discovery`].
///
/// NIST 800-53 Rev5: IA-5, SC-23.
///
/// # Errors
/// [`ProvisioningError::InvalidServiceDomain`] when `service_domain` does not
/// parse; [`ProvisioningError::IssuerNotTrusted`] when the issuer is not
/// https, has userinfo or an IP host, or is outside the service's registrable
/// domain and matches no scoped pin.
pub fn verify_issuer_pinned(service_domain: &str, issuer: &str) -> Result<(), ProvisioningError> {
    let service = parse_service_domain(service_domain)?;
    verify_issuer(&service, issuer)
}

/// Validates a discovery document against the entered service domain.
///
/// The issuer must share the service's registrable domain or match a scoped
/// pin; `provisioning.config_endpoint` must be https inside the service's
/// registrable domain (any port).
///
/// NIST 800-53 Rev5: IA-5, SC-23, SI-10, AC-4.
///
/// # Errors
/// [`ProvisioningError::IssuerNotTrusted`] for the issuer,
/// [`ProvisioningError::UntrustedEndpoint`] for `provisioning.config_endpoint`.
pub fn verify_discovery(
    service: &ServiceDomain,
    doc: &DiscoveryDoc,
) -> Result<(), ProvisioningError> {
    verify_issuer(service, &doc.oidc.issuer)?;
    verify_endpoint_in_scope(
        "config_endpoint",
        &doc.provisioning.config_endpoint,
        service.registrable(),
    )
}

/// Validates the OIDC metadata issuer and endpoints.
///
/// The `issuer` must be https with no userinfo, query or fragment. Every
/// endpoint present (authorization, token, device_authorization,
/// end_session, revocation) must be https, no userinfo, host inside the
/// issuer's registrable domain.
///
/// NIST 800-53 Rev5: IA-5, SC-23, SI-10.
///
/// # Errors
/// [`ProvisioningError::UntrustedEndpoint`].
pub fn verify_oidc_endpoints(meta: &OidcMetadata) -> Result<(), ProvisioningError> {
    let scope = issuer_scope(&meta.issuer)?;
    let endpoints = [
        (
            "authorization_endpoint",
            Some(meta.authorization_endpoint.as_str()),
        ),
        ("token_endpoint", Some(meta.token_endpoint.as_str())),
        (
            "device_authorization_endpoint",
            meta.device_authorization_endpoint.as_deref(),
        ),
        ("end_session_endpoint", meta.end_session_endpoint.as_deref()),
        ("revocation_endpoint", meta.revocation_endpoint.as_deref()),
    ];
    for (name, endpoint) in endpoints {
        if let Some(endpoint) = endpoint {
            verify_endpoint_in_scope(name, endpoint, &scope)?;
        }
    }
    Ok(())
}

/// Validates a device authorization response (RFC 8628 §3.2).
///
/// Checked against the metadata it came from: `verification_uri` and, when present,
/// `verification_uri_complete` must be https, without userinfo, inside the
/// issuer's registrable domain. Run before either URL is opened.
///
/// NIST 800-53 Rev5: IA-5, SC-23, SI-10.
///
/// # Errors
/// [`ProvisioningError::UntrustedEndpoint`].
pub fn verify_device_authorization(
    meta: &OidcMetadata,
    device: &DeviceAuthorization,
) -> Result<(), ProvisioningError> {
    let scope = issuer_scope(&meta.issuer)?;
    verify_endpoint_in_scope("verification_uri", &device.verification_uri, &scope)?;
    if let Some(complete) = device.verification_uri_complete.as_deref() {
        verify_endpoint_in_scope("verification_uri_complete", complete, &scope)?;
    }
    Ok(())
}

/// Validates a provisioned client config against the entered service domain.
///
/// - `registration.registrar_domain` must be `host` or `host:port` (LDH DNS
///   name, port 1..=65535);
/// - `sip.uri` must be `sip:`/`sips:` `[user@]host[:port]` with no
///   parameters or headers;
/// - `sip.domain` must be a bare LDH DNS host;
///
/// and every host must be inside the service's registrable domain. In
/// addition, `sip.dn` must be a non-empty RFC 3261 user part and
/// `user.display_name` must carry no control characters or angle brackets,
/// the same rules the manual-entry path applies, since both flow into
/// From/Contact headers.
///
/// NIST 800-53 Rev5: SC-23, SI-10, AC-4.
///
/// # Errors
/// [`ProvisioningError::UntrustedEndpoint`].
pub fn verify_client_config(
    service: &ServiceDomain,
    cfg: &ClientConfig,
) -> Result<(), ProvisioningError> {
    verify_registrar_domain(service, &cfg.registration.registrar_domain)?;
    verify_sip_uri(service, "sip.uri", &cfg.sip.uri)?;
    let bad = |why: &str| ProvisioningError::UntrustedEndpoint(format!("sip.domain: {why}"));
    let host = dns_host(&cfg.sip.domain).map_err(bad)?;
    host_in_scope(&host, service.registrable()).map_err(bad)?;
    // RFC 3261 §25.1: the directory number becomes the AOR user part.
    if !is_sip_user(&cfg.sip.dn) {
        return Err(ProvisioningError::UntrustedEndpoint(
            "sip.dn: empty or not an RFC 3261 user part".into(),
        ));
    }
    if let Some(user) = cfg.user.as_ref() {
        verify_display_name(&user.display_name)?;
    }
    Ok(())
}

/// `user.display_name`: no CR, LF, NUL or other control characters and no
/// `<` / `>`, matching the GUI's manual-entry `validate_sip_component`, so a
/// provisioned name cannot inject or terminate a SIP header.
///
/// NIST 800-53 Rev5: SI-10 (information input validation).
fn verify_display_name(name: &str) -> Result<(), ProvisioningError> {
    if name.chars().any(char::is_control) {
        return Err(ProvisioningError::UntrustedEndpoint(
            "user.display_name contains control characters".into(),
        ));
    }
    if name.contains(['<', '>']) {
        return Err(ProvisioningError::UntrustedEndpoint(
            "user.display_name contains angle brackets".into(),
        ));
    }
    Ok(())
}

/// RFC 3261 §25.1 `user`: unreserved / escaped / user-unreserved, minus `;`
/// `?` `/` (refused so parameters and headers cannot be smuggled) and `:`
/// (password). Every `%` must start a valid `%HH` escape. Empty is refused.
fn is_sip_user(user: &str) -> bool {
    let b = user.as_bytes();
    if b.is_empty() {
        return false;
    }
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if c == b'%' {
            let hex = |j: usize| b.get(j).is_some_and(u8::is_ascii_hexdigit);
            if !(hex(i + 1) && hex(i + 2)) {
                return false;
            }
            i += 3;
            continue;
        }
        let ok = c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'_'
                    | b'.'
                    | b'!'
                    | b'~'
                    | b'*'
                    | b'\''
                    | b'('
                    | b')'
                    | b'&'
                    | b'='
                    | b'+'
                    | b'$'
                    | b','
            );
        if !ok {
            return false;
        }
        i += 1;
    }
    true
}

/// `registration.registrar_domain`: `host` or `host:port` in scope.
fn verify_registrar_domain(service: &ServiceDomain, reg: &str) -> Result<(), ProvisioningError> {
    let bad = |why: &str| ProvisioningError::UntrustedEndpoint(format!("registrar_domain: {why}"));
    if reg.is_empty() || reg.len() > MAX_DNS_NAME_LEN + 6 {
        return Err(bad("empty or too long"));
    }
    if !reg
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    {
        return Err(bad("must be a bare host or host:port"));
    }
    let host_part = match reg.split_once(':') {
        Some((h, p)) => {
            parse_port(p).ok_or_else(|| bad("invalid port"))?;
            h
        }
        None => reg,
    };
    let host = dns_host(host_part).map_err(bad)?;
    host_in_scope(&host, service.registrable()).map_err(bad)
}

/// A provisioned SIP URI: `sip:`/`sips:` scheme, optional user part, a DNS
/// host in scope and an optional port. Parameters and headers are refused
/// (RFC 3261 §19.1.1), as is more than one `@`, so the host is unambiguous.
fn verify_sip_uri(service: &ServiceDomain, name: &str, raw: &str) -> Result<(), ProvisioningError> {
    let bad = |why: &str| ProvisioningError::UntrustedEndpoint(format!("{name}: {why}"));
    if raw.is_empty() || raw.len() > MAX_SIP_URI_LEN {
        return Err(bad("empty or too long"));
    }
    let (scheme, rest) = raw.split_once(':').ok_or_else(|| bad("not a SIP URI"))?;
    if !(scheme.eq_ignore_ascii_case("sip") || scheme.eq_ignore_ascii_case("sips")) {
        return Err(bad("scheme must be sip or sips"));
    }
    let hostport = match rest.split_once('@') {
        Some((user, hostport)) => {
            if !is_sip_user(user) {
                return Err(bad("invalid user part"));
            }
            hostport
        }
        None => rest,
    };
    if !hostport
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
    {
        return Err(bad(
            "host must be a DNS name with an optional port, no parameters or headers",
        ));
    }
    let host_part = match hostport.split_once(':') {
        Some((h, p)) => {
            parse_port(p).ok_or_else(|| bad("invalid port"))?;
            h
        }
        None => hostport,
    };
    let host = dns_host(host_part).map_err(bad)?;
    host_in_scope(&host, service.registrable()).map_err(bad)
}

/// `Ok` when `host`'s registrable domain equals `scope`.
fn host_in_scope(host: &str, scope: &str) -> Result<(), &'static str> {
    match registrable_domain(host) {
        Some(r) if r == scope => Ok(()),
        Some(_) => Err("outside the service domain"),
        None => Err("is a public suffix"),
    }
}

/// Registrable domain of an OIDC issuer URL (https, no userinfo, query or
/// fragment, DNS host that is not a public suffix).
fn issuer_scope(issuer: &str) -> Result<String, ProvisioningError> {
    let host = issuer_host(issuer)
        .map_err(|why| ProvisioningError::UntrustedEndpoint(format!("issuer: {why}")))?;
    registrable_domain(&host).ok_or_else(|| {
        ProvisioningError::UntrustedEndpoint("issuer host is a public suffix".to_string())
    })
}

/// Checks an issuer URL as used by [`crate::ProvisioningClient::fetch_oidc_metadata`]
/// to build the metadata URL: https, no userinfo, DNS host, and no query or
/// fragment (OIDC Discovery 1.0 §2).
///
/// # Errors
/// [`ProvisioningError::IssuerNotTrusted`].
pub(crate) fn verify_issuer_url(issuer: &str) -> Result<(), ProvisioningError> {
    issuer_host(issuer)
        .map(drop)
        .map_err(ProvisioningError::IssuerNotTrusted)
}

/// Issuer half of [`verify_discovery`].
fn verify_issuer(service: &ServiceDomain, issuer: &str) -> Result<(), ProvisioningError> {
    let host = issuer_host(issuer).map_err(ProvisioningError::IssuerNotTrusted)?;
    if PINNED_ISSUERS
        .iter()
        .any(|(scope, pinned)| *scope == service.registrable() && *pinned == host)
    {
        return Ok(());
    }
    match registrable_domain(&host) {
        Some(r) if r == service.registrable() => Ok(()),
        _ => Err(ProvisioningError::IssuerNotTrusted(format!(
            "issuer host `{host}` is not under the entered domain `{}`",
            service.host()
        ))),
    }
}

/// Checks that `raw` is an https URL without userinfo whose DNS host's
/// registrable domain equals `scope`.
pub(crate) fn verify_endpoint_in_scope(
    name: &str,
    raw: &str,
    scope: &str,
) -> Result<(), ProvisioningError> {
    let host = https_dns_host(raw)
        .map_err(|why| ProvisioningError::UntrustedEndpoint(format!("{name}: {why}")))?;
    match registrable_domain(&host) {
        Some(r) if r == scope => Ok(()),
        _ => Err(ProvisioningError::UntrustedEndpoint(format!(
            "{name}: host `{host}` is outside `{scope}`"
        ))),
    }
}

/// [`https_dns_host`] plus no query or fragment (OIDC Discovery 1.0 §2).
fn issuer_host(raw: &str) -> Result<String, String> {
    let host = https_dns_host(raw)?;
    // `https_dns_host` already parsed `raw`; a second parse cannot fail.
    let url = Url::parse(raw).map_err(|e| format!("unparseable URL: {e}"))?;
    if url.query().is_some() || url.fragment().is_some() {
        return Err("issuer must not carry a query or fragment".to_string());
    }
    Ok(host)
}

/// Parses `raw` as an absolute https URL with no userinfo and a DNS host;
/// returns the lowercase host.
fn https_dns_host(raw: &str) -> Result<String, String> {
    if raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("URL contains control characters or whitespace".to_string());
    }
    let url = Url::parse(raw).map_err(|e| format!("unparseable URL: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!("must be https, got `{}`", url.scheme()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URL must not carry userinfo".to_string());
    }
    match url.host() {
        Some(Host::Domain(d)) => dns_host(d).map_err(str::to_string),
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => Err("IP-literal host not allowed".to_string()),
        None => Err("URL has no host".to_string()),
    }
}

/// Validates an LDH DNS name (RFC 1123 §2.1) and returns it lowercased. A
/// numeric final label is refused (IPv4-like).
fn dns_host(host: &str) -> Result<String, &'static str> {
    if host.is_empty() || host.len() > MAX_DNS_NAME_LEN {
        return Err("host name empty or too long");
    }
    let ldh = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_DNS_LABEL_LEN
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if !ldh {
        return Err("host name labels must be letters, digits and `-`");
    }
    if host
        .rsplit('.')
        .next()
        .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("IP-literal host not allowed");
    }
    Ok(host.to_ascii_lowercase())
}

/// Parses a decimal port in 1..=65535.
fn parse_port(p: &str) -> Option<u16> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    p.parse::<u16>().ok().filter(|port| *port != 0)
}

/// Registrable domain of a lowercase DNS host: one label plus the longest
/// matching [`PUBLIC_SUFFIXES`] entry (default: the TLD). `None` when the
/// host is itself a suffix or a single label.
fn registrable_domain(host: &str) -> Option<String> {
    let suffix_labels = PUBLIC_SUFFIXES
        .iter()
        .filter(|s| {
            host.strip_suffix(**s)
                .is_some_and(|prefix| prefix.is_empty() || prefix.ends_with('.'))
        })
        .map(|s| s.split('.').count())
        .max()
        .unwrap_or(1);
    let labels: Vec<&str> = host.split('.').collect();
    let start = labels.len().checked_sub(suffix_labels + 1)?;
    labels.get(start..).map(|l| l.join("."))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_same_registrable_domain() {
        verify_issuer_pinned("sbc.oopl.dev.mil", "https://icam.oopl.dev.mil/realms/dcim").unwrap();
    }

    #[test]
    fn accepts_when_domain_has_scheme_or_port() {
        verify_issuer_pinned("https://sbc.oopl.dev.mil:443", "https://idp.oopl.dev.mil/x").unwrap();
    }

    #[test]
    fn rejects_foreign_issuer() {
        let err = verify_issuer_pinned("sbc.oopl.dev.mil", "https://evil.example.com/realms/x")
            .unwrap_err();
        assert!(matches!(err, ProvisioningError::IssuerNotTrusted(_)));
    }

    #[test]
    fn registrable_domain_longest_suffix() {
        assert_eq!(
            registrable_domain("a.b.oopl.dev.mil").as_deref(),
            Some("oopl.dev.mil")
        );
        assert_eq!(
            registrable_domain("x.y.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(registrable_domain("dev.mil"), None);
        assert_eq!(registrable_domain("mil"), None);
        // Suffix match is label-aligned.
        assert_eq!(
            registrable_domain("sbc.xdev.mil").as_deref(),
            Some("xdev.mil")
        );
    }

    #[test]
    fn parse_port_bounds() {
        assert_eq!(parse_port("5061"), Some(5061));
        assert_eq!(parse_port("65535"), Some(65535));
        for p in ["", "0", "65536", "99999", "+1", "080a", "000001"] {
            assert_eq!(parse_port(p), None, "{p:?}");
        }
    }

    #[test]
    fn parse_rejects_numeric_hosts_and_empty_labels() {
        for input in [
            "sbc.0x7f",
            "0x7f.1",
            "sbc.oopl.dev.mil.",
            ".sbc.oopl.dev.mil",
            "sbc..dev.mil",
            "-sbc.oopl.dev.mil",
            "xn--bcher-kva.example.com:",
            "https://",
            "https:///",
        ] {
            assert!(
                matches!(
                    parse_service_domain(input),
                    Err(ProvisioningError::InvalidServiceDomain(_))
                ),
                "{input:?}"
            );
        }
    }

    #[test]
    fn rejects_non_https_issuer() {
        let err =
            verify_issuer_pinned("sbc.oopl.dev.mil", "http://icam.oopl.dev.mil/x").unwrap_err();
        assert!(matches!(err, ProvisioningError::IssuerNotTrusted(_)));
    }
}
