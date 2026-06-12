//! Issuer pinning — the trust bootstrap for the sign-in flow.
//!
//! Discovery is unauthenticated, so a compromised or spoofed POP could point
//! the client at an attacker-controlled IdP. Per the design doc (Security
//! Considerations → "Issuer pinning"), the discovery document's `issuer` host
//! MUST share the registrable domain of the service domain the user typed, or
//! be on a build-time allowlist. This check runs **before** any browser is
//! opened or token endpoint is contacted.

use url::Url;

use crate::error::ProvisioningError;

/// Issuers always accepted regardless of the entered service domain (known
/// first-party IdPs). Keep this short and exact.
const PINNED_ISSUER_HOSTS: &[&str] = &["icam.oopl.dev.mil"];

/// Verifies that `issuer` is trustworthy for a client that entered
/// `service_domain`.
///
/// Accepts when the issuer host is on [`PINNED_ISSUER_HOSTS`], or shares the
/// registrable domain (eTLD+1, approximated as the last two labels) with the
/// service domain. Rejects non-HTTPS issuers outright.
///
/// # Errors
/// [`ProvisioningError::IssuerNotTrusted`] when the issuer is not HTTPS or its
/// registrable domain differs from the entered service domain.
pub fn verify_issuer_pinned(
    service_domain: &str,
    issuer: &str,
) -> Result<(), ProvisioningError> {
    let url = Url::parse(issuer)
        .map_err(|e| ProvisioningError::IssuerNotTrusted(format!("unparseable issuer: {e}")))?;
    if url.scheme() != "https" {
        return Err(ProvisioningError::IssuerNotTrusted(format!(
            "issuer must be https, got `{}`",
            url.scheme()
        )));
    }
    let issuer_host = url
        .host_str()
        .ok_or_else(|| ProvisioningError::IssuerNotTrusted("issuer has no host".to_string()))?;

    if PINNED_ISSUER_HOSTS
        .iter()
        .any(|h| h.eq_ignore_ascii_case(issuer_host))
    {
        return Ok(());
    }

    // Strip a possible scheme/port the caller may have included in the
    // "domain" and compare registrable domains.
    let service_host = service_domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(service_domain)
        .split(':')
        .next()
        .unwrap_or(service_domain);

    if registrable_domain(issuer_host).eq_ignore_ascii_case(&registrable_domain(service_host)) {
        Ok(())
    } else {
        Err(ProvisioningError::IssuerNotTrusted(format!(
            "issuer host `{issuer_host}` is not under the entered domain `{service_host}`"
        )))
    }
}

/// Approximate registrable domain (eTLD+1) as the last two dot-labels. This
/// is intentionally conservative — adequate for the simple `.mil` / `.dev.mil`
/// style hosts this fleet uses; combine with [`PINNED_ISSUER_HOSTS`] for
/// anything that needs the full public-suffix list.
fn registrable_domain(host: &str) -> String {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    let n = labels.len();
    if n >= 2 {
        format!("{}.{}", labels[n - 2], labels[n - 1])
    } else {
        host.to_string()
    }
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
    fn rejects_non_https_issuer() {
        let err =
            verify_issuer_pinned("sbc.oopl.dev.mil", "http://icam.oopl.dev.mil/x").unwrap_err();
        assert!(matches!(err, ProvisioningError::IssuerNotTrusted(_)));
    }
}
