//! Shared HTTP helpers for the SBC's front-facing pods.
//!
//! Both `sbc-api-server` (login rate limiter) and
//! `sbc-provision-server` (SC-7 source allowlist) sit behind the same
//! frontend nginx and need the *real* client IP for a security
//! decision. This crate is the single place that logic lives so the two
//! entry points can't drift apart.
//!
//! ## NIST 800-53 Rev5 Controls
//!
//! - **SC-7**: Boundary Protection (trusted-proxy verification)

use std::net::IpAddr;

use http::HeaderMap;
use ipnet::IpNet;

/// Parse a comma-separated list of CIDRs (as used for the
/// `SBC_TRUSTED_PROXIES` / `SBC_PROVISION_ALLOWED_CIDRS` env vars).
///
/// Whitespace around entries and empty entries are ignored, so an unset
/// or blank var yields an empty list. On a malformed entry the error
/// carries the offending token for diagnostics.
///
/// # Errors
///
/// Returns the offending entry and the parse error when any element is
/// not a valid CIDR / IP.
pub fn parse_cidr_list(raw: &str) -> Result<Vec<IpNet>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<IpNet>().map_err(|e| format!("{s}: {e}")))
        .collect()
}

/// Resolve the effective client IP for a request that may have arrived
/// through the frontend nginx.
///
/// nginx is configured with `proxy_set_header X-Real-IP $remote_addr`,
/// which *overwrites* any client-supplied `X-Real-IP` with the TCP peer
/// nginx itself sees — so the header is trustworthy, **but only when the
/// request actually came from nginx**. A caller connecting directly to
/// the pod (bypassing nginx, e.g. another workload on the cluster
/// network) can set `X-Real-IP` to anything.
///
/// Therefore:
///
/// - When `trusted_proxies` is non-empty, `X-Real-IP` is honored **only**
///   if the direct peer (`peer`) is within one of those networks;
///   otherwise the header is ignored and `peer` is returned, so a direct
///   caller cannot spoof its address.
/// - When `trusted_proxies` is empty, proxy verification is disabled and
///   `X-Real-IP` is honored unconditionally (preserving the historical
///   behavior). Front-facing pods should log a startup warning in this
///   case and operators should set the trusted-proxy list to the nginx
///   pod network.
///
/// Falls back to `peer` whenever the header is absent or unparseable.
#[must_use]
pub fn resolve_client_ip(headers: &HeaderMap, peer: IpAddr, trusted_proxies: &[IpNet]) -> IpAddr {
    let trust_header =
        trusted_proxies.is_empty() || trusted_proxies.iter().any(|net| net.contains(&peer));
    if trust_header
        && let Some(ip) = headers
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return ip;
    }
    peer
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn hdrs(x_real_ip: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = x_real_ip {
            h.insert("x-real-ip", v.parse().unwrap());
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn parse_cidr_list_handles_blanks_and_errors() {
        assert!(parse_cidr_list("").unwrap().is_empty());
        assert!(parse_cidr_list("  ,  ").unwrap().is_empty());
        let ok = parse_cidr_list("10.0.0.0/8, 192.168.1.0/24 ,::1/128").unwrap();
        assert_eq!(ok.len(), 3);
        assert!(parse_cidr_list("10.0.0.0/8, nonsense").is_err());
    }

    #[test]
    fn empty_trusted_list_honors_header_unconditionally() {
        // Verification disabled: header is trusted even from an
        // arbitrary peer (historical behavior).
        let got = resolve_client_ip(&hdrs(Some("203.0.113.7")), ip("10.9.9.9"), &[]);
        assert_eq!(got, ip("203.0.113.7"));
    }

    #[test]
    fn trusted_peer_honors_header() {
        let proxies = [net("10.0.0.0/8")];
        let got = resolve_client_ip(&hdrs(Some("203.0.113.7")), ip("10.1.2.3"), &proxies);
        assert_eq!(got, ip("203.0.113.7"));
    }

    #[test]
    fn untrusted_peer_ignores_header_and_returns_peer() {
        // A direct caller not in the trusted-proxy set cannot spoof its
        // address: the forged X-Real-IP is discarded.
        let proxies = [net("10.0.0.0/8")];
        let got = resolve_client_ip(&hdrs(Some("10.1.2.3")), ip("198.51.100.9"), &proxies);
        assert_eq!(got, ip("198.51.100.9"));
    }

    #[test]
    fn missing_header_falls_back_to_peer() {
        let proxies = [net("10.0.0.0/8")];
        let got = resolve_client_ip(&hdrs(None), ip("10.1.2.3"), &proxies);
        assert_eq!(got, ip("10.1.2.3"));
    }

    #[test]
    fn malformed_header_falls_back_to_peer() {
        let got = resolve_client_ip(&hdrs(Some("not-an-ip")), ip("10.1.2.3"), &[]);
        assert_eq!(got, ip("10.1.2.3"));
    }
}
