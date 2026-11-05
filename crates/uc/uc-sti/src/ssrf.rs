//! SSRF guard for attacker-supplied `x5u` / `info` URLs.
//!
//! The `info` parameter of an inbound Identity header is chosen by whoever
//! sent the INVITE. Before anything is dereferenced:
//!
//! - only `https://` is accepted (RFC 8224 §12, ATIS-1000074 §5.3.1),
//! - userinfo is refused, the port must be 443 unless the host is on the
//!   operator allow-list,
//! - every resolved address must be public: loopback, RFC 1918, CGNAT,
//!   link-local (incl. 169.254.169.254 metadata), multicast, ULA, reserved,
//!   documentation, Teredo, 6to4 relay and v4-mapped/NAT64/6to4 forms of
//!   those are refused,
//! - the connection goes to the vetted address (no second resolution, so no
//!   DNS-rebinding window).
//!
//! ## NIST 800-53 Rev5: SC-7 (Boundary Protection), SI-10

use crate::error::FetchError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Maximum accepted `x5u` length.
pub const MAX_URL_LEN: usize = 1024;

/// A parsed, policy-checked `https` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X5uUrl {
    /// Host (lower-cased; IPv6 literals without brackets).
    pub host: String,
    /// Port.
    pub port: u16,
    /// Path and query (starts with `/`).
    pub path: String,
}

impl X5uUrl {
    /// Parses and applies the URL-level policy.
    ///
    /// # Errors
    /// [`FetchError::Policy`] on any violation.
    pub fn parse(url: &str, allow_hosts: &[String]) -> Result<Self, FetchError> {
        if url.len() > MAX_URL_LEN || url.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return Err(FetchError::Policy("url-chars"));
        }
        let rest = url
            .get(..8)
            .filter(|p| p.eq_ignore_ascii_case("https://"))
            .and_then(|_| url.get(8..))
            .ok_or(FetchError::Policy("scheme"))?;
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.is_empty() || authority.contains('@') {
            return Err(FetchError::Policy("authority"));
        }
        let (host, port) = split_host_port(authority)?;
        let host = host.to_ascii_lowercase();
        let allow_listed = allow_hosts.iter().any(|h| h.eq_ignore_ascii_case(&host));
        if !allow_hosts.is_empty() && !allow_listed {
            return Err(FetchError::Policy("host-not-allowed"));
        }
        let port = port.unwrap_or(443);
        if port != 443 && !allow_listed {
            return Err(FetchError::Policy("port"));
        }
        if let Ok(ip) = host.parse::<IpAddr>()
            && is_forbidden_ip(ip)
        {
            return Err(FetchError::Policy("address"));
        }
        let tail = tail.split('#').next().unwrap_or("");
        let path = if tail.is_empty() || tail.starts_with('?') {
            format!("/{tail}")
        } else {
            tail.to_owned()
        };
        Ok(Self { host, port, path })
    }
}

fn split_host_port(authority: &str) -> Result<(&str, Option<u16>), FetchError> {
    let bad = FetchError::Policy("authority");
    if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or_else(|| bad.clone())?;
        if h.parse::<Ipv6Addr>().is_err() {
            return Err(bad);
        }
        return match after {
            "" => Ok((h, None)),
            p => Ok((
                h,
                Some(
                    p.strip_prefix(':')
                        .and_then(|p| p.parse().ok())
                        .ok_or(bad)?,
                ),
            )),
        };
    }
    let (h, p) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, Some(p.parse::<u16>().map_err(|_| bad.clone())?)),
        None => (authority, None),
    };
    if h.is_empty()
        || h.len() > 253
        || !h
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(bad);
    }
    Ok((h, p))
}

/// True if `ip` must never be contacted for an `x5u` fetch.
#[must_use]
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_v4(v4),
        IpAddr::V6(v6) => is_forbidden_v6(v6),
    }
}

fn is_forbidden_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local() // 169.254/16, includes cloud metadata
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..128).contains(&b)) // 100.64/10 CGNAT
        || (a == 192 && b == 0 && c == 0) // 192.0.0/24 IETF
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || (a == 192 && b == 88 && c == 99) // 192.88.99/24 6to4 relay anycast
        || a >= 240 // reserved
}

fn is_forbidden_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_forbidden_v4(v4);
    }
    let seg = ip.segments();
    // NAT64 well-known prefix 64:ff9b::/96: judge the embedded v4 address.
    if seg[0] == 0x64 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0] {
        let [a, b] = seg[6].to_be_bytes();
        let [c, d] = seg[7].to_be_bytes();
        let v4 = Ipv4Addr::new(a, b, c, d);
        return is_forbidden_v4(v4);
    }
    // 6to4 2002::/16 (RFC 3056): the next 32 bits are a v4 address the
    // relay would deliver to; judge it.
    if seg[0] == 0x2002 {
        let [a, b] = seg[1].to_be_bytes();
        let [c, d] = seg[2].to_be_bytes();
        return is_forbidden_v4(Ipv4Addr::new(a, b, c, d));
    }
    ip.is_unspecified()
        || (seg[0] == 0x2001 && seg[1] == 0) // Teredo 2001::/32 (tunnels to any v4)
        || ip.is_loopback()
        || ip.is_multicast()
        || (seg[0] & 0xfe00) == 0xfc00 // ULA fc00::/7
        || (seg[0] & 0xffc0) == 0xfe80 // link-local
        || (seg[0] & 0xffc0) == 0xfec0 // site-local (deprecated)
        || (seg[0] == 0x2001 && seg[1] == 0x0db8) // documentation
        || seg[..6] == [0, 0, 0, 0, 0, 0] // IPv4-compatible / reserved ::/96
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssrf_table() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a00:1",
            "ff02::1",
            "::127.0.0.1",
            "192.88.99.1",
            "2002:7f00:1::1",
            "2002:a9fe:a9fe::",
            "2002:c0a8:101::1",
            "2001:0:4136:e378::1",
        ] {
            assert!(
                is_forbidden_ip(ip.parse().unwrap()),
                "{ip} must be forbidden"
            );
        }
        for ip in [
            "8.8.8.8",
            "2606:4700::1111",
            "64:ff9b::808:808",
            "2002:808:808::1",
        ] {
            assert!(
                !is_forbidden_ip(ip.parse().unwrap()),
                "{ip} must be allowed"
            );
        }
    }

    #[test]
    fn url_policy() {
        let ok = X5uUrl::parse("https://Cert.Example.com/sti/a.pem?x=1", &[]).unwrap();
        assert_eq!(ok.host, "cert.example.com");
        assert_eq!(ok.port, 443);
        assert_eq!(ok.path, "/sti/a.pem?x=1");
        assert_eq!(X5uUrl::parse("https://h.example", &[]).unwrap().path, "/");
        let p = |u: &str| X5uUrl::parse(u, &[]).unwrap_err();
        assert_eq!(p("http://cert.example.com/a"), FetchError::Policy("scheme"));
        assert_eq!(
            p("https://cert.example.com:8443/a"),
            FetchError::Policy("port")
        );
        assert_eq!(
            p("https://u:p@cert.example.com/a"),
            FetchError::Policy("authority")
        );
        assert_eq!(p("https://127.0.0.1/a"), FetchError::Policy("address"));
        assert_eq!(
            p("https://[::ffff:127.0.0.1]/a"),
            FetchError::Policy("address")
        );
        assert_eq!(
            p("https://169.254.169.254/latest"),
            FetchError::Policy("address")
        );
        assert!(X5uUrl::parse("https://bad_host/a", &[]).is_err());
        assert!(X5uUrl::parse("https:///a", &[]).is_err());
        assert!(X5uUrl::parse("https://h.example/a\r\nb", &[]).is_err());
        let allow = vec!["cert.example.com".to_string()];
        assert!(X5uUrl::parse("https://other.example.com/a", &allow).is_err());
        assert_eq!(
            X5uUrl::parse("https://cert.example.com:8443/a", &allow)
                .unwrap()
                .port,
            8443
        );
    }
}
