//! Minimal IP prefix (CIDR) type used by topology hiding.
//!
//! POAM: POA&M-151 - replaces string-prefix matching (`"10."` matched
//! `10.example.com`) with typed address/prefix matching.
//!
//! NIST 800-53 Rev5: SC-7 (Boundary Protection).

use crate::error::{SipError, SipResult};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// An IPv4 or IPv6 network prefix, e.g. `10.0.0.0/8` or `fc00::/7`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpCidr {
    addr: IpAddr,
    prefix: u8,
}

impl IpCidr {
    /// Creates a prefix; host bits of `addr` are masked off.
    ///
    /// # Errors
    /// Returns [`SipError::ParseError`] if `prefix` exceeds 32 (IPv4) or 128
    /// (IPv6).
    pub fn new(addr: IpAddr, prefix: u8) -> SipResult<Self> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(SipError::ParseError {
                reason: "CIDR prefix length out of range".to_string(),
            });
        }
        let addr = match addr {
            IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask32(prefix))),
            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask128(prefix))),
        };
        Ok(Self { addr, prefix })
    }

    /// Network address.
    #[must_use]
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// Prefix length.
    #[must_use]
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Returns true if `ip` is inside this prefix. IPv4-mapped IPv6
    /// addresses (`::ffff:a.b.c.d`) are matched against IPv4 prefixes.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, normalize(ip)) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                u32::from(a) & mask32(self.prefix) == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                u128::from(a) & mask128(self.prefix) == u128::from(net)
            }
            _ => false,
        }
    }
}

/// Maps IPv4-mapped (`::ffff:a.b.c.d`, RFC 4291 §2.5.5.2) and deprecated
/// IPv4-compatible (`::a.b.c.d`, excluding `::` and `::1`) addresses to IPv4
/// so they cannot bypass IPv4 rules.
#[must_use]
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let bits = u128::from(v6);
            if bits >> 32 == 0 && bits > 1 {
                // Fits in 32 bits by the shift check above.
                return IpAddr::V4(Ipv4Addr::from(u32::try_from(bits).unwrap_or(0)));
            }
            ip
        }
        IpAddr::V4(_) => ip,
    }
}

fn mask32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn mask128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

impl FromStr for IpCidr {
    type Err = SipError;

    /// Parses `addr/prefix` or a bare address (full-length prefix).
    fn from_str(s: &str) -> SipResult<Self> {
        let bad = || SipError::ParseError {
            reason: "invalid CIDR".to_string(),
        };
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().map_err(|_| bad())?;
        let prefix = match p {
            None => {
                if addr.is_ipv4() {
                    32
                } else {
                    128
                }
            }
            Some(p) => {
                if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(bad());
                }
                p.parse::<u8>().map_err(|_| bad())?
            }
        };
        Self::new(addr, prefix)
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn c(s: &str) -> IpCidr {
        s.parse().unwrap()
    }

    // POAM-151
    #[test]
    fn parse_rejects_bad() {
        for s in [
            "10.0.0.0/33",
            "::/129",
            "10.0.0.0/8x",
            "garbage",
            "10.0.0.0/",
            "/8",
        ] {
            assert!(s.parse::<IpCidr>().is_err(), "{s}");
        }
    }

    #[test]
    fn contains() {
        assert!(c("100.64.0.0/10").contains("100.127.255.255".parse().unwrap()));
        assert!(!c("100.64.0.0/10").contains("100.128.0.1".parse().unwrap()));
        assert!(c("fc00::/7").contains("fd12::1".parse().unwrap()));
        assert!(!c("fc00::/7").contains("fbff::1".parse().unwrap()));
        assert!(c("10.0.0.0/8").contains("::ffff:10.0.0.1".parse().unwrap()));
        assert!(c("0.0.0.0/0").contains("1.2.3.4".parse().unwrap()));
        assert_eq!(c("10.1.2.3/8").to_string(), "10.0.0.0/8");
    }
}
