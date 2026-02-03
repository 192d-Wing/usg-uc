//! IP network and CIDR matching.

use crate::error::{AclError, AclResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP network (CIDR notation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpNetwork {
    /// Network address.
    addr: IpAddr,
    /// Prefix length.
    prefix: u8,
}

impl IpNetwork {
    /// Creates a new IPv4 network.
    pub fn v4(addr: Ipv4Addr, prefix: u8) -> AclResult<Self> {
        if prefix > 32 {
            return Err(AclError::InvalidPrefix { prefix, max: 32 });
        }
        Ok(Self {
            addr: IpAddr::V4(addr),
            prefix,
        })
    }

    /// Creates a new IPv6 network.
    pub fn v6(addr: Ipv6Addr, prefix: u8) -> AclResult<Self> {
        if prefix > 128 {
            return Err(AclError::InvalidPrefix { prefix, max: 128 });
        }
        Ok(Self {
            addr: IpAddr::V6(addr),
            prefix,
        })
    }

    /// Creates a network from an IP address and prefix.
    pub fn new(addr: IpAddr, prefix: u8) -> AclResult<Self> {
        match addr {
            IpAddr::V4(v4) => Self::v4(v4, prefix),
            IpAddr::V6(v6) => Self::v6(v6, prefix),
        }
    }

    /// Creates a single host network (/32 or /128).
    pub fn host(addr: IpAddr) -> Self {
        let prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self { addr, prefix }
    }

    /// Parses from CIDR notation (e.g., "192.168.1.0/24").
    pub fn parse(s: &str) -> AclResult<Self> {
        if let Some(pos) = s.find('/') {
            let addr_str = &s[..pos];
            let prefix_str = &s[pos + 1..];

            let addr: IpAddr = addr_str.parse().map_err(|_| AclError::InvalidIpAddress {
                address: addr_str.to_string(),
            })?;

            let prefix: u8 = prefix_str.parse().map_err(|_| AclError::InvalidNetwork {
                network: s.to_string(),
                reason: "invalid prefix".to_string(),
            })?;

            Self::new(addr, prefix)
        } else {
            // No prefix, treat as host
            let addr: IpAddr = s.parse().map_err(|_| AclError::InvalidIpAddress {
                address: s.to_string(),
            })?;
            Ok(Self::host(addr))
        }
    }

    /// Returns the network address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// Returns the prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Checks if an IP address is contained in this network.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => self.contains_v4(net, ip),
            (IpAddr::V6(net), IpAddr::V6(ip)) => self.contains_v6(net, ip),
            _ => false, // v4/v6 mismatch
        }
    }

    /// Checks IPv4 containment.
    fn contains_v4(&self, net: Ipv4Addr, ip: Ipv4Addr) -> bool {
        if self.prefix == 0 {
            return true;
        }
        if self.prefix >= 32 {
            return net == ip;
        }

        let net_bits = u32::from_be_bytes(net.octets());
        let ip_bits = u32::from_be_bytes(ip.octets());
        let mask = !0u32 << (32 - self.prefix);

        (net_bits & mask) == (ip_bits & mask)
    }

    /// Checks IPv6 containment.
    fn contains_v6(&self, net: Ipv6Addr, ip: Ipv6Addr) -> bool {
        if self.prefix == 0 {
            return true;
        }
        if self.prefix >= 128 {
            return net == ip;
        }

        let net_bits = u128::from_be_bytes(net.octets());
        let ip_bits = u128::from_be_bytes(ip.octets());
        let mask = !0u128 << (128 - self.prefix);

        (net_bits & mask) == (ip_bits & mask)
    }

    /// Returns whether this is an IPv4 network.
    pub fn is_ipv4(&self) -> bool {
        matches!(self.addr, IpAddr::V4(_))
    }

    /// Returns whether this is an IPv6 network.
    pub fn is_ipv6(&self) -> bool {
        matches!(self.addr, IpAddr::V6(_))
    }

    /// Returns whether this is a single host.
    pub fn is_host(&self) -> bool {
        match self.addr {
            IpAddr::V4(_) => self.prefix == 32,
            IpAddr::V6(_) => self.prefix == 128,
        }
    }
}

impl std::fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Network match trait.
pub trait NetworkMatch {
    /// Checks if this matches the given IP address.
    fn matches(&self, addr: IpAddr) -> bool;
}

impl NetworkMatch for IpNetwork {
    fn matches(&self, addr: IpAddr) -> bool {
        self.contains(addr)
    }
}

impl NetworkMatch for IpAddr {
    fn matches(&self, addr: IpAddr) -> bool {
        *self == addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_network() {
        let net = IpNetwork::v4(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        assert!(net.is_ipv4());
        assert!(!net.is_ipv6());
        assert!(!net.is_host());
    }

    #[test]
    fn test_ipv4_containment() {
        let net = IpNetwork::v4(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();

        // In network
        assert!(net.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(net.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))));

        // Not in network
        assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));
        assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));

        // IPv6 doesn't match
        assert!(!net.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_ipv4_host() {
        let host = IpNetwork::host(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert!(host.is_host());
        assert!(host.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(!host.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
    }

    #[test]
    fn test_ipv6_network() {
        let net = IpNetwork::v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32).unwrap();
        assert!(net.is_ipv6());

        assert!(net.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        assert!(net.contains(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0xffff, 0xffff, 0, 0, 0, 1
        ))));
        assert!(!net.contains(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_parse_cidr() {
        let net = IpNetwork::parse("10.0.0.0/8").unwrap();
        assert_eq!(net.addr(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(net.prefix(), 8);
    }

    #[test]
    fn test_parse_host() {
        let net = IpNetwork::parse("192.168.1.100").unwrap();
        assert!(net.is_host());
        assert_eq!(net.prefix(), 32);
    }

    #[test]
    fn test_parse_ipv6() {
        let net = IpNetwork::parse("2001:db8::/32").unwrap();
        assert!(net.is_ipv6());
        assert_eq!(net.prefix(), 32);
    }

    #[test]
    fn test_invalid_prefix() {
        assert!(IpNetwork::v4(Ipv4Addr::new(192, 168, 1, 0), 33).is_err());
        assert!(IpNetwork::v6(Ipv6Addr::LOCALHOST, 129).is_err());
    }

    #[test]
    fn test_invalid_parse() {
        assert!(IpNetwork::parse("invalid").is_err());
        assert!(IpNetwork::parse("192.168.1.0/abc").is_err());
    }

    #[test]
    fn test_display() {
        let net = IpNetwork::v4(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        assert_eq!(net.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn test_zero_prefix() {
        let net = IpNetwork::v4(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap();
        // 0.0.0.0/0 matches everything
        assert!(net.contains(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(net.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_network_match_trait() {
        let net = IpNetwork::parse("192.168.1.0/24").unwrap();
        let addr: IpAddr = "192.168.1.100".parse().unwrap();

        assert!(net.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(addr.matches(addr));
    }
}
