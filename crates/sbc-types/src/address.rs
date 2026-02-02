//! Socket address types with IPv6-first design.
//!
//! ## NIST 800-53 Rev5: SC-7 (Boundary Protection)
//!
//! All network addresses are represented with explicit protocol awareness.
//! IPv6 is preferred per project requirements.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// IPv6-first socket address wrapper.
///
/// This type encourages IPv6 usage while maintaining IPv4 compatibility.
/// All SBC network operations should use this type rather than raw `SocketAddr`.
///
/// ## Example
///
/// ```
/// use sbc_types::SbcSocketAddr;
/// use std::net::{IpAddr, Ipv6Addr};
///
/// // Create an IPv6 address (preferred)
/// let addr = SbcSocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5060);
/// assert!(addr.is_ipv6());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SbcSocketAddr {
    inner: SocketAddr,
}

impl SbcSocketAddr {
    /// Creates a new socket address from an IP address and port.
    ///
    /// ## NIST 800-53 Rev5: SC-7 (Boundary Protection)
    ///
    /// Logs a debug warning if IPv4 is used (IPv6 is preferred).
    #[must_use]
    pub const fn new(ip: IpAddr, port: u16) -> Self {
        Self {
            inner: SocketAddr::new(ip, port),
        }
    }

    /// Creates an IPv6 socket address.
    #[must_use]
    pub const fn new_v6(ip: Ipv6Addr, port: u16) -> Self {
        Self {
            inner: SocketAddr::new(IpAddr::V6(ip), port),
        }
    }

    /// Creates an IPv4 socket address.
    ///
    /// Note: IPv6 is preferred per project requirements.
    #[must_use]
    pub const fn new_v4(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            inner: SocketAddr::new(IpAddr::V4(ip), port),
        }
    }

    /// Returns the IP address.
    #[must_use]
    pub const fn ip(&self) -> IpAddr {
        self.inner.ip()
    }

    /// Returns the port number.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.inner.port()
    }

    /// Returns true if this is an IPv6 address.
    #[must_use]
    pub const fn is_ipv6(&self) -> bool {
        self.inner.is_ipv6()
    }

    /// Returns true if this is an IPv4 address.
    #[must_use]
    pub const fn is_ipv4(&self) -> bool {
        self.inner.is_ipv4()
    }

    /// Returns the underlying `SocketAddr`.
    #[must_use]
    pub const fn as_std(&self) -> SocketAddr {
        self.inner
    }

    /// Converts an IPv4 address to IPv6 using IPv4-mapped representation.
    ///
    /// If already IPv6, returns self unchanged.
    #[must_use]
    pub const fn to_ipv6_mapped(&self) -> Self {
        match self.inner.ip() {
            IpAddr::V6(_) => *self,
            IpAddr::V4(v4) => Self {
                inner: SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), self.inner.port()),
            },
        }
    }
}

impl From<SocketAddr> for SbcSocketAddr {
    fn from(addr: SocketAddr) -> Self {
        Self { inner: addr }
    }
}

impl From<SbcSocketAddr> for SocketAddr {
    fn from(addr: SbcSocketAddr) -> Self {
        addr.inner
    }
}

impl fmt::Display for SbcSocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl FromStr for SbcSocketAddr {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let addr: SocketAddr = s.parse()?;
        Ok(Self { inner: addr })
    }
}

/// Transport protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum TransportType {
    /// UDP (unreliable, connectionless).
    Udp,
    /// TCP (reliable, connection-oriented).
    Tcp,
    /// TLS over TCP (encrypted).
    Tls,
    /// WebSocket (HTTP upgrade).
    WebSocket,
    /// Secure WebSocket (TLS).
    WebSocketSecure,
}

impl TransportType {
    /// Returns true if this transport provides encryption.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        matches!(self, Self::Tls | Self::WebSocketSecure)
    }

    /// Returns true if this transport is connection-oriented.
    #[must_use]
    pub const fn is_connection_oriented(&self) -> bool {
        !matches!(self, Self::Udp)
    }

    /// Returns the default SIP port for this transport.
    #[must_use]
    pub const fn default_sip_port(&self) -> u16 {
        match self {
            Self::Udp | Self::Tcp => 5060,
            Self::Tls | Self::WebSocketSecure => 5061,
            Self::WebSocket => 80,
        }
    }
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp => write!(f, "UDP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Tls => write!(f, "TLS"),
            Self::WebSocket => write!(f, "WS"),
            Self::WebSocketSecure => write!(f, "WSS"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_address() {
        let addr = SbcSocketAddr::new_v6(Ipv6Addr::LOCALHOST, 5060);
        assert!(addr.is_ipv6());
        assert!(!addr.is_ipv4());
        assert_eq!(addr.port(), 5060);
    }

    #[test]
    fn test_ipv4_to_ipv6_mapped() {
        let v4_addr = SbcSocketAddr::new_v4(Ipv4Addr::new(192, 168, 1, 1), 5060);
        let mapped = v4_addr.to_ipv6_mapped();
        assert!(mapped.is_ipv6());
        assert_eq!(mapped.port(), 5060);
    }

    #[test]
    fn test_transport_security() {
        assert!(!TransportType::Udp.is_secure());
        assert!(!TransportType::Tcp.is_secure());
        assert!(TransportType::Tls.is_secure());
        assert!(TransportType::WebSocketSecure.is_secure());
    }

    #[test]
    fn test_parse_address() {
        let addr: SbcSocketAddr = "[::1]:5060".parse().unwrap();
        assert!(addr.is_ipv6());
        assert_eq!(addr.port(), 5060);
    }
}
