//! DNS configuration.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// DNS resolver configuration.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// DNS server addresses.
    pub servers: Vec<SocketAddr>,

    /// Query timeout.
    pub timeout: Duration,

    /// Number of retries.
    pub retries: u32,

    /// Enable caching.
    pub cache_enabled: bool,

    /// Maximum cache entries.
    pub cache_max_entries: usize,

    /// Minimum TTL to cache (overrides lower TTLs).
    pub cache_min_ttl: Duration,

    /// Maximum TTL to cache (overrides higher TTLs).
    pub cache_max_ttl: Duration,

    /// Negative cache TTL (for NXDOMAIN responses).
    pub cache_negative_ttl: Duration,

    /// ENUM configuration.
    pub enum_config: EnumConfig,

    /// SIP resolver configuration.
    pub sip_config: SipResolverConfig,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
            ],
            timeout: Duration::from_secs(5),
            retries: 2,
            cache_enabled: true,
            cache_max_entries: 10000,
            cache_min_ttl: Duration::from_secs(60),
            cache_max_ttl: Duration::from_secs(86400), // 24 hours
            cache_negative_ttl: Duration::from_secs(300), // 5 minutes
            enum_config: EnumConfig::default(),
            sip_config: SipResolverConfig::default(),
        }
    }
}

/// ENUM (E.164 to URI) configuration.
#[derive(Debug, Clone)]
pub struct EnumConfig {
    /// ENUM domain suffixes to query.
    pub domains: Vec<String>,

    /// Preferred services (in order of preference).
    pub preferred_services: Vec<String>,

    /// Enable ENUM lookups.
    pub enabled: bool,
}

impl Default for EnumConfig {
    fn default() -> Self {
        Self {
            domains: vec!["e164.arpa".to_string(), "e164.org".to_string()],
            preferred_services: vec![
                "E2U+sip".to_string(),
                "E2U+h323".to_string(),
                "E2U+email:mailto".to_string(),
            ],
            enabled: true,
        }
    }
}

/// SIP DNS resolver configuration per RFC 3263.
#[derive(Debug, Clone)]
pub struct SipResolverConfig {
    /// Transport preference order.
    pub transport_preference: Vec<TransportPref>,

    /// Use NAPTR for transport selection.
    pub use_naptr: bool,

    /// Use SRV for server selection.
    pub use_srv: bool,

    /// Fallback to A/AAAA if SRV not found.
    pub fallback_to_address: bool,

    /// Default port for each transport.
    pub default_ports: DefaultPorts,
}

impl Default for SipResolverConfig {
    fn default() -> Self {
        Self {
            transport_preference: vec![TransportPref::Tls, TransportPref::Tcp, TransportPref::Udp],
            use_naptr: true,
            use_srv: true,
            fallback_to_address: true,
            default_ports: DefaultPorts::default(),
        }
    }
}

/// Transport preference for SIP routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportPref {
    /// UDP transport.
    Udp,
    /// TCP transport.
    Tcp,
    /// TLS transport.
    Tls,
    /// SCTP transport.
    Sctp,
    /// WebSocket transport.
    WebSocket,
    /// Secure WebSocket transport.
    WebSocketSecure,
}

impl TransportPref {
    /// Returns the NAPTR service field for this transport.
    #[must_use]
    pub const fn naptr_service(&self) -> &'static str {
        match self {
            Self::Udp => "SIP+D2U",
            Self::Tcp => "SIP+D2T",
            Self::Tls => "SIPS+D2T",
            Self::Sctp => "SIP+D2S",
            Self::WebSocket => "SIP+D2W",
            Self::WebSocketSecure => "SIPS+D2W",
        }
    }

    /// Returns the SRV prefix for this transport.
    #[must_use]
    pub const fn srv_prefix(&self) -> &'static str {
        match self {
            Self::Udp => "_sip._udp",
            Self::Tcp => "_sip._tcp",
            Self::Tls => "_sips._tcp",
            Self::Sctp => "_sip._sctp",
            Self::WebSocket => "_sip._ws",
            Self::WebSocketSecure => "_sips._wss",
        }
    }
}

impl std::fmt::Display for TransportPref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp => write!(f, "UDP"),
            Self::Tcp => write!(f, "TCP"),
            Self::Tls => write!(f, "TLS"),
            Self::Sctp => write!(f, "SCTP"),
            Self::WebSocket => write!(f, "WS"),
            Self::WebSocketSecure => write!(f, "WSS"),
        }
    }
}

/// Default ports for each transport.
#[derive(Debug, Clone)]
pub struct DefaultPorts {
    /// UDP port.
    pub udp: u16,
    /// TCP port.
    pub tcp: u16,
    /// TLS port.
    pub tls: u16,
    /// SCTP port.
    pub sctp: u16,
    /// WebSocket port.
    pub websocket: u16,
    /// Secure WebSocket port.
    pub websocket_secure: u16,
}

impl Default for DefaultPorts {
    fn default() -> Self {
        Self {
            udp: 5060,
            tcp: 5060,
            tls: 5061,
            sctp: 5060,
            websocket: 80,
            websocket_secure: 443,
        }
    }
}

impl DefaultPorts {
    /// Gets the default port for a transport.
    #[must_use]
    pub const fn for_transport(&self, transport: TransportPref) -> u16 {
        match transport {
            TransportPref::Udp => self.udp,
            TransportPref::Tcp => self.tcp,
            TransportPref::Tls => self.tls,
            TransportPref::Sctp => self.sctp,
            TransportPref::WebSocket => self.websocket,
            TransportPref::WebSocketSecure => self.websocket_secure,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = DnsConfig::default();
        assert!(config.cache_enabled);
        assert_eq!(config.retries, 2);
        assert!(!config.servers.is_empty());
    }

    #[test]
    fn test_transport_pref() {
        assert_eq!(TransportPref::Tls.naptr_service(), "SIPS+D2T");
        assert_eq!(TransportPref::Udp.srv_prefix(), "_sip._udp");
        assert_eq!(TransportPref::Tcp.to_string(), "TCP");
    }

    #[test]
    fn test_default_ports() {
        let ports = DefaultPorts::default();
        assert_eq!(ports.for_transport(TransportPref::Udp), 5060);
        assert_eq!(ports.for_transport(TransportPref::Tls), 5061);
    }
}
