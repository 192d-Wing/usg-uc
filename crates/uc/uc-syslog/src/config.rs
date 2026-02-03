//! Syslog configuration types.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Syslog configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyslogConfig {
    /// Enable syslog forwarding.
    pub enabled: bool,
    /// Syslog server address.
    pub server: SocketAddr,
    /// Transport protocol.
    pub transport: SyslogTransport,
    /// Application name.
    pub app_name: String,
    /// Hostname.
    pub hostname: Option<String>,
    /// Default facility.
    pub facility: u8,
    /// Include structured data.
    pub structured_data: bool,
    /// Use RFC 5424 format (vs BSD format).
    pub use_rfc5424: bool,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server: "127.0.0.1:514".parse().unwrap_or_else(|_| {
                SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 514)
            }),
            transport: SyslogTransport::Udp,
            app_name: "sbc".to_string(),
            hostname: None,
            facility: 16, // local0
            structured_data: true,
            use_rfc5424: true,
        }
    }
}

impl SyslogConfig {
    /// Creates a UDP syslog configuration.
    #[must_use]
    pub fn udp(server: SocketAddr) -> Self {
        Self {
            enabled: true,
            server,
            transport: SyslogTransport::Udp,
            ..Default::default()
        }
    }

    /// Creates a TCP syslog configuration.
    #[must_use]
    pub fn tcp(server: SocketAddr) -> Self {
        Self {
            enabled: true,
            server,
            transport: SyslogTransport::Tcp,
            ..Default::default()
        }
    }
}

/// Syslog transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyslogTransport {
    /// UDP transport.
    #[default]
    Udp,
    /// TCP transport.
    Tcp,
}

impl std::fmt::Display for SyslogTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp => write!(f, "udp"),
            Self::Tcp => write!(f, "tcp"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SyslogConfig::default();
        assert!(!config.enabled);
        assert!(matches!(config.transport, SyslogTransport::Udp));
        assert_eq!(config.app_name, "sbc");
    }

    #[test]
    fn test_udp_config() {
        let config = SyslogConfig::udp("192.168.1.100:514".parse().unwrap());
        assert!(config.enabled);
        assert!(matches!(config.transport, SyslogTransport::Udp));
    }

    #[test]
    fn test_tcp_config() {
        let config = SyslogConfig::tcp("192.168.1.100:514".parse().unwrap());
        assert!(config.enabled);
        assert!(matches!(config.transport, SyslogTransport::Tcp));
    }
}
