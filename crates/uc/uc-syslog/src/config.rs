//! Syslog configuration types.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// IANA port for syslog over TLS (RFC 5425 §4.1).
pub const SYSLOG_TLS_PORT: u16 = 6514;

/// Syslog configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// TLS settings; required when `transport` is `tls` and rejected
    /// otherwise.
    pub tls: Option<SyslogTlsConfig>,
}

/// RFC 5425 TLS client settings.
///
/// The server certificate is always verified against `ca_file` and
/// `server_name` (RFC 5425 §5.1, §5.2); there is no option to disable it.
///
/// NIST 800-53 Rev5: SC-8, AU-9 (protection of audit information in transit)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyslogTlsConfig {
    /// PEM file with the trust anchors for the collector certificate.
    pub ca_file: PathBuf,
    /// DNS name or IP address the collector certificate must match.
    ///
    /// POAM: POA&M-245 RFC 5425 §5.2.2 end-entity certificate fingerprint
    /// matching is not implemented; only certification-path validation
    /// against `ca_file` is supported. A self-signed collector must have
    /// its certificate placed in `ca_file` as a trust anchor. The RFC's
    /// mandatory SHA-1 fingerprint conflicts with CNSA 2.0, and a custom
    /// rustls verifier needs its own plan entry.
    pub server_name: String,
    /// Client certificate chain (PEM) for mutual authentication.
    #[serde(default)]
    pub client_cert: Option<PathBuf>,
    /// Client private key (PEM, P-384/P-521, mode 0600) for mutual
    /// authentication.
    #[serde(default)]
    pub client_key: Option<PathBuf>,
    /// Also offer TLS 1.2 (CNSA suites only). Default: TLS 1.3 only.
    #[serde(default)]
    pub allow_tls12: bool,
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
            tls: None,
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

    /// Creates an RFC 5425 TLS syslog configuration.
    ///
    /// RFC 5425 §4.1: a port of `0` in `server` is replaced with the
    /// IANA-assigned [`SYSLOG_TLS_PORT`] (6514).
    #[must_use]
    pub fn tls(mut server: SocketAddr, tls: SyslogTlsConfig) -> Self {
        if server.port() == 0 {
            server.set_port(SYSLOG_TLS_PORT);
        }
        Self {
            enabled: true,
            server,
            transport: SyslogTransport::Tls,
            use_rfc5424: true,
            tls: Some(tls),
            ..Default::default()
        }
    }
}

/// Syslog transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyslogTransport {
    /// UDP transport (RFC 5426). No protection in transit.
    #[default]
    Udp,
    /// TCP transport (LF-framed, RFC 6587 §3.4.2). No protection in transit.
    Tcp,
    /// TLS transport (RFC 5425, octet-counting framing).
    Tls,
}

impl std::fmt::Display for SyslogTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Udp => write!(f, "udp"),
            Self::Tcp => write!(f, "tcp"),
            Self::Tls => write!(f, "tls"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

    #[test]
    fn test_tls_transport_serde() {
        let t: SyslogTransport = serde_json::from_str("\"tls\"").unwrap();
        assert_eq!(t, SyslogTransport::Tls);
        assert_eq!(SyslogTransport::Tls.to_string(), "tls");
    }
}
