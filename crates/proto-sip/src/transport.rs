//! SIP transport definitions per RFC 3261.
//!
//! Defines valid transport protocols for SIP messages.
//!
//! # Safety-Critical Code Compliance (Power of 10)
//!
//! - All functions have bounded execution
//! - No recursion is used

use crate::error::{SipError, SipResult};
use std::fmt;
use std::str::FromStr;

/// SIP transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// UDP transport (RFC 3261).
    Udp,
    /// TCP transport (RFC 3261).
    Tcp,
    /// TLS over TCP (RFC 3261).
    Tls,
    /// SCTP transport (RFC 4168).
    Sctp,
    /// WebSocket transport (RFC 7118).
    Ws,
    /// Secure WebSocket transport (RFC 7118).
    Wss,
    /// DTLS over UDP (RFC 4347).
    DtlsUdp,
}

impl Transport {
    /// Returns the transport name for use in Via headers.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
            Self::Tls => "TLS",
            Self::Sctp => "SCTP",
            Self::Ws => "WS",
            Self::Wss => "WSS",
            Self::DtlsUdp => "DTLS-UDP",
        }
    }

    /// Returns true if this transport is reliable (connection-oriented).
    #[must_use]
    pub fn is_reliable(&self) -> bool {
        matches!(self, Self::Tcp | Self::Tls | Self::Sctp | Self::Ws | Self::Wss)
    }

    /// Returns true if this transport provides encryption.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        matches!(self, Self::Tls | Self::Wss | Self::DtlsUdp)
    }

    /// Returns the default port for this transport.
    ///
    /// RFC 3261: UDP/TCP/SCTP use 5060, TLS uses 5061
    /// RFC 7118: WS uses 80, WSS uses 443
    /// DTLS-UDP uses 5061 (same as TLS)
    #[must_use]
    pub fn default_port(&self) -> u16 {
        match self {
            Self::Udp | Self::Tcp | Self::Sctp => 5060,
            Self::Tls | Self::DtlsUdp => 5061,
            Self::Ws => 80,
            Self::Wss => 443,
        }
    }

    /// Returns true if this is a valid RFC 3261 core transport.
    #[must_use]
    pub fn is_rfc3261_core(&self) -> bool {
        matches!(self, Self::Udp | Self::Tcp | Self::Tls)
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Transport {
    type Err = SipError;

    fn from_str(s: &str) -> SipResult<Self> {
        match s.to_uppercase().as_str() {
            "UDP" => Ok(Self::Udp),
            "TCP" => Ok(Self::Tcp),
            "TLS" => Ok(Self::Tls),
            "SCTP" => Ok(Self::Sctp),
            "WS" => Ok(Self::Ws),
            "WSS" => Ok(Self::Wss),
            "DTLS-UDP" | "DTLS" => Ok(Self::DtlsUdp),
            _ => Err(SipError::InvalidHeader {
                name: "transport".to_string(),
                reason: format!("unknown transport: {s}"),
            }),
        }
    }
}

/// Validates a transport parameter value.
///
/// # Errors
///
/// Returns an error if the transport is not recognized.
pub fn validate_transport(transport: &str) -> SipResult<Transport> {
    transport.parse()
}

/// Returns all standard SIP transports.
#[must_use]
pub fn all_transports() -> &'static [Transport] {
    &[
        Transport::Udp,
        Transport::Tcp,
        Transport::Tls,
        Transport::Sctp,
        Transport::Ws,
        Transport::Wss,
        Transport::DtlsUdp,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_parse() {
        assert_eq!("UDP".parse::<Transport>().unwrap(), Transport::Udp);
        assert_eq!("tcp".parse::<Transport>().unwrap(), Transport::Tcp);
        assert_eq!("TLS".parse::<Transport>().unwrap(), Transport::Tls);
        assert_eq!("WS".parse::<Transport>().unwrap(), Transport::Ws);
        assert_eq!("WSS".parse::<Transport>().unwrap(), Transport::Wss);
    }

    #[test]
    fn test_transport_display() {
        assert_eq!(Transport::Udp.to_string(), "UDP");
        assert_eq!(Transport::Tcp.to_string(), "TCP");
        assert_eq!(Transport::Tls.to_string(), "TLS");
    }

    #[test]
    fn test_transport_properties() {
        assert!(!Transport::Udp.is_reliable());
        assert!(Transport::Tcp.is_reliable());
        assert!(Transport::Tls.is_reliable());

        assert!(!Transport::Udp.is_secure());
        assert!(!Transport::Tcp.is_secure());
        assert!(Transport::Tls.is_secure());
        assert!(Transport::Wss.is_secure());
    }

    #[test]
    fn test_transport_default_port() {
        // RFC 3261 transports
        assert_eq!(Transport::Udp.default_port(), 5060);
        assert_eq!(Transport::Tcp.default_port(), 5060);
        assert_eq!(Transport::Tls.default_port(), 5061);
        assert_eq!(Transport::Sctp.default_port(), 5060);
        assert_eq!(Transport::DtlsUdp.default_port(), 5061);
        // RFC 7118 WebSocket transports
        assert_eq!(Transport::Ws.default_port(), 80);
        assert_eq!(Transport::Wss.default_port(), 443);
    }

    #[test]
    fn test_invalid_transport() {
        assert!("INVALID".parse::<Transport>().is_err());
    }
}
