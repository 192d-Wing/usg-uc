//! SDP media description per RFC 4566.

use crate::attribute::{Attribute, AttributeName, Direction};
use crate::error::{SdpError, SdpResult};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// Media type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaType {
    /// Audio media.
    Audio,
    /// Video media.
    Video,
    /// Text media.
    Text,
    /// Application data.
    Application,
    /// Message (for MSRP).
    Message,
}

impl MediaType {
    /// Returns the media type string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Text => "text",
            Self::Application => "application",
            Self::Message => "message",
        }
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for MediaType {
    type Err = SdpError;

    fn from_str(s: &str) -> SdpResult<Self> {
        match s.to_lowercase().as_str() {
            "audio" => Ok(Self::Audio),
            "video" => Ok(Self::Video),
            "text" => Ok(Self::Text),
            "application" => Ok(Self::Application),
            "message" => Ok(Self::Message),
            _ => Err(SdpError::InvalidMedia {
                reason: format!("unknown media type: {s}"),
            }),
        }
    }
}

/// Transport protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    /// RTP/AVP (RFC 3551).
    RtpAvp,
    /// RTP/SAVP (SRTP, RFC 3711).
    RtpSavp,
    /// RTP/AVPF (feedback, RFC 4585).
    RtpAvpf,
    /// RTP/SAVPF (SRTP with feedback).
    RtpSavpf,
    /// UDP/TLS/RTP/SAVP (DTLS-SRTP).
    UdpTlsRtpSavp,
    /// UDP/TLS/RTP/SAVPF (DTLS-SRTP with feedback).
    UdpTlsRtpSavpf,
    /// UDP (raw UDP).
    Udp,
    /// TCP (raw TCP).
    Tcp,
}

impl TransportProtocol {
    /// Returns the protocol string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RtpAvp => "RTP/AVP",
            Self::RtpSavp => "RTP/SAVP",
            Self::RtpAvpf => "RTP/AVPF",
            Self::RtpSavpf => "RTP/SAVPF",
            Self::UdpTlsRtpSavp => "UDP/TLS/RTP/SAVP",
            Self::UdpTlsRtpSavpf => "UDP/TLS/RTP/SAVPF",
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
        }
    }

    /// Returns true if this protocol uses SRTP.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        matches!(
            self,
            Self::RtpSavp | Self::RtpSavpf | Self::UdpTlsRtpSavp | Self::UdpTlsRtpSavpf
        )
    }

    /// Returns true if this protocol uses DTLS.
    #[must_use]
    pub const fn uses_dtls(&self) -> bool {
        matches!(self, Self::UdpTlsRtpSavp | Self::UdpTlsRtpSavpf)
    }

    /// Returns true if this protocol supports feedback.
    #[must_use]
    pub const fn supports_feedback(&self) -> bool {
        matches!(self, Self::RtpAvpf | Self::RtpSavpf | Self::UdpTlsRtpSavpf)
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for TransportProtocol {
    type Err = SdpError;

    fn from_str(s: &str) -> SdpResult<Self> {
        match s.to_uppercase().as_str() {
            "RTP/AVP" => Ok(Self::RtpAvp),
            "RTP/SAVP" => Ok(Self::RtpSavp),
            "RTP/AVPF" => Ok(Self::RtpAvpf),
            "RTP/SAVPF" => Ok(Self::RtpSavpf),
            "UDP/TLS/RTP/SAVP" => Ok(Self::UdpTlsRtpSavp),
            "UDP/TLS/RTP/SAVPF" => Ok(Self::UdpTlsRtpSavpf),
            "UDP" => Ok(Self::Udp),
            "TCP" => Ok(Self::Tcp),
            _ => Err(SdpError::InvalidMedia {
                reason: format!("unknown transport protocol: {s}"),
            }),
        }
    }
}

/// Connection data (c= line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionData {
    /// Network type (always "IN" for Internet).
    pub net_type: String,
    /// Address type ("IP4" or "IP6").
    pub addr_type: String,
    /// Connection address.
    pub address: String,
}

impl ConnectionData {
    /// Creates connection data from an IP address.
    #[must_use]
    pub fn from_addr(addr: IpAddr) -> Self {
        let (addr_type, address) = match addr {
            IpAddr::V4(v4) => ("IP4".to_string(), v4.to_string()),
            IpAddr::V6(v6) => ("IP6".to_string(), v6.to_string()),
        };

        Self {
            net_type: "IN".to_string(),
            addr_type,
            address,
        }
    }

    /// Parses connection data from the c= line value.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(s: &str) -> SdpResult<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(SdpError::InvalidConnection {
                reason: format!("expected 3 parts, got {}", parts.len()),
            });
        }

        Ok(Self {
            net_type: parts[0].to_string(),
            addr_type: parts[1].to_string(),
            address: parts[2].to_string(),
        })
    }

    /// Returns true if this is an IPv6 connection.
    #[must_use]
    pub fn is_ipv6(&self) -> bool {
        self.addr_type == "IP6"
    }
}

impl fmt::Display for ConnectionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "c={} {} {}", self.net_type, self.addr_type, self.address)
    }
}

/// Media description (m= section).
#[derive(Debug, Clone)]
pub struct MediaDescription {
    /// Media type.
    pub media_type: MediaType,
    /// Port number.
    pub port: u16,
    /// Number of ports (default 1).
    pub num_ports: Option<u16>,
    /// Transport protocol.
    pub protocol: TransportProtocol,
    /// Format/payload types.
    pub formats: Vec<String>,
    /// Connection data (optional, inherits from session).
    pub connection: Option<ConnectionData>,
    /// Media-level attributes.
    pub attributes: Vec<Attribute>,
}

impl MediaDescription {
    /// Creates a new media description.
    #[must_use]
    pub const fn new(media_type: MediaType, port: u16, protocol: TransportProtocol) -> Self {
        Self {
            media_type,
            port,
            num_ports: None,
            protocol,
            formats: Vec::new(),
            connection: None,
            attributes: Vec::new(),
        }
    }

    /// Adds a format/payload type.
    #[must_use]
    pub fn with_format(mut self, format: impl Into<String>) -> Self {
        self.formats.push(format.into());
        self
    }

    /// Sets the connection data.
    #[must_use]
    pub fn with_connection(mut self, connection: ConnectionData) -> Self {
        self.connection = Some(connection);
        self
    }

    /// Adds an attribute.
    pub fn add_attribute(&mut self, attr: Attribute) {
        self.attributes.push(attr);
    }

    /// Gets the first attribute with the given name.
    #[must_use]
    pub fn get_attribute(&self, name: &AttributeName) -> Option<&Attribute> {
        self.attributes.iter().find(|a| &a.name == name)
    }

    /// Gets all attributes with the given name.
    #[must_use]
    pub fn get_attributes(&self, name: &AttributeName) -> Vec<&Attribute> {
        self.attributes.iter().filter(|a| &a.name == name).collect()
    }

    /// Returns the media direction.
    #[must_use]
    pub fn direction(&self) -> Direction {
        for attr in &self.attributes {
            match attr.name {
                AttributeName::Sendrecv => return Direction::Sendrecv,
                AttributeName::Sendonly => return Direction::Sendonly,
                AttributeName::Recvonly => return Direction::Recvonly,
                AttributeName::Inactive => return Direction::Inactive,
                _ => {}
            }
        }
        Direction::Sendrecv
    }

    /// Returns the mid (media identifier) if present.
    #[must_use]
    pub fn mid(&self) -> Option<&str> {
        self.get_attribute(&AttributeName::Mid)
            .and_then(|a| a.value.as_deref())
    }

    /// Returns true if RTCP multiplexing is enabled.
    #[must_use]
    pub fn has_rtcp_mux(&self) -> bool {
        self.get_attribute(&AttributeName::RtcpMux).is_some()
    }

    /// Returns the fingerprint if present.
    #[must_use]
    pub fn fingerprint(&self) -> Option<(&str, &str)> {
        self.get_attribute(&AttributeName::Fingerprint)
            .and_then(|a| a.fingerprint())
    }

    /// Returns the ICE username fragment if present.
    #[must_use]
    pub fn ice_ufrag(&self) -> Option<&str> {
        self.get_attribute(&AttributeName::IceUfrag)
            .and_then(|a| a.value.as_deref())
    }

    /// Returns the ICE password if present.
    #[must_use]
    pub fn ice_pwd(&self) -> Option<&str> {
        self.get_attribute(&AttributeName::IcePwd)
            .and_then(|a| a.value.as_deref())
    }

    /// Parses a media description from an m= line.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse_mline(line: &str) -> SdpResult<Self> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(SdpError::InvalidMedia {
                reason: "m= line requires at least 4 parts".to_string(),
            });
        }

        let media_type: MediaType = parts[0].parse()?;

        // Parse port (may include /num_ports)
        let (port, num_ports) = if let Some((p, n)) = parts[1].split_once('/') {
            let port = p.parse().map_err(|_| SdpError::InvalidMedia {
                reason: format!("invalid port: {p}"),
            })?;
            let num = n.parse().map_err(|_| SdpError::InvalidMedia {
                reason: format!("invalid num_ports: {n}"),
            })?;
            (port, Some(num))
        } else {
            let port = parts[1].parse().map_err(|_| SdpError::InvalidMedia {
                reason: format!("invalid port: {}", parts[1]),
            })?;
            (port, None)
        };

        let protocol: TransportProtocol = parts[2].parse()?;
        let formats: Vec<String> = parts[3..]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();

        Ok(Self {
            media_type,
            port,
            num_ports,
            protocol,
            formats,
            connection: None,
            attributes: Vec::new(),
        })
    }
}

impl fmt::Display for MediaDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // m= line
        write!(f, "m={} ", self.media_type)?;
        if let Some(num) = self.num_ports {
            write!(f, "{}/{} ", self.port, num)?;
        } else {
            write!(f, "{} ", self.port)?;
        }
        write!(f, "{}", self.protocol)?;
        for fmt in &self.formats {
            write!(f, " {fmt}")?;
        }
        writeln!(f)?;

        // c= line (if present)
        if let Some(ref conn) = self.connection {
            writeln!(f, "{conn}")?;
        }

        // Attributes
        for attr in &self.attributes {
            writeln!(f, "{attr}")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_media_type() {
        assert_eq!("audio".parse::<MediaType>().unwrap(), MediaType::Audio);
        assert_eq!("video".parse::<MediaType>().unwrap(), MediaType::Video);
    }

    #[test]
    fn test_transport_protocol() {
        assert!("RTP/SAVP".parse::<TransportProtocol>().unwrap().is_secure());
        assert!(
            "UDP/TLS/RTP/SAVPF"
                .parse::<TransportProtocol>()
                .unwrap()
                .uses_dtls()
        );
    }

    #[test]
    fn test_connection_data() {
        let conn = ConnectionData::from_addr("::1".parse().unwrap());
        assert!(conn.is_ipv6());
        assert_eq!(format!("{conn}"), "c=IN IP6 ::1");
    }

    #[test]
    fn test_media_parse() {
        let media = MediaDescription::parse_mline("audio 49170 RTP/SAVP 0 8").unwrap();
        assert_eq!(media.media_type, MediaType::Audio);
        assert_eq!(media.port, 49170);
        assert_eq!(media.formats, vec!["0", "8"]);
    }

    #[test]
    fn test_media_display() {
        let mut media = MediaDescription::new(MediaType::Audio, 5000, TransportProtocol::RtpSavp);
        media.formats.push("0".to_string());
        media.add_attribute(Attribute::flag(AttributeName::Sendrecv));

        let output = format!("{media}");
        assert!(output.contains("m=audio 5000 RTP/SAVP 0"));
        assert!(output.contains("a=sendrecv"));
    }
}
