//! SDP attributes per RFC 4566.

use crate::error::{SdpError, SdpResult};
use std::fmt;
use std::str::FromStr;

/// Common SDP attribute names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttributeName {
    /// rtpmap - RTP payload type mapping.
    Rtpmap,
    /// fmtp - Format parameters.
    Fmtp,
    /// ptime - Packet time.
    Ptime,
    /// maxptime - Maximum packet time.
    Maxptime,
    /// sendrecv - Bidirectional.
    Sendrecv,
    /// sendonly - Send only.
    Sendonly,
    /// recvonly - Receive only.
    Recvonly,
    /// inactive - Neither send nor receive.
    Inactive,
    /// ice-ufrag - ICE username fragment.
    IceUfrag,
    /// ice-pwd - ICE password.
    IcePwd,
    /// ice-options - ICE options.
    IceOptions,
    /// candidate - ICE candidate.
    Candidate,
    /// fingerprint - DTLS fingerprint.
    Fingerprint,
    /// setup - DTLS setup role.
    Setup,
    /// mid - Media identifier.
    Mid,
    /// group - Media bundling.
    Group,
    /// ssrc - Synchronization source.
    Ssrc,
    /// rtcp - RTCP port.
    Rtcp,
    /// rtcp-mux - RTCP multiplexing.
    RtcpMux,
    /// rtcp-rsize - Reduced-size RTCP.
    RtcpRsize,
    /// extmap - RTP header extension.
    Extmap,
    /// Custom attribute.
    Custom(String),
}

impl AttributeName {
    /// Returns the attribute name string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Rtpmap => "rtpmap",
            Self::Fmtp => "fmtp",
            Self::Ptime => "ptime",
            Self::Maxptime => "maxptime",
            Self::Sendrecv => "sendrecv",
            Self::Sendonly => "sendonly",
            Self::Recvonly => "recvonly",
            Self::Inactive => "inactive",
            Self::IceUfrag => "ice-ufrag",
            Self::IcePwd => "ice-pwd",
            Self::IceOptions => "ice-options",
            Self::Candidate => "candidate",
            Self::Fingerprint => "fingerprint",
            Self::Setup => "setup",
            Self::Mid => "mid",
            Self::Group => "group",
            Self::Ssrc => "ssrc",
            Self::Rtcp => "rtcp",
            Self::RtcpMux => "rtcp-mux",
            Self::RtcpRsize => "rtcp-rsize",
            Self::Extmap => "extmap",
            Self::Custom(name) => name,
        }
    }

    /// Returns true if this attribute takes a value.
    #[must_use]
    pub const fn has_value(&self) -> bool {
        !matches!(
            self,
            Self::Sendrecv
                | Self::Sendonly
                | Self::Recvonly
                | Self::Inactive
                | Self::RtcpMux
                | Self::RtcpRsize
        )
    }
}

impl fmt::Display for AttributeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for AttributeName {
    type Err = SdpError;

    fn from_str(s: &str) -> SdpResult<Self> {
        Ok(match s.to_lowercase().as_str() {
            "rtpmap" => Self::Rtpmap,
            "fmtp" => Self::Fmtp,
            "ptime" => Self::Ptime,
            "maxptime" => Self::Maxptime,
            "sendrecv" => Self::Sendrecv,
            "sendonly" => Self::Sendonly,
            "recvonly" => Self::Recvonly,
            "inactive" => Self::Inactive,
            "ice-ufrag" => Self::IceUfrag,
            "ice-pwd" => Self::IcePwd,
            "ice-options" => Self::IceOptions,
            "candidate" => Self::Candidate,
            "fingerprint" => Self::Fingerprint,
            "setup" => Self::Setup,
            "mid" => Self::Mid,
            "group" => Self::Group,
            "ssrc" => Self::Ssrc,
            "rtcp" => Self::Rtcp,
            "rtcp-mux" => Self::RtcpMux,
            "rtcp-rsize" => Self::RtcpRsize,
            "extmap" => Self::Extmap,
            _ => Self::Custom(s.to_string()),
        })
    }
}

/// An SDP attribute (a= line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Attribute name.
    pub name: AttributeName,
    /// Attribute value (if any).
    pub value: Option<String>,
}

impl Attribute {
    /// Creates an attribute with a value.
    #[must_use]
    pub fn new(name: AttributeName, value: impl Into<String>) -> Self {
        Self {
            name,
            value: Some(value.into()),
        }
    }

    /// Creates a flag attribute (no value).
    #[must_use]
    pub const fn flag(name: AttributeName) -> Self {
        Self { name, value: None }
    }

    /// Parses an attribute from a line (without 'a=' prefix).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(line: &str) -> SdpResult<Self> {
        if let Some((name, value)) = line.split_once(':') {
            let name: AttributeName = name.parse()?;
            Ok(Self::new(name, value))
        } else {
            let name: AttributeName = line.parse()?;
            Ok(Self::flag(name))
        }
    }

    /// Returns true if this is a direction attribute.
    #[must_use]
    pub const fn is_direction(&self) -> bool {
        matches!(
            self.name,
            AttributeName::Sendrecv
                | AttributeName::Sendonly
                | AttributeName::Recvonly
                | AttributeName::Inactive
        )
    }

    /// Returns the rtpmap payload type if this is an rtpmap attribute.
    #[must_use]
    pub fn rtpmap_payload_type(&self) -> Option<u8> {
        if self.name != AttributeName::Rtpmap {
            return None;
        }

        self.value
            .as_ref()
            .and_then(|v| v.split_whitespace().next())
            .and_then(|pt| pt.parse().ok())
    }

    /// Returns the fingerprint hash if this is a fingerprint attribute.
    #[must_use]
    pub fn fingerprint(&self) -> Option<(&str, &str)> {
        if self.name != AttributeName::Fingerprint {
            return None;
        }

        self.value.as_ref().and_then(|v| v.split_once(' '))
    }
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a={}", self.name)?;
        if let Some(ref value) = self.value {
            write!(f, ":{value}")?;
        }
        Ok(())
    }
}

/// Media direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Direction {
    /// Bidirectional (default).
    #[default]
    Sendrecv,
    /// Send only.
    Sendonly,
    /// Receive only.
    Recvonly,
    /// Inactive.
    Inactive,
}

impl Direction {
    /// Returns the attribute name for this direction.
    #[must_use]
    pub const fn as_attribute_name(&self) -> AttributeName {
        match self {
            Self::Sendrecv => AttributeName::Sendrecv,
            Self::Sendonly => AttributeName::Sendonly,
            Self::Recvonly => AttributeName::Recvonly,
            Self::Inactive => AttributeName::Inactive,
        }
    }

    /// Creates an attribute for this direction.
    #[must_use]
    pub const fn to_attribute(&self) -> Attribute {
        Attribute::flag(self.as_attribute_name())
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_attribute_name())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_attribute_parse() {
        let attr = Attribute::parse("rtpmap:0 PCMU/8000").expect("valid rtpmap");
        assert_eq!(attr.name, AttributeName::Rtpmap);
        assert_eq!(attr.value, Some("0 PCMU/8000".to_string()));
    }

    #[test]
    fn test_attribute_flag() {
        let attr = Attribute::parse("sendrecv").expect("valid flag");
        assert_eq!(attr.name, AttributeName::Sendrecv);
        assert!(attr.value.is_none());
    }

    #[test]
    fn test_attribute_display() {
        let attr = Attribute::new(AttributeName::Rtpmap, "0 PCMU/8000");
        assert_eq!(format!("{attr}"), "a=rtpmap:0 PCMU/8000");

        let flag = Attribute::flag(AttributeName::Sendrecv);
        assert_eq!(format!("{flag}"), "a=sendrecv");
    }

    #[test]
    fn test_rtpmap_payload_type() {
        let attr = Attribute::new(AttributeName::Rtpmap, "96 opus/48000/2");
        assert_eq!(attr.rtpmap_payload_type(), Some(96));
    }

    #[test]
    fn test_fingerprint_parse() {
        let attr = Attribute::new(AttributeName::Fingerprint, "sha-384 AA:BB:CC");
        let (algo, hash) = attr.fingerprint().unwrap();
        assert_eq!(algo, "sha-384");
        assert_eq!(hash, "AA:BB:CC");
    }

    #[test]
    fn test_direction() {
        assert_eq!(Direction::Sendrecv.to_string(), "sendrecv");
        assert!(Direction::Sendrecv.to_attribute().is_direction());
    }
}
