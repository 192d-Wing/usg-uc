//! SDP attributes per RFC 8866.

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

/// Direction constraint for an extmap attribute (RFC 5285 Section 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtmapDirection {
    /// Extension is used in both directions (default).
    Sendrecv,
    /// Extension is only sent.
    Sendonly,
    /// Extension is only received.
    Recvonly,
    /// Extension is inactive.
    Inactive,
}

impl fmt::Display for ExtmapDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sendrecv => write!(f, "sendrecv"),
            Self::Sendonly => write!(f, "sendonly"),
            Self::Recvonly => write!(f, "recvonly"),
            Self::Inactive => write!(f, "inactive"),
        }
    }
}

/// Parsed extmap attribute per RFC 5285 Section 7.
///
/// Format: `a=extmap:<id>[/<direction>] <URI> [<extensionattributes>]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extmap {
    /// Extension ID (1-14 for one-byte header, 1-255 for two-byte header).
    pub id: u8,
    /// Direction constraint (None means sendrecv by default).
    pub direction: Option<ExtmapDirection>,
    /// Extension URI (the unique identifier for the extension type).
    pub uri: String,
    /// Optional extension-specific attributes.
    pub extension_attributes: Option<String>,
}

impl Extmap {
    /// Parses an extmap value string (the part after `"extmap:"`).
    ///
    /// Handles: `<id>[/<direction>] <URI> [<extensionattributes>]`
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be parsed.
    pub fn parse(value: &str) -> SdpResult<Self> {
        let (id_part, rest) = value.split_once(' ').ok_or_else(|| SdpError::InvalidAttribute {
            name: "extmap".to_string(),
            reason: "missing URI".to_string(),
        })?;
        let rest = rest.trim();

        // Parse ID and optional direction
        let (id_str, direction) = if let Some((id_str, dir_str)) = id_part.split_once('/') {
            let dir = match dir_str {
                "sendrecv" => ExtmapDirection::Sendrecv,
                "sendonly" => ExtmapDirection::Sendonly,
                "recvonly" => ExtmapDirection::Recvonly,
                "inactive" => ExtmapDirection::Inactive,
                _ => {
                    return Err(SdpError::InvalidAttribute {
                        name: "extmap".to_string(),
                        reason: format!("invalid direction: {dir_str}"),
                    });
                }
            };
            (id_str, Some(dir))
        } else {
            (id_part, None)
        };

        let id: u8 = id_str.parse().map_err(|_| SdpError::InvalidAttribute {
            name: "extmap".to_string(),
            reason: format!("invalid ID: {id_str}"),
        })?;

        // Parse URI and optional extension attributes
        let (uri, extension_attributes) = if let Some((uri, attrs)) = rest.split_once(' ') {
            (uri.to_string(), Some(attrs.to_string()))
        } else {
            (rest.to_string(), None)
        };

        Ok(Self {
            id,
            direction,
            uri,
            extension_attributes,
        })
    }

    /// Formats as an SDP attribute value (the part after `"extmap:"`).
    #[must_use]
    pub fn to_sdp_value(&self) -> String {
        let mut s = self.id.to_string();
        if let Some(ref dir) = self.direction {
            s.push('/');
            s.push_str(&dir.to_string());
        }
        s.push(' ');
        s.push_str(&self.uri);
        if let Some(ref attrs) = self.extension_attributes {
            s.push(' ');
            s.push_str(attrs);
        }
        s
    }

    /// Returns true if the ID is valid for one-byte header format (1-14).
    #[must_use]
    pub const fn is_one_byte_compatible(&self) -> bool {
        self.id >= 1 && self.id <= 14
    }
}

impl fmt::Display for Extmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a=extmap:{}", self.to_sdp_value())
    }
}

impl Attribute {
    /// If this is an extmap attribute, parse and return the structured Extmap.
    ///
    /// # Errors
    ///
    /// Returns an error if the extmap value cannot be parsed.
    #[must_use]
    pub fn as_extmap(&self) -> Option<SdpResult<Extmap>> {
        if self.name != AttributeName::Extmap {
            return None;
        }
        Some(
            self.value
                .as_ref()
                .ok_or_else(|| SdpError::InvalidAttribute {
                    name: "extmap".to_string(),
                    reason: "missing value".to_string(),
                })
                .and_then(|v| Extmap::parse(v)),
        )
    }
}

/// Negotiated RTP header extensions from SDP offer/answer exchange.
#[derive(Debug, Clone, Default)]
pub struct NegotiatedExtensions {
    /// Extensions to include when sending RTP packets.
    pub send: Vec<Extmap>,
    /// Extensions to expect when receiving RTP packets.
    pub recv: Vec<Extmap>,
}

impl NegotiatedExtensions {
    /// Returns true if there are no negotiated extensions.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.send.is_empty() && self.recv.is_empty()
    }

    /// Finds the negotiated extension ID for a given URI in the send direction.
    #[must_use]
    pub fn send_id_for_uri(&self, uri: &str) -> Option<u8> {
        self.send.iter().find(|e| e.uri == uri).map(|e| e.id)
    }

    /// Finds the negotiated extension ID for a given URI in the recv direction.
    #[must_use]
    pub fn recv_id_for_uri(&self, uri: &str) -> Option<u8> {
        self.recv.iter().find(|e| e.uri == uri).map(|e| e.id)
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

    // ─── Extmap tests ─────────────────────────────────────────────

    #[test]
    fn test_extmap_parse_simple() {
        let ext = Extmap::parse("1 urn:ietf:params:rtp-hdrext:ssrc-audio-level").unwrap();
        assert_eq!(ext.id, 1);
        assert!(ext.direction.is_none());
        assert_eq!(ext.uri, "urn:ietf:params:rtp-hdrext:ssrc-audio-level");
        assert!(ext.extension_attributes.is_none());
    }

    #[test]
    fn test_extmap_parse_with_direction() {
        let ext =
            Extmap::parse("2/sendonly urn:ietf:params:rtp-hdrext:toffset").unwrap();
        assert_eq!(ext.id, 2);
        assert_eq!(ext.direction, Some(ExtmapDirection::Sendonly));
        assert_eq!(ext.uri, "urn:ietf:params:rtp-hdrext:toffset");
    }

    #[test]
    fn test_extmap_parse_with_attributes() {
        let ext = Extmap::parse("3 urn:example:ext some-attr=value").unwrap();
        assert_eq!(ext.id, 3);
        assert_eq!(ext.uri, "urn:example:ext");
        assert_eq!(
            ext.extension_attributes,
            Some("some-attr=value".to_string())
        );
    }

    #[test]
    fn test_extmap_roundtrip() {
        let ext = Extmap {
            id: 5,
            direction: Some(ExtmapDirection::Recvonly),
            uri: "urn:example:test".to_string(),
            extension_attributes: None,
        };
        let sdp_value = ext.to_sdp_value();
        let parsed = Extmap::parse(&sdp_value).unwrap();
        assert_eq!(parsed, ext);
    }

    #[test]
    fn test_extmap_display() {
        let ext = Extmap {
            id: 1,
            direction: None,
            uri: "urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string(),
            extension_attributes: None,
        };
        assert_eq!(
            format!("{ext}"),
            "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level"
        );
    }

    #[test]
    fn test_extmap_is_one_byte_compatible() {
        assert!(Extmap {
            id: 14,
            direction: None,
            uri: String::new(),
            extension_attributes: None,
        }
        .is_one_byte_compatible());
        assert!(!Extmap {
            id: 15,
            direction: None,
            uri: String::new(),
            extension_attributes: None,
        }
        .is_one_byte_compatible());
    }

    #[test]
    fn test_attribute_as_extmap() {
        let attr = Attribute::new(
            AttributeName::Extmap,
            "1 urn:ietf:params:rtp-hdrext:ssrc-audio-level",
        );
        let ext = attr.as_extmap().unwrap().unwrap();
        assert_eq!(ext.id, 1);

        // Non-extmap returns None
        let other = Attribute::new(AttributeName::Rtpmap, "0 PCMU/8000");
        assert!(other.as_extmap().is_none());
    }

    #[test]
    fn test_negotiated_extensions() {
        let mut neg = NegotiatedExtensions::default();
        assert!(neg.is_empty());

        neg.send.push(Extmap {
            id: 1,
            direction: None,
            uri: "urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string(),
            extension_attributes: None,
        });
        assert!(!neg.is_empty());
        assert_eq!(
            neg.send_id_for_uri("urn:ietf:params:rtp-hdrext:ssrc-audio-level"),
            Some(1)
        );
        assert!(neg.send_id_for_uri("urn:nonexistent").is_none());
    }
}
