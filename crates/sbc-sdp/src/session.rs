//! SDP session description per RFC 4566.

use crate::attribute::{Attribute, AttributeName};
use crate::error::{SdpError, SdpResult};
use crate::media::{ConnectionData, MediaDescription};
use crate::SDP_VERSION;
use std::fmt;
use std::str::FromStr;

/// Origin (o= line) information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// Username.
    pub username: String,
    /// Session ID.
    pub session_id: String,
    /// Session version.
    pub session_version: String,
    /// Network type.
    pub net_type: String,
    /// Address type.
    pub addr_type: String,
    /// Unicast address.
    pub unicast_address: String,
}

impl Origin {
    /// Creates a new origin with default values.
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            username: "-".to_string(),
            session_id: session_id.into(),
            session_version: "1".to_string(),
            net_type: "IN".to_string(),
            addr_type: "IP6".to_string(),
            unicast_address: "::1".to_string(),
        }
    }

    /// Parses origin from o= line value.
    pub fn parse(s: &str) -> SdpResult<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() != 6 {
            return Err(SdpError::ParseError {
                reason: format!("origin requires 6 parts, got {}", parts.len()),
            });
        }

        Ok(Self {
            username: parts[0].to_string(),
            session_id: parts[1].to_string(),
            session_version: parts[2].to_string(),
            net_type: parts[3].to_string(),
            addr_type: parts[4].to_string(),
            unicast_address: parts[5].to_string(),
        })
    }

    /// Increments the session version.
    pub fn increment_version(&mut self) {
        if let Ok(v) = self.session_version.parse::<u64>() {
            self.session_version = (v + 1).to_string();
        }
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "o={} {} {} {} {} {}",
            self.username,
            self.session_id,
            self.session_version,
            self.net_type,
            self.addr_type,
            self.unicast_address
        )
    }
}

/// Timing (t= line) information.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Timing {
    /// Start time (0 = now).
    pub start_time: u64,
    /// Stop time (0 = unbounded).
    pub stop_time: u64,
}

impl Timing {
    /// Creates timing for a permanent session.
    #[must_use]
    pub fn permanent() -> Self {
        Self {
            start_time: 0,
            stop_time: 0,
        }
    }

    /// Parses timing from t= line value.
    pub fn parse(s: &str) -> SdpResult<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(SdpError::ParseError {
                reason: "timing requires 2 parts".to_string(),
            });
        }

        let start_time = parts[0].parse().map_err(|_| SdpError::ParseError {
            reason: "invalid start time".to_string(),
        })?;
        let stop_time = parts[1].parse().map_err(|_| SdpError::ParseError {
            reason: "invalid stop time".to_string(),
        })?;

        Ok(Self {
            start_time,
            stop_time,
        })
    }
}

impl fmt::Display for Timing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t={} {}", self.start_time, self.stop_time)
    }
}

/// Complete SDP session description.
#[derive(Debug, Clone)]
pub struct SessionDescription {
    /// Protocol version (always 0).
    pub version: u8,
    /// Origin.
    pub origin: Origin,
    /// Session name.
    pub session_name: String,
    /// Session information (optional).
    pub session_info: Option<String>,
    /// URI (optional).
    pub uri: Option<String>,
    /// Email addresses.
    pub emails: Vec<String>,
    /// Phone numbers.
    pub phones: Vec<String>,
    /// Session-level connection data (optional).
    pub connection: Option<ConnectionData>,
    /// Timing.
    pub timing: Timing,
    /// Session-level attributes.
    pub attributes: Vec<Attribute>,
    /// Media descriptions.
    pub media: Vec<MediaDescription>,
}

impl SessionDescription {
    /// Creates a new session description.
    #[must_use]
    pub fn new(origin: Origin) -> Self {
        Self {
            version: SDP_VERSION,
            origin,
            session_name: "-".to_string(),
            session_info: None,
            uri: None,
            emails: Vec::new(),
            phones: Vec::new(),
            connection: None,
            timing: Timing::permanent(),
            attributes: Vec::new(),
            media: Vec::new(),
        }
    }

    /// Sets the session name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.session_name = name.into();
        self
    }

    /// Sets the connection data.
    #[must_use]
    pub fn with_connection(mut self, connection: ConnectionData) -> Self {
        self.connection = Some(connection);
        self
    }

    /// Adds a session-level attribute.
    pub fn add_attribute(&mut self, attr: Attribute) {
        self.attributes.push(attr);
    }

    /// Adds a media description.
    pub fn add_media(&mut self, media: MediaDescription) {
        self.media.push(media);
    }

    /// Gets a session-level attribute.
    #[must_use]
    pub fn get_attribute(&self, name: &AttributeName) -> Option<&Attribute> {
        self.attributes.iter().find(|a| &a.name == name)
    }

    /// Returns the group attribute value if present.
    #[must_use]
    pub fn group(&self) -> Option<&str> {
        self.get_attribute(&AttributeName::Group)
            .and_then(|a| a.value.as_deref())
    }

    /// Returns session-level ICE credentials.
    #[must_use]
    pub fn ice_credentials(&self) -> Option<(&str, &str)> {
        let ufrag = self
            .get_attribute(&AttributeName::IceUfrag)
            .and_then(|a| a.value.as_deref())?;
        let pwd = self
            .get_attribute(&AttributeName::IcePwd)
            .and_then(|a| a.value.as_deref())?;
        Some((ufrag, pwd))
    }

    /// Returns the session-level fingerprint if present.
    #[must_use]
    pub fn fingerprint(&self) -> Option<(&str, &str)> {
        self.get_attribute(&AttributeName::Fingerprint)
            .and_then(|a| a.fingerprint())
    }

    /// Returns audio media descriptions.
    #[must_use]
    pub fn audio_media(&self) -> Vec<&MediaDescription> {
        self.media
            .iter()
            .filter(|m| m.media_type == crate::media::MediaType::Audio)
            .collect()
    }

    /// Returns video media descriptions.
    #[must_use]
    pub fn video_media(&self) -> Vec<&MediaDescription> {
        self.media
            .iter()
            .filter(|m| m.media_type == crate::media::MediaType::Video)
            .collect()
    }
}

impl fmt::Display for SessionDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // v= line
        writeln!(f, "v={}", self.version)?;

        // o= line
        writeln!(f, "{}", self.origin)?;

        // s= line
        writeln!(f, "s={}", self.session_name)?;

        // i= line (optional)
        if let Some(ref info) = self.session_info {
            writeln!(f, "i={info}")?;
        }

        // u= line (optional)
        if let Some(ref uri) = self.uri {
            writeln!(f, "u={uri}")?;
        }

        // e= lines
        for email in &self.emails {
            writeln!(f, "e={email}")?;
        }

        // p= lines
        for phone in &self.phones {
            writeln!(f, "p={phone}")?;
        }

        // c= line (optional)
        if let Some(ref conn) = self.connection {
            writeln!(f, "{conn}")?;
        }

        // t= line
        writeln!(f, "{}", self.timing)?;

        // Session attributes
        for attr in &self.attributes {
            writeln!(f, "{attr}")?;
        }

        // Media descriptions
        for media in &self.media {
            write!(f, "{media}")?;
        }

        Ok(())
    }
}

impl FromStr for SessionDescription {
    type Err = SdpError;

    fn from_str(s: &str) -> SdpResult<Self> {
        let mut version: Option<u8> = None;
        let mut origin: Option<Origin> = None;
        let mut session_name: Option<String> = None;
        let mut session_info: Option<String> = None;
        let mut uri: Option<String> = None;
        let mut emails: Vec<String> = Vec::new();
        let mut phones: Vec<String> = Vec::new();
        let mut connection: Option<ConnectionData> = None;
        let mut timing: Option<Timing> = None;
        let mut attributes: Vec<Attribute> = Vec::new();
        let mut media: Vec<MediaDescription> = Vec::new();
        let mut current_media: Option<MediaDescription> = None;

        for (line_num, line) in s.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Parse type=value
            if line.len() < 2 || line.chars().nth(1) != Some('=') {
                return Err(SdpError::InvalidLine {
                    line: line_num + 1,
                    reason: "invalid line format".to_string(),
                });
            }

            let line_type = line.chars().next().ok_or_else(|| SdpError::InvalidLine {
                line: line_num + 1,
                reason: "empty line".to_string(),
            })?;
            let value = &line[2..];

            match line_type {
                'v' => {
                    version = Some(value.parse().map_err(|_| SdpError::InvalidLine {
                        line: line_num + 1,
                        reason: "invalid version".to_string(),
                    })?);
                }
                'o' => {
                    origin = Some(Origin::parse(value)?);
                }
                's' => {
                    session_name = Some(value.to_string());
                }
                'i' => {
                    if current_media.is_some() {
                        // Media-level info (ignored for now)
                    } else {
                        session_info = Some(value.to_string());
                    }
                }
                'u' => {
                    uri = Some(value.to_string());
                }
                'e' => {
                    emails.push(value.to_string());
                }
                'p' => {
                    phones.push(value.to_string());
                }
                'c' => {
                    let conn = ConnectionData::parse(value)?;
                    if let Some(ref mut m) = current_media {
                        m.connection = Some(conn);
                    } else {
                        connection = Some(conn);
                    }
                }
                't' => {
                    timing = Some(Timing::parse(value)?);
                }
                'a' => {
                    let attr = Attribute::parse(value)?;
                    if let Some(ref mut m) = current_media {
                        m.attributes.push(attr);
                    } else {
                        attributes.push(attr);
                    }
                }
                'm' => {
                    // Finish previous media section
                    if let Some(m) = current_media.take() {
                        media.push(m);
                    }
                    current_media = Some(MediaDescription::parse_mline(value)?);
                }
                _ => {
                    // Ignore unknown line types
                }
            }
        }

        // Finish last media section
        if let Some(m) = current_media {
            media.push(m);
        }

        // Validate required fields
        let version = version.ok_or(SdpError::MissingField {
            field: "v (version)".to_string(),
        })?;

        if version != SDP_VERSION {
            return Err(SdpError::UnsupportedVersion { version });
        }

        let origin = origin.ok_or(SdpError::MissingField {
            field: "o (origin)".to_string(),
        })?;

        let session_name = session_name.ok_or(SdpError::MissingField {
            field: "s (session name)".to_string(),
        })?;

        let timing = timing.ok_or(SdpError::MissingField {
            field: "t (timing)".to_string(),
        })?;

        Ok(Self {
            version,
            origin,
            session_name,
            session_info,
            uri,
            emails,
            phones,
            connection,
            timing,
            attributes,
            media,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_origin_parse() {
        let origin = Origin::parse("- 123456 1 IN IP6 ::1").unwrap();
        assert_eq!(origin.session_id, "123456");
        assert_eq!(origin.addr_type, "IP6");
    }

    #[test]
    fn test_timing_permanent() {
        let timing = Timing::permanent();
        assert_eq!(timing.start_time, 0);
        assert_eq!(timing.stop_time, 0);
    }

    #[test]
    fn test_session_parse() {
        let sdp = "v=0\r\n\
                   o=- 123456 1 IN IP6 ::1\r\n\
                   s=-\r\n\
                   t=0 0\r\n\
                   m=audio 5000 RTP/SAVP 0\r\n\
                   a=rtpmap:0 PCMU/8000\r\n";

        let session: SessionDescription = sdp.parse().unwrap();
        assert_eq!(session.version, 0);
        assert_eq!(session.origin.session_id, "123456");
        assert_eq!(session.media.len(), 1);
        assert_eq!(session.media[0].port, 5000);
    }

    #[test]
    fn test_session_roundtrip() {
        let origin = Origin::new("12345");
        let mut session = SessionDescription::new(origin);
        session.add_attribute(Attribute::flag(AttributeName::IceOptions));

        let mut media =
            MediaDescription::new(crate::media::MediaType::Audio, 5000, crate::media::TransportProtocol::RtpSavp);
        media.formats.push("0".to_string());
        session.add_media(media);

        let sdp = session.to_string();
        let reparsed: SessionDescription = sdp.parse().unwrap();

        assert_eq!(reparsed.origin.session_id, "12345");
        assert_eq!(reparsed.media.len(), 1);
    }

    #[test]
    fn test_missing_version() {
        let sdp = "o=- 123 1 IN IP4 127.0.0.1\r\n\
                   s=-\r\n\
                   t=0 0\r\n";

        let result: SdpResult<SessionDescription> = sdp.parse();
        assert!(matches!(result, Err(SdpError::MissingField { .. })));
    }

    #[test]
    fn test_audio_video_helpers() {
        let sdp = "v=0\r\n\
                   o=- 123 1 IN IP6 ::1\r\n\
                   s=-\r\n\
                   t=0 0\r\n\
                   m=audio 5000 RTP/SAVP 0\r\n\
                   m=video 5002 RTP/SAVP 96\r\n";

        let session: SessionDescription = sdp.parse().unwrap();
        assert_eq!(session.audio_media().len(), 1);
        assert_eq!(session.video_media().len(), 1);
    }
}
