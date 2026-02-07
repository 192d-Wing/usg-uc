//! SDP session description per RFC 8866.

use crate::SDP_VERSION;
use crate::attribute::{Attribute, AttributeName};
use crate::error::{SdpError, SdpResult};
use crate::media::{ConnectionData, MediaDescription};
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
    ///
    /// # Errors
    /// Returns an error if the operation fails.
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

/// Timing (t= line) information with optional repeat times.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Timing {
    /// Start time (0 = now).
    pub start_time: u64,
    /// Stop time (0 = unbounded).
    pub stop_time: u64,
    /// Repeat times (r= lines) per RFC 8866 §5.11.
    pub repeat_times: Vec<RepeatTimes>,
}

impl Timing {
    /// Creates timing for a permanent session.
    #[must_use]
    pub const fn permanent() -> Self {
        Self {
            start_time: 0,
            stop_time: 0,
            repeat_times: Vec::new(),
        }
    }

    /// Creates timing with specific start/stop times.
    #[must_use]
    pub const fn with_times(start_time: u64, stop_time: u64) -> Self {
        Self {
            start_time,
            stop_time,
            repeat_times: Vec::new(),
        }
    }

    /// Adds repeat times to this timing.
    pub fn add_repeat(&mut self, repeat: RepeatTimes) {
        self.repeat_times.push(repeat);
    }

    /// Builder method to add repeat times.
    #[must_use]
    pub fn with_repeat(mut self, repeat: RepeatTimes) -> Self {
        self.repeat_times.push(repeat);
        self
    }

    /// Returns whether this timing has repeat times.
    #[must_use]
    pub const fn has_repeats(&self) -> bool {
        !self.repeat_times.is_empty()
    }

    /// Parses timing from t= line value.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
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
            repeat_times: Vec::new(),
        })
    }
}

impl fmt::Display for Timing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "t={} {}", self.start_time, self.stop_time)?;
        // Write r= lines for repeat times
        for repeat in &self.repeat_times {
            write!(f, "\n{repeat}")?;
        }
        Ok(())
    }
}

// ============================================================================
// RFC 8866 §5.11 - Repeat Times (r= line)
// ============================================================================

/// Time value that can be specified in compact form per RFC 8866 §5.10.
///
/// Values can be in seconds, or with a unit suffix:
/// - `d` - days
/// - `h` - hours
/// - `m` - minutes
/// - `s` - seconds (explicit)
///
/// Examples: `7d`, `1h`, `1800` (30 minutes)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeValue {
    /// Value in seconds.
    pub seconds: u64,
}

impl TimeValue {
    /// Creates a new time value from seconds.
    #[must_use]
    pub const fn from_seconds(seconds: u64) -> Self {
        Self { seconds }
    }

    /// Creates a time value from days.
    #[must_use]
    pub const fn from_days(days: u64) -> Self {
        Self {
            seconds: days * 86400,
        }
    }

    /// Creates a time value from hours.
    #[must_use]
    pub const fn from_hours(hours: u64) -> Self {
        Self {
            seconds: hours * 3600,
        }
    }

    /// Creates a time value from minutes.
    #[must_use]
    pub const fn from_minutes(minutes: u64) -> Self {
        Self {
            seconds: minutes * 60,
        }
    }

    /// Parses a time value from a string (compact form supported).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(s: &str) -> SdpResult<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(SdpError::ParseError {
                reason: "empty time value".to_string(),
            });
        }

        // Check for unit suffix
        let (value_str, multiplier) = s
            .strip_suffix('d')
            .map(|num| (num, 86400u64))
            .or_else(|| s.strip_suffix('h').map(|num| (num, 3600u64)))
            .or_else(|| s.strip_suffix('m').map(|num| (num, 60u64)))
            .or_else(|| s.strip_suffix('s').map(|num| (num, 1u64)))
            .unwrap_or((s, 1u64));

        let value: u64 = value_str.parse().map_err(|_| SdpError::ParseError {
            reason: format!("invalid time value: {s}"),
        })?;

        Ok(Self {
            seconds: value * multiplier,
        })
    }

    /// Returns the value in seconds.
    #[must_use]
    pub const fn as_seconds(&self) -> u64 {
        self.seconds
    }

    /// Returns the value as a Duration.
    #[must_use]
    pub const fn as_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.seconds)
    }

    /// Formats the value in compact form if appropriate.
    #[must_use]
    pub fn to_compact_string(&self) -> String {
        // Use compact form for clean divisibility
        if self.seconds.is_multiple_of(86400) && self.seconds >= 86400 {
            format!("{}d", self.seconds / 86400)
        } else if self.seconds.is_multiple_of(3600) && self.seconds >= 3600 {
            format!("{}h", self.seconds / 3600)
        } else if self.seconds.is_multiple_of(60) && self.seconds >= 60 {
            format!("{}m", self.seconds / 60)
        } else {
            self.seconds.to_string()
        }
    }
}

impl fmt::Display for TimeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Default to compact form
        write!(f, "{}", self.to_compact_string())
    }
}

/// Repeat times (r= line) per RFC 8866 §5.11.
///
/// Repeat times specify periodic sessions for things like weekly broadcasts.
/// The format is:
/// ```text
/// r=<repeat interval> <active duration> <offsets from start-time>
/// ```
///
/// ## Example
///
/// ```
/// use proto_sdp::session::{RepeatTimes, TimeValue};
///
/// // Daily 1-hour session starting at midnight
/// let repeat = RepeatTimes::new(
///     TimeValue::from_days(1),      // repeat every day
///     TimeValue::from_hours(1),     // 1 hour duration
///     vec![TimeValue::from_seconds(0)], // starts at midnight
/// );
///
/// assert_eq!(repeat.interval.as_seconds(), 86400);
/// assert_eq!(repeat.duration.as_seconds(), 3600);
/// ```
///
/// ## RFC 8866 Example
///
/// For a session active on Monday 10:00-11:00 and Tuesday 10:00-11:00:
/// ```text
/// t=3034423619 3042462419
/// r=604800 3600 0 90000
/// ```
/// - `604800s` = 7 days (weekly repeat)
/// - 3600s = 1 hour duration
/// - 0 = first occurrence at start time
/// - 90000 = 25 hours (Tuesday 10:00, offset from Monday 9:00)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeatTimes {
    /// Repeat interval (e.g., 7 days for weekly).
    pub interval: TimeValue,
    /// Active duration of each occurrence.
    pub duration: TimeValue,
    /// Offsets from the start time (at least one required).
    pub offsets: Vec<TimeValue>,
}

impl RepeatTimes {
    /// Creates new repeat times.
    #[must_use]
    pub const fn new(interval: TimeValue, duration: TimeValue, offsets: Vec<TimeValue>) -> Self {
        Self {
            interval,
            duration,
            offsets,
        }
    }

    /// Creates daily repeat times.
    #[must_use]
    pub const fn daily(duration: TimeValue, offsets: Vec<TimeValue>) -> Self {
        Self::new(TimeValue::from_days(1), duration, offsets)
    }

    /// Creates weekly repeat times.
    #[must_use]
    pub const fn weekly(duration: TimeValue, offsets: Vec<TimeValue>) -> Self {
        Self::new(TimeValue::from_days(7), duration, offsets)
    }

    /// Parses repeat times from r= line value.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn parse(s: &str) -> SdpResult<Self> {
        let parts: Vec<&str> = s.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(SdpError::ParseError {
                reason: format!(
                    "repeat times requires at least 3 parts (interval, duration, offset), got {}",
                    parts.len()
                ),
            });
        }

        let interval = TimeValue::parse(parts[0])?;
        let duration = TimeValue::parse(parts[1])?;

        let mut offsets = Vec::with_capacity(parts.len() - 2);
        for part in &parts[2..] {
            offsets.push(TimeValue::parse(part)?);
        }

        if offsets.is_empty() {
            return Err(SdpError::ParseError {
                reason: "repeat times requires at least one offset".to_string(),
            });
        }

        Ok(Self {
            interval,
            duration,
            offsets,
        })
    }

    /// Returns the repeat interval in seconds.
    #[must_use]
    pub const fn interval_seconds(&self) -> u64 {
        self.interval.as_seconds()
    }

    /// Returns the active duration in seconds.
    #[must_use]
    pub const fn duration_seconds(&self) -> u64 {
        self.duration.as_seconds()
    }

    /// Returns all offsets in seconds.
    #[must_use]
    pub fn offset_seconds(&self) -> Vec<u64> {
        self.offsets.iter().map(TimeValue::as_seconds).collect()
    }

    /// Checks if the repeat times are valid.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        // Interval must be positive
        if self.interval.seconds == 0 {
            return false;
        }
        // Duration must be positive
        if self.duration.seconds == 0 {
            return false;
        }
        // Duration should not exceed interval
        if self.duration.seconds > self.interval.seconds {
            return false;
        }
        // Must have at least one offset
        if self.offsets.is_empty() {
            return false;
        }
        true
    }
}

impl fmt::Display for RepeatTimes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r={} {}", self.interval, self.duration)?;
        for offset in &self.offsets {
            write!(f, " {offset}")?;
        }
        Ok(())
    }
}

// ============================================================================
// RFC 8866 §5.8 - Bandwidth (b= line)
// ============================================================================

/// Bandwidth information (b= line) per RFC 8866 §5.8.
///
/// Specifies the proposed bandwidth for the session or media.
///
/// Common bandwidth types:
/// - `CT` - Conference Total: total bandwidth for all media at all sites
/// - `AS` - Application Specific: bandwidth for a single media stream
/// - `TIAS` - Transport Independent Application Specific (RFC 3890)
///
/// ## Example
///
/// ```
/// use proto_sdp::session::BandwidthInfo;
///
/// let bw = BandwidthInfo::new("AS", 128);
/// assert_eq!(bw.bwtype(), "AS");
/// assert_eq!(bw.bandwidth(), 128);
/// assert_eq!(bw.to_string(), "b=AS:128");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BandwidthInfo {
    /// Bandwidth type (e.g., "CT", "AS", "TIAS").
    bwtype: String,
    /// Bandwidth value (kbps for CT/AS, bps for TIAS).
    bandwidth: u64,
}

impl BandwidthInfo {
    /// Creates a new bandwidth info.
    #[must_use]
    pub fn new(bwtype: impl Into<String>, bandwidth: u64) -> Self {
        Self {
            bwtype: bwtype.into(),
            bandwidth,
        }
    }

    /// Returns the bandwidth type.
    #[must_use]
    pub fn bwtype(&self) -> &str {
        &self.bwtype
    }

    /// Returns the bandwidth value.
    #[must_use]
    pub const fn bandwidth(&self) -> u64 {
        self.bandwidth
    }

    /// Parses bandwidth from b= line value.
    ///
    /// # Errors
    /// Returns an error if the format is invalid.
    pub fn parse(s: &str) -> SdpResult<Self> {
        let (bwtype, bw_str) = s.split_once(':').ok_or_else(|| SdpError::ParseError {
            reason: "bandwidth requires format 'type:value'".to_string(),
        })?;

        let bandwidth = bw_str.parse().map_err(|_| SdpError::ParseError {
            reason: format!("invalid bandwidth value: {bw_str}"),
        })?;

        Ok(Self {
            bwtype: bwtype.to_string(),
            bandwidth,
        })
    }
}

impl fmt::Display for BandwidthInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b={}:{}", self.bwtype, self.bandwidth)
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
    /// Bandwidth lines (b=).
    pub bandwidth: Vec<BandwidthInfo>,
    /// Timing.
    pub timing: Timing,
    /// Time zone adjustments (z= line, raw value).
    pub time_zones: Option<String>,
    /// Encryption key (k= line, raw value, deprecated).
    pub encryption_key: Option<String>,
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
            bandwidth: Vec::new(),
            timing: Timing::permanent(),
            time_zones: None,
            encryption_key: None,
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

        // b= lines
        for bw in &self.bandwidth {
            writeln!(f, "{bw}")?;
        }

        // t= line
        writeln!(f, "{}", self.timing)?;

        // z= line (optional)
        if let Some(ref tz) = self.time_zones {
            writeln!(f, "z={tz}")?;
        }

        // k= line (optional, deprecated)
        if let Some(ref key) = self.encryption_key {
            writeln!(f, "k={key}")?;
        }

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

/// Parser state for SDP session description.
#[derive(Default)]
struct SdpParseState {
    version: Option<u8>,
    origin: Option<Origin>,
    session_name: Option<String>,
    session_info: Option<String>,
    uri: Option<String>,
    emails: Vec<String>,
    phones: Vec<String>,
    connection: Option<ConnectionData>,
    bandwidth: Vec<BandwidthInfo>,
    timing: Option<Timing>,
    time_zones: Option<String>,
    encryption_key: Option<String>,
    attributes: Vec<Attribute>,
    media: Vec<MediaDescription>,
    current_media: Option<MediaDescription>,
}

#[allow(clippy::unnecessary_wraps)] // All parse methods return Result for consistency
impl SdpParseState {
    /// Parses a single SDP line.
    fn parse_line(&mut self, line_type: char, value: &str, line_num: usize) -> SdpResult<()> {
        match line_type {
            'v' => self.parse_version(value, line_num),
            'o' => self.parse_origin(value),
            's' => self.parse_session_name(value),
            'i' => self.parse_info(value),
            'u' => self.parse_uri(value),
            'e' => self.parse_email(value),
            'p' => self.parse_phone(value),
            'c' => self.parse_connection(value),
            'b' => self.parse_bandwidth(value),
            't' => self.parse_timing(value),
            'r' => self.parse_repeat(value, line_num),
            'z' => self.parse_time_zones(value),
            'k' => self.parse_encryption_key(value),
            'a' => self.parse_attribute(value),
            'm' => self.parse_media(value),
            _ => Ok(()), // Ignore truly unknown line types
        }
    }

    fn parse_version(&mut self, value: &str, line_num: usize) -> SdpResult<()> {
        self.version = Some(value.parse().map_err(|_| SdpError::InvalidLine {
            line: line_num + 1,
            reason: "invalid version".to_string(),
        })?);
        Ok(())
    }

    fn parse_origin(&mut self, value: &str) -> SdpResult<()> {
        self.origin = Some(Origin::parse(value)?);
        Ok(())
    }

    fn parse_session_name(&mut self, value: &str) -> SdpResult<()> {
        self.session_name = Some(value.to_string());
        Ok(())
    }

    fn parse_info(&mut self, value: &str) -> SdpResult<()> {
        if let Some(ref mut m) = self.current_media {
            m.info = Some(value.to_string());
        } else {
            self.session_info = Some(value.to_string());
        }
        Ok(())
    }

    fn parse_uri(&mut self, value: &str) -> SdpResult<()> {
        self.uri = Some(value.to_string());
        Ok(())
    }

    fn parse_email(&mut self, value: &str) -> SdpResult<()> {
        self.emails.push(value.to_string());
        Ok(())
    }

    fn parse_phone(&mut self, value: &str) -> SdpResult<()> {
        self.phones.push(value.to_string());
        Ok(())
    }

    fn parse_connection(&mut self, value: &str) -> SdpResult<()> {
        let conn = ConnectionData::parse(value)?;
        if let Some(ref mut m) = self.current_media {
            m.connection = Some(conn);
        } else {
            self.connection = Some(conn);
        }
        Ok(())
    }

    fn parse_timing(&mut self, value: &str) -> SdpResult<()> {
        self.timing = Some(Timing::parse(value)?);
        Ok(())
    }

    fn parse_bandwidth(&mut self, value: &str) -> SdpResult<()> {
        let bw = BandwidthInfo::parse(value)?;
        if let Some(ref mut m) = self.current_media {
            m.bandwidth.push(bw);
        } else {
            self.bandwidth.push(bw);
        }
        Ok(())
    }

    fn parse_time_zones(&mut self, value: &str) -> SdpResult<()> {
        self.time_zones = Some(value.to_string());
        Ok(())
    }

    fn parse_encryption_key(&mut self, value: &str) -> SdpResult<()> {
        if let Some(ref mut m) = self.current_media {
            m.encryption_key = Some(value.to_string());
        } else {
            self.encryption_key = Some(value.to_string());
        }
        Ok(())
    }

    fn parse_repeat(&mut self, value: &str, line_num: usize) -> SdpResult<()> {
        if let Some(ref mut t) = self.timing {
            t.add_repeat(RepeatTimes::parse(value)?);
            Ok(())
        } else {
            Err(SdpError::InvalidLine {
                line: line_num + 1,
                reason: "r= line must follow t= line".to_string(),
            })
        }
    }

    fn parse_attribute(&mut self, value: &str) -> SdpResult<()> {
        let attr = Attribute::parse(value)?;
        if let Some(ref mut m) = self.current_media {
            m.attributes.push(attr);
        } else {
            self.attributes.push(attr);
        }
        Ok(())
    }

    fn parse_media(&mut self, value: &str) -> SdpResult<()> {
        if let Some(m) = self.current_media.take() {
            self.media.push(m);
        }
        self.current_media = Some(MediaDescription::parse_mline(value)?);
        Ok(())
    }

    /// Finalizes parsing and builds the session description.
    fn build(mut self) -> SdpResult<SessionDescription> {
        // Finish last media section
        if let Some(m) = self.current_media.take() {
            self.media.push(m);
        }

        let version = self.version.ok_or_else(|| SdpError::MissingField {
            field: "v (version)".to_string(),
        })?;

        if version != SDP_VERSION {
            return Err(SdpError::UnsupportedVersion { version });
        }

        let origin = self.origin.ok_or_else(|| SdpError::MissingField {
            field: "o (origin)".to_string(),
        })?;

        let session_name = self.session_name.ok_or_else(|| SdpError::MissingField {
            field: "s (session name)".to_string(),
        })?;

        let timing = self.timing.ok_or_else(|| SdpError::MissingField {
            field: "t (timing)".to_string(),
        })?;

        Ok(SessionDescription {
            version,
            origin,
            session_name,
            session_info: self.session_info,
            uri: self.uri,
            emails: self.emails,
            phones: self.phones,
            connection: self.connection,
            bandwidth: self.bandwidth,
            timing,
            time_zones: self.time_zones,
            encryption_key: self.encryption_key,
            attributes: self.attributes,
            media: self.media,
        })
    }
}

/// Parses the line type and value from an SDP line.
fn parse_sdp_line(line: &str, line_num: usize) -> SdpResult<(char, &str)> {
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

    Ok((line_type, &line[2..]))
}

impl FromStr for SessionDescription {
    type Err = SdpError;

    fn from_str(s: &str) -> SdpResult<Self> {
        let mut state = SdpParseState::default();

        for (line_num, line) in s.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let (line_type, value) = parse_sdp_line(line, line_num)?;
            state.parse_line(line_type, value, line_num)?;
        }

        state.build()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
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

        let mut media = MediaDescription::new(
            crate::media::MediaType::Audio,
            5000,
            crate::media::TransportProtocol::RtpSavp,
        );
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

    // ========================================================================
    // RFC 8866 §5.11 - Repeat Times Tests
    // ========================================================================

    #[test]
    fn test_time_value_from_seconds() {
        let tv = TimeValue::from_seconds(3600);
        assert_eq!(tv.as_seconds(), 3600);
    }

    #[test]
    fn test_time_value_from_days() {
        let tv = TimeValue::from_days(7);
        assert_eq!(tv.as_seconds(), 604_800); // 7 * 86400
    }

    #[test]
    fn test_time_value_from_hours() {
        let tv = TimeValue::from_hours(2);
        assert_eq!(tv.as_seconds(), 7200);
    }

    #[test]
    fn test_time_value_from_minutes() {
        let tv = TimeValue::from_minutes(30);
        assert_eq!(tv.as_seconds(), 1800);
    }

    #[test]
    fn test_time_value_parse_seconds() {
        let tv = TimeValue::parse("3600").unwrap();
        assert_eq!(tv.as_seconds(), 3600);
    }

    #[test]
    fn test_time_value_parse_with_suffix() {
        assert_eq!(TimeValue::parse("7d").unwrap().as_seconds(), 604_800);
        assert_eq!(TimeValue::parse("2h").unwrap().as_seconds(), 7200);
        assert_eq!(TimeValue::parse("30m").unwrap().as_seconds(), 1800);
        assert_eq!(TimeValue::parse("60s").unwrap().as_seconds(), 60);
    }

    #[test]
    fn test_time_value_compact_display() {
        assert_eq!(TimeValue::from_days(7).to_compact_string(), "7d");
        assert_eq!(TimeValue::from_hours(2).to_compact_string(), "2h");
        assert_eq!(TimeValue::from_minutes(30).to_compact_string(), "30m");
        assert_eq!(TimeValue::from_seconds(45).to_compact_string(), "45");
    }

    #[test]
    fn test_repeat_times_creation() {
        let repeat = RepeatTimes::new(
            TimeValue::from_days(7),
            TimeValue::from_hours(1),
            vec![TimeValue::from_seconds(0)],
        );

        assert_eq!(repeat.interval_seconds(), 604_800);
        assert_eq!(repeat.duration_seconds(), 3600);
        assert!(repeat.is_valid());
    }

    #[test]
    fn test_repeat_times_daily() {
        let repeat = RepeatTimes::daily(
            TimeValue::from_hours(1),
            vec![TimeValue::from_hours(9)], // 9am daily
        );

        assert_eq!(repeat.interval_seconds(), 86400);
        assert!(repeat.is_valid());
    }

    #[test]
    fn test_repeat_times_weekly() {
        let repeat = RepeatTimes::weekly(
            TimeValue::from_hours(2),
            vec![TimeValue::from_seconds(0), TimeValue::from_days(1)],
        );

        assert_eq!(repeat.interval_seconds(), 604_800);
        assert!(repeat.is_valid());
    }

    #[test]
    fn test_repeat_times_parse_simple() {
        // Weekly, 1 hour, starting at offset 0
        let repeat = RepeatTimes::parse("604800 3600 0").unwrap();

        assert_eq!(repeat.interval.as_seconds(), 604_800);
        assert_eq!(repeat.duration.as_seconds(), 3600);
        assert_eq!(repeat.offsets.len(), 1);
        assert_eq!(repeat.offsets[0].as_seconds(), 0);
    }

    #[test]
    fn test_repeat_times_parse_compact() {
        // Weekly (7d), 1 hour (1h), offsets at 0 and 25h
        let repeat = RepeatTimes::parse("7d 1h 0 25h").unwrap();

        assert_eq!(repeat.interval.as_seconds(), 604_800);
        assert_eq!(repeat.duration.as_seconds(), 3600);
        assert_eq!(repeat.offsets.len(), 2);
        assert_eq!(repeat.offsets[0].as_seconds(), 0);
        assert_eq!(repeat.offsets[1].as_seconds(), 90000); // 25 hours
    }

    #[test]
    fn test_repeat_times_parse_rfc_example() {
        // RFC 8866 example: weekly, 1 hour, offsets at 0 and 90000
        let repeat = RepeatTimes::parse("604800 3600 0 90000").unwrap();

        assert_eq!(repeat.interval_seconds(), 604_800);
        assert_eq!(repeat.duration_seconds(), 3600);
        assert_eq!(repeat.offset_seconds(), vec![0, 90000]);
    }

    #[test]
    fn test_repeat_times_display() {
        let repeat = RepeatTimes::new(
            TimeValue::from_days(7),
            TimeValue::from_hours(1),
            vec![TimeValue::from_seconds(0), TimeValue::from_hours(25)],
        );

        let display = repeat.to_string();
        assert!(display.starts_with("r="));
        assert!(display.contains("7d"));
        assert!(display.contains("1h"));
    }

    #[test]
    fn test_repeat_times_invalid_no_offset() {
        let result = RepeatTimes::parse("7d 1h");
        assert!(result.is_err());
    }

    #[test]
    fn test_repeat_times_is_valid() {
        // Valid
        let valid = RepeatTimes::new(
            TimeValue::from_days(1),
            TimeValue::from_hours(1),
            vec![TimeValue::from_seconds(0)],
        );
        assert!(valid.is_valid());

        // Invalid: zero interval
        let invalid_interval = RepeatTimes::new(
            TimeValue::from_seconds(0),
            TimeValue::from_hours(1),
            vec![TimeValue::from_seconds(0)],
        );
        assert!(!invalid_interval.is_valid());

        // Invalid: zero duration
        let invalid_duration = RepeatTimes::new(
            TimeValue::from_days(1),
            TimeValue::from_seconds(0),
            vec![TimeValue::from_seconds(0)],
        );
        assert!(!invalid_duration.is_valid());

        // Invalid: duration > interval
        let invalid_too_long = RepeatTimes::new(
            TimeValue::from_hours(1),
            TimeValue::from_hours(2),
            vec![TimeValue::from_seconds(0)],
        );
        assert!(!invalid_too_long.is_valid());

        // Invalid: no offsets
        let invalid_no_offsets = RepeatTimes {
            interval: TimeValue::from_days(1),
            duration: TimeValue::from_hours(1),
            offsets: vec![],
        };
        assert!(!invalid_no_offsets.is_valid());
    }

    #[test]
    fn test_timing_with_repeat() {
        let timing =
            Timing::with_times(3_034_423_619, 3_042_462_419).with_repeat(RepeatTimes::new(
                TimeValue::from_days(7),
                TimeValue::from_hours(1),
                vec![TimeValue::from_seconds(0), TimeValue::from_hours(25)],
            ));

        assert!(timing.has_repeats());
        assert_eq!(timing.repeat_times.len(), 1);
    }

    #[test]
    fn test_timing_display_with_repeat() {
        let timing = Timing::with_times(0, 0).with_repeat(RepeatTimes::new(
            TimeValue::from_days(1),
            TimeValue::from_hours(1),
            vec![TimeValue::from_seconds(0)],
        ));

        let display = timing.to_string();
        assert!(display.contains("t=0 0"));
        assert!(display.contains("r="));
    }

    #[test]
    fn test_session_parse_with_repeat_times() {
        let sdp = "v=0\r\n\
                   o=- 123456 1 IN IP6 ::1\r\n\
                   s=Weekly Broadcast\r\n\
                   t=3034423619 3042462419\r\n\
                   r=604800 3600 0 90000\r\n\
                   m=audio 5000 RTP/SAVP 0\r\n";

        let session: SessionDescription = sdp.parse().unwrap();
        assert!(session.timing.has_repeats());
        assert_eq!(session.timing.repeat_times.len(), 1);

        let repeat = &session.timing.repeat_times[0];
        assert_eq!(repeat.interval_seconds(), 604_800);
        assert_eq!(repeat.duration_seconds(), 3600);
        assert_eq!(repeat.offset_seconds(), vec![0, 90000]);
    }

    #[test]
    fn test_session_parse_with_multiple_repeat_times() {
        let sdp = "v=0\r\n\
                   o=- 123 1 IN IP6 ::1\r\n\
                   s=-\r\n\
                   t=0 0\r\n\
                   r=7d 1h 0\r\n\
                   r=1d 30m 9h 14h\r\n\
                   m=audio 5000 RTP/SAVP 0\r\n";

        let session: SessionDescription = sdp.parse().unwrap();
        assert_eq!(session.timing.repeat_times.len(), 2);

        // First repeat: weekly, 1 hour
        assert_eq!(session.timing.repeat_times[0].interval_seconds(), 604_800);
        assert_eq!(session.timing.repeat_times[0].duration_seconds(), 3600);

        // Second repeat: daily, 30 min, at 9am and 2pm
        assert_eq!(session.timing.repeat_times[1].interval_seconds(), 86400);
        assert_eq!(session.timing.repeat_times[1].duration_seconds(), 1800);
        assert_eq!(session.timing.repeat_times[1].offsets.len(), 2);
    }

    #[test]
    fn test_session_roundtrip_with_repeat_times() {
        let origin = Origin::new("12345");
        let mut session = SessionDescription::new(origin);
        session.timing = Timing::with_times(0, 0).with_repeat(RepeatTimes::new(
            TimeValue::from_days(7),
            TimeValue::from_hours(2),
            vec![TimeValue::from_seconds(0)],
        ));

        let sdp = session.to_string();
        let reparsed: SessionDescription = sdp.parse().unwrap();

        assert!(reparsed.timing.has_repeats());
        assert_eq!(reparsed.timing.repeat_times[0].interval_seconds(), 604_800);
    }

    #[test]
    fn test_repeat_times_error_before_timing() {
        let sdp = "v=0\r\n\
                   o=- 123 1 IN IP6 ::1\r\n\
                   s=-\r\n\
                   r=7d 1h 0\r\n\
                   t=0 0\r\n";

        let result: SdpResult<SessionDescription> = sdp.parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_time_value_as_duration() {
        let tv = TimeValue::from_hours(2);
        let duration = tv.as_duration();
        assert_eq!(duration.as_secs(), 7200);
    }
}
