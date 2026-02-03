//! SIPREC recording metadata per RFC 7865.
//!
//! Defines the metadata structures exchanged between the Session Recording
//! Client (SRC) and Session Recording Server (SRS).
//!
//! ## Metadata Components
//!
//! Per RFC 7865 Section 5:
//! - Recording Session metadata
//! - Communication Session metadata
//! - Participant information
//! - Media stream information

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::time::{Duration, SystemTime};

/// Unique identifier for recording entities.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordingId(String);

impl RecordingId {
    /// Creates a new recording ID.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generates a new unique recording ID.
    #[must_use]
    pub fn generate() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos();
        Self(format!("rec-{timestamp:x}"))
    }

    /// Returns the ID as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecordingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Direction of a media stream relative to a participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    /// Stream sends media.
    Send,
    /// Stream receives media.
    Receive,
    /// Stream both sends and receives.
    SendReceive,
    /// Stream is inactive.
    Inactive,
}

impl fmt::Display for StreamDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Send => write!(f, "sendonly"),
            Self::Receive => write!(f, "recvonly"),
            Self::SendReceive => write!(f, "sendrecv"),
            Self::Inactive => write!(f, "inactive"),
        }
    }
}

/// Role of a participant in the communication session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParticipantRole {
    /// Caller (initiator).
    Caller,
    /// Callee (recipient).
    #[default]
    Callee,
    /// Observer (third party).
    Observer,
    /// Supervisor (monitoring).
    Supervisor,
}

impl fmt::Display for ParticipantRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Caller => write!(f, "caller"),
            Self::Callee => write!(f, "callee"),
            Self::Observer => write!(f, "observer"),
            Self::Supervisor => write!(f, "supervisor"),
        }
    }
}

/// Participant in a recorded communication session.
#[derive(Debug, Clone)]
pub struct Participant {
    /// Unique participant ID.
    pub id: String,
    /// SIP `AoR` (Address of Record).
    pub aor: String,
    /// Display name.
    pub display_name: Option<String>,
    /// Participant role.
    pub role: ParticipantRole,
    /// When participant joined.
    pub join_time: Option<SystemTime>,
    /// When participant left.
    pub leave_time: Option<SystemTime>,
    /// Associated media stream IDs.
    pub stream_ids: Vec<String>,
    /// Additional custom attributes.
    pub attributes: HashMap<String, String>,
}

impl Participant {
    /// Creates a new participant.
    #[must_use]
    pub fn new(id: impl Into<String>, aor: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            aor: aor.into(),
            display_name: None,
            role: ParticipantRole::default(),
            join_time: None,
            leave_time: None,
            stream_ids: Vec::new(),
            attributes: HashMap::new(),
        }
    }

    /// Sets the display name.
    #[must_use]
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Sets the role.
    #[must_use]
    pub const fn with_role(mut self, role: ParticipantRole) -> Self {
        self.role = role;
        self
    }

    /// Sets the join time.
    #[must_use]
    pub const fn with_join_time(mut self, time: SystemTime) -> Self {
        self.join_time = Some(time);
        self
    }

    /// Associates a stream ID with this participant.
    pub fn add_stream(&mut self, stream_id: impl Into<String>) {
        self.stream_ids.push(stream_id.into());
    }

    /// Sets a custom attribute.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// Records that participant left.
    pub const fn left(&mut self, time: SystemTime) {
        self.leave_time = Some(time);
    }

    /// Duration participant was active.
    #[must_use]
    pub fn duration(&self) -> Option<Duration> {
        match (self.join_time, self.leave_time) {
            (Some(join), Some(leave)) => leave.duration_since(join).ok(),
            _ => None,
        }
    }
}

/// Media stream in a recording session.
#[derive(Debug, Clone)]
pub struct MediaStream {
    /// Unique stream ID.
    pub id: String,
    /// Media type (audio, video, etc.).
    pub media_type: String,
    /// Codec name.
    pub codec: Option<String>,
    /// RTP payload type.
    pub payload_type: Option<u8>,
    /// Stream direction.
    pub direction: StreamDirection,
    /// SSRC (Synchronization Source).
    pub ssrc: Option<u32>,
    /// Associated participant ID.
    pub participant_id: Option<String>,
    /// Stream start time.
    pub start_time: Option<SystemTime>,
    /// Stream end time.
    pub end_time: Option<SystemTime>,
    /// Additional attributes.
    pub attributes: HashMap<String, String>,
}

impl MediaStream {
    /// Creates a new media stream.
    #[must_use]
    pub fn new(id: impl Into<String>, media_type: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            media_type: media_type.into(),
            codec: None,
            payload_type: None,
            direction: StreamDirection::SendReceive,
            ssrc: None,
            participant_id: None,
            start_time: None,
            end_time: None,
            attributes: HashMap::new(),
        }
    }

    /// Creates an audio stream.
    #[must_use]
    pub fn audio(id: impl Into<String>) -> Self {
        Self::new(id, "audio")
    }

    /// Creates a video stream.
    #[must_use]
    pub fn video(id: impl Into<String>) -> Self {
        Self::new(id, "video")
    }

    /// Sets the codec.
    #[must_use]
    pub fn with_codec(mut self, codec: impl Into<String>) -> Self {
        self.codec = Some(codec.into());
        self
    }

    /// Sets the payload type.
    #[must_use]
    pub const fn with_payload_type(mut self, pt: u8) -> Self {
        self.payload_type = Some(pt);
        self
    }

    /// Sets the SSRC.
    #[must_use]
    pub const fn with_ssrc(mut self, ssrc: u32) -> Self {
        self.ssrc = Some(ssrc);
        self
    }

    /// Sets the direction.
    #[must_use]
    pub const fn with_direction(mut self, direction: StreamDirection) -> Self {
        self.direction = direction;
        self
    }

    /// Associates with a participant.
    #[must_use]
    pub fn with_participant(mut self, participant_id: impl Into<String>) -> Self {
        self.participant_id = Some(participant_id.into());
        self
    }

    /// Marks stream as started.
    pub const fn started(&mut self, time: SystemTime) {
        self.start_time = Some(time);
    }

    /// Marks stream as ended.
    pub const fn ended(&mut self, time: SystemTime) {
        self.end_time = Some(time);
    }

    /// Returns stream duration.
    #[must_use]
    pub fn duration(&self) -> Option<Duration> {
        match (self.start_time, self.end_time) {
            (Some(start), Some(end)) => end.duration_since(start).ok(),
            _ => None,
        }
    }
}

/// Session-level metadata.
#[derive(Debug, Clone)]
pub struct SessionMetadata {
    /// Recording session ID (RS identifier).
    pub recording_session_id: RecordingId,
    /// Communication session ID (CS Call-ID).
    pub communication_session_id: String,
    /// Recording start time.
    pub start_time: SystemTime,
    /// Recording end time (if ended).
    pub end_time: Option<SystemTime>,
    /// Session state.
    pub state: SessionState,
    /// Recording reason/trigger.
    pub reason: Option<String>,
    /// Recording server URI.
    pub srs_uri: Option<String>,
    /// Custom session attributes.
    pub attributes: HashMap<String, String>,
}

impl SessionMetadata {
    /// Creates new session metadata.
    #[must_use]
    pub fn new(communication_session_id: impl Into<String>) -> Self {
        Self {
            recording_session_id: RecordingId::generate(),
            communication_session_id: communication_session_id.into(),
            start_time: SystemTime::now(),
            end_time: None,
            state: SessionState::Pending,
            reason: None,
            srs_uri: None,
            attributes: HashMap::new(),
        }
    }

    /// Sets the recording reason.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Sets the SRS URI.
    #[must_use]
    pub fn with_srs_uri(mut self, uri: impl Into<String>) -> Self {
        self.srs_uri = Some(uri.into());
        self
    }

    /// Marks session as active.
    pub const fn activate(&mut self) {
        self.state = SessionState::Active;
    }

    /// Marks session as completed.
    pub fn complete(&mut self) {
        self.state = SessionState::Completed;
        self.end_time = Some(SystemTime::now());
    }

    /// Marks session as failed.
    pub fn fail(&mut self, reason: impl Into<String>) {
        self.state = SessionState::Failed;
        self.end_time = Some(SystemTime::now());
        self.set_attribute("failure_reason", reason);
    }

    /// Sets a custom attribute.
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// Recording duration.
    #[must_use]
    pub fn duration(&self) -> Option<Duration> {
        let end = self.end_time.unwrap_or_else(SystemTime::now);
        end.duration_since(self.start_time).ok()
    }
}

/// Recording session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SessionState {
    /// Session setup pending.
    #[default]
    Pending,
    /// Session is active (recording).
    Active,
    /// Session paused (temporarily stopped).
    Paused,
    /// Session completed successfully.
    Completed,
    /// Session failed.
    Failed,
}

impl fmt::Display for SessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Complete recording metadata structure per RFC 7865.
#[derive(Debug, Clone)]
pub struct RecordingMetadata {
    /// Session-level metadata.
    pub session: SessionMetadata,
    /// Participants in the communication session.
    pub participants: Vec<Participant>,
    /// Media streams being recorded.
    pub streams: Vec<MediaStream>,
    /// Metadata format version.
    pub version: String,
}

impl RecordingMetadata {
    /// Creates new recording metadata.
    #[must_use]
    pub fn new(communication_session_id: impl Into<String>) -> Self {
        Self {
            session: SessionMetadata::new(communication_session_id),
            participants: Vec::new(),
            streams: Vec::new(),
            version: "1.0".to_string(),
        }
    }

    /// Adds a participant.
    pub fn add_participant(&mut self, participant: Participant) {
        self.participants.push(participant);
    }

    /// Adds a media stream.
    pub fn add_stream(&mut self, stream: MediaStream) {
        self.streams.push(stream);
    }

    /// Gets a participant by ID.
    #[must_use]
    pub fn get_participant(&self, id: &str) -> Option<&Participant> {
        self.participants.iter().find(|p| p.id == id)
    }

    /// Gets a mutable participant by ID.
    pub fn get_participant_mut(&mut self, id: &str) -> Option<&mut Participant> {
        self.participants.iter_mut().find(|p| p.id == id)
    }

    /// Gets a stream by ID.
    #[must_use]
    pub fn get_stream(&self, id: &str) -> Option<&MediaStream> {
        self.streams.iter().find(|s| s.id == id)
    }

    /// Gets a mutable stream by ID.
    pub fn get_stream_mut(&mut self, id: &str) -> Option<&mut MediaStream> {
        self.streams.iter_mut().find(|s| s.id == id)
    }

    /// Generates XML representation per RFC 7865.
    ///
    /// Note: This is a simplified XML representation. A full implementation
    /// would use proper XML libraries for namespace handling.
    #[must_use]
    pub fn to_xml(&self) -> String {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n");

        // Session info
        let _ = writeln!(xml, "  <session id=\"{}\">", self.session.recording_session_id);
        let _ = writeln!(
            xml,
            "    <call-id>{}</call-id>",
            self.session.communication_session_id
        );
        let _ = writeln!(xml, "    <state>{}</state>", self.session.state);
        if let Some(ref reason) = self.session.reason {
            let _ = writeln!(xml, "    <reason>{reason}</reason>");
        }
        xml.push_str("  </session>\n");

        // Participants
        xml.push_str("  <participants>\n");
        for participant in &self.participants {
            let _ = writeln!(xml, "    <participant id=\"{}\">", participant.id);
            let _ = writeln!(xml, "      <aor>{}</aor>", participant.aor);
            if let Some(ref name) = participant.display_name {
                let _ = writeln!(xml, "      <name>{name}</name>");
            }
            let _ = writeln!(xml, "      <role>{}</role>", participant.role);
            xml.push_str("    </participant>\n");
        }
        xml.push_str("  </participants>\n");

        // Streams
        xml.push_str("  <streams>\n");
        for stream in &self.streams {
            let _ = writeln!(xml, "    <stream id=\"{}\">", stream.id);
            let _ = writeln!(xml, "      <media-type>{}</media-type>", stream.media_type);
            if let Some(ref codec) = stream.codec {
                let _ = writeln!(xml, "      <codec>{codec}</codec>");
            }
            let _ = writeln!(xml, "      <direction>{}</direction>", stream.direction);
            if let Some(ssrc) = stream.ssrc {
                let _ = writeln!(xml, "      <ssrc>{ssrc}</ssrc>");
            }
            if let Some(ref participant_id) = stream.participant_id {
                let _ = writeln!(xml, "      <participant-id>{participant_id}</participant-id>");
            }
            xml.push_str("    </stream>\n");
        }
        xml.push_str("  </streams>\n");

        xml.push_str("</recording>\n");
        xml
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recording_id_generation() {
        let id1 = RecordingId::generate();
        let id2 = RecordingId::generate();

        // IDs should be unique (different)
        assert_ne!(id1.as_str(), id2.as_str());
        assert!(id1.as_str().starts_with("rec-"));
    }

    #[test]
    fn test_participant_creation() {
        let mut participant = Participant::new("p1", "sip:alice@example.com")
            .with_display_name("Alice")
            .with_role(ParticipantRole::Caller)
            .with_join_time(SystemTime::now());

        participant.add_stream("stream-1");
        participant.set_attribute("department", "sales");

        assert_eq!(participant.id, "p1");
        assert_eq!(participant.aor, "sip:alice@example.com");
        assert_eq!(participant.display_name.as_deref(), Some("Alice"));
        assert_eq!(participant.role, ParticipantRole::Caller);
        assert_eq!(participant.stream_ids.len(), 1);
        assert_eq!(
            participant.attributes.get("department").map(String::as_str),
            Some("sales")
        );
    }

    #[test]
    fn test_media_stream_creation() {
        let stream = MediaStream::audio("s1")
            .with_codec("PCMU")
            .with_payload_type(0)
            .with_ssrc(12345)
            .with_direction(StreamDirection::SendReceive)
            .with_participant("p1");

        assert_eq!(stream.id, "s1");
        assert_eq!(stream.media_type, "audio");
        assert_eq!(stream.codec.as_deref(), Some("PCMU"));
        assert_eq!(stream.payload_type, Some(0));
        assert_eq!(stream.ssrc, Some(12345));
        assert_eq!(stream.direction, StreamDirection::SendReceive);
        assert_eq!(stream.participant_id.as_deref(), Some("p1"));
    }

    #[test]
    fn test_session_metadata() {
        let mut metadata = SessionMetadata::new("call-123@example.com")
            .with_reason("compliance recording")
            .with_srs_uri("sip:recorder@example.com");

        assert_eq!(metadata.communication_session_id, "call-123@example.com");
        assert_eq!(metadata.state, SessionState::Pending);

        metadata.activate();
        assert_eq!(metadata.state, SessionState::Active);

        metadata.complete();
        assert_eq!(metadata.state, SessionState::Completed);
        assert!(metadata.end_time.is_some());
    }

    #[test]
    fn test_recording_metadata_xml() {
        let mut metadata = RecordingMetadata::new("call-abc@example.com");

        metadata.add_participant(
            Participant::new("p1", "sip:alice@example.com")
                .with_display_name("Alice")
                .with_role(ParticipantRole::Caller),
        );

        metadata.add_participant(
            Participant::new("p2", "sip:bob@example.com")
                .with_display_name("Bob")
                .with_role(ParticipantRole::Callee),
        );

        metadata.add_stream(
            MediaStream::audio("s1")
                .with_codec("PCMU")
                .with_ssrc(11111)
                .with_participant("p1"),
        );

        metadata.add_stream(
            MediaStream::audio("s2")
                .with_codec("PCMU")
                .with_ssrc(22222)
                .with_participant("p2"),
        );

        let xml = metadata.to_xml();

        assert!(xml.contains("urn:ietf:params:xml:ns:recording:1"));
        assert!(xml.contains("call-abc@example.com"));
        assert!(xml.contains("Alice"));
        assert!(xml.contains("Bob"));
        assert!(xml.contains("<media-type>audio</media-type>"));
        assert!(xml.contains("<codec>PCMU</codec>"));
    }

    #[test]
    fn test_stream_direction_display() {
        assert_eq!(format!("{}", StreamDirection::Send), "sendonly");
        assert_eq!(format!("{}", StreamDirection::Receive), "recvonly");
        assert_eq!(format!("{}", StreamDirection::SendReceive), "sendrecv");
        assert_eq!(format!("{}", StreamDirection::Inactive), "inactive");
    }

    #[test]
    fn test_participant_role_display() {
        assert_eq!(format!("{}", ParticipantRole::Caller), "caller");
        assert_eq!(format!("{}", ParticipantRole::Callee), "callee");
        assert_eq!(format!("{}", ParticipantRole::Observer), "observer");
        assert_eq!(format!("{}", ParticipantRole::Supervisor), "supervisor");
    }
}
