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

use crate::error::{SiprecError, SiprecResult};
use crate::xml::{escape_attr, escape_text};

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
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        #[allow(clippy::cast_possible_truncation)] // nanos won't overflow u64 until year 2554
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_nanos() as u64;
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        Self(format!("rec-{timestamp:x}-{counter:x}"))
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
    /// RFC 7989 Session-ID of the CS, emitted as `<sipSessionID>`.
    pub sip_session_id: Option<String>,
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
            sip_session_id: None,
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

    /// Serializes the metadata as an RFC 7865 `application/rs-metadata+xml`
    /// document (`urn:ietf:params:xml:ns:recording:1`, `datamode` complete).
    ///
    /// Element IDs (`session_id`, `participant_id`, `stream_id`) are fresh
    /// base64-encoded 128-bit values from the `uc-crypto` RNG on every call.
    /// RFC 7865 §6.10: IDs MUST be globally unique.
    ///
    /// Codec, SSRC, payload type and role are internal model fields that are
    /// not part of the RFC 7865 schema and are not emitted; the SRS learns them
    /// from the RS SDP (`a=label`, RFC 7866 §7.1.1).
    ///
    /// # Errors
    ///
    /// - [`SiprecError::InvalidMetadata`] if any field contains a code point
    ///   that is illegal in XML 1.0, a stream label is not an RFC 4574 token,
    ///   or a stream references an unknown participant.
    /// - [`SiprecError::LimitExceeded`] if a count, field length, or the total
    ///   document size exceeds the caps in this module.
    /// - [`SiprecError::MetadataError`] if the RNG fails.
    // NIST 800-53 Rev5: SI-10 (Information Input Validation), SI-15
    // (Information Output Filtering) - every attacker-derived string is
    // escaped or rejected; no markup is built from raw fields.
    // NIST 800-53 Rev5: SC-5 (Denial-of-Service Protection) - count, length
    // and total-size caps.
    // POAM: POA&M-305 - IDs are not stable across calls, so metadata
    // snapshots/partial updates (re-INVITE, transfer, T.38 switch) cannot yet
    // refer to previously sent elements.
    pub fn to_rfc7865_xml(&self) -> SiprecResult<String> {
        self.to_rfc7865_xml_with(&mut random_id)
    }

    /// Serializer core with an injectable ID source (golden-file tests).
    pub(crate) fn to_rfc7865_xml_with(
        &self,
        next_id: &mut dyn FnMut() -> SiprecResult<String>,
    ) -> SiprecResult<String> {
        self.check_limits()?;

        let session_id = next_id()?;
        let participant_ids = self
            .participants
            .iter()
            .map(|_| next_id())
            .collect::<SiprecResult<Vec<_>>>()?;
        let stream_ids = self
            .streams
            .iter()
            .map(|_| next_id())
            .collect::<SiprecResult<Vec<_>>>()?;

        // Owner index for each stream (validated before any output).
        let mut owners = Vec::with_capacity(self.streams.len());
        for stream in &self.streams {
            check_label(&stream.id)?;
            let owner = match &stream.participant_id {
                Some(pid) => Some(
                    self.participants
                        .iter()
                        .position(|p| &p.id == pid)
                        .ok_or_else(|| invalid("stream references unknown participant"))?,
                ),
                None => None,
            };
            owners.push(owner);
        }

        let mut out = String::with_capacity(1024);
        out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str("<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">\n");
        // RFC 7865 §5.1.2 / §9: the schema element is `datamode`.
        out.push_str("  <datamode>complete</datamode>\n");

        // RFC 7865 §6.3 Communication Session.
        let _ = writeln!(out, "  <session session_id=\"{session_id}\">");
        if let Some(sid) = &self.session.sip_session_id {
            let _ = writeln!(
                out,
                "    <sipSessionID>{}</sipSessionID>",
                escape_text(sid)?
            );
        }
        out.push_str("  </session>\n");

        // RFC 7865 §6.5 Participant.
        for (p, pid) in self.participants.iter().zip(&participant_ids) {
            let _ = writeln!(out, "  <participant participant_id=\"{pid}\">");
            let _ = write!(out, "    <nameID aor=\"{}\"", escape_attr(&p.aor)?);
            match &p.display_name {
                Some(name) => {
                    let _ = writeln!(out, ">\n      <name>{}</name>", escape_text(name)?);
                    out.push_str("    </nameID>\n");
                }
                None => out.push_str("/>\n"),
            }
            out.push_str("  </participant>\n");
        }

        // RFC 7865 §6.7 Media Stream; label matches the RS SDP a=label.
        for (s, sid) in self.streams.iter().zip(&stream_ids) {
            let _ = writeln!(
                out,
                "  <stream stream_id=\"{sid}\" session_id=\"{session_id}\">"
            );
            let _ = writeln!(out, "    <label>{}</label>", escape_text(&s.id)?);
            out.push_str("  </stream>\n");
        }

        // RFC 7865 §6.4 association of the CS with the RS.
        let _ = writeln!(out, "  <sessionrecordingassoc session_id=\"{session_id}\">");
        write_assoc_times(
            &mut out,
            Some(self.session.start_time),
            self.session.end_time,
        );
        out.push_str("  </sessionrecordingassoc>\n");

        // RFC 7865 §9: `recording` is an xs:sequence, so every
        // participantsessionassoc precedes every participantstreamassoc.
        for (p, pid) in self.participants.iter().zip(&participant_ids) {
            let _ = writeln!(
                out,
                "  <participantsessionassoc participant_id=\"{pid}\" session_id=\"{session_id}\">"
            );
            write_assoc_times(&mut out, p.join_time, p.leave_time);
            out.push_str("  </participantsessionassoc>\n");
        }

        for (idx, pid) in participant_ids.iter().enumerate() {
            // RFC 7865 §6.8: a participant sends the streams it owns and
            // receives the streams owned by the other participants.
            let _ = writeln!(out, "  <participantstreamassoc participant_id=\"{pid}\">");
            for (owner, sid) in owners.iter().zip(&stream_ids) {
                if *owner == Some(idx) {
                    let _ = writeln!(out, "    <send>{sid}</send>");
                }
            }
            for (owner, sid) in owners.iter().zip(&stream_ids) {
                if owner.is_some_and(|o| o != idx) {
                    let _ = writeln!(out, "    <recv>{sid}</recv>");
                }
            }
            out.push_str("  </participantstreamassoc>\n");
        }

        out.push_str("</recording>\n");

        if out.len() > MAX_DOCUMENT_BYTES {
            return Err(SiprecError::LimitExceeded {
                what: "metadata document bytes",
                limit: MAX_DOCUMENT_BYTES,
            });
        }
        Ok(out)
    }

    fn check_limits(&self) -> SiprecResult<()> {
        if self.participants.len() > MAX_PARTICIPANTS {
            return Err(SiprecError::LimitExceeded {
                what: "participants",
                limit: MAX_PARTICIPANTS,
            });
        }
        if self.streams.len() > MAX_STREAMS {
            return Err(SiprecError::LimitExceeded {
                what: "streams",
                limit: MAX_STREAMS,
            });
        }
        let fields = self
            .participants
            .iter()
            .flat_map(|p| std::iter::once(p.aor.as_str()).chain(p.display_name.as_deref()))
            .chain(self.streams.iter().map(|s| s.id.as_str()))
            .chain(self.session.sip_session_id.as_deref());
        for field in fields {
            if field.len() > MAX_FIELD_BYTES {
                return Err(SiprecError::LimitExceeded {
                    what: "metadata field bytes",
                    limit: MAX_FIELD_BYTES,
                });
            }
        }
        Ok(())
    }
}

/// Maximum participants serialized into one metadata document.
pub const MAX_PARTICIPANTS: usize = 16;
/// Maximum media streams serialized into one metadata document.
pub const MAX_STREAMS: usize = 32;
/// Maximum length in bytes of any single string field.
pub const MAX_FIELD_BYTES: usize = 1024;
/// Maximum size in bytes of the serialized document.
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

fn invalid(reason: &str) -> SiprecError {
    SiprecError::InvalidMetadata {
        reason: reason.to_string(),
    }
}

/// RFC 4574 §4: `label` is a `token` (RFC 4566 token-char). We accept only
/// the `[A-Za-z0-9._-]` subset so labels never need escaping anywhere.
fn check_label(label: &str) -> SiprecResult<()> {
    let ok = !label.is_empty()
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'));
    if ok {
        Ok(())
    } else {
        Err(invalid("stream label is not an RFC 4574 token"))
    }
}

fn write_assoc_times(out: &mut String, start: Option<SystemTime>, stop: Option<SystemTime>) {
    if let Some(t) = start {
        let _ = writeln!(out, "    <associate-time>{}</associate-time>", rfc3339(t));
    }
    if let Some(t) = stop {
        let _ = writeln!(
            out,
            "    <disassociate-time>{}</disassociate-time>",
            rfc3339(t)
        );
    }
}

/// RFC 7865 §6.10: a random (version 4) UUID, base64 encoded. The version
/// and variant bits are set as RFC 9562 §5.4 requires, leaving 122 random
/// bits.
fn random_id() -> SiprecResult<String> {
    // NIST 800-53 Rev5: SC-13 - randomness via uc-crypto (aws-lc-rs).
    let mut bytes: [u8; 16] =
        uc_crypto::random::generate_random().map_err(|e| SiprecError::MetadataError {
            reason: format!("RNG failure: {e}"),
        })?;
    let [.., version, _, variant, _, _, _, _, _, _, _] = &mut bytes;
    *version = (*version & 0x0F) | 0x40;
    *variant = (*variant & 0x3F) | 0x80;
    Ok(base64_encode(&bytes))
}

/// Standard base64 (RFC 4648 §4) with padding.
pub(crate) fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let idx = |shift: u32| {
            char::from(
                ALPHABET
                    .get(((n >> shift) & 0x3f) as usize)
                    .copied()
                    .unwrap_or(b'A'),
            )
        };
        out.push(idx(18));
        out.push(idx(12));
        out.push(if chunk.len() > 1 { idx(6) } else { '=' });
        out.push(if chunk.len() > 2 { idx(0) } else { '=' });
    }
    out
}

/// Formats a time as RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`). Times before
/// the Unix epoch clamp to the epoch.
pub(crate) fn rfc3339(t: SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian
/// (H. Hinnant's `civil_from_days`, unsigned domain).
const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

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

    fn sample() -> RecordingMetadata {
        let mut metadata = RecordingMetadata::new("call-abc@example.com");
        metadata.session.start_time = UNIX_EPOCH + Duration::from_secs(1_292_542_867);
        metadata.session.sip_session_id =
            Some("ab30317f1a784dc48ff824d0d3715d86;remote=47755a9de7794ba387653f2099600ef2".into());
        metadata.add_participant(
            Participant::new("p1", "sip:alice@example.com")
                .with_display_name("Alice")
                .with_role(ParticipantRole::Caller)
                .with_join_time(UNIX_EPOCH + Duration::from_secs(1_292_542_867)),
        );
        metadata.add_participant(
            Participant::new("p2", "sip:bob@example.com")
                .with_join_time(UNIX_EPOCH + Duration::from_secs(1_292_542_867)),
        );
        metadata.add_stream(
            MediaStream::audio("96")
                .with_codec("PCMU")
                .with_ssrc(11111)
                .with_participant("p1"),
        );
        metadata.add_stream(MediaStream::audio("97").with_participant("p2"));
        metadata
    }

    fn counter_ids() -> impl FnMut() -> SiprecResult<String> {
        let mut n = 0u8;
        move || {
            n = n.wrapping_add(1);
            Ok(base64_encode(&[n; 16]))
        }
    }

    #[test]
    fn test_rfc7865_golden() -> Result<(), Box<dyn std::error::Error>> {
        let xml = sample().to_rfc7865_xml_with(&mut counter_ids())?;
        let golden = include_str!("../tests/fixtures/rfc7865_basic.xml");
        assert_eq!(xml, golden);
        // Internal-only fields never reach the SRS.
        assert!(!xml.contains("PCMU"));
        assert!(!xml.contains("11111"));
        assert!(!xml.contains("caller"));
        Ok(())
    }

    #[test]
    fn test_rfc7865_ids_are_random_base64() -> Result<(), Box<dyn std::error::Error>> {
        let xml = sample().to_rfc7865_xml()?;
        let start = xml.find("session_id=\"").ok_or("session_id")? + 12;
        let id = xml.get(start..start + 24).ok_or("id")?;
        assert!(id.ends_with("=="));
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        );
        let again = sample().to_rfc7865_xml()?;
        assert_ne!(xml, again);
        Ok(())
    }

    #[test]
    fn test_rfc7865_escapes_display_name_and_aor() -> Result<(), Box<dyn std::error::Error>> {
        let mut m = RecordingMetadata::new("c");
        m.add_participant(
            Participant::new("p1", "sip:\"x\"&<y>@example.com")
                .with_display_name("</name><participant participant_id=\"evil\">"),
        );
        let xml = m.to_rfc7865_xml()?;
        assert!(xml.contains(
            "<name>&lt;/name&gt;&lt;participant participant_id=&quot;evil&quot;&gt;</name>"
        ));
        assert!(xml.contains("aor=\"sip:&quot;x&quot;&amp;&lt;y&gt;@example.com\""));
        assert_eq!(xml.matches("<participant ").count(), 1);
        Ok(())
    }

    #[test]
    fn test_rfc7865_rejects_control_chars() {
        let mut m = RecordingMetadata::new("c");
        m.add_participant(Participant::new("p1", "sip:a@b").with_display_name("a\u{1}b"));
        assert!(matches!(
            m.to_rfc7865_xml(),
            Err(SiprecError::InvalidMetadata { .. })
        ));
    }

    #[test]
    fn test_rfc7865_limits() {
        let mut m = RecordingMetadata::new("c");
        for i in 0..=MAX_PARTICIPANTS {
            m.add_participant(Participant::new(format!("p{i}"), "sip:a@b"));
        }
        assert!(matches!(
            m.to_rfc7865_xml(),
            Err(SiprecError::LimitExceeded {
                what: "participants",
                ..
            })
        ));

        let mut m = RecordingMetadata::new("c");
        m.add_participant(Participant::new("p", "a".repeat(MAX_FIELD_BYTES + 1)));
        assert!(matches!(
            m.to_rfc7865_xml(),
            Err(SiprecError::LimitExceeded { .. })
        ));

        // Many maximal escaped fields push the document over the total cap.
        let mut m = RecordingMetadata::new("c");
        for i in 0..MAX_PARTICIPANTS {
            m.add_participant(
                Participant::new(format!("p{i}"), "&".repeat(MAX_FIELD_BYTES))
                    .with_display_name("<".repeat(MAX_FIELD_BYTES)),
            );
        }
        assert!(matches!(
            m.to_rfc7865_xml(),
            Err(SiprecError::LimitExceeded {
                what: "metadata document bytes",
                ..
            })
        ));

        let mut m = RecordingMetadata::new("c");
        for i in 0..=MAX_STREAMS {
            m.add_stream(MediaStream::audio(format!("s{i}")));
        }
        assert!(matches!(
            m.to_rfc7865_xml(),
            Err(SiprecError::LimitExceeded {
                what: "streams",
                ..
            })
        ));
    }

    #[test]
    fn test_rfc7865_rejects_bad_label_and_unknown_owner() {
        let mut m = RecordingMetadata::new("c");
        m.add_stream(MediaStream::audio("a b"));
        assert!(m.to_rfc7865_xml().is_err());

        let mut m = RecordingMetadata::new("c");
        m.add_stream(MediaStream::audio("s1").with_participant("nobody"));
        assert!(m.to_rfc7865_xml().is_err());
    }

    #[test]
    fn test_rfc3339_and_base64() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_secs(1_292_542_867)),
            "2010-12-16T23:41:07Z"
        );
        assert_eq!(
            rfc3339(UNIX_EPOCH + Duration::from_secs(951_782_401)),
            "2000-02-29T00:00:01Z"
        );
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(&[0u8; 16]).len(), 24);
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
