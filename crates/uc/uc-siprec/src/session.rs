//! SIPREC recording session management.
//!
//! This module implements the Session Recording Client (SRC) that manages
//! recording sessions with the Session Recording Server (SRS).
//!
//! ## Session Lifecycle
//!
//! 1. Call arrives at SBC (Communication Session starts)
//! 2. SRC evaluates recording triggers
//! 3. SRC creates Recording Session to SRS (INVITE)
//! 4. SRS accepts recording (200 OK)
//! 5. SRC begins media forking to SRS
//! 6. Communication Session ends
//! 7. SRC terminates Recording Session (BYE)

use crate::config::{RecordingConfig, RecordingTrigger, SrsEndpoint};
use crate::error::{SiprecError, SiprecResult};
use crate::forking::{ForkerState, MediaForker, StreamFork};
use crate::metadata::{
    MediaStream, Participant, ParticipantRole, RecordingId, RecordingMetadata, StreamDirection,
};
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::time::SystemTime;

/// State of a recording session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecordingSessionState {
    /// Session created, awaiting setup.
    #[default]
    Created,
    /// INVITE sent to SRS, awaiting response.
    Inviting,
    /// Received provisional response, session proceeding.
    Proceeding,
    /// Recording session established and active.
    Active,
    /// Session on hold (paused).
    OnHold,
    /// Session terminating (BYE sent).
    Terminating,
    /// Session terminated normally.
    Terminated,
    /// Session failed.
    Failed,
}

impl fmt::Display for RecordingSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Inviting => write!(f, "inviting"),
            Self::Proceeding => write!(f, "proceeding"),
            Self::Active => write!(f, "active"),
            Self::OnHold => write!(f, "on-hold"),
            Self::Terminating => write!(f, "terminating"),
            Self::Terminated => write!(f, "terminated"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Events during recording session lifecycle.
#[derive(Debug, Clone)]
pub enum SessionRecordingEvent {
    /// Session created for a call.
    Created {
        /// Recording session ID.
        session_id: String,
        /// Communication session (call) ID.
        call_id: String,
    },
    /// INVITE sent to SRS.
    InviteSent {
        /// Recording session ID.
        session_id: String,
        /// SRS address.
        srs_address: String,
    },
    /// Received provisional response.
    Proceeding {
        /// Recording session ID.
        session_id: String,
        /// Response code (e.g., 180, 183).
        response_code: u16,
    },
    /// Recording session established.
    Established {
        /// Recording session ID.
        session_id: String,
    },
    /// Media forking started.
    ForkingStarted {
        /// Recording session ID.
        session_id: String,
        /// Number of streams being forked.
        stream_count: usize,
    },
    /// Recording paused/resumed.
    PauseStateChanged {
        /// Recording session ID.
        session_id: String,
        /// Whether recording is now paused.
        paused: bool,
    },
    /// Participant added to recording.
    ParticipantAdded {
        /// Recording session ID.
        session_id: String,
        /// Participant ID.
        participant_id: String,
        /// Participant AoR.
        aor: String,
    },
    /// Stream added to recording.
    StreamAdded {
        /// Recording session ID.
        session_id: String,
        /// Stream ID.
        stream_id: String,
        /// Media type.
        media_type: String,
    },
    /// Session terminating.
    Terminating {
        /// Recording session ID.
        session_id: String,
    },
    /// Session terminated.
    Terminated {
        /// Recording session ID.
        session_id: String,
        /// Duration in seconds.
        duration_secs: u64,
    },
    /// Session failed.
    Failed {
        /// Recording session ID.
        session_id: String,
        /// Failure reason.
        reason: String,
    },
}

/// A SIPREC recording session.
#[derive(Debug)]
pub struct RecordingSession {
    /// Unique recording session ID.
    id: RecordingId,
    /// Communication session (call) ID being recorded.
    call_id: String,
    /// Session state.
    state: RecordingSessionState,
    /// Recording metadata.
    metadata: RecordingMetadata,
    /// Media forker.
    forker: MediaForker,
    /// Selected SRS endpoint.
    srs_endpoint: Option<SrsEndpoint>,
    /// SIP Call-ID for the recording session.
    recording_call_id: Option<String>,
    /// Local tag for recording session.
    local_tag: Option<String>,
    /// Remote tag from SRS.
    remote_tag: Option<String>,
    /// CSeq for recording session.
    cseq: u32,
    /// Session creation time.
    created_at: SystemTime,
    /// Session termination time.
    terminated_at: Option<SystemTime>,
    /// Failure reason if failed.
    failure_reason: Option<String>,
}

impl RecordingSession {
    /// Creates a new recording session.
    #[must_use]
    pub fn new(call_id: impl Into<String>) -> Self {
        let call_id = call_id.into();
        let id = RecordingId::generate();

        Self {
            metadata: RecordingMetadata::new(&call_id),
            forker: MediaForker::new(id.as_str()),
            id,
            call_id,
            state: RecordingSessionState::Created,
            srs_endpoint: None,
            recording_call_id: None,
            local_tag: None,
            remote_tag: None,
            cseq: 1,
            created_at: SystemTime::now(),
            terminated_at: None,
            failure_reason: None,
        }
    }

    /// Returns the session ID.
    #[must_use]
    pub fn id(&self) -> &RecordingId {
        &self.id
    }

    /// Returns the communication session (call) ID.
    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Returns the current state.
    #[must_use]
    pub fn state(&self) -> RecordingSessionState {
        self.state
    }

    /// Returns the metadata.
    #[must_use]
    pub fn metadata(&self) -> &RecordingMetadata {
        &self.metadata
    }

    /// Returns mutable metadata.
    pub fn metadata_mut(&mut self) -> &mut RecordingMetadata {
        &mut self.metadata
    }

    /// Returns the media forker.
    #[must_use]
    pub fn forker(&self) -> &MediaForker {
        &self.forker
    }

    /// Returns mutable media forker.
    pub fn forker_mut(&mut self) -> &mut MediaForker {
        &mut self.forker
    }

    /// Sets the SRS endpoint.
    pub fn set_srs_endpoint(&mut self, endpoint: SrsEndpoint) {
        self.metadata.session.srs_uri = Some(endpoint.effective_uri());
        self.srs_endpoint = Some(endpoint);
    }

    /// Gets the SRS endpoint.
    #[must_use]
    pub fn srs_endpoint(&self) -> Option<&SrsEndpoint> {
        self.srs_endpoint.as_ref()
    }

    /// Sets the recording Call-ID.
    pub fn set_recording_call_id(&mut self, call_id: impl Into<String>) {
        self.recording_call_id = Some(call_id.into());
    }

    /// Gets the recording Call-ID.
    #[must_use]
    pub fn recording_call_id(&self) -> Option<&str> {
        self.recording_call_id.as_deref()
    }

    /// Sets the local tag.
    pub fn set_local_tag(&mut self, tag: impl Into<String>) {
        self.local_tag = Some(tag.into());
    }

    /// Sets the remote tag.
    pub fn set_remote_tag(&mut self, tag: impl Into<String>) {
        self.remote_tag = Some(tag.into());
    }

    /// Gets next CSeq and increments.
    pub fn next_cseq(&mut self) -> u32 {
        let seq = self.cseq;
        self.cseq += 1;
        seq
    }

    /// Adds a participant to the recording.
    pub fn add_participant(
        &mut self,
        id: impl Into<String>,
        aor: impl Into<String>,
        role: ParticipantRole,
    ) -> SiprecResult<()> {
        let participant = Participant::new(id, aor)
            .with_role(role)
            .with_join_time(SystemTime::now());

        self.metadata.add_participant(participant);
        Ok(())
    }

    /// Adds caller as participant.
    pub fn add_caller(&mut self, aor: impl Into<String>, display_name: Option<String>) {
        let mut participant = Participant::new("caller", aor)
            .with_role(ParticipantRole::Caller)
            .with_join_time(SystemTime::now());

        if let Some(name) = display_name {
            participant = participant.with_display_name(name);
        }

        self.metadata.add_participant(participant);
    }

    /// Adds callee as participant.
    pub fn add_callee(&mut self, aor: impl Into<String>, display_name: Option<String>) {
        let mut participant = Participant::new("callee", aor)
            .with_role(ParticipantRole::Callee)
            .with_join_time(SystemTime::now());

        if let Some(name) = display_name {
            participant = participant.with_display_name(name);
        }

        self.metadata.add_participant(participant);
    }

    /// Adds a media stream to record.
    pub fn add_stream(
        &mut self,
        id: impl Into<String>,
        media_type: impl Into<String>,
        direction: StreamDirection,
    ) {
        let stream = MediaStream::new(id, media_type).with_direction(direction);
        self.metadata.add_stream(stream);
    }

    /// Sets up media forking for a stream.
    pub fn setup_forking(
        &mut self,
        stream_id: impl Into<String>,
        source_addr: SocketAddr,
        dest_addr: SocketAddr,
        fork_addr: SocketAddr,
    ) -> SiprecResult<()> {
        if self.forker.state() == ForkerState::Uninitialized {
            self.forker.initialize()?;
        }

        let fork = StreamFork::new(stream_id, source_addr, dest_addr, fork_addr);
        self.forker.add_fork(fork)?;
        Ok(())
    }

    /// Starts the recording session (transitions to Inviting).
    pub fn start(&mut self) -> SiprecResult<SessionRecordingEvent> {
        if self.state != RecordingSessionState::Created {
            return Err(SiprecError::InvalidState {
                expected: "created".to_string(),
                actual: self.state.to_string(),
            });
        }

        self.state = RecordingSessionState::Inviting;

        Ok(SessionRecordingEvent::InviteSent {
            session_id: self.id.to_string(),
            srs_address: self
                .srs_endpoint
                .as_ref()
                .map(|e| e.address.clone())
                .unwrap_or_default(),
        })
    }

    /// Handles provisional response from SRS.
    pub fn on_provisional(&mut self, code: u16) -> SiprecResult<SessionRecordingEvent> {
        if self.state != RecordingSessionState::Inviting {
            return Err(SiprecError::InvalidState {
                expected: "inviting".to_string(),
                actual: self.state.to_string(),
            });
        }

        self.state = RecordingSessionState::Proceeding;

        Ok(SessionRecordingEvent::Proceeding {
            session_id: self.id.to_string(),
            response_code: code,
        })
    }

    /// Handles 200 OK from SRS - session established.
    pub fn on_established(&mut self) -> SiprecResult<SessionRecordingEvent> {
        if !matches!(
            self.state,
            RecordingSessionState::Inviting | RecordingSessionState::Proceeding
        ) {
            return Err(SiprecError::InvalidState {
                expected: "inviting or proceeding".to_string(),
                actual: self.state.to_string(),
            });
        }

        self.state = RecordingSessionState::Active;
        self.metadata.session.activate();

        // Start forking if configured
        if self.forker.state() == ForkerState::Initialized {
            self.forker.start()?;
        }

        Ok(SessionRecordingEvent::Established {
            session_id: self.id.to_string(),
        })
    }

    /// Handles session failure.
    pub fn on_failed(&mut self, reason: impl Into<String>) -> SessionRecordingEvent {
        let reason = reason.into();
        self.state = RecordingSessionState::Failed;
        self.failure_reason = Some(reason.clone());
        self.terminated_at = Some(SystemTime::now());
        self.metadata.session.fail(&reason);

        // Stop forking
        let _ = self.forker.stop();

        SessionRecordingEvent::Failed {
            session_id: self.id.to_string(),
            reason,
        }
    }

    /// Pauses recording.
    pub fn pause(&mut self) -> SiprecResult<SessionRecordingEvent> {
        if self.state != RecordingSessionState::Active {
            return Err(SiprecError::InvalidState {
                expected: "active".to_string(),
                actual: self.state.to_string(),
            });
        }

        self.state = RecordingSessionState::OnHold;
        self.forker.pause()?;

        Ok(SessionRecordingEvent::PauseStateChanged {
            session_id: self.id.to_string(),
            paused: true,
        })
    }

    /// Resumes recording.
    pub fn resume(&mut self) -> SiprecResult<SessionRecordingEvent> {
        if self.state != RecordingSessionState::OnHold {
            return Err(SiprecError::InvalidState {
                expected: "on-hold".to_string(),
                actual: self.state.to_string(),
            });
        }

        self.state = RecordingSessionState::Active;
        self.forker.start()?;

        Ok(SessionRecordingEvent::PauseStateChanged {
            session_id: self.id.to_string(),
            paused: false,
        })
    }

    /// Terminates the recording session.
    pub fn terminate(&mut self) -> SiprecResult<SessionRecordingEvent> {
        if matches!(
            self.state,
            RecordingSessionState::Terminated | RecordingSessionState::Failed
        ) {
            return Err(SiprecError::InvalidState {
                expected: "active or on-hold".to_string(),
                actual: self.state.to_string(),
            });
        }

        self.state = RecordingSessionState::Terminating;
        self.forker.stop()?;

        Ok(SessionRecordingEvent::Terminating {
            session_id: self.id.to_string(),
        })
    }

    /// Confirms termination (after BYE acknowledged).
    pub fn on_terminated(&mut self) -> SessionRecordingEvent {
        self.state = RecordingSessionState::Terminated;
        self.terminated_at = Some(SystemTime::now());
        self.metadata.session.complete();

        // Mark participants as left
        for participant in &mut self.metadata.participants {
            if participant.leave_time.is_none() {
                participant.left(SystemTime::now());
            }
        }

        // Mark streams as ended
        for stream in &mut self.metadata.streams {
            if stream.end_time.is_none() {
                stream.ended(SystemTime::now());
            }
        }

        let duration_secs = self
            .terminated_at
            .and_then(|t| t.duration_since(self.created_at).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        SessionRecordingEvent::Terminated {
            session_id: self.id.to_string(),
            duration_secs,
        }
    }

    /// Returns session duration.
    #[must_use]
    pub fn duration_secs(&self) -> u64 {
        let end = self.terminated_at.unwrap_or_else(SystemTime::now);
        end.duration_since(self.created_at)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Generates XML metadata for the recording.
    #[must_use]
    pub fn metadata_xml(&self) -> String {
        self.metadata.to_xml()
    }
}

/// Session Recording Client (SRC) - manages recording sessions.
#[derive(Debug, Default)]
pub struct SessionRecordingClient {
    /// Recording configuration.
    config: RecordingConfig,
    /// Active recording sessions by call ID.
    sessions: HashMap<String, RecordingSession>,
    /// Session count by SRS.
    sessions_per_srs: HashMap<String, usize>,
}

impl SessionRecordingClient {
    /// Creates a new SRC with the given configuration.
    #[must_use]
    pub fn new(config: RecordingConfig) -> Self {
        Self {
            config,
            sessions: HashMap::new(),
            sessions_per_srs: HashMap::new(),
        }
    }

    /// Returns the configuration.
    #[must_use]
    pub fn config(&self) -> &RecordingConfig {
        &self.config
    }

    /// Updates the configuration.
    pub fn set_config(&mut self, config: RecordingConfig) {
        self.config = config;
    }

    /// Returns the number of active sessions.
    #[must_use]
    pub fn active_session_count(&self) -> usize {
        self.sessions
            .values()
            .filter(|s| matches!(s.state(), RecordingSessionState::Active))
            .count()
    }

    /// Returns total session count.
    #[must_use]
    pub fn total_session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Checks if a call should be recorded.
    #[must_use]
    pub fn should_record(&self, context: &RecordingContext) -> bool {
        if !self.config.is_enabled() {
            return false;
        }

        // Check max sessions
        if self.active_session_count() >= self.config.max_sessions {
            tracing::warn!(
                max = self.config.max_sessions,
                "max recording sessions reached"
            );
            return false;
        }

        // Check exempt trunks
        if let Some(ref trunk_id) = context.trunk_id {
            if self.config.is_trunk_exempt(trunk_id) {
                return false;
            }
        }

        // Evaluate triggers based on mode
        match self.config.mode {
            crate::config::RecordingMode::AllCalls => true,
            crate::config::RecordingMode::Selective => {
                self.evaluate_triggers(&self.config.triggers, context)
            }
            crate::config::RecordingMode::OnDemand => context.explicit_record_request,
            crate::config::RecordingMode::Disabled => false,
        }
    }

    /// Evaluates recording triggers against context.
    fn evaluate_triggers(&self, triggers: &[RecordingTrigger], context: &RecordingContext) -> bool {
        if triggers.is_empty() {
            // No triggers = record all
            return true;
        }

        for trigger in triggers {
            if self.evaluate_trigger(trigger, context) {
                return true;
            }
        }
        false
    }

    /// Evaluates a single trigger.
    fn evaluate_trigger(&self, trigger: &RecordingTrigger, context: &RecordingContext) -> bool {
        match trigger {
            RecordingTrigger::Trunk(trunk) => context.trunk_id.as_ref().is_some_and(|t| t == trunk),

            RecordingTrigger::CallerPattern(pattern) => {
                // Simple substring matching (would use regex in production)
                context.caller.contains(pattern)
            }

            RecordingTrigger::CalleePattern(pattern) => context.callee.contains(pattern),

            RecordingTrigger::HeaderMatch { name, pattern } => context
                .headers
                .get(name)
                .is_some_and(|v| v.contains(pattern)),

            RecordingTrigger::TimeWindow {
                start_hour,
                end_hour,
            } => {
                // Would check current time against window
                let _ = (start_hour, end_hour);
                true // Simplified
            }

            RecordingTrigger::ExplicitFlag => context.explicit_record_request,

            RecordingTrigger::InboundOnly => context.is_inbound,

            RecordingTrigger::OutboundOnly => !context.is_inbound,

            RecordingTrigger::Any(triggers) => {
                triggers.iter().any(|t| self.evaluate_trigger(t, context))
            }

            RecordingTrigger::All(triggers) => {
                triggers.iter().all(|t| self.evaluate_trigger(t, context))
            }

            RecordingTrigger::Not(inner) => !self.evaluate_trigger(inner, context),
        }
    }

    /// Creates a recording session for a call.
    pub fn create_session(
        &mut self,
        call_id: impl Into<String>,
    ) -> SiprecResult<&mut RecordingSession> {
        let call_id = call_id.into();

        if self.sessions.contains_key(&call_id) {
            return Err(SiprecError::SessionExists {
                call_id: call_id.clone(),
            });
        }

        // Select SRS endpoint
        let servers = self.config.available_servers();
        if servers.is_empty() {
            return Err(SiprecError::NoRecordingServer);
        }

        // Simple round-robin selection (would be weighted in production)
        let srs = servers[0].clone();

        let mut session = RecordingSession::new(&call_id);
        session.set_srs_endpoint(srs.clone());

        // Track session count per SRS
        *self
            .sessions_per_srs
            .entry(srs.address.clone())
            .or_insert(0) += 1;

        self.sessions.insert(call_id.clone(), session);

        self.sessions
            .get_mut(&call_id)
            .ok_or(SiprecError::SessionNotFound {
                session_id: call_id,
            })
    }

    /// Gets a session by call ID.
    #[must_use]
    pub fn get_session(&self, call_id: &str) -> Option<&RecordingSession> {
        self.sessions.get(call_id)
    }

    /// Gets a mutable session by call ID.
    pub fn get_session_mut(&mut self, call_id: &str) -> Option<&mut RecordingSession> {
        self.sessions.get_mut(call_id)
    }

    /// Removes a terminated session.
    pub fn remove_session(&mut self, call_id: &str) -> Option<RecordingSession> {
        if let Some(session) = self.sessions.remove(call_id) {
            // Update SRS session count
            if let Some(srs) = session.srs_endpoint() {
                if let Some(count) = self.sessions_per_srs.get_mut(&srs.address) {
                    *count = count.saturating_sub(1);
                }
            }
            Some(session)
        } else {
            None
        }
    }

    /// Iterates over all sessions.
    pub fn sessions(&self) -> impl Iterator<Item = &RecordingSession> {
        self.sessions.values()
    }
}

/// Context for evaluating recording triggers.
#[derive(Debug, Clone, Default)]
pub struct RecordingContext {
    /// Call ID.
    pub call_id: String,
    /// Caller AoR/number.
    pub caller: String,
    /// Callee AoR/number.
    pub callee: String,
    /// Is this an inbound call.
    pub is_inbound: bool,
    /// Trunk ID if applicable.
    pub trunk_id: Option<String>,
    /// Explicit recording request flag.
    pub explicit_record_request: bool,
    /// Relevant SIP headers.
    pub headers: HashMap<String, String>,
}

impl RecordingContext {
    /// Creates a new recording context.
    #[must_use]
    pub fn new(
        call_id: impl Into<String>,
        caller: impl Into<String>,
        callee: impl Into<String>,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            caller: caller.into(),
            callee: callee.into(),
            ..Default::default()
        }
    }

    /// Sets as inbound call.
    #[must_use]
    pub fn inbound(mut self) -> Self {
        self.is_inbound = true;
        self
    }

    /// Sets as outbound call.
    #[must_use]
    pub fn outbound(mut self) -> Self {
        self.is_inbound = false;
        self
    }

    /// Sets the trunk ID.
    #[must_use]
    pub fn with_trunk(mut self, trunk_id: impl Into<String>) -> Self {
        self.trunk_id = Some(trunk_id.into());
        self
    }

    /// Sets explicit recording request.
    #[must_use]
    pub fn with_explicit_request(mut self) -> Self {
        self.explicit_record_request = true;
        self
    }

    /// Adds a header.
    pub fn add_header(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.headers.insert(name.into(), value.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RecordingMode;

    #[test]
    fn test_recording_session_lifecycle() {
        let mut session = RecordingSession::new("call-123@example.com");

        assert_eq!(session.state(), RecordingSessionState::Created);

        // Add participants
        session.add_caller("sip:alice@example.com", Some("Alice".to_string()));
        session.add_callee("sip:bob@example.com", Some("Bob".to_string()));

        // Add stream
        session.add_stream("audio-1", "audio", StreamDirection::SendReceive);

        // Start session
        let event = session.start().unwrap();
        assert!(matches!(event, SessionRecordingEvent::InviteSent { .. }));
        assert_eq!(session.state(), RecordingSessionState::Inviting);

        // Provisional response
        let event = session.on_provisional(180).unwrap();
        assert!(matches!(event, SessionRecordingEvent::Proceeding { .. }));
        assert_eq!(session.state(), RecordingSessionState::Proceeding);

        // Established
        let event = session.on_established().unwrap();
        assert!(matches!(event, SessionRecordingEvent::Established { .. }));
        assert_eq!(session.state(), RecordingSessionState::Active);

        // Terminate
        let event = session.terminate().unwrap();
        assert!(matches!(event, SessionRecordingEvent::Terminating { .. }));
        assert_eq!(session.state(), RecordingSessionState::Terminating);

        // Confirmed termination
        let event = session.on_terminated();
        assert!(matches!(event, SessionRecordingEvent::Terminated { .. }));
        assert_eq!(session.state(), RecordingSessionState::Terminated);
    }

    #[test]
    fn test_session_pause_resume() {
        let mut session = RecordingSession::new("call-456");
        session.set_srs_endpoint(SrsEndpoint::new("10.0.0.1:5060"));
        session.forker_mut().initialize().unwrap();

        let _ = session.start();
        let _ = session.on_established();

        // Pause
        let event = session.pause().unwrap();
        assert!(matches!(
            event,
            SessionRecordingEvent::PauseStateChanged { paused: true, .. }
        ));
        assert_eq!(session.state(), RecordingSessionState::OnHold);

        // Resume
        let event = session.resume().unwrap();
        assert!(matches!(
            event,
            SessionRecordingEvent::PauseStateChanged { paused: false, .. }
        ));
        assert_eq!(session.state(), RecordingSessionState::Active);
    }

    #[test]
    fn test_session_failure() {
        let mut session = RecordingSession::new("call-789");
        let _ = session.start();

        let event = session.on_failed("SRS unreachable");
        assert!(matches!(event, SessionRecordingEvent::Failed { .. }));
        assert_eq!(session.state(), RecordingSessionState::Failed);
    }

    #[test]
    fn test_session_recording_client() {
        let config =
            RecordingConfig::all_calls().with_primary_server(SrsEndpoint::new("10.0.0.1:5060"));

        let mut client = SessionRecordingClient::new(config);

        let context = RecordingContext::new("call-1", "alice", "bob").inbound();

        assert!(client.should_record(&context));

        let session = client.create_session("call-1").unwrap();
        assert_eq!(session.call_id(), "call-1");
        assert!(session.srs_endpoint().is_some());

        assert_eq!(client.total_session_count(), 1);
    }

    #[test]
    fn test_selective_recording_triggers() {
        let config = RecordingConfig::selective()
            .with_primary_server(SrsEndpoint::new("10.0.0.1:5060"))
            .with_trigger(RecordingTrigger::trunk("pstn-trunk"));

        let client = SessionRecordingClient::new(config);

        // Should record calls from matching trunk
        let context = RecordingContext::new("call-1", "alice", "bob").with_trunk("pstn-trunk");
        assert!(client.should_record(&context));

        // Should not record calls from other trunk
        let context = RecordingContext::new("call-2", "alice", "bob").with_trunk("internal-trunk");
        assert!(!client.should_record(&context));
    }

    #[test]
    fn test_exempt_trunks() {
        let config = RecordingConfig::all_calls()
            .with_primary_server(SrsEndpoint::new("10.0.0.1:5060"))
            .with_exempt_trunk("internal-calls");

        let client = SessionRecordingClient::new(config);

        let context = RecordingContext::new("call-1", "alice", "bob").with_trunk("internal-calls");
        assert!(!client.should_record(&context));

        let context = RecordingContext::new("call-2", "alice", "bob").with_trunk("external");
        assert!(client.should_record(&context));
    }

    #[test]
    fn test_disabled_recording() {
        let config = RecordingConfig::disabled();
        let client = SessionRecordingClient::new(config);

        let context = RecordingContext::new("call-1", "alice", "bob");
        assert!(!client.should_record(&context));
    }

    #[test]
    fn test_on_demand_recording() {
        let config = RecordingConfig {
            mode: RecordingMode::OnDemand,
            ..RecordingConfig::all_calls().with_primary_server(SrsEndpoint::new("10.0.0.1:5060"))
        };

        let client = SessionRecordingClient::new(config);

        // Without explicit request
        let context = RecordingContext::new("call-1", "alice", "bob");
        assert!(!client.should_record(&context));

        // With explicit request
        let context = RecordingContext::new("call-2", "alice", "bob").with_explicit_request();
        assert!(client.should_record(&context));
    }

    #[test]
    fn test_metadata_xml_generation() {
        let mut session = RecordingSession::new("call-xml-test");
        session.add_caller("sip:alice@example.com", Some("Alice".to_string()));
        session.add_callee("sip:bob@example.com", Some("Bob".to_string()));
        session.add_stream("audio-1", "audio", StreamDirection::SendReceive);

        let xml = session.metadata_xml();
        assert!(xml.contains("<aor>sip:alice@example.com</aor>"));
        assert!(xml.contains("<aor>sip:bob@example.com</aor>"));
        assert!(xml.contains("<media-type>audio</media-type>"));
    }
}
