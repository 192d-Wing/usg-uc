//! Media session management.

use crate::MAX_STREAMS_PER_SESSION;
use crate::error::{MediaError, MediaResult};
use crate::stream::{MediaStream, StreamConfig, StreamDirection, StreamState};
use std::collections::HashMap;
use std::time::Instant;
use uc_codecs::CodecCapability;

/// Media handling mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MediaMode {
    /// Full relay mode (B2BUA).
    ///
    /// Media flows through the SBC, allowing for:
    /// - Transcoding between codecs
    /// - Media manipulation
    /// - Recording
    /// - Topology hiding
    #[default]
    Relay,

    /// Pass-through mode.
    ///
    /// Media flows directly between endpoints:
    /// - Lower latency
    /// - Reduced SBC load
    /// - No transcoding support
    PassThrough,

    /// Early media relay.
    ///
    /// Initial media is relayed, then may switch to pass-through.
    EarlyRelay,
}

impl std::fmt::Display for MediaMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Relay => write!(f, "relay"),
            Self::PassThrough => write!(f, "pass-through"),
            Self::EarlyRelay => write!(f, "early-relay"),
        }
    }
}

/// Media session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Session created but not active.
    Created,
    /// Session is negotiating.
    Negotiating,
    /// Session is active.
    Active,
    /// Session is on hold.
    OnHold,
    /// Session is being modified.
    Modifying,
    /// Session is closing.
    Closing,
    /// Session is closed.
    Closed,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Negotiating => write!(f, "negotiating"),
            Self::Active => write!(f, "active"),
            Self::OnHold => write!(f, "on_hold"),
            Self::Modifying => write!(f, "modifying"),
            Self::Closing => write!(f, "closing"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// Media session configuration.
#[derive(Debug, Clone)]
pub struct MediaSessionConfig {
    /// Session ID.
    pub session_id: String,
    /// Media mode.
    pub mode: MediaMode,
    /// Local codecs (in preference order).
    pub local_codecs: Vec<CodecCapability>,
    /// Enable SRTP.
    pub srtp_enabled: bool,
    /// Enable RTCP.
    pub rtcp_enabled: bool,
    /// Enable RTCP multiplexing.
    pub rtcp_mux: bool,
}

impl MediaSessionConfig {
    /// Creates a new session configuration.
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            mode: MediaMode::default(),
            local_codecs: Vec::new(),
            srtp_enabled: true,
            rtcp_enabled: true,
            rtcp_mux: true,
        }
    }

    /// Sets the media mode.
    pub fn with_mode(mut self, mode: MediaMode) -> Self {
        self.mode = mode;
        self
    }

    /// Adds a local codec.
    pub fn with_codec(mut self, codec: CodecCapability) -> Self {
        self.local_codecs.push(codec);
        self
    }

    /// Sets local codecs.
    pub fn with_codecs(mut self, codecs: Vec<CodecCapability>) -> Self {
        self.local_codecs = codecs;
        self
    }

    /// Enables/disables SRTP.
    pub fn with_srtp(mut self, enabled: bool) -> Self {
        self.srtp_enabled = enabled;
        self
    }
}

/// Media session.
///
/// Manages media streams between two endpoints (A-leg and B-leg).
#[derive(Debug)]
pub struct MediaSession {
    /// Configuration.
    config: MediaSessionConfig,
    /// Current state.
    state: SessionState,
    /// When the session was created.
    created_at: Instant,
    /// When the session became active.
    active_at: Option<Instant>,
    /// A-leg streams (caller side).
    a_leg_streams: HashMap<u32, MediaStream>,
    /// B-leg streams (callee side).
    b_leg_streams: HashMap<u32, MediaStream>,
    /// Negotiated codecs.
    negotiated_codecs: Vec<CodecCapability>,
    /// Next stream ID.
    next_stream_id: u32,
}

impl MediaSession {
    /// Creates a new media session.
    pub fn new(config: MediaSessionConfig) -> Self {
        Self {
            config,
            state: SessionState::Created,
            created_at: Instant::now(),
            active_at: None,
            a_leg_streams: HashMap::new(),
            b_leg_streams: HashMap::new(),
            negotiated_codecs: Vec::new(),
            next_stream_id: 1,
        }
    }

    /// Returns the session ID.
    pub fn session_id(&self) -> &str {
        &self.config.session_id
    }

    /// Returns the media mode.
    pub fn mode(&self) -> MediaMode {
        self.config.mode
    }

    /// Returns the current state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Returns whether SRTP is enabled.
    pub fn srtp_enabled(&self) -> bool {
        self.config.srtp_enabled
    }

    /// Returns the negotiated codecs.
    pub fn negotiated_codecs(&self) -> &[CodecCapability] {
        &self.negotiated_codecs
    }

    /// Returns A-leg streams.
    pub fn a_leg_streams(&self) -> impl Iterator<Item = &MediaStream> {
        self.a_leg_streams.values()
    }

    /// Returns B-leg streams.
    pub fn b_leg_streams(&self) -> impl Iterator<Item = &MediaStream> {
        self.b_leg_streams.values()
    }

    /// Negotiates codecs with remote.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn negotiate_codecs(&mut self, remote_codecs: &[CodecCapability]) -> MediaResult<()> {
        if self.state != SessionState::Created && self.state != SessionState::Negotiating {
            return Err(MediaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "negotiating".to_string(),
            });
        }

        self.state = SessionState::Negotiating;

        // Find intersection of codecs
        let mut negotiated = Vec::new();
        for local in &self.config.local_codecs {
            for remote in remote_codecs {
                if local.name.eq_ignore_ascii_case(&remote.name)
                    && local.clock_rate == remote.clock_rate
                {
                    negotiated.push(local.clone());
                    break;
                }
            }
        }

        if negotiated.is_empty() {
            return Err(MediaError::CodecNegotiationFailed {
                reason: "no common codecs".to_string(),
            });
        }

        self.negotiated_codecs = negotiated;
        Ok(())
    }

    /// Adds an A-leg stream.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn add_a_leg_stream(&mut self, config: StreamConfig) -> MediaResult<u32> {
        self.add_stream(config, true)
    }

    /// Adds a B-leg stream.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn add_b_leg_stream(&mut self, config: StreamConfig) -> MediaResult<u32> {
        self.add_stream(config, false)
    }

    /// Adds a stream to the specified leg.
    fn add_stream(&mut self, mut config: StreamConfig, is_a_leg: bool) -> MediaResult<u32> {
        let streams = if is_a_leg {
            &self.a_leg_streams
        } else {
            &self.b_leg_streams
        };

        if streams.len() >= MAX_STREAMS_PER_SESSION {
            return Err(MediaError::ResourceExhausted {
                resource: "streams".to_string(),
            });
        }

        let stream_id = self.next_stream_id;
        self.next_stream_id += 1;
        config.stream_id = stream_id;

        let stream = MediaStream::new(config);

        if is_a_leg {
            self.a_leg_streams.insert(stream_id, stream);
        } else {
            self.b_leg_streams.insert(stream_id, stream);
        }

        Ok(stream_id)
    }

    /// Gets an A-leg stream by ID.
    pub fn get_a_leg_stream(&self, stream_id: u32) -> Option<&MediaStream> {
        self.a_leg_streams.get(&stream_id)
    }

    /// Gets a B-leg stream by ID.
    pub fn get_b_leg_stream(&self, stream_id: u32) -> Option<&MediaStream> {
        self.b_leg_streams.get(&stream_id)
    }

    /// Gets a mutable A-leg stream by ID.
    pub fn get_a_leg_stream_mut(&mut self, stream_id: u32) -> Option<&mut MediaStream> {
        self.a_leg_streams.get_mut(&stream_id)
    }

    /// Gets a mutable B-leg stream by ID.
    pub fn get_b_leg_stream_mut(&mut self, stream_id: u32) -> Option<&mut MediaStream> {
        self.b_leg_streams.get_mut(&stream_id)
    }

    /// Activates the session.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn activate(&mut self) -> MediaResult<()> {
        match self.state {
            SessionState::Negotiating | SessionState::Created => {
                self.state = SessionState::Active;
                self.active_at = Some(Instant::now());

                // Start all streams
                for stream in self.a_leg_streams.values_mut() {
                    if stream.state() == StreamState::Created {
                        stream.start()?;
                    }
                }
                for stream in self.b_leg_streams.values_mut() {
                    if stream.state() == StreamState::Created {
                        stream.start()?;
                    }
                }

                Ok(())
            }
            _ => Err(MediaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "active".to_string(),
            }),
        }
    }

    /// Puts the session on hold.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn hold(&mut self) -> MediaResult<()> {
        if self.state == SessionState::Active {
            self.state = SessionState::OnHold;

            // Hold all streams
            for stream in self.a_leg_streams.values_mut() {
                stream.set_direction(StreamDirection::Inactive);
            }
            for stream in self.b_leg_streams.values_mut() {
                stream.set_direction(StreamDirection::Inactive);
            }

            Ok(())
        } else {
            Err(MediaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "on_hold".to_string(),
            })
        }
    }

    /// Resumes the session from hold.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn resume(&mut self) -> MediaResult<()> {
        if self.state == SessionState::OnHold {
            self.state = SessionState::Active;

            // Resume all streams
            for stream in self.a_leg_streams.values_mut() {
                stream.set_direction(StreamDirection::SendRecv);
            }
            for stream in self.b_leg_streams.values_mut() {
                stream.set_direction(StreamDirection::SendRecv);
            }

            Ok(())
        } else {
            Err(MediaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "active".to_string(),
            })
        }
    }

    /// Closes the session.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn close(&mut self) -> MediaResult<()> {
        if self.state == SessionState::Closed {
            return Ok(());
        }

        self.state = SessionState::Closing;

        // Stop all streams
        for stream in self.a_leg_streams.values_mut() {
            let _ = stream.stop();
        }
        for stream in self.b_leg_streams.values_mut() {
            let _ = stream.stop();
        }

        self.state = SessionState::Closed;
        Ok(())
    }

    /// Returns how long the session has been active.
    pub fn active_duration(&self) -> Option<std::time::Duration> {
        self.active_at.map(|t| t.elapsed())
    }

    /// Returns the total number of streams.
    pub fn stream_count(&self) -> usize {
        self.a_leg_streams.len() + self.b_leg_streams.len()
    }

    /// Returns when the session was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns how long since the session was created.
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::MediaType;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn test_session_config() -> MediaSessionConfig {
        MediaSessionConfig::new("test-session-1")
            .with_mode(MediaMode::Relay)
            .with_codec(CodecCapability::pcmu())
            .with_codec(CodecCapability::pcma())
    }

    fn test_stream_config() -> StreamConfig {
        StreamConfig {
            stream_id: 0, // Will be assigned
            media_type: MediaType::Audio,
            direction: StreamDirection::SendRecv,
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5004),
            remote_addr: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                5004,
            )),
            payload_type: 0,
            clock_rate: 8000,
            ssrc: 0x12345678,
        }
    }

    #[test]
    fn test_media_mode_display() {
        assert_eq!(MediaMode::Relay.to_string(), "relay");
        assert_eq!(MediaMode::PassThrough.to_string(), "pass-through");
    }

    #[test]
    fn test_session_creation() {
        let session = MediaSession::new(test_session_config());
        assert_eq!(session.session_id(), "test-session-1");
        assert_eq!(session.mode(), MediaMode::Relay);
        assert_eq!(session.state(), SessionState::Created);
    }

    #[test]
    fn test_codec_negotiation() {
        let mut session = MediaSession::new(test_session_config());

        let remote_codecs = vec![CodecCapability::pcmu(), CodecCapability::opus(111)];

        session.negotiate_codecs(&remote_codecs).unwrap();

        // Only PCMU should be negotiated (we didn't add Opus locally)
        assert_eq!(session.negotiated_codecs().len(), 1);
        assert_eq!(session.negotiated_codecs()[0].name, "PCMU");
    }

    #[test]
    fn test_codec_negotiation_failure() {
        let mut session = MediaSession::new(test_session_config());

        let remote_codecs = vec![CodecCapability::opus(111)];

        // Should fail - no common codecs
        assert!(session.negotiate_codecs(&remote_codecs).is_err());
    }

    #[test]
    fn test_add_streams() {
        let mut session = MediaSession::new(test_session_config());

        let stream_id_a = session.add_a_leg_stream(test_stream_config()).unwrap();
        let stream_id_b = session.add_b_leg_stream(test_stream_config()).unwrap();

        assert_ne!(stream_id_a, stream_id_b);
        assert_eq!(session.stream_count(), 2);
        assert!(session.get_a_leg_stream(stream_id_a).is_some());
        assert!(session.get_b_leg_stream(stream_id_b).is_some());
    }

    #[test]
    fn test_session_lifecycle() {
        let mut session = MediaSession::new(test_session_config());
        session.add_a_leg_stream(test_stream_config()).unwrap();
        session.add_b_leg_stream(test_stream_config()).unwrap();

        // Negotiate
        session
            .negotiate_codecs(&[CodecCapability::pcmu()])
            .unwrap();
        assert_eq!(session.state(), SessionState::Negotiating);

        // Activate
        session.activate().unwrap();
        assert_eq!(session.state(), SessionState::Active);

        // Hold
        session.hold().unwrap();
        assert_eq!(session.state(), SessionState::OnHold);

        // Resume
        session.resume().unwrap();
        assert_eq!(session.state(), SessionState::Active);

        // Close
        session.close().unwrap();
        assert_eq!(session.state(), SessionState::Closed);
    }

    #[test]
    fn test_session_config_builder() {
        let config = MediaSessionConfig::new("session-1")
            .with_mode(MediaMode::PassThrough)
            .with_codec(CodecCapability::pcmu())
            .with_srtp(true);

        assert_eq!(config.mode, MediaMode::PassThrough);
        assert!(config.srtp_enabled);
        assert_eq!(config.local_codecs.len(), 1);
    }
}
