//! Media stream management.

use crate::error::{MediaError, MediaResult};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Media stream direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    /// Send only.
    SendOnly,
    /// Receive only.
    RecvOnly,
    /// Send and receive.
    SendRecv,
    /// Inactive.
    Inactive,
}

impl StreamDirection {
    /// Returns true if this direction allows sending.
    pub fn can_send(&self) -> bool {
        matches!(self, Self::SendOnly | Self::SendRecv)
    }

    /// Returns true if this direction allows receiving.
    pub fn can_recv(&self) -> bool {
        matches!(self, Self::RecvOnly | Self::SendRecv)
    }

    /// Parses from SDP attribute.
    pub fn from_sdp(attr: &str) -> Option<Self> {
        match attr.to_lowercase().as_str() {
            "sendonly" => Some(Self::SendOnly),
            "recvonly" => Some(Self::RecvOnly),
            "sendrecv" => Some(Self::SendRecv),
            "inactive" => Some(Self::Inactive),
            _ => None,
        }
    }

    /// Returns SDP attribute string.
    pub fn as_sdp(&self) -> &'static str {
        match self {
            Self::SendOnly => "sendonly",
            Self::RecvOnly => "recvonly",
            Self::SendRecv => "sendrecv",
            Self::Inactive => "inactive",
        }
    }
}

impl std::fmt::Display for StreamDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_sdp())
    }
}

/// Media stream state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is created but not active.
    Created,
    /// Stream is starting.
    Starting,
    /// Stream is active.
    Active,
    /// Stream is on hold.
    OnHold,
    /// Stream is stopping.
    Stopping,
    /// Stream is stopped.
    Stopped,
    /// Stream has failed.
    Failed,
}

impl std::fmt::Display for StreamState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Starting => write!(f, "starting"),
            Self::Active => write!(f, "active"),
            Self::OnHold => write!(f, "on_hold"),
            Self::Stopping => write!(f, "stopping"),
            Self::Stopped => write!(f, "stopped"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Media stream statistics.
#[derive(Debug, Clone, Default)]
pub struct StreamStats {
    /// Packets sent.
    pub packets_sent: u64,
    /// Packets received.
    pub packets_received: u64,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_received: u64,
    /// Packets lost.
    pub packets_lost: u64,
    /// Jitter in milliseconds.
    pub jitter_ms: f64,
    /// Round-trip time in milliseconds.
    pub rtt_ms: Option<f64>,
}

/// Media stream configuration.
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// Stream ID.
    pub stream_id: u32,
    /// Media type (audio/video).
    pub media_type: MediaType,
    /// Direction.
    pub direction: StreamDirection,
    /// Local address.
    pub local_addr: SocketAddr,
    /// Remote address.
    pub remote_addr: Option<SocketAddr>,
    /// Payload type.
    pub payload_type: u8,
    /// Clock rate.
    pub clock_rate: u32,
    /// SSRC.
    pub ssrc: u32,
}

/// Media type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    /// Audio media.
    Audio,
    /// Video media.
    Video,
    /// Application data.
    Application,
}

impl std::fmt::Display for MediaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Audio => write!(f, "audio"),
            Self::Video => write!(f, "video"),
            Self::Application => write!(f, "application"),
        }
    }
}

/// Media stream.
#[derive(Debug)]
pub struct MediaStream {
    /// Stream configuration.
    config: StreamConfig,
    /// Current state.
    state: StreamState,
    /// When the stream was created.
    created_at: Instant,
    /// When the stream became active.
    active_at: Option<Instant>,
    /// Packets sent counter.
    packets_sent: AtomicU64,
    /// Packets received counter.
    packets_received: AtomicU64,
    /// Bytes sent counter.
    bytes_sent: AtomicU64,
    /// Bytes received counter.
    bytes_received: AtomicU64,
}

impl MediaStream {
    /// Creates a new media stream.
    pub fn new(config: StreamConfig) -> Self {
        Self {
            config,
            state: StreamState::Created,
            created_at: Instant::now(),
            active_at: None,
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    /// Returns the stream ID.
    pub fn stream_id(&self) -> u32 {
        self.config.stream_id
    }

    /// Returns the media type.
    pub fn media_type(&self) -> MediaType {
        self.config.media_type
    }

    /// Returns the current direction.
    pub fn direction(&self) -> StreamDirection {
        self.config.direction
    }

    /// Returns the current state.
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Returns the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.config.local_addr
    }

    /// Returns the remote address.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.config.remote_addr
    }

    /// Sets the remote address.
    pub fn set_remote_addr(&mut self, addr: SocketAddr) {
        self.config.remote_addr = Some(addr);
    }

    /// Returns the SSRC.
    pub fn ssrc(&self) -> u32 {
        self.config.ssrc
    }

    /// Returns the payload type.
    pub fn payload_type(&self) -> u8 {
        self.config.payload_type
    }

    /// Starts the stream.
    pub fn start(&mut self) -> MediaResult<()> {
        match self.state {
            StreamState::Created | StreamState::Stopped => {
                self.state = StreamState::Starting;
                self.state = StreamState::Active;
                self.active_at = Some(Instant::now());
                Ok(())
            }
            _ => Err(MediaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "active".to_string(),
            }),
        }
    }

    /// Stops the stream.
    pub fn stop(&mut self) -> MediaResult<()> {
        match self.state {
            StreamState::Active | StreamState::OnHold => {
                self.state = StreamState::Stopping;
                self.state = StreamState::Stopped;
                Ok(())
            }
            StreamState::Stopped => Ok(()), // Already stopped
            _ => Err(MediaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "stopped".to_string(),
            }),
        }
    }

    /// Puts the stream on hold.
    pub fn hold(&mut self) -> MediaResult<()> {
        if self.state == StreamState::Active {
            self.state = StreamState::OnHold;
            Ok(())
        } else {
            Err(MediaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "on_hold".to_string(),
            })
        }
    }

    /// Resumes from hold.
    pub fn resume(&mut self) -> MediaResult<()> {
        if self.state == StreamState::OnHold {
            self.state = StreamState::Active;
            Ok(())
        } else {
            Err(MediaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "active".to_string(),
            })
        }
    }

    /// Sets the direction.
    pub fn set_direction(&mut self, direction: StreamDirection) {
        self.config.direction = direction;
    }

    /// Records a sent packet.
    pub fn record_sent(&self, bytes: usize) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Records a received packet.
    pub fn record_received(&self, bytes: usize) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Returns current statistics.
    pub fn stats(&self) -> StreamStats {
        StreamStats {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_lost: 0, // Would be calculated from RTP sequence numbers
            jitter_ms: 0.0,  // Would be calculated from RTP timestamps
            rtt_ms: None,    // Would come from RTCP
        }
    }

    /// Returns how long the stream has been active.
    pub fn active_duration(&self) -> Option<std::time::Duration> {
        self.active_at.map(|t| t.elapsed())
    }

    /// Returns when the stream was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns how long since the stream was created.
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_config() -> StreamConfig {
        StreamConfig {
            stream_id: 1,
            media_type: MediaType::Audio,
            direction: StreamDirection::SendRecv,
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5004),
            remote_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5004)),
            payload_type: 0,
            clock_rate: 8000,
            ssrc: 0x12345678,
        }
    }

    #[test]
    fn test_stream_direction() {
        assert!(StreamDirection::SendRecv.can_send());
        assert!(StreamDirection::SendRecv.can_recv());
        assert!(StreamDirection::SendOnly.can_send());
        assert!(!StreamDirection::SendOnly.can_recv());
        assert!(StreamDirection::RecvOnly.can_recv());
        assert!(!StreamDirection::RecvOnly.can_send());
    }

    #[test]
    fn test_stream_direction_sdp() {
        assert_eq!(StreamDirection::from_sdp("sendrecv"), Some(StreamDirection::SendRecv));
        assert_eq!(StreamDirection::SendRecv.as_sdp(), "sendrecv");
    }

    #[test]
    fn test_stream_creation() {
        let stream = MediaStream::new(test_config());
        assert_eq!(stream.state(), StreamState::Created);
        assert_eq!(stream.stream_id(), 1);
        assert_eq!(stream.media_type(), MediaType::Audio);
    }

    #[test]
    fn test_stream_lifecycle() {
        let mut stream = MediaStream::new(test_config());

        // Start
        assert!(stream.start().is_ok());
        assert_eq!(stream.state(), StreamState::Active);

        // Hold
        assert!(stream.hold().is_ok());
        assert_eq!(stream.state(), StreamState::OnHold);

        // Resume
        assert!(stream.resume().is_ok());
        assert_eq!(stream.state(), StreamState::Active);

        // Stop
        assert!(stream.stop().is_ok());
        assert_eq!(stream.state(), StreamState::Stopped);
    }

    #[test]
    fn test_stream_stats() {
        let stream = MediaStream::new(test_config());

        stream.record_sent(100);
        stream.record_sent(100);
        stream.record_received(150);

        let stats = stream.stats();
        assert_eq!(stats.packets_sent, 2);
        assert_eq!(stats.bytes_sent, 200);
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.bytes_received, 150);
    }

    #[test]
    fn test_invalid_state_transition() {
        let mut stream = MediaStream::new(test_config());

        // Can't hold before starting
        assert!(stream.hold().is_err());

        // Can't resume when not on hold
        assert!(stream.resume().is_err());
    }
}
