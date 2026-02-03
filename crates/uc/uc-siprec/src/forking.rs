//! Media forking for SIPREC recording.
//!
//! This module handles the duplication and forwarding of media streams
//! to the Session Recording Server (SRS).
//!
//! ## Media Flow
//!
//! ```text
//! Caller -----> SBC -----> Callee
//!                |
//!                +-------> SRS (Recording Server)
//! ```

use crate::error::{SiprecError, SiprecResult};
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

/// Mode for media forking to recording server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForkingMode {
    /// Fork both directions (full duplex recording).
    #[default]
    BothDirections,
    /// Fork only inbound (caller to callee) direction.
    InboundOnly,
    /// Fork only outbound (callee to caller) direction.
    OutboundOnly,
    /// Disable forking.
    Disabled,
}

impl fmt::Display for ForkingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BothDirections => write!(f, "both"),
            Self::InboundOnly => write!(f, "inbound"),
            Self::OutboundOnly => write!(f, "outbound"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

/// Represents a forked media stream.
#[derive(Debug, Clone)]
pub struct StreamFork {
    /// Stream identifier (matches original stream).
    pub stream_id: String,
    /// Original source address.
    pub source_addr: SocketAddr,
    /// Original destination address.
    pub dest_addr: SocketAddr,
    /// Recording server destination address.
    pub fork_addr: SocketAddr,
    /// Whether this fork is active.
    pub active: bool,
    /// SSRC for the forked stream (may differ from original).
    pub fork_ssrc: Option<u32>,
    /// Forking mode for this stream.
    pub mode: ForkingMode,
    /// Packets forked count.
    pub packets_forked: u64,
    /// Bytes forked count.
    pub bytes_forked: u64,
}

impl StreamFork {
    /// Creates a new stream fork.
    #[must_use]
    pub fn new(
        stream_id: impl Into<String>,
        source_addr: SocketAddr,
        dest_addr: SocketAddr,
        fork_addr: SocketAddr,
    ) -> Self {
        Self {
            stream_id: stream_id.into(),
            source_addr,
            dest_addr,
            fork_addr,
            active: false,
            fork_ssrc: None,
            mode: ForkingMode::BothDirections,
            packets_forked: 0,
            bytes_forked: 0,
        }
    }

    /// Sets the forking mode.
    #[must_use]
    pub const fn with_mode(mut self, mode: ForkingMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the fork SSRC.
    #[must_use]
    pub const fn with_fork_ssrc(mut self, ssrc: u32) -> Self {
        self.fork_ssrc = Some(ssrc);
        self
    }

    /// Activates the fork.
    pub const fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivates the fork.
    pub const fn deactivate(&mut self) {
        self.active = false;
    }

    /// Records a forked packet.
    pub const fn record_forked_packet(&mut self, bytes: usize) {
        self.packets_forked += 1;
        self.bytes_forked += bytes as u64;
    }
}

/// State of the media forker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForkerState {
    /// Forker not initialized.
    #[default]
    Uninitialized,
    /// Forker initialized but not active.
    Initialized,
    /// Forker is actively forking media.
    Active,
    /// Forker paused.
    Paused,
    /// Forker stopped.
    Stopped,
    /// Forker in error state.
    Error,
}

impl fmt::Display for ForkerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uninitialized => write!(f, "uninitialized"),
            Self::Initialized => write!(f, "initialized"),
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Stopped => write!(f, "stopped"),
            Self::Error => write!(f, "error"),
        }
    }
}

/// Media forker for SIPREC.
///
/// Manages the forking of media streams to the recording server.
#[derive(Debug)]
pub struct MediaForker {
    /// Recording session ID.
    session_id: String,
    /// Forked streams.
    forks: HashMap<String, StreamFork>,
    /// Forker state.
    state: ForkerState,
    /// Default forking mode.
    default_mode: ForkingMode,
    /// Total packets forked across all streams.
    total_packets_forked: u64,
    /// Total bytes forked across all streams.
    total_bytes_forked: u64,
    /// Error message if in error state.
    error_message: Option<String>,
}

impl MediaForker {
    /// Creates a new media forker.
    #[must_use]
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            forks: HashMap::new(),
            state: ForkerState::Uninitialized,
            default_mode: ForkingMode::BothDirections,
            total_packets_forked: 0,
            total_bytes_forked: 0,
            error_message: None,
        }
    }

    /// Sets the default forking mode.
    #[must_use]
    pub const fn with_default_mode(mut self, mode: ForkingMode) -> Self {
        self.default_mode = mode;
        self
    }

    /// Returns the session ID.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the current state.
    #[must_use]
    pub const fn state(&self) -> ForkerState {
        self.state
    }

    /// Returns the number of forks.
    #[must_use]
    pub fn fork_count(&self) -> usize {
        self.forks.len()
    }

    /// Returns the total packets forked.
    #[must_use]
    pub const fn total_packets_forked(&self) -> u64 {
        self.total_packets_forked
    }

    /// Returns the total bytes forked.
    #[must_use]
    pub const fn total_bytes_forked(&self) -> u64 {
        self.total_bytes_forked
    }

    /// Initializes the forker.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn initialize(&mut self) -> SiprecResult<()> {
        if self.state != ForkerState::Uninitialized {
            return Err(SiprecError::InvalidState {
                expected: "uninitialized".to_string(),
                actual: self.state.to_string(),
            });
        }
        self.state = ForkerState::Initialized;
        tracing::info!(session_id = %self.session_id, "media forker initialized");
        Ok(())
    }

    /// Adds a stream fork.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn add_fork(&mut self, fork: StreamFork) -> SiprecResult<()> {
        if self.state == ForkerState::Uninitialized {
            return Err(SiprecError::InvalidState {
                expected: "initialized or active".to_string(),
                actual: "uninitialized".to_string(),
            });
        }

        let stream_id = fork.stream_id.clone();
        tracing::debug!(
            session_id = %self.session_id,
            stream_id = %stream_id,
            fork_addr = %fork.fork_addr,
            "adding stream fork"
        );

        self.forks.insert(stream_id, fork);
        Ok(())
    }

    /// Removes a stream fork.
    pub fn remove_fork(&mut self, stream_id: &str) -> Option<StreamFork> {
        let fork = self.forks.remove(stream_id);
        if fork.is_some() {
            tracing::debug!(
                session_id = %self.session_id,
                stream_id = %stream_id,
                "removed stream fork"
            );
        }
        fork
    }

    /// Gets a stream fork.
    #[must_use]
    pub fn get_fork(&self, stream_id: &str) -> Option<&StreamFork> {
        self.forks.get(stream_id)
    }

    /// Gets a mutable stream fork.
    pub fn get_fork_mut(&mut self, stream_id: &str) -> Option<&mut StreamFork> {
        self.forks.get_mut(stream_id)
    }

    /// Activates all forks and starts forking.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn start(&mut self) -> SiprecResult<()> {
        match self.state {
            ForkerState::Initialized | ForkerState::Paused => {
                for fork in self.forks.values_mut() {
                    fork.activate();
                }
                self.state = ForkerState::Active;
                tracing::info!(
                    session_id = %self.session_id,
                    fork_count = self.forks.len(),
                    "media forking started"
                );
                Ok(())
            }
            ForkerState::Active => Ok(()), // Already active
            _ => Err(SiprecError::InvalidState {
                expected: "initialized or paused".to_string(),
                actual: self.state.to_string(),
            }),
        }
    }

    /// Pauses all forks.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn pause(&mut self) -> SiprecResult<()> {
        if self.state != ForkerState::Active {
            return Err(SiprecError::InvalidState {
                expected: "active".to_string(),
                actual: self.state.to_string(),
            });
        }

        for fork in self.forks.values_mut() {
            fork.deactivate();
        }
        self.state = ForkerState::Paused;
        tracing::info!(session_id = %self.session_id, "media forking paused");
        Ok(())
    }

    /// Stops all forks.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn stop(&mut self) -> SiprecResult<()> {
        // Aggregate stats before stopping
        for fork in self.forks.values() {
            self.total_packets_forked += fork.packets_forked;
            self.total_bytes_forked += fork.bytes_forked;
        }

        for fork in self.forks.values_mut() {
            fork.deactivate();
        }
        self.state = ForkerState::Stopped;

        tracing::info!(
            session_id = %self.session_id,
            total_packets = self.total_packets_forked,
            total_bytes = self.total_bytes_forked,
            "media forking stopped"
        );
        Ok(())
    }

    /// Records a forked packet for a stream.
    pub fn record_forked(&mut self, stream_id: &str, bytes: usize) {
        if let Some(fork) = self.forks.get_mut(stream_id) {
            fork.record_forked_packet(bytes);
        }
    }

    /// Checks if forker should process a packet for the given stream.
    #[must_use]
    pub fn should_fork(&self, stream_id: &str) -> bool {
        if self.state != ForkerState::Active {
            return false;
        }
        self.forks
            .get(stream_id)
            .is_some_and(|f| f.active && f.mode != ForkingMode::Disabled)
    }

    /// Gets fork destination for a stream.
    #[must_use]
    pub fn fork_destination(&self, stream_id: &str) -> Option<SocketAddr> {
        self.forks
            .get(stream_id)
            .filter(|f| f.active)
            .map(|f| f.fork_addr)
    }

    /// Sets error state.
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.error_message = Some(message.into());
        self.state = ForkerState::Error;
        for fork in self.forks.values_mut() {
            fork.deactivate();
        }
    }

    /// Gets error message if in error state.
    #[must_use]
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Gets all fork addresses for SDP generation.
    #[must_use]
    pub fn all_fork_addresses(&self) -> Vec<SocketAddr> {
        self.forks.values().map(|f| f.fork_addr).collect()
    }

    /// Gets statistics summary.
    #[must_use]
    pub fn stats(&self) -> ForkerStats {
        let mut stats = ForkerStats {
            session_id: self.session_id.clone(),
            state: self.state,
            active_forks: 0,
            total_forks: self.forks.len(),
            packets_forked: self.total_packets_forked,
            bytes_forked: self.total_bytes_forked,
        };

        for fork in self.forks.values() {
            if fork.active {
                stats.active_forks += 1;
            }
            stats.packets_forked += fork.packets_forked;
            stats.bytes_forked += fork.bytes_forked;
        }

        stats
    }
}

/// Statistics for a media forker.
#[derive(Debug, Clone)]
pub struct ForkerStats {
    /// Session ID.
    pub session_id: String,
    /// Current state.
    pub state: ForkerState,
    /// Number of active forks.
    pub active_forks: usize,
    /// Total number of forks.
    pub total_forks: usize,
    /// Packets forked.
    pub packets_forked: u64,
    /// Bytes forked.
    pub bytes_forked: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), port)
    }

    #[test]
    fn test_stream_fork_creation() {
        let fork = StreamFork::new(
            "stream-1",
            test_addr(5000),
            test_addr(5002),
            test_addr(6000),
        )
        .with_mode(ForkingMode::BothDirections)
        .with_fork_ssrc(12345);

        assert_eq!(fork.stream_id, "stream-1");
        assert_eq!(fork.source_addr.port(), 5000);
        assert_eq!(fork.dest_addr.port(), 5002);
        assert_eq!(fork.fork_addr.port(), 6000);
        assert_eq!(fork.fork_ssrc, Some(12345));
        assert!(!fork.active);
    }

    #[test]
    fn test_forker_lifecycle() {
        let mut forker = MediaForker::new("session-123");

        assert_eq!(forker.state(), ForkerState::Uninitialized);

        forker.initialize().expect("initialize");
        assert_eq!(forker.state(), ForkerState::Initialized);

        let fork = StreamFork::new("s1", test_addr(5000), test_addr(5002), test_addr(6000));
        forker.add_fork(fork).expect("add_fork");
        assert_eq!(forker.fork_count(), 1);

        forker.start().expect("start");
        assert_eq!(forker.state(), ForkerState::Active);
        assert!(forker.should_fork("s1"));

        forker.pause().expect("pause");
        assert_eq!(forker.state(), ForkerState::Paused);
        assert!(!forker.should_fork("s1"));

        forker.start().expect("resume");
        assert_eq!(forker.state(), ForkerState::Active);

        forker.stop().expect("stop");
        assert_eq!(forker.state(), ForkerState::Stopped);
    }

    #[test]
    fn test_fork_stats() {
        let mut forker = MediaForker::new("session-456");
        forker.initialize().expect("initialize");

        let fork1 = StreamFork::new("s1", test_addr(5000), test_addr(5002), test_addr(6000));
        let fork2 = StreamFork::new("s2", test_addr(5004), test_addr(5006), test_addr(6002));
        forker.add_fork(fork1).expect("add_fork1");
        forker.add_fork(fork2).expect("add_fork2");

        forker.start().expect("start");

        // Simulate forked packets
        forker.record_forked("s1", 160);
        forker.record_forked("s1", 160);
        forker.record_forked("s2", 160);

        let stats = forker.stats();
        assert_eq!(stats.active_forks, 2);
        assert_eq!(stats.total_forks, 2);
        assert_eq!(stats.packets_forked, 3);
        assert_eq!(stats.bytes_forked, 480);
    }

    #[test]
    fn test_forking_mode_display() {
        assert_eq!(format!("{}", ForkingMode::BothDirections), "both");
        assert_eq!(format!("{}", ForkingMode::InboundOnly), "inbound");
        assert_eq!(format!("{}", ForkingMode::OutboundOnly), "outbound");
        assert_eq!(format!("{}", ForkingMode::Disabled), "disabled");
    }

    #[test]
    fn test_fork_destination() {
        let mut forker = MediaForker::new("session-789");
        forker.initialize().expect("initialize");

        let fork = StreamFork::new("s1", test_addr(5000), test_addr(5002), test_addr(6000));
        forker.add_fork(fork).expect("add_fork");

        // Not active yet
        assert!(forker.fork_destination("s1").is_none());

        forker.start().expect("start");
        assert_eq!(
            forker.fork_destination("s1").expect("fork dest").port(),
            6000
        );
    }

    #[test]
    fn test_error_state() {
        let mut forker = MediaForker::new("session-error");
        forker.initialize().expect("initialize");

        let fork = StreamFork::new("s1", test_addr(5000), test_addr(5002), test_addr(6000));
        forker.add_fork(fork).expect("add_fork");
        forker.start().expect("start");

        forker.set_error("connection lost to recording server");

        assert_eq!(forker.state(), ForkerState::Error);
        assert_eq!(
            forker.error_message(),
            Some("connection lost to recording server")
        );
        assert!(!forker.should_fork("s1"));
    }
}
