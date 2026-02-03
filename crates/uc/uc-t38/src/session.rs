//! T.38 session management.
//!
//! Manages T.38 fax sessions including audio-to-T.38 gateway transitions.

use crate::config::T38Config;
use crate::error::{T38Error, T38Result};
use crate::ifp::{DataType, IfpPacket, T30Indication};
use crate::signal::{FaxPhase, SignalDetector, T30Signal};
use crate::udptl::UdptlTransport;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// T.38 session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum T38SessionState {
    /// Session created, not yet started.
    Idle,
    /// Waiting for fax signal detection (audio mode).
    WaitingForSignal,
    /// Switching from audio to T.38.
    Switching,
    /// T.38 session active - Phase A (call establishment).
    PhaseA,
    /// T.38 session active - Phase B (negotiation).
    PhaseB,
    /// T.38 session active - Phase C (image transfer).
    PhaseC,
    /// T.38 session active - Phase D (post-message).
    PhaseD,
    /// T.38 session active - Phase E (call release).
    PhaseE,
    /// Session completed successfully.
    Completed,
    /// Session failed.
    Failed,
    /// Session terminated.
    Terminated,
}

impl T38SessionState {
    /// Returns the corresponding fax phase if in an active state.
    #[must_use]
    pub const fn fax_phase(&self) -> Option<FaxPhase> {
        match self {
            Self::PhaseA => Some(FaxPhase::PhaseA),
            Self::PhaseB => Some(FaxPhase::PhaseB),
            Self::PhaseC => Some(FaxPhase::PhaseC),
            Self::PhaseD => Some(FaxPhase::PhaseD),
            Self::PhaseE => Some(FaxPhase::PhaseE),
            _ => None,
        }
    }

    /// Returns true if the session is in an active fax state.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(
            self,
            Self::PhaseA | Self::PhaseB | Self::PhaseC | Self::PhaseD | Self::PhaseE
        )
    }

    /// Returns true if the session has ended.
    #[must_use]
    pub const fn is_ended(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Terminated)
    }
}

impl std::fmt::Display for T38SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::WaitingForSignal => write!(f, "waiting-for-signal"),
            Self::Switching => write!(f, "switching"),
            Self::PhaseA => write!(f, "phase-a"),
            Self::PhaseB => write!(f, "phase-b"),
            Self::PhaseC => write!(f, "phase-c"),
            Self::PhaseD => write!(f, "phase-d"),
            Self::PhaseE => write!(f, "phase-e"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Terminated => write!(f, "terminated"),
        }
    }
}

/// T.38 session statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct T38SessionStats {
    /// Number of pages transmitted.
    pub pages_transmitted: u32,
    /// Number of pages received.
    pub pages_received: u32,
    /// Total bytes transmitted.
    pub bytes_transmitted: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Number of packets lost.
    pub packets_lost: u32,
    /// Number of packets recovered.
    pub packets_recovered: u32,
    /// Highest data rate achieved (bps).
    pub max_data_rate: u32,
}

/// T.38 fax session.
pub struct T38Session {
    /// Session identifier.
    id: String,
    /// Current state.
    state: T38SessionState,
    /// Associated SIP Call-ID.
    call_id: Option<String>,
    /// UDPTL transport (once established).
    transport: Option<Arc<UdptlTransport>>,
    /// Signal detector for audio mode.
    signal_detector: SignalDetector,
    /// Session creation time.
    created_at: Instant,
    /// Last activity time.
    last_activity: Instant,
    /// Session statistics.
    stats: T38SessionStats,
    /// Sequence number for outgoing packets.
    seq_num: u16,
    /// Last detected signal.
    last_signal: Option<T30Signal>,
    /// Configuration.
    config: T38Config,
}

impl T38Session {
    /// Creates a new T.38 session.
    #[must_use]
    pub fn new(id: impl Into<String>, config: T38Config) -> Self {
        let now = Instant::now();
        Self {
            id: id.into(),
            state: T38SessionState::Idle,
            call_id: None,
            transport: None,
            signal_detector: SignalDetector::new(8000),
            created_at: now,
            last_activity: now,
            stats: T38SessionStats::default(),
            seq_num: 0,
            last_signal: None,
            config,
        }
    }

    /// Returns the session ID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the current state.
    #[must_use]
    pub fn state(&self) -> T38SessionState {
        self.state
    }

    /// Returns the session statistics.
    #[must_use]
    pub fn stats(&self) -> &T38SessionStats {
        &self.stats
    }

    /// Associates this session with a SIP call.
    pub fn set_call_id(&mut self, call_id: impl Into<String>) {
        self.call_id = Some(call_id.into());
    }

    /// Returns the associated SIP Call-ID.
    #[must_use]
    pub fn call_id(&self) -> Option<&str> {
        self.call_id.as_deref()
    }

    /// Starts waiting for fax signal (audio gateway mode).
    pub fn start_audio_detection(&mut self) {
        self.state = T38SessionState::WaitingForSignal;
        self.signal_detector.reset();
        debug!(session = %self.id, "Started audio fax signal detection");
    }

    /// Processes audio samples for fax signal detection.
    ///
    /// Returns `Some(signal)` if a fax signal is detected.
    pub fn process_audio(&mut self, samples: &[i16]) -> Option<T30Signal> {
        if self.state != T38SessionState::WaitingForSignal {
            return None;
        }

        if let Some(signal) = self.signal_detector.process(samples) {
            self.last_signal = Some(signal);
            self.last_activity = Instant::now();

            // Check if we should auto-switch to T.38
            let should_switch = match signal {
                T30Signal::Cng => self.config.session.auto_switch_on_cng,
                T30Signal::Ced => self.config.session.auto_switch_on_ced,
                _ => false,
            };

            if should_switch {
                info!(session = %self.id, signal = %signal, "Fax signal detected, triggering T.38 switch");
                self.state = T38SessionState::Switching;
            }

            return Some(signal);
        }

        None
    }

    /// Sets up the UDPTL transport for T.38.
    pub fn set_transport(&mut self, transport: Arc<UdptlTransport>) {
        self.transport = Some(transport);
        self.state = T38SessionState::PhaseA;
        self.last_activity = Instant::now();
        info!(session = %self.id, "T.38 transport established");
    }

    /// Sends an IFP packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport is not established or sending fails.
    pub async fn send_ifp(&mut self, data_type: DataType, data: Vec<u8>) -> T38Result<()> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| T38Error::TransportError {
                reason: "transport not established".to_string(),
            })?;

        let data_len = data.len();
        let ifp = IfpPacket::new(self.seq_num, data_type, data);
        self.seq_num = self.seq_num.wrapping_add(1);

        transport.send(ifp).await?;

        self.stats.bytes_transmitted += data_len as u64;
        self.last_activity = Instant::now();

        // Track max data rate
        let rate = data_type.bit_rate();
        if rate > self.stats.max_data_rate {
            self.stats.max_data_rate = rate;
        }

        Ok(())
    }

    /// Sends a T.30 indication.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport is not established or sending fails.
    pub async fn send_indication(&mut self, indication: T30Indication) -> T38Result<()> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| T38Error::TransportError {
                reason: "transport not established".to_string(),
            })?;

        let ifp = IfpPacket::indication(self.seq_num, indication);
        self.seq_num = self.seq_num.wrapping_add(1);

        transport.send(ifp).await?;
        self.last_activity = Instant::now();

        debug!(session = %self.id, indication = ?indication, "Sent T.30 indication");

        Ok(())
    }

    /// Receives an IFP packet.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport is not established or receiving fails.
    pub async fn recv_ifp(&mut self) -> T38Result<IfpPacket> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| T38Error::TransportError {
                reason: "transport not established".to_string(),
            })?;

        let ifp = transport.recv().await?;

        self.stats.bytes_received += ifp.data.len() as u64;
        self.last_activity = Instant::now();

        // Update phase based on received signal
        if let Some(indication) = ifp.indication {
            self.handle_indication(indication);
        }

        Ok(ifp)
    }

    /// Handles a received T.30 indication.
    fn handle_indication(&mut self, indication: T30Indication) {
        match indication {
            T30Indication::Cng | T30Indication::Ced => {
                if self.state == T38SessionState::PhaseA {
                    debug!(session = %self.id, "Phase A: Call establishment");
                }
            }
            T30Indication::V21Preamble => {
                if self.state == T38SessionState::PhaseA {
                    self.state = T38SessionState::PhaseB;
                    debug!(session = %self.id, "Transitioning to Phase B");
                }
            }
            T30Indication::V17ShortTraining
            | T30Indication::V17LongTraining
            | T30Indication::V27Training
            | T30Indication::V29Training => {
                if self.state == T38SessionState::PhaseB {
                    self.state = T38SessionState::PhaseC;
                    debug!(session = %self.id, "Transitioning to Phase C");
                }
            }
            T30Indication::PageMarker => {
                self.stats.pages_received += 1;
                self.state = T38SessionState::PhaseD;
                debug!(
                    session = %self.id,
                    pages = self.stats.pages_received,
                    "Page received, transitioning to Phase D"
                );
            }
            _ => {}
        }
    }

    /// Marks a page as transmitted.
    pub fn page_transmitted(&mut self) {
        self.stats.pages_transmitted += 1;
        info!(
            session = %self.id,
            pages = self.stats.pages_transmitted,
            "Page transmitted"
        );
    }

    /// Completes the session successfully.
    pub fn complete(&mut self) {
        self.state = T38SessionState::Completed;
        self.last_activity = Instant::now();
        info!(
            session = %self.id,
            pages_tx = self.stats.pages_transmitted,
            pages_rx = self.stats.pages_received,
            "T.38 session completed"
        );
    }

    /// Fails the session with a reason.
    pub fn fail(&mut self, reason: &str) {
        self.state = T38SessionState::Failed;
        self.last_activity = Instant::now();
        warn!(session = %self.id, reason, "T.38 session failed");
    }

    /// Terminates the session.
    pub fn terminate(&mut self) {
        self.state = T38SessionState::Terminated;
        self.last_activity = Instant::now();
        info!(session = %self.id, "T.38 session terminated");
    }

    /// Returns the session age.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Returns time since last activity.
    #[must_use]
    pub fn idle_time(&self) -> Duration {
        self.last_activity.elapsed()
    }
}

impl std::fmt::Debug for T38Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("T38Session")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("call_id", &self.call_id)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

/// T.38 session manager.
pub struct T38SessionManager {
    /// Active sessions by ID.
    sessions: Arc<RwLock<HashMap<String, T38Session>>>,
    /// Configuration.
    config: T38Config,
}

impl T38SessionManager {
    /// Creates a new session manager.
    #[must_use]
    pub fn new(config: T38Config) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Creates a new T.38 session.
    ///
    /// # Errors
    ///
    /// Returns an error if the session limit is reached.
    pub async fn create_session(&self, id: impl Into<String>) -> T38Result<String> {
        let id = id.into();
        let mut sessions = self.sessions.write().await;

        if sessions.len() >= self.config.session.max_sessions {
            return Err(T38Error::SessionNotFound {
                session_id: format!(
                    "max sessions ({}) reached",
                    self.config.session.max_sessions
                ),
            });
        }

        if sessions.contains_key(&id) {
            return Err(T38Error::SessionExists {
                session_id: id.clone(),
            });
        }

        let session = T38Session::new(id.clone(), self.config.clone());
        sessions.insert(id.clone(), session);

        info!(session_id = %id, "Created T.38 session");
        Ok(id)
    }

    /// Gets a session by ID.
    pub async fn get_session(&self, id: &str) -> Option<T38SessionState> {
        let sessions = self.sessions.read().await;
        sessions.get(id).map(|s| s.state())
    }

    /// Updates a session with a closure.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is not found.
    pub async fn update_session<F, R>(&self, id: &str, f: F) -> T38Result<R>
    where
        F: FnOnce(&mut T38Session) -> R,
    {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(id) {
            Ok(f(session))
        } else {
            Err(T38Error::SessionNotFound {
                session_id: id.to_string(),
            })
        }
    }

    /// Removes a session.
    pub async fn remove_session(&self, id: &str) -> Option<T38SessionStats> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(id).map(|s| s.stats)
    }

    /// Returns the number of active sessions.
    pub async fn session_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.len()
    }

    /// Cleans up expired sessions.
    pub async fn cleanup_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let idle_timeout = self.config.session.idle_timeout;

        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.idle_time() > idle_timeout && s.state.is_ended())
            .map(|(id, _)| id.clone())
            .collect();

        let count = expired.len();
        for id in expired {
            sessions.remove(&id);
            debug!(session_id = %id, "Cleaned up expired T.38 session");
        }

        if count > 0 {
            info!(count, "Cleaned up expired T.38 sessions");
        }

        count
    }
}

impl std::fmt::Debug for T38SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("T38SessionManager")
            .field("max_sessions", &self.config.session.max_sessions)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_session_state() {
        assert!(T38SessionState::PhaseC.is_active());
        assert!(!T38SessionState::Idle.is_active());
        assert!(T38SessionState::Completed.is_ended());
        assert!(!T38SessionState::PhaseA.is_ended());
    }

    #[test]
    fn test_session_creation() {
        let config = T38Config::default();
        let session = T38Session::new("test-session", config);

        assert_eq!(session.id(), "test-session");
        assert_eq!(session.state(), T38SessionState::Idle);
    }

    #[test]
    fn test_session_audio_detection() {
        let config = T38Config::default();
        let mut session = T38Session::new("test", config);

        session.start_audio_detection();
        assert_eq!(session.state(), T38SessionState::WaitingForSignal);
    }

    #[tokio::test]
    async fn test_session_manager() {
        let config = T38Config::default();
        let manager = T38SessionManager::new(config);

        let id = manager.create_session("session-1").await.unwrap();
        assert_eq!(id, "session-1");
        assert_eq!(manager.session_count().await, 1);

        manager.remove_session("session-1").await;
        assert_eq!(manager.session_count().await, 0);
    }

    #[test]
    fn test_session_state_display() {
        assert_eq!(T38SessionState::PhaseA.to_string(), "phase-a");
        assert_eq!(T38SessionState::Completed.to_string(), "completed");
    }
}
