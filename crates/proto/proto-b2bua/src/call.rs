//! B2BUA call management.
//!
//! A call represents a complete B2BUA session with two legs:
//! - A-leg: Connection to the caller
//! - B-leg: Connection to the callee

use crate::B2buaMode;
use crate::error::{B2buaError, B2buaResult};
use crate::leg::{CallLeg, LegConfig, LegRole, LegState};
use std::time::Instant;

/// Unique call identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallId(String);

impl CallId {
    /// Creates a new call ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Creates a unique call ID.
    pub fn generate() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        Self(format!("call-{timestamp:x}-{counter:x}"))
    }

    /// Returns the ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CallId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for CallId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for CallId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Call state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    /// Call created, A-leg being set up.
    Initializing,
    /// A-leg INVITE received, waiting to process.
    Received,
    /// B-leg INVITE being sent.
    Routing,
    /// B-leg proceeding (1xx received).
    Proceeding,
    /// Early media established.
    EarlyMedia,
    /// Call is active (both legs connected).
    Active,
    /// Call is on hold.
    OnHold,
    /// Call is being transferred.
    Transferring,
    /// Call is being torn down.
    Terminating,
    /// Call has ended.
    Terminated,
    /// Call failed.
    Failed,
}

impl std::fmt::Display for CallState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Initializing => write!(f, "Initializing"),
            Self::Received => write!(f, "Received"),
            Self::Routing => write!(f, "Routing"),
            Self::Proceeding => write!(f, "Proceeding"),
            Self::EarlyMedia => write!(f, "EarlyMedia"),
            Self::Active => write!(f, "Active"),
            Self::OnHold => write!(f, "OnHold"),
            Self::Transferring => write!(f, "Transferring"),
            Self::Terminating => write!(f, "Terminating"),
            Self::Terminated => write!(f, "Terminated"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Call configuration.
#[derive(Debug, Clone)]
pub struct CallConfig {
    /// Call ID.
    pub call_id: CallId,
    /// B2BUA mode.
    pub mode: B2buaMode,
    /// A-leg local URI (B2BUA's identity to caller).
    pub a_leg_local_uri: String,
    /// A-leg remote URI (caller's identity).
    pub a_leg_remote_uri: String,
    /// B-leg local URI (B2BUA's identity to callee).
    pub b_leg_local_uri: String,
    /// B-leg remote URI (callee's identity).
    pub b_leg_remote_uri: String,
}

impl CallConfig {
    /// Creates a new call configuration.
    pub fn new(
        a_leg_local_uri: impl Into<String>,
        a_leg_remote_uri: impl Into<String>,
        b_leg_local_uri: impl Into<String>,
        b_leg_remote_uri: impl Into<String>,
    ) -> Self {
        Self {
            call_id: CallId::generate(),
            mode: B2buaMode::default(),
            a_leg_local_uri: a_leg_local_uri.into(),
            a_leg_remote_uri: a_leg_remote_uri.into(),
            b_leg_local_uri: b_leg_local_uri.into(),
            b_leg_remote_uri: b_leg_remote_uri.into(),
        }
    }

    /// Sets the call ID.
    #[must_use]
    pub fn with_call_id(mut self, call_id: CallId) -> Self {
        self.call_id = call_id;
        self
    }

    /// Sets the B2BUA mode.
    #[must_use]
    pub fn with_mode(mut self, mode: B2buaMode) -> Self {
        self.mode = mode;
        self
    }
}

/// B2BUA call.
///
/// Manages the complete call lifecycle with both legs.
#[derive(Debug)]
pub struct Call {
    /// Call ID.
    id: CallId,
    /// Current state.
    state: CallState,
    /// B2BUA mode.
    mode: B2buaMode,
    /// A-leg (caller side).
    a_leg: CallLeg,
    /// B-leg (callee side).
    b_leg: CallLeg,
    /// When the call was created.
    created_at: Instant,
    /// When the call became active.
    active_at: Option<Instant>,
    /// Failure reason if failed.
    failure_reason: Option<String>,
    /// Failure status code if failed.
    failure_code: Option<u16>,
}

impl Call {
    /// Creates a new call.
    pub fn new(config: CallConfig) -> Self {
        let a_leg_config = LegConfig::new(
            format!("{}-a", config.call_id),
            LegRole::ALeg,
            &config.a_leg_local_uri,
            &config.a_leg_remote_uri,
        );
        let b_leg_config = LegConfig::new(
            format!("{}-b", config.call_id),
            LegRole::BLeg,
            &config.b_leg_local_uri,
            &config.b_leg_remote_uri,
        );

        Self {
            id: config.call_id,
            state: CallState::Initializing,
            mode: config.mode,
            a_leg: CallLeg::new(a_leg_config),
            b_leg: CallLeg::new(b_leg_config),
            created_at: Instant::now(),
            active_at: None,
            failure_reason: None,
            failure_code: None,
        }
    }

    /// Returns the call ID.
    pub fn id(&self) -> &CallId {
        &self.id
    }

    /// Returns the current state.
    pub fn state(&self) -> CallState {
        self.state
    }

    /// Returns the B2BUA mode.
    pub fn mode(&self) -> B2buaMode {
        self.mode
    }

    /// Returns a reference to the A-leg.
    pub fn a_leg(&self) -> &CallLeg {
        &self.a_leg
    }

    /// Returns a mutable reference to the A-leg.
    pub fn a_leg_mut(&mut self) -> &mut CallLeg {
        &mut self.a_leg
    }

    /// Returns a reference to the B-leg.
    pub fn b_leg(&self) -> &CallLeg {
        &self.b_leg
    }

    /// Returns a mutable reference to the B-leg.
    pub fn b_leg_mut(&mut self) -> &mut CallLeg {
        &mut self.b_leg
    }

    /// Returns a reference to a leg by role.
    pub fn leg(&self, role: LegRole) -> &CallLeg {
        match role {
            LegRole::ALeg => &self.a_leg,
            LegRole::BLeg => &self.b_leg,
        }
    }

    /// Returns a mutable reference to a leg by role.
    pub fn leg_mut(&mut self, role: LegRole) -> &mut CallLeg {
        match role {
            LegRole::ALeg => &mut self.a_leg,
            LegRole::BLeg => &mut self.b_leg,
        }
    }

    /// Returns when the call was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns when the call became active.
    pub fn active_at(&self) -> Option<Instant> {
        self.active_at
    }

    /// Returns the failure reason.
    pub fn failure_reason(&self) -> Option<&str> {
        self.failure_reason.as_deref()
    }

    /// Returns the failure status code.
    pub fn failure_code(&self) -> Option<u16> {
        self.failure_code
    }

    /// Marks the call as received (A-leg INVITE received).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn receive(&mut self) -> B2buaResult<()> {
        match self.state {
            CallState::Initializing => {
                self.state = CallState::Received;
                self.a_leg.start_invite()?;
                Ok(())
            }
            _ => Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Received".to_string(),
            }),
        }
    }

    /// Starts routing (B-leg INVITE being sent).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn start_routing(&mut self) -> B2buaResult<()> {
        match self.state {
            CallState::Received => {
                self.state = CallState::Routing;
                self.b_leg.start_invite()?;
                Ok(())
            }
            _ => Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Routing".to_string(),
            }),
        }
    }

    /// Processes a provisional response from B-leg.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn receive_provisional(&mut self, status_code: u16) -> B2buaResult<()> {
        match self.state {
            CallState::Routing | CallState::Proceeding => {
                self.b_leg.receive_provisional(status_code)?;
                self.state = CallState::Proceeding;
                Ok(())
            }
            _ => Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Proceeding".to_string(),
            }),
        }
    }

    /// Establishes early media.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn establish_early_media(&mut self) -> B2buaResult<()> {
        match self.state {
            CallState::Routing | CallState::Proceeding => {
                self.b_leg.establish_early_media()?;
                self.a_leg.establish_early_media()?;
                self.state = CallState::EarlyMedia;
                Ok(())
            }
            CallState::EarlyMedia => Ok(()), // Already in early media
            _ => Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "EarlyMedia".to_string(),
            }),
        }
    }

    /// Activates the call (B-leg 200 OK received).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn activate(&mut self) -> B2buaResult<()> {
        match self.state {
            CallState::Routing | CallState::Proceeding | CallState::EarlyMedia => {
                self.b_leg.activate(200)?;
                self.a_leg.activate(200)?;
                self.state = CallState::Active;
                self.active_at = Some(Instant::now());
                Ok(())
            }
            CallState::Active => Ok(()), // Already active
            _ => Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Active".to_string(),
            }),
        }
    }

    /// Puts the call on hold.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn hold(&mut self) -> B2buaResult<()> {
        match self.state {
            CallState::Active => {
                self.a_leg.hold()?;
                self.b_leg.hold()?;
                self.state = CallState::OnHold;
                Ok(())
            }
            CallState::OnHold => Ok(()), // Already on hold
            _ => Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "OnHold".to_string(),
            }),
        }
    }

    /// Resumes the call from hold.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn resume(&mut self) -> B2buaResult<()> {
        if self.state == CallState::OnHold {
            self.a_leg.resume()?;
            self.b_leg.resume()?;
            self.state = CallState::Active;
            Ok(())
        } else {
            Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Active".to_string(),
            })
        }
    }

    /// Starts termination.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn start_termination(&mut self) -> B2buaResult<()> {
        match self.state {
            CallState::Terminated | CallState::Failed => Ok(()), // Already done
            _ => {
                self.state = CallState::Terminating;

                // Terminate both legs if they're active
                if !self.a_leg.is_terminated() {
                    let _ = self.a_leg.start_termination();
                }
                if !self.b_leg.is_terminated() {
                    let _ = self.b_leg.start_termination();
                }

                Ok(())
            }
        }
    }

    /// Completes termination.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn terminate(&mut self) -> B2buaResult<()> {
        if self.state != CallState::Terminated {
            let _ = self.a_leg.terminate();
            let _ = self.b_leg.terminate();
            self.state = CallState::Terminated;
        }
        Ok(())
    }

    /// Fails the call with a status code and reason.
    pub fn fail(&mut self, status_code: u16, reason: impl Into<String>) {
        let reason_str = reason.into();
        self.failure_code = Some(status_code);
        self.failure_reason = Some(reason_str.clone());

        // Fail both legs
        if !self.a_leg.is_terminated() {
            self.a_leg.fail(status_code, &reason_str);
        }
        if !self.b_leg.is_terminated() {
            self.b_leg.fail(status_code, &reason_str);
        }

        self.state = CallState::Failed;
    }

    /// Returns whether the call is active.
    pub fn is_active(&self) -> bool {
        self.state == CallState::Active
    }

    /// Returns whether the call is terminated.
    pub fn is_terminated(&self) -> bool {
        matches!(self.state, CallState::Terminated | CallState::Failed)
    }

    /// Returns how long the call has been active.
    pub fn active_duration(&self) -> Option<std::time::Duration> {
        self.active_at.map(|t| t.elapsed())
    }

    /// Returns how long the call has been running.
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Updates the call state based on leg states.
    ///
    /// Call this after modifying legs directly.
    pub fn sync_state(&mut self) {
        // If both legs are terminated, call is terminated
        if self.a_leg.is_terminated() && self.b_leg.is_terminated() {
            if self.a_leg.state() == LegState::Failed || self.b_leg.state() == LegState::Failed {
                self.state = CallState::Failed;
            } else {
                self.state = CallState::Terminated;
            }
        }
        // If both legs are active, call is active
        else if self.a_leg.is_active()
            && self.b_leg.is_active()
            && self.state != CallState::OnHold
        {
            self.state = CallState::Active;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_call_config() -> CallConfig {
        CallConfig::new(
            "sip:b2bua@sbc.example.com",
            "sip:alice@client.example.com",
            "sip:b2bua@sbc.example.com",
            "sip:bob@server.example.com",
        )
    }

    #[test]
    fn test_call_id() {
        let id1 = CallId::generate();
        let id2 = CallId::generate();
        assert_ne!(id1, id2);

        let id3 = CallId::new("test-call");
        assert_eq!(id3.as_str(), "test-call");
    }

    #[test]
    fn test_call_state_display() {
        assert_eq!(CallState::Active.to_string(), "Active");
        assert_eq!(CallState::Terminated.to_string(), "Terminated");
    }

    #[test]
    fn test_call_creation() {
        let call = Call::new(test_call_config());
        assert_eq!(call.state(), CallState::Initializing);
        assert_eq!(call.mode(), B2buaMode::MediaRelay);
        assert_eq!(call.a_leg().role(), LegRole::ALeg);
        assert_eq!(call.b_leg().role(), LegRole::BLeg);
    }

    #[test]
    fn test_call_config_builder() {
        let config = test_call_config()
            .with_call_id(CallId::new("custom-id"))
            .with_mode(B2buaMode::SignalingOnly);

        assert_eq!(config.call_id.as_str(), "custom-id");
        assert_eq!(config.mode, B2buaMode::SignalingOnly);
    }

    #[test]
    fn test_call_lifecycle() {
        let mut call = Call::new(test_call_config());

        // Receive INVITE on A-leg
        call.receive().unwrap();
        assert_eq!(call.state(), CallState::Received);
        assert_eq!(call.a_leg().state(), LegState::Inviting);

        // Start routing to B-leg
        call.start_routing().unwrap();
        assert_eq!(call.state(), CallState::Routing);
        assert_eq!(call.b_leg().state(), LegState::Inviting);

        // Receive 180 Ringing from B-leg
        call.receive_provisional(180).unwrap();
        assert_eq!(call.state(), CallState::Proceeding);

        // Receive 200 OK from B-leg
        call.activate().unwrap();
        assert_eq!(call.state(), CallState::Active);
        assert!(call.is_active());
        assert!(call.a_leg().is_active());
        assert!(call.b_leg().is_active());

        // Terminate
        call.start_termination().unwrap();
        assert_eq!(call.state(), CallState::Terminating);

        call.terminate().unwrap();
        assert_eq!(call.state(), CallState::Terminated);
        assert!(call.is_terminated());
    }

    #[test]
    fn test_call_early_media() {
        let mut call = Call::new(test_call_config());

        call.receive().unwrap();
        call.start_routing().unwrap();
        call.receive_provisional(183).unwrap();
        call.establish_early_media().unwrap();
        assert_eq!(call.state(), CallState::EarlyMedia);

        call.activate().unwrap();
        assert_eq!(call.state(), CallState::Active);
    }

    #[test]
    fn test_call_hold_resume() {
        let mut call = Call::new(test_call_config());
        call.receive().unwrap();
        call.start_routing().unwrap();
        call.activate().unwrap();

        // Hold
        call.hold().unwrap();
        assert_eq!(call.state(), CallState::OnHold);
        assert_eq!(call.a_leg().state(), LegState::OnHold);
        assert_eq!(call.b_leg().state(), LegState::OnHold);

        // Resume
        call.resume().unwrap();
        assert_eq!(call.state(), CallState::Active);
    }

    #[test]
    fn test_call_failure() {
        let mut call = Call::new(test_call_config());
        call.receive().unwrap();
        call.start_routing().unwrap();

        // B-leg returns 486 Busy Here
        call.fail(486, "Busy Here");
        assert_eq!(call.state(), CallState::Failed);
        assert_eq!(call.failure_code(), Some(486));
        assert_eq!(call.failure_reason(), Some("Busy Here"));
        assert!(call.is_terminated());
    }

    #[test]
    fn test_call_leg_access() {
        let mut call = Call::new(test_call_config());

        // Access by role
        assert_eq!(call.leg(LegRole::ALeg).role(), LegRole::ALeg);
        assert_eq!(call.leg(LegRole::BLeg).role(), LegRole::BLeg);

        // Mutate by role
        call.leg_mut(LegRole::ALeg).set_remote_tag("tag-a");
        assert_eq!(call.a_leg().remote_tag(), Some("tag-a"));
    }

    #[test]
    fn test_invalid_state_transitions() {
        let mut call = Call::new(test_call_config());

        // Can't start routing before receiving
        assert!(call.start_routing().is_err());

        // Can't activate before routing
        call.receive().unwrap();
        assert!(call.activate().is_err());

        // Can't hold before active
        assert!(call.hold().is_err());
    }

    #[test]
    fn test_call_sync_state() {
        let mut call = Call::new(test_call_config());
        call.receive().unwrap();
        call.start_routing().unwrap();

        // Manually activate legs
        call.a_leg_mut().activate(200).unwrap();
        call.b_leg_mut().activate(200).unwrap();

        // Sync should detect both legs are active
        call.sync_state();
        assert_eq!(call.state(), CallState::Active);
    }

    #[test]
    fn test_call_active_duration() {
        let mut call = Call::new(test_call_config());
        call.receive().unwrap();
        call.start_routing().unwrap();
        call.activate().unwrap();

        // Should have active duration now
        assert!(call.active_duration().is_some());
        assert!(call.active_at().is_some());
    }
}
