//! Call leg management.
//!
//! A call leg represents one side of a B2BUA call. Each call has two legs:
//! - A-leg: The originating side (caller/UAC)
//! - B-leg: The terminating side (callee/UAS)

use crate::error::{B2buaError, B2buaResult};
use std::time::Instant;

/// Call leg role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegRole {
    /// A-leg (originating/caller side).
    ///
    /// The B2BUA acts as UAS to the A-leg.
    ALeg,
    /// B-leg (terminating/callee side).
    ///
    /// The B2BUA acts as UAC to the B-leg.
    BLeg,
}

impl std::fmt::Display for LegRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ALeg => write!(f, "A-leg"),
            Self::BLeg => write!(f, "B-leg"),
        }
    }
}

/// Call leg state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegState {
    /// Leg created, waiting to process.
    Created,
    /// INVITE sent/received, waiting for response.
    Inviting,
    /// Provisional response received (1xx).
    Proceeding,
    /// Early media established.
    EarlyMedia,
    /// Final response received, leg is active.
    Active,
    /// Leg is on hold.
    OnHold,
    /// BYE sent, waiting for response.
    Terminating,
    /// Leg has been terminated.
    Terminated,
    /// Leg failed.
    Failed,
}

impl std::fmt::Display for LegState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "Created"),
            Self::Inviting => write!(f, "Inviting"),
            Self::Proceeding => write!(f, "Proceeding"),
            Self::EarlyMedia => write!(f, "EarlyMedia"),
            Self::Active => write!(f, "Active"),
            Self::OnHold => write!(f, "OnHold"),
            Self::Terminating => write!(f, "Terminating"),
            Self::Terminated => write!(f, "Terminated"),
            Self::Failed => write!(f, "Failed"),
        }
    }
}

/// Call leg configuration.
#[derive(Debug, Clone)]
pub struct LegConfig {
    /// Leg ID.
    pub leg_id: String,
    /// Role (A-leg or B-leg).
    pub role: LegRole,
    /// Local URI.
    pub local_uri: String,
    /// Remote URI.
    pub remote_uri: String,
    /// Call-ID for this leg.
    pub call_id: String,
    /// Local tag.
    pub local_tag: String,
}

impl LegConfig {
    /// Creates a new leg configuration.
    pub fn new(
        leg_id: impl Into<String>,
        role: LegRole,
        local_uri: impl Into<String>,
        remote_uri: impl Into<String>,
    ) -> Self {
        let leg_id = leg_id.into();
        Self {
            leg_id: leg_id.clone(),
            role,
            local_uri: local_uri.into(),
            remote_uri: remote_uri.into(),
            call_id: generate_call_id(&leg_id),
            local_tag: generate_tag(),
        }
    }

    /// Creates an A-leg configuration.
    pub fn a_leg(
        leg_id: impl Into<String>,
        local_uri: impl Into<String>,
        remote_uri: impl Into<String>,
    ) -> Self {
        Self::new(leg_id, LegRole::ALeg, local_uri, remote_uri)
    }

    /// Creates a B-leg configuration.
    pub fn b_leg(
        leg_id: impl Into<String>,
        local_uri: impl Into<String>,
        remote_uri: impl Into<String>,
    ) -> Self {
        Self::new(leg_id, LegRole::BLeg, local_uri, remote_uri)
    }
}

/// Call leg.
#[derive(Debug)]
pub struct CallLeg {
    /// Configuration.
    config: LegConfig,
    /// Current state.
    state: LegState,
    /// Remote tag (from To/From header).
    remote_tag: Option<String>,
    /// Local CSeq.
    local_cseq: u32,
    /// Remote CSeq.
    remote_cseq: Option<u32>,
    /// Remote target (Contact URI).
    remote_target: Option<String>,
    /// Route set.
    route_set: Vec<String>,
    /// Last response code received.
    last_response_code: Option<u16>,
    /// When the leg was created.
    created_at: Instant,
    /// When the leg became active.
    active_at: Option<Instant>,
    /// Failure reason if failed.
    failure_reason: Option<String>,
}

impl CallLeg {
    /// Creates a new call leg.
    pub fn new(config: LegConfig) -> Self {
        Self {
            config,
            state: LegState::Created,
            remote_tag: None,
            local_cseq: 1,
            remote_cseq: None,
            remote_target: None,
            route_set: Vec::new(),
            last_response_code: None,
            created_at: Instant::now(),
            active_at: None,
            failure_reason: None,
        }
    }

    /// Returns the leg ID.
    pub fn leg_id(&self) -> &str {
        &self.config.leg_id
    }

    /// Returns the role.
    pub fn role(&self) -> LegRole {
        self.config.role
    }

    /// Returns the current state.
    pub fn state(&self) -> LegState {
        self.state
    }

    /// Returns the local URI.
    pub fn local_uri(&self) -> &str {
        &self.config.local_uri
    }

    /// Returns the remote URI.
    pub fn remote_uri(&self) -> &str {
        &self.config.remote_uri
    }

    /// Returns the Call-ID.
    pub fn call_id(&self) -> &str {
        &self.config.call_id
    }

    /// Returns the local tag.
    pub fn local_tag(&self) -> &str {
        &self.config.local_tag
    }

    /// Returns the remote tag.
    pub fn remote_tag(&self) -> Option<&str> {
        self.remote_tag.as_deref()
    }

    /// Returns the remote target.
    pub fn remote_target(&self) -> Option<&str> {
        self.remote_target.as_deref()
    }

    /// Returns the route set.
    pub fn route_set(&self) -> &[String] {
        &self.route_set
    }

    /// Returns the last response code.
    pub fn last_response_code(&self) -> Option<u16> {
        self.last_response_code
    }

    /// Returns when the leg was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns when the leg became active.
    pub fn active_at(&self) -> Option<Instant> {
        self.active_at
    }

    /// Returns the failure reason.
    pub fn failure_reason(&self) -> Option<&str> {
        self.failure_reason.as_deref()
    }

    /// Sets the remote tag.
    pub fn set_remote_tag(&mut self, tag: impl Into<String>) {
        self.remote_tag = Some(tag.into());
    }

    /// Sets the remote target.
    pub fn set_remote_target(&mut self, target: impl Into<String>) {
        self.remote_target = Some(target.into());
    }

    /// Sets the route set.
    pub fn set_route_set(&mut self, routes: Vec<String>) {
        self.route_set = routes;
    }

    /// Gets the next local CSeq and increments.
    pub fn next_cseq(&mut self) -> u32 {
        self.local_cseq += 1;
        self.local_cseq
    }

    /// Updates the remote CSeq.
    pub fn update_remote_cseq(&mut self, cseq: u32) -> B2buaResult<()> {
        if let Some(current) = self.remote_cseq {
            if cseq < current {
                return Err(B2buaError::InvalidLegOperation {
                    reason: format!("CSeq {} is less than current {}", cseq, current),
                });
            }
        }
        self.remote_cseq = Some(cseq);
        Ok(())
    }

    /// Starts inviting (INVITE sent/received).
    pub fn start_invite(&mut self) -> B2buaResult<()> {
        match self.state {
            LegState::Created => {
                self.state = LegState::Inviting;
                Ok(())
            }
            _ => Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Inviting".to_string(),
            }),
        }
    }

    /// Processes a provisional response (1xx).
    pub fn receive_provisional(&mut self, status_code: u16) -> B2buaResult<()> {
        self.last_response_code = Some(status_code);

        match self.state {
            LegState::Inviting | LegState::Proceeding => {
                self.state = LegState::Proceeding;
                Ok(())
            }
            _ => Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Proceeding".to_string(),
            }),
        }
    }

    /// Establishes early media.
    pub fn establish_early_media(&mut self) -> B2buaResult<()> {
        match self.state {
            LegState::Inviting | LegState::Proceeding => {
                self.state = LegState::EarlyMedia;
                Ok(())
            }
            LegState::EarlyMedia => Ok(()), // Already in early media
            _ => Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "EarlyMedia".to_string(),
            }),
        }
    }

    /// Activates the leg (2xx received/sent).
    pub fn activate(&mut self, status_code: u16) -> B2buaResult<()> {
        self.last_response_code = Some(status_code);

        match self.state {
            LegState::Inviting | LegState::Proceeding | LegState::EarlyMedia => {
                self.state = LegState::Active;
                self.active_at = Some(Instant::now());
                Ok(())
            }
            LegState::Active => Ok(()), // Already active
            _ => Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Active".to_string(),
            }),
        }
    }

    /// Puts the leg on hold.
    pub fn hold(&mut self) -> B2buaResult<()> {
        match self.state {
            LegState::Active => {
                self.state = LegState::OnHold;
                Ok(())
            }
            LegState::OnHold => Ok(()), // Already on hold
            _ => Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "OnHold".to_string(),
            }),
        }
    }

    /// Resumes from hold.
    pub fn resume(&mut self) -> B2buaResult<()> {
        if self.state == LegState::OnHold {
            self.state = LegState::Active;
            Ok(())
        } else {
            Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Active".to_string(),
            })
        }
    }

    /// Starts termination (BYE sent).
    pub fn start_termination(&mut self) -> B2buaResult<()> {
        match self.state {
            LegState::Active | LegState::OnHold | LegState::EarlyMedia => {
                self.state = LegState::Terminating;
                Ok(())
            }
            LegState::Terminating => Ok(()), // Already terminating
            LegState::Terminated => Ok(()),  // Already terminated
            _ => Err(B2buaError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "Terminating".to_string(),
            }),
        }
    }

    /// Completes termination.
    pub fn terminate(&mut self) -> B2buaResult<()> {
        match self.state {
            LegState::Terminated => Ok(()), // Already terminated
            _ => {
                self.state = LegState::Terminated;
                Ok(())
            }
        }
    }

    /// Fails the leg with a reason.
    pub fn fail(&mut self, status_code: u16, reason: impl Into<String>) {
        self.last_response_code = Some(status_code);
        self.failure_reason = Some(reason.into());
        self.state = LegState::Failed;
    }

    /// Returns whether the leg is active.
    pub fn is_active(&self) -> bool {
        self.state == LegState::Active
    }

    /// Returns whether the leg is terminated.
    pub fn is_terminated(&self) -> bool {
        matches!(self.state, LegState::Terminated | LegState::Failed)
    }

    /// Returns how long the leg has been active.
    pub fn active_duration(&self) -> Option<std::time::Duration> {
        self.active_at.map(|t| t.elapsed())
    }

    /// Returns how long the leg has been running.
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }
}

/// Generates a unique Call-ID.
fn generate_call_id(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{}-{:x}@b2bua", prefix, timestamp)
}

/// Generates a unique tag.
fn generate_tag() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}", timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_leg() -> CallLeg {
        let config = LegConfig::a_leg("leg-1", "sip:b2bua@example.com", "sip:alice@example.com");
        CallLeg::new(config)
    }

    #[test]
    fn test_leg_creation() {
        let leg = test_leg();
        assert_eq!(leg.role(), LegRole::ALeg);
        assert_eq!(leg.state(), LegState::Created);
        assert!(!leg.call_id().is_empty());
        assert!(!leg.local_tag().is_empty());
    }

    #[test]
    fn test_leg_role_display() {
        assert_eq!(LegRole::ALeg.to_string(), "A-leg");
        assert_eq!(LegRole::BLeg.to_string(), "B-leg");
    }

    #[test]
    fn test_leg_state_display() {
        assert_eq!(LegState::Created.to_string(), "Created");
        assert_eq!(LegState::Active.to_string(), "Active");
        assert_eq!(LegState::Terminated.to_string(), "Terminated");
    }

    #[test]
    fn test_leg_invite_flow() {
        let mut leg = test_leg();

        // Start invite
        leg.start_invite().unwrap();
        assert_eq!(leg.state(), LegState::Inviting);

        // Receive 100 Trying
        leg.receive_provisional(100).unwrap();
        assert_eq!(leg.state(), LegState::Proceeding);

        // Receive 180 Ringing
        leg.receive_provisional(180).unwrap();
        assert_eq!(leg.state(), LegState::Proceeding);

        // Receive 200 OK
        leg.activate(200).unwrap();
        assert_eq!(leg.state(), LegState::Active);
        assert!(leg.is_active());
    }

    #[test]
    fn test_leg_early_media() {
        let mut leg = test_leg();

        leg.start_invite().unwrap();
        leg.receive_provisional(183).unwrap();
        leg.establish_early_media().unwrap();
        assert_eq!(leg.state(), LegState::EarlyMedia);

        leg.activate(200).unwrap();
        assert_eq!(leg.state(), LegState::Active);
    }

    #[test]
    fn test_leg_hold_resume() {
        let mut leg = test_leg();
        leg.start_invite().unwrap();
        leg.activate(200).unwrap();

        // Hold
        leg.hold().unwrap();
        assert_eq!(leg.state(), LegState::OnHold);

        // Resume
        leg.resume().unwrap();
        assert_eq!(leg.state(), LegState::Active);
    }

    #[test]
    fn test_leg_termination() {
        let mut leg = test_leg();
        leg.start_invite().unwrap();
        leg.activate(200).unwrap();

        // Start termination
        leg.start_termination().unwrap();
        assert_eq!(leg.state(), LegState::Terminating);

        // Complete termination
        leg.terminate().unwrap();
        assert_eq!(leg.state(), LegState::Terminated);
        assert!(leg.is_terminated());
    }

    #[test]
    fn test_leg_failure() {
        let mut leg = test_leg();
        leg.start_invite().unwrap();

        // Fail with 486 Busy Here
        leg.fail(486, "Busy Here");
        assert_eq!(leg.state(), LegState::Failed);
        assert_eq!(leg.last_response_code(), Some(486));
        assert_eq!(leg.failure_reason(), Some("Busy Here"));
        assert!(leg.is_terminated());
    }

    #[test]
    fn test_leg_cseq() {
        let mut leg = test_leg();

        assert_eq!(leg.next_cseq(), 2);
        assert_eq!(leg.next_cseq(), 3);

        // Update remote CSeq
        leg.update_remote_cseq(100).unwrap();
        leg.update_remote_cseq(101).unwrap();

        // Should fail for lower CSeq
        assert!(leg.update_remote_cseq(99).is_err());
    }

    #[test]
    fn test_leg_config_builders() {
        let a_config = LegConfig::a_leg("leg-a", "sip:a@example.com", "sip:b@example.com");
        assert_eq!(a_config.role, LegRole::ALeg);

        let b_config = LegConfig::b_leg("leg-b", "sip:b2bua@example.com", "sip:c@example.com");
        assert_eq!(b_config.role, LegRole::BLeg);
    }

    #[test]
    fn test_invalid_state_transitions() {
        let mut leg = test_leg();

        // Can't activate from Created
        assert!(leg.activate(200).is_err());

        // Can't hold from Created
        assert!(leg.hold().is_err());

        // Can't resume from Created
        assert!(leg.resume().is_err());
    }

    #[test]
    fn test_leg_remote_info() {
        let mut leg = test_leg();

        leg.set_remote_tag("remote-tag-123");
        assert_eq!(leg.remote_tag(), Some("remote-tag-123"));

        leg.set_remote_target("sip:alice@192.168.1.100:5060");
        assert_eq!(leg.remote_target(), Some("sip:alice@192.168.1.100:5060"));

        let routes = vec!["<sip:proxy@example.com;lr>".to_string()];
        leg.set_route_set(routes.clone());
        assert_eq!(leg.route_set(), &routes);
    }
}
