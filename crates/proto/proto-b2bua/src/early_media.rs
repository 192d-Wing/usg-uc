//! Early media handling for B2BUA per RFC 3960.
//!
//! This module implements early media management for 183 Session Progress
//! responses that contain SDP, enabling media flow before call answer.
//!
//! ## RFC 3960 Overview
//!
//! - Early media is media exchanged before the call is answered (2xx)
//! - Typically signaled via 183 Session Progress with SDP
//! - Used for ringback tones, IVR announcements, etc.
//! - B2BUA must handle early media on both legs
//!
//! ## B2BUA Early Media Modes
//!
//! - **None**: No early media support (only media after 200 OK)
//! - **Local**: B2BUA generates local ringback
//! - **Relay**: Relay early media from B-leg to A-leg
//! - **Gate**: Hold early media until call is confirmed

use crate::B2buaMode;
use crate::mode::MediaAddress;

/// Early media disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EarlyMediaMode {
    /// No early media support.
    None,
    /// B2BUA generates local ringback tone.
    LocalRingback,
    /// Relay early media from B-leg to A-leg (default for MediaRelay mode).
    #[default]
    Relay,
    /// Gate early media until call confirmation.
    Gate,
}

impl std::fmt::Display for EarlyMediaMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::LocalRingback => write!(f, "local-ringback"),
            Self::Relay => write!(f, "relay"),
            Self::Gate => write!(f, "gate"),
        }
    }
}

/// Early media state per leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EarlyMediaState {
    /// No early media negotiated.
    None,
    /// Early media offer sent (waiting for answer).
    OfferSent,
    /// Early media active (183 with SDP received/sent).
    Active,
    /// Early media completed (call answered or failed).
    Completed,
}

impl std::fmt::Display for EarlyMediaState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::OfferSent => write!(f, "offer-sent"),
            Self::Active => write!(f, "active"),
            Self::Completed => write!(f, "completed"),
        }
    }
}

/// Early media session information.
#[derive(Debug, Clone)]
pub struct EarlyMediaSession {
    /// State of early media.
    state: EarlyMediaState,
    /// Local media address for early media.
    local_address: Option<MediaAddress>,
    /// Remote media address from early media SDP.
    remote_address: Option<MediaAddress>,
    /// Whether early media SDP has been processed.
    sdp_processed: bool,
    /// The SDP offer (from INVITE).
    offer_sdp: Option<String>,
    /// The SDP answer (from 183).
    answer_sdp: Option<String>,
}

impl EarlyMediaSession {
    /// Creates a new early media session.
    pub fn new() -> Self {
        Self {
            state: EarlyMediaState::None,
            local_address: None,
            remote_address: None,
            sdp_processed: false,
            offer_sdp: None,
            answer_sdp: None,
        }
    }

    /// Returns the current state.
    pub fn state(&self) -> EarlyMediaState {
        self.state
    }

    /// Returns the local media address.
    pub fn local_address(&self) -> Option<&MediaAddress> {
        self.local_address.as_ref()
    }

    /// Returns the remote media address.
    pub fn remote_address(&self) -> Option<&MediaAddress> {
        self.remote_address.as_ref()
    }

    /// Returns the offer SDP.
    pub fn offer_sdp(&self) -> Option<&str> {
        self.offer_sdp.as_deref()
    }

    /// Returns the answer SDP.
    pub fn answer_sdp(&self) -> Option<&str> {
        self.answer_sdp.as_deref()
    }

    /// Returns true if early media is active.
    pub fn is_active(&self) -> bool {
        self.state == EarlyMediaState::Active
    }

    /// Sets the offer SDP (from INVITE).
    pub fn set_offer(&mut self, sdp: String, local_address: MediaAddress) {
        self.offer_sdp = Some(sdp);
        self.local_address = Some(local_address);
        self.state = EarlyMediaState::OfferSent;
    }

    /// Processes a 183 Session Progress with SDP answer.
    pub fn receive_183_with_sdp(&mut self, sdp: String, remote_address: MediaAddress) {
        self.answer_sdp = Some(sdp);
        self.remote_address = Some(remote_address);
        self.sdp_processed = true;
        self.state = EarlyMediaState::Active;
    }

    /// Marks early media as completed (call answered or failed).
    pub fn complete(&mut self) {
        self.state = EarlyMediaState::Completed;
    }

    /// Checks if SDP has been processed.
    pub fn is_sdp_processed(&self) -> bool {
        self.sdp_processed
    }
}

impl Default for EarlyMediaSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Early media handler for B2BUA.
///
/// Manages early media state for both legs of a B2BUA call.
#[derive(Debug, Clone)]
pub struct EarlyMediaHandler {
    /// B2BUA mode.
    mode: B2buaMode,
    /// Early media disposition mode.
    early_media_mode: EarlyMediaMode,
    /// A-leg early media session.
    a_leg: EarlyMediaSession,
    /// B-leg early media session.
    b_leg: EarlyMediaSession,
    /// Whether to forward early media from B-leg to A-leg.
    forward_early_media: bool,
}

impl EarlyMediaHandler {
    /// Creates a new early media handler.
    pub fn new(mode: B2buaMode) -> Self {
        let early_media_mode = match mode {
            B2buaMode::SignalingOnly => EarlyMediaMode::None,
            B2buaMode::MediaRelay => EarlyMediaMode::Relay,
            B2buaMode::MediaAware => EarlyMediaMode::Relay,
            B2buaMode::MediaTermination => EarlyMediaMode::Gate,
        };

        Self {
            mode,
            early_media_mode,
            a_leg: EarlyMediaSession::new(),
            b_leg: EarlyMediaSession::new(),
            forward_early_media: early_media_mode == EarlyMediaMode::Relay,
        }
    }

    /// Creates a handler with a specific early media mode.
    pub fn with_mode(mode: B2buaMode, early_media_mode: EarlyMediaMode) -> Self {
        Self {
            mode,
            early_media_mode,
            a_leg: EarlyMediaSession::new(),
            b_leg: EarlyMediaSession::new(),
            forward_early_media: early_media_mode == EarlyMediaMode::Relay,
        }
    }

    /// Returns the B2BUA mode.
    pub fn b2bua_mode(&self) -> B2buaMode {
        self.mode
    }

    /// Returns the early media mode.
    pub fn early_media_mode(&self) -> EarlyMediaMode {
        self.early_media_mode
    }

    /// Returns the A-leg session.
    pub fn a_leg(&self) -> &EarlyMediaSession {
        &self.a_leg
    }

    /// Returns the B-leg session.
    pub fn b_leg(&self) -> &EarlyMediaSession {
        &self.b_leg
    }

    /// Returns true if early media should be forwarded.
    pub fn should_forward(&self) -> bool {
        self.forward_early_media
    }

    /// Sets the A-leg offer (INVITE from caller).
    pub fn set_a_leg_offer(&mut self, sdp: String, local_address: MediaAddress) {
        self.a_leg.set_offer(sdp, local_address);
    }

    /// Sets the B-leg offer (INVITE to callee).
    pub fn set_b_leg_offer(&mut self, sdp: String, local_address: MediaAddress) {
        self.b_leg.set_offer(sdp, local_address);
    }

    /// Processes 183 from B-leg.
    ///
    /// Returns the SDP to forward to A-leg (if any).
    pub fn receive_b_leg_183(
        &mut self,
        sdp: String,
        remote_address: MediaAddress,
    ) -> Option<EarlyMediaAction> {
        self.b_leg.receive_183_with_sdp(sdp, remote_address);

        match self.early_media_mode {
            EarlyMediaMode::None => None,
            EarlyMediaMode::LocalRingback => Some(EarlyMediaAction::GenerateLocalRingback),
            EarlyMediaMode::Relay => {
                // Forward early media SDP to A-leg
                Some(EarlyMediaAction::ForwardToALeg {
                    sdp: self.b_leg.answer_sdp().map(String::from),
                })
            }
            EarlyMediaMode::Gate => Some(EarlyMediaAction::GateUntilAnswer),
        }
    }

    /// Processes 183 from A-leg (for re-INVITE scenarios).
    pub fn receive_a_leg_183(&mut self, sdp: String, remote_address: MediaAddress) {
        self.a_leg.receive_183_with_sdp(sdp, remote_address);
    }

    /// Called when call is answered (200 OK received).
    pub fn call_answered(&mut self) {
        self.a_leg.complete();
        self.b_leg.complete();
    }

    /// Called when call fails.
    pub fn call_failed(&mut self) {
        self.a_leg.complete();
        self.b_leg.complete();
    }

    /// Returns true if any leg has active early media.
    pub fn has_active_early_media(&self) -> bool {
        self.a_leg.is_active() || self.b_leg.is_active()
    }

    /// Checks if early media is supported for the current mode.
    pub fn is_early_media_supported(&self) -> bool {
        self.early_media_mode != EarlyMediaMode::None
    }
}

/// Action to take when early media is received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EarlyMediaAction {
    /// Generate local ringback tone.
    GenerateLocalRingback,
    /// Forward early media SDP to A-leg.
    ForwardToALeg {
        /// SDP to forward.
        sdp: Option<String>,
    },
    /// Gate early media until call is answered.
    GateUntilAnswer,
}

/// Early media configuration.
#[derive(Debug, Clone)]
pub struct EarlyMediaConfig {
    /// Early media disposition mode.
    pub mode: EarlyMediaMode,
    /// Local ringback file path (for LocalRingback mode).
    pub ringback_file: Option<String>,
    /// Timeout for early media (seconds).
    pub timeout: u32,
    /// Whether to send 183 to caller when receiving from callee.
    pub forward_183: bool,
}

impl Default for EarlyMediaConfig {
    fn default() -> Self {
        Self {
            mode: EarlyMediaMode::Relay,
            ringback_file: None,
            timeout: 180,
            forward_183: true,
        }
    }
}

impl EarlyMediaConfig {
    /// Creates a new configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the early media mode.
    #[must_use]
    pub fn with_mode(mut self, mode: EarlyMediaMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the ringback file.
    #[must_use]
    pub fn with_ringback(mut self, path: impl Into<String>) -> Self {
        self.ringback_file = Some(path.into());
        self
    }

    /// Sets the timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: u32) -> Self {
        self.timeout = timeout;
        self
    }

    /// Disables 183 forwarding.
    #[must_use]
    pub fn without_183_forward(mut self) -> Self {
        self.forward_183 = false;
        self
    }
}

/// Checks if a response code indicates early media capability.
pub fn is_early_media_response(status_code: u16) -> bool {
    // 183 Session Progress typically carries early media SDP
    // 180 Ringing may also carry early media in some cases
    status_code == 183 || status_code == 180
}

/// Checks if a response should trigger early media setup.
pub fn should_setup_early_media(status_code: u16, has_sdp: bool) -> bool {
    // Only 183 with SDP should trigger early media
    status_code == 183 && has_sdp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_early_media_mode_display() {
        assert_eq!(EarlyMediaMode::None.to_string(), "none");
        assert_eq!(EarlyMediaMode::Relay.to_string(), "relay");
        assert_eq!(EarlyMediaMode::LocalRingback.to_string(), "local-ringback");
        assert_eq!(EarlyMediaMode::Gate.to_string(), "gate");
    }

    #[test]
    fn test_early_media_state_display() {
        assert_eq!(EarlyMediaState::None.to_string(), "none");
        assert_eq!(EarlyMediaState::Active.to_string(), "active");
    }

    #[test]
    fn test_early_media_session_lifecycle() {
        let mut session = EarlyMediaSession::new();
        assert_eq!(session.state(), EarlyMediaState::None);

        // Set offer
        let local = MediaAddress::new("10.0.0.1", 20000);
        session.set_offer("v=0...".to_string(), local);
        assert_eq!(session.state(), EarlyMediaState::OfferSent);

        // Receive 183 with SDP
        let remote = MediaAddress::new("192.168.1.100", 30000);
        session.receive_183_with_sdp("v=0...".to_string(), remote);
        assert_eq!(session.state(), EarlyMediaState::Active);
        assert!(session.is_active());

        // Complete
        session.complete();
        assert_eq!(session.state(), EarlyMediaState::Completed);
    }

    #[test]
    fn test_early_media_handler_signaling_only() {
        let handler = EarlyMediaHandler::new(B2buaMode::SignalingOnly);
        assert_eq!(handler.early_media_mode(), EarlyMediaMode::None);
        assert!(!handler.is_early_media_supported());
    }

    #[test]
    fn test_early_media_handler_media_relay() {
        let handler = EarlyMediaHandler::new(B2buaMode::MediaRelay);
        assert_eq!(handler.early_media_mode(), EarlyMediaMode::Relay);
        assert!(handler.is_early_media_supported());
        assert!(handler.should_forward());
    }

    #[test]
    fn test_early_media_handler_receive_183() {
        let mut handler = EarlyMediaHandler::new(B2buaMode::MediaRelay);

        // Set B-leg offer
        let local = MediaAddress::new("10.0.0.1", 20000);
        handler.set_b_leg_offer("v=0...".to_string(), local);

        // Receive 183 from B-leg
        let remote = MediaAddress::new("192.168.1.100", 30000);
        let action = handler.receive_b_leg_183("v=0...".to_string(), remote);

        assert!(handler.b_leg().is_active());
        assert!(matches!(
            action,
            Some(EarlyMediaAction::ForwardToALeg { .. })
        ));
    }

    #[test]
    fn test_early_media_handler_call_answered() {
        let mut handler = EarlyMediaHandler::new(B2buaMode::MediaRelay);

        // Setup early media
        let local = MediaAddress::new("10.0.0.1", 20000);
        handler.set_b_leg_offer("v=0...".to_string(), local);

        let remote = MediaAddress::new("192.168.1.100", 30000);
        handler.receive_b_leg_183("v=0...".to_string(), remote);

        assert!(handler.has_active_early_media());

        // Call answered
        handler.call_answered();
        assert!(!handler.has_active_early_media());
    }

    #[test]
    fn test_early_media_config() {
        let config = EarlyMediaConfig::new()
            .with_mode(EarlyMediaMode::LocalRingback)
            .with_ringback("/audio/ringback.wav")
            .with_timeout(120);

        assert_eq!(config.mode, EarlyMediaMode::LocalRingback);
        assert_eq!(
            config.ringback_file,
            Some("/audio/ringback.wav".to_string())
        );
        assert_eq!(config.timeout, 120);
    }

    #[test]
    fn test_is_early_media_response() {
        assert!(is_early_media_response(183));
        assert!(is_early_media_response(180));
        assert!(!is_early_media_response(200));
        assert!(!is_early_media_response(100));
    }

    #[test]
    fn test_should_setup_early_media() {
        assert!(should_setup_early_media(183, true));
        assert!(!should_setup_early_media(183, false));
        assert!(!should_setup_early_media(180, true));
    }
}
