//! ICE consent freshness and keepalive per RFC 8445 §9-10.
//!
//! This module implements consent verification and keepalives for
//! maintaining ICE connections after establishment.
//!
//! ## RFC 8445 Compliance
//!
//! - **§9**: Consent Freshness
//! - **§10**: Keepalives
//!
//! ## RFC 7675 Compliance
//!
//! - STUN consent freshness mechanism

use crate::error::IceResult;
use proto_stun::{StunClass, StunMessage, StunMessageType};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Consent freshness interval per RFC 7675 (5 seconds).
const CONSENT_FRESHNESS_INTERVAL: Duration = Duration::from_secs(5);

/// Consent timeout per RFC 7675 (30 seconds).
const CONSENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Keepalive interval per RFC 8445 §10 (15 seconds for STUN).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Error indicating consent has been revoked per RFC 7675 §6.
///
/// When consent expires, the agent MUST immediately cease sending data.
/// This error type represents that condition and should be used to
/// prevent any further media transmission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentRevoked;

/// Maximum time without any traffic before sending keepalive.
const TRAFFIC_TIMEOUT: Duration = Duration::from_secs(15);

/// State of consent freshness.
///
/// Per RFC 7675, consent represents the peer's willingness to receive traffic.
/// When consent expires, the sending agent MUST stop all transmission immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentState {
    /// Consent is fresh (recently verified).
    Fresh,
    /// Consent verification in progress.
    Pending,
    /// Consent has expired (no response within timeout).
    ///
    /// **RFC 7675 §6**: When consent expires, the agent MUST cease
    /// sending media traffic immediately. This is a consent revocation.
    Expired,
}

impl std::fmt::Display for ConsentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fresh => write!(f, "fresh"),
            Self::Pending => write!(f, "pending"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

/// Consent freshness tracker per RFC 7675.
///
/// Tracks the consent state for a single peer and ensures
/// that we have received indication that the peer is still
/// willing to receive traffic.
#[derive(Debug)]
pub struct ConsentTracker {
    /// Last time consent was verified.
    last_consent: Option<Instant>,
    /// Last time we sent a consent check.
    last_check_sent: Option<Instant>,
    /// Current consent state.
    state: ConsentState,
    /// Number of consecutive failed checks.
    failed_checks: u32,
    /// Maximum failed checks before expiration.
    max_failed_checks: u32,
    /// Consent freshness interval.
    consent_interval: Duration,
    /// Consent timeout.
    consent_timeout: Duration,
}

impl ConsentTracker {
    /// Creates a new consent tracker with default settings.
    pub fn new() -> Self {
        Self {
            last_consent: None,
            last_check_sent: None,
            state: ConsentState::Pending,
            failed_checks: 0,
            max_failed_checks: 6, // ~30 seconds at 5s interval
            consent_interval: CONSENT_FRESHNESS_INTERVAL,
            consent_timeout: CONSENT_TIMEOUT,
        }
    }

    /// Creates a consent tracker with custom settings.
    pub fn with_settings(consent_interval: Duration, consent_timeout: Duration) -> Self {
        // Use millis to handle sub-second intervals correctly
        let interval_millis = consent_interval.as_millis().max(1) as u64;
        let timeout_millis = consent_timeout.as_millis() as u64;
        let max_failed_checks = (timeout_millis / interval_millis) as u32;
        Self {
            last_consent: None,
            last_check_sent: None,
            state: ConsentState::Pending,
            failed_checks: 0,
            max_failed_checks: max_failed_checks.max(1),
            consent_interval,
            consent_timeout,
        }
    }

    /// Returns the current consent state.
    pub fn state(&self) -> ConsentState {
        self.state
    }

    /// Returns whether consent is currently valid.
    pub fn is_consented(&self) -> bool {
        self.state == ConsentState::Fresh
    }

    /// Returns whether consent has been revoked and transmission MUST stop.
    ///
    /// Per RFC 7675 §6: "When consent expires, the agent MUST immediately
    /// cease sending data on the ICE candidate pair."
    ///
    /// Callers MUST check this and stop all media transmission when it returns true.
    pub fn is_revoked(&self) -> bool {
        self.state == ConsentState::Expired
    }

    /// Returns whether transmission is allowed.
    ///
    /// Per RFC 7675 §6, this returns false when consent has expired,
    /// indicating that the agent MUST NOT send any media data.
    pub fn can_send(&self) -> bool {
        self.state != ConsentState::Expired
    }

    /// Returns the time since last consent verification.
    pub fn time_since_consent(&self) -> Option<Duration> {
        self.last_consent.map(|t| t.elapsed())
    }

    /// Checks if a consent check should be sent now.
    pub fn should_check(&self) -> bool {
        match self.state {
            ConsentState::Expired => false,
            ConsentState::Fresh | ConsentState::Pending => self
                .last_check_sent
                .is_none_or(|t| t.elapsed() >= self.consent_interval),
        }
    }

    /// Records that a consent check was sent.
    pub fn check_sent(&mut self) {
        self.last_check_sent = Some(Instant::now());
        if self.state == ConsentState::Fresh {
            self.state = ConsentState::Pending;
        }
    }

    /// Records a successful consent response.
    pub fn consent_received(&mut self) {
        self.last_consent = Some(Instant::now());
        self.state = ConsentState::Fresh;
        self.failed_checks = 0;
    }

    /// Records a failed consent check (timeout or error).
    pub fn check_failed(&mut self) {
        self.failed_checks += 1;
        if self.failed_checks >= self.max_failed_checks {
            self.state = ConsentState::Expired;
        }
    }

    /// Updates consent state based on time elapsed.
    ///
    /// Should be called periodically to detect consent expiration.
    pub fn update(&mut self) {
        if self.state == ConsentState::Expired {
            return;
        }

        // Check if consent has expired based on last verification
        if let Some(last) = self.last_consent {
            if last.elapsed() > self.consent_timeout {
                self.state = ConsentState::Expired;
            }
        } else if let Some(first_check) = self.last_check_sent {
            // Never received consent - check if we've timed out
            if first_check.elapsed() > self.consent_timeout {
                self.state = ConsentState::Expired;
            }
        }
    }

    /// Resets the tracker for a new connection or ICE restart.
    pub fn reset(&mut self) {
        self.last_consent = None;
        self.last_check_sent = None;
        self.state = ConsentState::Pending;
        self.failed_checks = 0;
    }
}

impl Default for ConsentTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Keepalive tracker per RFC 8445 §10.
///
/// Tracks when keepalives should be sent to maintain NAT bindings.
#[derive(Debug)]
pub struct KeepaliveTracker {
    /// Last time any traffic was sent.
    last_traffic_sent: Option<Instant>,
    /// Last time any traffic was received.
    last_traffic_received: Option<Instant>,
    /// Keepalive interval.
    keepalive_interval: Duration,
    /// Traffic timeout before sending keepalive.
    traffic_timeout: Duration,
}

impl KeepaliveTracker {
    /// Creates a new keepalive tracker with default settings.
    pub fn new() -> Self {
        Self {
            last_traffic_sent: None,
            last_traffic_received: None,
            keepalive_interval: KEEPALIVE_INTERVAL,
            traffic_timeout: TRAFFIC_TIMEOUT,
        }
    }

    /// Creates a keepalive tracker with custom settings.
    pub fn with_interval(keepalive_interval: Duration) -> Self {
        Self {
            last_traffic_sent: None,
            last_traffic_received: None,
            keepalive_interval,
            traffic_timeout: keepalive_interval,
        }
    }

    /// Records that traffic was sent.
    pub fn traffic_sent(&mut self) {
        self.last_traffic_sent = Some(Instant::now());
    }

    /// Records that traffic was received.
    pub fn traffic_received(&mut self) {
        self.last_traffic_received = Some(Instant::now());
    }

    /// Checks if a keepalive should be sent now.
    ///
    /// Per RFC 8445 §10, keepalives should be sent if no traffic
    /// has been sent within the keepalive interval to maintain NAT bindings.
    pub fn should_keepalive(&self) -> bool {
        let now = Instant::now();

        // Check when we last sent traffic
        let send_stale = self
            .last_traffic_sent
            .is_none_or(|t| now.duration_since(t) >= self.traffic_timeout);

        // Check when we last received traffic (also counts as activity)
        let recv_stale = self
            .last_traffic_received
            .is_none_or(|t| now.duration_since(t) >= self.traffic_timeout);

        // Only need keepalive if both send and receive are stale
        // (if we've sent or received anything recently, NAT binding is fresh)
        send_stale && recv_stale
    }

    /// Returns the time until next keepalive should be sent.
    pub fn time_until_keepalive(&self) -> Duration {
        let now = Instant::now();

        let since_send = self.last_traffic_sent.map_or(self.keepalive_interval, |t| {
            let elapsed = now.duration_since(t);
            self.keepalive_interval.saturating_sub(elapsed)
        });

        let since_recv = self
            .last_traffic_received
            .map_or(self.keepalive_interval, |t| {
                let elapsed = now.duration_since(t);
                self.keepalive_interval.saturating_sub(elapsed)
            });

        since_send.min(since_recv)
    }

    /// Resets the tracker.
    pub fn reset(&mut self) {
        self.last_traffic_sent = None;
        self.last_traffic_received = None;
    }
}

impl Default for KeepaliveTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Keepalive message type per RFC 8445 §10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepaliveType {
    /// STUN Binding Indication (preferred).
    StunIndication,
    /// RTP "no-op" packet (media streams only).
    RtpNoOp,
}

/// Combined consent and keepalive manager.
///
/// Manages both consent freshness verification and keepalives
/// for an established ICE connection.
pub struct ConsentKeepaliveManager {
    /// Consent tracker.
    consent: ConsentTracker,
    /// Keepalive tracker.
    keepalive: KeepaliveTracker,
    /// Remote address for checks.
    remote_addr: SocketAddr,
    /// Transaction ID for current consent check.
    current_transaction: Option<[u8; 12]>,
}

impl ConsentKeepaliveManager {
    /// Creates a new manager for the given remote address.
    pub fn new(remote_addr: SocketAddr) -> Self {
        Self {
            consent: ConsentTracker::new(),
            keepalive: KeepaliveTracker::new(),
            remote_addr,
            current_transaction: None,
        }
    }

    /// Returns the consent state.
    pub fn consent_state(&self) -> ConsentState {
        self.consent.state()
    }

    /// Returns whether consent is valid.
    pub fn is_consented(&self) -> bool {
        self.consent.is_consented()
    }

    /// Returns whether consent has been revoked and transmission MUST stop.
    ///
    /// Per RFC 7675 §6: "When consent expires, the agent MUST immediately
    /// cease sending data on the ICE candidate pair."
    ///
    /// When this returns true:
    /// - MUST stop sending all media (RTP/RTCP)
    /// - SHOULD close the ICE connection
    /// - MAY attempt ICE restart if supported
    pub fn is_revoked(&self) -> bool {
        self.consent.is_revoked()
    }

    /// Returns whether sending media is currently allowed.
    ///
    /// This is the primary check that MUST be called before sending any media.
    /// Returns false when consent has expired per RFC 7675 §6.
    pub fn can_send(&self) -> bool {
        self.consent.can_send()
    }

    /// Checks consent and returns an error if transmission is not allowed.
    ///
    /// Per RFC 7675 §6, returns an error when consent has expired.
    /// Callers should use this to guard media transmission.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn check_consent(&self) -> Result<(), ConsentRevoked> {
        if self.consent.is_revoked() {
            Err(ConsentRevoked)
        } else {
            Ok(())
        }
    }

    /// Records that media traffic was sent.
    pub fn media_sent(&mut self) {
        self.keepalive.traffic_sent();
    }

    /// Records that media traffic was received.
    pub fn media_received(&mut self) {
        self.keepalive.traffic_received();
    }

    /// Updates state and returns the next action to take.
    pub fn tick(&mut self) -> Option<ConsentKeepaliveAction> {
        // Update consent state
        self.consent.update();

        // Check if consent has expired
        if self.consent.state() == ConsentState::Expired {
            return Some(ConsentKeepaliveAction::ConsentExpired);
        }

        // Check if we need to send a consent check
        if self.consent.should_check() {
            return Some(ConsentKeepaliveAction::SendConsentCheck);
        }

        // Check if we need to send a keepalive
        if self.keepalive.should_keepalive() {
            return Some(ConsentKeepaliveAction::SendKeepalive);
        }

        None
    }

    /// Creates a STUN Binding Indication for keepalive.
    ///
    /// Per RFC 8445 §10, a STUN Binding Indication can be used
    /// as a keepalive mechanism.
    pub fn create_keepalive(&mut self) -> StunMessage {
        let mut transaction_id = [0u8; 12];
        if uc_crypto::random::fill_random(&mut transaction_id).is_err() {
            // Fallback
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            transaction_id[..8].copy_from_slice(&now.to_be_bytes());
        }

        self.keepalive.traffic_sent();

        StunMessage::new(
            StunMessageType::new(proto_stun::StunMethod::Binding, StunClass::Indication),
            transaction_id,
        )
    }

    /// Creates a STUN Binding Request for consent check.
    pub fn create_consent_check(&mut self) -> StunMessage {
        let mut transaction_id = [0u8; 12];
        if uc_crypto::random::fill_random(&mut transaction_id).is_err() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            transaction_id[..8].copy_from_slice(&now.to_be_bytes());
        }

        self.current_transaction = Some(transaction_id);
        self.consent.check_sent();

        StunMessage::new(StunMessageType::binding_request(), transaction_id)
    }

    /// Processes a STUN response (consent check response or keepalive response).
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn process_response(&mut self, response: &StunMessage) -> IceResult<()> {
        // Check if this is a response to our consent check
        if let Some(expected_tid) = self.current_transaction
            && response.transaction_id == expected_tid
        {
            if response.msg_type.class == StunClass::SuccessResponse {
                self.consent.consent_received();
                self.keepalive.traffic_received();
                self.current_transaction = None;
                return Ok(());
            } else if response.msg_type.class == StunClass::ErrorResponse {
                self.consent.check_failed();
                self.current_transaction = None;
            }
        }

        // Any valid STUN traffic counts as received traffic for keepalive
        self.keepalive.traffic_received();

        Ok(())
    }

    /// Handles consent check timeout.
    pub fn consent_check_timeout(&mut self) {
        self.consent.check_failed();
        self.current_transaction = None;
    }

    /// Resets for ICE restart.
    pub fn reset(&mut self) {
        self.consent.reset();
        self.keepalive.reset();
        self.current_transaction = None;
    }
}

impl std::fmt::Debug for ConsentKeepaliveManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsentKeepaliveManager")
            .field("remote_addr", &self.remote_addr)
            .field("consent_state", &self.consent.state())
            .field("has_pending_check", &self.current_transaction.is_some())
            .finish_non_exhaustive()
    }
}

/// Action to take from consent/keepalive manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentKeepaliveAction {
    /// Send a consent check (STUN Binding Request).
    SendConsentCheck,
    /// Send a keepalive (STUN Binding Indication).
    SendKeepalive,
    /// Consent has expired - close the connection.
    ConsentExpired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consent_tracker_initial_state() {
        let tracker = ConsentTracker::new();
        assert_eq!(tracker.state(), ConsentState::Pending);
        assert!(!tracker.is_consented());
    }

    #[test]
    fn test_consent_tracker_consent_received() {
        let mut tracker = ConsentTracker::new();

        tracker.check_sent();
        assert!(tracker.state() == ConsentState::Pending);

        tracker.consent_received();
        assert_eq!(tracker.state(), ConsentState::Fresh);
        assert!(tracker.is_consented());
    }

    #[test]
    fn test_consent_tracker_check_failure() {
        let mut tracker =
            ConsentTracker::with_settings(Duration::from_millis(100), Duration::from_millis(300));

        // Fail enough checks to expire
        for _ in 0..tracker.max_failed_checks {
            tracker.check_sent();
            tracker.check_failed();
        }

        assert_eq!(tracker.state(), ConsentState::Expired);
    }

    #[test]
    fn test_consent_tracker_reset() {
        let mut tracker = ConsentTracker::new();
        tracker.consent_received();
        assert!(tracker.is_consented());

        tracker.reset();
        assert_eq!(tracker.state(), ConsentState::Pending);
        assert!(!tracker.is_consented());
    }

    #[test]
    fn test_keepalive_tracker_initial() {
        let tracker = KeepaliveTracker::new();
        assert!(tracker.should_keepalive());
    }

    #[test]
    fn test_keepalive_tracker_traffic_sent() {
        let mut tracker = KeepaliveTracker::with_interval(Duration::from_secs(1));
        tracker.traffic_sent();

        // Should not need keepalive immediately after traffic
        assert!(!tracker.should_keepalive());
    }

    #[test]
    fn test_keepalive_tracker_traffic_received() {
        let mut tracker = KeepaliveTracker::with_interval(Duration::from_secs(1));
        tracker.traffic_received();

        // Should not need keepalive immediately after receiving traffic
        assert!(!tracker.should_keepalive());
    }

    #[test]
    fn test_consent_keepalive_manager_creation() {
        let addr = "192.168.1.1:5060".parse().unwrap();
        let manager = ConsentKeepaliveManager::new(addr);

        assert_eq!(manager.consent_state(), ConsentState::Pending);
        assert!(!manager.is_consented());
    }

    #[test]
    fn test_consent_keepalive_manager_tick_initial() {
        let addr = "192.168.1.1:5060".parse().unwrap();
        let mut manager = ConsentKeepaliveManager::new(addr);

        // Initial tick should request consent check
        let action = manager.tick();
        assert_eq!(action, Some(ConsentKeepaliveAction::SendConsentCheck));
    }

    #[test]
    fn test_consent_keepalive_manager_consent_flow() {
        let addr = "192.168.1.1:5060".parse().unwrap();
        let mut manager = ConsentKeepaliveManager::new(addr);

        // Create and "send" consent check
        let request = manager.create_consent_check();

        // Simulate success response
        let response =
            StunMessage::new(StunMessageType::binding_response(), request.transaction_id);
        manager.process_response(&response).unwrap();

        assert!(manager.is_consented());
        assert_eq!(manager.consent_state(), ConsentState::Fresh);
    }

    #[test]
    fn test_consent_keepalive_manager_keepalive() {
        let addr = "192.168.1.1:5060".parse().unwrap();
        let mut manager = ConsentKeepaliveManager::new(addr);

        let keepalive = manager.create_keepalive();
        assert_eq!(keepalive.msg_type.class, StunClass::Indication);
    }
}
