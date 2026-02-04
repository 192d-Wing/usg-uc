//! SCTP association state machine (RFC 9260 Section 4).
//!
//! This module implements the SCTP association state machine that governs
//! the lifecycle of an SCTP association.

use std::fmt;

// =============================================================================
// Association State
// =============================================================================

/// SCTP Association States (RFC 9260 Section 4).
///
/// ```text
///                              +---------+
///                              |  CLOSED |
///                              +---------+
///                               /       \
///                   INIT sent /         \ INIT received
///                            /           \
///                           v             v
///                    +-----------+   +-----------+
///                    |COOKIE-WAIT|   |  (Note 1) |
///                    +-----------+   +-----------+
///                          |
///               INIT-ACK received
///                          |
///                          v
///                    +-----------+
///                    |COOKIE-    |
///                    |ECHOED     |
///                    +-----------+
///                          |
///               COOKIE-ACK received
///                          |
///                          v
///                    +-----------+
///                    |ESTABLISHED|
///                    +-----------+
///                     /         \
///        SHUTDOWN   /           \  SHUTDOWN
///        sent      /             \ received
///                 v               v
///         +-----------+     +-----------+
///         |SHUTDOWN-  |     |SHUTDOWN-  |
///         |PENDING    |     |RECEIVED   |
///         +-----------+     +-----------+
///               |                 |
///    SHUTDOWN   |                 | SHUTDOWN-ACK
///    sent       |                 | sent
///               v                 v
///         +-----------+     +-----------+
///         |SHUTDOWN-  |     |SHUTDOWN-  |
///         |SENT       |     |ACK-SENT   |
///         +-----------+     +-----------+
///               \                 /
///                \               /
///      SHUTDOWN-  \             / SHUTDOWN-
///      ACK         \           /  COMPLETE
///      received     \         /   received
///                    v       v
///                   +---------+
///                   | CLOSED  |
///                   +---------+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssociationState {
    /// No association exists. This is the initial state.
    Closed,
    /// INIT has been sent, waiting for INIT-ACK.
    CookieWait,
    /// COOKIE-ECHO has been sent, waiting for COOKIE-ACK.
    CookieEchoed,
    /// Association is established and operational.
    Established,
    /// Application has requested shutdown, but outgoing data remains.
    ShutdownPending,
    /// SHUTDOWN has been sent, waiting for all data to be acknowledged.
    ShutdownSent,
    /// SHUTDOWN has been received, waiting for application shutdown.
    ShutdownReceived,
    /// SHUTDOWN-ACK has been sent, waiting for SHUTDOWN-COMPLETE.
    ShutdownAckSent,
}

impl AssociationState {
    /// Returns true if the association is in a connected state.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        matches!(
            self,
            Self::Established | Self::ShutdownPending | Self::ShutdownReceived
        )
    }

    /// Returns true if the association is in a shutdown state.
    #[must_use]
    pub const fn is_shutting_down(&self) -> bool {
        matches!(
            self,
            Self::ShutdownPending
                | Self::ShutdownSent
                | Self::ShutdownReceived
                | Self::ShutdownAckSent
        )
    }

    /// Returns true if the association can send data.
    #[must_use]
    pub const fn can_send_data(&self) -> bool {
        matches!(self, Self::Established | Self::ShutdownReceived)
    }

    /// Returns true if the association can receive data.
    #[must_use]
    pub const fn can_receive_data(&self) -> bool {
        matches!(
            self,
            Self::Established | Self::ShutdownPending | Self::ShutdownSent
        )
    }

    /// Returns true if the association is in a handshake state.
    #[must_use]
    pub const fn is_handshaking(&self) -> bool {
        matches!(self, Self::CookieWait | Self::CookieEchoed)
    }
}

impl fmt::Display for AssociationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(f, "CLOSED"),
            Self::CookieWait => write!(f, "COOKIE-WAIT"),
            Self::CookieEchoed => write!(f, "COOKIE-ECHOED"),
            Self::Established => write!(f, "ESTABLISHED"),
            Self::ShutdownPending => write!(f, "SHUTDOWN-PENDING"),
            Self::ShutdownSent => write!(f, "SHUTDOWN-SENT"),
            Self::ShutdownReceived => write!(f, "SHUTDOWN-RECEIVED"),
            Self::ShutdownAckSent => write!(f, "SHUTDOWN-ACK-SENT"),
        }
    }
}

impl Default for AssociationState {
    fn default() -> Self {
        Self::Closed
    }
}

// =============================================================================
// State Events
// =============================================================================

/// Events that trigger state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateEvent {
    // Application events
    /// Application initiates association (sends INIT).
    Associate,
    /// Application requests graceful shutdown.
    Shutdown,
    /// Application requests immediate abort.
    Abort,

    // Received chunks
    /// Received INIT chunk.
    ReceiveInit,
    /// Received INIT-ACK chunk.
    ReceiveInitAck,
    /// Received COOKIE-ECHO chunk.
    ReceiveCookieEcho,
    /// Received COOKIE-ACK chunk.
    ReceiveCookieAck,
    /// Received SHUTDOWN chunk.
    ReceiveShutdown,
    /// Received SHUTDOWN-ACK chunk.
    ReceiveShutdownAck,
    /// Received SHUTDOWN-COMPLETE chunk.
    ReceiveShutdownComplete,
    /// Received ABORT chunk.
    ReceiveAbort,

    // Timer events
    /// T1-init timer expired (INIT retransmission).
    T1InitExpired,
    /// T1-cookie timer expired (COOKIE-ECHO retransmission).
    T1CookieExpired,
    /// T2-shutdown timer expired (SHUTDOWN retransmission).
    T2ShutdownExpired,

    // Internal events
    /// All outgoing data has been acknowledged.
    AllDataAcked,
    /// Maximum retransmissions reached.
    MaxRetransmissions,
}

impl fmt::Display for StateEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Associate => write!(f, "ASSOCIATE"),
            Self::Shutdown => write!(f, "SHUTDOWN"),
            Self::Abort => write!(f, "ABORT"),
            Self::ReceiveInit => write!(f, "RECV(INIT)"),
            Self::ReceiveInitAck => write!(f, "RECV(INIT-ACK)"),
            Self::ReceiveCookieEcho => write!(f, "RECV(COOKIE-ECHO)"),
            Self::ReceiveCookieAck => write!(f, "RECV(COOKIE-ACK)"),
            Self::ReceiveShutdown => write!(f, "RECV(SHUTDOWN)"),
            Self::ReceiveShutdownAck => write!(f, "RECV(SHUTDOWN-ACK)"),
            Self::ReceiveShutdownComplete => write!(f, "RECV(SHUTDOWN-COMPLETE)"),
            Self::ReceiveAbort => write!(f, "RECV(ABORT)"),
            Self::T1InitExpired => write!(f, "T1-INIT-EXPIRED"),
            Self::T1CookieExpired => write!(f, "T1-COOKIE-EXPIRED"),
            Self::T2ShutdownExpired => write!(f, "T2-SHUTDOWN-EXPIRED"),
            Self::AllDataAcked => write!(f, "ALL-DATA-ACKED"),
            Self::MaxRetransmissions => write!(f, "MAX-RETRANSMISSIONS"),
        }
    }
}

// =============================================================================
// State Actions
// =============================================================================

/// Actions to be taken as a result of state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateAction {
    /// No action required.
    None,
    /// Send INIT chunk.
    SendInit,
    /// Send INIT-ACK chunk with state cookie.
    SendInitAck,
    /// Send COOKIE-ECHO chunk.
    SendCookieEcho,
    /// Send COOKIE-ACK chunk.
    SendCookieAck,
    /// Send SHUTDOWN chunk.
    SendShutdown,
    /// Send SHUTDOWN-ACK chunk.
    SendShutdownAck,
    /// Send SHUTDOWN-COMPLETE chunk.
    SendShutdownComplete,
    /// Send ABORT chunk.
    SendAbort,
    /// Start T1-init timer.
    StartT1Init,
    /// Start T1-cookie timer.
    StartT1Cookie,
    /// Start T2-shutdown timer.
    StartT2Shutdown,
    /// Stop T1-init timer.
    StopT1Init,
    /// Stop T1-cookie timer.
    StopT1Cookie,
    /// Stop T2-shutdown timer.
    StopT2Shutdown,
    /// Delete the TCB (Transmission Control Block).
    DeleteTcb,
    /// Notify application of connection established.
    NotifyConnected,
    /// Notify application of connection terminated.
    NotifyDisconnected,
    /// Notify application of error.
    NotifyError,
}

// =============================================================================
// State Machine
// =============================================================================

/// SCTP association state machine.
#[derive(Debug, Clone)]
pub struct StateMachine {
    /// Current state.
    state: AssociationState,
    /// Number of INIT retransmissions.
    init_retries: u32,
    /// Number of COOKIE-ECHO retransmissions.
    cookie_retries: u32,
    /// Number of SHUTDOWN retransmissions.
    shutdown_retries: u32,
    /// Maximum retransmissions for INIT.
    max_init_retries: u32,
    /// Maximum retransmissions for association setup.
    max_assoc_retries: u32,
    /// Maximum retransmissions for shutdown.
    max_shutdown_retries: u32,
}

impl StateMachine {
    /// Default maximum INIT retransmissions (RFC 9260).
    pub const DEFAULT_MAX_INIT_RETRIES: u32 = 8;
    /// Default maximum association retransmissions (RFC 9260).
    pub const DEFAULT_MAX_ASSOC_RETRIES: u32 = 10;
    /// Default maximum shutdown retransmissions.
    pub const DEFAULT_MAX_SHUTDOWN_RETRIES: u32 = 5;

    /// Creates a new state machine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: AssociationState::Closed,
            init_retries: 0,
            cookie_retries: 0,
            shutdown_retries: 0,
            max_init_retries: Self::DEFAULT_MAX_INIT_RETRIES,
            max_assoc_retries: Self::DEFAULT_MAX_ASSOC_RETRIES,
            max_shutdown_retries: Self::DEFAULT_MAX_SHUTDOWN_RETRIES,
        }
    }

    /// Returns the current state.
    #[must_use]
    pub const fn state(&self) -> AssociationState {
        self.state
    }

    /// Processes an event and returns the resulting actions.
    ///
    /// This method implements the state transition logic from RFC 9260 Section 4.
    pub fn process_event(&mut self, event: StateEvent) -> Vec<StateAction> {
        let mut actions = Vec::new();

        match (self.state, event) {
            // CLOSED state transitions
            (AssociationState::Closed, StateEvent::Associate) => {
                self.state = AssociationState::CookieWait;
                self.init_retries = 0;
                actions.push(StateAction::SendInit);
                actions.push(StateAction::StartT1Init);
            }
            (AssociationState::Closed, StateEvent::ReceiveInit) => {
                // Respond with INIT-ACK (stay in CLOSED for server)
                actions.push(StateAction::SendInitAck);
            }
            (AssociationState::Closed, StateEvent::ReceiveCookieEcho) => {
                // Validate cookie and transition to ESTABLISHED
                self.state = AssociationState::Established;
                actions.push(StateAction::SendCookieAck);
                actions.push(StateAction::NotifyConnected);
            }

            // COOKIE-WAIT state transitions
            (AssociationState::CookieWait, StateEvent::ReceiveInitAck) => {
                self.state = AssociationState::CookieEchoed;
                self.cookie_retries = 0;
                actions.push(StateAction::StopT1Init);
                actions.push(StateAction::SendCookieEcho);
                actions.push(StateAction::StartT1Cookie);
            }
            (AssociationState::CookieWait, StateEvent::T1InitExpired) => {
                self.init_retries += 1;
                if self.init_retries > self.max_init_retries {
                    self.state = AssociationState::Closed;
                    actions.push(StateAction::DeleteTcb);
                    actions.push(StateAction::NotifyError);
                } else {
                    actions.push(StateAction::SendInit);
                    actions.push(StateAction::StartT1Init);
                }
            }
            (AssociationState::CookieWait, StateEvent::ReceiveAbort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::StopT1Init);
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyError);
            }
            (AssociationState::CookieWait, StateEvent::Abort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::StopT1Init);
                actions.push(StateAction::DeleteTcb);
            }

            // COOKIE-ECHOED state transitions
            (AssociationState::CookieEchoed, StateEvent::ReceiveCookieAck) => {
                self.state = AssociationState::Established;
                actions.push(StateAction::StopT1Cookie);
                actions.push(StateAction::NotifyConnected);
            }
            (AssociationState::CookieEchoed, StateEvent::T1CookieExpired) => {
                self.cookie_retries += 1;
                let total_retries = self.init_retries + self.cookie_retries;
                if total_retries > self.max_assoc_retries {
                    self.state = AssociationState::Closed;
                    actions.push(StateAction::DeleteTcb);
                    actions.push(StateAction::NotifyError);
                } else {
                    actions.push(StateAction::SendCookieEcho);
                    actions.push(StateAction::StartT1Cookie);
                }
            }
            (AssociationState::CookieEchoed, StateEvent::ReceiveAbort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::StopT1Cookie);
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyError);
            }
            (AssociationState::CookieEchoed, StateEvent::Abort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::StopT1Cookie);
                actions.push(StateAction::SendAbort);
                actions.push(StateAction::DeleteTcb);
            }
            // Handle receiving INIT while in COOKIE-ECHOED (peer restart)
            (AssociationState::CookieEchoed, StateEvent::ReceiveInit) => {
                // This could indicate peer restart - respond with INIT-ACK
                actions.push(StateAction::SendInitAck);
            }

            // ESTABLISHED state transitions
            (AssociationState::Established, StateEvent::Shutdown) => {
                self.state = AssociationState::ShutdownPending;
                // Will transition to ShutdownSent once all data is acked
            }
            (AssociationState::Established, StateEvent::ReceiveShutdown) => {
                self.state = AssociationState::ShutdownReceived;
                // Wait for application to complete
            }
            (AssociationState::Established, StateEvent::Abort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::SendAbort);
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyDisconnected);
            }
            (AssociationState::Established, StateEvent::ReceiveAbort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyDisconnected);
            }

            // SHUTDOWN-PENDING state transitions
            (AssociationState::ShutdownPending, StateEvent::AllDataAcked) => {
                self.state = AssociationState::ShutdownSent;
                self.shutdown_retries = 0;
                actions.push(StateAction::SendShutdown);
                actions.push(StateAction::StartT2Shutdown);
            }
            (AssociationState::ShutdownPending, StateEvent::ReceiveShutdown) => {
                self.state = AssociationState::ShutdownReceived;
                // Stop sending data, transition to shutdown completion
            }
            (AssociationState::ShutdownPending, StateEvent::Abort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::SendAbort);
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyDisconnected);
            }
            (AssociationState::ShutdownPending, StateEvent::ReceiveAbort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyDisconnected);
            }

            // SHUTDOWN-SENT state transitions
            (AssociationState::ShutdownSent, StateEvent::ReceiveShutdownAck) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::StopT2Shutdown);
                actions.push(StateAction::SendShutdownComplete);
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyDisconnected);
            }
            (AssociationState::ShutdownSent, StateEvent::T2ShutdownExpired) => {
                self.shutdown_retries += 1;
                if self.shutdown_retries > self.max_shutdown_retries {
                    self.state = AssociationState::Closed;
                    actions.push(StateAction::SendAbort);
                    actions.push(StateAction::DeleteTcb);
                    actions.push(StateAction::NotifyError);
                } else {
                    actions.push(StateAction::SendShutdown);
                    actions.push(StateAction::StartT2Shutdown);
                }
            }
            (AssociationState::ShutdownSent, StateEvent::ReceiveShutdown) => {
                // Simultaneous shutdown
                self.state = AssociationState::ShutdownAckSent;
                actions.push(StateAction::StopT2Shutdown);
                actions.push(StateAction::SendShutdownAck);
                actions.push(StateAction::StartT2Shutdown);
            }
            (AssociationState::ShutdownSent, StateEvent::Abort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::StopT2Shutdown);
                actions.push(StateAction::SendAbort);
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyDisconnected);
            }
            (AssociationState::ShutdownSent, StateEvent::ReceiveAbort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::StopT2Shutdown);
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyDisconnected);
            }

            // SHUTDOWN-RECEIVED state transitions
            (AssociationState::ShutdownReceived, StateEvent::AllDataAcked) => {
                self.state = AssociationState::ShutdownAckSent;
                self.shutdown_retries = 0;
                actions.push(StateAction::SendShutdownAck);
                actions.push(StateAction::StartT2Shutdown);
            }
            (AssociationState::ShutdownReceived, StateEvent::Abort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::SendAbort);
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyDisconnected);
            }
            (AssociationState::ShutdownReceived, StateEvent::ReceiveAbort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyDisconnected);
            }

            // SHUTDOWN-ACK-SENT state transitions
            (AssociationState::ShutdownAckSent, StateEvent::ReceiveShutdownComplete) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::StopT2Shutdown);
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyDisconnected);
            }
            (AssociationState::ShutdownAckSent, StateEvent::T2ShutdownExpired) => {
                self.shutdown_retries += 1;
                if self.shutdown_retries > self.max_shutdown_retries {
                    self.state = AssociationState::Closed;
                    actions.push(StateAction::DeleteTcb);
                    actions.push(StateAction::NotifyError);
                } else {
                    actions.push(StateAction::SendShutdownAck);
                    actions.push(StateAction::StartT2Shutdown);
                }
            }
            (AssociationState::ShutdownAckSent, StateEvent::Abort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::StopT2Shutdown);
                actions.push(StateAction::SendAbort);
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyDisconnected);
            }
            (AssociationState::ShutdownAckSent, StateEvent::ReceiveAbort) => {
                self.state = AssociationState::Closed;
                actions.push(StateAction::StopT2Shutdown);
                actions.push(StateAction::DeleteTcb);
                actions.push(StateAction::NotifyDisconnected);
            }

            // Ignore events that don't cause transitions
            _ => {
                tracing::trace!(
                    state = %self.state,
                    event = %event,
                    "Ignoring event in current state"
                );
            }
        }

        actions
    }

    /// Resets the state machine to initial state.
    pub fn reset(&mut self) {
        self.state = AssociationState::Closed;
        self.init_retries = 0;
        self.cookie_retries = 0;
        self.shutdown_retries = 0;
    }
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_display() {
        assert_eq!(AssociationState::Closed.to_string(), "CLOSED");
        assert_eq!(AssociationState::Established.to_string(), "ESTABLISHED");
        assert_eq!(
            AssociationState::ShutdownPending.to_string(),
            "SHUTDOWN-PENDING"
        );
    }

    #[test]
    fn test_state_properties() {
        assert!(AssociationState::Established.is_connected());
        assert!(!AssociationState::Closed.is_connected());
        assert!(AssociationState::ShutdownPending.is_shutting_down());
        assert!(!AssociationState::Established.is_shutting_down());
        assert!(AssociationState::CookieWait.is_handshaking());
        assert!(!AssociationState::Established.is_handshaking());
    }

    #[test]
    fn test_client_handshake() {
        let mut sm = StateMachine::new();
        assert_eq!(sm.state(), AssociationState::Closed);

        // Client initiates
        let actions = sm.process_event(StateEvent::Associate);
        assert_eq!(sm.state(), AssociationState::CookieWait);
        assert!(actions.contains(&StateAction::SendInit));
        assert!(actions.contains(&StateAction::StartT1Init));

        // Receives INIT-ACK
        let actions = sm.process_event(StateEvent::ReceiveInitAck);
        assert_eq!(sm.state(), AssociationState::CookieEchoed);
        assert!(actions.contains(&StateAction::StopT1Init));
        assert!(actions.contains(&StateAction::SendCookieEcho));
        assert!(actions.contains(&StateAction::StartT1Cookie));

        // Receives COOKIE-ACK
        let actions = sm.process_event(StateEvent::ReceiveCookieAck);
        assert_eq!(sm.state(), AssociationState::Established);
        assert!(actions.contains(&StateAction::StopT1Cookie));
        assert!(actions.contains(&StateAction::NotifyConnected));
    }

    #[test]
    fn test_server_handshake() {
        let mut sm = StateMachine::new();

        // Server receives INIT (stays in CLOSED)
        let actions = sm.process_event(StateEvent::ReceiveInit);
        assert_eq!(sm.state(), AssociationState::Closed);
        assert!(actions.contains(&StateAction::SendInitAck));

        // Server receives COOKIE-ECHO
        let actions = sm.process_event(StateEvent::ReceiveCookieEcho);
        assert_eq!(sm.state(), AssociationState::Established);
        assert!(actions.contains(&StateAction::SendCookieAck));
        assert!(actions.contains(&StateAction::NotifyConnected));
    }

    #[test]
    fn test_graceful_shutdown() {
        let mut sm = StateMachine::new();

        // Get to ESTABLISHED
        sm.process_event(StateEvent::Associate);
        sm.process_event(StateEvent::ReceiveInitAck);
        sm.process_event(StateEvent::ReceiveCookieAck);
        assert_eq!(sm.state(), AssociationState::Established);

        // Application requests shutdown
        let _actions = sm.process_event(StateEvent::Shutdown);
        assert_eq!(sm.state(), AssociationState::ShutdownPending);

        // All data acknowledged
        let actions = sm.process_event(StateEvent::AllDataAcked);
        assert_eq!(sm.state(), AssociationState::ShutdownSent);
        assert!(actions.contains(&StateAction::SendShutdown));

        // Receive SHUTDOWN-ACK
        let actions = sm.process_event(StateEvent::ReceiveShutdownAck);
        assert_eq!(sm.state(), AssociationState::Closed);
        assert!(actions.contains(&StateAction::SendShutdownComplete));
        assert!(actions.contains(&StateAction::NotifyDisconnected));
    }

    #[test]
    fn test_abort() {
        let mut sm = StateMachine::new();

        // Get to ESTABLISHED
        sm.process_event(StateEvent::Associate);
        sm.process_event(StateEvent::ReceiveInitAck);
        sm.process_event(StateEvent::ReceiveCookieAck);

        // Abort
        let actions = sm.process_event(StateEvent::Abort);
        assert_eq!(sm.state(), AssociationState::Closed);
        assert!(actions.contains(&StateAction::SendAbort));
        assert!(actions.contains(&StateAction::DeleteTcb));
        assert!(actions.contains(&StateAction::NotifyDisconnected));
    }

    #[test]
    fn test_init_timeout_max_retries() {
        let mut sm = StateMachine::new();

        sm.process_event(StateEvent::Associate);
        assert_eq!(sm.state(), AssociationState::CookieWait);

        // Exhaust retries
        for _ in 0..=StateMachine::DEFAULT_MAX_INIT_RETRIES {
            sm.process_event(StateEvent::T1InitExpired);
        }

        assert_eq!(sm.state(), AssociationState::Closed);
    }

    #[test]
    fn test_receive_abort_clears_state() {
        let mut sm = StateMachine::new();

        // Get to COOKIE-WAIT
        sm.process_event(StateEvent::Associate);

        // Receive ABORT
        let actions = sm.process_event(StateEvent::ReceiveAbort);
        assert_eq!(sm.state(), AssociationState::Closed);
        assert!(actions.contains(&StateAction::StopT1Init));
        assert!(actions.contains(&StateAction::DeleteTcb));
        assert!(actions.contains(&StateAction::NotifyError));
    }

    #[test]
    fn test_reset() {
        let mut sm = StateMachine::new();

        sm.process_event(StateEvent::Associate);
        sm.process_event(StateEvent::ReceiveInitAck);
        assert_ne!(sm.state(), AssociationState::Closed);

        sm.reset();
        assert_eq!(sm.state(), AssociationState::Closed);
    }
}
