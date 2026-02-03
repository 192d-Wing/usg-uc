//! Server transaction state machines.
//!
//! Per RFC 3261 Section 17.2.

use crate::error::{TransactionError, TransactionResult};
use crate::timer::{TimerConfig, TimerType, next_retransmit_interval};
use crate::{TransactionKey, TransportType};
use std::time::{Duration, Instant};

/// Server INVITE transaction state (RFC 3261 Section 17.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerInviteState {
    /// Initial state, received INVITE.
    Proceeding,
    /// Sent final response, waiting for ACK.
    Completed,
    /// Received ACK, absorbing retransmits.
    Confirmed,
    /// Transaction terminated.
    Terminated,
}

impl std::fmt::Display for ServerInviteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Proceeding => write!(f, "Proceeding"),
            Self::Completed => write!(f, "Completed"),
            Self::Confirmed => write!(f, "Confirmed"),
            Self::Terminated => write!(f, "Terminated"),
        }
    }
}

/// Server INVITE transaction (RFC 3261 Section 17.2.1).
#[derive(Debug)]
pub struct ServerInviteTransaction {
    /// Transaction key.
    key: TransactionKey,
    /// Current state.
    state: ServerInviteState,
    /// Transport type.
    transport: TransportType,
    /// Timer configuration.
    timer_config: TimerConfig,
    /// Current Timer G value (response retransmit).
    timer_g_value: Duration,
    /// When Timer G fires next.
    timer_g_deadline: Option<Instant>,
    /// When Timer H fires (wait for ACK).
    timer_h_deadline: Option<Instant>,
    /// When Timer I fires (absorb ACK retransmits).
    timer_i_deadline: Option<Instant>,
    /// Last response status code sent.
    last_response_code: Option<u16>,
    /// Retransmission count.
    retransmit_count: u32,
}

impl ServerInviteTransaction {
    /// Creates a new server INVITE transaction.
    pub fn new(key: TransactionKey, transport: TransportType) -> Self {
        Self {
            key,
            state: ServerInviteState::Proceeding,
            transport,
            timer_config: TimerConfig::default(),
            timer_g_value: Duration::ZERO,
            timer_g_deadline: None,
            timer_h_deadline: None,
            timer_i_deadline: None,
            last_response_code: None,
            retransmit_count: 0,
        }
    }

    /// Returns the transaction key.
    pub fn key(&self) -> &TransactionKey {
        &self.key
    }

    /// Returns the current state.
    pub fn state(&self) -> ServerInviteState {
        self.state
    }

    /// Returns the last response code sent.
    pub fn last_response_code(&self) -> Option<u16> {
        self.last_response_code
    }

    /// Sends a response.
    ///
    /// The transaction layer calls this when the TU wants to send a response.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn send_response(&mut self, status_code: u16) -> TransactionResult<()> {
        self.last_response_code = Some(status_code);

        match self.state {
            ServerInviteState::Proceeding => {
                if (100..200).contains(&status_code) {
                    // 1xx - stay in Proceeding
                    Ok(())
                } else if (200..300).contains(&status_code) {
                    // RFC 3261 Section 17.2.1: 2xx responses are NOT handled by the
                    // server INVITE transaction. The TU (Transaction User) is responsible
                    // for retransmitting 2xx responses and receiving the ACK directly.
                    // The transaction terminates immediately and the dialog layer takes over.
                    self.state = ServerInviteState::Terminated;
                    Ok(())
                } else if (300..700).contains(&status_code) {
                    // 3xx-6xx - enter Completed
                    self.enter_completed();
                    Ok(())
                } else {
                    Err(TransactionError::InvalidResponse {
                        reason: format!("invalid status code: {status_code}"),
                    })
                }
            }
            ServerInviteState::Completed => {
                // Response retransmission (triggered by Timer G or request retransmit)
                Ok(())
            }
            _ => Err(TransactionError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "sending response".to_string(),
            }),
        }
    }

    /// Receives a request retransmission.
    ///
    /// Returns true if a response should be retransmitted.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn receive_request(&mut self) -> TransactionResult<bool> {
        match self.state {
            ServerInviteState::Proceeding => {
                // Retransmit last provisional if any
                Ok(self.last_response_code.is_some())
            }
            ServerInviteState::Completed => {
                // Retransmit final response
                self.retransmit_count += 1;
                Ok(true)
            }
            ServerInviteState::Confirmed => {
                // Absorb retransmit
                Ok(false)
            }
            ServerInviteState::Terminated => Ok(false),
        }
    }

    /// Receives an ACK.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn receive_ack(&mut self) -> TransactionResult<()> {
        match self.state {
            ServerInviteState::Completed => {
                self.enter_confirmed();
                Ok(())
            }
            ServerInviteState::Confirmed => {
                // Absorb ACK retransmit
                Ok(())
            }
            _ => Err(TransactionError::InvalidStateTransition {
                from: self.state.to_string(),
                to: "receiving ACK".to_string(),
            }),
        }
    }

    /// Processes timer expirations.
    pub fn check_timers(&mut self) -> Option<TimerType> {
        let now = Instant::now();

        match self.state {
            ServerInviteState::Completed => {
                // Check Timer H first (ACK wait timeout)
                if let Some(deadline) = self.timer_h_deadline
                    && now >= deadline
                {
                    self.state = ServerInviteState::Terminated;
                    return Some(TimerType::TimerH);
                }

                // Check Timer G (response retransmit)
                if let Some(deadline) = self.timer_g_deadline
                    && now >= deadline
                {
                    self.retransmit_count += 1;
                    self.timer_g_value =
                        next_retransmit_interval(self.timer_g_value, self.timer_config.t2);
                    self.timer_g_deadline = Some(now + self.timer_g_value);
                    return Some(TimerType::TimerG);
                }
            }
            ServerInviteState::Confirmed => {
                // Check Timer I
                if let Some(deadline) = self.timer_i_deadline
                    && now >= deadline
                {
                    self.state = ServerInviteState::Terminated;
                    return Some(TimerType::TimerI);
                }
            }
            _ => {}
        }

        None
    }

    /// Enters the Completed state.
    fn enter_completed(&mut self) {
        self.state = ServerInviteState::Completed;

        let now = Instant::now();

        // Start Timer H
        self.timer_h_deadline = Some(now + self.timer_config.timer_h());

        // Start Timer G for unreliable transport
        if self.transport == TransportType::Unreliable {
            self.timer_g_value = self.timer_config.timer_g();
            self.timer_g_deadline = Some(now + self.timer_g_value);
        }
    }

    /// Enters the Confirmed state.
    fn enter_confirmed(&mut self) {
        self.state = ServerInviteState::Confirmed;
        self.timer_g_deadline = None;
        self.timer_h_deadline = None;

        // Start Timer I
        let timer_i = if self.transport == TransportType::Unreliable {
            self.timer_config.timer_i_unreliable()
        } else {
            self.timer_config.timer_i_reliable()
        };

        if timer_i > Duration::ZERO {
            self.timer_i_deadline = Some(Instant::now() + timer_i);
        } else {
            self.state = ServerInviteState::Terminated;
        }
    }

    /// Returns whether the transaction is terminated.
    pub fn is_terminated(&self) -> bool {
        self.state == ServerInviteState::Terminated
    }
}

/// Server non-INVITE transaction state (RFC 3261 Section 17.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerNonInviteState {
    /// Trying to process request.
    Trying,
    /// Sent provisional response.
    Proceeding,
    /// Sent final response.
    Completed,
    /// Transaction terminated.
    Terminated,
}

impl std::fmt::Display for ServerNonInviteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trying => write!(f, "Trying"),
            Self::Proceeding => write!(f, "Proceeding"),
            Self::Completed => write!(f, "Completed"),
            Self::Terminated => write!(f, "Terminated"),
        }
    }
}

/// Server non-INVITE transaction (RFC 3261 Section 17.2.2).
#[derive(Debug)]
pub struct ServerNonInviteTransaction {
    /// Transaction key.
    key: TransactionKey,
    /// Current state.
    state: ServerNonInviteState,
    /// Transport type.
    transport: TransportType,
    /// Timer configuration.
    timer_config: TimerConfig,
    /// When Timer J fires.
    timer_j_deadline: Option<Instant>,
    /// Last response status code sent.
    last_response_code: Option<u16>,
}

impl ServerNonInviteTransaction {
    /// Creates a new server non-INVITE transaction.
    pub fn new(key: TransactionKey, transport: TransportType) -> Self {
        Self {
            key,
            state: ServerNonInviteState::Trying,
            transport,
            timer_config: TimerConfig::default(),
            timer_j_deadline: None,
            last_response_code: None,
        }
    }

    /// Returns the transaction key.
    pub fn key(&self) -> &TransactionKey {
        &self.key
    }

    /// Returns the current state.
    pub fn state(&self) -> ServerNonInviteState {
        self.state
    }

    /// Sends a response.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn send_response(&mut self, status_code: u16) -> TransactionResult<()> {
        self.last_response_code = Some(status_code);

        match self.state {
            ServerNonInviteState::Trying => {
                if (100..200).contains(&status_code) {
                    self.state = ServerNonInviteState::Proceeding;
                    Ok(())
                } else if (200..700).contains(&status_code) {
                    self.enter_completed();
                    Ok(())
                } else {
                    Err(TransactionError::InvalidResponse {
                        reason: format!("invalid status code: {status_code}"),
                    })
                }
            }
            ServerNonInviteState::Proceeding => {
                if (100..200).contains(&status_code) {
                    Ok(())
                } else if (200..700).contains(&status_code) {
                    self.enter_completed();
                    Ok(())
                } else {
                    Err(TransactionError::InvalidResponse {
                        reason: format!("invalid status code: {status_code}"),
                    })
                }
            }
            ServerNonInviteState::Completed => {
                // Response retransmission
                Ok(())
            }
            ServerNonInviteState::Terminated => Err(TransactionError::Terminated),
        }
    }

    /// Receives a request retransmission.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn receive_request(&mut self) -> TransactionResult<bool> {
        match self.state {
            ServerNonInviteState::Trying => {
                // First request - no response yet
                Ok(false)
            }
            ServerNonInviteState::Proceeding | ServerNonInviteState::Completed => {
                // Retransmit last response
                Ok(self.last_response_code.is_some())
            }
            ServerNonInviteState::Terminated => Ok(false),
        }
    }

    /// Processes timer expirations.
    pub fn check_timers(&mut self) -> Option<TimerType> {
        if self.state == ServerNonInviteState::Completed
            && let Some(deadline) = self.timer_j_deadline
            && Instant::now() >= deadline
        {
            self.state = ServerNonInviteState::Terminated;
            return Some(TimerType::TimerJ);
        }
        None
    }

    /// Enters the Completed state.
    fn enter_completed(&mut self) {
        self.state = ServerNonInviteState::Completed;

        let timer_j = if self.transport == TransportType::Unreliable {
            self.timer_config.timer_j_unreliable()
        } else {
            self.timer_config.timer_j_reliable()
        };

        if timer_j > Duration::ZERO {
            self.timer_j_deadline = Some(Instant::now() + timer_j);
        } else {
            self.state = ServerNonInviteState::Terminated;
        }
    }

    /// Returns whether the transaction is terminated.
    pub fn is_terminated(&self) -> bool {
        self.state == ServerNonInviteState::Terminated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_invite_initial_state() {
        let key = TransactionKey::server("z9hG4bK776asdhds", "INVITE");
        let tx = ServerInviteTransaction::new(key, TransportType::Unreliable);

        assert_eq!(tx.state(), ServerInviteState::Proceeding);
    }

    #[test]
    fn test_server_invite_send_100() {
        let key = TransactionKey::server("z9hG4bK776asdhds", "INVITE");
        let mut tx = ServerInviteTransaction::new(key, TransportType::Unreliable);

        tx.send_response(100).unwrap();
        assert_eq!(tx.state(), ServerInviteState::Proceeding);
        assert_eq!(tx.last_response_code(), Some(100));
    }

    #[test]
    fn test_server_invite_send_200() {
        let key = TransactionKey::server("z9hG4bK776asdhds", "INVITE");
        let mut tx = ServerInviteTransaction::new(key, TransportType::Unreliable);

        tx.send_response(200).unwrap();
        assert_eq!(tx.state(), ServerInviteState::Terminated);
    }

    #[test]
    fn test_server_invite_send_486_receive_ack() {
        let key = TransactionKey::server("z9hG4bK776asdhds", "INVITE");
        let mut tx = ServerInviteTransaction::new(key, TransportType::Unreliable);

        tx.send_response(486).unwrap();
        assert_eq!(tx.state(), ServerInviteState::Completed);

        tx.receive_ack().unwrap();
        assert_eq!(tx.state(), ServerInviteState::Confirmed);
    }

    #[test]
    fn test_server_invite_reliable_transport() {
        let key = TransactionKey::server("z9hG4bK776asdhds", "INVITE");
        let mut tx = ServerInviteTransaction::new(key, TransportType::Reliable);

        tx.send_response(486).unwrap();
        assert_eq!(tx.state(), ServerInviteState::Completed);
        // No Timer G for reliable transport
        assert!(tx.timer_g_deadline.is_none());

        tx.receive_ack().unwrap();
        // Immediate termination for reliable transport
        assert_eq!(tx.state(), ServerInviteState::Terminated);
    }

    #[test]
    fn test_server_non_invite_lifecycle() {
        let key = TransactionKey::server("z9hG4bK776asdhds", "OPTIONS");
        let mut tx = ServerNonInviteTransaction::new(key, TransportType::Unreliable);

        assert_eq!(tx.state(), ServerNonInviteState::Trying);

        // Send 100
        tx.send_response(100).unwrap();
        assert_eq!(tx.state(), ServerNonInviteState::Proceeding);

        // Send 200
        tx.send_response(200).unwrap();
        assert_eq!(tx.state(), ServerNonInviteState::Completed);
    }

    #[test]
    fn test_server_non_invite_reliable() {
        let key = TransactionKey::server("z9hG4bK776asdhds", "OPTIONS");
        let mut tx = ServerNonInviteTransaction::new(key, TransportType::Reliable);

        tx.send_response(200).unwrap();
        // Immediate termination for reliable transport
        assert_eq!(tx.state(), ServerNonInviteState::Terminated);
    }
}
