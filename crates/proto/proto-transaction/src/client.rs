//! Client transaction state machines.
//!
//! Per RFC 3261 Section 17.1.

use crate::error::TransactionResult;
use crate::timer::{TimerConfig, TimerType, next_retransmit_interval};
use crate::{TransactionKey, TransportType};
use std::time::{Duration, Instant};

/// Client INVITE transaction state (RFC 3261 Section 17.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientInviteState {
    /// Initial state, sending INVITE.
    Calling,
    /// Received provisional response (1xx).
    Proceeding,
    /// Received final response, sending ACK for non-2xx.
    Completed,
    /// Transaction terminated.
    Terminated,
}

impl std::fmt::Display for ClientInviteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Calling => write!(f, "Calling"),
            Self::Proceeding => write!(f, "Proceeding"),
            Self::Completed => write!(f, "Completed"),
            Self::Terminated => write!(f, "Terminated"),
        }
    }
}

/// Client INVITE transaction (RFC 3261 Section 17.1.1).
#[derive(Debug)]
pub struct ClientInviteTransaction {
    /// Transaction key.
    key: TransactionKey,
    /// Current state.
    state: ClientInviteState,
    /// Transport type.
    transport: TransportType,
    /// Timer configuration.
    timer_config: TimerConfig,
    /// When the transaction was created.
    created_at: Instant,
    /// Current Timer A value (retransmit interval).
    timer_a_value: Duration,
    /// When Timer A fires next.
    timer_a_deadline: Option<Instant>,
    /// When Timer B fires (transaction timeout).
    timer_b_deadline: Option<Instant>,
    /// When Timer D fires (wait for response retransmits).
    timer_d_deadline: Option<Instant>,
    /// Retransmission count.
    retransmit_count: u32,
    /// Last response status code received.
    last_response_code: Option<u16>,
}

impl ClientInviteTransaction {
    /// Creates a new client INVITE transaction.
    pub fn new(key: TransactionKey, transport: TransportType) -> Self {
        let now = Instant::now();
        let timer_config = TimerConfig::default();

        let (timer_a_deadline, timer_a_value) = if transport == TransportType::Unreliable {
            (Some(now + timer_config.timer_a()), timer_config.timer_a())
        } else {
            (None, Duration::ZERO)
        };

        Self {
            key,
            state: ClientInviteState::Calling,
            transport,
            timer_config: timer_config.clone(),
            created_at: now,
            timer_a_value,
            timer_a_deadline,
            timer_b_deadline: Some(now + timer_config.timer_b()),
            timer_d_deadline: None,
            retransmit_count: 0,
            last_response_code: None,
        }
    }

    /// Returns the transaction key.
    pub fn key(&self) -> &TransactionKey {
        &self.key
    }

    /// Returns the current state.
    pub fn state(&self) -> ClientInviteState {
        self.state
    }

    /// Returns the transport type.
    pub fn transport(&self) -> TransportType {
        self.transport
    }

    /// Returns the retransmission count.
    pub fn retransmit_count(&self) -> u32 {
        self.retransmit_count
    }

    /// Returns the last response code received.
    pub fn last_response_code(&self) -> Option<u16> {
        self.last_response_code
    }

    /// Returns when the transaction was created.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Returns how long the transaction has been running.
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// Processes a received response.
    ///
    /// Returns true if the response was accepted.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn receive_response(&mut self, status_code: u16) -> TransactionResult<bool> {
        self.last_response_code = Some(status_code);

        match self.state {
            ClientInviteState::Calling => {
                if (100..200).contains(&status_code) {
                    // 1xx response -> Proceeding
                    self.state = ClientInviteState::Proceeding;
                    self.timer_a_deadline = None; // Stop retransmits
                    Ok(true)
                } else if (200..300).contains(&status_code) {
                    // 2xx response -> Terminated (handled by TU)
                    self.state = ClientInviteState::Terminated;
                    Ok(true)
                } else if (300..700).contains(&status_code) {
                    // 3xx-6xx response -> Completed
                    self.enter_completed();
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ClientInviteState::Proceeding => {
                if (100..200).contains(&status_code) {
                    // Another 1xx response
                    Ok(true)
                } else if (200..300).contains(&status_code) {
                    // 2xx response -> Terminated
                    self.state = ClientInviteState::Terminated;
                    Ok(true)
                } else if (300..700).contains(&status_code) {
                    // 3xx-6xx response -> Completed
                    self.enter_completed();
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ClientInviteState::Completed => {
                // Retransmitted response - resend ACK
                if (300..700).contains(&status_code) {
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ClientInviteState::Terminated => Ok(false),
        }
    }

    /// Processes a timer expiration.
    ///
    /// Returns the timer type that fired, if any action is needed.
    pub fn check_timers(&mut self) -> Option<TimerType> {
        let now = Instant::now();

        match self.state {
            ClientInviteState::Calling => {
                // Check Timer B first (transaction timeout)
                if let Some(deadline) = self.timer_b_deadline
                    && now >= deadline {
                        self.state = ClientInviteState::Terminated;
                        return Some(TimerType::TimerB);
                    }

                // Check Timer A (retransmit)
                if let Some(deadline) = self.timer_a_deadline
                    && now >= deadline {
                        self.retransmit_count += 1;
                        self.timer_a_value =
                            next_retransmit_interval(self.timer_a_value, self.timer_config.t2);
                        self.timer_a_deadline = Some(now + self.timer_a_value);
                        return Some(TimerType::TimerA);
                    }
            }
            ClientInviteState::Completed => {
                // Check Timer D
                if let Some(deadline) = self.timer_d_deadline
                    && now >= deadline {
                        self.state = ClientInviteState::Terminated;
                        return Some(TimerType::TimerD);
                    }
            }
            _ => {}
        }

        None
    }

    /// Returns time until next timer fires.
    pub fn next_timer_deadline(&self) -> Option<Instant> {
        match self.state {
            ClientInviteState::Calling => {
                let deadlines: Vec<Instant> = [self.timer_a_deadline, self.timer_b_deadline]
                    .into_iter()
                    .flatten()
                    .collect();
                deadlines.into_iter().min()
            }
            ClientInviteState::Completed => self.timer_d_deadline,
            _ => None,
        }
    }

    /// Enters the Completed state.
    fn enter_completed(&mut self) {
        self.state = ClientInviteState::Completed;
        self.timer_a_deadline = None;
        self.timer_b_deadline = None;

        // Start Timer D
        let timer_d = if self.transport == TransportType::Unreliable {
            self.timer_config.timer_d_unreliable()
        } else {
            self.timer_config.timer_d_reliable()
        };

        if timer_d > Duration::ZERO {
            self.timer_d_deadline = Some(Instant::now() + timer_d);
        } else {
            self.state = ClientInviteState::Terminated;
        }
    }

    /// Returns whether the transaction is terminated.
    pub fn is_terminated(&self) -> bool {
        self.state == ClientInviteState::Terminated
    }
}

/// Client non-INVITE transaction state (RFC 3261 Section 17.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientNonInviteState {
    /// Trying to send request.
    Trying,
    /// Received provisional response.
    Proceeding,
    /// Received final response.
    Completed,
    /// Transaction terminated.
    Terminated,
}

impl std::fmt::Display for ClientNonInviteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Trying => write!(f, "Trying"),
            Self::Proceeding => write!(f, "Proceeding"),
            Self::Completed => write!(f, "Completed"),
            Self::Terminated => write!(f, "Terminated"),
        }
    }
}

/// Client non-INVITE transaction (RFC 3261 Section 17.1.2).
#[derive(Debug)]
pub struct ClientNonInviteTransaction {
    /// Transaction key.
    key: TransactionKey,
    /// Current state.
    state: ClientNonInviteState,
    /// Transport type.
    transport: TransportType,
    /// Timer configuration.
    timer_config: TimerConfig,
    /// Current Timer E value (retransmit interval).
    timer_e_value: Duration,
    /// When Timer E fires next.
    timer_e_deadline: Option<Instant>,
    /// When Timer F fires (transaction timeout).
    timer_f_deadline: Option<Instant>,
    /// When Timer K fires (wait for response retransmits).
    timer_k_deadline: Option<Instant>,
    /// Retransmission count.
    retransmit_count: u32,
    /// Last response status code received.
    last_response_code: Option<u16>,
}

impl ClientNonInviteTransaction {
    /// Creates a new client non-INVITE transaction.
    pub fn new(key: TransactionKey, transport: TransportType) -> Self {
        let now = Instant::now();
        let timer_config = TimerConfig::default();

        let (timer_e_deadline, timer_e_value) = if transport == TransportType::Unreliable {
            (Some(now + timer_config.timer_e()), timer_config.timer_e())
        } else {
            (None, Duration::ZERO)
        };

        Self {
            key,
            state: ClientNonInviteState::Trying,
            transport,
            timer_config: timer_config.clone(),
            timer_e_value,
            timer_e_deadline,
            timer_f_deadline: Some(now + timer_config.timer_f()),
            timer_k_deadline: None,
            retransmit_count: 0,
            last_response_code: None,
        }
    }

    /// Returns the transaction key.
    pub fn key(&self) -> &TransactionKey {
        &self.key
    }

    /// Returns the current state.
    pub fn state(&self) -> ClientNonInviteState {
        self.state
    }

    /// Processes a received response.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn receive_response(&mut self, status_code: u16) -> TransactionResult<bool> {
        self.last_response_code = Some(status_code);

        match self.state {
            ClientNonInviteState::Trying => {
                if (100..200).contains(&status_code) {
                    self.state = ClientNonInviteState::Proceeding;
                    Ok(true)
                } else if (200..700).contains(&status_code) {
                    self.enter_completed();
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ClientNonInviteState::Proceeding => {
                if (100..200).contains(&status_code) {
                    Ok(true)
                } else if (200..700).contains(&status_code) {
                    self.enter_completed();
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ClientNonInviteState::Completed => {
                // Absorb retransmits
                Ok(true)
            }
            ClientNonInviteState::Terminated => Ok(false),
        }
    }

    /// Processes timer expirations.
    pub fn check_timers(&mut self) -> Option<TimerType> {
        let now = Instant::now();

        match self.state {
            ClientNonInviteState::Trying | ClientNonInviteState::Proceeding => {
                // Check Timer F first
                if let Some(deadline) = self.timer_f_deadline
                    && now >= deadline {
                        self.state = ClientNonInviteState::Terminated;
                        return Some(TimerType::TimerF);
                    }

                // Check Timer E
                // RFC 3261 Section 17.1.2.2: Timer E caps at T2 in both Trying and Proceeding states
                if let Some(deadline) = self.timer_e_deadline
                    && now >= deadline {
                        self.retransmit_count += 1;
                        self.timer_e_value =
                            next_retransmit_interval(self.timer_e_value, self.timer_config.t2);
                        self.timer_e_deadline = Some(now + self.timer_e_value);
                        return Some(TimerType::TimerE);
                    }
            }
            ClientNonInviteState::Completed => {
                if let Some(deadline) = self.timer_k_deadline
                    && now >= deadline {
                        self.state = ClientNonInviteState::Terminated;
                        return Some(TimerType::TimerK);
                    }
            }
            _ => {}
        }

        None
    }

    /// Enters the Completed state.
    fn enter_completed(&mut self) {
        self.state = ClientNonInviteState::Completed;
        self.timer_e_deadline = None;
        self.timer_f_deadline = None;

        let timer_k = if self.transport == TransportType::Unreliable {
            self.timer_config.timer_k_unreliable()
        } else {
            self.timer_config.timer_k_reliable()
        };

        if timer_k > Duration::ZERO {
            self.timer_k_deadline = Some(Instant::now() + timer_k);
        } else {
            self.state = ClientNonInviteState::Terminated;
        }
    }

    /// Returns whether the transaction is terminated.
    pub fn is_terminated(&self) -> bool {
        self.state == ClientNonInviteState::Terminated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_invite_initial_state() {
        let key = TransactionKey::client("z9hG4bK776asdhds", "INVITE");
        let tx = ClientInviteTransaction::new(key, TransportType::Unreliable);

        assert_eq!(tx.state(), ClientInviteState::Calling);
        assert!(!tx.is_terminated());
    }

    #[test]
    fn test_client_invite_receive_100() {
        let key = TransactionKey::client("z9hG4bK776asdhds", "INVITE");
        let mut tx = ClientInviteTransaction::new(key, TransportType::Unreliable);

        assert!(tx.receive_response(100).unwrap());
        assert_eq!(tx.state(), ClientInviteState::Proceeding);
    }

    #[test]
    fn test_client_invite_receive_200() {
        let key = TransactionKey::client("z9hG4bK776asdhds", "INVITE");
        let mut tx = ClientInviteTransaction::new(key, TransportType::Unreliable);

        assert!(tx.receive_response(200).unwrap());
        assert_eq!(tx.state(), ClientInviteState::Terminated);
    }

    #[test]
    fn test_client_invite_receive_486() {
        let key = TransactionKey::client("z9hG4bK776asdhds", "INVITE");
        let mut tx = ClientInviteTransaction::new(key, TransportType::Unreliable);

        assert!(tx.receive_response(486).unwrap());
        assert_eq!(tx.state(), ClientInviteState::Completed);
    }

    #[test]
    fn test_client_invite_reliable_transport() {
        let key = TransactionKey::client("z9hG4bK776asdhds", "INVITE");
        let mut tx = ClientInviteTransaction::new(key, TransportType::Reliable);

        // No Timer A for reliable transport
        assert!(tx.timer_a_deadline.is_none());

        // Should still have Timer B
        assert!(tx.timer_b_deadline.is_some());

        // Receive 486 -> immediate termination (no Timer D for reliable)
        assert!(tx.receive_response(486).unwrap());
        assert_eq!(tx.state(), ClientInviteState::Terminated);
    }

    #[test]
    fn test_client_non_invite_lifecycle() {
        let key = TransactionKey::client("z9hG4bK776asdhds", "OPTIONS");
        let mut tx = ClientNonInviteTransaction::new(key, TransportType::Unreliable);

        assert_eq!(tx.state(), ClientNonInviteState::Trying);

        // Receive 100
        assert!(tx.receive_response(100).unwrap());
        assert_eq!(tx.state(), ClientNonInviteState::Proceeding);

        // Receive 200
        assert!(tx.receive_response(200).unwrap());
        assert_eq!(tx.state(), ClientNonInviteState::Completed);
    }

    #[test]
    fn test_client_update_transaction() {
        // RFC 3311: UPDATE uses non-INVITE transaction state machine
        let key = TransactionKey::client("z9hG4bK776asdhds", "UPDATE");
        let mut tx = ClientNonInviteTransaction::new(key, TransportType::Unreliable);

        assert_eq!(tx.state(), ClientNonInviteState::Trying);
        assert_eq!(tx.key().method, "UPDATE");

        // Receive 200 OK (session modified)
        assert!(tx.receive_response(200).unwrap());
        assert_eq!(tx.state(), ClientNonInviteState::Completed);
    }

    #[test]
    fn test_client_update_with_session_timer_refresh() {
        // RFC 4028: UPDATE can be used for session timer refresh
        let key = TransactionKey::client("z9hG4bK776asdhds", "UPDATE");
        let mut tx = ClientNonInviteTransaction::new(key, TransportType::Unreliable);

        // Receive 422 (Session Interval Too Small)
        assert!(tx.receive_response(422).unwrap());
        assert_eq!(tx.state(), ClientNonInviteState::Completed);
    }
}
