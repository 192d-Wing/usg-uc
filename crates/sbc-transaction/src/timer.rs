//! Transaction timer management.

use crate::{DEFAULT_T1, DEFAULT_T2, DEFAULT_T4};
use std::time::Duration;

/// Timer configuration.
#[derive(Debug, Clone)]
pub struct TimerConfig {
    /// T1 - RTT estimate.
    pub t1: Duration,
    /// T2 - Maximum retransmit interval.
    pub t2: Duration,
    /// T4 - Maximum duration a message can remain in the network.
    pub t4: Duration,
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            t1: DEFAULT_T1,
            t2: DEFAULT_T2,
            t4: DEFAULT_T4,
        }
    }
}

impl TimerConfig {
    /// Creates a new timer configuration.
    pub fn new(t1: Duration, t2: Duration, t4: Duration) -> Self {
        Self { t1, t2, t4 }
    }

    /// Returns Timer A initial value.
    pub fn timer_a(&self) -> Duration {
        self.t1
    }

    /// Returns Timer B value (64*T1).
    pub fn timer_b(&self) -> Duration {
        self.t1 * 64
    }

    /// Returns Timer D value for unreliable transport.
    pub fn timer_d_unreliable(&self) -> Duration {
        Duration::from_secs(32).max(self.t1 * 64)
    }

    /// Returns Timer D value for reliable transport.
    pub fn timer_d_reliable(&self) -> Duration {
        Duration::ZERO
    }

    /// Returns Timer E initial value.
    pub fn timer_e(&self) -> Duration {
        self.t1
    }

    /// Returns Timer F value (64*T1).
    pub fn timer_f(&self) -> Duration {
        self.t1 * 64
    }

    /// Returns Timer G initial value.
    pub fn timer_g(&self) -> Duration {
        self.t1
    }

    /// Returns Timer H value (64*T1).
    pub fn timer_h(&self) -> Duration {
        self.t1 * 64
    }

    /// Returns Timer I value for unreliable transport.
    pub fn timer_i_unreliable(&self) -> Duration {
        self.t4
    }

    /// Returns Timer I value for reliable transport.
    pub fn timer_i_reliable(&self) -> Duration {
        Duration::ZERO
    }

    /// Returns Timer J value for unreliable transport.
    pub fn timer_j_unreliable(&self) -> Duration {
        self.t1 * 64
    }

    /// Returns Timer J value for reliable transport.
    pub fn timer_j_reliable(&self) -> Duration {
        Duration::ZERO
    }

    /// Returns Timer K value for unreliable transport.
    pub fn timer_k_unreliable(&self) -> Duration {
        self.t4
    }

    /// Returns Timer K value for reliable transport.
    pub fn timer_k_reliable(&self) -> Duration {
        Duration::ZERO
    }
}

/// SIP transaction timer types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerType {
    /// Timer A - INVITE request retransmit (client).
    TimerA,
    /// Timer B - INVITE transaction timeout (client).
    TimerB,
    /// Timer C - Proxy INVITE transaction timeout.
    TimerC,
    /// Timer D - Wait for response retransmits (client INVITE).
    TimerD,
    /// Timer E - Non-INVITE request retransmit (client).
    TimerE,
    /// Timer F - Non-INVITE transaction timeout (client).
    TimerF,
    /// Timer G - INVITE response retransmit (server).
    TimerG,
    /// Timer H - Wait for ACK receipt (server INVITE).
    TimerH,
    /// Timer I - Wait for ACK retransmits (server INVITE).
    TimerI,
    /// Timer J - Wait for retransmits (server non-INVITE).
    TimerJ,
    /// Timer K - Wait for response retransmits (client non-INVITE).
    TimerK,
}

impl std::fmt::Display for TimerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimerA => write!(f, "Timer A"),
            Self::TimerB => write!(f, "Timer B"),
            Self::TimerC => write!(f, "Timer C"),
            Self::TimerD => write!(f, "Timer D"),
            Self::TimerE => write!(f, "Timer E"),
            Self::TimerF => write!(f, "Timer F"),
            Self::TimerG => write!(f, "Timer G"),
            Self::TimerH => write!(f, "Timer H"),
            Self::TimerI => write!(f, "Timer I"),
            Self::TimerJ => write!(f, "Timer J"),
            Self::TimerK => write!(f, "Timer K"),
        }
    }
}

/// Calculates the next retransmit interval with exponential backoff.
///
/// The interval doubles each time until reaching T2.
pub fn next_retransmit_interval(current: Duration, t2: Duration) -> Duration {
    let doubled = current * 2;
    doubled.min(t2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timer_config_defaults() {
        let config = TimerConfig::default();
        assert_eq!(config.t1, DEFAULT_T1);
        assert_eq!(config.t2, DEFAULT_T2);
        assert_eq!(config.t4, DEFAULT_T4);
    }

    #[test]
    fn test_timer_calculations() {
        let config = TimerConfig::default();

        // Timer B = 64 * T1 = 64 * 500ms = 32s
        assert_eq!(config.timer_b(), Duration::from_millis(32000));

        // Timer A = T1
        assert_eq!(config.timer_a(), DEFAULT_T1);
    }

    #[test]
    fn test_retransmit_backoff() {
        let t2 = Duration::from_secs(4);
        let t1 = Duration::from_millis(500);

        // First retransmit: 500ms -> 1000ms
        let next = next_retransmit_interval(t1, t2);
        assert_eq!(next, Duration::from_millis(1000));

        // Second: 1000ms -> 2000ms
        let next = next_retransmit_interval(next, t2);
        assert_eq!(next, Duration::from_millis(2000));

        // Third: 2000ms -> 4000ms (capped at T2)
        let next = next_retransmit_interval(next, t2);
        assert_eq!(next, Duration::from_millis(4000));

        // Fourth: capped at T2
        let next = next_retransmit_interval(next, t2);
        assert_eq!(next, Duration::from_millis(4000));
    }

    #[test]
    fn test_timer_type_display() {
        assert_eq!(TimerType::TimerA.to_string(), "Timer A");
        assert_eq!(TimerType::TimerB.to_string(), "Timer B");
    }

    #[test]
    fn test_reliable_timers_zero() {
        let config = TimerConfig::default();
        assert_eq!(config.timer_d_reliable(), Duration::ZERO);
        assert_eq!(config.timer_i_reliable(), Duration::ZERO);
        assert_eq!(config.timer_j_reliable(), Duration::ZERO);
        assert_eq!(config.timer_k_reliable(), Duration::ZERO);
    }
}
