//! SCTP timer management and RTO calculation (RFC 9260 Section 6.3).
//!
//! This module implements:
//! - RTO (Retransmission Timeout) calculation using SRTT and RTTVAR
//! - Timer management for T1-init, T1-cookie, T2-shutdown, T3-rtx, and heartbeat

use std::time::{Duration, Instant};

// =============================================================================
// RTO Calculator
// =============================================================================

/// RTO (Retransmission Timeout) calculator per RFC 9260 Section 6.3.
///
/// Uses Karn's algorithm and Jacobson's algorithm for RTT estimation:
/// - SRTT: Smoothed Round-Trip Time
/// - RTTVAR: RTT Variance
/// - RTO = SRTT + 4 * RTTVAR (bounded by min/max)
#[derive(Debug, Clone)]
pub struct RtoCalculator {
    /// Smoothed Round-Trip Time.
    srtt: Option<Duration>,
    /// RTT variance.
    rttvar: Option<Duration>,
    /// Current RTO value.
    rto: Duration,
    /// Minimum RTO (RFC 9260 recommends 1 second).
    rto_min: Duration,
    /// Maximum RTO (RFC 9260 recommends 60 seconds).
    rto_max: Duration,
    /// Alpha for SRTT calculation (1/8).
    alpha: f64,
    /// Beta for RTTVAR calculation (1/4).
    beta: f64,
}

impl RtoCalculator {
    /// Default initial RTO (3 seconds per RFC 9260).
    pub const DEFAULT_RTO_INITIAL: Duration = Duration::from_secs(3);
    /// Default minimum RTO (1 second per RFC 9260).
    pub const DEFAULT_RTO_MIN: Duration = Duration::from_secs(1);
    /// Default maximum RTO (60 seconds per RFC 9260).
    pub const DEFAULT_RTO_MAX: Duration = Duration::from_secs(60);

    /// Creates a new RTO calculator with default values.
    pub fn new() -> Self {
        Self::with_config(
            Self::DEFAULT_RTO_INITIAL,
            Self::DEFAULT_RTO_MIN,
            Self::DEFAULT_RTO_MAX,
        )
    }

    /// Creates a new RTO calculator with custom configuration.
    pub fn with_config(initial: Duration, min: Duration, max: Duration) -> Self {
        Self {
            srtt: None,
            rttvar: None,
            rto: initial,
            rto_min: min,
            rto_max: max,
            alpha: 1.0 / 8.0,
            beta: 1.0 / 4.0,
        }
    }

    /// Returns the current RTO value.
    pub fn rto(&self) -> Duration {
        self.rto
    }

    /// Returns the smoothed RTT, if available.
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// Returns the RTT variance, if available.
    pub fn rttvar(&self) -> Option<Duration> {
        self.rttvar
    }

    /// Updates the RTO based on a new RTT measurement.
    ///
    /// Implements RFC 9260 Section 6.3.1:
    /// - First measurement: SRTT = R, RTTVAR = R/2, RTO = SRTT + 4*RTTVAR
    /// - Subsequent: RTTVAR' = (1-β)*RTTVAR + β*|SRTT - R|,
    ///   SRTT' = (1-α)*SRTT + α*R, RTO = SRTT + 4*RTTVAR
    pub fn update(&mut self, rtt: Duration) {
        let rtt_secs = rtt.as_secs_f64();

        match self.srtt {
            None => {
                // First measurement
                self.srtt = Some(rtt);
                self.rttvar = Some(rtt / 2);
            }
            Some(srtt) => {
                // Subsequent measurements
                let srtt_secs = srtt.as_secs_f64();
                let rttvar_secs = self.rttvar.map_or(0.0, |d| d.as_secs_f64());

                // RTTVAR' = (1 - β) * RTTVAR + β * |SRTT - R|
                let new_rttvar = (1.0 - self.beta)
                    .mul_add(rttvar_secs, self.beta * (srtt_secs - rtt_secs).abs());

                // SRTT' = (1 - α) * SRTT + α * R
                let new_srtt = (1.0 - self.alpha).mul_add(srtt_secs, self.alpha * rtt_secs);

                self.srtt = Some(Duration::from_secs_f64(new_srtt));
                self.rttvar = Some(Duration::from_secs_f64(new_rttvar));
            }
        }

        self.recalculate_rto();
    }

    /// Recalculates RTO from current SRTT and RTTVAR.
    fn recalculate_rto(&mut self) {
        if let (Some(srtt), Some(rttvar)) = (self.srtt, self.rttvar) {
            // RTO = SRTT + 4 * RTTVAR
            let rto = srtt + rttvar * 4;

            // Apply bounds
            self.rto = rto.clamp(self.rto_min, self.rto_max);
        }
    }

    /// Doubles the RTO (exponential backoff) after a timeout.
    ///
    /// Per RFC 9260 Section 6.3.3, RTO is doubled on each retransmission,
    /// up to the maximum RTO value.
    pub fn backoff(&mut self) {
        self.rto = (self.rto * 2).min(self.rto_max);
    }

    /// Resets the RTO to initial value (used after successful transmission).
    pub fn reset(&mut self) {
        self.rto = Self::DEFAULT_RTO_INITIAL;
        self.srtt = None;
        self.rttvar = None;
    }
}

impl Default for RtoCalculator {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Timer Types
// =============================================================================

/// SCTP timer types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerType {
    /// T1-init: INIT retransmission.
    T1Init,
    /// T1-cookie: COOKIE ECHO retransmission.
    T1Cookie,
    /// T2-shutdown: SHUTDOWN retransmission.
    T2Shutdown,
    /// T3-rtx: Data retransmission.
    T3Rtx,
    /// Heartbeat timer for path liveness.
    Heartbeat,
}

impl std::fmt::Display for TimerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::T1Init => write!(f, "T1-INIT"),
            Self::T1Cookie => write!(f, "T1-COOKIE"),
            Self::T2Shutdown => write!(f, "T2-SHUTDOWN"),
            Self::T3Rtx => write!(f, "T3-RTX"),
            Self::Heartbeat => write!(f, "HEARTBEAT"),
        }
    }
}

// =============================================================================
// Timer
// =============================================================================

/// A single SCTP timer.
#[derive(Debug, Clone)]
#[allow(clippy::struct_field_names)]
pub struct Timer {
    /// Timer type.
    timer_type: TimerType,
    /// When the timer was started.
    started_at: Option<Instant>,
    /// Timer duration.
    duration: Duration,
    /// Number of expirations (for retry tracking).
    expiration_count: u32,
}

impl Timer {
    /// Creates a new timer.
    pub fn new(timer_type: TimerType, duration: Duration) -> Self {
        Self {
            timer_type,
            started_at: None,
            duration,
            expiration_count: 0,
        }
    }

    /// Returns the timer type.
    pub fn timer_type(&self) -> TimerType {
        self.timer_type
    }

    /// Returns true if the timer is currently running.
    pub fn is_running(&self) -> bool {
        self.started_at.is_some()
    }

    /// Starts the timer.
    pub fn start(&mut self) {
        self.started_at = Some(Instant::now());
    }

    /// Starts the timer with a specific duration.
    pub fn start_with_duration(&mut self, duration: Duration) {
        self.duration = duration;
        self.started_at = Some(Instant::now());
    }

    /// Stops the timer.
    pub fn stop(&mut self) {
        self.started_at = None;
    }

    /// Returns true if the timer has expired.
    pub fn is_expired(&self) -> bool {
        self.started_at
            .is_some_and(|started| started.elapsed() >= self.duration)
    }

    /// Returns the time remaining until expiration, or None if not running.
    pub fn remaining(&self) -> Option<Duration> {
        self.started_at.map(|started| {
            let elapsed = started.elapsed();
            self.duration.saturating_sub(elapsed)
        })
    }

    /// Records an expiration and returns the count.
    pub fn record_expiration(&mut self) -> u32 {
        self.expiration_count += 1;
        self.started_at = None;
        self.expiration_count
    }

    /// Returns the expiration count.
    pub fn expiration_count(&self) -> u32 {
        self.expiration_count
    }

    /// Resets the expiration count.
    pub fn reset_count(&mut self) {
        self.expiration_count = 0;
    }

    /// Updates the timer duration.
    pub fn set_duration(&mut self, duration: Duration) {
        self.duration = duration;
    }
}

// =============================================================================
// Timer Manager
// =============================================================================

/// Manages all timers for an SCTP association.
#[derive(Debug)]
pub struct TimerManager {
    /// T1-init timer.
    t1_init: Timer,
    /// T1-cookie timer.
    t1_cookie: Timer,
    /// T2-shutdown timer.
    t2_shutdown: Timer,
    /// T3-rtx timer (per-path in full implementation).
    t3_rtx: Timer,
    /// Heartbeat timer.
    heartbeat: Timer,
    /// RTO calculator.
    rto: RtoCalculator,
    /// Heartbeat interval.
    heartbeat_interval: Duration,
}

impl TimerManager {
    /// Default heartbeat interval (30 seconds).
    pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

    /// Creates a new timer manager.
    pub fn new() -> Self {
        let rto = RtoCalculator::new();
        let initial_rto = rto.rto();

        Self {
            t1_init: Timer::new(TimerType::T1Init, initial_rto),
            t1_cookie: Timer::new(TimerType::T1Cookie, initial_rto),
            t2_shutdown: Timer::new(TimerType::T2Shutdown, initial_rto),
            t3_rtx: Timer::new(TimerType::T3Rtx, initial_rto),
            heartbeat: Timer::new(TimerType::Heartbeat, Self::DEFAULT_HEARTBEAT_INTERVAL),
            rto,
            heartbeat_interval: Self::DEFAULT_HEARTBEAT_INTERVAL,
        }
    }

    /// Creates a timer manager with custom heartbeat interval.
    pub fn with_heartbeat_interval(heartbeat_interval: Duration) -> Self {
        let mut manager = Self::new();
        manager.heartbeat_interval = heartbeat_interval;
        manager.heartbeat.set_duration(heartbeat_interval);
        manager
    }

    /// Returns a reference to the RTO calculator.
    pub fn rto_calculator(&self) -> &RtoCalculator {
        &self.rto
    }

    /// Returns a mutable reference to the RTO calculator.
    pub fn rto_calculator_mut(&mut self) -> &mut RtoCalculator {
        &mut self.rto
    }

    /// Updates the RTO with a new RTT measurement.
    pub fn update_rto(&mut self, rtt: Duration) {
        self.rto.update(rtt);
        // Update timer durations with new RTO
        let new_rto = self.rto.rto();
        self.t1_init.set_duration(new_rto);
        self.t1_cookie.set_duration(new_rto);
        self.t2_shutdown.set_duration(new_rto);
        self.t3_rtx.set_duration(new_rto);
    }

    /// Starts the T1-init timer.
    pub fn start_t1_init(&mut self) {
        self.t1_init.start_with_duration(self.rto.rto());
    }

    /// Stops the T1-init timer.
    pub fn stop_t1_init(&mut self) {
        self.t1_init.stop();
    }

    /// Starts the T1-cookie timer.
    pub fn start_t1_cookie(&mut self) {
        self.t1_cookie.start_with_duration(self.rto.rto());
    }

    /// Stops the T1-cookie timer.
    pub fn stop_t1_cookie(&mut self) {
        self.t1_cookie.stop();
    }

    /// Starts the T2-shutdown timer.
    pub fn start_t2_shutdown(&mut self) {
        self.t2_shutdown.start_with_duration(self.rto.rto());
    }

    /// Stops the T2-shutdown timer.
    pub fn stop_t2_shutdown(&mut self) {
        self.t2_shutdown.stop();
    }

    /// Starts the T3-rtx timer.
    pub fn start_t3_rtx(&mut self) {
        self.t3_rtx.start_with_duration(self.rto.rto());
    }

    /// Stops the T3-rtx timer.
    pub fn stop_t3_rtx(&mut self) {
        self.t3_rtx.stop();
    }

    /// Returns true if T3-rtx timer is running.
    pub fn is_t3_running(&self) -> bool {
        self.t3_rtx.is_running()
    }

    /// Returns true if T3-rtx timer has expired.
    pub fn is_t3_expired(&self) -> bool {
        self.t3_rtx.is_expired()
    }

    /// Starts the heartbeat timer.
    pub fn start_heartbeat(&mut self) {
        self.heartbeat.start_with_duration(self.heartbeat_interval);
    }

    /// Stops the heartbeat timer.
    pub fn stop_heartbeat(&mut self) {
        self.heartbeat.stop();
    }

    /// Returns a list of expired timers.
    pub fn expired_timers(&self) -> Vec<TimerType> {
        let mut expired = Vec::new();

        if self.t1_init.is_expired() {
            expired.push(TimerType::T1Init);
        }
        if self.t1_cookie.is_expired() {
            expired.push(TimerType::T1Cookie);
        }
        if self.t2_shutdown.is_expired() {
            expired.push(TimerType::T2Shutdown);
        }
        if self.t3_rtx.is_expired() {
            expired.push(TimerType::T3Rtx);
        }
        if self.heartbeat.is_expired() {
            expired.push(TimerType::Heartbeat);
        }

        expired
    }

    /// Records expiration for a timer and applies backoff.
    pub fn record_expiration(&mut self, timer_type: TimerType) -> u32 {
        let count = match timer_type {
            TimerType::T1Init => self.t1_init.record_expiration(),
            TimerType::T1Cookie => self.t1_cookie.record_expiration(),
            TimerType::T2Shutdown => self.t2_shutdown.record_expiration(),
            TimerType::T3Rtx => self.t3_rtx.record_expiration(),
            TimerType::Heartbeat => self.heartbeat.record_expiration(),
        };

        // Apply exponential backoff for RTO-based timers
        if matches!(
            timer_type,
            TimerType::T1Init | TimerType::T1Cookie | TimerType::T2Shutdown | TimerType::T3Rtx
        ) {
            self.rto.backoff();
        }

        count
    }

    /// Returns the expiration count for a timer.
    pub fn expiration_count(&self, timer_type: TimerType) -> u32 {
        match timer_type {
            TimerType::T1Init => self.t1_init.expiration_count(),
            TimerType::T1Cookie => self.t1_cookie.expiration_count(),
            TimerType::T2Shutdown => self.t2_shutdown.expiration_count(),
            TimerType::T3Rtx => self.t3_rtx.expiration_count(),
            TimerType::Heartbeat => self.heartbeat.expiration_count(),
        }
    }

    /// Resets all timers and the RTO calculator.
    pub fn reset(&mut self) {
        self.t1_init.stop();
        self.t1_init.reset_count();
        self.t1_cookie.stop();
        self.t1_cookie.reset_count();
        self.t2_shutdown.stop();
        self.t2_shutdown.reset_count();
        self.t3_rtx.stop();
        self.t3_rtx.reset_count();
        self.heartbeat.stop();
        self.heartbeat.reset_count();
        self.rto.reset();
    }
}

impl Default for TimerManager {
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
    use std::thread;

    #[test]
    fn test_rto_default_values() {
        let rto = RtoCalculator::new();
        assert_eq!(rto.rto(), RtoCalculator::DEFAULT_RTO_INITIAL);
        assert!(rto.srtt().is_none());
        assert!(rto.rttvar().is_none());
    }

    #[test]
    fn test_rto_first_measurement() {
        let mut rto = RtoCalculator::new();

        rto.update(Duration::from_millis(100));

        assert!(rto.srtt().is_some());
        assert!(rto.rttvar().is_some());
        assert_eq!(rto.srtt().unwrap(), Duration::from_millis(100));
        assert_eq!(rto.rttvar().unwrap(), Duration::from_millis(50));
    }

    #[test]
    fn test_rto_subsequent_measurements() {
        let mut rto = RtoCalculator::new();

        rto.update(Duration::from_millis(100));
        let initial_srtt = rto.srtt().unwrap();

        rto.update(Duration::from_millis(150));
        let new_srtt = rto.srtt().unwrap();

        // SRTT should have moved towards 150ms
        assert!(new_srtt > initial_srtt);
    }

    #[test]
    fn test_rto_backoff() {
        let mut rto = RtoCalculator::new();
        let initial = rto.rto();

        rto.backoff();
        assert_eq!(rto.rto(), initial * 2);

        rto.backoff();
        assert_eq!(rto.rto(), initial * 4);
    }

    #[test]
    fn test_rto_backoff_max() {
        let mut rto = RtoCalculator::new();

        // Backoff many times
        for _ in 0..10 {
            rto.backoff();
        }

        // Should be clamped to max
        assert_eq!(rto.rto(), RtoCalculator::DEFAULT_RTO_MAX);
    }

    #[test]
    fn test_rto_min_bound() {
        let mut rto = RtoCalculator::with_config(
            Duration::from_millis(100),
            Duration::from_secs(1),
            Duration::from_secs(60),
        );

        // Very small RTT should still result in RTO >= min
        rto.update(Duration::from_millis(10));
        assert!(rto.rto() >= Duration::from_secs(1));
    }

    #[test]
    fn test_timer_type_display() {
        assert_eq!(TimerType::T1Init.to_string(), "T1-INIT");
        assert_eq!(TimerType::Heartbeat.to_string(), "HEARTBEAT");
    }

    #[test]
    fn test_timer_start_stop() {
        let mut timer = Timer::new(TimerType::T1Init, Duration::from_millis(100));

        assert!(!timer.is_running());

        timer.start();
        assert!(timer.is_running());
        assert!(!timer.is_expired());

        timer.stop();
        assert!(!timer.is_running());
    }

    #[test]
    fn test_timer_expiration() {
        let mut timer = Timer::new(TimerType::T1Init, Duration::from_millis(10));

        timer.start();
        assert!(!timer.is_expired());

        // Wait for expiration
        thread::sleep(Duration::from_millis(20));
        assert!(timer.is_expired());

        let count = timer.record_expiration();
        assert_eq!(count, 1);
        assert!(!timer.is_running());
    }

    #[test]
    fn test_timer_remaining() {
        let mut timer = Timer::new(TimerType::T1Init, Duration::from_millis(100));

        assert!(timer.remaining().is_none());

        timer.start();
        let remaining = timer.remaining().unwrap();
        assert!(remaining <= Duration::from_millis(100));
    }

    #[test]
    fn test_timer_manager_creation() {
        let manager = TimerManager::new();
        assert_eq!(
            manager.rto_calculator().rto(),
            RtoCalculator::DEFAULT_RTO_INITIAL
        );
    }

    #[test]
    fn test_timer_manager_start_stop() {
        let mut manager = TimerManager::new();

        manager.start_t1_init();
        assert!(manager.t1_init.is_running());

        manager.stop_t1_init();
        assert!(!manager.t1_init.is_running());
    }

    #[test]
    fn test_timer_manager_expired_timers() {
        let mut manager = TimerManager::new();

        // Start timers with very short duration
        manager
            .t1_init
            .start_with_duration(Duration::from_millis(1));

        thread::sleep(Duration::from_millis(10));

        let expired = manager.expired_timers();
        assert!(expired.contains(&TimerType::T1Init));
    }

    #[test]
    fn test_timer_manager_rto_update() {
        let mut manager = TimerManager::new();

        manager.update_rto(Duration::from_millis(100));

        assert!(manager.rto_calculator().srtt().is_some());
    }

    #[test]
    fn test_timer_manager_reset() {
        let mut manager = TimerManager::new();

        manager.start_t1_init();
        manager.record_expiration(TimerType::T1Init);

        manager.reset();

        assert!(!manager.t1_init.is_running());
        assert_eq!(manager.expiration_count(TimerType::T1Init), 0);
    }
}
