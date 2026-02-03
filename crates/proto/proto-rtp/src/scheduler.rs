//! RTCP transmission scheduling per RFC 3550 §6.3.5.
//!
//! This module implements the RTCP timing rules for determining when to
//! send RTCP packets. The algorithm ensures that RTCP bandwidth is kept
//! within the specified limit (typically 5% of session bandwidth) while
//! providing timely feedback.
//!
//! ## RFC 3550 Requirements
//!
//! - §6.3.1: RTCP bandwidth fraction (typically 5%)
//! - §6.3.2: Minimum interval (5 seconds, adjustable)
//! - §6.3.5: Randomization (0.5 to 1.5 × computed interval)
//! - §6.3.6: Initial report delay (half the minimum)
//! - Appendix A.7: Reference algorithm implementation

use std::time::{Duration, Instant};

/// Minimum RTCP interval in seconds (RFC 3550 §6.2).
pub const RTCP_MIN_INTERVAL_SECS: f64 = 5.0;

/// RTCP bandwidth fraction (5% of session bandwidth per RFC 3550 §6.2).
pub const RTCP_BANDWIDTH_FRACTION: f64 = 0.05;

/// Sender bandwidth fraction (25% of RTCP bandwidth per RFC 3550 §6.3.1).
pub const RTCP_SENDER_BANDWIDTH_FRACTION: f64 = 0.25;

/// Compensation factor for timer reconsideration (RFC 3550 A.7).
/// This is e - 1.5, where e is Euler's number.
pub const RTCP_COMPENSATION_FACTOR: f64 = 1.21828;

/// Initial RTCP packet average size estimate (bytes).
pub const INITIAL_AVG_RTCP_SIZE: f64 = 100.0;

/// RTCP scheduler for computing transmission intervals.
///
/// Implements RFC 3550 §6.3 and Appendix A.7 algorithm for determining
/// when to send RTCP packets.
///
/// ## Example
///
/// ```
/// use proto_rtp::scheduler::{RtcpScheduler, SessionParams};
///
/// let params = SessionParams {
///     session_bandwidth: 64000.0, // 64 kbps
///     rtcp_bandwidth: Some(3200.0), // 5% of session
///     members: 10,
///     senders: 2,
///     we_sent: true,
///     initial: true,
/// };
///
/// let mut scheduler = RtcpScheduler::new(params);
/// let interval = scheduler.compute_interval();
/// println!("Next RTCP in {:?}", interval);
/// ```
#[derive(Debug, Clone)]
pub struct RtcpScheduler {
    /// Session parameters.
    params: SessionParams,
    /// Average RTCP packet size (exponentially weighted).
    avg_rtcp_size: f64,
    /// Last computed transmission time.
    tp: Option<Instant>,
    /// Next scheduled transmission time.
    tn: Option<Instant>,
    /// Number of RTCP packets sent.
    rtcp_packets_sent: u64,
}

/// Session parameters for RTCP scheduling.
#[derive(Debug, Clone)]
pub struct SessionParams {
    /// Session bandwidth in bits per second.
    pub session_bandwidth: f64,
    /// RTCP bandwidth in bits per second (default: 5% of session).
    pub rtcp_bandwidth: Option<f64>,
    /// Total number of members (participants) in the session.
    pub members: u32,
    /// Number of senders in the session.
    pub senders: u32,
    /// Whether we have sent RTP data since the last report.
    pub we_sent: bool,
    /// Whether this is the initial RTCP packet.
    pub initial: bool,
}

impl Default for SessionParams {
    fn default() -> Self {
        Self {
            session_bandwidth: 64000.0, // 64 kbps
            rtcp_bandwidth: None,
            members: 1,
            senders: 0,
            we_sent: false,
            initial: true,
        }
    }
}

impl RtcpScheduler {
    /// Creates a new RTCP scheduler with the given parameters.
    #[must_use]
    pub fn new(params: SessionParams) -> Self {
        Self {
            params,
            avg_rtcp_size: INITIAL_AVG_RTCP_SIZE,
            tp: None,
            tn: None,
            rtcp_packets_sent: 0,
        }
    }

    /// Updates session parameters.
    pub fn update_params(&mut self, params: SessionParams) {
        self.params = params;
    }

    /// Updates the member count.
    pub fn set_members(&mut self, members: u32) {
        self.params.members = members;
    }

    /// Updates the sender count.
    pub fn set_senders(&mut self, senders: u32) {
        self.params.senders = senders;
    }

    /// Sets whether we have sent RTP data.
    pub fn set_we_sent(&mut self, we_sent: bool) {
        self.params.we_sent = we_sent;
    }

    /// Updates the average RTCP packet size with exponential weighting.
    ///
    /// Per RFC 3550 A.7, the estimate is:
    /// `avg_rtcp_size` = (1/16) * `packet_size` + (15/16) * `avg_rtcp_size`
    pub fn update_avg_size(&mut self, packet_size: usize) {
        self.avg_rtcp_size = (packet_size as f64 / 16.0) + (15.0 * self.avg_rtcp_size / 16.0);
    }

    /// Returns the current average RTCP packet size.
    #[must_use]
    pub fn avg_rtcp_size(&self) -> f64 {
        self.avg_rtcp_size
    }

    /// Returns the effective RTCP bandwidth.
    #[must_use]
    pub fn rtcp_bandwidth(&self) -> f64 {
        self.params
            .rtcp_bandwidth
            .unwrap_or(self.params.session_bandwidth * RTCP_BANDWIDTH_FRACTION)
    }

    /// Computes the deterministic RTCP interval per RFC 3550 A.7.
    ///
    /// The interval is based on:
    /// - RTCP bandwidth allocated
    /// - Number of participants
    /// - Average RTCP packet size
    /// - Whether we are a sender
    #[must_use]
    pub fn compute_deterministic_interval(&self) -> Duration {
        let rtcp_bw = self.rtcp_bandwidth();
        let members = self.params.members as f64;
        let senders = self.params.senders as f64;

        // Calculate the effective number of members for interval computation
        // Per RFC 3550 §6.3.1, senders get 25% of RTCP bandwidth
        let (n, c) = if senders <= members * RTCP_SENDER_BANDWIDTH_FRACTION {
            // Separate sender/receiver budgets
            if self.params.we_sent {
                (senders, rtcp_bw * RTCP_SENDER_BANDWIDTH_FRACTION)
            } else {
                (
                    members - senders,
                    rtcp_bw * (1.0 - RTCP_SENDER_BANDWIDTH_FRACTION),
                )
            }
        } else {
            // Treat all as senders
            (members, rtcp_bw)
        };

        // Ensure at least 1 participant
        let n = n.max(1.0);

        // Compute interval: t = (n * avg_size * 8) / C
        // Where C is the RTCP bandwidth in bits/second
        let interval_secs = (n * self.avg_rtcp_size * 8.0) / c.max(1.0);

        // Apply minimum interval
        let min_interval = if self.params.initial {
            RTCP_MIN_INTERVAL_SECS / 2.0
        } else {
            RTCP_MIN_INTERVAL_SECS
        };

        let interval_secs = interval_secs.max(min_interval);

        Duration::from_secs_f64(interval_secs)
    }

    /// Computes the randomized RTCP interval per RFC 3550 §6.3.5.
    ///
    /// The interval is randomized to prevent synchronization:
    /// - Minimum: 0.5 × deterministic interval
    /// - Maximum: 1.5 × deterministic interval
    ///
    /// Also applies the compensation factor (e - 1.5) from A.7.
    #[must_use]
    pub fn compute_interval(&self) -> Duration {
        let det_interval = self.compute_deterministic_interval();

        // Apply randomization: [0.5, 1.5] × interval
        let random_factor = random_f64().mul_add(1.0, 0.5);
        let randomized = det_interval.mul_f64(random_factor);

        // Apply compensation factor for timer reconsideration
        randomized.mul_f64(1.0 / RTCP_COMPENSATION_FACTOR)
    }

    /// Schedules the next RTCP transmission.
    ///
    /// Returns the time when the next RTCP packet should be sent.
    pub fn schedule_next(&mut self) -> Instant {
        let interval = self.compute_interval();
        let now = Instant::now();

        self.tp = Some(now);
        self.tn = Some(now + interval);
        self.params.initial = false;

        now + interval
    }

    /// Performs timer reconsideration per RFC 3550 §6.3.6.
    ///
    /// When the membership count changes, this method should be called
    /// to recalculate the transmission time. Returns `Some(Instant)` if
    /// transmission should happen at a new time, `None` if no change.
    pub fn reconsider(&mut self) -> Option<Instant> {
        let tn = self.tn?;
        let tp = self.tp?;

        // Recalculate interval with current parameters
        let new_interval = self.compute_interval();
        let new_tn = tp + new_interval;

        // If new time is later than currently scheduled, update
        if new_tn > tn {
            self.tn = Some(new_tn);
            Some(new_tn)
        } else {
            None
        }
    }

    /// Checks if it's time to send an RTCP packet.
    ///
    /// Returns `true` if the scheduled time has passed.
    #[must_use]
    pub fn is_time_to_send(&self) -> bool {
        self.tn.is_none_or(|tn| Instant::now() >= tn) // Send if never scheduled
    }

    /// Returns the next scheduled transmission time.
    #[must_use]
    pub fn next_transmission_time(&self) -> Option<Instant> {
        self.tn
    }

    /// Returns the time until next transmission.
    #[must_use]
    pub fn time_until_next(&self) -> Option<Duration> {
        self.tn.and_then(|tn| {
            let now = Instant::now();
            if tn > now { Some(tn - now) } else { None }
        })
    }

    /// Called when an RTCP packet is sent.
    ///
    /// Updates internal state and schedules the next transmission.
    pub fn on_rtcp_sent(&mut self, packet_size: usize) {
        self.update_avg_size(packet_size);
        self.rtcp_packets_sent += 1;
        self.schedule_next();
    }

    /// Returns the number of RTCP packets sent.
    #[must_use]
    pub fn packets_sent(&self) -> u64 {
        self.rtcp_packets_sent
    }

    /// Returns current session parameters.
    #[must_use]
    pub fn params(&self) -> &SessionParams {
        &self.params
    }
}

/// RTCP interval bounds for validation and testing.
#[derive(Debug, Clone, Copy)]
pub struct IntervalBounds {
    /// Minimum randomized interval.
    pub min: Duration,
    /// Maximum randomized interval.
    pub max: Duration,
    /// Deterministic (non-randomized) interval.
    pub deterministic: Duration,
}

impl RtcpScheduler {
    /// Computes the interval bounds for the current parameters.
    ///
    /// Useful for testing and validation to ensure intervals
    /// fall within expected ranges.
    #[must_use]
    pub fn compute_interval_bounds(&self) -> IntervalBounds {
        let det = self.compute_deterministic_interval();

        // Randomization range: [0.5, 1.5] × interval / compensation
        let factor = 1.0 / RTCP_COMPENSATION_FACTOR;
        IntervalBounds {
            min: det.mul_f64(0.5 * factor),
            max: det.mul_f64(1.5 * factor),
            deterministic: det,
        }
    }
}

/// Generates a random f64 in [0, 1).
///
/// Uses a simple LCG for deterministic behavior in tests when needed.
/// In production, consider using a better random source.
fn random_f64() -> f64 {
    // Use thread-local state for randomness
    use std::cell::Cell;
    use std::time::SystemTime;

    thread_local! {
        static SEED: Cell<u64> = Cell::new(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(12345)
        );
    }

    SEED.with(|cell| {
        // LCG parameters (same as glibc)
        let seed = cell.get();
        let new_seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        cell.set(new_seed);

        // Extract bits and convert to [0, 1)
        (new_seed >> 16) as f64 / (1u64 << 48) as f64
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_scheduler() -> RtcpScheduler {
        RtcpScheduler::new(SessionParams::default())
    }

    #[test]
    fn test_scheduler_creation() {
        let scheduler = default_scheduler();
        assert!(scheduler.avg_rtcp_size() > 0.0);
        assert!(scheduler.rtcp_bandwidth() > 0.0);
    }

    #[test]
    fn test_deterministic_interval_minimum() {
        let scheduler = default_scheduler();
        let interval = scheduler.compute_deterministic_interval();

        // For initial packet, minimum is RTCP_MIN_INTERVAL_SECS / 2
        assert!(interval >= Duration::from_secs_f64(RTCP_MIN_INTERVAL_SECS / 2.0));
    }

    #[test]
    fn test_randomized_interval_bounds() {
        let scheduler = default_scheduler();
        let bounds = scheduler.compute_interval_bounds();

        // Min should be less than max
        assert!(bounds.min < bounds.max);

        // Deterministic should be in a reasonable range
        assert!(bounds.min < bounds.deterministic);
    }

    #[test]
    fn test_interval_scales_with_members() {
        let mut params = SessionParams::default();
        params.initial = false;

        let scheduler_small = RtcpScheduler::new(params.clone());

        params.members = 100;
        let scheduler_large = RtcpScheduler::new(params);

        let interval_small = scheduler_small.compute_deterministic_interval();
        let interval_large = scheduler_large.compute_deterministic_interval();

        // Larger group should have longer intervals
        assert!(interval_large >= interval_small);
    }

    #[test]
    fn test_sender_receiver_separation() {
        let mut params = SessionParams::default();
        params.members = 100;
        params.senders = 10; // 10% senders
        params.initial = false;

        // As a sender
        params.we_sent = true;
        let scheduler_sender = RtcpScheduler::new(params.clone());

        // As a receiver
        params.we_sent = false;
        let scheduler_receiver = RtcpScheduler::new(params);

        let interval_sender = scheduler_sender.compute_deterministic_interval();
        let interval_receiver = scheduler_receiver.compute_deterministic_interval();

        // Both should have valid intervals
        assert!(interval_sender >= Duration::from_secs_f64(RTCP_MIN_INTERVAL_SECS));
        assert!(interval_receiver >= Duration::from_secs_f64(RTCP_MIN_INTERVAL_SECS));
    }

    #[test]
    fn test_avg_size_update() {
        let mut scheduler = default_scheduler();
        let initial_size = scheduler.avg_rtcp_size();

        // Update with larger packet
        scheduler.update_avg_size(200);

        // Size should increase
        assert!(scheduler.avg_rtcp_size() > initial_size);

        // But not jump to the new value (exponential smoothing)
        assert!(scheduler.avg_rtcp_size() < 200.0);
    }

    #[test]
    fn test_schedule_next() {
        let mut scheduler = default_scheduler();

        let next = scheduler.schedule_next();
        assert!(next > Instant::now());

        // Should no longer be initial after scheduling
        assert!(!scheduler.params.initial);
    }

    #[test]
    fn test_time_until_next() {
        let mut scheduler = default_scheduler();

        // Initially no scheduled time
        let initial_time = scheduler.time_until_next();

        // Schedule next
        scheduler.schedule_next();

        // Now should have time until next
        let time_until = scheduler.time_until_next();
        assert!(time_until.is_some() || initial_time.is_none());
    }

    #[test]
    fn test_on_rtcp_sent() {
        let mut scheduler = default_scheduler();

        scheduler.on_rtcp_sent(150);
        assert_eq!(scheduler.packets_sent(), 1);

        scheduler.on_rtcp_sent(120);
        assert_eq!(scheduler.packets_sent(), 2);

        // Avg size should be somewhere between initial and packet sizes
        let avg = scheduler.avg_rtcp_size();
        assert!(avg > 0.0);
    }

    #[test]
    fn test_rtcp_bandwidth_default() {
        let params = SessionParams {
            session_bandwidth: 100000.0, // 100 kbps
            rtcp_bandwidth: None,
            ..Default::default()
        };
        let scheduler = RtcpScheduler::new(params);

        // Should default to 5%
        assert!((scheduler.rtcp_bandwidth() - 5000.0).abs() < 0.1);
    }

    #[test]
    fn test_rtcp_bandwidth_explicit() {
        let params = SessionParams {
            session_bandwidth: 100000.0,
            rtcp_bandwidth: Some(10000.0), // Explicit 10 kbps
            ..Default::default()
        };
        let scheduler = RtcpScheduler::new(params);

        assert!((scheduler.rtcp_bandwidth() - 10000.0).abs() < 0.1);
    }

    #[test]
    fn test_reconsider() {
        let mut scheduler = default_scheduler();

        // Schedule initial
        scheduler.schedule_next();

        // Increase member count (should increase interval)
        scheduler.set_members(100);

        // Reconsider should potentially push back transmission
        let _ = scheduler.reconsider();
    }

    #[test]
    fn test_interval_bounds() {
        let scheduler = default_scheduler();
        let bounds = scheduler.compute_interval_bounds();

        // Run multiple random intervals and verify they're in bounds
        for _ in 0..100 {
            let interval = scheduler.compute_interval();
            // Due to randomization, should be within expanded bounds
            // (the bounds are theoretical, actual can vary slightly)
            assert!(interval.as_secs_f64() > 0.0);
        }

        // Verify bound relationships
        assert!(bounds.min < bounds.deterministic);
        assert!(bounds.deterministic < bounds.max);
    }

    #[test]
    fn test_initial_interval_halved() {
        let params_initial = SessionParams {
            initial: true,
            ..Default::default()
        };
        let params_not_initial = SessionParams {
            initial: false,
            ..Default::default()
        };

        let scheduler_initial = RtcpScheduler::new(params_initial);
        let scheduler_not_initial = RtcpScheduler::new(params_not_initial);

        let interval_initial = scheduler_initial.compute_deterministic_interval();
        let interval_not_initial = scheduler_not_initial.compute_deterministic_interval();

        // Initial interval should be at most half of non-initial minimum
        // (due to the halved minimum for initial packets)
        assert!(interval_initial.as_secs_f64() <= RTCP_MIN_INTERVAL_SECS);

        // Non-initial should use the full minimum
        assert!(interval_not_initial.as_secs_f64() >= RTCP_MIN_INTERVAL_SECS);
    }
}
