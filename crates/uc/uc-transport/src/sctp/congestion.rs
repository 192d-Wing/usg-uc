//! SCTP congestion control (RFC 9260 Section 7).
//!
//! This module implements:
//! - Slow Start algorithm
//! - Congestion Avoidance algorithm
//! - Fast Retransmit (on 3 duplicate SACKs)
//! - cwnd adjustment on SACK reception

// =============================================================================
// Congestion Controller
// =============================================================================

/// Congestion control state per RFC 9260 Section 7.
///
/// SCTP uses a TCP-like congestion control algorithm with:
/// - Slow Start (cwnd < ssthresh)
/// - Congestion Avoidance (cwnd >= ssthresh)
/// - Fast Retransmit on 3 duplicate acknowledgements
#[derive(Debug, Clone)]
pub struct CongestionController {
    /// Congestion window (bytes).
    cwnd: u32,
    /// Slow-start threshold (bytes).
    ssthresh: u32,
    /// Partial bytes acknowledged (for congestion avoidance).
    partial_bytes_acked: u32,
    /// Current flight size (bytes of outstanding data).
    flight_size: u32,
    /// Path MTU.
    mtu: u32,
    /// Initial cwnd value.
    initial_cwnd: u32,
    /// Number of consecutive duplicate SACKs.
    dup_sack_count: u32,
    /// Whether we're in fast recovery.
    in_fast_recovery: bool,
    /// TSN that triggered fast recovery (for exit condition).
    fast_recovery_exit_tsn: Option<u32>,
}

impl CongestionController {
    /// Default initial cwnd (4 MTUs per RFC 9260 Section 7.2.1).
    pub const DEFAULT_INITIAL_CWND_MTUS: u32 = 4;
    /// Default MTU for SCTP.
    pub const DEFAULT_MTU: u32 = 1280;
    /// Initial ssthresh (very large, effectively infinite).
    pub const INITIAL_SSTHRESH: u32 = u32::MAX;
    /// Threshold for fast retransmit (3 duplicate SACKs).
    pub const FAST_RETRANSMIT_THRESHOLD: u32 = 3;

    /// Creates a new congestion controller with default settings.
    pub fn new() -> Self {
        Self::with_mtu(Self::DEFAULT_MTU)
    }

    /// Creates a new congestion controller with the specified MTU.
    pub fn with_mtu(mtu: u32) -> Self {
        let initial_cwnd = Self::calculate_initial_cwnd(mtu);

        Self {
            cwnd: initial_cwnd,
            ssthresh: Self::INITIAL_SSTHRESH,
            partial_bytes_acked: 0,
            flight_size: 0,
            mtu,
            initial_cwnd,
            dup_sack_count: 0,
            in_fast_recovery: false,
            fast_recovery_exit_tsn: None,
        }
    }

    /// Calculates initial cwnd per RFC 9260 Section 7.2.1.
    ///
    /// cwnd = min(4*MTU, max(2*MTU, 4380))
    fn calculate_initial_cwnd(mtu: u32) -> u32 {
        let four_mtu = 4 * mtu;
        let two_mtu = 2 * mtu;
        four_mtu.min(two_mtu.max(4380))
    }

    /// Returns the current congestion window.
    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    /// Returns the slow-start threshold.
    pub fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// Returns the current flight size.
    pub fn flight_size(&self) -> u32 {
        self.flight_size
    }

    /// Returns the MTU.
    pub fn mtu(&self) -> u32 {
        self.mtu
    }

    /// Returns true if in slow start phase.
    pub fn is_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// Returns true if in fast recovery.
    pub fn is_fast_recovery(&self) -> bool {
        self.in_fast_recovery
    }

    /// Returns the number of bytes that can be sent (cwnd - flight_size).
    pub fn available_window(&self) -> u32 {
        self.cwnd.saturating_sub(self.flight_size)
    }

    /// Records that data was sent, increasing flight size.
    pub fn on_data_sent(&mut self, bytes: u32) {
        self.flight_size = self.flight_size.saturating_add(bytes);
    }

    /// Processes a SACK, updating cwnd based on acknowledged bytes.
    ///
    /// Per RFC 9260 Section 7.2.1-7.2.2:
    /// - In slow start: cwnd += min(bytes_acked, MTU)
    /// - In congestion avoidance: cwnd += MTU when cwnd bytes are acked
    pub fn on_sack(&mut self, bytes_acked: u32, is_new_ack: bool) {
        // Reduce flight size
        self.flight_size = self.flight_size.saturating_sub(bytes_acked);

        if !is_new_ack {
            // Duplicate SACK
            self.on_duplicate_sack();
            return;
        }

        // Reset duplicate counter on new ACK
        self.dup_sack_count = 0;

        // Check fast recovery exit
        if self.in_fast_recovery
            && let Some(exit_tsn) = self.fast_recovery_exit_tsn
        {
            // Exit fast recovery when the triggering TSN is acknowledged
            // For simplicity, we'll just exit after any new ack
            self.in_fast_recovery = false;
            self.fast_recovery_exit_tsn = None;
            tracing::debug!("Exiting fast recovery after TSN {exit_tsn} acked");
        }

        if self.is_slow_start() {
            // Slow Start: cwnd += min(bytes_acked, MTU)
            let increase = bytes_acked.min(self.mtu);
            self.cwnd = self.cwnd.saturating_add(increase);
            tracing::trace!(cwnd = self.cwnd, increase, "Slow start: increased cwnd");
        } else {
            // Congestion Avoidance: increase cwnd by MTU when cwnd worth of bytes acked
            self.partial_bytes_acked = self.partial_bytes_acked.saturating_add(bytes_acked);

            if self.partial_bytes_acked >= self.cwnd {
                self.partial_bytes_acked = self.partial_bytes_acked.saturating_sub(self.cwnd);
                self.cwnd = self.cwnd.saturating_add(self.mtu);
                tracing::trace!(cwnd = self.cwnd, "Congestion avoidance: increased cwnd");
            }
        }
    }

    /// Handles a duplicate SACK.
    fn on_duplicate_sack(&mut self) {
        self.dup_sack_count += 1;

        if self.dup_sack_count >= Self::FAST_RETRANSMIT_THRESHOLD && !self.in_fast_recovery {
            // Enter fast recovery
            self.enter_fast_recovery();
        }
    }

    /// Enters fast recovery mode.
    ///
    /// Per RFC 9260 Section 7.2.4:
    /// - ssthresh = max(cwnd/2, 4*MTU)
    /// - cwnd = ssthresh
    fn enter_fast_recovery(&mut self) {
        let four_mtu = 4 * self.mtu;
        self.ssthresh = (self.cwnd / 2).max(four_mtu);
        self.cwnd = self.ssthresh;
        self.in_fast_recovery = true;
        self.partial_bytes_acked = 0;

        tracing::debug!(
            cwnd = self.cwnd,
            ssthresh = self.ssthresh,
            "Entered fast recovery"
        );
    }

    /// Sets the fast recovery exit TSN.
    pub fn set_fast_recovery_exit_tsn(&mut self, tsn: u32) {
        self.fast_recovery_exit_tsn = Some(tsn);
    }

    /// Handles ECN-CE (Congestion Experienced) notification.
    ///
    /// Per RFC 9260 Section 7.2.5, when a packet is received with the
    /// CE bit set in the IP header (indicated via ECNE chunk), the sender
    /// should reduce cwnd similar to packet loss detection:
    /// - ssthresh = max(cwnd/2, 4*MTU)
    /// - cwnd = ssthresh
    ///
    /// Unlike timeout, cwnd is set to ssthresh (not MTU), since ECN provides
    /// earlier notification than actual packet loss.
    ///
    /// Returns true if cwnd was reduced, false if already in ECN response.
    pub fn on_ecn_ce_received(&mut self) -> bool {
        // Avoid reducing cwnd multiple times for the same congestion event
        // Similar to fast recovery - don't double-reduce
        if self.in_fast_recovery {
            tracing::trace!("ECN CE received but already in fast recovery, ignoring");
            return false;
        }

        let four_mtu = 4 * self.mtu;
        self.ssthresh = (self.cwnd / 2).max(four_mtu);
        self.cwnd = self.ssthresh;
        self.partial_bytes_acked = 0;
        // Enter a fast-recovery-like state to prevent further reductions
        self.in_fast_recovery = true;

        tracing::debug!(
            cwnd = self.cwnd,
            ssthresh = self.ssthresh,
            "ECN CE received: reduced cwnd"
        );

        true
    }

    /// Handles a retransmission timeout.
    ///
    /// Per RFC 9260 Section 7.2.3:
    /// - ssthresh = max(cwnd/2, 4*MTU)
    /// - cwnd = MTU
    pub fn on_timeout(&mut self) {
        let four_mtu = 4 * self.mtu;
        self.ssthresh = (self.cwnd / 2).max(four_mtu);
        self.cwnd = self.mtu;
        self.partial_bytes_acked = 0;
        self.in_fast_recovery = false;
        self.fast_recovery_exit_tsn = None;
        self.dup_sack_count = 0;

        tracing::debug!(
            cwnd = self.cwnd,
            ssthresh = self.ssthresh,
            "Timeout: reduced cwnd to MTU"
        );
    }

    /// Updates the MTU (e.g., from PMTU discovery).
    pub fn update_mtu(&mut self, new_mtu: u32) {
        self.mtu = new_mtu;
        // Recalculate initial cwnd but don't reduce current cwnd
        self.initial_cwnd = Self::calculate_initial_cwnd(new_mtu);
    }

    /// Resets the congestion controller to initial state.
    pub fn reset(&mut self) {
        self.cwnd = self.initial_cwnd;
        self.ssthresh = Self::INITIAL_SSTHRESH;
        self.partial_bytes_acked = 0;
        self.flight_size = 0;
        self.dup_sack_count = 0;
        self.in_fast_recovery = false;
        self.fast_recovery_exit_tsn = None;
    }
}

impl Default for CongestionController {
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
    fn test_initial_cwnd_calculation() {
        // For MTU 1280: min(5120, max(2560, 4380)) = min(5120, 4380) = 4380
        let cc = CongestionController::with_mtu(1280);
        assert_eq!(cc.cwnd(), 4380);

        // For MTU 1500: min(6000, max(3000, 4380)) = min(6000, 4380) = 4380
        let cc = CongestionController::with_mtu(1500);
        assert_eq!(cc.cwnd(), 4380);

        // For MTU 500: min(2000, max(1000, 4380)) = min(2000, 4380) = 2000
        let cc = CongestionController::with_mtu(500);
        assert_eq!(cc.cwnd(), 2000);
    }

    #[test]
    fn test_slow_start() {
        let mut cc = CongestionController::with_mtu(1000);
        cc.ssthresh = 10000; // Force slow start

        assert!(cc.is_slow_start());

        let initial_cwnd = cc.cwnd();
        cc.on_sack(1000, true);

        // cwnd should increase by MTU in slow start
        assert!(cc.cwnd() > initial_cwnd);
    }

    #[test]
    fn test_slow_start_limited_increase() {
        let mut cc = CongestionController::with_mtu(1000);
        cc.ssthresh = 100000;

        let initial_cwnd = cc.cwnd();
        // Ack more than MTU
        cc.on_sack(5000, true);

        // cwnd should increase by min(bytes_acked, MTU) = MTU
        assert_eq!(cc.cwnd(), initial_cwnd + 1000);
    }

    #[test]
    fn test_congestion_avoidance() {
        let mut cc = CongestionController::with_mtu(1000);
        cc.cwnd = 5000;
        cc.ssthresh = 4000; // In congestion avoidance

        assert!(!cc.is_slow_start());

        let initial_cwnd = cc.cwnd();

        // Ack partial bytes - should not increase cwnd yet
        cc.on_sack(2000, true);
        assert_eq!(cc.cwnd(), initial_cwnd);

        // Ack more bytes to exceed cwnd worth
        cc.on_sack(3000, true);
        // Now cwnd should increase by MTU
        assert_eq!(cc.cwnd(), initial_cwnd + 1000);
    }

    #[test]
    fn test_timeout_reduction() {
        let mut cc = CongestionController::with_mtu(1000);
        cc.cwnd = 10000;
        cc.ssthresh = 20000;

        cc.on_timeout();

        // cwnd should be reduced to MTU
        assert_eq!(cc.cwnd(), 1000);
        // ssthresh = max(cwnd/2, 4*MTU) = max(5000, 4000) = 5000
        assert_eq!(cc.ssthresh(), 5000);
    }

    #[test]
    fn test_fast_retransmit() {
        let mut cc = CongestionController::with_mtu(1000);
        cc.cwnd = 10000;
        cc.ssthresh = 20000;

        assert!(!cc.is_fast_recovery());

        // Receive 3 duplicate SACKs
        cc.on_sack(0, false); // dup 1
        cc.on_sack(0, false); // dup 2
        assert!(!cc.is_fast_recovery());

        cc.on_sack(0, false); // dup 3 - triggers fast recovery
        assert!(cc.is_fast_recovery());

        // ssthresh = max(10000/2, 4000) = 5000
        assert_eq!(cc.ssthresh(), 5000);
        // cwnd = ssthresh = 5000
        assert_eq!(cc.cwnd(), 5000);
    }

    #[test]
    fn test_fast_recovery_exit() {
        let mut cc = CongestionController::with_mtu(1000);
        cc.cwnd = 10000;

        // Trigger fast recovery
        for _ in 0..3 {
            cc.on_sack(0, false);
        }
        assert!(cc.is_fast_recovery());

        cc.set_fast_recovery_exit_tsn(100);

        // New ACK should exit fast recovery
        cc.on_sack(1000, true);
        assert!(!cc.is_fast_recovery());
    }

    #[test]
    fn test_flight_size_tracking() {
        let mut cc = CongestionController::new();

        assert_eq!(cc.flight_size(), 0);

        cc.on_data_sent(1000);
        assert_eq!(cc.flight_size(), 1000);

        cc.on_data_sent(500);
        assert_eq!(cc.flight_size(), 1500);

        cc.on_sack(700, true);
        assert_eq!(cc.flight_size(), 800);
    }

    #[test]
    fn test_available_window() {
        let mut cc = CongestionController::with_mtu(1000);
        // cwnd should be ~4380 for MTU 1000

        assert_eq!(cc.available_window(), cc.cwnd());

        cc.on_data_sent(1000);
        assert_eq!(cc.available_window(), cc.cwnd() - 1000);

        // If flight_size exceeds cwnd, available should be 0
        cc.flight_size = cc.cwnd() + 1000;
        assert_eq!(cc.available_window(), 0);
    }

    #[test]
    fn test_reset() {
        let mut cc = CongestionController::with_mtu(1000);
        cc.cwnd = 20000;
        cc.ssthresh = 10000;
        cc.flight_size = 5000;
        cc.in_fast_recovery = true;

        cc.reset();

        assert_eq!(cc.cwnd(), cc.initial_cwnd);
        assert_eq!(cc.ssthresh(), CongestionController::INITIAL_SSTHRESH);
        assert_eq!(cc.flight_size(), 0);
        assert!(!cc.in_fast_recovery);
    }

    #[test]
    fn test_mtu_update() {
        let mut cc = CongestionController::with_mtu(1000);
        let initial_cwnd = cc.cwnd();

        cc.update_mtu(1500);

        assert_eq!(cc.mtu(), 1500);
        // cwnd should not decrease
        assert!(cc.cwnd() >= initial_cwnd);
    }

    #[test]
    fn test_ecn_ce_cwnd_reduction() {
        let mut cc = CongestionController::with_mtu(1000);
        cc.cwnd = 10000;
        cc.ssthresh = 20000;

        assert!(!cc.is_fast_recovery());

        // ECN CE should reduce cwnd similar to fast recovery
        let reduced = cc.on_ecn_ce_received();
        assert!(reduced);
        assert!(cc.is_fast_recovery()); // Enters fast recovery-like state

        // ssthresh = max(10000/2, 4000) = 5000
        assert_eq!(cc.ssthresh(), 5000);
        // cwnd = ssthresh = 5000 (not MTU like timeout)
        assert_eq!(cc.cwnd(), 5000);
    }

    #[test]
    fn test_ecn_ce_no_double_reduce() {
        let mut cc = CongestionController::with_mtu(1000);
        cc.cwnd = 10000;
        cc.ssthresh = 20000;

        // First ECN CE should reduce
        let reduced = cc.on_ecn_ce_received();
        assert!(reduced);
        assert_eq!(cc.cwnd(), 5000);

        // Second ECN CE should NOT reduce (already in fast recovery)
        let reduced = cc.on_ecn_ce_received();
        assert!(!reduced);
        assert_eq!(cc.cwnd(), 5000); // No change
    }

    #[test]
    fn test_ecn_vs_timeout() {
        // ECN should be less aggressive than timeout
        let mut cc_ecn = CongestionController::with_mtu(1000);
        cc_ecn.cwnd = 10000;

        let mut cc_timeout = CongestionController::with_mtu(1000);
        cc_timeout.cwnd = 10000;

        cc_ecn.on_ecn_ce_received();
        cc_timeout.on_timeout();

        // ECN: cwnd = ssthresh = max(5000, 4000) = 5000
        // Timeout: cwnd = MTU = 1000
        assert!(cc_ecn.cwnd() > cc_timeout.cwnd());
        assert_eq!(cc_ecn.cwnd(), 5000);
        assert_eq!(cc_timeout.cwnd(), 1000);
    }
}
