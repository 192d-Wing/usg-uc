//! RFC 3262 - Reliability of Provisional Responses in SIP (100rel).
//!
//! This module implements reliable provisional response handling per RFC 3262.
//!
//! ## RFC 3262 Overview
//!
//! - Provisional responses (1xx except 100) can be made reliable using the
//!   `100rel` extension
//! - Reliable provisional responses MUST be acknowledged with PRACK
//! - PRACK uses its own transaction (non-INVITE client transaction)
//! - RSeq header provides sequence numbering for reliable provisionals
//!
//! ## Usage
//!
//! 1. UAC indicates support via `Supported: 100rel` or requires via `Require: 100rel`
//! 2. UAS sends provisional response with `Require: 100rel` and `RSeq` header
//! 3. UAC acknowledges with PRACK containing `RAck` header
//! 4. UAS responds to PRACK with 200 OK
//!
//! ## Timers
//!
//! - Provisional response retransmission uses Timer T1 with exponential backoff
//! - Maximum retransmission interval is T2 (4 seconds)
//! - Total timeout is 64*T1 (32 seconds)

use std::time::{Duration, Instant};

use crate::{DEFAULT_T1, DEFAULT_T2};

/// RFC 3262 100rel extension tag.
pub const EXTENSION_100REL: &str = "100rel";

/// Reliable provisional response state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReliableProvisionalState {
    /// Waiting to send reliable provisional.
    Pending,
    /// Provisional sent, waiting for PRACK.
    WaitingForPrack,
    /// PRACK received, processing.
    PrackReceived,
    /// Acknowledged (PRACK 200 sent).
    Acknowledged,
    /// Timed out waiting for PRACK.
    TimedOut,
}

impl std::fmt::Display for ReliableProvisionalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::WaitingForPrack => write!(f, "WaitingForPrack"),
            Self::PrackReceived => write!(f, "PrackReceived"),
            Self::Acknowledged => write!(f, "Acknowledged"),
            Self::TimedOut => write!(f, "TimedOut"),
        }
    }
}

/// RAck header value per RFC 3262 Section 7.2.
///
/// The RAck header is sent in PRACK to acknowledge a reliable provisional.
/// Format: `RAck: response-num CSeq-num method`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RAck {
    /// RSeq value from the provisional response being acknowledged.
    pub rseq: u32,
    /// CSeq sequence number of the original INVITE.
    pub cseq_num: u32,
    /// Method from the CSeq of the original INVITE (always "INVITE").
    pub method: String,
}

impl RAck {
    /// Creates a new RAck value.
    pub fn new(rseq: u32, cseq_num: u32, method: impl Into<String>) -> Self {
        Self {
            rseq,
            cseq_num,
            method: method.into(),
        }
    }

    /// Creates a RAck for an INVITE transaction.
    pub fn for_invite(rseq: u32, cseq_num: u32) -> Self {
        Self::new(rseq, cseq_num, "INVITE")
    }

    /// Formats as header value: "rseq cseq method".
    pub fn to_header_value(&self) -> String {
        format!("{} {} {}", self.rseq, self.cseq_num, self.method)
    }

    /// Parses a RAck header value.
    ///
    /// Format: `response-num CSeq-num method`
    pub fn parse(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 3 {
            return None;
        }

        let rseq = parts[0].parse().ok()?;
        let cseq_num = parts[1].parse().ok()?;
        let method = parts[2].to_string();

        Some(Self {
            rseq,
            cseq_num,
            method,
        })
    }
}

impl std::fmt::Display for RAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_header_value())
    }
}

/// Reliable provisional response tracker for UAS (server side).
///
/// Tracks reliable provisional responses sent and handles PRACK acknowledgment.
#[derive(Debug, Clone)]
pub struct ReliableProvisionalTracker {
    /// Current RSeq value (incremented for each reliable provisional).
    rseq: u32,
    /// CSeq of the INVITE being responded to.
    invite_cseq: u32,
    /// Pending reliable provisionals awaiting PRACK.
    pending: Vec<PendingProvisional>,
    /// Maximum retransmission interval.
    t2: Duration,
}

/// A pending reliable provisional response awaiting PRACK.
#[derive(Debug, Clone)]
pub struct PendingProvisional {
    /// RSeq value for this provisional.
    pub rseq: u32,
    /// Status code of the provisional (e.g., 180, 183).
    pub status_code: u16,
    /// Current retransmission interval.
    pub retransmit_interval: Duration,
    /// Time when this provisional was first sent.
    pub first_sent: Instant,
    /// Time of last transmission.
    pub last_sent: Instant,
    /// Number of retransmissions.
    pub retransmit_count: u32,
    /// Current state.
    pub state: ReliableProvisionalState,
}

impl ReliableProvisionalTracker {
    /// Creates a new tracker for an INVITE transaction.
    ///
    /// # Arguments
    ///
    /// * `invite_cseq` - CSeq sequence number of the INVITE
    /// * `initial_rseq` - Initial RSeq value (should be random per RFC 3262)
    pub fn new(invite_cseq: u32, initial_rseq: u32) -> Self {
        Self {
            rseq: initial_rseq,
            invite_cseq,
            pending: Vec::new(),
            t2: DEFAULT_T2,
        }
    }

    /// Creates a tracker with a random initial RSeq.
    pub fn new_random(invite_cseq: u32) -> Self {
        // Use a random value between 1 and 2^31 per RFC 3262
        let initial_rseq = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u32)
            .unwrap_or(1))
            % 0x7FFFFFFF
            + 1;
        Self::new(invite_cseq, initial_rseq)
    }

    /// Returns the current RSeq value.
    pub fn current_rseq(&self) -> u32 {
        self.rseq
    }

    /// Returns the INVITE CSeq this tracker is for.
    pub fn invite_cseq(&self) -> u32 {
        self.invite_cseq
    }

    /// Allocates and returns the next RSeq for a reliable provisional.
    ///
    /// Call this when sending a reliable provisional response.
    /// The returned RSeq should be included in the response's RSeq header.
    pub fn allocate_rseq(&mut self, status_code: u16) -> u32 {
        let rseq = self.rseq;
        self.rseq = self.rseq.wrapping_add(1);

        let now = Instant::now();
        self.pending.push(PendingProvisional {
            rseq,
            status_code,
            retransmit_interval: DEFAULT_T1,
            first_sent: now,
            last_sent: now,
            retransmit_count: 0,
            state: ReliableProvisionalState::WaitingForPrack,
        });

        rseq
    }

    /// Processes a received PRACK request.
    ///
    /// Returns `Ok(rseq)` if the PRACK matches a pending provisional,
    /// or `Err` with a description if the PRACK is invalid.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn receive_prack(&mut self, rack: &RAck) -> Result<u32, &'static str> {
        // Validate CSeq matches
        if rack.cseq_num != self.invite_cseq {
            return Err("RAck CSeq does not match INVITE");
        }

        if rack.method != "INVITE" {
            return Err("RAck method must be INVITE");
        }

        // Find and acknowledge the matching provisional
        for pending in &mut self.pending {
            if pending.rseq == rack.rseq {
                if pending.state == ReliableProvisionalState::WaitingForPrack {
                    pending.state = ReliableProvisionalState::PrackReceived;
                    return Ok(pending.rseq);
                } else if pending.state == ReliableProvisionalState::PrackReceived
                    || pending.state == ReliableProvisionalState::Acknowledged
                {
                    // PRACK retransmission, that's OK
                    return Ok(pending.rseq);
                }
            }
        }

        // Check if RSeq is too low (already acknowledged and removed)
        Err("Unknown or stale RSeq value")
    }

    /// Marks a provisional as fully acknowledged (after 200 to PRACK).
    pub fn mark_acknowledged(&mut self, rseq: u32) {
        for pending in &mut self.pending {
            if pending.rseq == rseq {
                pending.state = ReliableProvisionalState::Acknowledged;
            }
        }
    }

    /// Checks if any provisional needs retransmission.
    ///
    /// Returns the RSeq of provisionals that need to be retransmitted.
    pub fn check_retransmissions(&mut self) -> Vec<u32> {
        let now = Instant::now();
        let mut to_retransmit = Vec::new();

        for pending in &mut self.pending {
            if pending.state != ReliableProvisionalState::WaitingForPrack {
                continue;
            }

            let elapsed = now.duration_since(pending.last_sent);
            if elapsed >= pending.retransmit_interval {
                // Check for timeout (64*T1 = 32 seconds)
                let total_elapsed = now.duration_since(pending.first_sent);
                if total_elapsed >= Duration::from_millis(32000) {
                    pending.state = ReliableProvisionalState::TimedOut;
                    continue;
                }

                to_retransmit.push(pending.rseq);

                // Update retransmission state
                pending.last_sent = now;
                pending.retransmit_count += 1;

                // Double interval, cap at T2
                pending.retransmit_interval =
                    std::cmp::min(pending.retransmit_interval * 2, self.t2);
            }
        }

        to_retransmit
    }

    /// Returns true if there are any pending (unacknowledged) provisionals.
    pub fn has_pending(&self) -> bool {
        self.pending
            .iter()
            .any(|p| p.state == ReliableProvisionalState::WaitingForPrack)
    }

    /// Returns true if any provisional has timed out.
    pub fn has_timed_out(&self) -> bool {
        self.pending
            .iter()
            .any(|p| p.state == ReliableProvisionalState::TimedOut)
    }

    /// Clears all acknowledged provisionals from the pending list.
    pub fn clear_acknowledged(&mut self) {
        self.pending
            .retain(|p| p.state != ReliableProvisionalState::Acknowledged);
    }

    /// Returns the pending provisionals.
    pub fn pending(&self) -> &[PendingProvisional] {
        &self.pending
    }
}

/// Reliable provisional tracker for UAC (client side).
///
/// Tracks reliable provisional responses received and generates PRACK requests.
#[derive(Debug, Clone)]
pub struct ClientReliableProvisionalTracker {
    /// CSeq of the INVITE.
    invite_cseq: u32,
    /// Last received RSeq (for ordering).
    last_rseq: Option<u32>,
    /// Pending provisionals that need PRACK.
    pending_prack: Vec<ReceivedProvisional>,
}

/// A received reliable provisional that needs PRACK.
#[derive(Debug, Clone)]
pub struct ReceivedProvisional {
    /// RSeq value from the response.
    pub rseq: u32,
    /// Status code (e.g., 180, 183).
    pub status_code: u16,
    /// Whether PRACK has been sent.
    pub prack_sent: bool,
    /// Whether PRACK 200 OK has been received.
    pub prack_acknowledged: bool,
}

impl ClientReliableProvisionalTracker {
    /// Creates a new client-side tracker.
    pub fn new(invite_cseq: u32) -> Self {
        Self {
            invite_cseq,
            last_rseq: None,
            pending_prack: Vec::new(),
        }
    }

    /// Returns the INVITE CSeq.
    pub fn invite_cseq(&self) -> u32 {
        self.invite_cseq
    }

    /// Processes a received reliable provisional response.
    ///
    /// Returns `Ok(RAck)` if PRACK should be sent, or `Err` if the response
    /// should be discarded (e.g., out of order RSeq).
    pub fn receive_provisional(
        &mut self,
        rseq: u32,
        status_code: u16,
    ) -> Result<RAck, &'static str> {
        // RFC 3262 Section 4: RSeq must be greater than the previous one
        if let Some(last) = self.last_rseq
            && rseq <= last {
                return Err("RSeq out of order (must be greater than previous)");
            }

        self.last_rseq = Some(rseq);

        self.pending_prack.push(ReceivedProvisional {
            rseq,
            status_code,
            prack_sent: false,
            prack_acknowledged: false,
        });

        Ok(RAck::for_invite(rseq, self.invite_cseq))
    }

    /// Marks that PRACK has been sent for an RSeq.
    pub fn mark_prack_sent(&mut self, rseq: u32) {
        for pending in &mut self.pending_prack {
            if pending.rseq == rseq {
                pending.prack_sent = true;
            }
        }
    }

    /// Marks that PRACK 200 OK has been received.
    pub fn mark_prack_acknowledged(&mut self, rseq: u32) {
        for pending in &mut self.pending_prack {
            if pending.rseq == rseq {
                pending.prack_acknowledged = true;
            }
        }
    }

    /// Returns true if there are unacknowledged PRAcks.
    pub fn has_pending_prack(&self) -> bool {
        self.pending_prack
            .iter()
            .any(|p| p.prack_sent && !p.prack_acknowledged)
    }

    /// Returns the pending provisionals.
    pub fn pending(&self) -> &[ReceivedProvisional] {
        &self.pending_prack
    }

    /// Clears acknowledged entries.
    pub fn clear_acknowledged(&mut self) {
        self.pending_prack.retain(|p| !p.prack_acknowledged);
    }
}

/// Checks if 100rel is supported based on Supported header.
pub fn supports_100rel(supported_header: &str) -> bool {
    supported_header
        .split(',')
        .any(|ext| ext.trim().eq_ignore_ascii_case(EXTENSION_100REL))
}

/// Checks if 100rel is required based on Require header.
pub fn requires_100rel(require_header: &str) -> bool {
    require_header
        .split(',')
        .any(|ext| ext.trim().eq_ignore_ascii_case(EXTENSION_100REL))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rack_creation() {
        let rack = RAck::for_invite(1, 100);
        assert_eq!(rack.rseq, 1);
        assert_eq!(rack.cseq_num, 100);
        assert_eq!(rack.method, "INVITE");
    }

    #[test]
    fn test_rack_to_header_value() {
        let rack = RAck::for_invite(1, 100);
        assert_eq!(rack.to_header_value(), "1 100 INVITE");
    }

    #[test]
    fn test_rack_parse() {
        let rack = RAck::parse("1 100 INVITE").unwrap();
        assert_eq!(rack.rseq, 1);
        assert_eq!(rack.cseq_num, 100);
        assert_eq!(rack.method, "INVITE");
    }

    #[test]
    fn test_rack_parse_invalid() {
        assert!(RAck::parse("invalid").is_none());
        assert!(RAck::parse("1 100").is_none());
        assert!(RAck::parse("not a number 100 INVITE").is_none());
    }

    #[test]
    fn test_tracker_allocate_rseq() {
        let mut tracker = ReliableProvisionalTracker::new(100, 1);

        let rseq1 = tracker.allocate_rseq(180);
        assert_eq!(rseq1, 1);

        let rseq2 = tracker.allocate_rseq(183);
        assert_eq!(rseq2, 2);

        assert_eq!(tracker.pending().len(), 2);
    }

    #[test]
    fn test_tracker_receive_prack() {
        let mut tracker = ReliableProvisionalTracker::new(100, 1);
        let rseq = tracker.allocate_rseq(180);

        let rack = RAck::for_invite(rseq, 100);
        let result = tracker.receive_prack(&rack);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), rseq);
    }

    #[test]
    fn test_tracker_receive_prack_wrong_cseq() {
        let mut tracker = ReliableProvisionalTracker::new(100, 1);
        tracker.allocate_rseq(180);

        let rack = RAck::for_invite(1, 99); // Wrong CSeq
        let result = tracker.receive_prack(&rack);
        assert!(result.is_err());
    }

    #[test]
    fn test_tracker_receive_prack_unknown_rseq() {
        let mut tracker = ReliableProvisionalTracker::new(100, 1);
        tracker.allocate_rseq(180);

        let rack = RAck::for_invite(999, 100); // Unknown RSeq
        let result = tracker.receive_prack(&rack);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_tracker_receive_provisional() {
        let mut tracker = ClientReliableProvisionalTracker::new(100);

        let rack = tracker.receive_provisional(1, 180).unwrap();
        assert_eq!(rack.rseq, 1);
        assert_eq!(rack.cseq_num, 100);

        let rack2 = tracker.receive_provisional(2, 183).unwrap();
        assert_eq!(rack2.rseq, 2);
    }

    #[test]
    fn test_client_tracker_out_of_order_rseq() {
        let mut tracker = ClientReliableProvisionalTracker::new(100);

        tracker.receive_provisional(5, 180).unwrap();

        // RSeq must be greater than previous
        let result = tracker.receive_provisional(3, 183);
        assert!(result.is_err());

        // Same RSeq is also rejected
        let result = tracker.receive_provisional(5, 183);
        assert!(result.is_err());
    }

    #[test]
    fn test_supports_100rel() {
        assert!(supports_100rel("100rel"));
        assert!(supports_100rel("timer, 100rel"));
        assert!(supports_100rel("100rel, timer"));
        assert!(supports_100rel("  100rel  "));
        assert!(!supports_100rel("timer"));
        assert!(!supports_100rel(""));
    }

    #[test]
    fn test_requires_100rel() {
        assert!(requires_100rel("100rel"));
        assert!(requires_100rel("100rel, precondition"));
        assert!(!requires_100rel("precondition"));
    }

    #[test]
    fn test_reliable_provisional_state_display() {
        assert_eq!(ReliableProvisionalState::Pending.to_string(), "Pending");
        assert_eq!(
            ReliableProvisionalState::WaitingForPrack.to_string(),
            "WaitingForPrack"
        );
        assert_eq!(
            ReliableProvisionalState::Acknowledged.to_string(),
            "Acknowledged"
        );
    }

    #[test]
    fn test_tracker_has_pending() {
        let mut tracker = ReliableProvisionalTracker::new(100, 1);
        assert!(!tracker.has_pending());

        tracker.allocate_rseq(180);
        assert!(tracker.has_pending());
    }

    #[test]
    fn test_mark_acknowledged() {
        let mut tracker = ReliableProvisionalTracker::new(100, 1);
        let rseq = tracker.allocate_rseq(180);

        let rack = RAck::for_invite(rseq, 100);
        tracker.receive_prack(&rack).unwrap();
        tracker.mark_acknowledged(rseq);

        // After marking acknowledged, has_pending should be false
        assert!(!tracker.has_pending());
    }
}
