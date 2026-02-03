//! RTP sequence number tracking and jitter calculation.

use std::collections::VecDeque;

/// Tracks RTP sequence numbers for a single source.
///
/// Handles wraparound and detects discontinuities.
#[derive(Debug, Clone)]
pub struct SequenceTracker {
    /// Last received sequence number.
    last_seq: Option<u16>,
    /// Extended sequence number (handles wraparound).
    cycles: u32,
    /// Number of packets received.
    packets_received: u64,
    /// Number of packets lost.
    packets_lost: u64,
    /// Base sequence number (first received).
    base_seq: Option<u16>,
    /// Maximum sequence number seen.
    max_seq: u16,
}

impl SequenceTracker {
    /// Creates a new sequence tracker.
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_seq: None,
            cycles: 0,
            packets_received: 0,
            packets_lost: 0,
            base_seq: None,
            max_seq: 0,
        }
    }

    /// Updates the tracker with a new sequence number.
    ///
    /// Returns true if this packet should be processed (not a duplicate or old).
    pub fn update(&mut self, seq: u16) -> bool {
        self.packets_received += 1;

        if self.last_seq.is_none() {
            // First packet
            self.last_seq = Some(seq);
            self.base_seq = Some(seq);
            self.max_seq = seq;
            return true;
        }

        let last = self.last_seq.unwrap_or(0);

        // Calculate delta with wraparound handling
        let delta = seq.wrapping_sub(last);

        if delta == 0 {
            // Duplicate
            return false;
        }

        if delta < 0x8000 {
            // Normal case: seq is after last
            if seq < last {
                // Wraparound occurred
                self.cycles += 1;
            }

            // Check for lost packets
            if delta > 1 {
                self.packets_lost += (delta - 1) as u64;
            }

            self.last_seq = Some(seq);
            if seq > self.max_seq || (seq < 0x1000 && self.max_seq > 0xF000) {
                self.max_seq = seq;
            }

            true
        } else {
            // Packet is out of order or very late
            // Accept it but don't update tracking state
            true
        }
    }

    /// Returns the last received sequence number.
    #[must_use]
    pub fn last_seq(&self) -> Option<u16> {
        self.last_seq
    }

    /// Returns the extended sequence number (with cycles).
    #[must_use]
    pub fn extended_seq(&self) -> u64 {
        (self.cycles as u64 * 0x10000) + self.max_seq as u64
    }

    /// Returns the number of packets received.
    #[must_use]
    pub fn packets_received(&self) -> u64 {
        self.packets_received
    }

    /// Returns the number of packets lost.
    #[must_use]
    pub fn packets_lost(&self) -> u64 {
        self.packets_lost
    }

    /// Returns the packet loss fraction (0.0 to 1.0).
    #[must_use]
    pub fn loss_fraction(&self) -> f64 {
        let total = self.packets_received + self.packets_lost;
        if total == 0 {
            0.0
        } else {
            self.packets_lost as f64 / total as f64
        }
    }

    /// Resets the tracker.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Jitter calculator per RFC 3550.
#[derive(Debug, Clone)]
pub struct JitterCalculator {
    /// Current jitter estimate.
    jitter: f64,
    /// Last RTP timestamp received.
    last_rtp_ts: Option<u32>,
    /// Last arrival time in RTP timestamp units.
    last_arrival: Option<u32>,
    /// Clock rate for timestamp conversion.
    clock_rate: u32,
}

impl JitterCalculator {
    /// Creates a new jitter calculator.
    ///
    /// # Arguments
    ///
    /// * `clock_rate` - The RTP clock rate (e.g., 8000 for G.711, 48000 for Opus).
    #[must_use]
    pub fn new(clock_rate: u32) -> Self {
        Self {
            jitter: 0.0,
            last_rtp_ts: None,
            last_arrival: None,
            clock_rate,
        }
    }

    /// Updates the jitter calculation with a new packet.
    ///
    /// # Arguments
    ///
    /// * `rtp_ts` - The RTP timestamp from the packet.
    /// * `arrival_time_ms` - The local arrival time in milliseconds.
    pub fn update(&mut self, rtp_ts: u32, arrival_time_ms: u64) {
        // Convert arrival time to RTP timestamp units
        let arrival_ts = ((arrival_time_ms * self.clock_rate as u64) / 1000) as u32;

        if let (Some(last_ts), Some(last_arr)) = (self.last_rtp_ts, self.last_arrival) {
            // Calculate transit time difference
            let transit = arrival_ts.wrapping_sub(rtp_ts);
            let last_transit = last_arr.wrapping_sub(last_ts);
            let d = (transit as i64 - last_transit as i64).unsigned_abs() as f64;

            // RFC 3550 jitter calculation
            self.jitter += (d - self.jitter) / 16.0;
        }

        self.last_rtp_ts = Some(rtp_ts);
        self.last_arrival = Some(arrival_ts);
    }

    /// Returns the current jitter in RTP timestamp units.
    #[must_use]
    pub fn jitter(&self) -> u32 {
        self.jitter as u32
    }

    /// Returns the current jitter in milliseconds.
    #[must_use]
    pub fn jitter_ms(&self) -> f64 {
        (self.jitter * 1000.0) / self.clock_rate as f64
    }

    /// Resets the calculator.
    pub fn reset(&mut self) {
        self.jitter = 0.0;
        self.last_rtp_ts = None;
        self.last_arrival = None;
    }
}

/// Simple packet reorder buffer.
#[derive(Debug)]
pub struct ReorderBuffer {
    /// Maximum buffer size.
    max_size: usize,
    /// Packets waiting to be delivered.
    buffer: VecDeque<(u16, Vec<u8>)>,
    /// Next expected sequence number.
    next_seq: Option<u16>,
    /// Maximum wait time in packets.
    max_wait: u16,
}

impl ReorderBuffer {
    /// Creates a new reorder buffer.
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum number of packets to buffer.
    /// * `max_wait` - Maximum sequence number gap to wait for.
    #[must_use]
    pub fn new(max_size: usize, max_wait: u16) -> Self {
        Self {
            max_size,
            buffer: VecDeque::with_capacity(max_size),
            next_seq: None,
            max_wait,
        }
    }

    /// Inserts a packet into the buffer.
    ///
    /// Returns packets that are ready to be delivered in order.
    pub fn insert(&mut self, seq: u16, payload: Vec<u8>) -> Vec<(u16, Vec<u8>)> {
        let mut output = Vec::new();

        // Initialize on first packet
        if self.next_seq.is_none() {
            self.next_seq = Some(seq);
        }

        let next = self.next_seq.unwrap_or(seq);

        // If this is the next expected packet
        if seq == next {
            output.push((seq, payload));
            self.next_seq = Some(seq.wrapping_add(1));

            // Check if we can deliver more from buffer
            while let Some(&(buffered_seq, _)) = self.buffer.front() {
                if buffered_seq == self.next_seq.unwrap_or(0) {
                    if let Some((s, p)) = self.buffer.pop_front() {
                        output.push((s, p));
                        self.next_seq = Some(s.wrapping_add(1));
                    }
                } else {
                    break;
                }
            }
        } else {
            // Out of order - buffer it
            let delta = seq.wrapping_sub(next);

            if delta < 0x8000 && delta <= self.max_wait {
                // Future packet within acceptable range
                if self.buffer.len() < self.max_size {
                    // Insert in order
                    let pos = self
                        .buffer
                        .iter()
                        .position(|(s, _)| s.wrapping_sub(next) > delta)
                        .unwrap_or(self.buffer.len());
                    self.buffer.insert(pos, (seq, payload));
                }
            }
            // Else: too old or too far ahead, drop
        }

        output
    }

    /// Returns the number of buffered packets.
    #[must_use]
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }

    /// Clears the buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.next_seq = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_tracker() {
        let mut tracker = SequenceTracker::new();

        assert!(tracker.update(100));
        assert!(tracker.update(101));
        assert!(tracker.update(102));

        assert_eq!(tracker.packets_received(), 3);
        assert_eq!(tracker.packets_lost(), 0);
        assert_eq!(tracker.last_seq(), Some(102));
    }

    #[test]
    fn test_sequence_loss() {
        let mut tracker = SequenceTracker::new();

        tracker.update(100);
        tracker.update(105); // Lost 101-104

        assert_eq!(tracker.packets_lost(), 4);
    }

    #[test]
    fn test_sequence_wraparound() {
        let mut tracker = SequenceTracker::new();

        tracker.update(65534);
        tracker.update(65535);
        tracker.update(0); // Wraparound
        tracker.update(1);

        assert_eq!(tracker.packets_received(), 4);
        assert_eq!(tracker.packets_lost(), 0);
    }

    #[test]
    fn test_jitter_calculator() {
        let mut jitter = JitterCalculator::new(8000);

        jitter.update(0, 0);
        jitter.update(160, 20); // 20ms interval for G.711

        // Initial jitter should be minimal with perfect timing
        assert!(jitter.jitter_ms() < 10.0);
    }

    #[test]
    fn test_reorder_buffer() {
        let mut buffer = ReorderBuffer::new(10, 5);

        // In-order delivery
        let out = buffer.insert(100, vec![1]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 100);

        // Out of order
        let out = buffer.insert(103, vec![4]);
        assert_eq!(out.len(), 0);

        let out = buffer.insert(101, vec![2]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 101);

        let out = buffer.insert(102, vec![3]);
        assert_eq!(out.len(), 2); // Both 102 and 103
        assert_eq!(out[0].0, 102);
        assert_eq!(out[1].0, 103);
    }
}
