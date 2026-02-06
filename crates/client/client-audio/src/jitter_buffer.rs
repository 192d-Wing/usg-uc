//! Jitter buffer for RTP packet reordering and timing.
//!
//! This module provides a jitter buffer that:
//! - Reorders out-of-sequence RTP packets
//! - Handles packet loss with configurable PLC (Packet Loss Concealment)
//! - Provides adaptive depth based on network conditions
//! - Smooths playback timing to remove network jitter

use bytes::Bytes;
use std::collections::BTreeMap;
use tracing::{debug, trace, warn};

/// Minimum jitter buffer depth in milliseconds.
pub const MIN_DEPTH_MS: u32 = 20;

/// Default jitter buffer depth in milliseconds.
pub const DEFAULT_DEPTH_MS: u32 = 60;

/// Maximum jitter buffer depth in milliseconds.
pub const MAX_DEPTH_MS: u32 = 200;

/// Maximum number of packets to hold in the buffer.
const MAX_BUFFER_PACKETS: usize = 100;

/// Number of consecutive late packets before increasing buffer depth.
const LATE_THRESHOLD: u32 = 3;

/// Number of consecutive on-time packets before decreasing buffer depth.
const ONTIME_THRESHOLD: u32 = 100;

/// A buffered RTP packet with metadata.
#[derive(Debug, Clone)]
pub struct BufferedPacket {
    /// RTP sequence number.
    pub sequence: u16,
    /// RTP timestamp.
    pub timestamp: u32,
    /// Payload type.
    pub payload_type: u8,
    /// Audio payload data.
    pub payload: Bytes,
    /// Time when packet was received (monotonic).
    pub received_at: std::time::Instant,
}

impl BufferedPacket {
    /// Creates a new buffered packet.
    pub fn new(sequence: u16, timestamp: u32, payload_type: u8, payload: Bytes) -> Self {
        Self {
            sequence,
            timestamp,
            payload_type,
            payload,
            received_at: std::time::Instant::now(),
        }
    }
}

/// Result of getting a packet from the jitter buffer.
#[derive(Debug)]
pub enum JitterBufferResult {
    /// Packet available for playback.
    Packet(BufferedPacket),
    /// Buffer is empty, no packet available.
    Empty,
    /// Packet was lost, PLC should be applied.
    Lost {
        /// Expected sequence number.
        expected_sequence: u16,
        /// Expected timestamp.
        expected_timestamp: u32,
    },
    /// Buffer is not yet ready (still filling).
    NotReady,
}

/// Statistics for the jitter buffer.
#[derive(Debug, Clone, Default)]
pub struct JitterBufferStats {
    /// Total packets received.
    pub packets_received: u64,
    /// Total packets played out.
    pub packets_played: u64,
    /// Total packets lost (detected gaps).
    pub packets_lost: u64,
    /// Total packets dropped (too late or buffer overflow).
    pub packets_dropped: u64,
    /// Total packets that arrived out of order.
    pub packets_reordered: u64,
    /// Current buffer depth in milliseconds.
    pub current_depth_ms: u32,
    /// Current number of packets in buffer.
    pub current_packet_count: usize,
    /// Average jitter in milliseconds.
    pub average_jitter_ms: f32,
}

/// Adaptive jitter buffer for RTP audio streams.
pub struct JitterBuffer {
    /// Packets waiting for playout, keyed by sequence number.
    packets: BTreeMap<u16, BufferedPacket>,
    /// Target buffer depth in milliseconds.
    target_depth_ms: u32,
    /// Codec clock rate (samples per second).
    clock_rate: u32,
    /// Samples per packet (frame size).
    samples_per_packet: u32,
    /// Next expected sequence number for playout.
    next_playout_sequence: Option<u16>,
    /// Last timestamp played out.
    last_playout_timestamp: Option<u32>,
    /// Number of consecutive late packets.
    late_count: u32,
    /// Number of consecutive on-time packets.
    ontime_count: u32,
    /// Whether the buffer has been primed (initial fill).
    is_primed: bool,
    /// Statistics.
    stats: JitterBufferStats,
    /// Running jitter calculation.
    jitter_accumulator: f32,
    /// Last packet arrival time for jitter calculation.
    last_arrival: Option<std::time::Instant>,
    /// Last packet timestamp for jitter calculation.
    last_timestamp: Option<u32>,
}

impl JitterBuffer {
    /// Creates a new jitter buffer.
    ///
    /// # Arguments
    /// * `clock_rate` - Codec clock rate in Hz (e.g., 8000 for G.711, 48000 for Opus)
    /// * `samples_per_packet` - Number of samples per packet (e.g., 160 for 20ms at 8kHz)
    /// * `target_depth_ms` - Initial target buffer depth in milliseconds
    pub fn new(clock_rate: u32, samples_per_packet: u32, target_depth_ms: u32) -> Self {
        let target_depth_ms = target_depth_ms.clamp(MIN_DEPTH_MS, MAX_DEPTH_MS);

        debug!(
            "Creating jitter buffer: clock_rate={}, samples_per_packet={}, target_depth={}ms",
            clock_rate, samples_per_packet, target_depth_ms
        );

        Self {
            packets: BTreeMap::new(),
            target_depth_ms,
            clock_rate,
            samples_per_packet,
            next_playout_sequence: None,
            last_playout_timestamp: None,
            late_count: 0,
            ontime_count: 0,
            is_primed: false,
            stats: JitterBufferStats {
                current_depth_ms: target_depth_ms,
                ..Default::default()
            },
            jitter_accumulator: 0.0,
            last_arrival: None,
            last_timestamp: None,
        }
    }

    /// Creates a jitter buffer with default settings for G.711 (8kHz, 20ms frames).
    pub fn for_g711() -> Self {
        Self::new(8000, 160, DEFAULT_DEPTH_MS)
    }

    /// Creates a jitter buffer with default settings for G.722 (16kHz, 20ms frames).
    pub fn for_g722() -> Self {
        Self::new(16000, 320, DEFAULT_DEPTH_MS)
    }

    /// Creates a jitter buffer with default settings for Opus (48kHz, 20ms frames).
    pub fn for_opus() -> Self {
        Self::new(48000, 960, DEFAULT_DEPTH_MS)
    }

    /// Adds a packet to the jitter buffer.
    ///
    /// Returns `true` if the packet was added, `false` if it was dropped.
    pub fn push(&mut self, packet: BufferedPacket) -> bool {
        self.stats.packets_received += 1;

        // Update jitter calculation
        self.update_jitter(&packet);

        // Check if packet is too old (already played out)
        if let Some(next_seq) = self.next_playout_sequence {
            let age = sequence_diff(packet.sequence, next_seq);
            if age < 0 {
                // Packet is older than what we've already played
                trace!(
                    "Dropping late packet: seq={}, expected>={}",
                    packet.sequence, next_seq
                );
                self.stats.packets_dropped += 1;
                self.late_count += 1;
                self.ontime_count = 0;
                self.maybe_increase_depth();
                return false;
            }

            // Check if packet is reordered
            if age > 1 {
                self.stats.packets_reordered += 1;
            }
        }

        // Check buffer overflow
        if self.packets.len() >= MAX_BUFFER_PACKETS {
            warn!("Jitter buffer overflow, dropping oldest packet");
            if let Some((&oldest_seq, _)) = self.packets.first_key_value() {
                self.packets.remove(&oldest_seq);
                self.stats.packets_dropped += 1;
            }
        }

        // Add packet to buffer
        trace!(
            "Buffering packet: seq={}, ts={}, buffer_size={}",
            packet.sequence,
            packet.timestamp,
            self.packets.len() + 1
        );
        self.packets.insert(packet.sequence, packet);

        // Update on-time count for adaptive depth
        self.ontime_count += 1;
        self.late_count = 0;
        self.maybe_decrease_depth();

        true
    }

    /// Gets the next packet for playout.
    ///
    /// This should be called at regular intervals matching the packet duration.
    pub fn pop(&mut self) -> JitterBufferResult {
        // Check if buffer is primed
        if !self.is_primed {
            let buffered_ms = self.buffered_duration_ms();
            if buffered_ms < self.target_depth_ms {
                trace!(
                    "Buffer not primed: {}ms < {}ms target",
                    buffered_ms, self.target_depth_ms
                );
                return JitterBufferResult::NotReady;
            }
            self.is_primed = true;
            debug!("Jitter buffer primed with {}ms", buffered_ms);

            // Initialize playout sequence from first packet
            if let Some((&first_seq, _)) = self.packets.first_key_value() {
                self.next_playout_sequence = Some(first_seq);
            }
        }

        // Get expected sequence number
        let expected_seq = match self.next_playout_sequence {
            Some(seq) => seq,
            None => {
                // No sequence initialized, check if we have packets
                if let Some((&first_seq, _)) = self.packets.first_key_value() {
                    self.next_playout_sequence = Some(first_seq);
                    first_seq
                } else {
                    return JitterBufferResult::Empty;
                }
            }
        };

        // Try to get the expected packet
        if let Some(packet) = self.packets.remove(&expected_seq) {
            self.stats.packets_played += 1;
            self.last_playout_timestamp = Some(packet.timestamp);
            self.next_playout_sequence = Some(expected_seq.wrapping_add(1));
            self.stats.current_packet_count = self.packets.len();
            return JitterBufferResult::Packet(packet);
        }

        // Packet is missing - check if we should wait or declare it lost
        // Look ahead to see if we have future packets
        let have_future_packets = self
            .packets
            .keys()
            .any(|&seq| sequence_diff(seq, expected_seq) > 0);

        if have_future_packets {
            // We have later packets, so this one is lost
            self.stats.packets_lost += 1;
            let expected_timestamp = self
                .last_playout_timestamp
                .map_or(0, |ts| ts.wrapping_add(self.samples_per_packet));

            self.next_playout_sequence = Some(expected_seq.wrapping_add(1));
            self.last_playout_timestamp = Some(expected_timestamp);

            debug!(
                "Packet loss detected: seq={}, have {} future packets",
                expected_seq,
                self.packets.len()
            );

            return JitterBufferResult::Lost {
                expected_sequence: expected_seq,
                expected_timestamp,
            };
        }

        // Buffer is empty
        self.stats.current_packet_count = 0;
        JitterBufferResult::Empty
    }

    /// Updates jitter calculation based on RFC 3550.
    fn update_jitter(&mut self, packet: &BufferedPacket) {
        let now = packet.received_at;

        if let (Some(last_arrival), Some(last_ts)) = (self.last_arrival, self.last_timestamp) {
            // Calculate interarrival jitter per RFC 3550
            let arrival_diff = now.duration_since(last_arrival).as_secs_f32();
            #[allow(clippy::cast_precision_loss)]
            let timestamp_diff =
                timestamp_diff(packet.timestamp, last_ts) as f32 / self.clock_rate as f32;

            let d = (arrival_diff - timestamp_diff).abs();
            self.jitter_accumulator += (d - self.jitter_accumulator) / 16.0;
            self.stats.average_jitter_ms = self.jitter_accumulator * 1000.0;
        }

        self.last_arrival = Some(now);
        self.last_timestamp = Some(packet.timestamp);
    }

    /// Calculates the buffered duration in milliseconds.
    pub fn buffered_duration_ms(&self) -> u32 {
        #[allow(clippy::cast_possible_truncation)]
        let packet_count = self.packets.len() as u32;
        let packet_duration_ms = (self.samples_per_packet * 1000) / self.clock_rate;
        packet_count * packet_duration_ms
    }

    /// Maybe increase buffer depth due to late packets.
    fn maybe_increase_depth(&mut self) {
        if self.late_count >= LATE_THRESHOLD {
            let new_depth = (self.target_depth_ms + 10).min(MAX_DEPTH_MS);
            if new_depth != self.target_depth_ms {
                debug!(
                    "Increasing jitter buffer depth: {}ms -> {}ms",
                    self.target_depth_ms, new_depth
                );
                self.target_depth_ms = new_depth;
                self.stats.current_depth_ms = new_depth;
            }
            self.late_count = 0;
        }
    }

    /// Maybe decrease buffer depth due to consistent on-time packets.
    fn maybe_decrease_depth(&mut self) {
        if self.ontime_count >= ONTIME_THRESHOLD {
            let new_depth = (self.target_depth_ms.saturating_sub(10)).max(MIN_DEPTH_MS);
            if new_depth != self.target_depth_ms {
                debug!(
                    "Decreasing jitter buffer depth: {}ms -> {}ms",
                    self.target_depth_ms, new_depth
                );
                self.target_depth_ms = new_depth;
                self.stats.current_depth_ms = new_depth;
            }
            self.ontime_count = 0;
        }
    }

    /// Resets the jitter buffer state.
    pub fn reset(&mut self) {
        debug!("Resetting jitter buffer");
        self.packets.clear();
        self.next_playout_sequence = None;
        self.last_playout_timestamp = None;
        self.late_count = 0;
        self.ontime_count = 0;
        self.is_primed = false;
        self.last_arrival = None;
        self.last_timestamp = None;
        self.jitter_accumulator = 0.0;
        self.stats.current_packet_count = 0;
    }

    /// Returns the current statistics.
    pub const fn stats(&self) -> &JitterBufferStats {
        &self.stats
    }

    /// Returns the target buffer depth in milliseconds.
    pub const fn target_depth_ms(&self) -> u32 {
        self.target_depth_ms
    }

    /// Sets the target buffer depth in milliseconds.
    pub fn set_target_depth_ms(&mut self, depth_ms: u32) {
        self.target_depth_ms = depth_ms.clamp(MIN_DEPTH_MS, MAX_DEPTH_MS);
        self.stats.current_depth_ms = self.target_depth_ms;
    }

    /// Returns the number of packets currently buffered.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Returns whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Returns whether the buffer is primed and ready for playout.
    pub const fn is_ready(&self) -> bool {
        self.is_primed
    }
}

/// Thread-safe wrapper around [`JitterBuffer`] for cross-thread access.
///
/// Shared between the RTP I/O thread (push) and the decode thread (pop).
/// The inner `BTreeMap` typically holds <10 packets, so the mutex is held
/// for less than 1 microsecond per operation.
#[derive(Clone)]
pub struct SharedJitterBuffer {
    inner: std::sync::Arc<std::sync::Mutex<JitterBuffer>>,
}

impl SharedJitterBuffer {
    /// Creates a new shared jitter buffer.
    pub fn new(clock_rate: u32, samples_per_packet: u32, target_depth_ms: u32) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(JitterBuffer::new(
                clock_rate,
                samples_per_packet,
                target_depth_ms,
            ))),
        }
    }

    /// Adds a packet to the jitter buffer.
    pub fn push(&self, packet: BufferedPacket) -> bool {
        self.inner.lock().is_ok_and(|mut jb| jb.push(packet))
    }

    /// Gets the next packet for playout.
    pub fn pop(&self) -> JitterBufferResult {
        self.inner
            .lock()
            .map_or(JitterBufferResult::Empty, |mut jb| jb.pop())
    }

    /// Returns the number of packets currently buffered.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|jb| jb.len()).unwrap_or(0)
    }

    /// Returns whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns whether the buffer is primed and ready for playout.
    pub fn is_ready(&self) -> bool {
        self.inner.lock().map(|jb| jb.is_ready()).unwrap_or(false)
    }

    /// Returns the current statistics.
    pub fn stats(&self) -> JitterBufferStats {
        self.inner
            .lock()
            .map(|jb| jb.stats().clone())
            .unwrap_or_default()
    }

    /// Returns the buffered duration in milliseconds.
    pub fn buffered_duration_ms(&self) -> u32 {
        self.inner
            .lock()
            .map(|jb| jb.buffered_duration_ms())
            .unwrap_or(0)
    }

    /// Resets the jitter buffer state.
    pub fn reset(&self) {
        if let Ok(mut jb) = self.inner.lock() {
            jb.reset();
        }
    }
}

/// Calculates the difference between two sequence numbers, handling wrap-around.
fn sequence_diff(a: u16, b: u16) -> i32 {
    let diff = a.wrapping_sub(b).cast_signed();
    i32::from(diff)
}

/// Calculates the difference between two timestamps, handling wrap-around.
const fn timestamp_diff(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b).cast_signed()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet(seq: u16, ts: u32) -> BufferedPacket {
        BufferedPacket::new(seq, ts, 0, Bytes::from_static(&[0u8; 160]))
    }

    #[test]
    fn test_jitter_buffer_creation() {
        let jb = JitterBuffer::new(8000, 160, 60);
        assert_eq!(jb.target_depth_ms(), 60);
        assert!(jb.is_empty());
        assert!(!jb.is_ready());
    }

    #[test]
    fn test_jitter_buffer_for_codecs() {
        let g711 = JitterBuffer::for_g711();
        assert_eq!(g711.clock_rate, 8000);
        assert_eq!(g711.samples_per_packet, 160);

        let g722 = JitterBuffer::for_g722();
        assert_eq!(g722.clock_rate, 16000);
        assert_eq!(g722.samples_per_packet, 320);

        let opus = JitterBuffer::for_opus();
        assert_eq!(opus.clock_rate, 48000);
        assert_eq!(opus.samples_per_packet, 960);
    }

    #[test]
    fn test_push_and_pop() {
        let mut jb = JitterBuffer::new(8000, 160, 20); // 20ms depth = 1 packet

        // Push 2 packets to prime the buffer (>= 20ms)
        assert!(jb.push(make_packet(0, 0)));
        assert!(jb.push(make_packet(1, 160)));

        // Force buffer primed state for testing
        jb.next_playout_sequence = Some(0);
        jb.is_primed = true;

        // After priming, we should get packets
        match jb.pop() {
            JitterBufferResult::Packet(p) => assert_eq!(p.sequence, 0),
            other => panic!("Expected packet, got {:?}", other),
        }
    }

    #[test]
    fn test_packet_reordering() {
        let mut jb = JitterBuffer::new(8000, 160, 40);

        // Set up initial sequence state
        jb.next_playout_sequence = Some(0);

        // Push packet 0 first (establishes baseline)
        assert!(jb.push(make_packet(0, 0)));

        // Push packet 2 (skip 1 - this triggers reorder detection)
        assert!(jb.push(make_packet(2, 320)));

        // Reorder is detected when a packet arrives that isn't the expected next sequence
        // Since we pushed 0 then 2 (skipping 1), the jitter buffer should count this
        assert!(
            jb.stats().packets_reordered > 0,
            "Expected reordered count > 0, got {}",
            jb.stats().packets_reordered
        );
    }

    #[test]
    fn test_late_packet_dropped() {
        let mut jb = JitterBuffer::new(8000, 160, 20);

        // Prime buffer
        jb.push(make_packet(5, 800));
        jb.push(make_packet(6, 960));
        jb.next_playout_sequence = Some(5);
        jb.is_primed = true;

        // Pop one packet
        jb.pop();

        // Now push an old packet
        assert!(!jb.push(make_packet(3, 480)));
        assert!(jb.stats().packets_dropped > 0);
    }

    #[test]
    fn test_packet_loss_detection() {
        let mut jb = JitterBuffer::new(8000, 160, 20);

        // Push packets with a gap
        jb.push(make_packet(0, 0));
        jb.push(make_packet(2, 320)); // Skip sequence 1
        jb.next_playout_sequence = Some(0);
        jb.is_primed = true;

        // Get first packet
        match jb.pop() {
            JitterBufferResult::Packet(p) => assert_eq!(p.sequence, 0),
            _ => panic!("Expected packet 0"),
        }

        // Next should detect loss
        match jb.pop() {
            JitterBufferResult::Lost {
                expected_sequence, ..
            } => {
                assert_eq!(expected_sequence, 1);
            }
            _ => panic!("Expected loss detection"),
        }

        assert!(jb.stats().packets_lost > 0);
    }

    #[test]
    fn test_sequence_diff() {
        assert_eq!(sequence_diff(5, 3), 2);
        assert_eq!(sequence_diff(3, 5), -2);
        assert_eq!(sequence_diff(0, 65535), 1); // Wrap-around
        assert_eq!(sequence_diff(65535, 0), -1);
    }

    #[test]
    fn test_reset() {
        let mut jb = JitterBuffer::new(8000, 160, 60);
        jb.push(make_packet(0, 0));
        jb.push(make_packet(1, 160));

        jb.reset();

        assert!(jb.is_empty());
        assert!(!jb.is_ready());
    }

    #[test]
    fn test_depth_clamping() {
        let mut jb = JitterBuffer::new(8000, 160, 60);

        jb.set_target_depth_ms(5); // Below minimum
        assert_eq!(jb.target_depth_ms(), MIN_DEPTH_MS);

        jb.set_target_depth_ms(500); // Above maximum
        assert_eq!(jb.target_depth_ms(), MAX_DEPTH_MS);
    }
}
