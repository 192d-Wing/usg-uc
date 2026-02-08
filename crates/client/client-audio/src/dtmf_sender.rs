//! Non-blocking DTMF sender state machine.
//!
//! Replaces the blocking `handle_dtmf()` loop with a state machine that is
//! polled once per I/O thread iteration (~5ms). This keeps RTP receive and
//! mic capture running throughout DTMF digit transmission.

use crate::codec::CodecPipeline;
use crate::dtmf_tones::DtmfToneGenerator;
use crate::io_thread::DtmfCommand;
use crate::rtp_handler::RtpTransmitter;
use client_types::DtmfEvent;
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

/// Maximum number of queued DTMF digits.
const MAX_DIGIT_QUEUE: usize = 32;

/// Default inter-digit pause in milliseconds.
const INTER_DIGIT_PAUSE_MS: u64 = 100;

/// Number of end-of-event packets sent for reliability (RFC 4733).
const END_PACKET_REPEATS: u32 = 3;

/// Packet interval for DTMF events (20ms, matching typical codec frame).
const PACKET_INTERVAL: Duration = Duration::from_millis(20);

/// Phase of a single DTMF digit's lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DtmfPhase {
    /// No DTMF in progress.
    Idle,
    /// Actively sending tone/event packets.
    Sending,
    /// Sending the final end-of-event packets (3x).
    EndPackets,
    /// Pausing between consecutive digits.
    InterDigitPause,
}

/// Non-blocking DTMF sender.
///
/// Polled once per I/O loop iteration. Manages the lifecycle of one DTMF
/// digit at a time with a bounded queue for rapid-fire sequences.
pub struct DtmfSender {
    /// Current phase.
    phase: DtmfPhase,
    /// Queue of pending digits.
    queue: VecDeque<DtmfCommand>,
    /// Current digit being sent.
    current: Option<ActiveDigit>,
    /// RFC 4733 volume level (0-63, where 0 = loudest).
    volume: u8,
    /// Inter-digit pause in milliseconds.
    inter_digit_pause_ms: u64,
}

/// State for the digit currently being transmitted.
struct ActiveDigit {
    /// The DTMF command.
    cmd: DtmfCommand,
    /// Total duration in RFC 4733 timestamp units (8kHz clock).
    total_duration_ts: u16,
    /// When the current phase started.
    phase_start: Instant,
    /// When the last packet was sent (for 20ms pacing).
    last_packet_time: Instant,
    /// Number of continuation packets sent (not counting the initial marker packet).
    packets_sent: u32,
    /// Number of end packets sent so far.
    end_packets_sent: u32,
    /// In-band tone generator (for in-band mode only).
    tone_gen: Option<DtmfToneGenerator>,
    /// Whether the initial marker-bit packet has been sent.
    marker_sent: bool,
}

impl Default for DtmfSender {
    fn default() -> Self {
        Self::new(DtmfEvent::DEFAULT_VOLUME, INTER_DIGIT_PAUSE_MS)
    }
}

impl DtmfSender {
    /// Creates a new idle sender with the given DTMF configuration.
    #[must_use]
    pub const fn new(volume: u8, inter_digit_pause_ms: u64) -> Self {
        Self {
            phase: DtmfPhase::Idle,
            queue: VecDeque::new(),
            current: None,
            volume,
            inter_digit_pause_ms,
        }
    }

    /// Enqueues a DTMF digit. Returns `false` if the queue is full.
    pub fn enqueue(&mut self, cmd: DtmfCommand) -> bool {
        if self.queue.len() >= MAX_DIGIT_QUEUE {
            warn!("DTMF queue full ({MAX_DIGIT_QUEUE}), dropping digit '{}'", cmd.digit);
            return false;
        }
        let method = if cmd.use_rfc2833 { "RFC4733" } else { "in-band" };
        info!(
            "DTMF enqueued digit '{}' for {}ms ({}) [queue depth: {}]",
            cmd.digit,
            cmd.duration_ms,
            method,
            self.queue.len() + 1
        );
        self.queue.push_back(cmd);

        // If idle, immediately start processing
        if self.phase == DtmfPhase::Idle {
            self.try_start_next();
        }
        true
    }

    /// Returns `true` if DTMF is currently active (sending or pausing).
    pub fn is_active(&self) -> bool {
        self.phase != DtmfPhase::Idle
    }

    /// Returns `true` if an in-band DTMF tone is currently being sent.
    ///
    /// When true, the caller should suppress normal mic capture sends
    /// to avoid sending both mic audio and DTMF tones simultaneously.
    pub fn is_inband_active(&self) -> bool {
        self.phase == DtmfPhase::Sending
            && self
                .current
                .as_ref()
                .is_some_and(|d| !d.cmd.use_rfc2833)
    }

    /// Polls the state machine. Call once per I/O loop iteration.
    ///
    /// For RFC 4733 mode, sends telephone-event packets via the transmitter.
    /// For in-band mode, returns an encoded audio frame that the caller should
    /// send via `transmitter.send()` instead of normal mic audio.
    pub fn poll(
        &mut self,
        transmitter: &mut RtpTransmitter,
        codec: &mut CodecPipeline,
    ) -> Option<Vec<u8>> {
        match self.phase {
            DtmfPhase::Idle => None,
            DtmfPhase::Sending => self.poll_sending(transmitter, codec),
            DtmfPhase::EndPackets => {
                self.poll_end_packets(transmitter);
                None
            }
            DtmfPhase::InterDigitPause => {
                self.poll_pause();
                None
            }
        }
    }

    /// Attempts to dequeue the next digit and start sending it.
    fn try_start_next(&mut self) {
        if let Some(cmd) = self.queue.pop_front() {
            self.start_digit(cmd);
        } else {
            self.phase = DtmfPhase::Idle;
            self.current = None;
        }
    }

    /// Begins transmission of a single digit.
    fn start_digit(&mut self, cmd: DtmfCommand) {
        let method = if cmd.use_rfc2833 { "RFC4733" } else { "in-band" };
        debug!(
            "DTMF starting digit '{}' for {}ms ({})",
            cmd.digit, cmd.duration_ms, method
        );

        let total_duration_ts = DtmfEvent::duration_from_ms(cmd.duration_ms);
        let tone_gen = if cmd.use_rfc2833 {
            None
        } else {
            Some(DtmfToneGenerator::new(cmd.digit, 8000))
        };

        let now = Instant::now();
        self.current = Some(ActiveDigit {
            cmd,
            total_duration_ts,
            phase_start: now,
            last_packet_time: now,
            packets_sent: 0,
            end_packets_sent: 0,
            tone_gen,
            marker_sent: false,
        });
        self.phase = DtmfPhase::Sending;
    }

    /// Polls during the Sending phase.
    fn poll_sending(
        &mut self,
        transmitter: &mut RtpTransmitter,
        codec: &mut CodecPipeline,
    ) -> Option<Vec<u8>> {
        let digit = self.current.as_mut()?;

        // Check if it's time to send the next packet (every 20ms)
        if !digit.marker_sent || digit.last_packet_time.elapsed() >= PACKET_INTERVAL {
            if digit.cmd.use_rfc2833 {
                self.send_rfc4733_packet(transmitter);
            } else {
                return self.send_inband_packet(codec);
            }
        }
        None
    }

    /// Sends one RFC 4733 telephone-event packet.
    fn send_rfc4733_packet(&mut self, transmitter: &mut RtpTransmitter) {
        let Some(digit) = self.current.as_mut() else {
            return;
        };

        let is_marker = !digit.marker_sent;

        // Compute cumulative duration in timestamp units
        let elapsed_ts = if is_marker {
            0u16
        } else {
            DtmfEvent::duration_from_ms((digit.packets_sent + 1) * 20)
        };

        // Check if we've reached the target duration
        if !is_marker && elapsed_ts >= digit.total_duration_ts {
            // Transition to end packets
            self.phase = DtmfPhase::EndPackets;
            return;
        }

        let mut event = DtmfEvent::new(digit.cmd.digit, elapsed_ts);
        event.volume = self.volume;
        if let Err(e) = transmitter.send_dtmf(&event, is_marker) {
            if is_marker {
                warn!("RFC4733 start send error: {e}");
            } else {
                trace!("RFC4733 continuation send error: {e}");
            }
        }

        digit.marker_sent = true;
        digit.packets_sent += 1;
        digit.last_packet_time = Instant::now();
    }

    /// Sends one in-band DTMF audio frame. Returns the encoded bytes.
    fn send_inband_packet(&mut self, codec: &mut CodecPipeline) -> Option<Vec<u8>> {
        let digit = self.current.as_mut()?;

        let codec_sample_rate = 8000u32;
        let samples_per_packet = (codec_sample_rate * 20 / 1000) as usize; // 160 samples

        // Check if we've sent enough packets
        let total_packets = digit.cmd.duration_ms / 20;
        if digit.packets_sent >= total_packets {
            // In-band mode: skip end packets, go straight to inter-digit pause
            self.transition_to_pause();
            return None;
        }

        let tone_gen = digit.tone_gen.as_mut()?;
        let mut tone_samples = vec![0i16; samples_per_packet];
        tone_gen.generate_samples(&mut tone_samples);

        let result = match codec.encode(&tone_samples) {
            Ok(encoded) => Some(encoded.to_vec()),
            Err(e) => {
                warn!("In-band DTMF encode error: {e}");
                None
            }
        };

        digit.packets_sent += 1;
        digit.last_packet_time = Instant::now();
        digit.marker_sent = true; // first packet sent

        result
    }

    /// Polls during the `EndPackets` phase. Sends one end packet per call.
    fn poll_end_packets(&mut self, transmitter: &mut RtpTransmitter) {
        let Some(digit) = self.current.as_mut() else {
            self.transition_to_pause();
            return;
        };

        if digit.end_packets_sent >= END_PACKET_REPEATS {
            debug!("DTMF digit '{}' sent successfully", digit.cmd.digit);
            self.transition_to_pause();
            return;
        }

        let mut event = DtmfEvent::with_end(digit.cmd.digit, digit.total_duration_ts);
        event.volume = self.volume;
        if let Err(e) = transmitter.send_dtmf(&event, false) {
            trace!("RFC4733 end send error: {e}");
        }

        digit.end_packets_sent += 1;
    }

    /// Polls during the `InterDigitPause` phase.
    fn poll_pause(&mut self) {
        let elapsed = self
            .current
            .as_ref()
            .map_or(Duration::ZERO, |d| d.phase_start.elapsed());

        if elapsed >= Duration::from_millis(self.inter_digit_pause_ms) {
            self.current = None;
            self.try_start_next();
        }
    }

    /// Transitions to the inter-digit pause (or idle if queue is empty).
    fn transition_to_pause(&mut self) {
        if self.queue.is_empty() {
            // No more digits — go idle immediately
            if let Some(ref d) = self.current {
                debug!("DTMF digit '{}' sent successfully", d.cmd.digit);
            }
            self.phase = DtmfPhase::Idle;
            self.current = None;
        } else {
            // More digits queued — pause before next
            self.phase = DtmfPhase::InterDigitPause;
            if let Some(ref mut d) = self.current {
                d.phase_start = Instant::now();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use client_types::DtmfDigit;

    fn make_cmd(digit: DtmfDigit, duration_ms: u32, rfc2833: bool) -> DtmfCommand {
        DtmfCommand {
            digit,
            duration_ms,
            use_rfc2833: rfc2833,
        }
    }

    #[test]
    fn test_new_sender_is_idle() {
        let sender = DtmfSender::default();
        assert!(!sender.is_active());
        assert!(!sender.is_inband_active());
    }

    #[test]
    fn test_enqueue_activates() {
        let mut sender = DtmfSender::default();
        let ok = sender.enqueue(make_cmd(DtmfDigit::Five, 100, true));
        assert!(ok);
        assert!(sender.is_active());
        assert!(!sender.is_inband_active()); // RFC4733, not in-band
    }

    #[test]
    fn test_enqueue_inband_detects_active() {
        let mut sender = DtmfSender::default();
        sender.enqueue(make_cmd(DtmfDigit::Five, 100, false));
        assert!(sender.is_inband_active());
    }

    #[test]
    fn test_queue_overflow() {
        let mut sender = DtmfSender::default();
        for i in 0..MAX_DIGIT_QUEUE {
            let ok = sender.enqueue(make_cmd(DtmfDigit::Zero, 100, true));
            assert!(ok, "digit {i} should enqueue");
        }
        // 33rd should fail (32 in queue + 1 active = 32 queued, but first was dequeued to active)
        // Actually: first enqueue pops immediately to active, so queue holds MAX-1 before rejecting at MAX.
        // Let's fill to exactly MAX in the queue:
        // First enqueue: goes to queue, then try_start_next pops it to active. queue=0
        // Next 31: go to queue. queue=31
        // 33rd: queue.len()=31, still < 32, accepted. queue=32
        // But wait, queue len check is >= 32... let me recalculate.
        // After first enqueue: active=Some, queue=0
        // After enqueues 2..33 (32 more): queue=32 at the 33rd overall push
        // Actually enqueue pushes then checks: no, it checks first.
        // At this point queue.len() = MAX_DIGIT_QUEUE - 1 = 31 (because first was popped to active)
        // So we need one more to fill to 32.
        let ok = sender.enqueue(make_cmd(DtmfDigit::Zero, 100, true));
        assert!(ok, "should still fit (queue has 31 after first popped to active)");
        // Now queue has 32 — next should fail
        let ok = sender.enqueue(make_cmd(DtmfDigit::Zero, 100, true));
        assert!(!ok, "should reject when queue is full");
    }

    #[test]
    fn test_phase_transition_rfc4733() {
        let mut sender = DtmfSender::default();
        sender.enqueue(make_cmd(DtmfDigit::Five, 100, true));
        assert_eq!(sender.phase, DtmfPhase::Sending);
        assert!(sender.current.is_some());
    }

    #[test]
    fn test_phase_transition_inband() {
        let mut sender = DtmfSender::default();
        sender.enqueue(make_cmd(DtmfDigit::Five, 100, false));
        assert_eq!(sender.phase, DtmfPhase::Sending);
        assert!(sender.current.as_ref().unwrap().tone_gen.is_some());
    }
}
