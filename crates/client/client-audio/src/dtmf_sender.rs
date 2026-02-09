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
/// pjproject uses 0ms by default (PJMEDIA_DTMF_DIGIT_PAUSE_LEN = 0).
const INTER_DIGIT_PAUSE_MS: u64 = 0;

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
///
/// In RFC 4733 mode, sends both telephone-event packets AND in-band audio
/// tones simultaneously (dual-send). This ensures DTMF is received even if
/// the remote gateway doesn't properly process telephone-event packets.
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
    /// Codec clock rate (e.g., 8000 for G.711, 16000 for G.722).
    codec_clock_rate: u32,
    /// Codec samples per frame (e.g., 160 for G.711, 320 for G.722).
    codec_samples_per_frame: usize,
    /// Pre-allocated buffer for tone generation (avoids per-packet allocation).
    tone_buffer: Vec<i16>,
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
    /// Tone generator (always present — used for in-band and dual-send).
    tone_gen: Option<DtmfToneGenerator>,
    /// Whether the initial marker-bit packet has been sent.
    marker_sent: bool,
}

impl Default for DtmfSender {
    fn default() -> Self {
        Self::new(DtmfEvent::DEFAULT_VOLUME, INTER_DIGIT_PAUSE_MS, 8000, 160)
    }
}

impl DtmfSender {
    /// Creates a new idle sender with the given DTMF configuration.
    #[must_use]
    pub const fn new(
        volume: u8,
        inter_digit_pause_ms: u64,
        codec_clock_rate: u32,
        codec_samples_per_frame: usize,
    ) -> Self {
        Self {
            phase: DtmfPhase::Idle,
            queue: VecDeque::new(),
            current: None,
            volume,
            inter_digit_pause_ms,
            codec_clock_rate,
            codec_samples_per_frame,
            tone_buffer: Vec::new(),
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

    /// Returns `true` if DTMF tone/packets are being actively sent.
    ///
    /// Unlike [`is_active()`](Self::is_active), this returns `false` during
    /// the inter-digit pause, allowing normal mic audio to resume between
    /// digits (matches pjproject behavior).
    pub fn is_sending_tone(&self) -> bool {
        matches!(self.phase, DtmfPhase::Sending | DtmfPhase::EndPackets)
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
    /// Returns an encoded audio frame (in-band DTMF tone) that the caller
    /// should send via `transmitter.send()`. For RFC 4733 mode this provides
    /// dual-send (telephone-event + in-band audio simultaneously).
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
                // Continue inband tone during end packets so the remote's
                // audio RTP stream stays continuous (no gap → no robotic
                // speech after DTMF). transmitter.send() in the caller
                // advances the audio timestamp naturally.
                self.generate_tone_frame(codec)
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
    ///
    /// Always creates a tone generator regardless of mode — for RFC 4733,
    /// the tone is sent alongside telephone-event packets (dual-send).
    fn start_digit(&mut self, cmd: DtmfCommand) {
        let method = if cmd.use_rfc2833 {
            "RFC4733+inband"
        } else {
            "in-band"
        };
        debug!(
            "DTMF starting digit '{}' for {}ms ({})",
            cmd.digit, cmd.duration_ms, method
        );

        let total_duration_ts = DtmfEvent::duration_from_ms(cmd.duration_ms);
        let tone_gen = Some(DtmfToneGenerator::new(cmd.digit, self.codec_clock_rate));

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
    ///
    /// For RFC 4733: sends telephone-event packet AND returns in-band tone
    /// frame (dual-send). For pure in-band: returns tone frame only.
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
                // Always generate inband tone — even on the frame that
                // transitions to EndPackets. The tone sustains continuously
                // through the entire event to prevent audio RTP gaps.
                return self.generate_tone_frame(codec);
            } else {
                return self.send_inband_packet(codec);
            }
        }
        None
    }

    /// Sends one RFC 4733 telephone-event packet.
    ///
    /// Duration progression matches pjproject: each packet advances by one
    /// frame period (160 samples = 20ms). The marker packet carries
    /// duration=160, not 0. Capped at the target event duration.
    fn send_rfc4733_packet(&mut self, transmitter: &mut RtpTransmitter) {
        let Some(digit) = self.current.as_mut() else {
            return;
        };

        let is_marker = !digit.marker_sent;

        // Compute cumulative duration: (packets_sent + 1) * frame_period.
        // Marker (packets_sent=0) → 160, next → 320, 480, 640, 800 …
        let elapsed_ts = DtmfEvent::duration_from_ms((digit.packets_sent + 1) * 20);

        // If we've already sent a packet at the target duration, transition
        // to end packets (like pjproject's `cur_ts >= dtmf_duration` check).
        if !is_marker && elapsed_ts > digit.total_duration_ts {
            self.phase = DtmfPhase::EndPackets;
            return;
        }

        // Cap at target (pjproject: `if (cur_ts > duration) cur_ts = duration`)
        let capped_ts = elapsed_ts.min(digit.total_duration_ts);

        let mut event = DtmfEvent::new(digit.cmd.digit, capped_ts);
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

        // Check if we've sent enough packets
        let total_packets = digit.cmd.duration_ms / 20;
        if digit.packets_sent >= total_packets {
            // In-band mode: skip end packets, go straight to inter-digit pause
            self.transition_to_pause();
            return None;
        }

        let result = self.generate_tone_frame(codec);

        let digit = self.current.as_mut()?;
        digit.packets_sent += 1;
        digit.last_packet_time = Instant::now();
        digit.marker_sent = true;

        result
    }

    /// Generates one frame of in-band DTMF tone audio, encoded via the codec.
    ///
    /// Uses the pre-allocated `tone_buffer` and the codec's actual sample rate
    /// and frame size (works for G.711, G.722, Opus, etc.).
    fn generate_tone_frame(&mut self, codec: &mut CodecPipeline) -> Option<Vec<u8>> {
        let digit = self.current.as_mut()?;
        let tone_gen = digit.tone_gen.as_mut()?;

        let samples = self.codec_samples_per_frame;
        self.tone_buffer.resize(samples, 0);
        tone_gen.generate_samples(&mut self.tone_buffer[..samples]);

        match codec.encode(&self.tone_buffer[..samples]) {
            Ok(encoded) => Some(encoded.to_vec()),
            Err(e) => {
                warn!("DTMF tone encode error: {e}");
                None
            }
        }
    }

    /// Polls during the `EndPackets` phase.
    ///
    /// End packets are paced at 20ms intervals (codec frame rate) matching
    /// pjproject, rather than burst-sent. The caller generates inband tone
    /// frames alongside end packets to keep the audio RTP stream continuous.
    fn poll_end_packets(&mut self, transmitter: &mut RtpTransmitter) {
        let Some(digit) = self.current.as_mut() else {
            self.transition_to_pause();
            return;
        };

        if digit.end_packets_sent >= END_PACKET_REPEATS {
            // No advance_dtmf_timestamp needed — inband tone frames sent
            // during EndPackets already advance the audio timestamp via
            // transmitter.send() in the caller.
            self.transition_to_pause();
            return;
        }

        // Pace end packets at 20ms intervals (codec frame rate), like pjproject.
        if digit.end_packets_sent > 0 && digit.last_packet_time.elapsed() < PACKET_INTERVAL {
            return;
        }

        let mut event = DtmfEvent::with_end(digit.cmd.digit, digit.total_duration_ts);
        event.volume = self.volume;
        if let Err(e) = transmitter.send_dtmf(&event, false) {
            trace!("RFC4733 end send error: {e}");
        }

        digit.end_packets_sent += 1;
        digit.last_packet_time = Instant::now();
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

    /// Sends a forced end packet if DTMF is mid-send, then clears all state.
    ///
    /// Called during stream teardown so the remote knows the event is over
    /// (matches pjproject's `stream_destroy` behavior).
    pub fn flush(&mut self, transmitter: &mut RtpTransmitter) {
        if let Some(ref digit) = self.current {
            if digit.cmd.use_rfc2833
                && matches!(self.phase, DtmfPhase::Sending | DtmfPhase::EndPackets)
            {
                let duration = if self.phase == DtmfPhase::Sending {
                    DtmfEvent::duration_from_ms((digit.packets_sent + 1) * 20)
                        .min(digit.total_duration_ts)
                } else {
                    digit.total_duration_ts
                };
                let mut event = DtmfEvent::with_end(digit.cmd.digit, duration);
                event.volume = self.volume;
                let _ = transmitter.send_dtmf(&event, false);
                info!("DTMF flush: sent forced end for '{}'", digit.cmd.digit);
            }
        }
        self.phase = DtmfPhase::Idle;
        self.current = None;
        self.queue.clear();
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
        // RFC4733 dual-send: is_active=true, but is_inband_active=false
        // because use_rfc2833=true (inband is sent alongside, not standalone)
        assert!(!sender.is_inband_active());
    }

    #[test]
    fn test_enqueue_inband_detects_active() {
        let mut sender = DtmfSender::default();
        sender.enqueue(make_cmd(DtmfDigit::Five, 100, false));
        // Pure inband: is_inband_active because use_rfc2833 = false
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
