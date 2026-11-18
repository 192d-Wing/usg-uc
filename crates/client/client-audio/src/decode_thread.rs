//! Dedicated decode/playout thread for pull-based audio playback.
//!
//! This thread monitors the playback ring buffer fill level and decodes
//! frames from the jitter buffer as needed, ensuring the CPAL playback
//! callback always has audio data available. By running as a dedicated
//! `std::thread` (not a tokio task), it avoids cooperative scheduling
//! delays that cause playback gaps.

use crate::aec::AecReference;
use crate::backend::{PlaybackHandle, create_playback};
use crate::codec::CodecPipeline;
use crate::comfort_noise::{ComfortNoiseConfig, ComfortNoiseGenerator, decode_cn_payload};
use crate::drift_compensator::{DriftCompensator, DriftConfig};
use crate::dtmf_tones::DtmfToneGenerator;
use crate::jitter_buffer::{JitterBufferResult, SharedJitterBuffer};
use crate::postfilter::{Postfilter, PostfilterConfig};
use crate::rtp_handler::SharedDtmfQueue;
use crate::sinc_resampler::Resampler;
use crate::stream::Sample;
use crate::wsola::WsolaPlc;
use client_types::{CodecPreference, DtmfDigit, DtmfEvent};

/// Write a slice of i16 samples to a file as little-endian bytes in batched writes.
///
/// Uses a stack buffer to convert samples to LE bytes, then writes in chunks
/// to reduce syscall count from N (per-sample) to ~N/512.
#[inline]
fn dump_samples(dump: &mut impl std::io::Write, samples: &[i16]) {
    // Stack buffer: 1024 bytes = 512 samples per write_all call.
    let mut buf = [0u8; 1024];
    for chunk in samples.chunks(512) {
        let byte_len = chunk.len() * 2;
        for (i, &s) in chunk.iter().enumerate() {
            let bytes = s.to_le_bytes();
            buf[i * 2] = bytes[0];
            buf[i * 2 + 1] = bytes[1];
        }
        let _ = dump.write_all(&buf[..byte_len]);
    }
}

/// Cross-fades `tone` with `other` in place over the first `fade_len` samples.
///
/// `to_tone = true` ramps from `other` into `tone` (generator onset; the rest
/// of the frame stays pure tone); `false` ramps from `tone` into `other`
/// (generator release; the rest of the frame is `other`). Used at DTMF
/// generator boundaries: carriers leak real in-band tone around the
/// telephone-event window, and a hard splice between leaked and generated
/// tone is heard as a doubled/retriggered tone. The fade is kept short
/// (~5ms) — a frame-length ramp creates an audible amplitude scoop instead.
#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn crossfade_frames(tone: &mut [i16], other: &[i16], fade_len: usize, to_tone: bool) {
    let n = tone.len().min(other.len());
    if n == 0 {
        return;
    }
    let fade = fade_len.clamp(1, n);
    #[allow(clippy::cast_precision_loss)]
    let fade_f = fade as f32;
    for (i, (sample, &o)) in tone.iter_mut().zip(other).enumerate() {
        if i >= fade {
            if to_tone {
                break; // remainder of the frame is already pure tone
            }
            *sample = o; // remainder of the frame is the decoded audio
            continue;
        }
        let t = i as f32 / fade_f;
        let (from, to) = if to_tone {
            (f32::from(o), f32::from(*sample))
        } else {
            (f32::from(*sample), f32::from(o))
        };
        *sample = (to - from).mul_add(t, from).round() as i16;
    }
}
use ringbuf::traits::{Observer, Producer};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

/// Environment variable to enable audio dump for debugging.
/// Set `DUMP_DECODED_AUDIO=1` to write decoded audio to `/tmp/decoded-audio.raw`.
const DUMP_ENV_VAR: &str = "DUMP_DECODED_AUDIO";

/// Environment variable to enable DTMF diagnostics.
/// Set `DUMP_DTMF=1` to write:
///   - `/tmp/dtmf-trace.csv`  — packet-level event trace
///   - `/tmp/dtmf-tone.raw`   — generated tone PCM (s16le, device rate, mono)
///   - `/tmp/decoded-audio.raw` — full decoded audio (also enabled)
const DUMP_DTMF_ENV: &str = "DUMP_DTMF";

/// Initial target fill level for the playback ring buffer (in frames).
/// At 20ms per frame, 3 frames = 60ms cushion. This is the starting
/// value; it adapts down based on jitter buffer health.
const INITIAL_FILL_FRAMES: usize = 3;

/// Minimum adaptive fill (in frames). Never go below 2 frames (40ms)
/// to absorb scheduling jitter, even on low-latency networks.
const MIN_FILL_FRAMES: usize = 2;

/// Maximum adaptive fill (in frames). Cap at 4 frames (80ms) to bound
/// latency even on high-jitter networks.
const MAX_FILL_FRAMES: usize = 4;

/// Playback gain applied to decoded remote audio (linear).
/// Unity gain: logs show G.711 ulaw from `BulkVS` peaks at 20000-29000
/// (already -3 to -1 dBFS). Any gain above 1.0 causes hard clipping
/// at 32767, producing audible distortion ("static").
const PLAYBACK_GAIN: f32 = 1.0;

/// Peak amplitude threshold to open the gain gate (speech detected).
/// G.711 ulaw speech is well above 2000 during active speech.
const GATE_OPEN_PEAK: i16 = 2000;

/// Peak amplitude threshold to close the gain gate (back to unity).
/// Below this, quantization noise dominates — don't amplify it.
const GATE_CLOSE_PEAK: i16 = 500;

/// Frames to hold the gain gate open after the last speech frame.
/// 15 frames * 20ms = 300ms — covers inter-word pauses and sentence tails.
const GAIN_HOLD_FRAMES: u32 = 15;

/// Headroom scale factor applied after resampling to prevent sinc overshoot
/// from hard-clipping at ±32767. The sinc resampler can overshoot by up to
/// ~3% on transients; 0.97 provides sufficient headroom while keeping the
/// signal close to full scale.
const RESAMPLE_HEADROOM: f32 = 0.97;

/// Exponential ramp speed for gain transitions (per frame).
/// 0.15 gives a ~130ms time constant (smooth, no audible steps).
const GAIN_RAMP_SPEED: f32 = 0.15;

/// Minimum valid DTMF duration in timestamp units (40ms at 8kHz = 320).
const DTMF_MIN_DURATION: u16 = 320;

/// How far before a scheduled event's stamped start the tone activates, in
/// RTP timestamp units (50ms at 8kHz). Carriers leak 20-40ms of real in-band
/// tone into the audio just before the stamped start (gateway detection
/// latency); starting the generator inside the guard re-covers that leak.
const DTMF_START_GUARD: u32 = 400;

/// A telephone-event scheduled for playout by RTP timestamp.
struct ScheduledDtmf {
    digit: DtmfDigit,
    start_ts: u32,
    /// Provisional until `ended`: the NEW packet carries only ~20ms of
    /// duration; continuations grow it and the END packet finalizes it.
    end_ts: u32,
    /// Whether the END packet for this event has been seen.
    ended: bool,
}

/// Maximum number of telephone-events queued for playout per call (SR-48).
/// The schedule is pre-sized to this so the decode thread does not allocate
/// for it in steady state.
///
/// On overflow the OLDEST queued event is dropped: events whose END never
/// arrives are never expired by [`advance_dtmf_schedule`], so dropping the
/// newest would let a flood of never-ended events lock out every later
/// real digit.
// NIST 800-53 Rev5: SC-5, SI-10 (bounded per-call state on wire input).
const DTMF_SCHEDULE_CAP: usize = 8;

/// Maximum distance, in RTP timestamp units, between a NEW telephone-event's
/// start and the current playout position. Starts further ahead or behind
/// are rejected.
///
/// The playout position is measured on the AUDIO codec's RTP clock
/// ([`rtp_ts_units_per_ms`]): 4 s for PCMU/PCMA/G.722 (8000 Hz), 0.67 s for
/// Opus (48000 Hz), still above any jitter-buffer lead.
// NIST 800-53 Rev5: SC-5, SI-10. RFC 4733 §2.3/§2.5: the event timestamp is
// the event start on the media clock, so it tracks the audio timeline.
// POAM: POA&M-378 -- with Opus the offer carries only telephone-event/8000
// while the audio clock is 48000; RFC 4733 §2.1 / RFC 7160 let a sender use
// a different clock (and timestamp base) for events, so event timestamps
// and durations are then compared on the wrong clock (digits rejected,
// durations 6x off). Not offering telephone-event/48000 with Opus, and not
// scaling, is a recorded deviation.
const DTMF_MAX_START_DISTANCE: u32 = 32_000;

/// Bound of the received-DTMF notification channel (SR-48). Notifications
/// beyond it are dropped rather than blocking the decode thread.
const DTMF_RX_CHANNEL_CAP: usize = 16;

/// Mutable DTMF playout state threaded through [`advance_dtmf_schedule`].
struct DtmfPlayout {
    schedule: std::collections::VecDeque<ScheduledDtmf>,
    active_gen: Option<DtmfToneGenerator>,
    fade_in: bool,
    /// Stamped start of the playing tone (routes duration updates to it).
    active_start: Option<u32>,
    /// Playout-timeline end of the playing tone (grows with continuations).
    end_ts: Option<u32>,
    /// Whether the playing tone's END packet has been seen.
    active_ended: bool,
}

impl DtmfPlayout {
    fn new() -> Self {
        Self {
            schedule: std::collections::VecDeque::with_capacity(DTMF_SCHEDULE_CAP),
            active_gen: None,
            fade_in: false,
            active_start: None,
            end_ts: None,
            active_ended: false,
        }
    }

    /// Clears the active tone (boundary frame played or failsafe).
    const fn clear_active(&mut self) {
        self.active_gen = None;
        self.fade_in = false;
        self.active_start = None;
        self.end_ts = None;
        self.active_ended = false;
    }
}

/// Advances the DTMF playout schedule to `now_ts` (RTP timestamp units):
/// activates the next queued tone once the playout point enters its window
/// (minus [`DTMF_START_GUARD`]), drops *ended* windows entirely behind the
/// playout point, and returns whether the active tone's end has been reached.
///
/// An event whose END packet hasn't been seen is never expired or
/// end-reached: its `end_ts` is provisional (the NEW packet carries only
/// ~20ms) and still growing — expiring on it discards the whole tone.
///
/// `now_ts` comes from the decoded frame when audio is flowing, or from a
/// wall-clock extrapolation when the carrier suppresses audio during DTMF —
/// tones must start and stop on time either way.
#[allow(clippy::cast_possible_wrap)]
fn advance_dtmf_schedule(now_ts: u32, dtmf: &mut DtmfPlayout, device_rate: u32) -> bool {
    if dtmf.active_gen.is_none() {
        while let Some(head) = dtmf.schedule.front() {
            let expired = head.ended && now_ts.wrapping_sub(head.end_ts) as i32 >= 0;
            let reached =
                now_ts.wrapping_sub(head.start_ts.wrapping_sub(DTMF_START_GUARD)) as i32 >= 0;
            if expired {
                // Whole (finalized) window is behind the playout point.
                trace!(
                    "dtmf sched: expired digit={:?} window=({},{}) now={now_ts}",
                    head.digit, head.start_ts, head.end_ts
                );
                dtmf.schedule.pop_front();
                continue;
            }
            if reached {
                trace!(
                    "dtmf sched: activate digit={:?} window=({},{}) ended={} now={now_ts}",
                    head.digit, head.start_ts, head.end_ts, head.ended
                );
                dtmf.active_gen = Some(DtmfToneGenerator::new(head.digit, device_rate));
                dtmf.fade_in = true;
                dtmf.active_start = Some(head.start_ts);
                dtmf.end_ts = Some(head.end_ts);
                dtmf.active_ended = head.ended;
                dtmf.schedule.pop_front();
            }
            break;
        }
    }
    dtmf.active_gen.is_some()
        && dtmf.active_ended
        && dtmf
            .end_ts
            .is_some_and(|end| now_ts.wrapping_sub(end) as i32 >= 0)
}

/// Maximum valid DTMF duration in timestamp units (5000ms at 8kHz = 40000).
// POAM: POA&M-378 -- RFC 4733 §2.5.1.3 lets one segment's duration run to
// 65535 units (then the sender starts a new segment); events over 40000
// (5 s at 8 kHz, 0.83 s at 48 kHz) are discarded as malformed here, so a
// long press is cut short or heard twice. Recorded deviation.
const DTMF_MAX_DURATION: u16 = 40000;

/// Receive-side state of the RFC 4733 event in progress.
///
/// RFC 4733 sends several packets per event (NEW, continuations, 3x END),
/// all carrying the event's start timestamp. `current_ts` stays set after
/// the END so retransmitted END packets are not taken as a new event.
struct DtmfRx {
    /// Start timestamp of the current event.
    current_ts: Option<u32>,
    /// Duration of the current event (monotonic within an event).
    current_duration: u16,
}

impl DtmfRx {
    const fn new() -> Self {
        Self {
            current_ts: None,
            current_duration: 0,
        }
    }
}

/// What [`ingest_dtmf_event`] did with one telephone-event packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DtmfIngest {
    /// Dropped before touching the receive state: a non-monotonic duration
    /// within the event, or a duration over [`DTMF_MAX_DURATION`] (counted
    /// as malformed).
    Discarded,
    /// A NEW event that is already an END shorter than
    /// [`DTMF_MIN_DURATION`] (counted as malformed).
    ShortEnd,
    /// A NEW event whose start is more than [`DTMF_MAX_START_DISTANCE`]
    /// from the playout position (counted in `dtmf_rejected`; not queued,
    /// not counted as received, receive state untouched).
    Rejected,
    /// A NEW event was queued for playout.
    Scheduled,
    /// A continuation/END was applied to the playing or a queued tone (or
    /// matched neither).
    Updated,
}

/// Applies one decoded telephone-event packet (start timestamp `packet_ts`)
/// to the receive state and the playout schedule.
///
/// `playout_ts` is the current playout position in RTP timestamp units
/// (`None` before the first decoded frame, in which case the start-distance
/// check is skipped and only [`DTMF_SCHEDULE_CAP`] bounds the schedule).
///
/// Allocation-free: the schedule never grows past its pre-sized capacity.
// NIST 800-53 Rev5: SC-5, SI-10 (bounded, validated wire input).
fn ingest_dtmf_event(
    rx: &mut DtmfRx,
    dtmf: &mut DtmfPlayout,
    packet_ts: u32,
    event: DtmfEvent,
    playout_ts: Option<u32>,
    metrics: &DecodeMetrics,
) -> DtmfIngest {
    let is_new = rx.current_ts != Some(packet_ts);
    if !is_new && event.duration < rx.current_duration {
        return DtmfIngest::Discarded; // Non-monotonic duration within event
    }
    if event.duration > DTMF_MAX_DURATION {
        metrics.dtmf_malformed.fetch_add(1, Ordering::Relaxed);
        return DtmfIngest::Discarded; // Duration exceeds RFC sanity bound (5s)
    }
    // A NEW start far from the playout clock (wrapping signed distance) is
    // a hostile or broken sender, not a digit to play.
    // `min(d, -d)` on the wrapped difference is |signed distance| mod 2^32.
    if is_new
        && playout_ts.is_some_and(|p| {
            let d = packet_ts.wrapping_sub(p);
            d.min(d.wrapping_neg()) > DTMF_MAX_START_DISTANCE
        })
    {
        metrics.dtmf_rejected.fetch_add(1, Ordering::Relaxed);
        return DtmfIngest::Rejected;
    }
    if is_new && event.end && event.duration < DTMF_MIN_DURATION {
        // Refused before touching the receive state (SEC-5): the event in
        // progress keeps its duration.
        metrics.dtmf_malformed.fetch_add(1, Ordering::Relaxed);
        return DtmfIngest::ShortEnd;
    }
    rx.current_duration = event.duration;
    // Every packet refines the playout end: ts is the event start, duration
    // grows monotonically and the END packet carries the final value.
    let event_end_ts = packet_ts.wrapping_add(u32::from(event.duration));

    if is_new {
        rx.current_ts = Some(packet_ts);
        metrics.dtmf_received.fetch_add(1, Ordering::Relaxed);
        // Schedule for playout-timeline activation rather than activating
        // now: with rapid digit sequences this packet arrives while the
        // previous tone is still playing out, and switching the generator
        // here blurred/stuttered digits.
        if dtmf.schedule.len() >= DTMF_SCHEDULE_CAP {
            // Drop-oldest keeps the push within the pre-sized capacity.
            dtmf.schedule.pop_front();
            metrics.dtmf_rejected.fetch_add(1, Ordering::Relaxed);
        }
        dtmf.schedule.push_back(ScheduledDtmf {
            digit: event.digit,
            start_ts: packet_ts,
            end_ts: event_end_ts,
            ended: event.end,
        });
        return DtmfIngest::Scheduled;
    }
    if dtmf.active_start == Some(packet_ts) {
        // Continuation/END for the currently playing tone.
        dtmf.end_ts = Some(event_end_ts);
        dtmf.active_ended |= event.end;
    } else if let Some(entry) = dtmf.schedule.iter_mut().find(|e| e.start_ts == packet_ts) {
        // Continuation/END for a not-yet-started tone.
        entry.end_ts = event_end_ts;
        entry.ended |= event.end;
    }
    DtmfIngest::Updated
}

/// Sender half of the received-DTMF notification channel (decode thread to
/// the pipeline owner, drained by `AudioPipeline::drain_received_dtmf`).
pub type DtmfRxSender = mpsc::SyncSender<DtmfDigit>;

/// Creates the received-DTMF notification channel, bounded to
/// [`DTMF_RX_CHANNEL_CAP`] (the buffer is allocated once, here).
///
/// No production code drains the receiver yet
/// (`AudioPipeline::drain_received_dtmf` has no caller); once it is full,
/// further notifications are dropped (newest lost), which is intended: the
/// decode thread must never block on it.
// NIST 800-53 Rev5: SC-5 (bounded queue fed by wire input).
pub(crate) fn dtmf_rx_channel() -> (DtmfRxSender, mpsc::Receiver<DtmfDigit>) {
    mpsc::sync_channel(DTMF_RX_CHANNEL_CAP)
}

/// Notifies the pipeline owner of a newly received digit. Never blocks the
/// decode thread: a full or disconnected channel drops the notification.
fn notify_dtmf_rx(tx: &DtmfRxSender, digit: DtmfDigit) {
    let _ = tx.try_send(digit);
}

/// Command sent from the main thread to the decode thread.
pub enum DecodeCommand {
    /// Switch the playback (output) device. `None` = system default.
    SwitchOutputDevice(Option<String>),
}

/// Handle to the running decode thread.
///
/// When dropped, signals the thread to stop and joins it.
pub struct DecodeThreadHandle {
    /// The thread join handle.
    thread: Option<thread::JoinHandle<()>>,
    /// Shared running flag.
    running: Arc<AtomicBool>,
    /// Channel to send commands to the decode thread.
    cmd_tx: mpsc::Sender<DecodeCommand>,
}

impl DecodeThreadHandle {
    /// Returns a clone of the command sender for cross-thread signaling.
    ///
    /// Used by the I/O thread to trigger a playback stream refresh after
    /// an input device switch (macOS Bluetooth HFP→A2DP profile change).
    pub fn cmd_sender(&self) -> mpsc::Sender<DecodeCommand> {
        self.cmd_tx.clone()
    }

    /// Switches the playback (output) device during an active call.
    pub fn switch_output_device(&self, device_name: Option<String>) {
        if let Err(e) = self
            .cmd_tx
            .send(DecodeCommand::SwitchOutputDevice(device_name))
        {
            warn!("Failed to send output device switch command: {e}");
        }
    }

    /// Stops the decode thread and waits for it to finish.
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.thread.take()
            && let Err(e) = handle.join()
        {
            warn!("Decode thread panicked: {e:?}");
        }
    }
}

impl Drop for DecodeThreadHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// RTP timestamp units per millisecond on the audio codec's RTP clock
/// (8 for PCMU/PCMA and G.722, 48 for Opus).
///
/// RFC 3551 §4.5.2: G.722 samples at 16 kHz but its RTP clock is 8000 Hz,
/// so the per-frame sample count must not be used for this.
const fn rtp_ts_units_per_ms(rtp_clock_rate: u32) -> u32 {
    let units = rtp_clock_rate / 1000;
    if units == 0 { 1 } else { units }
}

/// Playout position extrapolated from the last anchor (RTP ts of the last
/// decoded or CN frame) by the wall time elapsed since it.
#[allow(clippy::cast_possible_truncation)]
const fn extrapolate_playout_ts(anchor_ts: u32, elapsed: Duration, units_per_ms: u32) -> u32 {
    anchor_ts.wrapping_add((elapsed.as_millis() as u32).saturating_mul(units_per_ms))
}

/// Interval between two rate-limited warnings.
const WARN_RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(1);

/// Allocation-free limiter for a warning driven by wire input: the first
/// occurrence is logged, then at most one per [`WARN_RATE_LIMIT_INTERVAL`],
/// carrying how many were suppressed since the last one.
// NIST 800-53 Rev5: AU-4, SC-5 (wire input must not drive warn-level log
// volume).
struct WarnRateLimit {
    last: Option<Instant>,
    suppressed: u64,
}

impl WarnRateLimit {
    const fn new() -> Self {
        Self {
            last: None,
            suppressed: 0,
        }
    }

    /// Records one occurrence at `now`. Returns `Some(suppressed)` when it
    /// should be logged (the count of occurrences dropped since the last
    /// logged one), `None` when it is suppressed.
    fn check(&mut self, now: Instant) -> Option<u64> {
        if self
            .last
            .is_some_and(|last| now.saturating_duration_since(last) < WARN_RATE_LIMIT_INTERVAL)
        {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

/// Shared atomic counters for decode-thread metrics.
///
/// Created by the pipeline and passed to `spawn()`. The decode thread
/// increments these lock-free; the pipeline reads them in `stats()`.
pub struct DecodeMetrics {
    /// Frames recovered from in-band FEC (RFC 7587 / RFC 6716 §2.1.7 LBRR).
    ///
    /// Counts decodes that took the FEC path with a SILK/Hybrid packet N+1;
    /// see POA&M-141 for packets that carry no LBRR.
    pub fec_recovered: AtomicU64,
    /// Frames generated by PLC (codec-native Opus PLC or WSOLA concealment).
    pub plc_generated: AtomicU64,
    /// DTMF events received from remote.
    pub dtmf_received: AtomicU64,
    /// Malformed DTMF packets (invalid duration, impossible jumps).
    pub dtmf_malformed: AtomicU64,
    /// Telephone-event PACKETS refused by the per-call bounds (SR-48), not
    /// events: each packet of an event whose NEW start was too far from the
    /// playout clock counts (its continuations and ENDs look new again and
    /// are refused too), plus one per queued event evicted when the schedule
    /// was full.
    pub dtmf_rejected: AtomicU64,
    /// Audio packets the codec failed to decode (wire-driven; the matching
    /// `warn!` is rate-limited, see [`WarnRateLimit`]).
    pub decode_errors: AtomicU64,
    /// Decoded frames dropped because they were longer than one ptime
    /// (RTP payload larger than the negotiated frame).
    pub oversized_frames_dropped: AtomicU64,
}

impl DecodeMetrics {
    /// Creates zeroed metrics.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            fec_recovered: AtomicU64::new(0),
            plc_generated: AtomicU64::new(0),
            dtmf_received: AtomicU64::new(0),
            dtmf_malformed: AtomicU64::new(0),
            dtmf_rejected: AtomicU64::new(0),
            decode_errors: AtomicU64::new(0),
            oversized_frames_dropped: AtomicU64::new(0),
        })
    }
}

/// Configuration for the decode thread.
pub struct DecodeThreadConfig {
    /// Codec preference for creating the decode pipeline.
    pub codec: CodecPreference,
    /// Device sample rate (e.g., 48000).
    pub device_rate: u32,
    /// DTMF telephone-event payload type (from SDP negotiation, default 101).
    pub dtmf_payload_type: u8,
    /// AEC far-end reference buffer (shared with I/O thread).
    /// When present, decoded codec-rate PCM is pushed here for echo cancellation.
    pub aec_ref: Option<Arc<AecReference>>,
    /// Drift compensator configuration.
    pub drift: DriftConfig,
    /// Postfilter configuration.
    pub postfilter: PostfilterConfig,
    /// Comfort noise generator configuration.
    pub comfort_noise: ComfortNoiseConfig,
    /// Channel for received DTMF digit notifications.
    /// When present, the decode thread sends each new DTMF digit here.
    pub dtmf_rx_tx: Option<DtmfRxSender>,
    /// Shared DTMF packet queue (JB bypass).
    /// When present, DTMF packets arrive here instead of the jitter buffer.
    pub dtmf_queue: Option<SharedDtmfQueue>,
}

/// Spawns the decode thread.
///
/// The thread monitors the playback ring buffer fill level and decodes
/// frames from the jitter buffer as needed. It also owns the CPAL
/// playback stream handle so it can hot-swap the output device.
///
/// # Arguments
/// * `config` - Decode thread configuration
/// * `producer` - Ring buffer producer (writes decoded audio for CPAL to read)
/// * `playback_handle` - Playback stream handle (kept alive by this thread)
/// * `jitter_buffer` - Shared jitter buffer (reads packets pushed by I/O thread)
/// * `running` - Shared flag to signal shutdown
/// * `playback_underruns` - Counter shared with CPAL callback for underrun tracking
pub fn spawn(
    config: DecodeThreadConfig,
    producer: ringbuf::HeapProd<Sample>,
    playback_handle: Box<dyn PlaybackHandle>,
    jitter_buffer: SharedJitterBuffer,
    running: Arc<AtomicBool>,
    playback_underruns: Arc<AtomicU64>,
    metrics: Arc<DecodeMetrics>,
) -> DecodeThreadHandle {
    let running_clone = running.clone();
    let (cmd_tx, cmd_rx) = mpsc::channel();

    let handle = thread::Builder::new()
        .name("audio-decode".to_string())
        .spawn(move || {
            crate::thread_priority::set_realtime_priority("decode");
            info!("Decode thread started");
            decode_loop(
                config,
                producer,
                playback_handle,
                jitter_buffer,
                &running_clone,
                &playback_underruns,
                cmd_rx,
                &metrics,
            );
            info!("Decode thread exited");
        });

    let thread = match handle {
        Ok(h) => Some(h),
        Err(e) => {
            warn!("Failed to spawn decode thread: {e}");
            None
        }
    };

    DecodeThreadHandle {
        thread,
        running,
        cmd_tx,
    }
}

/// Copies one decoded frame into the one-ptime scratch buffer and returns
/// the copied prefix for in-place processing.
///
/// The frame length comes from the RTP payload length, which the sender
/// controls: a G.711 payload of 161..=2880 bytes (ptime 30/40, or hostile)
/// decodes to more samples than `scratch` holds. Such a frame is dropped and
/// counted, never copied; `None` tells the caller to skip the packet.
// RFC 3551 §4.2: a receiver SHOULD accept packets of 0 to 200 ms of audio.
// Dropping frames longer than one ptime is a deliberate limit that does NOT
// meet that SHOULD (the SDP still offers a=maxptime:120).
// POAM: POA&M-317 — decode frames longer than one ptime (play them out as consecutive
// ptime chunks) or advertise a=maxptime matching the receive limit.
// NIST 800-53 Rev5: SI-10 (length checked before the copy), SC-5 (no panic).
fn copy_decoded_frame<'a>(
    codec_pcm: &[i16],
    scratch: &'a mut [i16],
    metrics: &DecodeMetrics,
) -> Option<&'a mut [i16]> {
    let Some(frame) = scratch.get_mut(..codec_pcm.len()) else {
        metrics
            .oversized_frames_dropped
            .fetch_add(1, Ordering::Relaxed);
        trace!(
            "Dropping oversized decoded frame: {} samples",
            codec_pcm.len()
        );
        return None;
    };
    frame.copy_from_slice(codec_pcm);
    Some(frame)
}

/// Main decode loop.
/// Produces one ptime of audio for a lost packet.
///
/// Order: (1) in-band FEC from `fec_source` (packet N+1) when the codec
/// supports it and the TOC says LBRR can be present, (2) codec-native PLC,
/// (3) WSOLA concealment. `fec_recovered` is incremented only on path 1.
/// `frame_samples` is one ptime (rate x ptime x channels); the returned
/// slice never exceeds it, fixing the 60 ms-per-lost-20 ms-frame drift.
// RFC 7587 §3.4, RFC 6716 §4.4
// NIST 800-53 Rev5: SI-10 (fec_source is untrusted; TOC-checked before decode)
fn conceal_lost_frame<'a>(
    codec: &mut CodecPipeline,
    plc: &'a mut WsolaPlc,
    scratch: &'a mut [i16],
    fec_source: Option<&[u8]>,
    frame_samples: usize,
    metrics: &DecodeMetrics,
) -> &'a [i16] {
    let frame_samples = frame_samples.min(scratch.len());

    if let Some(next) = fec_source
        && let Ok(fec_pcm) = codec.decode_fec(next, frame_samples)
    {
        let len = fec_pcm.len();
        scratch[..len].copy_from_slice(fec_pcm);
        trace!("FEC recovered {} samples", len);
        plc.good_frame(&scratch[..len]);
        metrics.fec_recovered.fetch_add(1, Ordering::Relaxed);
        return &scratch[..len];
    }

    metrics.plc_generated.fetch_add(1, Ordering::Relaxed);

    if codec.supports_plc()
        && let Ok(pcm) = codec.conceal(frame_samples)
    {
        let len = pcm.len();
        scratch[..len].copy_from_slice(pcm);
        return &scratch[..len];
    }

    plc.conceal()
}

#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::needless_pass_by_value
)]
fn decode_loop(
    config: DecodeThreadConfig,
    mut producer: ringbuf::HeapProd<Sample>,
    mut playback_handle: Box<dyn PlaybackHandle>,
    jitter_buffer: SharedJitterBuffer,
    running: &AtomicBool,
    playback_underruns: &AtomicU64,
    cmd_rx: mpsc::Receiver<DecodeCommand>,
    metrics: &DecodeMetrics,
) {
    // Create codec pipeline (each thread owns its own instance)
    let mut codec = match CodecPipeline::new(config.codec) {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create codec in decode thread: {e}");
            return;
        }
    };

    let codec_clock_rate = codec.clock_rate();
    let codec_samples = codec.samples_per_frame();
    // RTP timestamp units per millisecond on the codec's RTP clock (8 for
    // G.711 and G.722, 48 for Opus) — used to extrapolate the playout clock
    // by wall time when the JB is empty or DTMF arrives between frames.
    // RFC 3551 §4.5.2: G.722's RTP clock is 8000 Hz, not its 16 kHz rate.
    let ts_units_per_ms = rtp_ts_units_per_ms(codec_clock_rate);
    let mut device_rate = config.device_rate;
    #[allow(clippy::cast_possible_truncation)]
    let mut device_samples = (codec_samples as u32 * device_rate / codec_clock_rate) as usize;
    let mut target_fill_frames: usize = INITIAL_FILL_FRAMES;
    let mut target_fill = device_samples * target_fill_frames;

    // Drift compensator: measure every decode cycle for fast response
    let drift_cfg = config.drift.clone();
    let mut drift = DriftCompensator::with_config(1, config.drift);

    // Sinc resampler: automatically selects polyphase (integer ratio) or
    // fractional sinc (arbitrary ratio). Both provide ~50 dB stopband
    // attenuation, eliminating imaging artifacts ("static").
    let mut resampler = Resampler::new(codec_clock_rate, device_rate);
    info!(
        "Using {} resampler ({codec_clock_rate}Hz→{device_rate}Hz)",
        resampler.algorithm_name()
    );

    // Last sample pushed to ring buffer — used for fade-out on jitter buffer empty
    let mut last_output_sample: i16 = 0;

    // LPC-based packet loss concealment
    let mut plc = WsolaPlc::new(codec_samples);
    // Decoder-side postfilter: low-pass tilt complements the encoder-side
    // noise shaper by attenuating the high-frequency noise it boosted.
    let mut postfilter = Postfilter::with_config(&config.postfilter);
    // Comfort noise for remote DTX (jitter buffer empty for extended periods)
    let mut cng = ComfortNoiseGenerator::with_config(config.comfort_noise);
    let mut consecutive_empty: u32 = 0;

    // DTMF payload type from SDP negotiation (typically 101)
    let dtmf_pt = config.dtmf_payload_type;

    // Track current inbound DTMF event to avoid replaying. RFC 4733 sends
    // multiple packets per event (start + continuations + 3× end), all sharing
    // the same RTP timestamp. We keep this set even after end so retransmitted
    // end packets are still filtered by the is_new check.
    // RFC 4733 duration increases monotonically across continuation packets;
    // a decrease indicates a malformed packet (see DtmfRx / ingest_dtmf_event).
    let mut dtmf_rx = DtmfRx::new();
    // DTMF playout state: scheduled events, the active tone generator, and
    // its fade/boundary bookkeeping (see DtmfPlayout / advance_dtmf_schedule).
    let mut dtmf = DtmfPlayout::new();
    // Failsafe: event packets repeat every ~20ms while a tone is held, so a
    // quiet bypass queue for 200ms means every END retransmission was lost.
    let mut dtmf_last_packet = Instant::now();
    // Playout-clock anchor: RTP ts of the last decoded frame and when it was
    // decoded. The JB-empty path extrapolates the playout position from this
    // by wall time — carriers suppress audio outright during rapid DTMF, and
    // scheduled tones must still start/stop on time with no frames arriving.
    let mut last_decoded_ts: Option<u32> = None;
    let mut last_decoded_at = Instant::now();
    // Rate limit for the per-packet "Decode error" warning (SEC-4).
    let mut decode_error_warn = WarnRateLimit::new();

    // Gain gate state: holds the gate open during speech to prevent
    // gain fluctuation at speech boundaries that amplifies quantization noise.
    let mut gain_gate_open = false;
    let mut gain_hold_remaining: u32 = 0;
    let mut current_gain: f32 = 1.0;

    debug!(
        "Decode thread: codec={}, codec_rate={}, device_rate={}, \
         codec_samples={}, device_samples={}, target_fill={}",
        codec.name(),
        codec_clock_rate,
        device_rate,
        codec_samples,
        device_samples,
        target_fill
    );

    // DTMF diagnostics mode (set DUMP_DTMF=1)
    let dtmf_diag = std::env::var(DUMP_DTMF_ENV).is_ok_and(|v| v == "1");

    // Optional audio dump file for debugging (set DUMP_DECODED_AUDIO=1 or DUMP_DTMF=1)
    let mut audio_dump: Option<std::io::BufWriter<std::fs::File>> = std::env::var(DUMP_ENV_VAR)
        .ok()
        .filter(|v| v == "1")
        .or_else(|| if dtmf_diag { Some("1".to_string()) } else { None })
        .and_then(|_| {
            let path = "/tmp/decoded-audio.raw";
            match std::fs::File::create(path) {
                Ok(f) => {
                    info!("Audio dump enabled: writing decoded audio to {path} (s16le, {device_rate}Hz, mono)");
                    Some(std::io::BufWriter::new(f))
                }
                Err(e) => {
                    warn!("Failed to create audio dump file: {e}");
                    None
                }
            }
        });

    // DTMF trace CSV (set DUMP_DTMF=1)
    let mut dtmf_trace: Option<std::io::BufWriter<std::fs::File>> = if dtmf_diag {
        match std::fs::File::create("/tmp/dtmf-trace.csv") {
            Ok(f) => {
                let mut w = std::io::BufWriter::new(f);
                {
                    use std::io::Write;
                    let _ = writeln!(
                        w,
                        "time_us,source,digit,duration,duration_ms,end,is_new,gen_active,decoded_this_cycle"
                    );
                }
                info!("DTMF trace enabled: /tmp/dtmf-trace.csv");
                Some(w)
            }
            Err(e) => {
                warn!("Failed to create DTMF trace file: {e}");
                None
            }
        }
    } else {
        None
    };

    // DTMF tone PCM dump (set DUMP_DTMF=1)
    let mut dtmf_tone_dump: Option<std::io::BufWriter<std::fs::File>> = if dtmf_diag {
        match std::fs::File::create("/tmp/dtmf-tone.raw") {
            Ok(f) => {
                info!("DTMF tone dump enabled: /tmp/dtmf-tone.raw (s16le, {device_rate}Hz, mono)");
                Some(std::io::BufWriter::new(f))
            }
            Err(e) => {
                warn!("Failed to create DTMF tone dump file: {e}");
                None
            }
        }
    } else {
        None
    };

    let dtmf_diag_start = Instant::now();

    // Pre-allocated scratch buffers — reused every frame to avoid heap allocs.
    // `scratch` is used for comfort noise, DTMF tones, fade-out, and silence.
    // `codec_scratch` receives the decoded PCM from the codec (which returns
    // a borrow of its internal buffer — we need a mutable copy for postfilter).
    // `resample_buf` receives resampled output (replaces Vec allocation per frame).
    // +16 headroom for drift adjustment that can slightly increase device_samples.
    let mut scratch = vec![0i16; device_samples + 16];
    let mut codec_scratch = vec![0i16; codec_samples];
    let mut resample_buf = vec![0i16; device_samples + 16];

    // Diagnostic counters
    let mut diag_frames_decoded: u64 = 0;
    let mut diag_frames_lost: u64 = 0;
    let mut diag_jb_empty: u64 = 0;
    let mut diag_peak_pre_gain: i16 = 0;
    let mut diag_peak_post_gain: i16 = 0;
    let mut diag_timer = Instant::now();
    // DTMF diagnostic counters (reset every 2s with other diags)
    let mut diag_dtmf_tone_frames: u64 = 0;

    while running.load(Ordering::Relaxed) {
        // Check ring buffer fill level (lock-free)
        let occupied = producer.occupied_len();

        if occupied >= target_fill {
            // Healthy — wait for condvar signal from I/O thread (packet push).
            // Falls back to 10ms timeout if no packet arrives (e.g., silence
            // suppression / DTX). At 48kHz the CPAL callback consumes ~480
            // samples per 10ms, well within the ring buffer cushion.
            jitter_buffer.wait_for_push(Duration::from_millis(10));
        } else {
            // Determine how many frames to decode based on urgency
            let frames_to_decode = if occupied < device_samples {
                // Critical: ring buffer nearly empty, decode aggressively
                3
            } else if occupied < target_fill / 2 {
                // Below half target — decode 2 frames
                2
            } else {
                // Below target but not critical — 1 frame
                1
            };

            let mut decoded_this_cycle: u32 = 0;

            // Drain DTMF bypass queue (packets arrive here instead of JB
            // when set_dtmf_bypass is configured on the RTP receiver).
            if let Some(ref dtmf_queue) = config.dtmf_queue {
                while let Some(packet) = dtmf_queue.pop() {
                    if packet.payload.len() < 4 {
                        metrics.dtmf_malformed.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let bytes: [u8; 4] = [
                        packet.payload[0],
                        packet.payload[1],
                        packet.payload[2],
                        packet.payload[3],
                    ];
                    let is_new = dtmf_rx.current_ts != Some(packet.timestamp);
                    if let Some(event) = DtmfEvent::decode(&bytes) {
                        // Playout position now: the last decoded frame's
                        // timestamp extrapolated by wall time. Only a NEW
                        // event uses it (start-distance check).
                        let playout_ts = if is_new {
                            last_decoded_ts.map(|anchor| {
                                extrapolate_playout_ts(
                                    anchor,
                                    last_decoded_at.elapsed(),
                                    ts_units_per_ms,
                                )
                            })
                        } else {
                            None
                        };
                        match ingest_dtmf_event(
                            &mut dtmf_rx,
                            &mut dtmf,
                            packet.timestamp,
                            event,
                            playout_ts,
                            metrics,
                        ) {
                            DtmfIngest::Discarded | DtmfIngest::Rejected => continue,
                            DtmfIngest::ShortEnd => {
                                dtmf_last_packet = Instant::now();
                                continue;
                            }
                            DtmfIngest::Scheduled => {
                                dtmf_last_packet = Instant::now();
                                // NIST 800-53 Rev5: AU-4, SC-5 -- per-event
                                // logs are debug: wire input must not drive
                                // info-level log volume.
                                debug!(
                                    "DTMF bypass: NEW event digit={:?} ts={} seq={} end={} dur={}",
                                    event.digit,
                                    packet.timestamp,
                                    packet.sequence,
                                    event.end,
                                    event.duration
                                );
                                if let Some(ref tx) = config.dtmf_rx_tx {
                                    notify_dtmf_rx(tx, event.digit);
                                }
                            }
                            DtmfIngest::Updated => dtmf_last_packet = Instant::now(),
                        }
                        // Write DTMF trace entry
                        if let Some(ref mut trace) = dtmf_trace {
                            use std::io::Write;
                            let _ = writeln!(
                                trace,
                                "{},bypass,{:?},{},{},{},{},{},{}",
                                dtmf_diag_start.elapsed().as_micros(),
                                event.digit,
                                event.duration,
                                event.duration_to_ms(),
                                event.end,
                                is_new,
                                dtmf.active_gen.is_some(),
                                decoded_this_cycle,
                            );
                        }
                        if event.end {
                            debug!(
                                "DTMF bypass: END digit={:?} ts={} dur={}ms",
                                event.digit,
                                packet.timestamp,
                                event.duration_to_ms()
                            );
                            // The generator keeps running: it stops on the
                            // first decoded frame at/after dtmf.end_ts, which
                            // is when the event end reaches the playout
                            // timeline (the JB still holds in-event frames
                            // right now).
                        }
                    }
                }
            }

            for _ in 0..frames_to_decode {
                // Re-check the DTMF bypass queue between frames: carriers
                // flush the event-window audio as a burst right before the
                // first event packet, and decoding through that burst in one
                // cycle would play its muted frames before the event
                // activates the tone generator (heard as a gap splitting the
                // tone). Breaking re-runs the outer cycle, which drains the
                // bypass queue first.
                if let Some(ref q) = config.dtmf_queue
                    && !q.is_empty()
                {
                    break;
                }

                // Get drift adjustment from compensator
                #[allow(clippy::cast_precision_loss)]
                let depth_ms = jitter_buffer.buffered_duration_ms() as f32;
                let drift_adj = drift.update(depth_ms);
                #[allow(
                    clippy::cast_sign_loss,
                    clippy::cast_possible_truncation,
                    clippy::cast_possible_wrap
                )]
                let adjusted_device_samples = (device_samples as i32 + drift_adj).max(1) as usize;

                match jitter_buffer.pop() {
                    JitterBufferResult::Packet(packet) => {
                        consecutive_empty = 0;

                        // Handle RFC 3389 Comfort Noise packets (PT=13)
                        if packet.payload_type == proto_rtp::payload_types::CN {
                            // CN carries a valid RTP timestamp on the audio
                            // clock (RFC 3389 §4): re-anchor the playout
                            // clock so DTMF during VAD silence is measured
                            // from here, not from the last speech frame.
                            last_decoded_ts = Some(packet.timestamp);
                            last_decoded_at = Instant::now();
                            let noise_level = decode_cn_payload(&packet.payload);
                            cng.update_level(noise_level);
                            let cn_buf = &mut scratch[..adjusted_device_samples];
                            cn_buf.fill(0);
                            cng.generate(cn_buf);
                            producer.push_slice(cn_buf);
                            decoded_this_cycle += 1;
                            continue;
                        }

                        // Telephone-event packets ride through the JB to
                        // keep its sequence-number stream continuous (gaps
                        // stall it as presumed loss). All event handling —
                        // scheduling, tone generation — happens via the
                        // bypass queue drained at the top of the cycle; here
                        // they are simply consumed.
                        if packet.payload_type == dtmf_pt {
                            continue;
                        }

                        // Audio packet: always decode to keep codec state warm
                        // (ADPCM/LPC predictors need continuous input).
                        decoded_this_cycle += 1;

                        // Decode into codec's internal buffer, then copy to our scratch
                        let codec_pcm = match codec.decode(&packet.payload) {
                            Ok(pcm) => pcm,
                            Err(e) => {
                                metrics.decode_errors.fetch_add(1, Ordering::Relaxed);
                                if let Some(suppressed) = decode_error_warn.check(Instant::now()) {
                                    warn!("Decode error: {e} ({suppressed} suppressed)");
                                }
                                break;
                            }
                        };

                        // Copy to pre-allocated buffer (codec returns a borrow
                        // of its internal buffer; we need a mutable copy for
                        // PLC cross-fade and postfilter). A frame longer than
                        // one ptime is dropped and counted, not copied.
                        let Some(codec_buf) =
                            copy_decoded_frame(codec_pcm, &mut codec_scratch, metrics)
                        else {
                            continue;
                        };

                        // If recovering from loss, cross-fade for smooth transition
                        if plc.consecutive_losses() > 0 {
                            plc.recover(codec_buf);
                        } else {
                            plc.good_frame(codec_buf);
                        }

                        // If DTMF tone is active, discard decoded audio and
                        // generate tone instead. BulkVS sends audio interleaved
                        // with telephone-event packets — we must replace the audio
                        // with locally-generated tone, not just wait for JB empty.
                        // Anchor the playout clock: when the JB runs dry the
                        // empty branch extrapolates from here by wall time.
                        last_decoded_ts = Some(packet.timestamp);
                        last_decoded_at = Instant::now();

                        // Activate/expire scheduled tones at this frame's
                        // position on the playout timeline. The first decoded
                        // frame at/after the event-end ts is the boundary
                        // frame — fade the tone back into the decoded audio
                        // across it and stop the generator.
                        let dtmf_end_reached =
                            advance_dtmf_schedule(packet.timestamp, &mut dtmf, device_rate);
                        if dtmf_end_reached {
                            if let Some(mut tone_gen) = dtmf.active_gen.take() {
                                let tone_buf = &mut scratch[..adjusted_device_samples];
                                tone_gen.generate_samples(tone_buf);
                                let device_pcm = &mut resample_buf[..adjusted_device_samples];
                                resampler.process_adjusted_into(codec_buf, device_pcm);
                                crossfade_frames(
                                    tone_buf,
                                    device_pcm,
                                    device_rate as usize / 200,
                                    false,
                                );

                                if let Some(ref mut dump) = dtmf_tone_dump {
                                    dump_samples(dump, tone_buf);
                                }
                                if let Some(ref mut dump) = audio_dump {
                                    dump_samples(dump, tone_buf);
                                }
                                diag_dtmf_tone_frames += 1;
                                producer.push_slice(tone_buf);
                            }
                            dtmf.clear_active();
                            continue;
                        }

                        if let Some(ref mut tone_gen) = dtmf.active_gen {
                            let tone_buf = &mut scratch[..adjusted_device_samples];
                            tone_gen.generate_samples(tone_buf);

                            if dtmf.fade_in {
                                // First replaced frame: ramp decoded audio into
                                // the tone to mask the splice from any leaked
                                // in-band tone already played.
                                let device_pcm = &mut resample_buf[..adjusted_device_samples];
                                resampler.process_adjusted_into(codec_buf, device_pcm);
                                crossfade_frames(
                                    tone_buf,
                                    device_pcm,
                                    device_rate as usize / 200,
                                    true,
                                );
                                dtmf.fade_in = false;
                            }

                            if let Some(ref mut dump) = dtmf_tone_dump {
                                dump_samples(dump, tone_buf);
                            }
                            if let Some(ref mut dump) = audio_dump {
                                dump_samples(dump, tone_buf);
                            }
                            diag_dtmf_tone_frames += 1;
                            producer.push_slice(tone_buf);
                            continue;
                        }

                        // Postfilter: reduce G.711 quantization noise
                        // (operates at codec rate before resampling for maximum effect)
                        postfilter.process(codec_buf);

                        // Push codec-rate PCM to AEC reference buffer (before resample).
                        // The I/O thread pulls this as the far-end reference signal.
                        if let Some(ref aec_ref) = config.aec_ref {
                            aec_ref.push(codec_buf);
                        }

                        // Resample from codec rate to device rate (zero-alloc)
                        let device_pcm = &mut resample_buf[..adjusted_device_samples];
                        resampler.process_adjusted_into(codec_buf, device_pcm);

                        // Apply headroom to prevent sinc overshoot clipping
                        #[allow(clippy::cast_possible_truncation)]
                        for s in device_pcm.iter_mut() {
                            *s = (f32::from(*s) * RESAMPLE_HEADROOM) as i16;
                        }

                        // Track peak amplitude before gain
                        let peak = device_pcm
                            .iter()
                            .map(|s| s.saturating_abs())
                            .max()
                            .unwrap_or(0);
                        if peak > diag_peak_pre_gain {
                            diag_peak_pre_gain = peak;
                        }

                        // Update gain gate with hold timer.
                        // The gate stays open for GAIN_HOLD_FRAMES after the last
                        // speech-level peak, preventing gain fluctuation at the
                        // tail of sentences (where quantization noise is worst).
                        if peak >= GATE_OPEN_PEAK {
                            gain_gate_open = true;
                            gain_hold_remaining = GAIN_HOLD_FRAMES;
                        } else if gain_hold_remaining > 0 {
                            gain_hold_remaining -= 1;
                        } else if peak < GATE_CLOSE_PEAK {
                            gain_gate_open = false;
                        }

                        // Smooth exponential ramp toward target gain
                        let target_gain = if gain_gate_open { PLAYBACK_GAIN } else { 1.0 };
                        current_gain =
                            (target_gain - current_gain).mul_add(GAIN_RAMP_SPEED, current_gain);

                        // Apply gain in-place and track post-gain peak in a single pass
                        let mut frame_post_peak: i16 = 0;
                        for s in &mut *device_pcm {
                            #[allow(clippy::cast_possible_truncation)]
                            {
                                *s = (f32::from(*s) * current_gain).clamp(-32768.0, 32767.0) as i16;
                            }
                            let abs = s.saturating_abs();
                            if abs > frame_post_peak {
                                frame_post_peak = abs;
                            }
                        }
                        if frame_post_peak > diag_peak_post_gain {
                            diag_peak_post_gain = frame_post_peak;
                        }

                        // Track last output for fade-out
                        if let Some(&last) = device_pcm.last() {
                            last_output_sample = last;
                        }

                        // Write to audio dump file if enabled
                        if let Some(ref mut dump) = audio_dump {
                            dump_samples(dump, device_pcm);
                        }

                        let written = producer.push_slice(device_pcm);
                        if written < device_pcm.len() {
                            trace!(
                                "Ring buffer full: wrote {}/{} samples",
                                written,
                                device_pcm.len()
                            );
                        }

                        diag_frames_decoded += 1;
                    }
                    JitterBufferResult::Lost { fec_source, .. } => {
                        decoded_this_cycle += 1;

                        // In-band FEC from packet N+1 first, then codec-native
                        // PLC, then WSOLA. Every path yields exactly one ptime
                        // of audio (zero-alloc).
                        let concealed = conceal_lost_frame(
                            &mut codec,
                            &mut plc,
                            &mut codec_scratch,
                            fec_source.as_deref(),
                            codec_samples,
                            metrics,
                        );

                        // Resample concealed audio to device rate (zero-alloc)
                        let device_pcm = &mut resample_buf[..device_samples];
                        resampler.process_adjusted_into(concealed, device_pcm);

                        if let Some(&last) = device_pcm.last() {
                            last_output_sample = last;
                        }

                        producer.push_slice(device_pcm);
                        diag_frames_lost += 1;
                    }
                    JitterBufferResult::Empty | JitterBufferResult::NotReady => {
                        // If we already decoded real audio this cycle, just stop.
                        if decoded_this_cycle > 0 {
                            break;
                        }

                        // No frames to key the playout clock from: extrapolate
                        // by wall time so scheduled tones still start and stop
                        // on time (carriers suppress audio during rapid DTMF).
                        if let Some(anchor_ts) = last_decoded_ts {
                            let now_ts = extrapolate_playout_ts(
                                anchor_ts,
                                last_decoded_at.elapsed(),
                                ts_units_per_ms,
                            );
                            let end_reached = advance_dtmf_schedule(now_ts, &mut dtmf, device_rate);
                            if end_reached && let Some(mut tone_gen) = dtmf.active_gen.take() {
                                // Boundary frame with no decoded audio to
                                // blend into: fade the tone into silence.
                                let tone_buf = &mut scratch[..device_samples];
                                tone_gen.generate_samples(tone_buf);
                                let silence = &mut resample_buf[..device_samples];
                                silence.fill(0);
                                crossfade_frames(
                                    tone_buf,
                                    silence,
                                    device_rate as usize / 200,
                                    false,
                                );
                                if let Some(ref mut dump) = dtmf_tone_dump {
                                    dump_samples(dump, tone_buf);
                                }
                                if let Some(ref mut dump) = audio_dump {
                                    dump_samples(dump, tone_buf);
                                }
                                diag_dtmf_tone_frames += 1;
                                producer.push_slice(tone_buf);
                                dtmf.clear_active();
                                break;
                            }
                        }

                        // If a DTMF tone is active, keep generating frames
                        // even though the JB is empty (DTMF packets may arrive
                        // sparsely while the tone should sustain continuously).
                        if let Some(ref mut tone_gen) = dtmf.active_gen {
                            let tone_buf = &mut scratch[..device_samples];
                            tone_buf.fill(0);
                            tone_gen.generate_samples(tone_buf);

                            if dtmf.fade_in {
                                // Tone starts from silence here: short attack.
                                let silence = &mut resample_buf[..device_samples];
                                silence.fill(0);
                                crossfade_frames(
                                    tone_buf,
                                    silence,
                                    device_rate as usize / 200,
                                    true,
                                );
                                dtmf.fade_in = false;
                            }

                            // Dump tone PCM for analysis
                            if let Some(ref mut dump) = dtmf_tone_dump {
                                dump_samples(dump, tone_buf);
                            }
                            // Also write to main audio dump
                            if let Some(ref mut dump) = audio_dump {
                                dump_samples(dump, tone_buf);
                            }
                            if let Some(ref mut trace) = dtmf_trace {
                                use std::io::Write;
                                let peak = tone_buf
                                    .iter()
                                    .map(|s| s.saturating_abs())
                                    .max()
                                    .unwrap_or(0);
                                let _ = writeln!(
                                    trace,
                                    "{},tone_frame,,{},{},false,false,true,{}",
                                    dtmf_diag_start.elapsed().as_micros(),
                                    device_samples,
                                    peak,
                                    decoded_this_cycle,
                                );
                            }
                            diag_dtmf_tone_frames += 1;

                            producer.push_slice(tone_buf);
                            break;
                        }

                        diag_jb_empty += 1;

                        // The JB is momentarily empty. Check the ring buffer:
                        // if it still has a healthy cushion (> 2 frames), the
                        // existing samples will carry CPAL through until the next
                        // JB packet arrives (~20ms). Do NOT push silence/fade here
                        // because it interleaves gaps between real audio frames —
                        // the primary cause of choppiness.
                        let current_fill = producer.occupied_len();
                        if current_fill > device_samples * 2 {
                            break;
                        }

                        // Ring buffer critically low AND JB starved — inject
                        // fade/silence to prevent CPAL hard underrun.
                        consecutive_empty += 1;

                        let fill_buf = &mut scratch[..device_samples];
                        if consecutive_empty == 1 {
                            // Cosine fade-out from last output to zero.
                            #[allow(clippy::cast_precision_loss)]
                            let len_f = device_samples as f32;
                            for (i, sample) in fill_buf.iter_mut().enumerate() {
                                #[allow(clippy::cast_precision_loss)]
                                let t = i as f32 / len_f;
                                let gain = f32::midpoint(1.0, (std::f32::consts::PI * t).cos());
                                #[allow(clippy::cast_possible_truncation)]
                                {
                                    *sample = (f32::from(last_output_sample) * gain) as i16;
                                }
                            }
                            last_output_sample = 0;
                        } else if consecutive_empty >= 10 {
                            // After sustained emptiness, inject comfort noise.
                            cng.update_level(20.0);
                            fill_buf.fill(0);
                            cng.generate(fill_buf);
                        } else {
                            // Push silence to prevent ring buffer underrun.
                            fill_buf.fill(0);
                        }
                        producer.push_slice(fill_buf);

                        break;
                    }
                }
            }

            // NOTE: there used to be a "fast-drain" here that discarded JB
            // packets above a threshold while a DTMF generator was active.
            // It cut 120-140ms of stream at every tone onset (the carrier
            // bursts the event-window audio), starving the decode loop and
            // splitting the tone with silence. Latency creep is the adaptive
            // JB's and drift compensator's job; do not re-add a drain here.

            // Failsafe: event packets repeat every ~20ms while a tone is
            // held; 200ms without one means all END retransmissions were
            // lost (or the stream died) — stop the tone rather than letting
            // it ring until the next decoded frame crosses dtmf.end_ts.
            if (dtmf.active_gen.is_some() || !dtmf.schedule.is_empty())
                && dtmf_last_packet.elapsed() > Duration::from_millis(200)
            {
                trace!("DTMF failsafe: no event packets for 200ms, stopping tone");
                dtmf.clear_active();
                dtmf.schedule.clear();
            }

            // Wait for next packet notification instead of blind sleep.
            // After a successful decode, use 1ms timeout to quickly drain
            // burst arrivals. If JB was empty, use 5ms (matches the I/O
            // thread's socket recv_timeout).
            let wait_ms = if decoded_this_cycle > 0 { 1 } else { 5 };
            jitter_buffer.wait_for_push(Duration::from_millis(wait_ms));
        }

        // Check for commands (output device switch)
        if let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                DecodeCommand::SwitchOutputDevice(device_name) => {
                    info!(
                        "Decode thread: switching output device to {:?}",
                        device_name
                    );
                    let mut dm = crate::device::DeviceManager::new();
                    dm.set_output_device(device_name);
                    match create_playback(&dm) {
                        Ok(new_playback) => {
                            let new_rate = new_playback.sample_rate();
                            let (new_handle, mut new_producer, _new_underruns) =
                                new_playback.take_producer();

                            // Pre-fill new ring buffer with silence so CPAL has
                            // a cushion before the decode loop catches up.
                            #[allow(clippy::cast_possible_truncation)]
                            let prefill = (new_rate * 100 / 1000) as usize; // 100ms
                            let silence = vec![0i16; prefill];
                            new_producer.push_slice(&silence);

                            // Stop old stream first, then swap to new
                            playback_handle.stop();
                            producer = new_producer;
                            playback_handle = new_handle;

                            if new_rate != device_rate {
                                let old_rate = device_rate;
                                device_rate = new_rate;
                                #[allow(clippy::cast_possible_truncation)]
                                {
                                    device_samples = (codec_samples as u32 * device_rate
                                        / codec_clock_rate)
                                        as usize;
                                }
                                target_fill = device_samples * target_fill_frames;
                                scratch.resize(device_samples + 16, 0);
                                resample_buf.resize(device_samples + 16, 0);
                                resampler = Resampler::new(codec_clock_rate, device_rate);
                                drift = DriftCompensator::with_config(1, drift_cfg.clone());
                                info!(
                                    "Decode thread: playback rate changed {}→{}Hz, \
                                     using {} resampler, frame size {} samples",
                                    old_rate,
                                    device_rate,
                                    resampler.algorithm_name(),
                                    device_samples
                                );
                            }
                            info!("Decode thread: output device switched successfully");
                        }
                        Err(e) => {
                            warn!("Decode thread: failed to switch output device: {e}");
                        }
                    }
                }
            }
        }

        // Auto-recover from playback device disappearance (USB/Bluetooth disconnect).
        // If the CPAL error callback fired, switch to the system default output device.
        if playback_handle.has_error() {
            warn!("Decode thread: playback device error detected, switching to default output");
            let mut dm = crate::device::DeviceManager::new();
            dm.set_output_device(None);
            match create_playback(&dm) {
                Ok(new_playback) => {
                    let new_rate = new_playback.sample_rate();
                    let (new_handle, mut new_producer, _new_underruns) =
                        new_playback.take_producer();

                    // Pre-fill new ring buffer with silence
                    #[allow(clippy::cast_possible_truncation)]
                    let prefill = (new_rate * 100 / 1000) as usize; // 100ms
                    let silence = vec![0i16; prefill];
                    new_producer.push_slice(&silence);

                    playback_handle.stop();
                    producer = new_producer;
                    playback_handle = new_handle;

                    if new_rate != device_rate {
                        let old_rate = device_rate;
                        device_rate = new_rate;
                        #[allow(clippy::cast_possible_truncation)]
                        {
                            device_samples =
                                (codec_samples as u32 * device_rate / codec_clock_rate) as usize;
                        }
                        target_fill = device_samples * target_fill_frames;
                        scratch.resize(device_samples + 16, 0);
                        resample_buf.resize(device_samples + 16, 0);
                        resampler = Resampler::new(codec_clock_rate, device_rate);
                        drift = DriftCompensator::with_config(1, drift_cfg.clone());
                        info!(
                            "Decode thread: playback rate changed {}→{}Hz after recovery",
                            old_rate, device_rate,
                        );
                    }
                    info!("Decode thread: playback device recovered to default");
                }
                Err(e) => {
                    warn!("Decode thread: failed to recover playback device: {e}");
                    // Sleep briefly to avoid spinning on repeated failures
                    thread::sleep(Duration::from_millis(500));
                }
            }
        }

        // Diagnostic logging + adaptive ring buffer fill — every ~2 seconds
        if diag_timer.elapsed() >= Duration::from_secs(2) {
            let jb_stats = jitter_buffer.stats();
            let underruns = playback_underruns.load(Ordering::Relaxed);

            // Adapt ring buffer target fill based on JB health.
            // Lower fill = lower latency, higher underrun risk.
            let new_fill_frames = if underruns > 0 {
                // Underruns detected — stay conservative
                INITIAL_FILL_FRAMES
            } else if jb_stats.current_depth_ms <= 30 {
                // JB converged to low depth — safe to use fewer frames
                MIN_FILL_FRAMES
            } else if jb_stats.current_depth_ms <= 50 {
                // Intermediate: ceil(depth / 20) clamped to [MIN, MAX]
                #[allow(clippy::cast_possible_truncation)]
                let frames = jb_stats.current_depth_ms.div_ceil(20) as usize;
                frames.clamp(MIN_FILL_FRAMES, MAX_FILL_FRAMES)
            } else {
                INITIAL_FILL_FRAMES
            };

            if new_fill_frames != target_fill_frames {
                debug!(
                    "Adaptive fill: {} -> {} frames (jb_depth={}ms, underruns={})",
                    target_fill_frames, new_fill_frames, jb_stats.current_depth_ms, underruns,
                );
                target_fill_frames = new_fill_frames;
                target_fill = device_samples * target_fill_frames;
            }

            info!(
                "Decode diag: decoded={}, lost={}, jb_empty={}, ring_fill={}/{} ({}f), \
                 jb_pkts={}, jb_depth={}ms, jb_jitter={:.1}ms, pb_underruns={}, \
                 peak_pre={}, peak_post={}, gain={:.2}, \
                 dtmf_tone_frames={}, dtmf_gen_active={}",
                diag_frames_decoded,
                diag_frames_lost,
                diag_jb_empty,
                producer.occupied_len(),
                target_fill,
                target_fill_frames,
                jb_stats.current_packet_count,
                jb_stats.current_depth_ms,
                jb_stats.average_jitter_ms,
                underruns,
                diag_peak_pre_gain,
                diag_peak_post_gain,
                current_gain,
                diag_dtmf_tone_frames,
                dtmf.active_gen.is_some(),
            );
            diag_peak_pre_gain = 0;
            diag_peak_post_gain = 0;
            diag_dtmf_tone_frames = 0;
            diag_timer = Instant::now();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DecodeMetrics, conceal_lost_frame};
    use crate::codec::CodecPipeline;
    use crate::wsola::WsolaPlc;
    use client_types::CodecPreference;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_lost_frame_g711_uses_wsola_plc() {
        let mut codec = CodecPipeline::new(CodecPreference::G711Ulaw).unwrap();
        let spf = codec.samples_per_frame();
        let mut plc = WsolaPlc::new(spf);
        let mut scratch = vec![0i16; spf];
        let metrics = DecodeMetrics::new();
        let out = conceal_lost_frame(
            &mut codec,
            &mut plc,
            &mut scratch,
            Some(&[0xFF; 160]),
            spf,
            &metrics,
        );
        assert_eq!(out.len(), spf);
        assert_eq!(metrics.fec_recovered.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.plc_generated.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "opus-ffi")]
    fn opus_packets(codec: &mut CodecPipeline, frames: usize) -> Vec<Vec<u8>> {
        let spf = codec.samples_per_frame();
        (0..frames)
            .map(|f| {
                let pcm: Vec<i16> = (0..spf)
                    .map(|i| {
                        #[allow(clippy::cast_precision_loss)]
                        let t = (f * spf + i) as f32 / 48000.0;
                        #[allow(clippy::cast_possible_truncation)]
                        let v = (f32::sin(2.0 * std::f32::consts::PI * 200.0 * t) * 8000.0) as i16;
                        v
                    })
                    .collect();
                codec.encode(&pcm).unwrap().to_vec()
            })
            .collect()
    }

    #[cfg(feature = "opus-ffi")]
    #[test]
    fn test_lost_frame_opus_with_next_packet_uses_fec() {
        let mut enc = CodecPipeline::new(CodecPreference::Opus).unwrap();
        let packets = opus_packets(&mut enc, 12);
        let mut codec = CodecPipeline::new(CodecPreference::Opus).unwrap();
        let spf = codec.samples_per_frame();
        for p in &packets[..10] {
            codec.decode(p).unwrap();
        }
        let mut plc = WsolaPlc::new(spf);
        let mut scratch = vec![0i16; spf];
        let metrics = DecodeMetrics::new();
        let out = conceal_lost_frame(
            &mut codec,
            &mut plc,
            &mut scratch,
            Some(&packets[11]),
            spf,
            &metrics,
        );
        assert_eq!(out.len(), spf, "lost 20 ms frame must yield 20 ms");
        assert_eq!(metrics.fec_recovered.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.plc_generated.load(Ordering::Relaxed), 0);
    }

    #[cfg(feature = "opus-ffi")]
    #[test]
    fn test_lost_frame_opus_without_next_packet_uses_native_plc() {
        let mut enc = CodecPipeline::new(CodecPreference::Opus).unwrap();
        let packets = opus_packets(&mut enc, 10);
        let mut codec = CodecPipeline::new(CodecPreference::Opus).unwrap();
        let spf = codec.samples_per_frame();
        for p in &packets {
            codec.decode(p).unwrap();
        }
        let mut plc = WsolaPlc::new(spf);
        let mut scratch = vec![0i16; spf];
        let metrics = DecodeMetrics::new();
        let out = conceal_lost_frame(&mut codec, &mut plc, &mut scratch, None, spf, &metrics);
        assert_eq!(out.len(), spf);
        assert_eq!(metrics.fec_recovered.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.plc_generated.load(Ordering::Relaxed), 1);
    }

    use super::*;

    #[test]
    fn test_spawn_and_stop() {
        // Create a real playback stream (skip if no audio device available)
        let dm = crate::device::DeviceManager::new();
        let Ok(playback) = create_playback(&dm) else {
            return; // skip if no audio device
        };
        let (playback_handle, producer, underruns) = playback.take_producer();
        let running = Arc::new(AtomicBool::new(true));
        let jb = SharedJitterBuffer::new(8000, 160, 60);

        let config = DecodeThreadConfig {
            codec: CodecPreference::G711Ulaw,
            device_rate: playback_handle.sample_rate(),
            dtmf_payload_type: 101,
            aec_ref: None,
            drift: DriftConfig::default(),
            postfilter: PostfilterConfig::default(),
            comfort_noise: ComfortNoiseConfig::default(),
            dtmf_rx_tx: None,
            dtmf_queue: None,
        };

        let metrics = DecodeMetrics::new();
        let mut handle = spawn(
            config,
            producer,
            playback_handle,
            jb,
            running,
            underruns,
            metrics,
        );

        // Let it run briefly
        thread::sleep(Duration::from_millis(50));

        // Stop should return quickly
        handle.stop();
    }

    #[test]
    fn test_decode_thread_config() {
        let config = DecodeThreadConfig {
            codec: CodecPreference::G711Ulaw,
            device_rate: 48000,
            dtmf_payload_type: 101,
            aec_ref: None,
            drift: DriftConfig::default(),
            postfilter: PostfilterConfig::default(),
            comfort_noise: ComfortNoiseConfig::default(),
            dtmf_rx_tx: None,
            dtmf_queue: None,
        };
        assert_eq!(config.device_rate, 48000);
        assert_eq!(config.dtmf_payload_type, 101);
    }

    #[test]
    fn test_dtmf_duration_constants() {
        // DTMF_MIN_DURATION = 40ms at 8kHz = 320 samples
        assert_eq!(DTMF_MIN_DURATION, 320);
        // DTMF_MAX_DURATION = 5000ms at 8kHz = 40000 samples
        assert_eq!(DTMF_MAX_DURATION, 40000);
    }

    #[test]
    fn test_dtmf_validation_event_code() {
        // Valid event codes 0-16
        for code in 0..=16 {
            let bytes = [code, 0x80, 0x03, 0x20]; // end=true, duration=800 (100ms)
            assert!(
                DtmfEvent::decode(&bytes).is_some(),
                "Code {code} should be valid"
            );
        }
        // Invalid event code 17+
        for code in 17..=255 {
            let bytes = [code, 0x80, 0x03, 0x20];
            assert!(
                DtmfEvent::decode(&bytes).is_none(),
                "Code {code} should be invalid"
            );
        }
    }

    #[test]
    fn test_dtmf_validation_duration_range() {
        // Duration at 40ms minimum: 320 (0x0140)
        let event = DtmfEvent::decode(&[5, 0x80, 0x01, 0x40]).unwrap();
        assert_eq!(event.duration, 320);
        assert!(event.duration >= DTMF_MIN_DURATION);

        // Duration at 5000ms maximum: 40000 (0x9C40)
        let event = DtmfEvent::decode(&[5, 0x80, 0x9C, 0x40]).unwrap();
        assert_eq!(event.duration, 40000);
        assert!(event.duration <= DTMF_MAX_DURATION);

        // Duration over max: 40001 should be rejected by decode loop
        let event = DtmfEvent::decode(&[5, 0x80, 0x9C, 0x41]).unwrap();
        assert!(event.duration > DTMF_MAX_DURATION);
    }

    /// SEC-N-001: a G.711 payload longer than one 20 ms frame decodes to
    /// more samples than the one-ptime scratch buffer holds. The frame is
    /// dropped and counted; the copy used to index past the buffer and panic.
    #[test]
    fn test_oversized_decoded_frame_is_dropped_and_counted() {
        let mut codec = CodecPipeline::new(CodecPreference::G711Ulaw).unwrap();
        let spf = codec.samples_per_frame();
        let mut scratch = vec![0i16; spf];
        let metrics = DecodeMetrics::new();

        // 161 bytes (one over), 320 bytes (ptime 40) and 2880 bytes (the
        // codec's own decode-buffer limit).
        for (dropped, len) in [(1_u64, spf + 1), (2, 320), (3, 2880)] {
            let payload = vec![0xFF_u8; len];
            let pcm = codec.decode(&payload).unwrap();
            assert_eq!(pcm.len(), len);
            assert!(copy_decoded_frame(pcm, &mut scratch, &metrics).is_none());
            assert_eq!(
                metrics.oversized_frames_dropped.load(Ordering::Relaxed),
                dropped
            );
        }

        // One frame and shorter frames (including empty) are still copied.
        for len in [spf, spf - 1, 1, 0] {
            let payload = vec![0xFF_u8; len];
            let pcm = codec.decode(&payload).unwrap();
            let frame = copy_decoded_frame(pcm, &mut scratch, &metrics).unwrap();
            assert_eq!(frame.len(), len);
        }
        assert_eq!(metrics.oversized_frames_dropped.load(Ordering::Relaxed), 3);
    }

    /// Playback handle with no audio device behind it.
    struct NullPlayback;

    impl PlaybackHandle for NullPlayback {
        fn sample_rate(&self) -> u32 {
            48000
        }
        fn is_running(&self) -> bool {
            true
        }
        fn has_error(&self) -> bool {
            false
        }
        fn stop(&self) {}
    }

    /// SEC-N-001 end to end: no RTP payload length may panic the decode
    /// thread. Hostile lengths are fed through the jitter buffer into the
    /// running decode loop, followed by normal frames that must still play.
    #[test]
    fn test_decode_thread_survives_any_payload_length() {
        use crate::jitter_buffer::BufferedPacket;
        use bytes::Bytes;
        use ringbuf::traits::{Consumer, Split};

        let (producer, mut consumer) = ringbuf::HeapRb::<Sample>::new(48000).split();
        let running = Arc::new(AtomicBool::new(true));
        let jb = SharedJitterBuffer::new(8000, 160, 60);
        let metrics = DecodeMetrics::new();

        // 40 ms, one-over, decode-buffer limit, beyond it, empty, one byte;
        // then ordinary 20 ms frames.
        let lengths = [320_usize, 161, 2880, 4000, 0, 1, 160, 160, 160, 160];
        for (i, len) in lengths.iter().enumerate() {
            let seq = u16::try_from(i).unwrap();
            let ts = u32::from(seq) * 160;
            assert!(jb.push(BufferedPacket::new(
                seq,
                ts,
                0,
                Bytes::from(vec![0xFF_u8; *len])
            )));
        }

        let config = DecodeThreadConfig {
            codec: CodecPreference::G711Ulaw,
            device_rate: 48000,
            dtmf_payload_type: 101,
            aec_ref: None,
            drift: DriftConfig::default(),
            postfilter: PostfilterConfig::default(),
            comfort_noise: ComfortNoiseConfig::default(),
            dtmf_rx_tx: None,
            dtmf_queue: None,
        };
        let mut handle = spawn(
            config,
            producer,
            Box::new(NullPlayback),
            jb.clone(),
            running,
            Arc::new(AtomicU64::new(0)),
            metrics.clone(),
        );

        // Play out like the device callback would, until the loop has
        // worked through every queued packet.
        let mut played = 0_usize;
        let mut sink = vec![0i16; 4800];
        let deadline = Instant::now() + Duration::from_secs(5);
        while !jb.is_empty() && Instant::now() < deadline {
            played += consumer.pop_slice(&mut sink);
            thread::sleep(Duration::from_millis(10));
        }
        thread::sleep(Duration::from_millis(50));
        played += consumer.pop_slice(&mut sink);

        assert!(jb.is_empty(), "decode loop stopped consuming packets");
        assert!(
            handle.thread.as_ref().is_some_and(|t| !t.is_finished()),
            "decode thread died on a hostile payload length"
        );
        assert_eq!(
            metrics.oversized_frames_dropped.load(Ordering::Relaxed),
            3,
            "320-, 161- and 2880-sample frames are dropped and counted"
        );
        assert!(
            played > 0,
            "frames after the hostile ones were not played out"
        );

        handle.stop();
    }

    // ---- QA round 1 (B3): payload-length table per codec ----

    /// What the running decode thread did with a sequence of RTP payloads.
    struct QaDecodeRun {
        /// `DecodeMetrics::oversized_frames_dropped` at the end.
        oversized_dropped: u64,
        /// Samples that reached the playback ring buffer.
        played: usize,
        /// Whether the decode thread was still running at the end.
        alive: bool,
        /// Whether every queued packet was consumed.
        drained: bool,
    }

    /// Feeds `payloads` (one RTP packet each, payload type `payload_type`,
    /// timestamps `ts_step` apart) through the jitter buffer into a running
    /// decode thread for `codec`, the way the I/O thread hands over what
    /// `RtpReceiver` accepted, and plays the output out.
    fn qa_run_decode_thread(
        codec: CodecPreference,
        payload_type: u8,
        ts_step: u32,
        payloads: Vec<Vec<u8>>,
    ) -> QaDecodeRun {
        use crate::jitter_buffer::BufferedPacket;
        use bytes::Bytes;
        use ringbuf::traits::{Consumer, Split};

        let (producer, mut consumer) = ringbuf::HeapRb::<Sample>::new(96000).split();
        let running = Arc::new(AtomicBool::new(true));
        let jb = SharedJitterBuffer::new(ts_step * 50, ts_step, 60);
        let metrics = DecodeMetrics::new();

        for (i, payload) in payloads.into_iter().enumerate() {
            let seq = u16::try_from(i).unwrap();
            assert!(jb.push(BufferedPacket::new(
                seq,
                u32::from(seq) * ts_step,
                payload_type,
                Bytes::from(payload)
            )));
        }

        let config = DecodeThreadConfig {
            codec,
            device_rate: 48000,
            dtmf_payload_type: 101,
            aec_ref: None,
            drift: DriftConfig::default(),
            postfilter: PostfilterConfig::default(),
            comfort_noise: ComfortNoiseConfig::default(),
            dtmf_rx_tx: None,
            dtmf_queue: None,
        };
        let mut handle = spawn(
            config,
            producer,
            Box::new(NullPlayback),
            jb.clone(),
            running,
            Arc::new(AtomicU64::new(0)),
            metrics.clone(),
        );

        let mut played = 0_usize;
        let mut sink = vec![0i16; 4800];
        let deadline = Instant::now() + Duration::from_secs(10);
        while !jb.is_empty() && Instant::now() < deadline {
            played += consumer.pop_slice(&mut sink);
            thread::sleep(Duration::from_millis(5));
        }
        thread::sleep(Duration::from_millis(60));
        played += consumer.pop_slice(&mut sink);

        let run = QaDecodeRun {
            oversized_dropped: metrics.oversized_frames_dropped.load(Ordering::Relaxed),
            played,
            alive: handle.thread.as_ref().is_some_and(|t| !t.is_finished()),
            drained: jb.is_empty(),
        };
        handle.stop();
        run
    }

    /// Payload lengths around every boundary on the decode path: empty, one
    /// byte, one G.711 frame (160) and one over (161), 40 ms (320) and its
    /// neighbours, the G.722 decode-buffer limit in bytes (1440) and its
    /// neighbours, the largest payload a 1500-byte datagram carries (1488),
    /// the codec decode-buffer limit in samples (2880) and its neighbours,
    /// and well beyond it. The I/O path cannot deliver more than 1488 bytes
    /// in one packet; the larger ones show the decode thread does not depend
    /// on that. Normal frames follow and must still be played.
    const QA_HOSTILE_PAYLOAD_LENGTHS: [usize; 20] = [
        0, 1, 159, 160, 161, 319, 320, 321, 1439, 1440, 1441, 1488, 2879, 2880, 2881, 4000, 5760,
        5761, 65_535, 2,
    ];

    /// Runs the hostile lengths followed by eight normal frames of
    /// `frame_bytes` and checks the outcome. `samples_per_byte` is the
    /// codec's expansion (1 for G.711, 2 for G.722); `frame_samples` is one
    /// ptime of decoded audio.
    fn qa_assert_codec_survives_payload_lengths(
        codec: CodecPreference,
        payload_type: u8,
        fill: u8,
        frame_bytes: usize,
        samples_per_byte: usize,
    ) {
        let frame_samples = CodecPipeline::new(codec).unwrap().samples_per_frame();
        assert_eq!(frame_bytes * samples_per_byte, frame_samples);

        let mut lengths = QA_HOSTILE_PAYLOAD_LENGTHS.to_vec();
        lengths.extend([frame_bytes; 8]);

        // A decoded frame longer than one ptime that still fits the codec's
        // own decode buffer must be dropped and counted; a longer payload is
        // refused by the codec (an error, not a drop) and a shorter one is
        // played.
        let expected_dropped = lengths
            .iter()
            .map(|len| len * samples_per_byte)
            .filter(|samples| {
                *samples > frame_samples && *samples <= crate::codec::MAX_DECODED_SAMPLES
            })
            .count();
        assert!(expected_dropped >= 5, "table lost its oversized cases");

        let payloads = lengths.iter().map(|len| vec![fill; *len]).collect();
        let run = qa_run_decode_thread(codec, payload_type, 160, payloads);
        assert!(
            run.alive,
            "{codec:?}: decode thread died on a hostile payload length"
        );
        assert!(
            run.drained,
            "{codec:?}: decode thread stopped consuming packets"
        );
        assert_eq!(
            run.oversized_dropped,
            u64::try_from(expected_dropped).unwrap(),
            "{codec:?}: every oversized decoded frame is dropped and counted, nothing else is"
        );
        assert!(
            run.played > 0,
            "{codec:?}: frames after the hostile ones were not played out"
        );
    }

    #[test]
    fn test_qa_decode_thread_payload_length_table_pcmu() {
        qa_assert_codec_survives_payload_lengths(CodecPreference::G711Ulaw, 0, 0xFF, 160, 1);
    }

    #[test]
    fn test_qa_decode_thread_payload_length_table_pcma() {
        qa_assert_codec_survives_payload_lengths(CodecPreference::G711Alaw, 8, 0xD5, 160, 1);
    }

    #[test]
    fn test_qa_decode_thread_payload_length_table_g722() {
        qa_assert_codec_survives_payload_lengths(CodecPreference::G722, 9, 0xFA, 160, 2);
    }

    /// B3 at the copy itself, for each G.711/G.722 codec: decoded lengths
    /// at, one below and one above the scratch buffer, and at the codec's
    /// decode-buffer limit.
    #[test]
    fn test_qa_copy_decoded_frame_boundaries_per_codec() {
        for (codec, samples_per_byte) in [
            (CodecPreference::G711Ulaw, 1_usize),
            (CodecPreference::G711Alaw, 1),
            (CodecPreference::G722, 2),
        ] {
            let mut pipeline = CodecPipeline::new(codec).unwrap();
            let spf = pipeline.samples_per_frame();
            let frame_bytes = spf / samples_per_byte;
            let limit_bytes = crate::codec::MAX_DECODED_SAMPLES / samples_per_byte;
            let mut scratch = vec![0i16; spf];
            let metrics = DecodeMetrics::new();
            let mut dropped = 0_u64;

            for bytes in [
                0,
                1,
                frame_bytes - 1,
                frame_bytes,
                frame_bytes + 1,
                2 * frame_bytes,
                limit_bytes - 1,
                limit_bytes,
            ] {
                let payload = vec![0x55_u8; bytes];
                let pcm = pipeline.decode(&payload).unwrap();
                assert_eq!(pcm.len(), bytes * samples_per_byte, "{codec:?} {bytes}");
                let fits = pcm.len() <= spf;
                let copied = copy_decoded_frame(pcm, &mut scratch, &metrics);
                assert_eq!(copied.is_some(), fits, "{codec:?} {bytes} bytes");
                if let Some(frame) = copied {
                    assert_eq!(frame.len(), bytes * samples_per_byte);
                } else {
                    dropped += 1;
                }
                assert_eq!(
                    metrics.oversized_frames_dropped.load(Ordering::Relaxed),
                    dropped,
                    "{codec:?} {bytes} bytes"
                );
            }

            // One byte past the codec's decode buffer: refused by the codec,
            // so nothing reaches the copy.
            assert!(pipeline.decode(&vec![0x55_u8; limit_bytes + 1]).is_err());
            assert_eq!(dropped, 4, "{codec:?}");
        }
    }

    /// The loss-concealment path shares the one-ptime scratch buffer. With a
    /// hostile "next packet" of any length as the FEC source, it never
    /// returns (or copies) more than one ptime, for every codec.
    #[test]
    fn test_qa_conceal_lost_frame_hostile_fec_source_lengths() {
        for codec in [
            CodecPreference::G711Ulaw,
            CodecPreference::G711Alaw,
            CodecPreference::G722,
            CodecPreference::Opus,
        ] {
            let mut pipeline = CodecPipeline::new(codec).unwrap();
            let spf = pipeline.samples_per_frame();
            let mut plc = WsolaPlc::new(spf);
            let mut scratch = vec![0i16; spf];
            let metrics = DecodeMetrics::new();

            for len in [0_usize, 1, 2, 160, 161, 320, 1275, 1488, 2880, 2881, 65_535] {
                for fill in [0x00_u8, 0x18, 0x7F, 0xFF] {
                    let next = vec![fill; len];
                    // A frame size larger than the scratch buffer is clamped.
                    for frame_samples in [spf, spf + 1, 2880, 5760] {
                        let out = conceal_lost_frame(
                            &mut pipeline,
                            &mut plc,
                            &mut scratch,
                            Some(&next),
                            frame_samples,
                            &metrics,
                        );
                        assert!(
                            out.len() <= spf,
                            "{codec:?}: {} samples from a {len}-byte FEC source",
                            out.len()
                        );
                    }
                }
            }
        }
    }

    /// With the real Opus decoder, one packet can legitimately decode to
    /// more than the 20 ms scratch buffer (40/60 ms frames, or several
    /// frames in one packet). Such packets must be dropped and counted, and
    /// packets whose duration exceeds the decode buffer refused, without a
    /// panic. TOC-only packets are valid Opus (RFC 6716 §3.1): the decoder
    /// conceals the frame duration the TOC declares.
    #[cfg(feature = "opus-ffi")]
    #[test]
    fn test_qa_decode_thread_opus_long_frames_are_dropped_not_copied() {
        let mut codec = CodecPipeline::new(CodecPreference::Opus).unwrap();
        let spf = codec.samples_per_frame();
        let mut scratch = vec![0i16; spf];
        let metrics = DecodeMetrics::new();
        let mut dropped = 0_u64;

        // (TOC-led packet, what it declares)
        let packets: [(&[u8], &str); 8] = [
            (&[0x08], "SILK NB 20 ms, one frame"),
            (&[0x10], "SILK NB 40 ms, one frame"),
            (&[0x18], "SILK NB 60 ms, one frame"),
            (&[0x09], "SILK NB 2 x 20 ms, code 1"),
            (&[0x19], "SILK NB 2 x 60 ms, code 1 (120 ms)"),
            (&[0x1B, 0x02], "SILK NB 60 ms, code 3, two frames (120 ms)"),
            (
                &[0xFB, 0x30],
                "CELT FB 20 ms, code 3, 48 frames (960 ms, invalid)",
            ),
            (&[0x1B, 0x00], "code 3 with zero frames (invalid)"),
        ];
        for (packet, what) in packets {
            // A packet the decoder refuses leaves nothing to copy.
            if let Ok(pcm) = codec.decode(packet) {
                let len = pcm.len();
                let copied = copy_decoded_frame(pcm, &mut scratch, &metrics);
                assert_eq!(copied.is_some(), len <= spf, "{what}: {len} samples");
                if copied.is_none() {
                    dropped += 1;
                }
            }
            assert_eq!(
                metrics.oversized_frames_dropped.load(Ordering::Relaxed),
                dropped,
                "{what}"
            );
        }
        assert!(
            dropped >= 2,
            "the 40 ms and 60 ms packets decode to more than one 20 ms frame"
        );

        // The same packets through the running decode thread, followed by
        // TOC-only 20 ms packets that must still be played.
        let mut payloads: Vec<Vec<u8>> = packets.iter().map(|(p, _)| p.to_vec()).collect();
        payloads.extend(std::iter::repeat_n(vec![0x08_u8], 8));
        let run = qa_run_decode_thread(CodecPreference::Opus, 111, 960, payloads);
        assert!(run.alive, "decode thread died on a long Opus packet");
        assert!(run.drained, "decode thread stopped consuming packets");
        assert!(run.oversized_dropped >= 2);
        assert!(run.played > 0, "frames after the long ones were not played");
    }

    #[test]
    fn test_decode_metrics_dtmf_malformed() {
        let metrics = DecodeMetrics::new();
        assert_eq!(metrics.dtmf_malformed.load(Ordering::Relaxed), 0);
        metrics.dtmf_malformed.fetch_add(1, Ordering::Relaxed);
        assert_eq!(metrics.dtmf_malformed.load(Ordering::Relaxed), 1);
    }

    // ---- SR-48: RFC 4733 per-call bounds (QA, written before the fix) ----

    /// One telephone-event packet payload as the bypass queue decodes it.
    fn sr48_event(digit: DtmfDigit, end: bool, duration: u16) -> DtmfEvent {
        DtmfEvent {
            digit,
            end,
            volume: DtmfEvent::DEFAULT_VOLUME,
            duration,
        }
    }

    /// 200 ms ahead of the playout point at 8 kHz: an ordinary jitter-buffer
    /// lead for a NEW event packet.
    const SR48_NEAR_LEAD: u32 = 1600;

    /// 60 s at 8 kHz: far outside any sane playout window. Any start-distance
    /// bound of "a few seconds" must reject it.
    const SR48_FAR: u32 = 8000 * 60;

    /// Hostile far end: thousands of NEW events, each with a distinct start
    /// timestamp and no END, each close to the playout point. The schedule
    /// must stay within `DTMF_SCHEDULE_CAP` and must not reallocate.
    #[test]
    fn test_sr48_schedule_bounded_under_distinct_start_flood() {
        let metrics = DecodeMetrics::new();
        let mut rx = DtmfRx::new();
        let mut dtmf = DtmfPlayout::new();
        let capacity_before = dtmf.schedule.capacity();
        assert!(
            capacity_before >= DTMF_SCHEDULE_CAP,
            "schedule must be pre-sized to the cap"
        );

        let base: u32 = 1_000_000;
        for i in 0..5_000_u32 {
            let start = base.wrapping_add(i * 160);
            // Playout runs just behind each event, as on a live call, so
            // the start-distance check is not what bounds the schedule.
            let playout = Some(start.wrapping_sub(SR48_NEAR_LEAD));
            let _ = ingest_dtmf_event(
                &mut rx,
                &mut dtmf,
                start,
                sr48_event(DtmfDigit::Five, false, 160),
                playout,
                &metrics,
            );
            assert!(
                dtmf.schedule.len() <= DTMF_SCHEDULE_CAP,
                "SR-48: schedule grew to {} entries after {} NEW events (cap {DTMF_SCHEDULE_CAP})",
                dtmf.schedule.len(),
                i + 1
            );
        }
        assert_eq!(
            dtmf.schedule.capacity(),
            capacity_before,
            "SR-48: schedule reallocated on the real-time decode thread"
        );
    }

    /// Same flood before the first decoded frame (no playout anchor yet):
    /// the cap holds on its own.
    #[test]
    fn test_sr48_schedule_bounded_without_playout_anchor() {
        let metrics = DecodeMetrics::new();
        let mut rx = DtmfRx::new();
        let mut dtmf = DtmfPlayout::new();
        for i in 0..1_000_u32 {
            let _ = ingest_dtmf_event(
                &mut rx,
                &mut dtmf,
                i.wrapping_mul(160),
                sr48_event(DtmfDigit::One, false, 160),
                None,
                &metrics,
            );
        }
        assert!(
            dtmf.schedule.len() <= DTMF_SCHEDULE_CAP,
            "SR-48: schedule has {} entries with no playout anchor (cap {DTMF_SCHEDULE_CAP})",
            dtmf.schedule.len()
        );
    }

    /// A NEW event whose start is far ahead of the playout point (RTP
    /// timestamp distance, wrapping) is rejected: not queued, not counted
    /// as received.
    #[test]
    fn test_sr48_far_future_start_rejected() {
        for anchor in [1_000_000_u32, u32::MAX - 100] {
            let metrics = DecodeMetrics::new();
            let mut rx = DtmfRx::new();
            let mut dtmf = DtmfPlayout::new();
            let start = anchor.wrapping_add(SR48_FAR);
            let outcome = ingest_dtmf_event(
                &mut rx,
                &mut dtmf,
                start,
                sr48_event(DtmfDigit::Nine, false, 160),
                Some(anchor),
                &metrics,
            );
            assert_ne!(
                outcome,
                DtmfIngest::Scheduled,
                "SR-48: start {start} is 60 s ahead of playout {anchor} and must be rejected"
            );
            assert!(
                dtmf.schedule.is_empty(),
                "SR-48: far-future event was queued (anchor {anchor})"
            );
            assert_eq!(metrics.dtmf_received.load(Ordering::Relaxed), 0);
        }
    }

    /// A NEW event whose start is far behind the playout point is rejected.
    #[test]
    fn test_sr48_far_past_start_rejected() {
        for anchor in [10_000_000_u32, 50] {
            let metrics = DecodeMetrics::new();
            let mut rx = DtmfRx::new();
            let mut dtmf = DtmfPlayout::new();
            let start = anchor.wrapping_sub(SR48_FAR);
            let outcome = ingest_dtmf_event(
                &mut rx,
                &mut dtmf,
                start,
                sr48_event(DtmfDigit::Two, false, 160),
                Some(anchor),
                &metrics,
            );
            assert_ne!(
                outcome,
                DtmfIngest::Scheduled,
                "SR-48: start {start} is 60 s behind playout {anchor} and must be rejected"
            );
            assert!(dtmf.schedule.is_empty());
            assert_eq!(metrics.dtmf_received.load(Ordering::Relaxed), 0);
        }
    }

    /// Regression: an ordinary event a jitter-buffer depth ahead of the
    /// playout point is accepted, including across the 32-bit wrap.
    #[test]
    fn test_sr48_near_start_accepted_across_wrap() {
        for anchor in [1_000_000_u32, u32::MAX - 100, u32::MAX] {
            let metrics = DecodeMetrics::new();
            let mut rx = DtmfRx::new();
            let mut dtmf = DtmfPlayout::new();
            let start = anchor.wrapping_add(SR48_NEAR_LEAD);
            let outcome = ingest_dtmf_event(
                &mut rx,
                &mut dtmf,
                start,
                sr48_event(DtmfDigit::Star, false, 160),
                Some(anchor),
                &metrics,
            );
            assert_eq!(outcome, DtmfIngest::Scheduled, "anchor {anchor}");
            assert_eq!(dtmf.schedule.len(), 1);
            assert_eq!(metrics.dtmf_received.load(Ordering::Relaxed), 1);
            // A packet slightly behind playout (late NEW) is accepted too.
            let late = anchor.wrapping_sub(SR48_NEAR_LEAD);
            let outcome = ingest_dtmf_event(
                &mut rx,
                &mut dtmf,
                late,
                sr48_event(DtmfDigit::Pound, false, 160),
                Some(anchor),
                &metrics,
            );
            assert_eq!(
                outcome,
                DtmfIngest::Scheduled,
                "late start, anchor {anchor}"
            );
        }
    }

    /// Regression: a normal digit (NEW, continuations, 3x END) activates on
    /// the playout timeline and the END stops it at start + duration.
    #[test]
    fn test_sr48_real_end_still_stops_tone() {
        let metrics = DecodeMetrics::new();
        let mut rx = DtmfRx::new();
        let mut dtmf = DtmfPlayout::new();
        let start: u32 = 80_000;
        let playout = Some(start - SR48_NEAR_LEAD);
        let feed = |rx: &mut DtmfRx, dtmf: &mut DtmfPlayout, end: bool, dur: u16| {
            ingest_dtmf_event(
                rx,
                dtmf,
                start,
                sr48_event(DtmfDigit::Seven, end, dur),
                playout,
                &metrics,
            )
        };

        assert_eq!(feed(&mut rx, &mut dtmf, false, 160), DtmfIngest::Scheduled);
        // Continuation while still queued updates the queued entry.
        assert_eq!(feed(&mut rx, &mut dtmf, false, 480), DtmfIngest::Updated);
        assert!(!advance_dtmf_schedule(
            start - SR48_NEAR_LEAD,
            &mut dtmf,
            48000
        ));
        assert!(dtmf.active_gen.is_none(), "activated before its window");
        // Playout reaches the start: the tone activates.
        assert!(!advance_dtmf_schedule(start, &mut dtmf, 48000));
        assert!(dtmf.active_gen.is_some(), "tone did not activate");
        // Continuation and END for the playing tone; END retransmitted.
        assert_eq!(feed(&mut rx, &mut dtmf, false, 640), DtmfIngest::Updated);
        for _ in 0..3 {
            assert_eq!(feed(&mut rx, &mut dtmf, true, 800), DtmfIngest::Updated);
        }
        assert_eq!(metrics.dtmf_received.load(Ordering::Relaxed), 1);
        assert!(
            !advance_dtmf_schedule(start + 799, &mut dtmf, 48000),
            "tone stopped before its END duration"
        );
        assert!(
            advance_dtmf_schedule(start + 800, &mut dtmf, 48000),
            "SR-48 regression: END no longer stops the tone"
        );
    }

    /// Regression: an END that arrives while the event is still queued is
    /// recorded on the queued entry and stops the tone once played.
    #[test]
    fn test_sr48_end_before_activation_stops_tone() {
        let metrics = DecodeMetrics::new();
        let mut rx = DtmfRx::new();
        let mut dtmf = DtmfPlayout::new();
        let start: u32 = 4_000;
        let playout = Some(start - SR48_NEAR_LEAD);
        for (end, dur) in [(false, 160), (false, 400), (true, 800), (true, 800)] {
            let _ = ingest_dtmf_event(
                &mut rx,
                &mut dtmf,
                start,
                sr48_event(DtmfDigit::Zero, end, dur),
                playout,
                &metrics,
            );
        }
        assert_eq!(dtmf.schedule.len(), 1);
        assert!(dtmf.schedule[0].ended);
        assert!(!advance_dtmf_schedule(start, &mut dtmf, 48000));
        assert!(dtmf.active_gen.is_some());
        assert!(advance_dtmf_schedule(start + 800, &mut dtmf, 48000));
    }

    /// The received-DTMF notification channel is bounded: a far end that
    /// floods NEW events while nothing drains the receiver (production has
    /// no drain caller) cannot grow it, and the decode thread never blocks
    /// on it.
    #[test]
    fn test_sr48_received_dtmf_channel_bounded_and_non_blocking() {
        const SENT: usize = 10_000;
        /// Generous ceiling for any sane bounded capacity.
        const MAX_QUEUED: usize = 64;
        let (tx, rx) = dtmf_rx_channel();
        let (done_tx, done_rx) = mpsc::channel();
        let sender = thread::spawn(move || {
            for _ in 0..SENT {
                notify_dtmf_rx(&tx, DtmfDigit::Three);
            }
            let _ = done_tx.send(());
            tx
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "SR-48: notify_dtmf_rx blocked the decode thread on a full channel"
        );
        let _tx = sender.join().unwrap();
        let queued = rx.try_iter().count();
        assert!(
            queued <= MAX_QUEUED,
            "SR-48: {queued} digits queued after {SENT} notifications with no reader \
             (expected a bounded channel, <= {MAX_QUEUED})"
        );
    }

    // ---- SR-48 fix round 1 ----

    /// RFC-1: the playout clock runs at the codec's RTP clock rate, which for
    /// G.722 is 8000 Hz (RFC 3551 §4.5.2), not its 16 kHz sample rate.
    #[test]
    fn test_rfc1_ts_units_per_ms_follow_rtp_clock() {
        for (pref, want) in [
            (CodecPreference::G711Ulaw, 8),
            (CodecPreference::G711Alaw, 8),
            (CodecPreference::G722, 8),
            (CodecPreference::Opus, 48),
        ] {
            let codec = CodecPipeline::new(pref).unwrap();
            assert_eq!(
                super::rtp_ts_units_per_ms(codec.clock_rate()),
                want,
                "{pref:?}"
            );
        }
        // Opus: unchanged from the old samples-per-20ms derivation.
        let opus = CodecPipeline::new(CodecPreference::Opus).unwrap();
        assert_eq!(
            super::rtp_ts_units_per_ms(opus.clock_rate()),
            u32::try_from(opus.samples_per_frame() / 20).unwrap()
        );
        assert_eq!(super::rtp_ts_units_per_ms(0), 1);
    }

    /// RFC-1: on a G.722 call, a digit whose event start is 5 s after the
    /// last decoded frame (VAD silence, carrier suppressing audio) is
    /// accepted. With the old 16 units/ms the extrapolated playout ran 2x
    /// and the start looked 5 s behind, so it was rejected.
    #[test]
    fn test_rfc1_g722_event_five_seconds_after_last_frame_accepted() {
        let codec = CodecPipeline::new(CodecPreference::G722).unwrap();
        let units = super::rtp_ts_units_per_ms(codec.clock_rate());
        let anchor: u32 = 1_000_000;
        let elapsed = Duration::from_secs(5);
        // Sender's event start on its 8000 Hz RTP clock, 5 s later.
        let packet_ts = anchor.wrapping_add(5 * 8000);
        let playout = super::extrapolate_playout_ts(anchor, elapsed, units);

        let metrics = DecodeMetrics::new();
        let mut rx = DtmfRx::new();
        let mut dtmf = DtmfPlayout::new();
        let outcome = ingest_dtmf_event(
            &mut rx,
            &mut dtmf,
            packet_ts,
            sr48_event(DtmfDigit::Three, false, 160),
            Some(playout),
            &metrics,
        );
        assert_eq!(outcome, DtmfIngest::Scheduled);
        assert_eq!(metrics.dtmf_rejected.load(Ordering::Relaxed), 0);

        // The old derivation (samples_per_frame / 20 = 16) rejects it.
        let old_units = u32::try_from(codec.samples_per_frame() / 20).unwrap();
        assert_eq!(old_units, 16);
        let mut rx = DtmfRx::new();
        let mut dtmf = DtmfPlayout::new();
        let old = ingest_dtmf_event(
            &mut rx,
            &mut dtmf,
            packet_ts,
            sr48_event(DtmfDigit::Three, false, 160),
            Some(super::extrapolate_playout_ts(anchor, elapsed, old_units)),
            &metrics,
        );
        assert_eq!(old, DtmfIngest::Rejected);
    }

    /// The extrapolation wraps on the 32-bit RTP timestamp.
    #[test]
    fn test_rfc1_extrapolate_playout_wraps() {
        let got = super::extrapolate_playout_ts(u32::MAX - 7, Duration::from_millis(2), 8);
        assert_eq!(got, 8);
    }

    /// SEC-5: a NEW event that is already a too-short END is refused
    /// without overwriting the duration of the event in progress, so the
    /// next continuation of that event is not taken as non-monotonic.
    #[test]
    fn test_sec5_short_end_leaves_current_duration() {
        let metrics = DecodeMetrics::new();
        let mut rx = DtmfRx::new();
        let mut dtmf = DtmfPlayout::new();
        let start: u32 = 50_000;
        assert_eq!(
            ingest_dtmf_event(
                &mut rx,
                &mut dtmf,
                start,
                sr48_event(DtmfDigit::One, false, 800),
                Some(start),
                &metrics,
            ),
            DtmfIngest::Scheduled
        );
        assert_eq!(rx.current_duration, 800);

        // Different start ts, END with duration below DTMF_MIN_DURATION.
        assert_eq!(
            ingest_dtmf_event(
                &mut rx,
                &mut dtmf,
                start + 160,
                sr48_event(DtmfDigit::Two, true, DTMF_MIN_DURATION - 1),
                Some(start),
                &metrics,
            ),
            DtmfIngest::ShortEnd
        );
        assert_eq!(rx.current_duration, 800, "ShortEnd overwrote the duration");
        assert_eq!(rx.current_ts, Some(start));

        // The original event continues at 960: a monotonic update.
        assert_eq!(
            ingest_dtmf_event(
                &mut rx,
                &mut dtmf,
                start,
                sr48_event(DtmfDigit::One, false, 960),
                None,
                &metrics,
            ),
            DtmfIngest::Updated
        );
        assert_eq!(rx.current_duration, 960);
    }

    /// SEC-4: the first decode error is logged, the rest within the interval
    /// are suppressed and counted, and the next logged one reports them.
    #[test]
    fn test_sec4_warn_rate_limit() {
        let mut limit = super::WarnRateLimit::new();
        let t0 = Instant::now();
        assert_eq!(limit.check(t0), Some(0));
        for i in 1..=50_u64 {
            assert_eq!(limit.check(t0 + Duration::from_millis(i * 10)), None);
        }
        let t1 = t0 + super::WARN_RATE_LIMIT_INTERVAL;
        assert_eq!(limit.check(t1), Some(50));
        assert_eq!(limit.check(t1 + Duration::from_millis(1)), None);
        assert_eq!(
            limit.check(t1 + super::WARN_RATE_LIMIT_INTERVAL * 3),
            Some(1)
        );
    }
}
