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
    const fn new() -> Self {
        Self {
            schedule: std::collections::VecDeque::new(),
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
const DTMF_MAX_DURATION: u16 = 40000;

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

/// Shared atomic counters for decode-thread metrics.
///
/// Created by the pipeline and passed to `spawn()`. The decode thread
/// increments these lock-free; the pipeline reads them in `stats()`.
pub struct DecodeMetrics {
    /// Frames recovered via FEC (Opus inband FEC).
    pub fec_recovered: AtomicU64,
    /// Frames generated by PLC (WSOLA concealment).
    pub plc_generated: AtomicU64,
    /// DTMF events received from remote.
    pub dtmf_received: AtomicU64,
    /// Malformed DTMF packets (invalid duration, impossible jumps).
    pub dtmf_malformed: AtomicU64,
}

impl DecodeMetrics {
    /// Creates zeroed metrics.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            fec_recovered: AtomicU64::new(0),
            plc_generated: AtomicU64::new(0),
            dtmf_received: AtomicU64::new(0),
            dtmf_malformed: AtomicU64::new(0),
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
    pub dtmf_rx_tx: Option<mpsc::Sender<DtmfDigit>>,
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

/// Main decode loop.
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
    // RTP timestamp units per millisecond (e.g. 8 at 8kHz G.711) — used to
    // extrapolate the playout clock by wall time when the JB is empty.
    #[allow(clippy::cast_possible_truncation)]
    let ts_units_per_ms = (codec_samples / 20).max(1) as u32;
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
    let mut current_dtmf_ts: Option<u32> = None;
    // Track duration of the current DTMF event for validation.
    // RFC 4733 duration increases monotonically across continuation packets;
    // a decrease indicates a malformed packet.
    let mut current_dtmf_duration: u16 = 0;
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
    let dtmf_diag = std::env::var(DUMP_DTMF_ENV).ok().is_some_and(|v| v == "1");

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
                    let is_new = current_dtmf_ts != Some(packet.timestamp);
                    if let Some(event) = DtmfEvent::decode(&bytes) {
                        if !is_new && event.duration < current_dtmf_duration {
                            continue; // Non-monotonic duration within event
                        }
                        if event.duration > DTMF_MAX_DURATION {
                            metrics.dtmf_malformed.fetch_add(1, Ordering::Relaxed);
                            continue; // Duration exceeds RFC sanity bound (5s)
                        }
                        current_dtmf_duration = event.duration;
                        dtmf_last_packet = Instant::now();
                        // Every packet refines the playout end: ts is the
                        // event start, duration grows monotonically and the
                        // END packet carries the final value.
                        let event_end_ts = packet.timestamp.wrapping_add(u32::from(event.duration));

                        if is_new {
                            if event.end && event.duration < DTMF_MIN_DURATION {
                                metrics.dtmf_malformed.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            current_dtmf_ts = Some(packet.timestamp);
                            metrics.dtmf_received.fetch_add(1, Ordering::Relaxed);
                            info!(
                                "DTMF bypass: NEW event digit={:?} ts={} seq={} end={} dur={}",
                                event.digit,
                                packet.timestamp,
                                packet.sequence,
                                event.end,
                                event.duration
                            );
                            // Schedule for playout-timeline activation rather
                            // than activating now: with rapid digit sequences
                            // this packet arrives while the previous tone is
                            // still playing out, and switching the generator
                            // here blurred/stuttered digits.
                            dtmf.schedule.push_back(ScheduledDtmf {
                                digit: event.digit,
                                start_ts: packet.timestamp,
                                end_ts: event_end_ts,
                                ended: event.end,
                            });
                            if let Some(ref tx) = config.dtmf_rx_tx {
                                let _ = tx.send(event.digit);
                            }
                        } else if dtmf.active_start == Some(packet.timestamp) {
                            // Continuation/END for the currently playing tone.
                            dtmf.end_ts = Some(event_end_ts);
                            dtmf.active_ended |= event.end;
                        } else if let Some(entry) = dtmf
                            .schedule
                            .iter_mut()
                            .find(|e| e.start_ts == packet.timestamp)
                        {
                            // Continuation/END for a not-yet-started tone.
                            entry.end_ts = event_end_ts;
                            entry.ended |= event.end;
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
                            info!(
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
                                warn!("Decode error: {e}");
                                break;
                            }
                        };

                        // Copy to pre-allocated buffer (codec returns a borrow
                        // of its internal buffer; we need a mutable copy for
                        // PLC cross-fade and postfilter).
                        let decoded_len = codec_pcm.len();
                        codec_scratch[..decoded_len].copy_from_slice(codec_pcm);
                        let codec_buf = &mut codec_scratch[..decoded_len];

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
                        current_gain += (target_gain - current_gain) * GAIN_RAMP_SPEED;

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
                    JitterBufferResult::Lost { .. } => {
                        decoded_this_cycle += 1;

                        // Try FEC recovery first (Opus inband FEC), fall back to PLC.
                        // PLC conceal() reuses an internal scratch buffer (zero-alloc).
                        // FEC path borrows codec_scratch directly (also zero-alloc).
                        let concealed: &[i16] = if codec.supports_fec() {
                            if let Ok(fec_pcm) = codec.decode_fec() {
                                trace!("FEC recovered {} samples", fec_pcm.len());
                                let fec_len = fec_pcm.len();
                                codec_scratch[..fec_len].copy_from_slice(fec_pcm);
                                plc.good_frame(&codec_scratch[..fec_len]);
                                metrics.fec_recovered.fetch_add(1, Ordering::Relaxed);
                                &codec_scratch[..fec_len]
                            } else {
                                metrics.plc_generated.fetch_add(1, Ordering::Relaxed);
                                plc.conceal()
                            }
                        } else {
                            metrics.plc_generated.fetch_add(1, Ordering::Relaxed);
                            plc.conceal()
                        };

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
                            #[allow(clippy::cast_possible_truncation)]
                            let elapsed_units = (last_decoded_at.elapsed().as_millis() as u32)
                                .saturating_mul(ts_units_per_ms);
                            let now_ts = anchor_ts.wrapping_add(elapsed_units);
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
                                let gain = 0.5 * (1.0 + (std::f32::consts::PI * t).cos());
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

    #[test]
    fn test_decode_metrics_dtmf_malformed() {
        let metrics = DecodeMetrics::new();
        assert_eq!(metrics.dtmf_malformed.load(Ordering::Relaxed), 0);
        metrics.dtmf_malformed.fetch_add(1, Ordering::Relaxed);
        assert_eq!(metrics.dtmf_malformed.load(Ordering::Relaxed), 1);
    }
}
