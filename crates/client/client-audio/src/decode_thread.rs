//! Dedicated decode/playout thread for pull-based audio playback.
//!
//! This thread monitors the playback ring buffer fill level and decodes
//! frames from the jitter buffer as needed, ensuring the CPAL playback
//! callback always has audio data available. By running as a dedicated
//! `std::thread` (not a tokio task), it avoids cooperative scheduling
//! delays that cause playback gaps.

use crate::codec::CodecPipeline;
use crate::comfort_noise::ComfortNoiseGenerator;
use crate::drift_compensator::DriftCompensator;
use crate::jitter_buffer::{JitterBufferResult, SharedJitterBuffer};
use crate::plc::PacketLossConcealer;
use crate::sinc_resampler::Resampler;
use crate::stream::{PlaybackStream, PlaybackStreamHandle, Sample};
use client_types::CodecPreference;
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

/// Target fill level for the playback ring buffer (in frames).
/// At 20ms per frame, 8 frames = 160ms cushion.
/// Extra headroom helps Bluetooth A2DP devices that have irregular
/// callback timing compared to wired outputs.
const TARGET_FILL_FRAMES: usize = 8;

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

/// Exponential ramp speed for gain transitions (per frame).
/// 0.15 gives a ~130ms time constant (smooth, no audible steps).
const GAIN_RAMP_SPEED: f32 = 0.15;

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

/// Configuration for the decode thread.
pub struct DecodeThreadConfig {
    /// Codec preference for creating the decode pipeline.
    pub codec: CodecPreference,
    /// Device sample rate (e.g., 48000).
    pub device_rate: u32,
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
/// * `playback_handle` - CPAL playback stream handle (kept alive by this thread)
/// * `jitter_buffer` - Shared jitter buffer (reads packets pushed by I/O thread)
/// * `running` - Shared flag to signal shutdown
/// * `playback_underruns` - Counter shared with CPAL callback for underrun tracking
pub fn spawn(
    config: DecodeThreadConfig,
    producer: ringbuf::HeapProd<Sample>,
    playback_handle: PlaybackStreamHandle,
    jitter_buffer: SharedJitterBuffer,
    running: Arc<AtomicBool>,
    playback_underruns: Arc<AtomicU64>,
) -> DecodeThreadHandle {
    let running_clone = running.clone();
    let (cmd_tx, cmd_rx) = mpsc::channel();

    let handle = thread::Builder::new()
        .name("audio-decode".to_string())
        .spawn(move || {
            info!("Decode thread started");
            decode_loop(
                config,
                producer,
                playback_handle,
                jitter_buffer,
                &running_clone,
                &playback_underruns,
                cmd_rx,
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
    mut playback_handle: PlaybackStreamHandle,
    jitter_buffer: SharedJitterBuffer,
    running: &AtomicBool,
    playback_underruns: &AtomicU64,
    cmd_rx: mpsc::Receiver<DecodeCommand>,
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
    let mut device_rate = config.device_rate;
    #[allow(clippy::cast_possible_truncation)]
    let mut device_samples = (codec_samples as u32 * device_rate / codec_clock_rate) as usize;
    let mut target_fill = device_samples * TARGET_FILL_FRAMES;

    // Drift compensator: measure every decode cycle for fast response
    let mut drift = DriftCompensator::new(1);

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
    let mut plc = PacketLossConcealer::new(codec_samples);
    // Comfort noise for remote DTX (jitter buffer empty for extended periods)
    let mut cng = ComfortNoiseGenerator::new();
    let mut consecutive_empty: u32 = 0;

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

    // Optional audio dump file for debugging (set DUMP_DECODED_AUDIO=1)
    let mut audio_dump: Option<std::io::BufWriter<std::fs::File>> = std::env::var(DUMP_ENV_VAR)
        .ok()
        .filter(|v| v == "1")
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

    // Diagnostic counters
    let mut diag_frames_decoded: u64 = 0;
    let mut diag_frames_lost: u64 = 0;
    let mut diag_jb_empty: u64 = 0;
    let mut diag_peak_pre_gain: i16 = 0;
    let mut diag_peak_post_gain: i16 = 0;
    let mut diag_timer = Instant::now();

    while running.load(Ordering::Relaxed) {
        // Check ring buffer fill level (lock-free)
        let occupied = producer.occupied_len();

        if occupied >= target_fill {
            // Healthy — sleep and check again. 10ms is fine: at 48kHz the
            // CPAL callback consumes ~480 samples per 10ms, well within the
            // 160ms (7680 sample) cushion.
            thread::sleep(Duration::from_millis(10));
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

            for _ in 0..frames_to_decode {
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
                        decoded_this_cycle += 1;

                        // Decode
                        let codec_pcm = match codec.decode(&packet.payload) {
                            Ok(pcm) => pcm,
                            Err(e) => {
                                warn!("Decode error: {e}");
                                break;
                            }
                        };

                        let mut codec_vec = codec_pcm.to_vec();

                        // If recovering from loss, cross-fade for smooth transition
                        if plc.consecutive_losses() > 0 {
                            plc.recover(&mut codec_vec);
                        } else {
                            plc.good_frame(&codec_vec);
                        }

                        // Resample from codec rate to device rate
                        let device_pcm =
                            resampler.process_adjusted(&codec_vec, adjusted_device_samples);

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

                        // Apply gain
                        let gained: Vec<i16> = device_pcm
                            .iter()
                            .map(|&s| {
                                #[allow(clippy::cast_possible_truncation)]
                                let g =
                                    (f32::from(s) * current_gain).clamp(-32768.0, 32767.0) as i16;
                                g
                            })
                            .collect();

                        // Track peak amplitude after gain
                        if let Some(&post_peak) =
                            gained.iter().map(|s| s.saturating_abs()).max().as_ref()
                            && post_peak > diag_peak_post_gain
                        {
                            diag_peak_post_gain = post_peak;
                        }

                        // Track last output for fade-out
                        if let Some(&last) = gained.last() {
                            last_output_sample = last;
                        }

                        // Write to audio dump file if enabled
                        if let Some(ref mut dump) = audio_dump {
                            use std::io::Write;
                            // Write i16 samples as little-endian bytes
                            for &s in &gained {
                                let _ = dump.write_all(&s.to_le_bytes());
                            }
                        }

                        let written = producer.push_slice(&gained);
                        if written < gained.len() {
                            trace!(
                                "Ring buffer full: wrote {}/{} samples",
                                written,
                                gained.len()
                            );
                        }

                        diag_frames_decoded += 1;
                    }
                    JitterBufferResult::Lost { .. } => {
                        decoded_this_cycle += 1;
                        // Try FEC recovery first (Opus inband FEC), fall back to PLC
                        let concealed = if codec.supports_fec() {
                            match codec.decode_fec() {
                                Ok(fec_pcm) => {
                                    trace!("FEC recovered {} samples", fec_pcm.len());
                                    let v = fec_pcm.to_vec();
                                    plc.good_frame(&v);
                                    v
                                }
                                Err(_) => plc.conceal(),
                            }
                        } else {
                            plc.conceal()
                        };

                        // Resample concealed audio to device rate
                        let device_pcm = resampler.process_adjusted(&concealed, device_samples);

                        if let Some(&last) = device_pcm.last() {
                            last_output_sample = last;
                        }

                        producer.push_slice(&device_pcm);
                        diag_frames_lost += 1;
                    }
                    JitterBufferResult::Empty | JitterBufferResult::NotReady => {
                        // If we already decoded real audio this cycle, just stop.
                        if decoded_this_cycle > 0 {
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

                        if consecutive_empty == 1 {
                            // Cosine fade-out from last output to zero.
                            let mut fade = vec![0i16; device_samples];
                            #[allow(clippy::cast_precision_loss)]
                            let len_f = device_samples as f32;
                            for (i, sample) in fade.iter_mut().enumerate() {
                                #[allow(clippy::cast_precision_loss)]
                                let t = i as f32 / len_f;
                                let gain = 0.5 * (1.0 + (std::f32::consts::PI * t).cos());
                                #[allow(clippy::cast_possible_truncation)]
                                {
                                    *sample = (f32::from(last_output_sample) * gain) as i16;
                                }
                            }
                            last_output_sample = 0;
                            producer.push_slice(&fade);
                        } else if consecutive_empty >= 10 {
                            // After sustained emptiness, inject comfort noise
                            cng.update_level(20.0);
                            let mut cn_pcm = vec![0i16; device_samples];
                            cng.generate(&mut cn_pcm);
                            producer.push_slice(&cn_pcm);
                        } else {
                            // Push silence to prevent ring buffer underrun.
                            let silence = vec![0i16; device_samples];
                            producer.push_slice(&silence);
                        }

                        break;
                    }
                }
            }

            // Sleep before re-checking fill level (5ms whether we decoded or not)
            thread::sleep(Duration::from_millis(5));
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
                    match PlaybackStream::new(&dm) {
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
                                target_fill = device_samples * TARGET_FILL_FRAMES;
                                resampler = Resampler::new(codec_clock_rate, device_rate);
                                drift = DriftCompensator::new(1);
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

        // Diagnostic logging every ~2 seconds
        if diag_timer.elapsed() >= Duration::from_secs(2) {
            let jb_stats = jitter_buffer.stats();
            let underruns = playback_underruns.load(Ordering::Relaxed);
            info!(
                "Decode diag: decoded={}, lost={}, jb_empty={}, ring_fill={}/{}, \
                 jb_pkts={}, jb_depth={}ms, jb_jitter={:.1}ms, pb_underruns={}, \
                 peak_pre={}, peak_post={}, gain={:.2}",
                diag_frames_decoded,
                diag_frames_lost,
                diag_jb_empty,
                producer.occupied_len(),
                target_fill,
                jb_stats.current_packet_count,
                jb_stats.current_depth_ms,
                jb_stats.average_jitter_ms,
                underruns,
                diag_peak_pre_gain,
                diag_peak_post_gain,
                current_gain,
            );
            diag_peak_pre_gain = 0;
            diag_peak_post_gain = 0;
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
        let playback = match PlaybackStream::new(&dm) {
            Ok(p) => p,
            Err(_) => return, // skip if no audio device
        };
        let (playback_handle, producer, underruns) = playback.take_producer();
        let running = Arc::new(AtomicBool::new(true));
        let jb = SharedJitterBuffer::new(8000, 160, 60);

        let config = DecodeThreadConfig {
            codec: CodecPreference::G711Ulaw,
            device_rate: playback_handle.sample_rate(),
        };

        let mut handle = spawn(config, producer, playback_handle, jb, running, underruns);

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
        };
        assert_eq!(config.device_rate, 48000);
    }
}
