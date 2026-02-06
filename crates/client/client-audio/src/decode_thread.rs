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
use crate::pipeline::resample;
use crate::plc::PacketLossConcealer;
use crate::stream::Sample;
use client_types::CodecPreference;
use ringbuf::traits::{Observer, Producer};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

/// Target fill level for the playback ring buffer (in frames).
/// At 20ms per frame, 8 frames = 160ms cushion.
/// Extra headroom helps Bluetooth A2DP devices that have irregular
/// callback timing compared to wired outputs.
const TARGET_FILL_FRAMES: usize = 8;

/// Playback gain applied to decoded remote audio (linear).
/// G.711 ulaw from typical PSTN sources doesn't use the full i16 range.
/// 4.0 = +12 dB boost for comfortable listening volume without clipping.
const PLAYBACK_GAIN: f32 = 4.0;

/// Handle to the running decode thread.
///
/// When dropped, signals the thread to stop and joins it.
pub struct DecodeThreadHandle {
    /// The thread join handle.
    thread: Option<thread::JoinHandle<()>>,
    /// Shared running flag.
    running: Arc<AtomicBool>,
}

impl DecodeThreadHandle {
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
/// frames from the jitter buffer as needed.
///
/// # Arguments
/// * `config` - Decode thread configuration
/// * `producer` - Ring buffer producer (writes decoded audio for CPAL to read)
/// * `jitter_buffer` - Shared jitter buffer (reads packets pushed by I/O thread)
/// * `running` - Shared flag to signal shutdown
/// * `playback_underruns` - Counter shared with CPAL callback for underrun tracking
pub fn spawn(
    config: DecodeThreadConfig,
    producer: ringbuf::HeapProd<Sample>,
    jitter_buffer: SharedJitterBuffer,
    running: Arc<AtomicBool>,
    playback_underruns: Arc<AtomicU64>,
) -> DecodeThreadHandle {
    let running_clone = running.clone();

    let handle = thread::Builder::new()
        .name("audio-decode".to_string())
        .spawn(move || {
            info!("Decode thread started");
            decode_loop(config, producer, jitter_buffer, &running_clone, &playback_underruns);
            info!("Decode thread exited");
        });

    let thread = match handle {
        Ok(h) => Some(h),
        Err(e) => {
            warn!("Failed to spawn decode thread: {e}");
            None
        }
    };

    DecodeThreadHandle { thread, running }
}

/// Main decode loop.
#[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
fn decode_loop(
    config: DecodeThreadConfig,
    mut producer: ringbuf::HeapProd<Sample>,
    jitter_buffer: SharedJitterBuffer,
    running: &AtomicBool,
    playback_underruns: &AtomicU64,
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
    let device_rate = config.device_rate;
    #[allow(clippy::cast_possible_truncation)]
    let device_samples = (codec_samples as u32 * device_rate / codec_clock_rate) as usize;
    let target_fill = device_samples * TARGET_FILL_FRAMES;

    // Drift compensator: measure every decode cycle for fast response
    let mut drift = DriftCompensator::new(1);

    // Cross-frame state for smooth resampling
    let mut last_resample_input: i16 = 0;

    // LPC-based packet loss concealment
    let mut plc = PacketLossConcealer::new(codec_samples);
    // Comfort noise for remote DTX (jitter buffer empty for extended periods)
    let mut cng = ComfortNoiseGenerator::new();
    let mut consecutive_empty: u32 = 0;

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
            // 100ms (4800 sample) cushion.
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

                        // Resample from codec rate to device rate with drift compensation
                        let device_pcm = if codec_vec.len() == adjusted_device_samples {
                            if let Some(&last_in) = codec_vec.last() {
                                last_resample_input = last_in;
                            }
                            codec_vec
                        } else {
                            let resampled =
                                resample(&codec_vec, adjusted_device_samples, last_resample_input);
                            if let Some(&last_in) = codec_vec.last() {
                                last_resample_input = last_in;
                            }
                            resampled
                        };

                        // Track peak amplitude before gain
                        if let Some(&peak) = device_pcm.iter().map(|s| s.saturating_abs()).max().as_ref() {
                            if peak > diag_peak_pre_gain {
                                diag_peak_pre_gain = peak;
                            }
                        }

                        // Apply playback gain and write to ring buffer
                        let gained: Vec<i16> = device_pcm
                            .iter()
                            .map(|&s| {
                                #[allow(clippy::cast_possible_truncation)]
                                let g = (f32::from(s) * PLAYBACK_GAIN).clamp(-32768.0, 32767.0) as i16;
                                g
                            })
                            .collect();

                        // Track peak amplitude after gain
                        if let Some(&peak) = gained.iter().map(|s| s.saturating_abs()).max().as_ref() {
                            if peak > diag_peak_post_gain {
                                diag_peak_post_gain = peak;
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

                        // Resample from codec rate to device rate
                        let device_pcm = if concealed.len() == device_samples {
                            concealed
                        } else {
                            resample(&concealed, device_samples, last_resample_input)
                        };

                        last_resample_input = 0;
                        producer.push_slice(&device_pcm);
                        diag_frames_lost += 1;
                    }
                    JitterBufferResult::Empty | JitterBufferResult::NotReady => {
                        diag_jb_empty += 1;
                        consecutive_empty += 1;

                        // Smooth silence transition using PLC fadeout for the
                        // first few empty reads. Without this, the ring buffer
                        // drains and the CPAL callback abruptly transitions from
                        // decoded audio to held-last-sample, causing audible static.
                        // PLC generates a natural continuation that attenuates
                        // progressively (90% → 72% → 58% → silence).
                        if consecutive_empty <= 3 {
                            let concealed = plc.conceal();
                            let device_pcm = if concealed.len() == device_samples {
                                concealed
                            } else {
                                resample(&concealed, device_samples, last_resample_input)
                            };
                            last_resample_input = 0;
                            producer.push_slice(&device_pcm);
                        } else if consecutive_empty >= 25 {
                            // Sustained emptiness → inject subtle comfort noise
                            cng.update_level(20.0);

                            let mut cn_pcm = vec![0i16; device_samples];
                            cng.generate(&mut cn_pcm);
                            producer.push_slice(&cn_pcm);
                        }
                        // Between 4-24: push nothing, let ring buffer drain
                        // naturally with the PLC tail still providing cushion.

                        break;
                    }
                }
            }

            // Sleep before re-checking fill level (5ms whether we decoded or not)
            thread::sleep(Duration::from_millis(5));
        }

        // Diagnostic logging every ~2 seconds
        if diag_timer.elapsed() >= Duration::from_secs(2) {
            let jb_stats = jitter_buffer.stats();
            let underruns = playback_underruns.load(Ordering::Relaxed);
            info!(
                "Decode diag: decoded={}, lost={}, jb_empty={}, ring_fill={}/{}, \
                 jb_pkts={}, jb_depth={}ms, jb_jitter={:.1}ms, pb_underruns={}, \
                 peak_pre={}, peak_post={}",
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
    use ringbuf::HeapRb;
    use ringbuf::traits::Split;

    #[test]
    fn test_spawn_and_stop() {
        let running = Arc::new(AtomicBool::new(true));
        let jb = SharedJitterBuffer::new(8000, 160, 60);
        let ring = HeapRb::<Sample>::new(48000);
        let (producer, _consumer) = ring.split();
        let underruns = Arc::new(AtomicU64::new(0));

        let config = DecodeThreadConfig {
            codec: CodecPreference::G711Ulaw,
            device_rate: 48000,
        };

        let mut handle = spawn(config, producer, jb, running, underruns);

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
