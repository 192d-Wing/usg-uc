//! Dedicated decode/playout thread for pull-based audio playback.
//!
//! This thread monitors the playback ring buffer fill level and decodes
//! frames from the jitter buffer as needed, ensuring the CPAL playback
//! callback always has audio data available. By running as a dedicated
//! `std::thread` (not a tokio task), it avoids cooperative scheduling
//! delays that cause playback gaps.

use crate::codec::CodecPipeline;
use crate::drift_compensator::DriftCompensator;
use crate::jitter_buffer::{JitterBufferResult, SharedJitterBuffer};
use crate::pipeline::{fade_out, resample};
use crate::stream::Sample;
use client_types::CodecPreference;
use ringbuf::traits::{Observer, Producer};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

/// Target fill level for the playback ring buffer (in frames).
/// At 20ms per frame, 5 frames = 100ms cushion.
const TARGET_FILL_FRAMES: usize = 5;

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
pub fn spawn(
    config: DecodeThreadConfig,
    producer: ringbuf::HeapProd<Sample>,
    jitter_buffer: SharedJitterBuffer,
    running: Arc<AtomicBool>,
) -> DecodeThreadHandle {
    let running_clone = running.clone();

    let handle = thread::Builder::new()
        .name("audio-decode".to_string())
        .spawn(move || {
            info!("Decode thread started");
            decode_loop(config, producer, jitter_buffer, &running_clone);
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

    // Drift compensator: measure every 5 decode cycles (~25-50ms)
    let mut drift = DriftCompensator::new(5);

    // Cross-frame state for smooth resampling and PLC
    let mut last_resample_input: i16 = 0;
    let mut last_playback_sample: i16 = 0;

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
                        // Decode
                        let codec_pcm = match codec.decode(&packet.payload) {
                            Ok(pcm) => pcm,
                            Err(e) => {
                                warn!("Decode error: {e}");
                                break;
                            }
                        };

                        // Resample from codec rate to device rate with drift compensation
                        let device_pcm = if codec_pcm.len() == adjusted_device_samples {
                            if let Some(&last_in) = codec_pcm.last() {
                                last_resample_input = last_in;
                            }
                            codec_pcm.to_vec()
                        } else {
                            let resampled =
                                resample(codec_pcm, adjusted_device_samples, last_resample_input);
                            if let Some(&last_in) = codec_pcm.last() {
                                last_resample_input = last_in;
                            }
                            resampled
                        };

                        if let Some(&last) = device_pcm.last() {
                            last_playback_sample = last;
                        }

                        // Write to playback ring buffer
                        let written = producer.push_slice(&device_pcm);
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
                        // Packet loss concealment: fade out from last known sample
                        let mut plc = vec![0i16; device_samples];
                        fade_out(&mut plc, last_playback_sample);
                        last_playback_sample = 0;
                        last_resample_input = 0;

                        producer.push_slice(&plc);
                        diag_frames_lost += 1;
                    }
                    JitterBufferResult::Empty | JitterBufferResult::NotReady => {
                        diag_jb_empty += 1;
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
            info!(
                "Decode diag: decoded={}, lost={}, jb_empty={}, ring_fill={}/{}, \
                 jb_pkts={}, jb_depth={}ms, jb_jitter={:.1}ms",
                diag_frames_decoded,
                diag_frames_lost,
                diag_jb_empty,
                producer.occupied_len(),
                target_fill,
                jb_stats.current_packet_count,
                jb_stats.current_depth_ms,
                jb_stats.average_jitter_ms,
            );
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

        let config = DecodeThreadConfig {
            codec: CodecPreference::G711Ulaw,
            device_rate: 48000,
        };

        let mut handle = spawn(config, producer, jb, running);

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
