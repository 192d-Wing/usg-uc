//! Acoustic Echo Cancellation (AEC) using NLMS adaptive filter.
//!
//! Removes acoustic echo caused by speaker audio coupling back into the
//! microphone. Uses a Normalized Least Mean Squares (NLMS) adaptive filter
//! with double-talk detection to prevent filter divergence when both
//! near-end and far-end speakers are active simultaneously.
//!
//! ## Architecture
//!
//! The AEC operates at codec rate (8kHz for G.711, 16kHz for G.722).
//! - **Far-end reference**: decoded playback audio from the decode thread,
//!   shared via a lock-free ring buffer (`AecReference`).
//! - **Near-end input**: captured mic audio in the I/O thread, after AGC
//!   and resampling to codec rate.
//!
//! ```text
//! Decode Thread:                    I/O Thread:
//!   decoded PCM ──push──▶ AecReference ──pull──▶ AecProcessor
//!                        (ring buffer)           (NLMS filter)
//!                                                     │
//!                                              echo-cancelled PCM
//!                                                     │
//!                                                  encode
//! ```

use ringbuf::traits::{Consumer, Observer, Producer, Split};
use std::sync::Arc;

/// Configuration for Acoustic Echo Cancellation.
#[derive(Debug, Clone)]
pub struct AecConfig {
    /// Filter length in milliseconds.
    pub filter_length_ms: usize,
    /// NLMS step size (mu). Controls convergence speed vs. steady-state error.
    pub nlms_mu: f32,
    /// Double-talk detection threshold.
    pub doubletalk_threshold: f32,
    /// Minimum far-end energy to enable filter updates.
    pub min_farend_energy: f32,
    /// Residual echo suppression gain (linear).
    pub nlp_suppression: f32,
    /// NLP engagement threshold: echo-to-error ratio above which NLP kicks in.
    pub nlp_threshold: f32,
}

impl Default for AecConfig {
    fn default() -> Self {
        Self {
            filter_length_ms: 128,
            nlms_mu: 0.5,
            doubletalk_threshold: 2.0,
            min_farend_energy: 100.0,
            nlp_suppression: 0.1,
            nlp_threshold: 0.3,
        }
    }
}

impl AecConfig {
    /// Preset for headsets (short echo path, low tail length).
    pub fn headset() -> Self {
        Self {
            filter_length_ms: 64,
            nlms_mu: 0.6,
            doubletalk_threshold: 2.5,
            ..Self::default()
        }
    }

    /// Preset for built-in laptop/desktop speakers (medium tail length).
    pub fn speakers() -> Self {
        Self::default() // 128ms is already appropriate
    }

    /// Preset for speakerphone/room (long echo path, conservative adaptation).
    pub fn room() -> Self {
        Self {
            filter_length_ms: 256,
            nlms_mu: 0.3,
            doubletalk_threshold: 1.5,
            nlp_suppression: 0.05,
            ..Self::default()
        }
    }
}

/// Regularization constant to prevent division by zero in NLMS.
const NLMS_DELTA: f32 = 1e-6;

/// Shared far-end reference buffer for cross-thread AEC.
///
/// The decode thread pushes decoded PCM (at codec rate) into this buffer.
/// The I/O thread pulls samples to use as the AEC reference signal.
pub struct AecReference {
    /// Lock-free ring buffer producer (decode thread writes).
    producer: std::sync::Mutex<ringbuf::HeapProd<i16>>,
    /// Lock-free ring buffer consumer (I/O thread reads).
    consumer: std::sync::Mutex<ringbuf::HeapCons<i16>>,
}

impl AecReference {
    /// Creates a new AEC reference buffer.
    ///
    /// `capacity_ms` is the buffer capacity in milliseconds at the given sample rate.
    /// Should be at least 2x the filter length to handle jitter between threads.
    pub fn new(sample_rate: u32, capacity_ms: u32) -> Arc<Self> {
        #[allow(clippy::cast_possible_truncation)]
        let capacity = (sample_rate * capacity_ms / 1000) as usize;
        let rb = ringbuf::HeapRb::new(capacity);
        let (producer, consumer) = rb.split();
        Arc::new(Self {
            producer: std::sync::Mutex::new(producer),
            consumer: std::sync::Mutex::new(consumer),
        })
    }

    /// Pushes far-end reference samples (called from decode thread).
    pub fn push(&self, samples: &[i16]) {
        if let Ok(mut prod) = self.producer.lock() {
            let _ = prod.push_slice(samples);
        }
    }

    /// Pulls far-end reference samples into the provided buffer.
    /// Returns the number of samples actually read.
    pub fn pull(&self, output: &mut [i16]) -> usize {
        if let Ok(mut cons) = self.consumer.lock() {
            cons.pop_slice(output)
        } else {
            0
        }
    }

    /// Returns the number of samples available to read.
    pub fn available(&self) -> usize {
        self.consumer
            .lock()
            .map_or(0, |cons| cons.occupied_len())
    }
}

impl std::fmt::Debug for AecReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AecReference")
            .field("available", &self.available())
            .finish()
    }
}

/// Smoothing factor for ERLE estimation (exponential moving average).
/// 0.01 → ~100 frame time constant (~2s at 20ms frames).
const ERLE_SMOOTHING: f32 = 0.01;

/// NLMS adaptive filter for acoustic echo cancellation.
///
/// Processes mic audio frame-by-frame, subtracting the estimated echo
/// using an adaptive filter driven by the far-end reference signal.
#[derive(Debug)]
pub struct AecProcessor {
    /// Adaptive filter coefficients.
    filter: Vec<f32>,
    /// Far-end reference signal history (ring buffer for filter convolution).
    reference_history: Vec<f32>,
    /// Current write position in reference history.
    ref_pos: usize,
    /// Filter length in samples.
    filter_len: usize,
    /// Running power estimate of the reference signal (for NLMS normalization).
    ref_power: f32,
    /// Shared far-end reference buffer.
    aec_ref: Arc<AecReference>,
    /// Scratch buffer for pulling reference samples.
    ref_pull_buf: Vec<i16>,
    /// Whether AEC is enabled.
    enabled: bool,
    /// Configuration parameters.
    cfg: AecConfig,
    /// Running input (before cancellation) power estimate.
    input_power: f32,
    /// Running output (after cancellation) power estimate.
    output_power: f32,
    /// Current ERLE estimate in dB.
    erle_db: f32,
}

impl AecProcessor {
    /// Creates a new AEC processor with default configuration.
    ///
    /// `sample_rate` is the codec sample rate (e.g., 8000 for G.711).
    /// `aec_ref` is the shared reference buffer from the decode thread.
    pub fn new(sample_rate: u32, aec_ref: Arc<AecReference>) -> Self {
        Self::with_config(sample_rate, aec_ref, AecConfig::default())
    }

    /// Creates a new AEC processor with custom configuration.
    pub fn with_config(sample_rate: u32, aec_ref: Arc<AecReference>, cfg: AecConfig) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let filter_len = (sample_rate as usize * cfg.filter_length_ms) / 1000;
        Self {
            filter: vec![0.0; filter_len],
            reference_history: vec![0.0; filter_len],
            ref_pos: 0,
            filter_len,
            ref_power: 0.0,
            aec_ref,
            ref_pull_buf: vec![0; 960], // Max frame size at any rate
            enabled: true,
            cfg,
            input_power: 0.0,
            output_power: 0.0,
            erle_db: 0.0,
        }
    }

    /// Enables or disables AEC processing.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            // Reset filter when disabled
            self.filter.fill(0.0);
            self.reference_history.fill(0.0);
            self.ref_power = 0.0;
            self.input_power = 0.0;
            self.output_power = 0.0;
            self.erle_db = 0.0;
        }
    }

    /// Returns the current ERLE (Echo Return Loss Enhancement) estimate in dB.
    ///
    /// Higher values indicate better echo cancellation. Typical values:
    /// - 0-6 dB: poor / not converged
    /// - 6-12 dB: acceptable
    /// - 12+ dB: good
    pub fn erle_db(&self) -> f32 {
        self.erle_db
    }

    /// Processes a frame of mic audio in-place, removing estimated echo.
    ///
    /// `mic_pcm` is the captured audio at codec rate (modified in-place).
    /// The far-end reference is automatically pulled from the shared buffer.
    pub fn process(&mut self, mic_pcm: &mut [i16]) {
        if !self.enabled {
            return;
        }

        let frame_len = mic_pcm.len();

        // Pull far-end reference samples
        let pull_len = frame_len.min(self.ref_pull_buf.len());
        let ref_pulled = self.aec_ref.pull(&mut self.ref_pull_buf[..pull_len]);

        // If no reference available, can't cancel echo — pass through
        if ref_pulled == 0 {
            return;
        }

        // Accumulate frame-level input/output power for ERLE estimation.
        let mut frame_input_power = 0.0_f32;
        let mut frame_output_power = 0.0_f32;

        // Process sample by sample
        for i in 0..frame_len {
            // Get reference sample (zero-pad if we got fewer than frame_len)
            let ref_sample = if i < ref_pulled {
                self.ref_pull_buf[i] as f32
            } else {
                0.0
            };

            // Update reference history (circular buffer)
            self.reference_history[self.ref_pos] = ref_sample;

            // Update running power estimate (add new sample, subtract oldest)
            self.ref_power += ref_sample * ref_sample;
            // Exponential decay to prevent unbounded growth
            self.ref_power *= 1.0 - (1.0 / self.filter_len as f32);

            // Compute echo estimate: y_hat = sum(w[k] * x[n-k])
            let mut echo_estimate = 0.0_f32;
            for k in 0..self.filter_len {
                let ref_idx = (self.ref_pos + self.filter_len - k) % self.filter_len;
                echo_estimate = self.filter[k].mul_add(self.reference_history[ref_idx], echo_estimate);
            }

            // Error signal: mic - echo_estimate
            let mic_f = mic_pcm[i] as f32;
            let error = mic_f - echo_estimate;

            // Accumulate power for ERLE
            frame_input_power += mic_f * mic_f;
            frame_output_power += error * error;

            // Double-talk detection: compare mic energy to echo estimate energy
            let mic_energy = mic_f * mic_f;
            let echo_energy = echo_estimate * echo_estimate;
            let is_doubletalk = echo_energy > self.cfg.min_farend_energy
                && mic_energy > self.cfg.doubletalk_threshold * echo_energy;

            // NLMS filter update (skip during double-talk)
            if !is_doubletalk && self.ref_power > self.cfg.min_farend_energy {
                let norm = self.cfg.nlms_mu / (self.ref_power + NLMS_DELTA);
                for k in 0..self.filter_len {
                    let ref_idx = (self.ref_pos + self.filter_len - k) % self.filter_len;
                    self.filter[k] += norm * error * self.reference_history[ref_idx];
                }
            }

            // Non-linear processing (NLP): gated on ERLE.
            // When ERLE is high (>10 dB), the adaptive filter is doing its job
            // and NLP can use the configured threshold. When ERLE is low (<6 dB),
            // the filter hasn't converged — apply NLP more aggressively.
            let output = if echo_energy > self.cfg.min_farend_energy {
                let echo_ratio = echo_estimate.abs() / (error.abs() + 1.0);
                let effective_threshold = if self.erle_db < 6.0 {
                    // Aggressive NLP: lower threshold to suppress more residual echo
                    self.cfg.nlp_threshold * 0.5
                } else {
                    self.cfg.nlp_threshold
                };
                if echo_ratio > effective_threshold {
                    error * self.cfg.nlp_suppression
                } else {
                    error
                }
            } else {
                error
            };

            frame_output_power += output * output - error * error;

            // Write back
            #[allow(clippy::cast_possible_truncation)]
            {
                mic_pcm[i] = output.clamp(-32768.0, 32767.0) as i16;
            }

            // Advance reference position
            self.ref_pos = (self.ref_pos + 1) % self.filter_len;
        }

        // Update running ERLE estimate (exponential moving average).
        // Only update when there's meaningful input signal to avoid
        // division by zero and meaningless ERLE during silence.
        if frame_input_power > self.cfg.min_farend_energy {
            self.input_power += ERLE_SMOOTHING * (frame_input_power - self.input_power);
            self.output_power += ERLE_SMOOTHING * (frame_output_power.max(NLMS_DELTA) - self.output_power);
            if self.output_power > NLMS_DELTA {
                self.erle_db = 10.0 * (self.input_power / self.output_power).log10();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aec_reference_push_pull() {
        let aec_ref = AecReference::new(8000, 100); // 100ms buffer

        let samples: Vec<i16> = (0..160).map(|i| i as i16).collect();
        aec_ref.push(&samples);

        assert_eq!(aec_ref.available(), 160);

        let mut output = vec![0i16; 160];
        let pulled = aec_ref.pull(&mut output);
        assert_eq!(pulled, 160);
        assert_eq!(output, samples);
        assert_eq!(aec_ref.available(), 0);
    }

    #[test]
    fn test_aec_reference_overflow() {
        let aec_ref = AecReference::new(8000, 20); // 20ms = 160 samples

        // Push 320 samples — should overflow, keeping only latest 160
        let samples: Vec<i16> = (0..320).map(|i| i as i16).collect();
        aec_ref.push(&samples);

        // Available should be at most capacity
        assert!(aec_ref.available() <= 160);
    }

    #[test]
    fn test_aec_processor_passthrough_no_reference() {
        let aec_ref = AecReference::new(8000, 100);
        let mut processor = AecProcessor::new(8000, aec_ref);

        // With no reference signal, mic should pass through unchanged
        let mut mic: Vec<i16> = (0..160).map(|i| (i * 100) as i16).collect();
        let original = mic.clone();
        processor.process(&mut mic);

        assert_eq!(mic, original);
    }

    #[test]
    fn test_aec_processor_disabled() {
        let aec_ref = AecReference::new(8000, 100);
        let mut processor = AecProcessor::new(8000, aec_ref.clone());
        processor.set_enabled(false);

        // Push reference signal
        let ref_signal: Vec<i16> = (0..160).map(|i| (1000.0 * (i as f32 * 0.1).sin()) as i16).collect();
        aec_ref.push(&ref_signal);

        // Mic should pass through when disabled
        let mut mic = ref_signal.clone();
        let original = mic.clone();
        processor.process(&mut mic);
        assert_eq!(mic, original);
    }

    #[test]
    fn test_aec_reduces_echo() {
        let aec_ref = AecReference::new(8000, 200);
        let mut processor = AecProcessor::new(8000, aec_ref.clone());

        // Simulate echo: far-end plays a tone, mic picks it up with delay
        let num_frames = 50;
        let frame_size = 160;

        // Generate far-end signal (440 Hz tone)
        let total_samples = num_frames * frame_size;
        let farend: Vec<i16> = (0..total_samples)
            .map(|i| (8000.0 * (2.0 * std::f32::consts::PI * 440.0 * i as f32 / 8000.0).sin()) as i16)
            .collect();

        // Mic signal = echo (attenuated far-end, slight delay)
        // In a real room, echo arrives with ~5-20ms delay and ~-6dB attenuation
        let echo_delay = 40; // 5ms at 8kHz
        let echo_gain = 0.5_f32; // -6dB
        let mic_echo: Vec<i16> = (0..total_samples)
            .map(|i| {
                if i >= echo_delay {
                    #[allow(clippy::cast_possible_truncation)]
                    { (farend[i - echo_delay] as f32 * echo_gain) as i16 }
                } else {
                    0
                }
            })
            .collect();

        // Process frame by frame, feeding reference and mic
        let mut output_energy = 0.0_f64;
        let mut input_energy = 0.0_f64;

        for frame_idx in 0..num_frames {
            let start = frame_idx * frame_size;
            let end = start + frame_size;

            // Feed far-end reference
            aec_ref.push(&farend[start..end]);

            // Process mic (echo only, no near-end speech)
            let mut mic_frame = mic_echo[start..end].to_vec();
            let input_rms: f64 = mic_frame.iter().map(|&s| (s as f64).powi(2)).sum();

            processor.process(&mut mic_frame);

            let output_rms: f64 = mic_frame.iter().map(|&s| (s as f64).powi(2)).sum();

            // Only count frames after convergence (skip first 20 frames)
            if frame_idx >= 20 {
                input_energy += input_rms;
                output_energy += output_rms;
            }
        }

        // After convergence, echo should be significantly reduced
        // ERLE (Echo Return Loss Enhancement) should be at least 6dB (4x power reduction)
        let erle = if output_energy > 0.0 {
            10.0 * (input_energy / output_energy).log10()
        } else {
            f64::INFINITY
        };

        assert!(
            erle > 6.0,
            "ERLE too low: {erle:.1} dB (expected >6 dB echo reduction)"
        );
    }

    #[test]
    fn test_aec_erle_estimation() {
        let aec_ref = AecReference::new(8000, 200);
        let mut processor = AecProcessor::new(8000, aec_ref.clone());

        let num_frames = 50;
        let frame_size = 160;

        // Generate far-end tone and echo
        let total_samples = num_frames * frame_size;
        let farend: Vec<i16> = (0..total_samples)
            .map(|i| (8000.0 * (2.0 * std::f32::consts::PI * 440.0 * i as f32 / 8000.0).sin()) as i16)
            .collect();
        let echo_delay = 40;
        let echo_gain = 0.5_f32;
        let mic_echo: Vec<i16> = (0..total_samples)
            .map(|i| {
                if i >= echo_delay {
                    #[allow(clippy::cast_possible_truncation)]
                    { (farend[i - echo_delay] as f32 * echo_gain) as i16 }
                } else { 0 }
            })
            .collect();

        // Process frames
        for frame_idx in 0..num_frames {
            let start = frame_idx * frame_size;
            let end = start + frame_size;
            aec_ref.push(&farend[start..end]);
            let mut mic_frame = mic_echo[start..end].to_vec();
            processor.process(&mut mic_frame);
        }

        // After convergence, ERLE should be positive (some echo reduction)
        let erle = processor.erle_db();
        assert!(
            erle > 0.0,
            "ERLE should be positive after convergence, got {erle:.1} dB"
        );
    }

    #[test]
    fn test_aec_config_presets() {
        let headset = AecConfig::headset();
        assert_eq!(headset.filter_length_ms, 64);
        assert!(headset.nlms_mu > AecConfig::default().nlms_mu);

        let speakers = AecConfig::speakers();
        assert_eq!(speakers.filter_length_ms, 128);

        let room = AecConfig::room();
        assert_eq!(room.filter_length_ms, 256);
        assert!(room.nlms_mu < AecConfig::default().nlms_mu);
    }

    #[test]
    fn test_aec_preserves_near_end_speech() {
        let aec_ref = AecReference::new(8000, 200);
        let mut processor = AecProcessor::new(8000, aec_ref.clone());

        let frame_size = 160;
        let num_frames = 30;

        // Far-end silence — no echo to cancel
        let silence = vec![0i16; frame_size];

        // Near-end speech (880 Hz tone)
        let speech: Vec<i16> = (0..frame_size * num_frames)
            .map(|i| (6000.0 * (2.0 * std::f32::consts::PI * 880.0 * i as f32 / 8000.0).sin()) as i16)
            .collect();

        let mut output_energy = 0.0_f64;
        let mut input_energy = 0.0_f64;

        for frame_idx in 0..num_frames {
            let start = frame_idx * frame_size;
            let end = start + frame_size;

            aec_ref.push(&silence);

            let mut mic_frame = speech[start..end].to_vec();
            input_energy += mic_frame.iter().map(|&s| (s as f64).powi(2)).sum::<f64>();

            processor.process(&mut mic_frame);

            output_energy += mic_frame.iter().map(|&s| (s as f64).powi(2)).sum::<f64>();
        }

        // Near-end speech should be mostly preserved (within 3dB)
        let ratio = output_energy / input_energy.max(1.0);
        assert!(
            ratio > 0.5, // at most 3dB loss
            "Near-end speech too attenuated: ratio={ratio:.3} (expected >0.5)"
        );
    }
}
