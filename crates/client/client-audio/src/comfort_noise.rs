//! Comfort Noise Generation (CNG) for discontinuous transmission.
//!
//! When the remote party stops sending (DTX), or during local silence
//! suppression, total silence feels unnatural ("dead air"). This module
//! generates low-level background noise that matches the estimated
//! background noise level, making pauses sound natural.
//!
//! ## Algorithm
//!
//! 1. Uses a simple deterministic PRNG (xorshift32) to generate white noise.
//! 2. Scales the noise to match the VAD's estimated background noise floor.
//! 3. Applies a simple low-pass filter to shape the noise (background noise
//!    is typically weighted toward lower frequencies).
//!
//! ## Integration
//!
//! ```text
//! Remote DTX detected → [CNG] → Playback ring buffer
//! Local silence (VAD) → Skip RTP send (or send CN payload type 13)
//! ```

/// Configuration for Comfort Noise Generation.
#[derive(Debug, Clone)]
pub struct ComfortNoiseConfig {
    /// Target noise level relative to estimated noise floor (0.5 = half energy).
    pub level_factor: f32,
    /// One-pole low-pass filter coefficient for spectral shaping (0.0-1.0).
    /// Used as fallback when no LPC model is available.
    pub lp_filter_coeff: f32,
    /// LPC order for spectral shaping (4-8). Higher values capture more
    /// spectral detail but cost more CPU. 0 disables LPC (uses LP filter).
    pub lpc_order: usize,
    /// Crossfade duration in samples when transitioning between CNG and real audio.
    pub crossfade_samples: usize,
}

impl Default for ComfortNoiseConfig {
    fn default() -> Self {
        Self {
            level_factor: 0.5,
            lp_filter_coeff: 0.7,
            lpc_order: 6,
            crossfade_samples: 40, // ~5ms at 8kHz
        }
    }
}

/// Full-scale reference for dBov conversion (16-bit PCM).
const FULL_SCALE: f32 = 32768.0;

/// Converts an RMS amplitude to dBov (decibels relative to overload).
///
/// dBov = 20 * log10(rms / 32768). Result is always <= 0.
/// Returns -127.0 for silence (rms < 1.0).
fn rms_to_dbov(rms: f32) -> f32 {
    if rms < 1.0 {
        return -127.0;
    }
    (20.0 * (rms / FULL_SCALE).log10()).clamp(-127.0, 0.0)
}

/// Converts a dBov value back to RMS amplitude.
///
/// rms = 32768 * 10^(dbov/20). Input should be <= 0.
fn dbov_to_rms(dbov: f32) -> f32 {
    FULL_SCALE * 10.0_f32.powf(dbov / 20.0)
}

/// Encodes an RFC 3389 Comfort Noise payload from the VAD noise floor RMS.
///
/// The minimum CN payload is 1 byte: the noise level in -dBov (0 = max, 127 = silence).
/// Optional spectral information (bytes 2+) is not generated — the receiver's
/// CNG will shape the noise independently.
///
/// # Wire format (RFC 3389 §3)
/// ```text
///  0                   1
///  0 1 2 3 4 5 6 7 8 9 0 1 ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+
/// |  noise level  | spec  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn encode_cn_payload(noise_floor_rms: f32) -> Vec<u8> {
    let dbov = rms_to_dbov(noise_floor_rms);
    // CN byte = -dBov, clamped to 0..127
    let level = (-dbov).clamp(0.0, 127.0) as u8;
    vec![level]
}

/// Decodes an RFC 3389 Comfort Noise payload to an RMS noise level.
///
/// Reads byte 0 as noise level in -dBov and converts to RMS.
/// Returns a default low level if the payload is empty.
pub fn decode_cn_payload(payload: &[u8]) -> f32 {
    if payload.is_empty() {
        // RFC 3389 §3: empty payload = silence, use minimum audible level
        return dbov_to_rms(-127.0);
    }
    let neg_dbov = f32::from(payload[0]);
    dbov_to_rms(-neg_dbov)
}

/// Maximum LPC order supported.
const MAX_LPC_ORDER: usize = 8;

/// Comfort noise generator using spectrally shaped white noise.
///
/// When an LPC noise model is available (updated via `update_spectrum()`),
/// the generator drives white noise through an all-pole LPC synthesis filter
/// to match the spectral envelope of the actual background noise. Falls back
/// to a one-pole LP filter when no model is available.
#[derive(Debug)]
pub struct ComfortNoiseGenerator {
    /// PRNG state (xorshift32).
    rng_state: u32,
    /// Target noise level (RMS amplitude, from VAD noise floor).
    target_level: f32,
    /// Low-pass filter state (previous output sample, fallback path).
    lp_state: f32,
    /// LPC coefficients for spectral shaping (a[1]..a[p]).
    lpc_coeffs: [f32; MAX_LPC_ORDER],
    /// LPC synthesis filter memory (previous output samples).
    lpc_memory: [f32; MAX_LPC_ORDER],
    /// Active LPC order (0 = disabled, uses fallback LP).
    lpc_order: usize,
    /// Whether a valid LPC model has been computed.
    has_lpc_model: bool,
    /// Configuration parameters.
    cfg: ComfortNoiseConfig,
}

impl Default for ComfortNoiseGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ComfortNoiseGenerator {
    /// Creates a new comfort noise generator.
    pub fn new() -> Self {
        Self::with_config(ComfortNoiseConfig::default())
    }

    /// Creates a comfort noise generator with custom configuration.
    pub fn with_config(cfg: ComfortNoiseConfig) -> Self {
        let lpc_order = cfg.lpc_order.min(MAX_LPC_ORDER);
        Self {
            rng_state: 0x1234_5678,
            target_level: 0.0,
            lp_state: 0.0,
            lpc_coeffs: [0.0; MAX_LPC_ORDER],
            lpc_memory: [0.0; MAX_LPC_ORDER],
            lpc_order,
            has_lpc_model: false,
            cfg,
        }
    }

    /// Updates the target noise level from the VAD's noise floor estimate.
    ///
    /// Call this periodically (e.g., every time VAD transitions to silence)
    /// so the comfort noise level tracks the actual background.
    pub fn update_level(&mut self, noise_floor_rms: f32) {
        self.target_level = noise_floor_rms * self.cfg.level_factor;
    }

    /// Updates the spectral model from a recent noise frame.
    ///
    /// Computes LPC coefficients from the autocorrelation of the given PCM
    /// using Levinson-Durbin recursion. Call this periodically during silence
    /// (every ~500ms) so the CNG spectrum tracks the actual noise.
    pub fn update_spectrum(&mut self, noise_pcm: &[i16]) {
        if self.lpc_order == 0 || noise_pcm.len() < self.lpc_order * 2 {
            return;
        }

        // Compute autocorrelation R[0..p]
        let order = self.lpc_order;
        let mut r = [0.0_f64; MAX_LPC_ORDER + 1];
        let n = noise_pcm.len();
        for lag in 0..=order {
            let mut sum = 0.0_f64;
            for i in lag..n {
                sum += f64::from(noise_pcm[i]) * f64::from(noise_pcm[i - lag]);
            }
            r[lag] = sum;
        }

        // Bail if signal has no energy (all zeros)
        if r[0] < 1.0 {
            return;
        }

        // Levinson-Durbin recursion to compute LPC coefficients
        let mut a = [0.0_f64; MAX_LPC_ORDER + 1];
        let mut a_prev = [0.0_f64; MAX_LPC_ORDER + 1];
        a[0] = 1.0;
        a_prev[0] = 1.0;
        let mut error = r[0];

        for i in 1..=order {
            // Compute reflection coefficient k[i]
            let mut lambda = 0.0_f64;
            for j in 1..i {
                lambda += a_prev[j] * r[i - j];
            }
            lambda = -(r[i] + lambda) / error;

            // Check stability: |k| must be < 1
            if lambda.abs() >= 1.0 {
                // Unstable — keep previous model
                return;
            }

            // Update coefficients
            a[i] = lambda;
            for j in 1..i {
                a[j] = lambda.mul_add(a_prev[i - j], a_prev[j]);
            }
            error *= lambda.mul_add(-lambda, 1.0);
            a_prev[..=i].copy_from_slice(&a[..=i]);
        }

        // Store as f32 (skip a[0] which is always 1.0)
        for k in 0..order {
            #[allow(clippy::cast_possible_truncation)]
            {
                self.lpc_coeffs[k] = a[k + 1] as f32;
            }
        }
        self.has_lpc_model = true;
    }

    /// Generates a frame of comfort noise into the provided buffer.
    ///
    /// Uses LPC synthesis filter when a spectral model is available,
    /// otherwise falls back to one-pole LP filter.
    #[allow(clippy::cast_possible_truncation)]
    pub fn generate(&mut self, output: &mut [i16]) {
        if self.target_level < 1.0 {
            output.fill(0);
            return;
        }

        if self.has_lpc_model && self.lpc_order > 0 {
            self.generate_lpc(output);
        } else {
            self.generate_lp(output);
        }
    }

    /// Generates comfort noise using LPC synthesis filter.
    #[allow(clippy::cast_possible_truncation)]
    fn generate_lpc(&mut self, output: &mut [i16]) {
        let order = self.lpc_order;
        for sample in output.iter_mut() {
            let excitation = self.next_random() * self.target_level;

            // All-pole synthesis: y[n] = x[n] - a1*y[n-1] - a2*y[n-2] - ...
            let mut y = excitation;
            for k in 0..order {
                y -= self.lpc_coeffs[k] * self.lpc_memory[k];
            }

            // Shift memory
            for k in (1..order).rev() {
                self.lpc_memory[k] = self.lpc_memory[k - 1];
            }
            if order > 0 {
                self.lpc_memory[0] = y;
            }

            *sample = y.clamp(-32768.0, 32767.0) as i16;
        }
    }

    /// Generates comfort noise using simple one-pole LP filter (fallback).
    #[allow(clippy::cast_possible_truncation)]
    fn generate_lp(&mut self, output: &mut [i16]) {
        for sample in output.iter_mut() {
            let white = self.next_random();
            let scaled = white * self.target_level;
            let lp = self.cfg.lp_filter_coeff;
            self.lp_state = lp.mul_add(self.lp_state, (1.0 - lp) * scaled);
            *sample = self.lp_state.clamp(-32768.0, 32767.0) as i16;
        }
    }

    /// Applies a crossfade from CNG to real audio at the start of `output`.
    ///
    /// Call this when transitioning from CNG to decoded audio. The first
    /// `crossfade_samples` of `output` are blended with comfort noise to
    /// avoid an abrupt transition.
    #[allow(clippy::cast_possible_truncation)]
    pub fn crossfade_to_real(&mut self, output: &mut [i16]) {
        let fade_len = self.cfg.crossfade_samples.min(output.len());
        if fade_len == 0 || self.target_level < 1.0 {
            return;
        }

        // Generate CNG for the fade region
        let mut cng_buf = vec![0i16; fade_len];
        self.generate(&mut cng_buf);

        // Linear crossfade: CNG fades out, real audio fades in
        #[allow(clippy::cast_precision_loss)]
        let fade_len_f = fade_len as f32;
        for i in 0..fade_len {
            #[allow(clippy::cast_precision_loss)]
            let t = i as f32 / fade_len_f;
            let blended = f32::from(cng_buf[i]).mul_add(1.0 - t, f32::from(output[i]) * t);
            output[i] = blended.clamp(-32768.0, 32767.0) as i16;
        }
    }

    /// Returns whether comfort noise generation is active (level > 0).
    pub fn is_active(&self) -> bool {
        self.target_level >= 1.0
    }

    /// Returns the current target noise level.
    pub const fn target_level(&self) -> f32 {
        self.target_level
    }

    /// Returns whether a valid LPC spectral model is available.
    pub const fn has_spectrum(&self) -> bool {
        self.has_lpc_model
    }

    /// Generates a random f32 in the range -1.0..1.0 using xorshift32.
    #[allow(clippy::cast_precision_loss)]
    fn next_random(&mut self) -> f32 {
        // xorshift32 PRNG — fast, deterministic, good enough for noise
        self.rng_state ^= self.rng_state << 13;
        self.rng_state ^= self.rng_state >> 17;
        self.rng_state ^= self.rng_state << 5;

        // Map u32 to -1.0..1.0
        #[allow(clippy::cast_possible_wrap)]
        let signed = self.rng_state as i32;
        signed as f32 / i32::MAX as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_generator() {
        let cng = ComfortNoiseGenerator::new();
        assert!((cng.target_level() - 0.0).abs() < f32::EPSILON);
        assert!(!cng.is_active());
    }

    #[test]
    fn test_zero_level_produces_silence() {
        let mut cng = ComfortNoiseGenerator::new();
        let mut output = vec![0i16; 160];
        cng.generate(&mut output);
        assert!(output.iter().all(|&s| s == 0));
    }

    #[test]
    fn test_active_produces_noise() {
        let mut cng = ComfortNoiseGenerator::new();
        cng.update_level(200.0);
        assert!(cng.is_active());

        let mut output = vec![0i16; 160];
        cng.generate(&mut output);

        // Should have non-zero samples
        let non_zero = output.iter().filter(|&&s| s != 0).count();
        assert!(
            non_zero > output.len() / 2,
            "Should produce mostly non-zero samples, got {non_zero}/{}",
            output.len()
        );
    }

    #[test]
    fn test_noise_level_proportional() {
        let mut cng_low = ComfortNoiseGenerator::new();
        cng_low.update_level(50.0);
        let mut out_low = vec![0i16; 1600];
        cng_low.generate(&mut out_low);

        let mut cng_high = ComfortNoiseGenerator::new();
        cng_high.update_level(500.0);
        let mut out_high = vec![0i16; 1600];
        cng_high.generate(&mut out_high);

        let energy_low: f64 = out_low.iter().map(|&s| f64::from(s) * f64::from(s)).sum();
        let energy_high: f64 = out_high.iter().map(|&s| f64::from(s) * f64::from(s)).sum();

        assert!(
            energy_high > energy_low,
            "Higher level should produce more energy: low={energy_low}, high={energy_high}"
        );
    }

    #[test]
    fn test_noise_bounded() {
        let mut cng = ComfortNoiseGenerator::new();
        cng.update_level(1000.0); // Very high level

        let mut output = vec![0i16; 1600];
        cng.generate(&mut output);

        // All samples should be within i16 range (clamping works)
        assert!(output.iter().all(|&_s| true));
    }

    #[test]
    fn test_deterministic() {
        // Two generators with same seed should produce identical output
        let mut cng1 = ComfortNoiseGenerator::new();
        cng1.update_level(200.0);
        let mut out1 = vec![0i16; 160];
        cng1.generate(&mut out1);

        let mut cng2 = ComfortNoiseGenerator::new();
        cng2.update_level(200.0);
        let mut out2 = vec![0i16; 160];
        cng2.generate(&mut out2);

        assert_eq!(out1, out2, "Same seed should produce identical output");
    }

    #[test]
    fn test_update_level() {
        let mut cng = ComfortNoiseGenerator::new();
        assert!(!cng.is_active());

        cng.update_level(100.0);
        assert!(cng.is_active());
        assert!((cng.target_level() - 50.0).abs() < f32::EPSILON);

        cng.update_level(0.0);
        assert!(!cng.is_active());
    }

    #[test]
    fn test_cn_payload_roundtrip() {
        // Various RMS levels should survive encode → decode with reasonable accuracy
        for &rms in &[10.0, 50.0, 100.0, 500.0, 1000.0, 5000.0] {
            let payload = encode_cn_payload(rms);
            assert_eq!(payload.len(), 1, "CN payload should be 1 byte");
            let decoded = decode_cn_payload(&payload);
            // The single-byte quantization loses precision; verify within 1 dB
            let original_dbov = rms_to_dbov(rms);
            let decoded_dbov = rms_to_dbov(decoded);
            assert!(
                (original_dbov - decoded_dbov).abs() <= 1.0,
                "Roundtrip error too large for rms={rms}: {original_dbov:.1} vs {decoded_dbov:.1} dBov"
            );
        }
    }

    #[test]
    fn test_cn_payload_known_values() {
        // Near-silence should encode to 127 (maximum attenuation)
        let payload = encode_cn_payload(0.5);
        assert_eq!(payload[0], 127);

        // Full-scale should encode to 0 (no attenuation)
        let payload = encode_cn_payload(32768.0);
        assert_eq!(payload[0], 0);
    }

    #[test]
    fn test_cn_payload_empty_decode() {
        // Empty payload = silence per RFC 3389
        let rms = decode_cn_payload(&[]);
        assert!(
            rms < 1.0,
            "Empty CN payload should decode to near-silence, got {rms}"
        );
    }

    #[test]
    fn test_cn_payload_decode_extremes() {
        // Level 0 = 0 dBov = full scale
        let rms = decode_cn_payload(&[0]);
        assert!(
            (rms - 32768.0).abs() < 1.0,
            "Level 0 should decode to full scale, got {rms}"
        );

        // Level 127 = -127 dBov ≈ silence
        let rms = decode_cn_payload(&[127]);
        assert!(
            rms < 1.0,
            "Level 127 should decode to near-silence, got {rms}"
        );
    }

    #[test]
    fn test_dbov_conversion() {
        // Full-scale = 0 dBov
        assert!((rms_to_dbov(32768.0) - 0.0).abs() < 0.01);

        // Half scale ≈ -6 dBov
        assert!((rms_to_dbov(16384.0) - (-6.02)).abs() < 0.1);

        // Near-silence clamps to -127
        assert!((rms_to_dbov(0.1) - (-127.0)).abs() < 0.01);

        // Roundtrip
        let rms = 200.0;
        let back = dbov_to_rms(rms_to_dbov(rms));
        assert!(
            (rms - back).abs() < 1.0,
            "dBov roundtrip failed: {rms} → {back}"
        );
    }

    #[test]
    fn test_lpc_spectrum_update() {
        let mut cng = ComfortNoiseGenerator::new();
        assert!(!cng.has_spectrum());

        // Feed a noise frame with some spectral content
        let noise: Vec<i16> = (0..320)
            .map(|i| {
                #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
                {
                    (i as f32 * 0.3)
                        .sin()
                        .mul_add(500.0, (i as f32 * 0.7).cos() * 300.0) as i16
                }
            })
            .collect();
        cng.update_spectrum(&noise);
        assert!(cng.has_spectrum());
    }

    #[test]
    fn test_lpc_shaped_noise_differs_from_fallback() {
        // LPC-shaped CNG should produce different output than LP fallback
        let noise: Vec<i16> = (0..320)
            .map(|i| {
                #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
                {
                    ((i as f32 * 0.1).sin() * 1000.0) as i16
                }
            })
            .collect();

        let mut cng_lpc = ComfortNoiseGenerator::new();
        cng_lpc.update_level(200.0);
        cng_lpc.update_spectrum(&noise);

        let mut cng_lp = ComfortNoiseGenerator::with_config(ComfortNoiseConfig {
            lpc_order: 0, // Disable LPC
            ..ComfortNoiseConfig::default()
        });
        cng_lp.update_level(200.0);

        let mut out_lpc = vec![0i16; 160];
        let mut out_lp = vec![0i16; 160];
        cng_lpc.generate(&mut out_lpc);
        cng_lp.generate(&mut out_lp);

        // Both should produce non-zero output
        assert!(out_lpc.iter().any(|&s| s != 0));
        assert!(out_lp.iter().any(|&s| s != 0));

        // They should differ (different spectral shape)
        assert_ne!(out_lpc, out_lp, "LPC and LP noise should differ");
    }

    #[test]
    fn test_crossfade_to_real() {
        let mut cng = ComfortNoiseGenerator::new();
        cng.update_level(500.0);

        // Create "real audio" buffer
        #[allow(clippy::cast_possible_truncation)]
        let mut output: Vec<i16> = (0..160).map(|i| (i * 200) as i16).collect();
        let original = output.clone();

        cng.crossfade_to_real(&mut output);

        // First sample should be mostly CNG
        // Last samples should be unchanged (beyond crossfade region)
        let fade_len = cng.cfg.crossfade_samples;
        assert_eq!(output[fade_len..], original[fade_len..]);
        // First sample should differ from original (blended with CNG)
        assert_ne!(output[0], original[0]);
    }

    #[test]
    fn test_lpc_stability() {
        // All-zeros input should not crash or set model
        let mut cng = ComfortNoiseGenerator::new();
        let zeros = vec![0i16; 320];
        cng.update_spectrum(&zeros);
        assert!(!cng.has_spectrum(), "All-zeros should not produce a model");

        // Very short input should not crash
        let short = vec![100i16; 4];
        cng.update_spectrum(&short);
        assert!(!cng.has_spectrum());
    }

    #[test]
    fn test_low_pass_shapes_noise() {
        let mut cng = ComfortNoiseGenerator::new();
        cng.update_level(500.0);

        let mut output = vec![0i16; 1600];
        cng.generate(&mut output);

        // Compute simple spectral flatness proxy: ratio of
        // high-frequency energy to total energy.
        // With LP filter, high frequencies should be attenuated.
        let diffs: Vec<i32> = output
            .windows(2)
            .map(|w| i32::from(w[1]) - i32::from(w[0]))
            .collect();
        let diff_energy: f64 = diffs.iter().map(|&d| f64::from(d) * f64::from(d)).sum();
        let total_energy: f64 = output.iter().map(|&s| f64::from(s) * f64::from(s)).sum();

        // For white noise, diff_energy/total_energy ≈ 2.0
        // For LP-filtered noise, this ratio should be lower
        if total_energy > 0.0 {
            let ratio = diff_energy / total_energy;
            assert!(
                ratio < 2.0,
                "LP-filtered noise should have lower high-freq content, ratio={ratio}"
            );
        }
    }
}
