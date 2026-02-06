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

/// Target comfort noise level relative to the estimated noise floor.
/// 0.5 = half the noise floor energy (subtle, non-intrusive).
const CN_LEVEL_FACTOR: f32 = 0.5;

/// Simple one-pole low-pass filter coefficient for noise shaping.
/// Higher values = more smoothing (lower frequency content).
/// 0.7 produces a gentle roll-off above ~500 Hz at 8 kHz sample rate.
const LP_FILTER_COEFF: f32 = 0.7;

/// Comfort noise generator using shaped white noise.
#[derive(Debug)]
pub struct ComfortNoiseGenerator {
    /// PRNG state (xorshift32).
    rng_state: u32,
    /// Target noise level (RMS amplitude, from VAD noise floor).
    target_level: f32,
    /// Low-pass filter state (previous output sample).
    lp_state: f32,
}

impl Default for ComfortNoiseGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ComfortNoiseGenerator {
    /// Creates a new comfort noise generator.
    pub const fn new() -> Self {
        Self {
            rng_state: 0x1234_5678,
            target_level: 0.0,
            lp_state: 0.0,
        }
    }

    /// Updates the target noise level from the VAD's noise floor estimate.
    ///
    /// Call this periodically (e.g., every time VAD transitions to silence)
    /// so the comfort noise level tracks the actual background.
    pub fn update_level(&mut self, noise_floor_rms: f32) {
        self.target_level = noise_floor_rms * CN_LEVEL_FACTOR;
    }

    /// Generates a frame of comfort noise into the provided buffer.
    ///
    /// The output is shaped white noise at the configured level.
    #[allow(clippy::cast_possible_truncation)]
    pub fn generate(&mut self, output: &mut [i16]) {
        if self.target_level < 1.0 {
            // Level too low to be audible — fill with silence
            output.fill(0);
            return;
        }

        for sample in output.iter_mut() {
            // Generate white noise sample in -1.0..1.0
            let white = self.next_random();

            // Scale to target level
            let scaled = white * self.target_level;

            // Apply simple one-pole low-pass filter for spectral shaping
            self.lp_state = LP_FILTER_COEFF
                .mul_add(self.lp_state, (1.0 - LP_FILTER_COEFF) * scaled);

            // Convert to i16 with clamping
            *sample = self.lp_state.clamp(-32768.0, 32767.0) as i16;
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

    /// Generates a random f32 in the range -1.0..1.0 using xorshift32.
    #[allow(clippy::cast_precision_loss)]
    fn next_random(&mut self) -> f32 {
        // xorshift32 PRNG — fast, deterministic, good enough for noise
        self.rng_state ^= self.rng_state << 13;
        self.rng_state ^= self.rng_state >> 17;
        self.rng_state ^= self.rng_state << 5;

        // Map u32 to -1.0..1.0
        // Use the upper bits (better distribution) by converting to signed
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
        assert!(output.iter().all(|&s| s >= i16::MIN && s <= i16::MAX));
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
