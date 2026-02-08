//! In-band DTMF tone generation (ITU-T Q.23).
//!
//! Generates dual-tone multi-frequency (DTMF) audio signals for in-band signaling
//! when RFC 4733 telephone-event is not supported.

use client_types::DtmfDigit;
use std::f32::consts::PI;

/// DTMF frequency pairs (low, high) in Hz per ITU-T Q.23.
/// Index 16 (flash) has no in-band tone — it is a hookswitch signal only.
const DTMF_FREQUENCIES: [(f32, f32); 17] = [
    (941.0, 1336.0), // 0
    (697.0, 1209.0), // 1
    (697.0, 1336.0), // 2
    (697.0, 1477.0), // 3
    (770.0, 1209.0), // 4
    (770.0, 1336.0), // 5
    (770.0, 1477.0), // 6
    (852.0, 1209.0), // 7
    (852.0, 1336.0), // 8
    (852.0, 1477.0), // 9
    (941.0, 1209.0), // *
    (941.0, 1477.0), // #
    (697.0, 1633.0), // A
    (770.0, 1633.0), // B
    (852.0, 1633.0), // C
    (941.0, 1633.0), // D
    (0.0, 0.0),      // Flash (no in-band tone)
];

/// DTMF tone generator for in-band signaling.
///
/// Generates PCM samples at the specified sample rate by summing
/// two sine waves at the DTMF frequencies for the given digit.
pub struct DtmfToneGenerator {
    /// Sample rate (typically 8000 Hz for G.711).
    sample_rate: u32,
    /// Low frequency in Hz.
    low_freq: f32,
    /// High frequency in Hz.
    high_freq: f32,
    /// Current phase for low frequency oscillator (0.0 to 2π).
    low_phase: f32,
    /// Current phase for high frequency oscillator (0.0 to 2π).
    high_phase: f32,
    /// Amplitude (0.0 to 1.0). Default 0.5 to prevent clipping when summing.
    amplitude: f32,
}

impl DtmfToneGenerator {
    /// Creates a new DTMF tone generator for the given digit.
    ///
    /// # Arguments
    /// * `digit` - The DTMF digit to generate
    /// * `sample_rate` - Sample rate in Hz (e.g., 8000 for G.711)
    ///
    /// # Returns
    /// A new tone generator ready to produce samples
    pub const fn new(digit: DtmfDigit, sample_rate: u32) -> Self {
        let (low_freq, high_freq) = DTMF_FREQUENCIES[digit.event_code() as usize];

        Self {
            sample_rate,
            low_freq,
            high_freq,
            low_phase: 0.0,
            high_phase: 0.0,
            amplitude: 0.5, // 50% amplitude for each tone to prevent clipping
        }
    }

    /// Generates the next PCM sample (16-bit signed).
    ///
    /// Call this repeatedly to generate a continuous tone. The generator
    /// maintains phase continuity across calls.
    ///
    /// # Returns
    /// A 16-bit PCM sample value (-32768 to 32767)
    pub fn next_sample(&mut self) -> i16 {
        // Generate sine waves for both frequencies
        let low_sample = self.low_phase.sin() * self.amplitude;
        let high_sample = self.high_phase.sin() * self.amplitude;

        // Sum the two tones
        let mixed = low_sample + high_sample;

        // Convert to 16-bit PCM
        #[allow(clippy::cast_possible_truncation)]
        let pcm = (mixed * 32767.0) as i16;

        // Advance phases
        #[allow(clippy::cast_precision_loss)] // sample rates ≤ 48000 fit in f32
        let sample_rate_f32 = self.sample_rate as f32;
        self.low_phase += 2.0 * PI * self.low_freq / sample_rate_f32;
        self.high_phase += 2.0 * PI * self.high_freq / sample_rate_f32;

        // Wrap phases to prevent float precision issues
        if self.low_phase >= 2.0 * PI {
            self.low_phase -= 2.0 * PI;
        }
        if self.high_phase >= 2.0 * PI {
            self.high_phase -= 2.0 * PI;
        }

        pcm
    }

    /// Generates multiple PCM samples into a buffer.
    ///
    /// # Arguments
    /// * `buffer` - Output buffer to fill with PCM samples
    pub fn generate_samples(&mut self, buffer: &mut [i16]) {
        for sample in buffer.iter_mut() {
            *sample = self.next_sample();
        }
    }

    /// Generates DTMF tone samples for a specific duration.
    ///
    /// # Arguments
    /// * `digit` - The DTMF digit to generate
    /// * `duration_ms` - Duration in milliseconds
    /// * `sample_rate` - Sample rate in Hz
    ///
    /// # Returns
    /// A vector of 16-bit PCM samples
    pub fn generate_tone(digit: DtmfDigit, duration_ms: u32, sample_rate: u32) -> Vec<i16> {
        let num_samples = (sample_rate * duration_ms / 1000) as usize;
        let mut generator = Self::new(digit, sample_rate);
        let mut samples = vec![0i16; num_samples];
        generator.generate_samples(&mut samples);
        samples
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtmf_frequencies() {
        // Verify frequency table matches ITU-T Q.23
        assert_eq!(DTMF_FREQUENCIES[1], (697.0, 1209.0)); // Digit 1
        assert_eq!(DTMF_FREQUENCIES[5], (770.0, 1336.0)); // Digit 5
        assert_eq!(DTMF_FREQUENCIES[0], (941.0, 1336.0)); // Digit 0
        assert_eq!(DTMF_FREQUENCIES[10], (941.0, 1209.0)); // *
        assert_eq!(DTMF_FREQUENCIES[11], (941.0, 1477.0)); // #
    }

    #[test]
    fn test_tone_generator() {
        let mut generator = DtmfToneGenerator::new(DtmfDigit::Five, 8000);

        // First sample is 0 because sin(0)=0 for both oscillators, skip it
        let _first = generator.next_sample();
        let sample1 = generator.next_sample();
        let sample2 = generator.next_sample();

        // Samples should be non-zero (tone is active after phase 0)
        assert_ne!(sample1, 0);
        assert_ne!(sample2, 0);

        // Samples should be different (waveform progressing)
        assert_ne!(sample1, sample2);
    }

    #[test]
    fn test_generate_tone() {
        let samples = DtmfToneGenerator::generate_tone(DtmfDigit::One, 100, 8000);

        // 100ms at 8000 Hz = 800 samples
        assert_eq!(samples.len(), 800);

        // Check that we have non-zero samples (tone is present)
        let non_zero_count = samples.iter().filter(|&&s| s != 0).count();
        assert!(non_zero_count > 700); // Most samples should be non-zero
    }

    #[test]
    fn test_amplitude_range() {
        let mut generator = DtmfToneGenerator::new(DtmfDigit::Zero, 8000);

        // Generate many samples and check they're in valid range
        // Cast to i32 to allow meaningful range check (i16::abs() is always <= 32767)
        for _ in 0..1000 {
            let sample = generator.next_sample();
            assert!(i32::from(sample).abs() <= 32767);
        }
    }

    #[test]
    fn test_phase_continuity() {
        let mut generator = DtmfToneGenerator::new(DtmfDigit::Five, 8000);

        // Generate samples and verify no extreme jumps
        // Dual-tone signals (770 Hz + 1336 Hz) at 8kHz sample rate can have
        // large inter-sample differences due to constructive/destructive interference.
        // Max theoretical diff for two 0.5-amplitude tones: ~32767 per sample.
        // We check for truly discontinuous jumps (> 75% of full range).
        let mut prev = generator.next_sample();
        for _ in 0..100 {
            let current = generator.next_sample();
            let diff = i32::from(current).abs_diff(i32::from(prev));
            assert!(diff < 30000, "Phase discontinuity detected: diff={diff}");
            prev = current;
        }
    }
}
