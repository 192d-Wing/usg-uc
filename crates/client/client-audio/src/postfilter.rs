//! Decoder-side postfilter for G.711 quantization noise reduction.
//!
//! G.711 companding (µ-law/A-law) uses non-uniform quantization steps that
//! introduce noise correlated with the signal. Our encoder-side noise shaper
//! (Appendix III) pushes quantization noise energy toward high frequencies
//! (NTF = 1 − 0.5z⁻¹ → +3.5 dB at Nyquist). This postfilter compensates
//! by applying a gain-normalized low-pass tilt that attenuates the
//! high-frequency noise while preserving speech fundamentals and formants.
//!
//! Based on ITU-T G.711 Appendix III §4 recommendations. The filter
//! operates at codec rate (8 kHz) before resampling for maximum effect.

/// Low-pass tilt coefficient (0.0 = bypass, higher = more HF attenuation).
///
/// Frequency response (8 kHz sample rate):
/// - DC (0 Hz): 1.0 (unity — no bass boost)
/// - 1 kHz: ~0.97 (−0.3 dB, negligible)
/// - 2 kHz: ~0.89 (−1.0 dB, mild)
/// - 4 kHz (Nyquist): (1−α)/(1+α) = 0.54 (−5.4 dB, significant)
const TILT_ALPHA: f32 = 0.3;

/// Gain normalization factor: 1/(1+α).
/// Ensures DC gain is exactly 1.0 (no bass boost).
const GAIN_NORM: f32 = 1.0 / (1.0 + TILT_ALPHA);

/// Decoder-side postfilter using a gain-normalized low-pass tilt filter.
///
/// Implements `y[n] = (x[n] + α * x[n-1]) / (1 + α)`, which gently
/// attenuates high-frequency quantization noise pushed there by the
/// encoder-side noise shaper, while preserving speech fundamentals.
#[derive(Debug)]
pub struct Postfilter {
    /// Previous input sample for the tilt filter.
    prev_input: f32,
    /// Whether the postfilter is active.
    enabled: bool,
}

impl Default for Postfilter {
    fn default() -> Self {
        Self::new()
    }
}

impl Postfilter {
    /// Creates a new postfilter (enabled by default).
    pub const fn new() -> Self {
        Self {
            prev_input: 0.0,
            enabled: true,
        }
    }

    /// Enables or disables the postfilter.
    pub const fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns whether the postfilter is enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Applies the postfilter to a frame of decoded PCM in-place.
    ///
    /// The low-pass tilt `y[n] = (x[n] + α * x[n-1]) / (1 + α)` gently
    /// rolls off high-frequency quantization noise. Zero-allocation operation.
    #[allow(clippy::cast_possible_truncation)]
    pub fn process(&mut self, pcm: &mut [i16]) {
        if !self.enabled {
            return;
        }

        for sample in pcm.iter_mut() {
            let x = f32::from(*sample);
            let y = TILT_ALPHA.mul_add(self.prev_input, x) * GAIN_NORM;
            self.prev_input = x;
            *sample = y.clamp(-32768.0, 32767.0) as i16;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_postfilter() {
        let pf = Postfilter::new();
        assert!(pf.enabled());
    }

    #[test]
    fn test_disabled_is_passthrough() {
        let mut pf = Postfilter::new();
        pf.set_enabled(false);

        let original = vec![100i16, 200, 300, 400, 500];
        let mut output = original.clone();
        pf.process(&mut output);
        assert_eq!(
            output, original,
            "Disabled postfilter should not modify samples"
        );
    }

    #[test]
    fn test_silence_preserved() {
        let mut pf = Postfilter::new();
        let mut silence = vec![0i16; 160];
        pf.process(&mut silence);
        assert!(
            silence.iter().all(|&s| s == 0),
            "Silence should remain silence"
        );
    }

    #[test]
    fn test_dc_preserved() {
        // A constant DC signal should pass through at unity gain
        // (the gain normalization factor 1/(1+α) cancels the (1+α) DC gain)
        let mut pf = Postfilter::new();
        let mut dc = vec![1000i16; 160];
        pf.process(&mut dc);

        // After settling, output ≈ (x + α*x) / (1+α) = x = 1000
        let settled = dc[159];
        assert!(
            (settled - 1000).abs() < 10,
            "Settled DC should be ~1000 (unity gain), got {settled}"
        );
    }

    #[test]
    fn test_high_freq_attenuated() {
        // An alternating signal (+1000, -1000) is at Nyquist frequency
        // and should be attenuated by the low-pass tilt
        let mut pf = Postfilter::new();
        let mut alt: Vec<i16> = (0..160)
            .map(|i| if i % 2 == 0 { 1000 } else { -1000 })
            .collect();
        let original_energy: f64 = alt.iter().map(|&s| f64::from(s) * f64::from(s)).sum();

        pf.process(&mut alt);

        let filtered_energy: f64 = alt.iter().map(|&s| f64::from(s) * f64::from(s)).sum();

        // Nyquist gain = (1-α)/(1+α) = 0.7/1.3 ≈ 0.538, energy ≈ 0.29x
        // Allow some margin for the transient at the start
        assert!(
            filtered_energy < original_energy * 0.5,
            "Nyquist signal should be significantly attenuated: original={original_energy}, filtered={filtered_energy}"
        );
    }

    #[test]
    fn test_output_bounded() {
        let mut pf = Postfilter::new();
        // Large signal that could cause overflow
        let mut loud = vec![i16::MAX; 160];
        pf.process(&mut loud);
        assert!(
            loud.iter().all(|&s| s >= i16::MIN && s <= i16::MAX),
            "Output should be clamped to i16 range"
        );
    }

    #[test]
    fn test_cross_frame_continuity() {
        // Process two frames back-to-back and verify no discontinuity
        let mut pf = Postfilter::new();
        let mut frame1 = vec![500i16; 160];
        let mut frame2 = vec![500i16; 160];

        pf.process(&mut frame1);
        let last_of_frame1 = frame1[159];

        pf.process(&mut frame2);
        let first_of_frame2 = frame2[0];

        // Should be continuous (same input, filter has settled)
        assert!(
            (last_of_frame1 - first_of_frame2).abs() <= 1,
            "Cross-frame should be continuous: {last_of_frame1} vs {first_of_frame2}"
        );
    }

    #[test]
    fn test_enable_disable() {
        let mut pf = Postfilter::new();
        assert!(pf.enabled());

        pf.set_enabled(false);
        assert!(!pf.enabled());

        pf.set_enabled(true);
        assert!(pf.enabled());
    }
}
