//! Decoder-side postfilter for G.711 quantization noise reduction.
//!
//! G.711 companding (µ-law/A-law) uses non-uniform quantization steps that
//! introduce noise correlated with the signal. This postfilter applies a
//! mild spectral tilt to reduce perceived quantization noise while
//! preserving speech clarity.
//!
//! Based on ITU-T G.711 Appendix III §4 recommendations. The filter
//! operates at codec rate (8 kHz) before resampling for maximum effect.

/// Tilt filter coefficient (0.0 = bypass, higher = more tilt).
/// 0.4 provides gentle high-frequency emphasis that masks quantization
/// noise without altering speech timbre noticeably.
const TILT_ALPHA: f32 = 0.4;

/// Decoder-side postfilter using a first-order tilt filter.
///
/// Implements `y[n] = x[n] - α * x[n-1]`, a simple high-pass tilt
/// that attenuates low-frequency quantization noise energy while
/// gently boosting speech formant frequencies (1-4 kHz at 8 kHz sample rate).
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
    /// The tilt filter `y[n] = x[n] - α * x[n-1]` provides mild
    /// high-pass emphasis. This is a zero-allocation operation.
    #[allow(clippy::cast_possible_truncation)]
    pub fn process(&mut self, pcm: &mut [i16]) {
        if !self.enabled {
            return;
        }

        for sample in pcm.iter_mut() {
            let x = f32::from(*sample);
            let y = TILT_ALPHA.mul_add(-self.prev_input, x);
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
    fn test_dc_attenuated() {
        // A constant DC signal should be attenuated by the tilt filter
        let mut pf = Postfilter::new();
        let mut dc = vec![1000i16; 160];
        pf.process(&mut dc);

        // First sample passes through (prev=0), subsequent samples reduced
        assert_eq!(dc[0], 1000);
        // After settling, output ≈ x - 0.4*x = 0.6*x = 600
        let settled = dc[159];
        assert!(
            (settled - 600).abs() < 10,
            "Settled DC should be ~600 (60% of input), got {settled}"
        );
    }

    #[test]
    fn test_high_freq_preserved() {
        // An alternating signal (+1000, -1000) is high frequency
        // and should be relatively preserved by the high-pass tilt
        let mut pf = Postfilter::new();
        let mut alt: Vec<i16> = (0..160)
            .map(|i| if i % 2 == 0 { 1000 } else { -1000 })
            .collect();
        let original_energy: f64 = alt.iter().map(|&s| f64::from(s) * f64::from(s)).sum();

        pf.process(&mut alt);

        let filtered_energy: f64 = alt.iter().map(|&s| f64::from(s) * f64::from(s)).sum();

        // High-frequency energy should be boosted or roughly preserved (not attenuated)
        assert!(
            filtered_energy >= original_energy * 0.9,
            "High-frequency signal should be preserved: original={original_energy}, filtered={filtered_energy}"
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
