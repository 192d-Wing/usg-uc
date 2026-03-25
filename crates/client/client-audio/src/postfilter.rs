//! Decoder-side postfilter for G.711 quantization noise reduction.
//!
//! G.711 companding (µ-law/A-law) uses non-uniform quantization steps that
//! introduce noise correlated with the signal. Our encoder-side noise shaper
//! (Appendix III) pushes quantization noise energy toward high frequencies
//! (NTF = 1 − 0.5z⁻¹ → +3.5 dB at Nyquist). This postfilter compensates
//! by applying cascaded gain-normalized low-pass tilt stages that attenuate
//! the high-frequency noise while preserving speech fundamentals and formants.
//!
//! Based on ITU-T G.711 Appendix III §4 recommendations. The filter
//! operates at codec rate (8 kHz) before resampling for maximum effect.
//!
//! ## Filter response
//!
//! Two cascaded 1st-order tilt sections with α=0.45 give:
//! - DC: 0 dB (unity gain, speech fundamentals preserved)
//! - 1 kHz: ~-1 dB (formant region, minimal impact)
//! - 2 kHz: ~-4 dB (upper formants, slight attenuation)
//! - 3 kHz: ~-8 dB (consonant/noise boundary)
//! - 4 kHz (Nyquist): ~-17 dB (strong noise attenuation)

/// Configuration for the decoder-side postfilter.
#[derive(Debug, Clone)]
pub struct PostfilterConfig {
    /// Low-pass tilt coefficient (0.0 = bypass, higher = more HF attenuation).
    pub tilt_alpha: f32,
    /// Number of cascaded tilt stages (1 = 6 dB/oct, 2 = 12 dB/oct).
    pub stages: u8,
}

impl Default for PostfilterConfig {
    fn default() -> Self {
        // Two cascaded stages with α=0.45 give ~17 dB attenuation at Nyquist
        // while preserving speech fundamentals. This effectively suppresses
        // G.711 quantization noise from remote endpoints that lack
        // encoder-side noise shaping (most SIP providers).
        Self {
            tilt_alpha: 0.45,
            stages: 2,
        }
    }
}

/// Decoder-side postfilter using cascaded gain-normalized low-pass tilt stages.
///
/// Each stage implements `y[n] = (x[n] + α * x[n-1]) / (1 + α)`, which gently
/// attenuates high-frequency quantization noise. Cascading two stages gives
/// 12 dB/octave rolloff instead of 6 dB/octave.
#[derive(Debug)]
pub struct Postfilter {
    /// Previous input sample for each tilt stage.
    prev_input: [f32; 2],
    /// Whether the postfilter is active.
    enabled: bool,
    /// Tilt coefficient.
    tilt_alpha: f32,
    /// Gain normalization factor: 1/(1+α).
    gain_norm: f32,
    /// Number of active stages (1 or 2).
    stages: u8,
}

impl Default for Postfilter {
    fn default() -> Self {
        Self::new()
    }
}

impl Postfilter {
    /// Creates a new postfilter (enabled by default).
    pub fn new() -> Self {
        Self::with_config(PostfilterConfig::default())
    }

    /// Creates a postfilter with custom configuration.
    pub fn with_config(cfg: PostfilterConfig) -> Self {
        Self {
            prev_input: [0.0; 2],
            enabled: true,
            tilt_alpha: cfg.tilt_alpha,
            gain_norm: 1.0 / (1.0 + cfg.tilt_alpha),
            stages: cfg.stages.min(2).max(1),
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
    /// Each stage applies `y[n] = (x[n] + α * x[n-1]) / (1 + α)`.
    /// With 2 stages, the output of stage 1 feeds into stage 2.
    /// Zero-allocation operation.
    #[allow(clippy::cast_possible_truncation)]
    pub fn process(&mut self, pcm: &mut [i16]) {
        if !self.enabled {
            return;
        }

        let alpha = self.tilt_alpha;
        let norm = self.gain_norm;

        for sample in pcm.iter_mut() {
            // Stage 1
            let x0 = f32::from(*sample);
            let y0 = alpha.mul_add(self.prev_input[0], x0) * norm;
            self.prev_input[0] = x0;

            if self.stages >= 2 {
                // Stage 2: feed stage 1 output into stage 2
                let y1 = alpha.mul_add(self.prev_input[1], y0) * norm;
                self.prev_input[1] = y0;
                *sample = y1.clamp(-32768.0, 32767.0) as i16;
            } else {
                *sample = y0.clamp(-32768.0, 32767.0) as i16;
            }
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
        let mut pf = Postfilter::new();
        let mut dc = vec![1000i16; 160];
        pf.process(&mut dc);

        // After settling, each stage has DC gain of 1.0, so cascaded = 1.0
        let settled = dc[159];
        assert!(
            (settled - 1000).abs() < 10,
            "Settled DC should be ~1000 (unity gain), got {settled}"
        );
    }

    #[test]
    fn test_high_freq_attenuated() {
        // An alternating signal (+1000, -1000) is at Nyquist frequency
        // and should be strongly attenuated by 2-stage tilt
        let mut pf = Postfilter::new();
        let mut alt: Vec<i16> = (0..160)
            .map(|i| if i % 2 == 0 { 1000 } else { -1000 })
            .collect();
        let original_energy: f64 = alt.iter().map(|&s| f64::from(s) * f64::from(s)).sum();

        pf.process(&mut alt);

        let filtered_energy: f64 = alt.iter().map(|&s| f64::from(s) * f64::from(s)).sum();

        // 2-stage Nyquist gain = ((1-α)/(1+α))^2 = (0.55/1.45)^2 ≈ 0.144
        // Energy ≈ 0.021x. Allow margin for transient.
        assert!(
            filtered_energy < original_energy * 0.1,
            "Nyquist should be strongly attenuated with 2 stages: ratio={}",
            filtered_energy / original_energy
        );
    }

    #[test]
    fn test_single_stage_less_attenuation() {
        let cfg = PostfilterConfig {
            tilt_alpha: 0.45,
            stages: 1,
        };
        let mut pf = Postfilter::with_config(cfg);
        let mut alt: Vec<i16> = (0..160)
            .map(|i| if i % 2 == 0 { 1000 } else { -1000 })
            .collect();
        let original_energy: f64 = alt.iter().map(|&s| f64::from(s) * f64::from(s)).sum();

        pf.process(&mut alt);
        let filtered_energy: f64 = alt.iter().map(|&s| f64::from(s) * f64::from(s)).sum();

        // 1-stage: energy ratio ≈ 0.144 (less attenuation than 2-stage)
        assert!(
            filtered_energy < original_energy * 0.3,
            "Single stage should attenuate Nyquist but less than 2-stage"
        );
    }

    #[test]
    fn test_output_bounded() {
        let mut pf = Postfilter::new();
        let mut loud = vec![i16::MAX; 160];
        pf.process(&mut loud);
        assert!(
            loud.iter().all(|&s| s >= i16::MIN && s <= i16::MAX),
            "Output should be clamped to i16 range"
        );
    }

    #[test]
    fn test_cross_frame_continuity() {
        let mut pf = Postfilter::new();
        let mut frame1 = vec![500i16; 160];
        let mut frame2 = vec![500i16; 160];

        pf.process(&mut frame1);
        let last_of_frame1 = frame1[159];

        pf.process(&mut frame2);
        let first_of_frame2 = frame2[0];

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
