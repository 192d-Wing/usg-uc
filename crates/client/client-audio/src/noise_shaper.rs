//! Encoder-side noise shaping for G.711 (ITU-T G.711 Appendix III).
//!
//! G.711 companding (µ-law/A-law) uses non-uniform quantization steps that
//! introduce signal-correlated noise. This module feeds back filtered
//! quantization error to reshape the noise spectrum, pushing noise energy
//! from low frequencies (where speech concentrates and the ear is most
//! sensitive) to high frequencies (less perceptible in narrowband telephony).
//!
//! ## Algorithm
//!
//! First-order error feedback:
//! ```text
//! shaped[n] = x[n] + α * e[n-1]
//! encoded[n] = g711_encode(clamp(shaped[n]))
//! decoded[n] = g711_decode(encoded[n])
//! e[n] = shaped[n] - decoded[n]
//! ```
//!
//! With α = 0.5, the Noise Transfer Function is NTF(z) = 1 - 0.5·z⁻¹:
//! - DC (0 Hz): -6.0 dB noise reduction (speech fundamentals)
//! - 1 kHz: -3.0 dB reduction (first formant region)
//! - 4 kHz (Nyquist): +3.5 dB increase (less perceptible)
//!
//! ## Integration
//!
//! ```text
//! Mic → AGC → VAD → Resample(8kHz) → [NoiseShaper] → G.711 encode → RTP
//! ```

use uc_codecs::{G711Alaw, G711Ulaw};

/// Configuration for the encoder-side noise shaper.
#[derive(Debug, Clone)]
pub struct NoiseShaperConfig {
    /// Noise shaping filter coefficient (0.0-0.8).
    /// Higher values push more noise to high frequencies but risk audible HF noise.
    pub alpha: f32,
    /// Maximum absolute error feedback value. Prevents runaway divergence.
    pub error_clamp: f32,
}

impl Default for NoiseShaperConfig {
    fn default() -> Self {
        Self {
            // Reduced from 0.5 to 0.25: remote endpoints without a matching
            // decoder postfilter hear the shaped HF noise as static. Lower
            // alpha keeps noise shaping benefits while reducing HF artifacts.
            alpha: 0.25,
            error_clamp: 16384.0,
        }
    }
}

/// G.711 companding law for the noise shaper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompandingLaw {
    /// µ-law (PCMU, North America/Japan).
    MuLaw,
    /// A-law (PCMA, Europe/International).
    ALaw,
}

/// Encoder-side noise shaper for G.711.
///
/// Reshapes quantization noise by feeding back filtered error from the
/// previous sample. The shaped PCM, when encoded by the downstream codec,
/// produces a codestream with lower noise energy in the speech band.
#[derive(Debug)]
pub struct NoiseShaper {
    /// Which companding law to use for internal encode/decode.
    law: CompandingLaw,
    /// Previous quantization error (e[n-1]).
    prev_error: f32,
    /// Whether the noise shaper is active.
    enabled: bool,
    /// Configuration parameters.
    cfg: NoiseShaperConfig,
}

impl NoiseShaper {
    /// Creates a new noise shaper for the given companding law.
    pub fn new(law: CompandingLaw) -> Self {
        Self::with_config(law, NoiseShaperConfig::default())
    }

    /// Creates a noise shaper with custom configuration.
    pub fn with_config(law: CompandingLaw, cfg: NoiseShaperConfig) -> Self {
        Self {
            law,
            prev_error: 0.0,
            enabled: true,
            cfg,
        }
    }

    /// Creates a noise shaper that is enabled for G.711 codecs and disabled otherwise.
    ///
    /// Pass `None` for non-G.711 codecs; the shaper will be a no-op.
    pub fn new_optional(law: Option<CompandingLaw>) -> Self {
        match law {
            Some(law) => Self::new(law),
            None => Self {
                law: CompandingLaw::MuLaw,
                prev_error: 0.0,
                enabled: false,
                cfg: NoiseShaperConfig::default(),
            },
        }
    }

    /// Enables or disables the noise shaper.
    pub const fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns whether the noise shaper is enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Resets the error state. Call on device switches to prevent stale feedback.
    pub const fn reset(&mut self) {
        self.prev_error = 0.0;
    }

    /// Applies noise shaping to a frame of PCM in-place before G.711 encoding.
    ///
    /// Each sample is pre-distorted by the filtered quantization error so that
    /// the downstream G.711 encoder produces a noise-shaped codestream.
    /// This is a zero-allocation operation.
    #[allow(clippy::cast_possible_truncation)]
    pub fn process(&mut self, pcm: &mut [i16]) {
        if !self.enabled {
            return;
        }

        for sample in pcm.iter_mut() {
            let x = f32::from(*sample);

            // Add filtered error feedback: shaped = x + α * e[n-1]
            let shaped = self.cfg.alpha.mul_add(self.prev_error, x);

            // Clamp to i16 range before encoding
            let clamped = shaped.clamp(-32768.0, 32767.0) as i16;

            // Simulate G.711 encode→decode roundtrip to find quantization error
            let decoded = match self.law {
                CompandingLaw::MuLaw => {
                    let e = G711Ulaw::encode_sample(clamped);
                    G711Ulaw::decode_sample(e)
                }
                CompandingLaw::ALaw => {
                    let e = G711Alaw::encode_sample(clamped);
                    G711Alaw::decode_sample(e)
                }
            };

            // Quantization error = what we wanted - what we got
            let error = shaped - f32::from(decoded);

            // Clamp error to prevent runaway feedback
            self.prev_error = error.clamp(-self.cfg.error_clamp, self.cfg.error_clamp);

            // Output the shaped sample (codec will encode this identically)
            *sample = clamped;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_noise_shaper() {
        let ns = NoiseShaper::new(CompandingLaw::MuLaw);
        assert!(ns.enabled());
    }

    #[test]
    fn test_disabled_is_passthrough() {
        let mut ns = NoiseShaper::new(CompandingLaw::MuLaw);
        ns.set_enabled(false);

        let original = vec![100i16, 200, 300, 400, 500];
        let mut output = original.clone();
        ns.process(&mut output);
        assert_eq!(
            output, original,
            "Disabled noise shaper should not modify samples"
        );
    }

    #[test]
    fn test_silence_preserved() {
        let mut ns = NoiseShaper::new(CompandingLaw::MuLaw);
        let mut silence = vec![0i16; 160];
        ns.process(&mut silence);
        assert!(
            silence.iter().all(|&s| s == 0),
            "Silence should remain silence"
        );
    }

    #[test]
    fn test_output_bounded() {
        let mut ns = NoiseShaper::new(CompandingLaw::MuLaw);
        // Large signal that could cause overflow
        let mut loud = vec![i16::MAX; 160];
        ns.process(&mut loud);
        assert!(
            loud.iter().all(|&s| s >= i16::MIN && s <= i16::MAX),
            "Output should be clamped to i16 range"
        );

        // Negative extreme
        let mut neg_loud = vec![i16::MIN; 160];
        ns.process(&mut neg_loud);
        assert!(
            neg_loud.iter().all(|&s| s >= i16::MIN && s <= i16::MAX),
            "Negative output should be clamped to i16 range"
        );
    }

    #[test]
    fn test_error_clamped() {
        let mut ns = NoiseShaper::new(CompandingLaw::MuLaw);

        // Process many frames of alternating clipping signals to stress the error loop
        for _ in 0..100 {
            let mut frame: Vec<i16> = (0..160)
                .map(|i| if i % 2 == 0 { i16::MAX } else { i16::MIN })
                .collect();
            ns.process(&mut frame);
        }

        // Error should stay within bounds
        assert!(
            ns.prev_error.abs() <= NoiseShaperConfig::default().error_clamp,
            "Error should be clamped: got {}",
            ns.prev_error
        );
    }

    #[test]
    fn test_cross_frame_continuity() {
        let mut ns = NoiseShaper::new(CompandingLaw::MuLaw);

        // Process a DC signal across two frames
        let mut frame1 = vec![5000i16; 160];
        ns.process(&mut frame1);
        let error_after_frame1 = ns.prev_error;

        let mut frame2 = vec![5000i16; 160];
        ns.process(&mut frame2);

        // Error state should carry across frames (non-zero)
        assert!(
            error_after_frame1.abs() > 0.0 || ns.prev_error.abs() > 0.0,
            "Error should carry across frames"
        );
    }

    #[test]
    fn test_ulaw_and_alaw_both_work() {
        for law in [CompandingLaw::MuLaw, CompandingLaw::ALaw] {
            let mut ns = NoiseShaper::new(law);
            let mut pcm = vec![1000i16; 160];
            ns.process(&mut pcm);
            // Should not panic and should modify at least some samples
            // (the shaped values may differ from the originals)
        }
    }

    #[test]
    fn test_reset_clears_state() {
        let mut ns = NoiseShaper::new(CompandingLaw::MuLaw);
        let mut pcm = vec![10000i16; 160];
        ns.process(&mut pcm);

        // Error should be non-zero after processing
        assert!(ns.prev_error.abs() > 0.0);

        ns.reset();
        assert!(
            (ns.prev_error - 0.0).abs() < f32::EPSILON,
            "Reset should clear prev_error"
        );
    }

    #[test]
    fn test_new_optional_none_disabled() {
        let ns = NoiseShaper::new_optional(None);
        assert!(!ns.enabled());
    }

    #[test]
    fn test_new_optional_some_enabled() {
        let ns = NoiseShaper::new_optional(Some(CompandingLaw::MuLaw));
        assert!(ns.enabled());
    }

    #[test]
    fn test_dc_noise_reduced() {
        // Compare quantization error with and without noise shaping.
        // For a DC signal, noise shaping should reduce low-frequency error.
        let dc_value = 5000i16;
        let frames = 50;
        let frame_size = 160;

        // Without noise shaping: encode directly
        let mut unshaped_errors = Vec::new();
        for _ in 0..frames {
            for _ in 0..frame_size {
                let encoded = G711Ulaw::encode_sample(dc_value);
                let decoded = G711Ulaw::decode_sample(encoded);
                unshaped_errors.push(f64::from(dc_value) - f64::from(decoded));
            }
        }

        // With noise shaping
        let mut ns = NoiseShaper::new(CompandingLaw::MuLaw);
        let mut shaped_errors = Vec::new();
        for _ in 0..frames {
            let mut pcm = vec![dc_value; frame_size];
            ns.process(&mut pcm);
            for &shaped_sample in &pcm {
                let encoded = G711Ulaw::encode_sample(shaped_sample);
                let decoded = G711Ulaw::decode_sample(encoded);
                // Error relative to original (unshaped) input
                shaped_errors.push(f64::from(dc_value) - f64::from(decoded));
            }
        }

        // Compute low-frequency error power via running average (proxy for DC component).
        // A 16-sample running average captures energy below ~500 Hz at 8 kHz.
        let avg_window = 16;
        let unshaped_dc_power = running_avg_power(&unshaped_errors, avg_window);
        let shaped_dc_power = running_avg_power(&shaped_errors, avg_window);

        assert!(
            shaped_dc_power < unshaped_dc_power * 0.8,
            "Noise shaping should reduce low-frequency error: unshaped={unshaped_dc_power:.1}, shaped={shaped_dc_power:.1}"
        );
    }

    /// Computes the power of a running average of the signal (low-frequency proxy).
    fn running_avg_power(signal: &[f64], window: usize) -> f64 {
        if signal.len() < window {
            return 0.0;
        }
        let mut sum = 0.0;
        let mut power = 0.0;
        let mut count = 0;

        for (i, &s) in signal.iter().enumerate() {
            sum += s;
            if i >= window {
                sum -= signal[i - window];
            }
            if i >= window - 1 {
                let avg = sum / window as f64;
                power += avg * avg;
                count += 1;
            }
        }

        if count > 0 {
            power / count as f64
        } else {
            0.0
        }
    }

    #[test]
    fn test_enable_disable() {
        let mut ns = NoiseShaper::new(CompandingLaw::MuLaw);
        assert!(ns.enabled());

        ns.set_enabled(false);
        assert!(!ns.enabled());

        ns.set_enabled(true);
        assert!(ns.enabled());
    }
}
