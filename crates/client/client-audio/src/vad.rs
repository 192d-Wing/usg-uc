//! Voice Activity Detection (VAD) for discontinuous transmission.
//!
//! Detects speech vs silence in microphone audio using a combination
//! of short-term energy and zero-crossing rate. Pure Rust with no
//! external dependencies.
//!
//! ## Features
//!
//! - Adaptive noise floor estimation during silence periods
//! - Hangover (hold) period to avoid clipping word tails
//! - Hysteresis with separate speech/silence thresholds
//! - Background noise level tracking for comfort noise generation
//!
//! ## Usage
//!
//! ```text
//! Microphone → [AudioProcessor] → [VAD] → Speech? → Encode + Send
//!                                       → Silence? → Skip / DTX
//! ```

/// Minimum energy threshold (prevents triggering on near-zero input).
const MIN_ENERGY_THRESHOLD: f32 = 50.0;

/// Configuration for Voice Activity Detection.
#[derive(Debug, Clone)]
pub struct VadConfig {
    /// Ratio above noise floor for speech detection.
    pub speech_threshold_ratio: f32,
    /// Ratio for returning to silence (hysteresis).
    pub silence_threshold_ratio: f32,
    /// Zero-crossing rate threshold (0.0-1.0). High ZCR + marginal energy = noise.
    pub zcr_noise_threshold: f32,
    /// Frames to hold speech state after energy drops (at 20ms/frame).
    pub hangover_frames: u32,
    /// Smoothing factor for noise floor adaptation during silence.
    pub noise_floor_adapt_rate: f32,
    /// Maximum noise floor (prevents runaway in noisy environments).
    pub max_noise_floor: f32,
    /// Number of initial frames for noise floor calibration.
    pub calibration_frames: u32,
}

impl Default for VadConfig {
    fn default() -> Self {
        Self {
            speech_threshold_ratio: 2.5,
            silence_threshold_ratio: 2.0,
            zcr_noise_threshold: 0.5,
            hangover_frames: 25,
            noise_floor_adapt_rate: 0.02,
            max_noise_floor: 1000.0,
            calibration_frames: 25,
        }
    }
}

/// Voice Activity Detection result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VadDecision {
    /// Speech detected — frame should be transmitted.
    Speech,
    /// Silence detected — frame can be suppressed (DTX).
    Silence,
}

/// Voice Activity Detector using energy + zero-crossing rate.
#[derive(Debug)]
pub struct VoiceActivityDetector {
    /// Current state (speech or silence).
    in_speech: bool,
    /// Frames remaining in hangover period.
    hangover_counter: u32,
    /// Estimated background noise floor (RMS energy).
    noise_floor: f32,
    /// Frame counter for initial calibration.
    frame_count: u32,
    /// Whether initial calibration is complete.
    calibrated: bool,
    /// Configuration parameters.
    cfg: VadConfig,
}

impl Default for VoiceActivityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl VoiceActivityDetector {
    /// Creates a new VAD with default settings.
    pub fn new() -> Self {
        Self::with_config(VadConfig::default())
    }

    /// Creates a VAD with custom configuration.
    pub const fn with_config(cfg: VadConfig) -> Self {
        Self {
            in_speech: false,
            hangover_counter: 0,
            noise_floor: MIN_ENERGY_THRESHOLD,
            frame_count: 0,
            calibrated: false,
            cfg,
        }
    }

    /// Classifies a PCM frame as speech or silence.
    ///
    /// Should be called once per frame (typically every 20ms)
    /// after audio processing (noise gate, AGC).
    pub fn detect(&mut self, pcm: &[i16]) -> VadDecision {
        if pcm.is_empty() {
            return VadDecision::Silence;
        }

        let (energy, zcr) = compute_rms_and_zcr(pcm);

        self.frame_count = self.frame_count.saturating_add(1);

        // Initial calibration: assume first N frames are background noise
        if !self.calibrated {
            if self.frame_count <= self.cfg.calibration_frames {
                // Use first frames to estimate noise floor
                #[allow(clippy::cast_precision_loss)]
                let alpha = 1.0 / self.frame_count as f32;
                self.noise_floor = self.noise_floor.mul_add(1.0 - alpha, energy * alpha);
                self.noise_floor = self.noise_floor.max(MIN_ENERGY_THRESHOLD);
                return VadDecision::Silence;
            }
            self.calibrated = true;
        }

        // Determine thresholds based on current state (hysteresis)
        let threshold = if self.in_speech {
            (self.noise_floor * self.cfg.silence_threshold_ratio).max(MIN_ENERGY_THRESHOLD)
        } else {
            (self.noise_floor * self.cfg.speech_threshold_ratio).max(MIN_ENERGY_THRESHOLD)
        };

        // High ZCR with marginal energy → likely unvoiced noise, not speech
        let is_likely_noise = zcr > self.cfg.zcr_noise_threshold && energy < threshold * 1.5;

        let is_speech = energy > threshold && !is_likely_noise;

        if is_speech {
            self.in_speech = true;
            self.hangover_counter = self.cfg.hangover_frames;
        } else if self.hangover_counter > 0 {
            // In hangover period — keep speech state
            self.hangover_counter -= 1;
        } else {
            // Transition to silence
            self.in_speech = false;
            // Update noise floor during silence (slow adaptation)
            self.adapt_noise_floor(energy);
        }

        if self.in_speech {
            VadDecision::Speech
        } else {
            VadDecision::Silence
        }
    }

    /// Returns the current estimated background noise floor (RMS).
    pub const fn noise_floor(&self) -> f32 {
        self.noise_floor
    }

    /// Returns whether the VAD is currently in speech state.
    pub const fn in_speech(&self) -> bool {
        self.in_speech
    }

    /// Adapts the noise floor estimate during silence periods.
    fn adapt_noise_floor(&mut self, energy: f32) {
        // Only adapt if energy is reasonable (not a burst of noise)
        if energy < self.noise_floor * self.cfg.speech_threshold_ratio {
            self.noise_floor += (energy - self.noise_floor) * self.cfg.noise_floor_adapt_rate;
            self.noise_floor = self
                .noise_floor
                .clamp(MIN_ENERGY_THRESHOLD, self.cfg.max_noise_floor);
        }
    }
}

/// Computes RMS energy and zero-crossing rate in a single pass over the PCM buffer.
///
/// Returns `(rms, zcr)` where:
/// - `rms` is the Root Mean Square energy (f32)
/// - `zcr` is the zero-crossing rate in 0.0..1.0
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn compute_rms_and_zcr(pcm: &[i16]) -> (f32, f32) {
    if pcm.is_empty() {
        return (0.0, 0.0);
    }

    let mut sum_sq: f64 = f64::from(pcm[0]) * f64::from(pcm[0]);
    let mut crossings: u32 = 0;
    let mut prev = pcm[0];

    for &s in &pcm[1..] {
        sum_sq += f64::from(s) * f64::from(s);
        if (prev >= 0) != (s >= 0) {
            crossings += 1;
        }
        prev = s;
    }

    let rms = (sum_sq / pcm.len() as f64).sqrt() as f32;
    let zcr = if pcm.len() > 1 {
        crossings as f32 / (pcm.len() - 1) as f32
    } else {
        0.0
    };
    (rms, zcr)
}

/// Computes the zero-crossing rate of a PCM buffer (standalone, used in tests).
///
/// Returns a value in 0.0..1.0 where 0.0 means no zero crossings
/// and 1.0 means every consecutive pair crosses zero.
#[cfg(test)]
#[allow(clippy::cast_precision_loss)]
fn compute_zcr(pcm: &[i16]) -> f32 {
    if pcm.len() < 2 {
        return 0.0;
    }
    let crossings = pcm
        .windows(2)
        .filter(|w| (w[0] >= 0) != (w[1] >= 0))
        .count();
    crossings as f32 / (pcm.len() - 1) as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_vad() {
        let vad = VoiceActivityDetector::new();
        assert!(!vad.in_speech());
        assert!((vad.noise_floor() - MIN_ENERGY_THRESHOLD).abs() < f32::EPSILON);
    }

    #[test]
    fn test_silence_detected() {
        let mut vad = VoiceActivityDetector::new();
        // Skip calibration
        for _ in 0..=VadConfig::default().calibration_frames {
            vad.detect(&[0i16; 160]);
        }
        let result = vad.detect(&[0i16; 160]);
        assert_eq!(result, VadDecision::Silence);
    }

    #[test]
    fn test_speech_detected() {
        let mut vad = VoiceActivityDetector::new();
        // Calibrate with silence
        for _ in 0..=VadConfig::default().calibration_frames {
            vad.detect(&[0i16; 160]);
        }

        // Feed a loud speech-like signal (low ZCR, high energy)
        let signal: Vec<i16> = (0..160)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let s = (f64::sin(2.0 * std::f64::consts::PI * 200.0 * f64::from(i) / 8000.0)
                    * 5000.0) as i16;
                s
            })
            .collect();

        let result = vad.detect(&signal);
        assert_eq!(result, VadDecision::Speech);
        assert!(vad.in_speech());
    }

    #[test]
    fn test_hangover_prevents_cutting() {
        let mut vad = VoiceActivityDetector::new();
        // Calibrate
        for _ in 0..=VadConfig::default().calibration_frames {
            vad.detect(&[0i16; 160]);
        }

        // Speech frame
        let speech: Vec<i16> = vec![5000i16; 160];
        vad.detect(&speech);
        assert!(vad.in_speech());

        // First few silence frames should still be "speech" (hangover)
        for i in 0..VadConfig::default().hangover_frames {
            let result = vad.detect(&[1i16; 160]);
            assert_eq!(
                result,
                VadDecision::Speech,
                "Should be speech during hangover at frame {i}"
            );
        }

        // After hangover expires, should be silence
        let result = vad.detect(&[1i16; 160]);
        assert_eq!(result, VadDecision::Silence);
    }

    #[test]
    fn test_noise_floor_adaptation() {
        let mut vad = VoiceActivityDetector::new();
        // Calibrate with moderate noise
        let noise: Vec<i16> = vec![100i16; 160];
        for _ in 0..=VadConfig::default().calibration_frames {
            vad.detect(&noise);
        }

        // Noise floor should have adapted to the background level
        let floor = vad.noise_floor();
        assert!(
            floor > MIN_ENERGY_THRESHOLD,
            "Noise floor should adapt above minimum: {floor}"
        );
    }

    #[test]
    fn test_compute_zcr_silence() {
        let silence = vec![0i16; 160];
        let zcr = compute_zcr(&silence);
        assert!(zcr < f32::EPSILON, "Silence should have zero ZCR");
    }

    #[test]
    fn test_compute_zcr_alternating() {
        // Alternating positive/negative = maximum ZCR
        let alternating: Vec<i16> = (0..160)
            .map(|i| if i % 2 == 0 { 1000 } else { -1000 })
            .collect();
        let zcr = compute_zcr(&alternating);
        assert!(
            (zcr - 1.0).abs() < 0.02,
            "Alternating signal should have ZCR near 1.0, got {zcr}"
        );
    }

    #[test]
    fn test_compute_zcr_sine() {
        // Sine wave at 200 Hz sampled at 8000 Hz → ~0.05 ZCR
        let signal: Vec<i16> = (0..160)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let s = (f64::sin(2.0 * std::f64::consts::PI * 200.0 * f64::from(i) / 8000.0)
                    * 10000.0) as i16;
                s
            })
            .collect();
        let zcr = compute_zcr(&signal);
        // 200 Hz in 20ms = 4 full cycles = 8 zero crossings out of 159 pairs
        assert!(
            zcr < 0.15,
            "Low-frequency sine should have low ZCR, got {zcr}"
        );
    }

    #[test]
    fn test_hysteresis() {
        let mut vad = VoiceActivityDetector::new();
        // Calibrate with silence
        for _ in 0..=VadConfig::default().calibration_frames {
            vad.detect(&[0i16; 160]);
        }

        // Trigger speech
        let speech: Vec<i16> = vec![5000i16; 160];
        vad.detect(&speech);
        assert!(vad.in_speech());

        // Wait out hangover
        for _ in 0..=VadConfig::default().hangover_frames {
            vad.detect(&[0i16; 160]);
        }
        assert!(!vad.in_speech());

        // Marginal energy: above silence threshold but below speech threshold
        // This tests that the higher threshold is needed to re-enter speech
        #[allow(clippy::cast_possible_truncation)]
        let marginal: Vec<i16> = vec![
            (MIN_ENERGY_THRESHOLD * VadConfig::default().silence_threshold_ratio * 1.1)
                as i16;
            160
        ];
        let result = vad.detect(&marginal);
        // Should still be silence because we need SPEECH_THRESHOLD_RATIO to enter speech
        assert_eq!(result, VadDecision::Silence);
    }

    #[test]
    fn test_empty_frame() {
        let mut vad = VoiceActivityDetector::new();
        assert_eq!(vad.detect(&[]), VadDecision::Silence);
    }
}
