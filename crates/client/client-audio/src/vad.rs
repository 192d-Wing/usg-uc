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

/// Ratio above noise floor for speech detection.
/// A frame is classified as speech if its energy exceeds
/// `noise_floor * SPEECH_THRESHOLD_RATIO`.
/// 2.5 is tuned for Bluetooth HFP capture which has higher
/// background noise than wired microphones.
const SPEECH_THRESHOLD_RATIO: f32 = 2.5;

/// Ratio for returning to silence (lower than speech threshold
/// for hysteresis, avoiding rapid toggling).
const SILENCE_THRESHOLD_RATIO: f32 = 2.0;

/// Zero-crossing rate threshold (normalized to 0.0-1.0).
/// Speech typically has ZCR < 0.3, unvoiced noise is > 0.5.
/// Frames with very high ZCR and marginal energy are likely noise.
const ZCR_NOISE_THRESHOLD: f32 = 0.5;

/// Number of frames to hold speech state after energy drops.
/// Prevents cutting off word endings and inter-word pauses.
/// 25 frames at 20ms = 500ms hold time. Longer hold avoids
/// mid-sentence gaps that the remote side hears as breaks.
const HANGOVER_FRAMES: u32 = 25;

/// Smoothing factor for noise floor adaptation (slow, during silence).
/// Higher = faster adaptation. 0.02 → ~1 second time constant at 50 fps.
const NOISE_FLOOR_ADAPT_RATE: f32 = 0.02;

/// Maximum noise floor (prevents runaway adaptation in noisy environments).
/// Approximately -30 dBFS.
const MAX_NOISE_FLOOR: f32 = 1000.0;

/// Number of initial frames to skip for noise floor calibration.
/// Avoids speech in the first second from contaminating the estimate.
const CALIBRATION_FRAMES: u32 = 25;

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
}

impl Default for VoiceActivityDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl VoiceActivityDetector {
    /// Creates a new VAD with default settings.
    pub const fn new() -> Self {
        Self {
            in_speech: false,
            hangover_counter: 0,
            noise_floor: MIN_ENERGY_THRESHOLD,
            frame_count: 0,
            calibrated: false,
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

        let energy = compute_rms(pcm);
        let zcr = compute_zcr(pcm);

        self.frame_count = self.frame_count.saturating_add(1);

        // Initial calibration: assume first N frames are background noise
        if !self.calibrated {
            if self.frame_count <= CALIBRATION_FRAMES {
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
            (self.noise_floor * SILENCE_THRESHOLD_RATIO).max(MIN_ENERGY_THRESHOLD)
        } else {
            (self.noise_floor * SPEECH_THRESHOLD_RATIO).max(MIN_ENERGY_THRESHOLD)
        };

        // High ZCR with marginal energy → likely unvoiced noise, not speech
        let is_likely_noise = zcr > ZCR_NOISE_THRESHOLD && energy < threshold * 1.5;

        let is_speech = energy > threshold && !is_likely_noise;

        if is_speech {
            self.in_speech = true;
            self.hangover_counter = HANGOVER_FRAMES;
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
        if energy < self.noise_floor * SPEECH_THRESHOLD_RATIO {
            self.noise_floor += (energy - self.noise_floor) * NOISE_FLOOR_ADAPT_RATE;
            self.noise_floor = self
                .noise_floor
                .clamp(MIN_ENERGY_THRESHOLD, MAX_NOISE_FLOOR);
        }
    }
}

/// Computes the RMS (Root Mean Square) energy of a PCM buffer.
#[allow(clippy::cast_precision_loss)]
fn compute_rms(pcm: &[i16]) -> f32 {
    if pcm.is_empty() {
        return 0.0;
    }
    let sum_sq: f64 = pcm.iter().map(|&s| f64::from(s) * f64::from(s)).sum();
    #[allow(clippy::cast_possible_truncation)]
    let rms = (sum_sq / pcm.len() as f64).sqrt() as f32;
    rms
}

/// Computes the zero-crossing rate of a PCM buffer.
///
/// Returns a value in 0.0..1.0 where 0.0 means no zero crossings
/// and 1.0 means every consecutive pair crosses zero.
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
        for _ in 0..CALIBRATION_FRAMES + 1 {
            vad.detect(&[0i16; 160]);
        }
        let result = vad.detect(&[0i16; 160]);
        assert_eq!(result, VadDecision::Silence);
    }

    #[test]
    fn test_speech_detected() {
        let mut vad = VoiceActivityDetector::new();
        // Calibrate with silence
        for _ in 0..CALIBRATION_FRAMES + 1 {
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
        for _ in 0..CALIBRATION_FRAMES + 1 {
            vad.detect(&[0i16; 160]);
        }

        // Speech frame
        let speech: Vec<i16> = vec![5000i16; 160];
        vad.detect(&speech);
        assert!(vad.in_speech());

        // First few silence frames should still be "speech" (hangover)
        for i in 0..HANGOVER_FRAMES {
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
        for _ in 0..CALIBRATION_FRAMES + 1 {
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
        for _ in 0..CALIBRATION_FRAMES + 1 {
            vad.detect(&[0i16; 160]);
        }

        // Trigger speech
        let speech: Vec<i16> = vec![5000i16; 160];
        vad.detect(&speech);
        assert!(vad.in_speech());

        // Wait out hangover
        for _ in 0..HANGOVER_FRAMES + 1 {
            vad.detect(&[0i16; 160]);
        }
        assert!(!vad.in_speech());

        // Marginal energy: above silence threshold but below speech threshold
        // This tests that the higher threshold is needed to re-enter speech
        let marginal: Vec<i16> =
            vec![(MIN_ENERGY_THRESHOLD * SILENCE_THRESHOLD_RATIO * 1.1) as i16; 160];
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
