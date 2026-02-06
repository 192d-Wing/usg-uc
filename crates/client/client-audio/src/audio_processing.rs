//! Audio processing pipeline for capture audio.
//!
//! Provides Automatic Gain Control (AGC) and a noise gate, applied
//! to microphone audio before encoding. All processing is pure Rust
//! with no external dependencies, and works at any sample rate.
//!
//! ## Processing Chain
//!
//! ```text
//! Microphone → [Noise Gate] → [AGC] → Encoder
//! ```

/// Target RMS level in linear scale (approximately -18 dBFS).
/// This is a comfortable speech level for `VoIP`.
const AGC_TARGET_RMS: f32 = 4096.0;

/// Maximum gain the AGC will apply (12 dB = 4x).
/// Prevents boosting background noise excessively.
const AGC_MAX_GAIN: f32 = 4.0;

/// Minimum gain (prevents clipping on loud input, -6 dB = 0.5x).
const AGC_MIN_GAIN: f32 = 0.5;

/// AGC attack time constant: how quickly gain decreases when signal
/// is too loud. Faster attack prevents clipping. Expressed as a
/// smoothing factor per frame (0.0-1.0, higher = faster).
const AGC_ATTACK: f32 = 0.3;

/// AGC release time constant: how quickly gain increases when signal
/// is too quiet. Slower release sounds more natural.
const AGC_RELEASE: f32 = 0.05;

/// Noise gate threshold (RMS). Frames below this are considered
/// silence/noise and are zeroed. ~-50 dBFS.
const NOISE_GATE_THRESHOLD: f32 = 100.0;

/// Number of frames the gate stays open after speech stops.
/// Prevents cutting off word tails (5 frames × 20ms = 100ms hold).
const NOISE_GATE_HOLD_FRAMES: u32 = 5;

/// Noise gate fade-out length in samples when closing.
/// Prevents clicks from abrupt silence transitions.
const NOISE_GATE_FADE_SAMPLES: usize = 80;

/// Audio processing pipeline for the capture path.
#[derive(Debug)]
pub struct AudioProcessor {
    /// Whether AGC is enabled.
    agc_enabled: bool,
    /// Whether noise gate is enabled.
    noise_gate_enabled: bool,
    /// Current smoothed gain value.
    current_gain: f32,
    /// Noise gate state.
    gate_open: bool,
    /// Frames remaining in gate hold period.
    gate_hold_counter: u32,
}

impl Default for AudioProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl AudioProcessor {
    /// Creates a new audio processor with both AGC and noise gate enabled.
    pub const fn new() -> Self {
        Self {
            agc_enabled: true,
            noise_gate_enabled: true,
            current_gain: 1.0,
            gate_open: false,
            gate_hold_counter: 0,
        }
    }

    /// Enables or disables the AGC.
    pub const fn set_agc_enabled(&mut self, enabled: bool) {
        self.agc_enabled = enabled;
        if !enabled {
            self.current_gain = 1.0;
        }
    }

    /// Enables or disables the noise gate.
    pub const fn set_noise_gate_enabled(&mut self, enabled: bool) {
        self.noise_gate_enabled = enabled;
        if !enabled {
            self.gate_open = true;
            self.gate_hold_counter = 0;
        }
    }

    /// Returns whether AGC is enabled.
    pub const fn agc_enabled(&self) -> bool {
        self.agc_enabled
    }

    /// Returns whether noise gate is enabled.
    pub const fn noise_gate_enabled(&self) -> bool {
        self.noise_gate_enabled
    }

    /// Returns the current AGC gain value.
    pub const fn current_gain(&self) -> f32 {
        self.current_gain
    }

    /// Processes a frame of captured audio in-place.
    ///
    /// Applies noise gate first, then AGC.
    pub fn process(&mut self, pcm: &mut [i16]) {
        if pcm.is_empty() {
            return;
        }

        let rms = compute_rms(pcm);

        // 1. Noise gate
        if self.noise_gate_enabled {
            self.apply_noise_gate(pcm, rms);
        }

        // 2. AGC (only if gate is open — no point boosting gated silence)
        if self.agc_enabled && self.gate_open {
            self.apply_agc(pcm, rms);
        }
    }

    /// Applies the noise gate to a frame.
    fn apply_noise_gate(&mut self, pcm: &mut [i16], rms: f32) {
        if rms > NOISE_GATE_THRESHOLD {
            // Signal above threshold → open gate
            self.gate_open = true;
            self.gate_hold_counter = NOISE_GATE_HOLD_FRAMES;
        } else if self.gate_hold_counter > 0 {
            // In hold period → keep gate open
            self.gate_hold_counter -= 1;
        } else if self.gate_open {
            // Hold period expired → close gate with fade-out
            self.gate_open = false;
            let fade_len = NOISE_GATE_FADE_SAMPLES.min(pcm.len());
            #[allow(clippy::cast_precision_loss)]
            for (i, sample) in pcm.iter_mut().enumerate() {
                if i < fade_len {
                    let t = 1.0 - (i as f32 / fade_len as f32);
                    *sample = apply_gain(*sample, t);
                } else {
                    *sample = 0;
                }
            }
            return;
        }

        if !self.gate_open {
            // Gate is closed → zero the frame
            pcm.fill(0);
        }
    }

    /// Applies automatic gain control to a frame.
    fn apply_agc(&mut self, pcm: &mut [i16], rms: f32) {
        // Don't adjust on very quiet frames (noise floor)
        if rms < NOISE_GATE_THRESHOLD * 2.0 {
            return;
        }

        // Compute desired gain to reach target RMS
        let desired_gain = (AGC_TARGET_RMS / rms).clamp(AGC_MIN_GAIN, AGC_MAX_GAIN);

        // Smooth the gain transition (attack/release)
        let alpha = if desired_gain < self.current_gain {
            AGC_ATTACK // Reducing gain (loud signal) → fast
        } else {
            AGC_RELEASE // Increasing gain (quiet signal) → slow
        };

        self.current_gain += (desired_gain - self.current_gain) * alpha;
        self.current_gain = self.current_gain.clamp(AGC_MIN_GAIN, AGC_MAX_GAIN);

        // Apply gain to all samples
        for sample in pcm.iter_mut() {
            *sample = apply_gain(*sample, self.current_gain);
        }
    }
}

/// Computes the RMS (Root Mean Square) of a PCM buffer.
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

/// Applies a gain factor to a sample with clamping.
#[allow(clippy::cast_possible_truncation)]
fn apply_gain(sample: i16, gain: f32) -> i16 {
    let amplified = f32::from(sample) * gain;
    amplified.clamp(f32::from(i16::MIN), f32::from(i16::MAX)) as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_processor() {
        let proc = AudioProcessor::new();
        assert!(proc.agc_enabled());
        assert!(proc.noise_gate_enabled());
        assert!((proc.current_gain() - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_silence_is_gated() {
        let mut proc = AudioProcessor::new();
        let mut frame = vec![0i16; 160];
        proc.process(&mut frame);
        assert!(frame.iter().all(|&s| s == 0), "Silence should stay zero");
    }

    #[test]
    fn test_loud_signal_not_gated() {
        let mut proc = AudioProcessor::new();
        // Create a signal well above the noise gate threshold
        let mut frame: Vec<i16> = (0..160).map(|i| ((i % 20) * 1000) as i16).collect();
        let original_energy: f64 = frame.iter().map(|&s| f64::from(s) * f64::from(s)).sum();

        proc.process(&mut frame);

        let processed_energy: f64 = frame.iter().map(|&s| f64::from(s) * f64::from(s)).sum();
        assert!(
            processed_energy > 0.0,
            "Loud signal should not be gated to zero"
        );
        // AGC may change energy, but signal should still be present
        assert!(
            processed_energy > original_energy * 0.01,
            "Signal should retain significant energy"
        );
    }

    #[test]
    fn test_agc_boosts_quiet_signal() {
        let mut proc = AudioProcessor::new();
        proc.set_noise_gate_enabled(false); // Disable gate for this test

        // Create a quiet signal (RMS well below target)
        let mut frame = vec![200i16; 160];

        // Process several frames so AGC converges
        for _ in 0..50 {
            frame = vec![200i16; 160];
            proc.process(&mut frame);
        }

        // Gain should have increased above 1.0
        assert!(
            proc.current_gain() > 1.0,
            "AGC should boost quiet signal, gain={}",
            proc.current_gain()
        );
    }

    #[test]
    fn test_agc_reduces_loud_signal() {
        let mut proc = AudioProcessor::new();
        proc.set_noise_gate_enabled(false);

        // Create a loud signal (RMS well above target)
        let mut frame = vec![20000i16; 160];

        for _ in 0..20 {
            frame = vec![20000i16; 160];
            proc.process(&mut frame);
        }

        // Gain should have decreased below 1.0
        assert!(
            proc.current_gain() < 1.0,
            "AGC should reduce loud signal, gain={}",
            proc.current_gain()
        );
    }

    #[test]
    fn test_agc_gain_clamped() {
        let proc = AudioProcessor::new();
        // Initial gain should be within bounds
        assert!(proc.current_gain() >= AGC_MIN_GAIN);
        assert!(proc.current_gain() <= AGC_MAX_GAIN);
    }

    #[test]
    fn test_noise_gate_hold() {
        let mut proc = AudioProcessor::new();
        proc.set_agc_enabled(false); // Isolate gate behavior

        // First: open the gate with a loud frame
        let mut loud = vec![5000i16; 160];
        proc.process(&mut loud);
        assert!(proc.gate_open);

        // Then: send quiet frames — gate should hold open for HOLD_FRAMES
        for i in 0..NOISE_GATE_HOLD_FRAMES {
            let mut quiet = vec![1i16; 160];
            proc.process(&mut quiet);
            assert!(
                proc.gate_open || i == NOISE_GATE_HOLD_FRAMES - 1,
                "Gate should hold open at frame {i}"
            );
        }
    }

    #[test]
    fn test_disable_agc() {
        let mut proc = AudioProcessor::new();
        proc.set_agc_enabled(false);
        assert!(!proc.agc_enabled());
        assert!((proc.current_gain() - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_disable_noise_gate() {
        let mut proc = AudioProcessor::new();
        proc.set_noise_gate_enabled(false);
        assert!(!proc.noise_gate_enabled());
    }

    #[test]
    fn test_compute_rms() {
        let silence = vec![0i16; 160];
        assert!((compute_rms(&silence) - 0.0).abs() < f32::EPSILON);

        let loud = vec![10000i16; 160];
        let rms = compute_rms(&loud);
        assert!(
            (rms - 10000.0).abs() < 1.0,
            "RMS of constant 10000 should be ~10000, got {rms}"
        );
    }

    #[test]
    fn test_apply_gain_clamping() {
        // Should clamp to i16 range
        assert_eq!(apply_gain(i16::MAX, 2.0), i16::MAX);
        assert_eq!(apply_gain(i16::MIN, 2.0), i16::MIN);

        // Unity gain
        assert_eq!(apply_gain(1000, 1.0), 1000);

        // Zero gain
        assert_eq!(apply_gain(1000, 0.0), 0);
    }
}
