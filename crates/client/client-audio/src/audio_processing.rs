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

/// Configuration for the AGC (Automatic Gain Control).
#[derive(Debug, Clone)]
pub struct AgcConfig {
    /// Target RMS level in linear scale (approximately -18 dBFS).
    pub target_rms: f32,
    /// Maximum gain (12 dB = 4x). Prevents boosting background noise.
    pub max_gain: f32,
    /// Minimum gain (-6 dB = 0.5x). Prevents clipping on loud input.
    pub min_gain: f32,
    /// Attack coefficient: how quickly gain decreases (0.0-1.0, higher = faster).
    pub attack: f32,
    /// Release coefficient: how quickly gain increases (0.0-1.0, higher = faster).
    pub release: f32,
}

impl Default for AgcConfig {
    fn default() -> Self {
        Self {
            target_rms: 4096.0,
            max_gain: 4.0,
            min_gain: 0.5,
            attack: 0.3,
            release: 0.05,
        }
    }
}

/// Configuration for the noise gate.
#[derive(Debug, Clone)]
pub struct NoiseGateConfig {
    /// RMS threshold below which frames are gated. ~-50 dBFS.
    pub threshold: f32,
    /// Frames the gate stays open after speech stops (5 frames × 20ms = 100ms).
    pub hold_frames: u32,
    /// Fade-out length in samples when closing. Prevents clicks.
    pub fade_samples: usize,
}

impl Default for NoiseGateConfig {
    fn default() -> Self {
        Self {
            threshold: 100.0,
            hold_frames: 5,
            fade_samples: 80,
        }
    }
}

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
    /// AGC configuration.
    agc: AgcConfig,
    /// Noise gate configuration.
    gate: NoiseGateConfig,
}

impl Default for AudioProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl AudioProcessor {
    /// Creates a new audio processor with both AGC and noise gate enabled.
    pub fn new() -> Self {
        Self::with_config(AgcConfig::default(), NoiseGateConfig::default())
    }

    /// Creates an audio processor with custom configuration.
    pub fn with_config(agc: AgcConfig, gate: NoiseGateConfig) -> Self {
        Self {
            agc_enabled: true,
            noise_gate_enabled: true,
            current_gain: 1.0,
            gate_open: false,
            gate_hold_counter: 0,
            agc,
            gate,
        }
    }

    /// Resets all processing state (AGC gain, noise gate).
    ///
    /// Call this when switching input devices to prevent stale state
    /// (e.g., gain tuned for a quiet Bluetooth mic) from affecting the
    /// first frames from the new device.
    pub const fn reset(&mut self) {
        self.current_gain = 1.0;
        self.gate_open = false;
        self.gate_hold_counter = 0;
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
        if rms > self.gate.threshold {
            // Signal above threshold → open gate
            self.gate_open = true;
            self.gate_hold_counter = self.gate.hold_frames;
        } else if self.gate_hold_counter > 0 {
            // In hold period → keep gate open
            self.gate_hold_counter -= 1;
        } else if self.gate_open {
            // Hold period expired → close gate with fade-out
            self.gate_open = false;
            let fade_len = self.gate.fade_samples.min(pcm.len());
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
        if rms < self.gate.threshold * 2.0 {
            return;
        }

        // Compute desired gain to reach target RMS
        let desired_gain = (self.agc.target_rms / rms).clamp(self.agc.min_gain, self.agc.max_gain);

        // Smooth the gain transition (attack/release)
        let alpha = if desired_gain < self.current_gain {
            self.agc.attack // Reducing gain (loud signal) → fast
        } else {
            self.agc.release // Increasing gain (quiet signal) → slow
        };

        self.current_gain += (desired_gain - self.current_gain) * alpha;
        self.current_gain = self.current_gain.clamp(self.agc.min_gain, self.agc.max_gain);

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
        let cfg = AgcConfig::default();
        // Initial gain should be within bounds
        assert!(proc.current_gain() >= cfg.min_gain);
        assert!(proc.current_gain() <= cfg.max_gain);
    }

    #[test]
    fn test_noise_gate_hold() {
        let mut proc = AudioProcessor::new();
        proc.set_agc_enabled(false); // Isolate gate behavior
        let hold_frames = proc.gate.hold_frames;

        // First: open the gate with a loud frame
        let mut loud = vec![5000i16; 160];
        proc.process(&mut loud);
        assert!(proc.gate_open);

        // Then: send quiet frames — gate should hold open for HOLD_FRAMES
        for i in 0..hold_frames {
            let mut quiet = vec![1i16; 160];
            proc.process(&mut quiet);
            assert!(
                proc.gate_open || i == hold_frames - 1,
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
