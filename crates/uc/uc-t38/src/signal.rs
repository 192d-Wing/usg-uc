//! T.30 fax signal handling.
//!
//! Implements detection and processing of T.30 fax signals for
//! audio-to-T.38 gateway functionality.

use serde::{Deserialize, Serialize};

/// T.30 fax signal types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum T30Signal {
    /// Calling Tone (CNG) - 1100 Hz, 0.5s on/3s off.
    Cng,
    /// Called Station Identification (CED) - 2100 Hz.
    Ced,
    /// V.21 preamble flags.
    V21Preamble,
    /// Digital Identification Signal (DIS).
    Dis,
    /// Digital Command Signal (DCS).
    Dcs,
    /// Confirmation to Receive (CFR).
    Cfr,
    /// Training Check Frame (TCF).
    Tcf,
    /// End of Message (EOM).
    Eom,
    /// Multi-page Signal (MPS).
    Mps,
    /// End of Procedure (EOP).
    Eop,
    /// Message Confirmation (MCF).
    Mcf,
    /// Disconnect (DCN).
    Dcn,
    /// Non-Standard Facilities (NSF).
    Nsf,
    /// Non-Standard Setup (NSS).
    Nss,
    /// Failure to Train (FTT).
    Ftt,
    /// Retrain Negative (RTN).
    Rtn,
    /// Retrain Positive (RTP).
    Rtp,
    /// V.8 Call Menu Signal (CM).
    Cm,
    /// V.8 Joint Menu Signal (JM).
    Jm,
    /// V.34 Control Channel.
    V34Cc,
    /// V.34 Primary Channel.
    V34Primary,
    /// Unknown signal.
    Unknown,
}

impl T30Signal {
    /// Returns the signal name as defined in T.30.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Cng => "CNG",
            Self::Ced => "CED",
            Self::V21Preamble => "V.21 Preamble",
            Self::Dis => "DIS",
            Self::Dcs => "DCS",
            Self::Cfr => "CFR",
            Self::Tcf => "TCF",
            Self::Eom => "EOM",
            Self::Mps => "MPS",
            Self::Eop => "EOP",
            Self::Mcf => "MCF",
            Self::Dcn => "DCN",
            Self::Nsf => "NSF",
            Self::Nss => "NSS",
            Self::Ftt => "FTT",
            Self::Rtn => "RTN",
            Self::Rtp => "RTP",
            Self::Cm => "CM",
            Self::Jm => "JM",
            Self::V34Cc => "V.34 CC",
            Self::V34Primary => "V.34 Primary",
            Self::Unknown => "Unknown",
        }
    }

    /// Returns true if this is a call establishment signal.
    #[must_use]
    pub const fn is_call_establishment(&self) -> bool {
        matches!(self, Self::Cng | Self::Ced | Self::V21Preamble | Self::Cm | Self::Jm)
    }

    /// Returns true if this is a negotiation signal.
    #[must_use]
    pub const fn is_negotiation(&self) -> bool {
        matches!(
            self,
            Self::Dis | Self::Dcs | Self::Nsf | Self::Nss | Self::Cfr | Self::Ftt
        )
    }

    /// Returns true if this is an end-of-page signal.
    #[must_use]
    pub const fn is_end_of_page(&self) -> bool {
        matches!(self, Self::Eom | Self::Mps | Self::Eop)
    }

    /// Returns true if this is a confirmation signal.
    #[must_use]
    pub const fn is_confirmation(&self) -> bool {
        matches!(self, Self::Mcf | Self::Rtp | Self::Rtn)
    }

    /// Returns true if this is a disconnect signal.
    #[must_use]
    pub const fn is_disconnect(&self) -> bool {
        matches!(self, Self::Dcn)
    }
}

impl std::fmt::Display for T30Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Fax transmission phase per T.30.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaxPhase {
    /// Phase A: Call establishment.
    PhaseA,
    /// Phase B: Pre-message procedure (negotiation).
    PhaseB,
    /// Phase C: In-message procedure (image transfer).
    PhaseC,
    /// Phase D: Post-message procedure.
    PhaseD,
    /// Phase E: Call release.
    PhaseE,
}

impl FaxPhase {
    /// Returns the phase name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::PhaseA => "Phase A (Call Establishment)",
            Self::PhaseB => "Phase B (Pre-Message)",
            Self::PhaseC => "Phase C (Image Transfer)",
            Self::PhaseD => "Phase D (Post-Message)",
            Self::PhaseE => "Phase E (Call Release)",
        }
    }
}

impl std::fmt::Display for FaxPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Fax signal detector for audio streams.
#[derive(Debug)]
pub struct SignalDetector {
    /// Current detection state.
    state: DetectorState,
    /// Detected signal.
    detected_signal: Option<T30Signal>,
    /// Sample rate.
    sample_rate: u32,
    /// Samples accumulated.
    samples: Vec<i16>,
}

/// Internal detector state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum DetectorState {
    /// Idle, waiting for signal.
    Idle,
    /// Detecting CNG (1100 Hz).
    DetectingCng,
    /// Detecting CED (2100 Hz).
    DetectingCed,
    /// Signal confirmed.
    Confirmed,
}

impl SignalDetector {
    /// Creates a new signal detector.
    #[must_use]
    pub fn new(sample_rate: u32) -> Self {
        Self {
            state: DetectorState::Idle,
            detected_signal: None,
            sample_rate,
            samples: Vec::with_capacity(sample_rate as usize / 4), // 250ms buffer
        }
    }

    /// Processes audio samples and returns detected signal if any.
    pub fn process(&mut self, samples: &[i16]) -> Option<T30Signal> {
        self.samples.extend_from_slice(samples);

        // Need at least 100ms of samples for detection
        let min_samples = self.sample_rate as usize / 10;
        if self.samples.len() < min_samples {
            return None;
        }

        // Simple energy-based tone detection (placeholder)
        // Real implementation would use Goertzel algorithm for precise frequency detection
        let signal = self.detect_tone();

        if let Some(sig) = signal {
            self.detected_signal = Some(sig);
            self.state = DetectorState::Confirmed;
            self.samples.clear();
            return Some(sig);
        }

        // Trim buffer if too large
        if self.samples.len() > self.sample_rate as usize {
            self.samples.drain(0..self.sample_rate as usize / 2);
        }

        None
    }

    /// Detects tone frequency using simplified algorithm.
    fn detect_tone(&self) -> Option<T30Signal> {
        if self.samples.is_empty() {
            return None;
        }

        // Calculate energy
        let energy: i64 = self
            .samples
            .iter()
            .map(|&s| (s as i64) * (s as i64))
            .sum();
        let avg_energy = energy / self.samples.len() as i64;

        // If energy is too low, no signal
        if avg_energy < 100 {
            return None;
        }

        // Use Goertzel algorithm for 1100 Hz (CNG) and 2100 Hz (CED)
        let cng_magnitude = self.goertzel(1100.0);
        let ced_magnitude = self.goertzel(2100.0);

        // Threshold for detection (relative to energy)
        let threshold = (avg_energy as f64).sqrt() * 0.5;

        if cng_magnitude > threshold && cng_magnitude > ced_magnitude {
            return Some(T30Signal::Cng);
        }

        if ced_magnitude > threshold && ced_magnitude > cng_magnitude {
            return Some(T30Signal::Ced);
        }

        None
    }

    /// Goertzel algorithm for single frequency detection.
    fn goertzel(&self, target_freq: f64) -> f64 {
        let n = self.samples.len();
        let k = (target_freq * n as f64 / self.sample_rate as f64).round() as usize;
        let w = 2.0 * std::f64::consts::PI * k as f64 / n as f64;
        let coeff = 2.0 * w.cos();

        let mut s0 = 0.0;
        let mut s1 = 0.0;
        let mut s2;

        for &sample in &self.samples {
            s2 = s1;
            s1 = s0;
            s0 = f64::from(sample) + coeff * s1 - s2;
        }

        // Magnitude squared
        let power = s0 * s0 + s1 * s1 - coeff * s0 * s1;
        power.sqrt()
    }

    /// Resets the detector state.
    pub fn reset(&mut self) {
        self.state = DetectorState::Idle;
        self.detected_signal = None;
        self.samples.clear();
    }

    /// Returns the last detected signal.
    #[must_use]
    pub fn detected_signal(&self) -> Option<T30Signal> {
        self.detected_signal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_t30_signal_name() {
        assert_eq!(T30Signal::Cng.name(), "CNG");
        assert_eq!(T30Signal::Ced.name(), "CED");
        assert_eq!(T30Signal::Dcn.name(), "DCN");
    }

    #[test]
    fn test_signal_classification() {
        assert!(T30Signal::Cng.is_call_establishment());
        assert!(T30Signal::Ced.is_call_establishment());
        assert!(T30Signal::Dis.is_negotiation());
        assert!(T30Signal::Dcs.is_negotiation());
        assert!(T30Signal::Eop.is_end_of_page());
        assert!(T30Signal::Mcf.is_confirmation());
        assert!(T30Signal::Dcn.is_disconnect());
    }

    #[test]
    fn test_fax_phase() {
        assert_eq!(FaxPhase::PhaseA.name(), "Phase A (Call Establishment)");
        assert_eq!(FaxPhase::PhaseC.name(), "Phase C (Image Transfer)");
    }

    #[test]
    fn test_signal_detector_creation() {
        let detector = SignalDetector::new(8000);
        assert!(detector.detected_signal().is_none());
    }

    #[test]
    fn test_signal_detector_reset() {
        let mut detector = SignalDetector::new(8000);
        detector.reset();
        assert!(detector.detected_signal().is_none());
    }

    #[test]
    fn test_signal_display() {
        assert_eq!(T30Signal::Cng.to_string(), "CNG");
        assert_eq!(FaxPhase::PhaseA.to_string(), "Phase A (Call Establishment)");
    }
}
