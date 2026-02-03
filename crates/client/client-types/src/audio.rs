//! Audio configuration types.

use serde::{Deserialize, Serialize};

/// Audio configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioConfig {
    /// Input (microphone) device name, or None for default.
    pub input_device: Option<String>,
    /// Output (speaker) device name, or None for default.
    pub output_device: Option<String>,
    /// Ring device name, or None to use output device.
    pub ring_device: Option<String>,
    /// Input volume (0.0 - 1.0).
    pub input_volume: f32,
    /// Output volume (0.0 - 1.0).
    pub output_volume: f32,
    /// Ring volume (0.0 - 1.0).
    pub ring_volume: f32,
    /// Whether echo cancellation is enabled.
    pub echo_cancellation: bool,
    /// Whether noise suppression is enabled.
    pub noise_suppression: bool,
    /// Preferred codec for outgoing calls.
    pub preferred_codec: CodecPreference,
    /// Jitter buffer minimum depth in milliseconds.
    pub jitter_buffer_min_ms: u32,
    /// Jitter buffer maximum depth in milliseconds.
    pub jitter_buffer_max_ms: u32,
}

impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            input_device: None,
            output_device: None,
            ring_device: None,
            input_volume: 1.0,
            output_volume: 1.0,
            ring_volume: 1.0,
            echo_cancellation: true,
            noise_suppression: true,
            preferred_codec: CodecPreference::Opus,
            jitter_buffer_min_ms: 20,
            jitter_buffer_max_ms: 200,
        }
    }
}

impl AudioConfig {
    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.input_volume) {
            return Err("Input volume must be between 0.0 and 1.0".to_string());
        }
        if !(0.0..=1.0).contains(&self.output_volume) {
            return Err("Output volume must be between 0.0 and 1.0".to_string());
        }
        if !(0.0..=1.0).contains(&self.ring_volume) {
            return Err("Ring volume must be between 0.0 and 1.0".to_string());
        }
        if self.jitter_buffer_min_ms > self.jitter_buffer_max_ms {
            return Err("Jitter buffer min cannot exceed max".to_string());
        }
        if self.jitter_buffer_max_ms > 500 {
            return Err("Jitter buffer max cannot exceed 500ms".to_string());
        }
        Ok(())
    }
}

/// Preferred codec for calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CodecPreference {
    /// Opus (best quality, modern).
    #[default]
    Opus,
    /// G.722 (wideband, good compatibility).
    G722,
    /// G.711 mu-law (narrowband, maximum compatibility).
    G711Ulaw,
    /// G.711 a-law (narrowband, Europe/International).
    G711Alaw,
}

impl std::fmt::Display for CodecPreference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Opus => write!(f, "Opus (48 kHz)"),
            Self::G722 => write!(f, "G.722 (16 kHz)"),
            Self::G711Ulaw => write!(f, "G.711 \u{03bc}-law (8 kHz)"),
            Self::G711Alaw => write!(f, "G.711 A-law (8 kHz)"),
        }
    }
}

/// Audio device information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioDevice {
    /// Device name/identifier.
    pub name: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Whether this is the system default device.
    pub is_default: bool,
    /// Device type.
    pub device_type: AudioDeviceType,
    /// Number of channels supported.
    pub channels: u16,
    /// Sample rates supported.
    pub sample_rates: Vec<u32>,
}

/// Audio device type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioDeviceType {
    /// Input (microphone).
    Input,
    /// Output (speaker/headphone).
    Output,
}

impl std::fmt::Display for AudioDeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input => write!(f, "Input"),
            Self::Output => write!(f, "Output"),
        }
    }
}

/// Audio statistics for monitoring.
#[derive(Debug, Clone, Default)]
pub struct AudioStatistics {
    /// Number of samples captured from microphone.
    pub samples_captured: u64,
    /// Number of samples played to speaker.
    pub samples_played: u64,
    /// Number of RTP packets sent.
    pub rtp_packets_sent: u64,
    /// Number of RTP packets received.
    pub rtp_packets_received: u64,
    /// Number of packets lost.
    pub packets_lost: u64,
    /// Current jitter in milliseconds.
    pub jitter_ms: f64,
    /// Current jitter buffer depth in milliseconds.
    pub jitter_buffer_depth_ms: u32,
    /// Packets dropped due to late arrival.
    pub packets_late: u64,
    /// Frames interpolated due to packet loss.
    pub frames_interpolated: u64,
    /// SRTP decryption errors.
    pub srtp_errors: u64,
    /// Current codec name.
    pub current_codec: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_config_default() {
        let config = AudioConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_audio_config_invalid_volume() {
        let mut config = AudioConfig::default();
        config.input_volume = 1.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_audio_config_invalid_jitter_buffer() {
        let mut config = AudioConfig::default();
        config.jitter_buffer_min_ms = 100;
        config.jitter_buffer_max_ms = 50;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_codec_preference_display() {
        assert!(CodecPreference::Opus.to_string().contains("Opus"));
        assert!(CodecPreference::G722.to_string().contains("G.722"));
    }
}
