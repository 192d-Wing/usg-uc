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
    /// Music on Hold file path (optional WAV file).
    ///
    /// When a call is placed on hold, this audio file will be played
    /// to the remote party instead of silence.
    #[serde(default)]
    pub moh_file_path: Option<String>,
    /// Ringtone file path (optional WAV file).
    ///
    /// When an incoming call arrives, this audio file will be played
    /// on the ring device. If not set, a default system beep is used.
    #[serde(default)]
    pub ringtone_file_path: Option<String>,
    /// DTMF volume level for RFC 4733 telephone-event packets (0-63).
    ///
    /// 0 is loudest (0 dBm0), 63 is quietest (-63 dBm0).
    /// Default is 10 (-10 dBm0), the de facto standard.
    #[serde(default = "default_dtmf_volume")]
    pub dtmf_volume: u8,
    /// Inter-digit pause between consecutive DTMF digits in milliseconds.
    ///
    /// Default is 100ms. Lower values allow faster IVR navigation,
    /// higher values improve compatibility with slow decoders.
    #[serde(default = "default_dtmf_inter_digit_pause_ms")]
    pub dtmf_inter_digit_pause_ms: u32,
}

/// Default DTMF volume (-10 dBm0).
const fn default_dtmf_volume() -> u8 {
    10
}

/// Default inter-digit pause (100ms).
const fn default_dtmf_inter_digit_pause_ms() -> u32 {
    100
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
            moh_file_path: None,
            ringtone_file_path: None,
            dtmf_volume: default_dtmf_volume(),
            dtmf_inter_digit_pause_ms: default_dtmf_inter_digit_pause_ms(),
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
        if self.dtmf_volume > 63 {
            return Err("DTMF volume must be 0-63".to_string());
        }
        if self.dtmf_inter_digit_pause_ms > 1000 {
            return Err("DTMF inter-digit pause cannot exceed 1000ms".to_string());
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
    /// Detected device category for audio processing profile selection.
    pub category: DeviceCategory,
    /// Number of channels supported.
    pub channels: u16,
    /// Sample rates supported.
    pub sample_rates: Vec<u32>,
}

/// Device category for automatic audio processing profile selection.
///
/// Detected from the device name to apply optimized VAD, AEC, AGC,
/// and noise gate settings for each device class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceCategory {
    /// Built-in speakers (MacBook, iMac).
    BuiltInSpeaker,
    /// Built-in microphone.
    BuiltInMic,
    /// USB headset (Jabra, Plantronics, Poly, generic USB audio).
    UsbHeadset,
    /// Bluetooth HFP/A2DP device.
    Bluetooth,
    /// Conference speakerphone.
    Speakerphone,
    /// Unknown or unrecognized device.
    #[default]
    Unknown,
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

/// Call quality metrics for the quality dashboard.
///
/// Combines RTP, jitter buffer, and audio stats into a single
/// view suitable for real-time UI display.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallQualityMetrics {
    /// RTP packets sent.
    pub packets_sent: u64,
    /// RTP packets received.
    pub packets_received: u64,
    /// RTP packets lost (detected by jitter buffer).
    pub packets_lost: u64,
    /// Packet loss rate (0.0 - 1.0).
    pub packet_loss_rate: f64,
    /// Average network jitter in milliseconds.
    pub jitter_ms: f32,
    /// Current jitter buffer depth in milliseconds.
    pub jitter_buffer_depth_ms: u32,
    /// Capture underruns (mic buffer empty).
    pub capture_underruns: u64,
    /// Playback underruns (speaker buffer empty).
    pub playback_underruns: u64,
    /// SRTP decryption errors.
    pub srtp_errors: u64,
    /// Estimated MOS score (1.0 - 5.0, higher = better).
    ///
    /// Calculated using simplified E-model (ITU-T G.107):
    /// - 4.0+: Excellent (toll quality)
    /// - 3.5-4.0: Good
    /// - 3.0-3.5: Fair
    /// - <3.0: Poor
    pub mos_score: f32,
    /// Round-trip time in milliseconds (from RTCP SR/RR exchange).
    /// `None` if not yet measured.
    pub rtt_ms: Option<f32>,
    /// Active codec name (e.g., "G.711 \u{03BC}-law", "G.722", "Opus").
    pub codec: String,
}

impl CallQualityMetrics {
    /// Creates metrics from raw audio pipeline statistics.
    #[allow(clippy::too_many_arguments)]
    pub fn from_stats(
        packets_sent: u64,
        packets_received: u64,
        packets_lost: u64,
        packet_loss_rate: f64,
        jitter_ms: f32,
        jitter_buffer_depth_ms: u32,
        capture_underruns: u64,
        playback_underruns: u64,
        srtp_errors: u64,
        rtt_ms: Option<f32>,
        codec: String,
    ) -> Self {
        let mos_score = Self::estimate_mos(packet_loss_rate, jitter_ms);
        Self {
            packets_sent,
            packets_received,
            packets_lost,
            packet_loss_rate,
            jitter_ms,
            jitter_buffer_depth_ms,
            capture_underruns,
            playback_underruns,
            srtp_errors,
            mos_score,
            rtt_ms,
            codec,
        }
    }

    /// Estimates MOS score from packet loss rate and jitter.
    ///
    /// Uses simplified E-model: R = 93.2 - `packet_loss_effect` - `jitter_effect`
    /// Then maps R to MOS via standard formula.
    #[allow(clippy::cast_possible_truncation)]
    fn estimate_mos(packet_loss_rate: f64, jitter_ms: f32) -> f32 {
        // Simplified E-model R-factor calculation
        // R = 93.2 (base) - Id (delay impairment) - Ie-eff (equipment impairment from loss)
        let loss_pct = packet_loss_rate * 100.0;

        // Equipment impairment factor for G.711 (from ITU-T G.113)
        // Ie-eff = Ie + (95 - Ie) * Ppl / (Ppl + Bpl)
        // For G.711: Ie=0, Bpl=25.1
        let ie_eff = 95.0 * loss_pct / (loss_pct + 25.1);

        // Delay impairment (jitter adds to effective delay)
        // Id increases with delay; assume 100ms base + jitter
        let effective_delay_ms = 100.0 + f64::from(jitter_ms);
        let id = if effective_delay_ms > 177.3 {
            0.024f64.mul_add(effective_delay_ms, 0.11 * (effective_delay_ms - 177.3))
        } else {
            0.024 * effective_delay_ms
        };

        let r = (93.2 - id - ie_eff).clamp(0.0, 100.0);

        // Convert R-factor to MOS (ITU-T G.107 Annex B)
        let mos = if r < 6.5 {
            1.0
        } else if r > 100.0 {
            4.5
        } else {
            (r * (r - 60.0) * (100.0 - r)).mul_add(7e-6, 0.035f64.mul_add(r, 1.0))
        };

        mos.clamp(1.0, 5.0) as f32
    }
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
