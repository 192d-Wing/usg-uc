//! Opus codec (RFC 6716).
//!
//! Opus is a highly versatile audio codec supporting both speech and music
//! at a wide range of bitrates.
//!
//! ## Note
//!
//! This module provides a codec stub with configuration types.
//! Full Opus implementation requires FFI bindings to libopus
//! (documented exception to pure-Rust policy for codec quality).

use crate::error::{CodecError, CodecResult};
use crate::{AudioCodec, PayloadType};

/// Opus application mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpusApplication {
    /// Voice-over-IP application (speech coding).
    #[default]
    Voip,
    /// Audio application (music).
    Audio,
    /// Low-delay application.
    LowDelay,
}

/// Opus signal type hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpusSignal {
    /// Auto-detect signal type.
    #[default]
    Auto,
    /// Voice signal.
    Voice,
    /// Music signal.
    Music,
}

/// Opus bandwidth mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpusBandwidth {
    /// Narrowband (4 kHz).
    Narrowband,
    /// Mediumband (6 kHz).
    Mediumband,
    /// Wideband (8 kHz).
    Wideband,
    /// Superwideband (12 kHz).
    SuperWideband,
    /// Fullband (20 kHz).
    Fullband,
}

impl OpusBandwidth {
    /// Returns the maximum audio frequency.
    pub fn max_frequency(&self) -> u32 {
        match self {
            Self::Narrowband => 4000,
            Self::Mediumband => 6000,
            Self::Wideband => 8000,
            Self::SuperWideband => 12000,
            Self::Fullband => 20000,
        }
    }
}

/// Opus codec configuration.
#[derive(Debug, Clone)]
pub struct OpusConfig {
    /// Sample rate (8000, 12000, 16000, 24000, or 48000 Hz).
    pub sample_rate: u32,
    /// Number of channels (1 or 2).
    pub channels: u8,
    /// Bitrate in bits per second.
    pub bitrate: u32,
    /// Application mode.
    pub application: OpusApplication,
    /// Signal type hint.
    pub signal: OpusSignal,
    /// Enable in-band FEC.
    pub fec: bool,
    /// Enable DTX (discontinuous transmission).
    pub dtx: bool,
    /// Enable VBR (variable bitrate). Default: true.
    pub vbr: bool,
    /// Enable constrained VBR (limits bitrate variation). Default: true.
    pub vbr_constraint: bool,
    /// Frame duration in milliseconds (2.5, 5, 10, 20, 40, 60).
    pub frame_duration_ms: f32,
    /// Complexity (0-10).
    pub complexity: u8,
    /// Packet loss percentage hint (0-100).
    pub packet_loss_perc: u8,
}

impl Default for OpusConfig {
    fn default() -> Self {
        Self {
            sample_rate: 48000,
            channels: 2,
            bitrate: 64000,
            application: OpusApplication::Voip,
            signal: OpusSignal::Auto,
            fec: true,
            dtx: false,
            vbr: true,
            vbr_constraint: true,
            frame_duration_ms: 20.0,
            complexity: 9,
            packet_loss_perc: 0,
        }
    }
}

impl OpusConfig {
    /// Creates a VoIP-optimized configuration.
    ///
    /// Optimized for speech: mono, 32kbps VBR, DTX for silence, FEC for loss recovery.
    pub fn voip() -> Self {
        Self {
            sample_rate: 48000,
            channels: 1,
            bitrate: 32000,
            application: OpusApplication::Voip,
            signal: OpusSignal::Voice,
            fec: true,
            dtx: true,
            vbr: true,
            vbr_constraint: true,
            frame_duration_ms: 20.0,
            complexity: 9,
            packet_loss_perc: 10,
        }
    }

    /// Creates an audio/music-optimized configuration.
    ///
    /// Optimized for music: stereo, 96kbps CBR, no DTX, high complexity.
    pub fn audio() -> Self {
        Self {
            sample_rate: 48000,
            channels: 2,
            bitrate: 96000,
            application: OpusApplication::Audio,
            signal: OpusSignal::Music,
            fec: false,
            dtx: false,
            vbr: false,
            vbr_constraint: false,
            frame_duration_ms: 20.0,
            complexity: 10,
            packet_loss_perc: 0,
        }
    }

    /// Creates a low-delay configuration.
    ///
    /// Minimizes encoding latency: 10ms frames, no FEC/DTX overhead.
    pub fn low_delay() -> Self {
        Self {
            sample_rate: 48000,
            channels: 1,
            bitrate: 32000,
            application: OpusApplication::LowDelay,
            signal: OpusSignal::Voice,
            fec: false,
            dtx: false,
            vbr: true,
            vbr_constraint: true,
            frame_duration_ms: 10.0,
            complexity: 9,
            packet_loss_perc: 0,
        }
    }

    /// Validates the configuration.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn validate(&self) -> CodecResult<()> {
        // Validate sample rate
        match self.sample_rate {
            8000 | 12000 | 16000 | 24000 | 48000 => {}
            _ => {
                return Err(CodecError::UnsupportedSampleRate {
                    rate: self.sample_rate,
                });
            }
        }

        // Validate channels
        if self.channels != 1 && self.channels != 2 {
            return Err(CodecError::UnsupportedChannels {
                channels: self.channels,
            });
        }

        // Validate frame duration
        match self.frame_duration_ms as u32 {
            2 | 5 | 10 | 20 | 40 | 60 => {}
            _ => {
                return Err(CodecError::InvalidConfig {
                    reason: format!("unsupported frame duration: {}ms", self.frame_duration_ms),
                });
            }
        }

        // Validate complexity
        if self.complexity > 10 {
            return Err(CodecError::InvalidConfig {
                reason: "complexity must be 0-10".to_string(),
            });
        }

        Ok(())
    }

    /// Generates fmtp parameter string for SDP.
    pub fn to_fmtp(&self) -> String {
        let mut params = Vec::new();

        params.push(format!("minptime={}", self.frame_duration_ms as u32));

        if self.fec {
            params.push("useinbandfec=1".to_string());
        }

        if self.dtx {
            params.push("usedtx=1".to_string());
        }

        if self.channels == 2 {
            params.push("stereo=1".to_string());
        }

        params.join(";")
    }
}

/// Opus codec.
///
/// Note: This is a stub implementation. Full Opus requires libopus FFI.
#[derive(Debug, Clone)]
pub struct OpusCodec {
    /// Configuration.
    config: OpusConfig,
    /// Payload type (dynamic).
    payload_type: u8,
}

impl Default for OpusCodec {
    fn default() -> Self {
        Self::new(OpusConfig::default(), 111)
    }
}

impl OpusCodec {
    /// Creates a new Opus codec with the given configuration.
    pub fn new(config: OpusConfig, payload_type: u8) -> Self {
        Self {
            config,
            payload_type,
        }
    }

    /// Creates a VoIP-optimized Opus codec.
    pub fn voip(payload_type: u8) -> Self {
        Self::new(OpusConfig::voip(), payload_type)
    }

    /// Returns the configuration.
    pub fn config(&self) -> &OpusConfig {
        &self.config
    }

    /// Returns the configured bitrate.
    pub fn bitrate(&self) -> u32 {
        self.config.bitrate
    }
}

impl AudioCodec for OpusCodec {
    fn name(&self) -> &'static str {
        "opus"
    }

    fn payload_type(&self) -> PayloadType {
        PayloadType::Dynamic(self.payload_type)
    }

    fn clock_rate(&self) -> u32 {
        // Opus RTP always uses 48000 Hz clock
        48000
    }

    fn channels(&self) -> u8 {
        self.config.channels
    }

    fn frame_duration_ms(&self) -> u32 {
        self.config.frame_duration_ms as u32
    }

    fn samples_per_frame(&self) -> usize {
        // Samples at configured sample rate
        // Use integer math to avoid precision loss
        (self.config.sample_rate * self.config.frame_duration_ms as u32 / 1000) as usize
    }

    fn encode(&self, _pcm: &[i16], _output: &mut [u8]) -> CodecResult<usize> {
        // Opus encoding requires libopus FFI
        Err(CodecError::CodecNotAvailable {
            name: "Opus encoder not implemented (requires libopus)".to_string(),
        })
    }

    fn decode(&self, _encoded: &[u8], _output: &mut [i16]) -> CodecResult<usize> {
        // Opus decoding requires libopus FFI
        Err(CodecError::CodecNotAvailable {
            name: "Opus decoder not implemented (requires libopus)".to_string(),
        })
    }
}

/// Parses Opus fmtp parameters from SDP.
pub fn parse_fmtp(fmtp: &str) -> OpusConfig {
    let mut config = OpusConfig::default();

    for param in fmtp.split(';') {
        let parts: Vec<&str> = param.trim().split('=').collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0].to_lowercase();
        let value = parts[1];

        match key.as_str() {
            "minptime" => {
                if let Ok(v) = value.parse::<f32>() {
                    config.frame_duration_ms = v;
                }
            }
            "useinbandfec" => {
                config.fec = value == "1";
            }
            "usedtx" => {
                config.dtx = value == "1";
            }
            "stereo" => {
                config.channels = if value == "1" { 2 } else { 1 };
            }
            "maxaveragebitrate" => {
                if let Ok(v) = value.parse::<u32>() {
                    config.bitrate = v;
                }
            }
            _ => {}
        }
    }

    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opus_codec_info() {
        let codec = OpusCodec::default();
        assert_eq!(codec.name(), "opus");
        assert_eq!(codec.clock_rate(), 48000);
        assert!(codec.payload_type().is_dynamic());
    }

    #[test]
    fn test_opus_config_voip() {
        let config = OpusConfig::voip();
        assert_eq!(config.channels, 1);
        assert!(config.fec);
        assert!(config.dtx);
        assert!(config.vbr);
        assert!(config.vbr_constraint);
        assert_eq!(config.application, OpusApplication::Voip);
    }

    #[test]
    fn test_opus_config_audio_preset() {
        let config = OpusConfig::audio();
        assert_eq!(config.channels, 2);
        assert_eq!(config.bitrate, 96000);
        assert!(!config.fec);
        assert!(!config.dtx);
        assert!(!config.vbr, "Music preset uses CBR");
        assert!(!config.vbr_constraint);
        assert_eq!(config.complexity, 10);
        assert_eq!(config.application, OpusApplication::Audio);
    }

    #[test]
    fn test_opus_config_low_delay() {
        let config = OpusConfig::low_delay();
        assert!(!config.fec);
        assert!(!config.dtx);
        assert!(config.vbr);
        #[allow(clippy::float_cmp)]
        {
            assert_eq!(config.frame_duration_ms, 10.0);
        }
        assert_eq!(config.application, OpusApplication::LowDelay);
    }

    #[test]
    fn test_opus_config_validate() {
        let config = OpusConfig::default();
        assert!(config.validate().is_ok());

        let invalid = OpusConfig {
            sample_rate: 44100,
            ..OpusConfig::default()
        };
        assert!(invalid.validate().is_err());

        let invalid = OpusConfig {
            channels: 3,
            ..OpusConfig::default()
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_opus_fmtp() {
        let config = OpusConfig::voip();
        let fmtp = config.to_fmtp();

        assert!(fmtp.contains("minptime="));
        assert!(fmtp.contains("useinbandfec=1"));
        assert!(fmtp.contains("usedtx=1"));
    }

    #[test]
    fn test_parse_fmtp() {
        let fmtp = "minptime=20;useinbandfec=1;stereo=1";
        let config = parse_fmtp(fmtp);

        #[allow(clippy::float_cmp)]
        {
            assert_eq!(config.frame_duration_ms, 20.0);
        }
        assert!(config.fec);
        assert_eq!(config.channels, 2);
    }

    #[test]
    fn test_opus_samples_per_frame() {
        let codec = OpusCodec::new(OpusConfig::default(), 111);
        // 48000 Hz * 20ms = 960 samples
        assert_eq!(codec.samples_per_frame(), 960);
    }

    #[test]
    fn test_bandwidth_frequency() {
        assert_eq!(OpusBandwidth::Narrowband.max_frequency(), 4000);
        assert_eq!(OpusBandwidth::Fullband.max_frequency(), 20000);
    }
}
