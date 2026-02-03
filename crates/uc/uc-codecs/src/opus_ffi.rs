//! Opus FFI bindings using audiopus.
//!
//! This module provides actual Opus encoding/decoding via libopus FFI.
//! Enable with the `opus-ffi` feature flag.
//!
//! Requires libopus to be installed on the system:
//! - macOS: `brew install opus`
//! - Ubuntu/Debian: `apt install libopus-dev`
//! - RHEL/Fedora: `dnf install opus-devel`

#![cfg(feature = "opus-ffi")]

use crate::error::{CodecError, CodecResult};
use crate::opus::{OpusApplication, OpusConfig};
use audiopus::coder::{Decoder as OpusDecoder, Encoder as OpusEncoder};
use audiopus::{Application, Bandwidth, Bitrate, Channels, SampleRate, Signal};
use std::sync::Mutex;

/// Convert our application mode to audiopus Application.
fn to_audiopus_application(app: OpusApplication) -> Application {
    match app {
        OpusApplication::Voip => Application::Voip,
        OpusApplication::Audio => Application::Audio,
        OpusApplication::LowDelay => Application::LowDelay,
    }
}

/// Convert sample rate to audiopus SampleRate.
fn to_audiopus_sample_rate(rate: u32) -> CodecResult<SampleRate> {
    match rate {
        8000 => Ok(SampleRate::Hz8000),
        12000 => Ok(SampleRate::Hz12000),
        16000 => Ok(SampleRate::Hz16000),
        24000 => Ok(SampleRate::Hz24000),
        48000 => Ok(SampleRate::Hz48000),
        _ => Err(CodecError::UnsupportedSampleRate { rate }),
    }
}

/// Convert channels to audiopus Channels.
fn to_audiopus_channels(channels: u8) -> CodecResult<Channels> {
    match channels {
        1 => Ok(Channels::Mono),
        2 => Ok(Channels::Stereo),
        _ => Err(CodecError::UnsupportedChannels { channels }),
    }
}

/// Opus encoder with FFI bindings to libopus.
pub struct FfiOpusEncoder {
    /// The underlying audiopus encoder.
    encoder: Mutex<OpusEncoder>,
    /// Configuration.
    config: OpusConfig,
}

impl FfiOpusEncoder {
    /// Creates a new Opus FFI encoder with the given configuration.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn new(config: OpusConfig) -> CodecResult<Self> {
        config.validate()?;

        let sample_rate = to_audiopus_sample_rate(config.sample_rate)?;
        let channels = to_audiopus_channels(config.channels)?;
        let application = to_audiopus_application(config.application);

        let mut encoder = OpusEncoder::new(sample_rate, channels, application).map_err(|e| {
            CodecError::InvalidConfig {
                reason: format!("failed to create Opus encoder: {e}"),
            }
        })?;

        Self::configure_encoder(&mut encoder, &config)?;

        Ok(Self {
            encoder: Mutex::new(encoder),
            config,
        })
    }

    /// Configures the encoder with the specified settings.
    fn configure_encoder(encoder: &mut OpusEncoder, config: &OpusConfig) -> CodecResult<()> {
        encoder
            .set_bitrate(Bitrate::BitsPerSecond(config.bitrate as i32))
            .map_err(|e| CodecError::InvalidConfig {
                reason: format!("failed to set bitrate: {e}"),
            })?;

        let signal = match config.signal {
            crate::opus::OpusSignal::Auto => Signal::Auto,
            crate::opus::OpusSignal::Voice => Signal::Voice,
            crate::opus::OpusSignal::Music => Signal::Music,
        };
        encoder
            .set_signal(signal)
            .map_err(|e| CodecError::InvalidConfig {
                reason: format!("failed to set signal type: {e}"),
            })?;

        encoder
            .set_complexity(config.complexity as i32)
            .map_err(|e| CodecError::InvalidConfig {
                reason: format!("failed to set complexity: {e}"),
            })?;

        encoder
            .set_inband_fec(config.fec)
            .map_err(|e| CodecError::InvalidConfig {
                reason: format!("failed to set FEC: {e}"),
            })?;

        encoder
            .set_dtx(config.dtx)
            .map_err(|e| CodecError::InvalidConfig {
                reason: format!("failed to set DTX: {e}"),
            })?;

        encoder
            .set_packet_loss_perc(config.packet_loss_perc as i32)
            .map_err(|e| CodecError::InvalidConfig {
                reason: format!("failed to set packet loss percentage: {e}"),
            })?;

        Ok(())
    }

    /// Encodes PCM samples to Opus.
    ///
    /// Returns the number of bytes written to the output buffer.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn encode(&self, pcm: &[i16], output: &mut [u8]) -> CodecResult<usize> {
        let mut encoder = self
            .encoder
            .lock()
            .map_err(|_| CodecError::EncodingFailed {
                reason: "failed to acquire encoder lock".to_string(),
            })?;

        let result = encoder
            .encode(pcm, output)
            .map_err(|e| CodecError::EncodingFailed {
                reason: format!("Opus encoding failed: {e}"),
            })?;

        Ok(result.len())
    }

    /// Returns the configured sample rate.
    pub fn sample_rate(&self) -> u32 {
        self.config.sample_rate
    }

    /// Returns the number of channels.
    pub fn channels(&self) -> u8 {
        self.config.channels
    }

    /// Returns samples per frame based on configuration.
    pub fn samples_per_frame(&self) -> usize {
        (self.config.sample_rate as f32 * self.config.frame_duration_ms / 1000.0) as usize
    }
}

/// Opus decoder with FFI bindings to libopus.
pub struct FfiOpusDecoder {
    /// The underlying audiopus decoder.
    decoder: Mutex<OpusDecoder>,
    /// Sample rate for decoding.
    sample_rate: u32,
    /// Number of channels.
    channels: u8,
}

impl FfiOpusDecoder {
    /// Creates a new Opus FFI decoder.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn new(sample_rate: u32, channels: u8) -> CodecResult<Self> {
        let sample_rate_enum = to_audiopus_sample_rate(sample_rate)?;
        let channels_enum = to_audiopus_channels(channels)?;

        let decoder = OpusDecoder::new(sample_rate_enum, channels_enum).map_err(|e| {
            CodecError::InvalidConfig {
                reason: format!("failed to create Opus decoder: {e}"),
            }
        })?;

        Ok(Self {
            decoder: Mutex::new(decoder),
            sample_rate,
            channels,
        })
    }

    /// Decodes Opus to PCM samples.
    ///
    /// Returns the number of samples decoded.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode(&self, encoded: &[u8], output: &mut [i16]) -> CodecResult<usize> {
        let mut decoder = self
            .decoder
            .lock()
            .map_err(|_| CodecError::DecodingFailed {
                reason: "failed to acquire decoder lock".to_string(),
            })?;

        // Use FEC=false for normal decoding
        let result = decoder.decode(Some(encoded), output, false).map_err(|e| {
            CodecError::DecodingFailed {
                reason: format!("Opus decoding failed: {e}"),
            }
        })?;

        Ok(result.len())
    }

    /// Decodes with Forward Error Correction for lost packets.
    ///
    /// Call this when a packet is lost to attempt FEC recovery.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode_fec(&self, output: &mut [i16]) -> CodecResult<usize> {
        let mut decoder = self
            .decoder
            .lock()
            .map_err(|_| CodecError::DecodingFailed {
                reason: "failed to acquire decoder lock".to_string(),
            })?;

        // Pass None for lost packet, use FEC=true
        let result = decoder.decode(None::<&[u8]>, output, true).map_err(|e| {
            CodecError::DecodingFailed {
                reason: format!("Opus FEC decoding failed: {e}"),
            }
        })?;

        Ok(result.len())
    }

    /// Returns the configured sample rate.
    pub fn sample_rate(&self) -> u32 {
        self.sample_rate
    }

    /// Returns the number of channels.
    pub fn channels(&self) -> u8 {
        self.channels
    }
}

/// Opus codec with full FFI implementation.
///
/// This provides actual Opus encoding/decoding via libopus.
#[derive(Debug)]
pub struct FfiOpusCodec {
    /// Configuration.
    config: OpusConfig,
    /// Payload type.
    payload_type: u8,
    /// FFI encoder (lazy initialized).
    encoder: std::sync::OnceLock<FfiOpusEncoder>,
    /// FFI decoder (lazy initialized).
    decoder: std::sync::OnceLock<FfiOpusDecoder>,
}

impl FfiOpusCodec {
    /// Creates a new Opus FFI codec.
    pub fn new(config: OpusConfig, payload_type: u8) -> Self {
        Self {
            config,
            payload_type,
            encoder: std::sync::OnceLock::new(),
            decoder: std::sync::OnceLock::new(),
        }
    }

    /// Creates a VoIP-optimized Opus FFI codec.
    pub fn voip(payload_type: u8) -> Self {
        Self::new(OpusConfig::voip(), payload_type)
    }

    /// Returns the configuration.
    pub fn config(&self) -> &OpusConfig {
        &self.config
    }

    /// Gets or creates the encoder.
    fn get_encoder(&self) -> CodecResult<&FfiOpusEncoder> {
        self.encoder
            .get_or_try_init(|| FfiOpusEncoder::new(self.config.clone()))
    }

    /// Gets or creates the decoder.
    fn get_decoder(&self) -> CodecResult<&FfiOpusDecoder> {
        self.decoder
            .get_or_try_init(|| FfiOpusDecoder::new(self.config.sample_rate, self.config.channels))
    }

    /// Encodes PCM samples to Opus.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn encode(&self, pcm: &[i16], output: &mut [u8]) -> CodecResult<usize> {
        self.get_encoder()?.encode(pcm, output)
    }

    /// Decodes Opus to PCM samples.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode(&self, encoded: &[u8], output: &mut [i16]) -> CodecResult<usize> {
        self.get_decoder()?.decode(encoded, output)
    }

    /// Decodes with FEC for lost packets.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode_fec(&self, output: &mut [i16]) -> CodecResult<usize> {
        self.get_decoder()?.decode_fec(output)
    }

    /// Returns the payload type.
    pub fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// Returns samples per frame.
    pub fn samples_per_frame(&self) -> usize {
        (self.config.sample_rate as f32 * self.config.frame_duration_ms / 1000.0) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_encoder_creation() {
        let config = OpusConfig::voip();
        let encoder = FfiOpusEncoder::new(config);
        assert!(encoder.is_ok());
    }

    #[test]
    fn test_ffi_decoder_creation() {
        let decoder = FfiOpusDecoder::new(48000, 1);
        assert!(decoder.is_ok());
    }

    #[test]
    fn test_ffi_codec_encode_decode() {
        let codec = FfiOpusCodec::voip(111);

        // Create test signal (20ms at 48kHz mono = 960 samples)
        let mut pcm = vec![0i16; 960];
        for (i, sample) in pcm.iter_mut().enumerate() {
            let t = i as f32 / 48000.0;
            *sample = (f32::sin(2.0 * std::f32::consts::PI * 440.0 * t) * 16000.0) as i16;
        }

        // Encode
        let mut encoded = vec![0u8; 1275]; // Max Opus packet size
        let encoded_len = codec.encode(&pcm, &mut encoded).unwrap();
        assert!(encoded_len > 0);
        assert!(encoded_len < 1275);

        // Decode
        let mut decoded = vec![0i16; 960];
        let decoded_len = codec.decode(&encoded[..encoded_len], &mut decoded).unwrap();
        assert_eq!(decoded_len, 960);

        // Verify we got non-zero output
        let non_zero = decoded.iter().any(|&s| s != 0);
        assert!(non_zero, "Decoded audio should not be silent");
    }

    #[test]
    fn test_ffi_codec_stereo() {
        let config = OpusConfig {
            sample_rate: 48000,
            channels: 2,
            ..OpusConfig::default()
        };
        let codec = FfiOpusCodec::new(config, 111);

        // Stereo: 20ms at 48kHz = 960 samples per channel = 1920 total
        let mut pcm = vec![0i16; 1920];
        for (i, sample) in pcm.iter_mut().enumerate() {
            let t = (i / 2) as f32 / 48000.0;
            *sample = (f32::sin(2.0 * std::f32::consts::PI * 440.0 * t) * 16000.0) as i16;
        }

        let mut encoded = vec![0u8; 1275];
        let encoded_len = codec.encode(&pcm, &mut encoded).unwrap();
        assert!(encoded_len > 0);

        let mut decoded = vec![0i16; 1920];
        let decoded_len = codec.decode(&encoded[..encoded_len], &mut decoded).unwrap();
        assert_eq!(decoded_len, 1920);
    }

    #[test]
    fn test_invalid_sample_rate() {
        let config = OpusConfig {
            sample_rate: 44100, // Invalid for Opus
            ..OpusConfig::default()
        };
        let encoder = FfiOpusEncoder::new(config);
        assert!(encoder.is_err());
    }

    #[test]
    fn test_invalid_channels() {
        let decoder = FfiOpusDecoder::new(48000, 5); // Invalid channel count
        assert!(decoder.is_err());
    }
}
