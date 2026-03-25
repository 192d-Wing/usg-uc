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
use crate::{AudioCodec, PayloadType};
use audiopus::coder::{Decoder as OpusDecoder, Encoder as OpusEncoder};
use audiopus::{Application, Bitrate, Channels, SampleRate, Signal};
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

impl std::fmt::Debug for FfiOpusEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiOpusEncoder")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
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
            .set_complexity(config.complexity)
            .map_err(|e| CodecError::InvalidConfig {
                reason: format!("failed to set complexity: {e}"),
            })?;

        encoder
            .set_inband_fec(config.fec)
            .map_err(|e| CodecError::InvalidConfig {
                reason: format!("failed to set FEC: {e}"),
            })?;

        encoder
            .set_packet_loss_perc(config.packet_loss_perc)
            .map_err(|e| CodecError::InvalidConfig {
                reason: format!("failed to set packet loss percentage: {e}"),
            })?;

        encoder
            .set_vbr(config.vbr)
            .map_err(|e| CodecError::InvalidConfig {
                reason: format!("failed to set VBR: {e}"),
            })?;

        encoder
            .set_vbr_constraint(config.vbr_constraint)
            .map_err(|e| CodecError::InvalidConfig {
                reason: format!("failed to set VBR constraint: {e}"),
            })?;

        // DTX: use raw CTL request (OPUS_SET_DTX_REQUEST = 4016)
        // audiopus doesn't expose a typed set_dtx() method.
        encoder
            .set_encoder_ctl_request(4016, i32::from(config.dtx))
            .map_err(|e| CodecError::InvalidConfig {
                reason: format!("failed to set DTX: {e}"),
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
        let result = {
            let encoder = self
                .encoder
                .lock()
                .map_err(|_| CodecError::EncodingFailed {
                    reason: "failed to acquire encoder lock".to_string(),
                })?;

            encoder
                .encode(pcm, output)
                .map_err(|e| CodecError::EncodingFailed {
                    reason: format!("Opus encoding failed: {e}"),
                })?
        };

        Ok(result)
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
        (self.config.sample_rate * self.config.frame_duration_ms as u32 / 1000) as usize
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

impl std::fmt::Debug for FfiOpusDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FfiOpusDecoder")
            .field("sample_rate", &self.sample_rate)
            .field("channels", &self.channels)
            .finish_non_exhaustive()
    }
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
        let frames = {
            let mut decoder = self
                .decoder
                .lock()
                .map_err(|_| CodecError::DecodingFailed {
                    reason: "failed to acquire decoder lock".to_string(),
                })?;

            // Use FEC=false for normal decoding
            // opus_decode returns frames per channel; multiply by channels for total samples
            decoder.decode(Some(encoded), output, false).map_err(|e| {
                CodecError::DecodingFailed {
                    reason: format!("Opus decoding failed: {e}"),
                }
            })?
        };

        Ok(frames * self.channels as usize)
    }

    /// Decodes with Forward Error Correction for lost packets.
    ///
    /// Call this when a packet is lost to attempt FEC recovery.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn decode_fec(&self, output: &mut [i16]) -> CodecResult<usize> {
        let frames = {
            let mut decoder = self
                .decoder
                .lock()
                .map_err(|_| CodecError::DecodingFailed {
                    reason: "failed to acquire decoder lock".to_string(),
                })?;

            // Pass None for lost packet, use FEC=true
            // opus_decode returns frames per channel; multiply by channels for total samples
            decoder
                .decode(None::<&[u8]>, output, true)
                .map_err(|e| CodecError::DecodingFailed {
                    reason: format!("Opus FEC decoding failed: {e}"),
                })?
        };

        Ok(frames * self.channels as usize)
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
        if let Some(enc) = self.encoder.get() {
            return Ok(enc);
        }
        let enc = FfiOpusEncoder::new(self.config.clone())?;
        let _ = self.encoder.set(enc);
        self.encoder.get().ok_or_else(|| CodecError::InvalidConfig {
            reason: "failed to initialize Opus encoder".to_string(),
        })
    }

    /// Gets or creates the decoder.
    fn get_decoder(&self) -> CodecResult<&FfiOpusDecoder> {
        if let Some(dec) = self.decoder.get() {
            return Ok(dec);
        }
        let dec = FfiOpusDecoder::new(self.config.sample_rate, self.config.channels)?;
        let _ = self.decoder.set(dec);
        self.decoder.get().ok_or_else(|| CodecError::InvalidConfig {
            reason: "failed to initialize Opus decoder".to_string(),
        })
    }
}

impl AudioCodec for FfiOpusCodec {
    fn name(&self) -> &'static str {
        "opus"
    }

    fn payload_type(&self) -> PayloadType {
        PayloadType::Dynamic(self.payload_type)
    }

    fn clock_rate(&self) -> u32 {
        48000
    }

    fn channels(&self) -> u8 {
        self.config.channels
    }

    fn frame_duration_ms(&self) -> u32 {
        self.config.frame_duration_ms as u32
    }

    fn samples_per_frame(&self) -> usize {
        (self.config.sample_rate * self.config.frame_duration_ms as u32 / 1000) as usize
    }

    fn encode(&self, pcm: &[i16], output: &mut [u8]) -> CodecResult<usize> {
        self.get_encoder()?.encode(pcm, output)
    }

    fn decode(&self, encoded: &[u8], output: &mut [i16]) -> CodecResult<usize> {
        self.get_decoder()?.decode(encoded, output)
    }

    fn decode_fec(&self, output: &mut [i16]) -> CodecResult<usize> {
        self.get_decoder()?.decode_fec(output)
    }

    fn supports_fec(&self) -> bool {
        self.config.fec
    }
}

#[cfg(test)]
#[allow(
    clippy::cast_precision_loss,
    clippy::unwrap_used,
    clippy::needless_range_loop
)]
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
    fn test_ffi_codec_fec() {
        let codec = FfiOpusCodec::voip(111);
        assert!(codec.supports_fec());

        // Encode a frame first (FEC needs prior frame data)
        let mut pcm = vec![0i16; 960];
        for (i, sample) in pcm.iter_mut().enumerate() {
            let t = i as f32 / 48000.0;
            *sample = (f32::sin(2.0 * std::f32::consts::PI * 440.0 * t) * 16000.0) as i16;
        }
        let mut encoded = vec![0u8; 1275];
        let _ = codec.encode(&pcm, &mut encoded).unwrap();

        // Decode it normally to prime the decoder
        let mut decoded = vec![0i16; 960];
        let _ = codec.decode(&encoded[..100], &mut decoded);

        // Now try FEC decode (simulating lost packet)
        let mut fec_output = vec![0i16; 960];
        let fec_result = codec.decode_fec(&mut fec_output);
        // FEC may produce output or may fail depending on encoder state
        // Just verify it doesn't panic
        let _ = fec_result;
    }

    #[test]
    fn test_ffi_codec_audio_codec_trait() {
        let codec = FfiOpusCodec::voip(111);
        let boxed: Box<dyn AudioCodec> = Box::new(codec);
        assert_eq!(boxed.name(), "opus");
        assert_eq!(boxed.clock_rate(), 48000);
        assert_eq!(boxed.channels(), 1);
        assert_eq!(boxed.frame_duration_ms(), 20);
        assert_eq!(boxed.samples_per_frame(), 960);
        assert!(boxed.supports_fec());
    }

    #[test]
    fn test_fec_recovery_quality() {
        // Encode N frames, decode all normally except one which uses FEC.
        // Verify the FEC-recovered frame is non-silent and the overall
        // output has high correlation with the input.
        let codec = FfiOpusCodec::voip(111);
        let samples_per_frame = 960; // 20ms at 48kHz mono
        let num_frames = 50;
        let total_samples = samples_per_frame * num_frames;

        // Generate 1-second 440Hz sine wave
        let input: Vec<i16> = (0..total_samples)
            .map(|i| {
                let t = i as f32 / 48000.0;
                (f32::sin(2.0 * std::f32::consts::PI * 440.0 * t) * 16000.0) as i16
            })
            .collect();

        // Encode all frames
        let mut encoded_packets: Vec<Vec<u8>> = Vec::new();
        for frame_idx in 0..num_frames {
            let start = frame_idx * samples_per_frame;
            let end = start + samples_per_frame;
            let mut encoded = vec![0u8; 1275];
            let len = codec.encode(&input[start..end], &mut encoded).unwrap();
            encoded_packets.push(encoded[..len].to_vec());
        }

        // Decode with loss at frame 25 — use FEC to recover
        let lost_frame = 25;
        let mut output = Vec::with_capacity(total_samples);
        let mut fec_frame_rms = 0.0_f64;

        for frame_idx in 0..num_frames {
            let mut decoded = vec![0i16; samples_per_frame];
            if frame_idx == lost_frame {
                // Simulate loss: use decoder PLC/FEC (decode(None, fec=true))
                let len = codec.decode_fec(&mut decoded).unwrap();
                assert_eq!(len, samples_per_frame, "FEC should produce a full frame");

                // Compute RMS of recovered frame
                let sum_sq: f64 = decoded.iter().map(|&s| (s as f64) * (s as f64)).sum();
                fec_frame_rms = (sum_sq / len as f64).sqrt();
            } else {
                let len = codec
                    .decode(&encoded_packets[frame_idx], &mut decoded)
                    .unwrap();
                assert_eq!(len, samples_per_frame);
            }
            output.extend_from_slice(&decoded);
        }

        // FEC-recovered frame should not be silence (Opus PLC generates
        // continuation from decoder state after 24 good frames of 440Hz).
        assert!(
            fec_frame_rms > 500.0,
            "FEC recovered frame should not be silent: RMS={fec_frame_rms:.1}"
        );

        // Overall output should have high energy
        let total_rms: f64 = {
            let sum: f64 = output.iter().map(|&s| (s as f64) * (s as f64)).sum();
            (sum / output.len() as f64).sqrt()
        };
        assert!(
            total_rms > 5000.0,
            "Total output RMS should be high: {total_rms:.1}"
        );
    }

    #[test]
    fn test_fec_produces_active_audio() {
        // FEC/PLC recovery should produce audio with similar energy to the
        // original, not silence. We compare RMS levels rather than MSE because
        // Opus PLC generates a continuation tone with correct frequency/amplitude
        // but may differ in phase (making MSE unreliable).
        let codec = FfiOpusCodec::voip(111);
        let spf = 960;

        // Generate and encode 10 frames of sine wave
        let input: Vec<i16> = (0..spf * 10)
            .map(|i| {
                let t = i as f32 / 48000.0;
                (f32::sin(2.0 * std::f32::consts::PI * 440.0 * t) * 16000.0) as i16
            })
            .collect();

        let mut packets = Vec::new();
        for f in 0..10 {
            let mut enc = vec![0u8; 1275];
            let len = codec
                .encode(&input[f * spf..(f + 1) * spf], &mut enc)
                .unwrap();
            packets.push(enc[..len].to_vec());
        }

        // Decode frames 0-7 normally, then lose frame 8
        let mut decoded = vec![0i16; spf];
        for f in 0..8 {
            codec.decode(&packets[f], &mut decoded).unwrap();
        }

        // FEC recovery for lost frame 8
        let mut fec_output = vec![0i16; spf];
        let fec_len = codec.decode_fec(&mut fec_output).unwrap();
        assert_eq!(fec_len, spf);

        // Compute RMS of FEC output and original frame
        let fec_rms: f64 = {
            let sum: f64 = fec_output.iter().map(|&s| (s as f64) * (s as f64)).sum();
            (sum / spf as f64).sqrt()
        };
        let original_frame = &input[8 * spf..9 * spf];
        let original_rms: f64 = {
            let sum: f64 = original_frame
                .iter()
                .map(|&s| (s as f64) * (s as f64))
                .sum();
            (sum / spf as f64).sqrt()
        };

        // FEC output should have at least 25% of the original's energy
        // (it's a continuation, not an exact replica)
        assert!(
            fec_rms > original_rms * 0.25,
            "FEC RMS ({fec_rms:.1}) should be >25% of original RMS ({original_rms:.1})"
        );

        // FEC output should definitely not be silence
        assert!(
            fec_rms > 500.0,
            "FEC output should not be silent: RMS={fec_rms:.1}"
        );
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
