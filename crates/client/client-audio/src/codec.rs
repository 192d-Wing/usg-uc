//! Audio codec integration for encoding and decoding.
//!
//! This module provides a unified interface to the various audio codecs
//! supported by the soft client (G.711, G.722, Opus).

use crate::{AudioError, AudioResult};
use client_types::CodecPreference;
use tracing::{debug, trace};
#[cfg(feature = "opus-ffi")]
use uc_codecs::FfiOpusCodec;
#[cfg(not(feature = "opus-ffi"))]
use uc_codecs::OpusCodec;
use uc_codecs::opus::OpusConfig;
use uc_codecs::{AudioCodec, CodecCapability, G711Alaw, G711Ulaw, G722Codec};

/// Maximum encoded frame size in bytes.
pub const MAX_ENCODED_SIZE: usize = 1500;

/// Maximum decoded frame size in samples.
pub const MAX_DECODED_SAMPLES: usize = 2880; // 60ms at 48kHz

/// Default Opus payload type.
const DEFAULT_OPUS_PT: u8 = 111;

/// Codec wrapper providing a unified interface to different codecs.
pub struct CodecPipeline {
    /// The active codec for encoding/decoding.
    codec: Box<dyn AudioCodec>,
    /// Codec preference (for identification).
    preference: CodecPreference,
    /// Buffer for encoded output.
    encode_buffer: Vec<u8>,
    /// Buffer for decoded output.
    decode_buffer: Vec<i16>,
}

impl CodecPipeline {
    /// Creates a new codec pipeline with the specified codec.
    pub fn new(preference: CodecPreference) -> AudioResult<Self> {
        let codec: Box<dyn AudioCodec> = match preference {
            CodecPreference::Opus => Self::create_opus_codec(),
            CodecPreference::G722 => Box::new(G722Codec::new()),
            CodecPreference::G711Ulaw => Box::new(G711Ulaw::new()),
            CodecPreference::G711Alaw => Box::new(G711Alaw::new()),
        };

        debug!(
            "Created codec pipeline: {} ({}Hz, {}ms frames)",
            codec.name(),
            codec.clock_rate(),
            codec.frame_duration_ms()
        );

        Ok(Self {
            codec,
            preference,
            encode_buffer: vec![0u8; MAX_ENCODED_SIZE],
            decode_buffer: vec![0i16; MAX_DECODED_SAMPLES],
        })
    }

    /// Creates a codec pipeline from an RTP payload type.
    pub fn from_payload_type(payload_type: u8) -> AudioResult<Self> {
        let preference = match payload_type {
            0 => CodecPreference::G711Ulaw,
            8 => CodecPreference::G711Alaw,
            9 => CodecPreference::G722,
            96..=127 => CodecPreference::Opus, // Dynamic PT, assume Opus
            _ => {
                return Err(AudioError::CodecError(format!(
                    "Unknown payload type: {payload_type}"
                )));
            }
        };

        Self::new(preference)
    }

    /// Encodes PCM samples to the codec format.
    ///
    /// Returns the encoded bytes.
    pub fn encode(&mut self, pcm: &[i16]) -> AudioResult<&[u8]> {
        let encoded_len = self
            .codec
            .encode(pcm, &mut self.encode_buffer)
            .map_err(|e| AudioError::CodecError(format!("Encode failed: {e}")))?;

        trace!(
            "Encoded {} samples to {} bytes ({})",
            pcm.len(),
            encoded_len,
            self.codec.name()
        );

        Ok(&self.encode_buffer[..encoded_len])
    }

    /// Decodes codec-formatted data to PCM samples.
    ///
    /// Returns the decoded samples.
    pub fn decode(&mut self, encoded: &[u8]) -> AudioResult<&[i16]> {
        let decoded_len = self
            .codec
            .decode(encoded, &mut self.decode_buffer)
            .map_err(|e| AudioError::CodecError(format!("Decode failed: {e}")))?;

        trace!(
            "Decoded {} bytes to {} samples ({})",
            encoded.len(),
            decoded_len,
            self.codec.name()
        );

        Ok(&self.decode_buffer[..decoded_len])
    }

    /// Returns the codec name.
    pub fn name(&self) -> &'static str {
        self.codec.name()
    }

    /// Returns the codec clock rate in Hz.
    pub fn clock_rate(&self) -> u32 {
        self.codec.clock_rate()
    }

    /// Returns the number of audio channels.
    pub fn channels(&self) -> u8 {
        self.codec.channels()
    }

    /// Returns the frame duration in milliseconds.
    pub fn frame_duration_ms(&self) -> u32 {
        self.codec.frame_duration_ms()
    }

    /// Returns the number of samples per frame.
    pub fn samples_per_frame(&self) -> usize {
        self.codec.samples_per_frame()
    }

    /// Returns the RTP payload type value.
    pub fn payload_type(&self) -> u8 {
        self.codec.payload_type().value()
    }

    /// Returns the codec preference.
    pub const fn preference(&self) -> CodecPreference {
        self.preference
    }

    /// Returns the codec capability for SDP negotiation.
    pub fn capability(&self) -> CodecCapability {
        match self.preference {
            CodecPreference::Opus => CodecCapability::opus(DEFAULT_OPUS_PT),
            CodecPreference::G722 => CodecCapability::g722(),
            CodecPreference::G711Ulaw => CodecCapability::pcmu(),
            CodecPreference::G711Alaw => CodecCapability::pcma(),
        }
    }

    /// Generates silence/comfort noise samples for packet loss concealment.
    ///
    /// This is a simple implementation that outputs silence. A more sophisticated
    /// implementation could use the codec's native PLC or interpolation.
    pub fn generate_plc(&self, output: &mut [i16]) {
        // Simple silence for now
        // TODO: Implement proper PLC using previous frame interpolation
        output.fill(0);
        trace!("Generated {} samples of PLC", output.len());
    }

    /// Decodes with Forward Error Correction for a lost packet.
    ///
    /// Only works with codecs that support FEC (e.g., Opus with inband FEC).
    /// Returns the decoded samples, or an error if FEC is not supported.
    pub fn decode_fec(&mut self) -> AudioResult<&[i16]> {
        let decoded_len = self
            .codec
            .decode_fec(&mut self.decode_buffer)
            .map_err(|e| AudioError::CodecError(format!("FEC decode failed: {e}")))?;

        trace!(
            "FEC decoded {} samples ({})",
            decoded_len,
            self.codec.name()
        );
        Ok(&self.decode_buffer[..decoded_len])
    }

    /// Returns true if this codec supports Forward Error Correction.
    pub fn supports_fec(&self) -> bool {
        self.codec.supports_fec()
    }

    /// Creates the appropriate Opus codec based on feature flags.
    #[cfg(feature = "opus-ffi")]
    fn create_opus_codec() -> Box<dyn AudioCodec> {
        Box::new(FfiOpusCodec::new(OpusConfig::voip(), DEFAULT_OPUS_PT))
    }

    /// Creates the Opus codec stub (no FFI).
    #[cfg(not(feature = "opus-ffi"))]
    fn create_opus_codec() -> Box<dyn AudioCodec> {
        Box::new(OpusCodec::new(OpusConfig::default(), DEFAULT_OPUS_PT))
    }
}

impl std::fmt::Debug for CodecPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodecPipeline")
            .field("name", &self.codec.name())
            .field("clock_rate", &self.codec.clock_rate())
            .field("preference", &self.preference)
            .finish_non_exhaustive()
    }
}

/// Selects the best codec from a list of preferences and remote capabilities.
pub fn negotiate_codec(
    local_preferences: &[CodecPreference],
    remote_capabilities: &[CodecCapability],
) -> Option<CodecPreference> {
    for pref in local_preferences {
        let name = match pref {
            CodecPreference::Opus => "opus",
            CodecPreference::G722 => "G722",
            CodecPreference::G711Ulaw => "PCMU",
            CodecPreference::G711Alaw => "PCMA",
        };

        if remote_capabilities
            .iter()
            .any(|c| c.name.eq_ignore_ascii_case(name))
        {
            debug!("Negotiated codec: {pref:?}");
            return Some(*pref);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_pipeline_g711_ulaw() {
        let pipeline = CodecPipeline::new(CodecPreference::G711Ulaw).unwrap();
        assert_eq!(pipeline.name(), "PCMU");
        assert_eq!(pipeline.clock_rate(), 8000);
        assert_eq!(pipeline.frame_duration_ms(), 20);
        assert_eq!(pipeline.samples_per_frame(), 160);
    }

    #[test]
    fn test_codec_pipeline_g711_alaw() {
        let pipeline = CodecPipeline::new(CodecPreference::G711Alaw).unwrap();
        assert_eq!(pipeline.name(), "PCMA");
        assert_eq!(pipeline.clock_rate(), 8000);
    }

    #[test]
    fn test_codec_pipeline_g722() {
        let pipeline = CodecPipeline::new(CodecPreference::G722).unwrap();
        assert_eq!(pipeline.name(), "G722");
        // G.722 uses 8000 Hz clock rate in RTP despite 16000 Hz sample rate
        // This is per RFC 3551 - the RTP timestamp increments at 8000 Hz
        assert_eq!(pipeline.clock_rate(), 8000);
    }

    #[test]
    fn test_codec_pipeline_opus() {
        let pipeline = CodecPipeline::new(CodecPreference::Opus).unwrap();
        assert_eq!(pipeline.name(), "opus");
        assert_eq!(pipeline.clock_rate(), 48000);
    }

    #[test]
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
    fn test_encode_decode_g711() {
        let mut pipeline = CodecPipeline::new(CodecPreference::G711Ulaw).unwrap();

        // Create a simple sine wave
        let samples: Vec<i16> = (0..160)
            .map(|i| ((i as f32 * 0.1).sin() * 10000.0) as i16)
            .collect();

        // Encode (copy to release borrow)
        let encoded = pipeline.encode(&samples).unwrap().to_vec();
        assert_eq!(encoded.len(), 160); // G.711 is 1 byte per sample

        // Decode
        let decoded = pipeline.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 160);
    }

    #[test]
    #[allow(clippy::similar_names)]
    fn test_from_payload_type() {
        let pcmu = CodecPipeline::from_payload_type(0).unwrap();
        assert_eq!(pcmu.preference(), CodecPreference::G711Ulaw);

        let pcma = CodecPipeline::from_payload_type(8).unwrap();
        assert_eq!(pcma.preference(), CodecPreference::G711Alaw);

        let g722 = CodecPipeline::from_payload_type(9).unwrap();
        assert_eq!(g722.preference(), CodecPreference::G722);

        let opus = CodecPipeline::from_payload_type(111).unwrap();
        assert_eq!(opus.preference(), CodecPreference::Opus);
    }

    #[test]
    fn test_negotiate_codec() {
        let local = vec![
            CodecPreference::Opus,
            CodecPreference::G722,
            CodecPreference::G711Ulaw,
        ];

        let remote = vec![CodecCapability::pcmu(), CodecCapability::g722()];

        // Should select G722 (first local preference available in remote)
        let negotiated = negotiate_codec(&local, &remote);
        assert_eq!(negotiated, Some(CodecPreference::G722));
    }

    #[test]
    fn test_negotiate_codec_no_match() {
        let local = vec![CodecPreference::Opus];
        let remote = vec![CodecCapability::pcmu()];

        let negotiated = negotiate_codec(&local, &remote);
        assert_eq!(negotiated, None);
    }

    #[test]
    fn test_capability() {
        let pipeline = CodecPipeline::new(CodecPreference::G711Ulaw).unwrap();
        let cap = pipeline.capability();
        assert_eq!(cap.name, "PCMU");
        assert_eq!(cap.payload_type, 0);
    }

    #[test]
    fn test_plc_generation() {
        let pipeline = CodecPipeline::new(CodecPreference::G711Ulaw).unwrap();
        let mut output = vec![1i16; 160];
        pipeline.generate_plc(&mut output);
        assert!(output.iter().all(|&s| s == 0));
    }
}
