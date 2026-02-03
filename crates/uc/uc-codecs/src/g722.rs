//! G.722 codec (ITU-T G.722).
//!
//! G.722 is a wideband audio codec operating at 16 kHz sample rate.
//! This implementation uses sub-band ADPCM encoding per ITU-T G.722.
//!
//! ## Features
//!
//! - 64 kbps, 56 kbps, and 48 kbps modes
//! - 16 kHz sampling rate (wideband)
//! - Pure Rust ADPCM implementation

use crate::error::CodecResult;
use crate::g722_adpcm::{G722Decoder, G722Encoder};
use crate::{payload_types, AudioCodec, PayloadType};
use std::sync::Mutex;

/// G.722 codec modes (bit rates).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum G722Mode {
    /// Mode 1: 64 kbps (default).
    #[default]
    Mode1,
    /// Mode 2: 56 kbps.
    Mode2,
    /// Mode 3: 48 kbps.
    Mode3,
}

impl G722Mode {
    /// Returns the bit rate in kbps.
    pub fn bitrate_kbps(&self) -> u32 {
        match self {
            Self::Mode1 => 64,
            Self::Mode2 => 56,
            Self::Mode3 => 48,
        }
    }
}

/// G.722 codec.
///
/// Implements G.722 sub-band ADPCM encoding and decoding.
pub struct G722Codec {
    /// Operating mode.
    mode: G722Mode,
    /// Frame duration in milliseconds.
    frame_duration_ms: u32,
    /// Encoder state (interior mutability for AudioCodec trait).
    encoder: Mutex<G722Encoder>,
    /// Decoder state (interior mutability for AudioCodec trait).
    decoder: Mutex<G722Decoder>,
}

impl Default for G722Codec {
    fn default() -> Self {
        Self::new()
    }
}

impl G722Codec {
    /// Creates a new G.722 codec with default settings.
    pub fn new() -> Self {
        Self {
            mode: G722Mode::Mode1,
            frame_duration_ms: 20,
            encoder: Mutex::new(G722Encoder::new()),
            decoder: Mutex::new(G722Decoder::new()),
        }
    }

    /// Creates with custom mode.
    pub fn with_mode(mode: G722Mode) -> Self {
        Self {
            mode,
            frame_duration_ms: 20,
            encoder: Mutex::new(G722Encoder::new()),
            decoder: Mutex::new(G722Decoder::new()),
        }
    }

    /// Creates with custom frame duration.
    #[must_use]
    pub fn with_frame_duration(mut self, ms: u32) -> Self {
        self.frame_duration_ms = ms;
        self
    }

    /// Returns the current mode.
    pub fn mode(&self) -> G722Mode {
        self.mode
    }

    /// Returns the bit rate in kbps.
    pub fn bitrate_kbps(&self) -> u32 {
        self.mode.bitrate_kbps()
    }

    /// Resets encoder and decoder state.
    pub fn reset(&self) {
        if let Ok(mut encoder) = self.encoder.lock() {
            encoder.reset();
        }
        if let Ok(mut decoder) = self.decoder.lock() {
            decoder.reset();
        }
    }
}

impl std::fmt::Debug for G722Codec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("G722Codec")
            .field("mode", &self.mode)
            .field("frame_duration_ms", &self.frame_duration_ms)
            .finish_non_exhaustive()
    }
}

impl Clone for G722Codec {
    fn clone(&self) -> Self {
        Self {
            mode: self.mode,
            frame_duration_ms: self.frame_duration_ms,
            encoder: Mutex::new(G722Encoder::new()),
            decoder: Mutex::new(G722Decoder::new()),
        }
    }
}

impl AudioCodec for G722Codec {
    fn name(&self) -> &'static str {
        "G722"
    }

    fn payload_type(&self) -> PayloadType {
        PayloadType::Static(payload_types::G722)
    }

    fn clock_rate(&self) -> u32 {
        // G.722 has a quirk: RTP uses 8000 Hz clock rate even though
        // it actually operates at 16 kHz. This is per RFC 3551.
        8000
    }

    fn channels(&self) -> u8 {
        1
    }

    fn frame_duration_ms(&self) -> u32 {
        self.frame_duration_ms
    }

    fn samples_per_frame(&self) -> usize {
        // Actual audio samples at 16 kHz
        (16000 * self.frame_duration_ms / 1000) as usize
    }

    fn encode(&self, pcm: &[i16], output: &mut [u8]) -> CodecResult<usize> {
        let mut encoder = self.encoder.lock().map_err(|_| crate::error::CodecError::EncodingFailed {
            reason: "failed to acquire encoder lock".to_string(),
        })?;
        Ok(encoder.encode(pcm, output))
    }

    fn decode(&self, encoded: &[u8], output: &mut [i16]) -> CodecResult<usize> {
        let mut decoder = self.decoder.lock().map_err(|_| crate::error::CodecError::DecodingFailed {
            reason: "failed to acquire decoder lock".to_string(),
        })?;
        Ok(decoder.decode(encoded, output))
    }
}

/// Calculates G.722 payload size for given frame duration.
///
/// G.722 at 64 kbps produces 80 bytes per 10ms.
pub fn payload_size_for_duration(mode: G722Mode, duration_ms: u32) -> usize {
    let bits_per_sample = match mode {
        G722Mode::Mode1 => 4,
        G722Mode::Mode2 => 4, // Uses auxiliary data channel
        G722Mode::Mode3 => 4, // Uses auxiliary data channel
    };

    // At 16 kHz, samples per ms = 16
    let samples = 16 * duration_ms;
    (samples * bits_per_sample / 8) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g722_codec_info() {
        let codec = G722Codec::new();
        assert_eq!(codec.name(), "G722");
        assert_eq!(codec.clock_rate(), 8000); // RTP quirk
        assert_eq!(codec.channels(), 1);
        assert_eq!(codec.payload_type().value(), 9);
    }

    #[test]
    fn test_g722_samples_per_frame() {
        let codec = G722Codec::new();
        // 16 kHz * 20ms = 320 samples
        assert_eq!(codec.samples_per_frame(), 320);
    }

    #[test]
    fn test_g722_modes() {
        assert_eq!(G722Mode::Mode1.bitrate_kbps(), 64);
        assert_eq!(G722Mode::Mode2.bitrate_kbps(), 56);
        assert_eq!(G722Mode::Mode3.bitrate_kbps(), 48);
    }

    #[test]
    fn test_payload_size() {
        // 20ms at 64kbps = 160 bytes
        assert_eq!(payload_size_for_duration(G722Mode::Mode1, 20), 160);

        // 10ms at 64kbps = 80 bytes
        assert_eq!(payload_size_for_duration(G722Mode::Mode1, 10), 80);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let codec = G722Codec::new();

        // Create simple test signal
        let mut pcm = [0i16; 320]; // 20ms at 16kHz
        #[allow(clippy::cast_precision_loss)]
        for (i, sample) in pcm.iter_mut().enumerate() {
            let t = i as f32 / 16000.0;
            *sample = (f32::sin(2.0 * std::f32::consts::PI * 1000.0 * t) * 16000.0) as i16;
        }

        // Encode
        let mut encoded = [0u8; 160]; // 160 bytes for 320 samples
        let encoded_len = codec.encode(&pcm, &mut encoded).unwrap();
        assert_eq!(encoded_len, 160);

        // Decode
        let mut decoded = [0i16; 320];
        let decoded_len = codec.decode(&encoded, &mut decoded).unwrap();
        assert_eq!(decoded_len, 320);

        // Verify we got some output (not checking quality in unit test)
        let non_zero = decoded.iter().any(|&s| s != 0);
        assert!(non_zero, "Decoded output should not be all zeros");
    }

    #[test]
    fn test_codec_reset() {
        let codec = G722Codec::new();
        let pcm = [1000i16; 64];
        let mut output = [0u8; 32];

        // Encode some data
        codec.encode(&pcm, &mut output).unwrap();

        // Reset
        codec.reset();

        // Codec should still work after reset
        let result = codec.encode(&pcm, &mut output);
        assert!(result.is_ok());
    }
}
