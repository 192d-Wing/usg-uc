//! G.722 codec (ITU-T G.722).
//!
//! G.722 is a wideband audio codec operating at 16 kHz sample rate.
//!
//! ## Note
//!
//! This module provides a codec stub. Full G.722 implementation would
//! require either external FFI bindings or a substantial pure-Rust
//! ADPCM encoder/decoder implementation.

use crate::error::{CodecError, CodecResult};
use crate::{payload_types, AudioCodec, PayloadType};

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
/// Note: This is a stub implementation. Full G.722 requires ADPCM encoding.
#[derive(Debug, Clone)]
pub struct G722Codec {
    /// Operating mode.
    mode: G722Mode,
    /// Frame duration in milliseconds.
    frame_duration_ms: u32,
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
        }
    }

    /// Creates with custom mode.
    pub fn with_mode(mode: G722Mode) -> Self {
        Self {
            mode,
            frame_duration_ms: 20,
        }
    }

    /// Creates with custom frame duration.
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

    fn encode(&self, _pcm: &[i16], _output: &mut [u8]) -> CodecResult<usize> {
        // G.722 encoding requires ADPCM sub-band coding
        // This would be a significant implementation
        Err(CodecError::CodecNotAvailable {
            name: "G722 encoder not implemented".to_string(),
        })
    }

    fn decode(&self, _encoded: &[u8], _output: &mut [i16]) -> CodecResult<usize> {
        // G.722 decoding requires ADPCM sub-band decoding
        Err(CodecError::CodecNotAvailable {
            name: "G722 decoder not implemented".to_string(),
        })
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
    fn test_encode_not_implemented() {
        let codec = G722Codec::new();
        let pcm = [0i16; 320];
        let mut output = [0u8; 160];

        let result = codec.encode(&pcm, &mut output);
        assert!(result.is_err());
    }
}
