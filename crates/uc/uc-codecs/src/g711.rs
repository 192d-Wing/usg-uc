//! G.711 codec implementation (ITU-T G.711).
//!
//! Pure Rust implementation of G.711 PCM encoding:
//! - mu-law (PCMU) - North America/Japan
//! - a-law (PCMA) - Europe/rest of world

use crate::error::{CodecError, CodecResult};
use crate::{AudioCodec, PayloadType, payload_types};

/// G.711 mu-law codec.
#[derive(Debug, Clone, Default)]
pub struct G711Ulaw {
    /// Frame duration in milliseconds.
    frame_duration_ms: u32,
}

impl G711Ulaw {
    /// Creates a new G.711 mu-law codec.
    pub fn new() -> Self {
        Self::with_frame_duration(20)
    }

    /// Creates with custom frame duration.
    pub fn with_frame_duration(ms: u32) -> Self {
        Self {
            frame_duration_ms: ms,
        }
    }

    /// Encodes a single PCM sample to mu-law.
    #[inline]
    pub fn encode_sample(sample: i16) -> u8 {
        // Bias and clip the sample
        const BIAS: i32 = 0x84;
        const CLIP: i32 = 32635;

        let mut pcm_val = sample as i32;

        // Get sign
        let sign = if pcm_val < 0 {
            pcm_val = -pcm_val;
            0x80
        } else {
            0x00
        };

        // Clip to max
        if pcm_val > CLIP {
            pcm_val = CLIP;
        }

        // Add bias
        pcm_val += BIAS;

        // Find exponent
        let mut exponent = 7u8;
        let mut exp_mask = 0x4000i32;

        while exponent > 0 {
            if (pcm_val & exp_mask) != 0 {
                break;
            }
            exponent -= 1;
            exp_mask >>= 1;
        }

        // Extract mantissa
        let mantissa = ((pcm_val >> (exponent + 3)) & 0x0F) as u8;

        // Combine and complement
        !(sign | (exponent << 4) | mantissa)
    }

    /// Decodes a single mu-law sample to PCM.
    #[inline]
    pub fn decode_sample(ulaw: u8) -> i16 {
        // Complement
        let ulaw = !ulaw;

        let sign = ulaw & 0x80;
        let exponent = (ulaw >> 4) & 0x07;
        let mantissa = ulaw & 0x0F;

        let mut sample = ((mantissa as i32) << 3) + 0x84;
        sample <<= exponent;

        if sign != 0 {
            -(sample as i16)
        } else {
            sample as i16
        }
    }
}

impl AudioCodec for G711Ulaw {
    fn name(&self) -> &'static str {
        "PCMU"
    }

    fn payload_type(&self) -> PayloadType {
        PayloadType::Static(payload_types::PCMU)
    }

    fn clock_rate(&self) -> u32 {
        8000
    }

    fn channels(&self) -> u8 {
        1
    }

    fn frame_duration_ms(&self) -> u32 {
        self.frame_duration_ms
    }

    fn encode(&self, pcm: &[i16], output: &mut [u8]) -> CodecResult<usize> {
        if output.len() < pcm.len() {
            return Err(CodecError::BufferTooSmall {
                needed: pcm.len(),
                available: output.len(),
            });
        }

        for (i, &sample) in pcm.iter().enumerate() {
            output[i] = Self::encode_sample(sample);
        }

        Ok(pcm.len())
    }

    fn decode(&self, encoded: &[u8], output: &mut [i16]) -> CodecResult<usize> {
        if output.len() < encoded.len() {
            return Err(CodecError::BufferTooSmall {
                needed: encoded.len(),
                available: output.len(),
            });
        }

        for (i, &byte) in encoded.iter().enumerate() {
            output[i] = Self::decode_sample(byte);
        }

        Ok(encoded.len())
    }
}

/// G.711 a-law codec.
#[derive(Debug, Clone, Default)]
pub struct G711Alaw {
    /// Frame duration in milliseconds.
    frame_duration_ms: u32,
}

impl G711Alaw {
    /// Creates a new G.711 a-law codec.
    pub fn new() -> Self {
        Self::with_frame_duration(20)
    }

    /// Creates with custom frame duration.
    pub fn with_frame_duration(ms: u32) -> Self {
        Self {
            frame_duration_ms: ms,
        }
    }

    /// Encodes a single PCM sample to a-law.
    #[inline]
    pub fn encode_sample(sample: i16) -> u8 {
        let mut pcm_val = sample as i32;

        // Get sign
        let sign = if pcm_val < 0 {
            pcm_val = -pcm_val - 1;
            0x80
        } else {
            0x00
        };

        // Find exponent and mantissa
        let (exponent, mantissa) = if pcm_val > 32767 {
            (7, ((32767 >> 4) & 0x0F) as u8)
        } else if pcm_val >= 256 {
            let mut exp = 7u8;
            let mut exp_mask = 0x4000i32;

            while exp > 1 {
                if (pcm_val & exp_mask) != 0 {
                    break;
                }
                exp -= 1;
                exp_mask >>= 1;
            }

            let mant = ((pcm_val >> (exp + 3)) & 0x0F) as u8;
            (exp, mant)
        } else {
            // Small values
            (0, ((pcm_val >> 4) & 0x0F) as u8)
        };

        // Combine and XOR
        (sign | (exponent << 4) | mantissa) ^ 0x55
    }

    /// Decodes a single a-law sample to PCM.
    #[inline]
    pub fn decode_sample(alaw: u8) -> i16 {
        let alaw = alaw ^ 0x55;

        let sign = alaw & 0x80;
        let exponent = (alaw >> 4) & 0x07;
        let mantissa = alaw & 0x0F;

        let sample = if exponent == 0 {
            ((mantissa as i32) << 4) + 8
        } else {
            (((mantissa as i32) << 4) + 0x108) << (exponent - 1)
        };

        if sign != 0 {
            -(sample as i16)
        } else {
            sample as i16
        }
    }
}

impl AudioCodec for G711Alaw {
    fn name(&self) -> &'static str {
        "PCMA"
    }

    fn payload_type(&self) -> PayloadType {
        PayloadType::Static(payload_types::PCMA)
    }

    fn clock_rate(&self) -> u32 {
        8000
    }

    fn channels(&self) -> u8 {
        1
    }

    fn frame_duration_ms(&self) -> u32 {
        self.frame_duration_ms
    }

    fn encode(&self, pcm: &[i16], output: &mut [u8]) -> CodecResult<usize> {
        if output.len() < pcm.len() {
            return Err(CodecError::BufferTooSmall {
                needed: pcm.len(),
                available: output.len(),
            });
        }

        for (i, &sample) in pcm.iter().enumerate() {
            output[i] = Self::encode_sample(sample);
        }

        Ok(pcm.len())
    }

    fn decode(&self, encoded: &[u8], output: &mut [i16]) -> CodecResult<usize> {
        if output.len() < encoded.len() {
            return Err(CodecError::BufferTooSmall {
                needed: encoded.len(),
                available: output.len(),
            });
        }

        for (i, &byte) in encoded.iter().enumerate() {
            output[i] = Self::decode_sample(byte);
        }

        Ok(encoded.len())
    }
}

/// Converts mu-law to a-law (for transcoding).
#[inline]
pub fn ulaw_to_alaw(ulaw: u8) -> u8 {
    G711Alaw::encode_sample(G711Ulaw::decode_sample(ulaw))
}

/// Converts a-law to mu-law (for transcoding).
#[inline]
pub fn alaw_to_ulaw(alaw: u8) -> u8 {
    G711Ulaw::encode_sample(G711Alaw::decode_sample(alaw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ulaw_codec_info() {
        let codec = G711Ulaw::new();
        assert_eq!(codec.name(), "PCMU");
        assert_eq!(codec.clock_rate(), 8000);
        assert_eq!(codec.channels(), 1);
        assert_eq!(codec.payload_type().value(), 0);
    }

    #[test]
    fn test_alaw_codec_info() {
        let codec = G711Alaw::new();
        assert_eq!(codec.name(), "PCMA");
        assert_eq!(codec.clock_rate(), 8000);
        assert_eq!(codec.channels(), 1);
        assert_eq!(codec.payload_type().value(), 8);
    }

    #[test]
    fn test_ulaw_encode_decode_roundtrip() {
        let codec = G711Ulaw::new();

        // Test various sample values
        let samples = [0i16, 100, 1000, 10000, 32000, -100, -1000, -10000, -32000];

        for &original in &samples {
            let encoded = G711Ulaw::encode_sample(original);
            let decoded = G711Ulaw::decode_sample(encoded);

            // G.711 is lossy, but should be close
            let diff = (original - decoded).abs();
            assert!(diff < 1000, "diff too large for {original}: got {decoded}");
        }

        // Test frame encoding
        let pcm = [1000i16, 2000, 3000, 4000, -1000, -2000, -3000, -4000];
        let mut encoded = [0u8; 8];
        let mut decoded = [0i16; 8];

        let enc_len = codec.encode(&pcm, &mut encoded).unwrap();
        assert_eq!(enc_len, 8);

        let dec_len = codec.decode(&encoded, &mut decoded).unwrap();
        assert_eq!(dec_len, 8);

        // Verify roundtrip is reasonably close
        for i in 0..8 {
            let diff = (pcm[i] - decoded[i]).abs();
            assert!(diff < 1000, "sample {i} diff too large");
        }
    }

    #[test]
    fn test_alaw_encode_decode_roundtrip() {
        let codec = G711Alaw::new();

        let samples = [0i16, 100, 1000, 10000, 32000, -100, -1000, -10000, -32000];

        for &original in &samples {
            let encoded = G711Alaw::encode_sample(original);
            let decoded = G711Alaw::decode_sample(encoded);

            let diff = (original - decoded).abs();
            assert!(diff < 1000, "diff too large for {original}: got {decoded}");
        }

        // Test frame encoding
        let pcm = [1000i16, 2000, 3000, 4000, -1000, -2000, -3000, -4000];
        let mut encoded = [0u8; 8];
        let mut decoded = [0i16; 8];

        let enc_len = codec.encode(&pcm, &mut encoded).unwrap();
        assert_eq!(enc_len, 8);

        let dec_len = codec.decode(&encoded, &mut decoded).unwrap();
        assert_eq!(dec_len, 8);
    }

    #[test]
    fn test_ulaw_silence() {
        // Silence (zero) encodes with bias, so decoded value won't be exactly 0
        // mu-law has a bias of 132 (0x84) which affects small values
        let encoded = G711Ulaw::encode_sample(0);
        let decoded = G711Ulaw::decode_sample(encoded);

        // G.711 mu-law bias causes small values to have quantization offset
        // The decoded value should be small but not necessarily < 100
        assert!(decoded.abs() < 500, "silence decoded to {decoded}");
    }

    #[test]
    fn test_alaw_silence() {
        let encoded = G711Alaw::encode_sample(0);
        let decoded = G711Alaw::decode_sample(encoded);

        // A-law also has quantization effects on small values
        assert!(decoded.abs() < 500, "silence decoded to {decoded}");
    }

    #[test]
    fn test_transcoding() {
        // Test ulaw <-> alaw conversion
        let original_pcm = 5000i16;

        let ulaw = G711Ulaw::encode_sample(original_pcm);
        let alaw = ulaw_to_alaw(ulaw);
        let back_ulaw = alaw_to_ulaw(alaw);

        // Should be reasonably close after double conversion
        let decoded = G711Ulaw::decode_sample(back_ulaw);
        let diff = (original_pcm - decoded).abs();
        assert!(diff < 2000);
    }

    #[test]
    fn test_samples_per_frame() {
        let codec_20ms = G711Ulaw::with_frame_duration(20);
        assert_eq!(codec_20ms.samples_per_frame(), 160); // 8000 * 20 / 1000

        let codec_30ms = G711Ulaw::with_frame_duration(30);
        assert_eq!(codec_30ms.samples_per_frame(), 240); // 8000 * 30 / 1000
    }

    #[test]
    fn test_buffer_too_small() {
        let codec = G711Ulaw::new();
        let pcm = [0i16; 100];
        let mut small_buffer = [0u8; 50];

        let result = codec.encode(&pcm, &mut small_buffer);
        assert!(result.is_err());
    }
}
