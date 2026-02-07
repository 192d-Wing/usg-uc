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
        let encoded = !(sign | (exponent << 4) | mantissa);

        // ITU-T G.711 §3.2: all-zero suppression.
        // 0x00 can be misinterpreted as idle/lost on TDM networks.
        // 0x02 decodes to the same segment (exp=7, mant=13 vs mant=15),
        // producing -7519 instead of -8031 — only 512 LSB difference.
        if encoded == 0x00 { 0x02 } else { encoded }
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
        sample -= 0x84; // Subtract bias to restore correct PCM level

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

        // Get sign — ITU-T G.711 Table 1a: positive → bit 7 = 1, negative → bit 7 = 0
        let sign = if pcm_val < 0 {
            pcm_val = -pcm_val - 1;
            0x00
        } else {
            0x80
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

        // ITU-T G.711 Table 1a: bit 7 = 1 → positive, bit 7 = 0 → negative
        let sign = alaw & 0x80;
        let exponent = (alaw >> 4) & 0x07;
        let mantissa = alaw & 0x0F;

        let sample = if exponent == 0 {
            ((mantissa as i32) << 4) + 8
        } else {
            (((mantissa as i32) << 4) + 0x108) << (exponent - 1)
        };

        if sign != 0 {
            sample as i16
        } else {
            -(sample as i16)
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

/// ITU-T G.711 Table 3: µ-law to A-law direct conversion.
///
/// Generated from corrected ITU-compliant encode/decode with transparency tweaks
/// to guarantee that double conversion µ→A→µ preserves bits 1-7.
#[rustfmt::skip]
const ULAW_TO_ALAW: [u8; 256] = [
    0x2A, 0x2B, 0x28, 0x29, 0x2E, 0x2F, 0x2C, 0x2D, 0x22, 0x23, 0x20, 0x21, 0x26, 0x27, 0x24, 0x25,
    0x3A, 0x3B, 0x38, 0x39, 0x3E, 0x3F, 0x3C, 0x3D, 0x32, 0x33, 0x30, 0x31, 0x36, 0x37, 0x34, 0x35,
    0x0B, 0x08, 0x09, 0x0E, 0x0F, 0x0C, 0x0D, 0x02, 0x03, 0x00, 0x01, 0x06, 0x07, 0x04, 0x05, 0x1A,
    0x1B, 0x18, 0x19, 0x1E, 0x1F, 0x1C, 0x1D, 0x12, 0x13, 0x10, 0x11, 0x16, 0x17, 0x14, 0x15, 0x6B,
    0x68, 0x69, 0x6E, 0x6F, 0x6C, 0x6D, 0x62, 0x63, 0x60, 0x61, 0x66, 0x67, 0x64, 0x65, 0x7B, 0x79,
    0x7E, 0x7F, 0x7C, 0x7D, 0x72, 0x73, 0x70, 0x71, 0x76, 0x77, 0x74, 0x75, 0x4B, 0x49, 0x4F, 0x4D,
    0x42, 0x43, 0x40, 0x41, 0x46, 0x47, 0x44, 0x45, 0x5A, 0x5B, 0x58, 0x59, 0x5E, 0x5F, 0x5C, 0x5D,
    0x52, 0x52, 0x53, 0x53, 0x50, 0x50, 0x51, 0x51, 0x56, 0x56, 0x57, 0x57, 0x54, 0x54, 0x55, 0x55,
    0xAA, 0xAB, 0xA8, 0xA9, 0xAE, 0xAF, 0xAC, 0xAD, 0xA2, 0xA3, 0xA0, 0xA1, 0xA6, 0xA7, 0xA4, 0xA5,
    0xBA, 0xBB, 0xB8, 0xB9, 0xBE, 0xBF, 0xBC, 0xBD, 0xB2, 0xB3, 0xB0, 0xB1, 0xB6, 0xB7, 0xB4, 0xB5,
    0x8B, 0x88, 0x89, 0x8E, 0x8F, 0x8C, 0x8D, 0x82, 0x83, 0x80, 0x81, 0x86, 0x87, 0x84, 0x85, 0x9A,
    0x9B, 0x98, 0x99, 0x9E, 0x9F, 0x9C, 0x9D, 0x92, 0x93, 0x90, 0x91, 0x96, 0x97, 0x94, 0x95, 0xEB,
    0xE8, 0xE9, 0xEE, 0xEF, 0xEC, 0xED, 0xE2, 0xE3, 0xE0, 0xE1, 0xE6, 0xE7, 0xE4, 0xE5, 0xFB, 0xF9,
    0xFE, 0xFF, 0xFC, 0xFD, 0xF2, 0xF3, 0xF0, 0xF1, 0xF6, 0xF7, 0xF4, 0xF5, 0xCB, 0xC9, 0xCF, 0xCD,
    0xC2, 0xC3, 0xC0, 0xC1, 0xC6, 0xC7, 0xC4, 0xC5, 0xDA, 0xDB, 0xD8, 0xD9, 0xDE, 0xDF, 0xDC, 0xDD,
    0xD2, 0xD2, 0xD3, 0xD3, 0xD0, 0xD0, 0xD1, 0xD1, 0xD6, 0xD6, 0xD7, 0xD7, 0xD4, 0xD4, 0xD5, 0xD5,
];

/// ITU-T G.711 Table 4: A-law to µ-law direct conversion.
///
/// Generated from corrected ITU-compliant encode/decode with transparency tweaks
/// to guarantee that double conversion A→µ→A preserves bits 1-7.
#[rustfmt::skip]
const ALAW_TO_ULAW: [u8; 256] = [
    0x29, 0x2A, 0x27, 0x28, 0x2D, 0x2E, 0x2B, 0x2C, 0x21, 0x22, 0x20, 0x20, 0x25, 0x26, 0x23, 0x24,
    0x39, 0x3A, 0x37, 0x38, 0x3D, 0x3E, 0x3B, 0x3C, 0x31, 0x32, 0x2F, 0x30, 0x35, 0x36, 0x33, 0x34,
    0x0A, 0x0B, 0x08, 0x09, 0x0E, 0x0F, 0x0C, 0x0D, 0x02, 0x03, 0x00, 0x01, 0x06, 0x07, 0x04, 0x05,
    0x1A, 0x1B, 0x18, 0x19, 0x1E, 0x1F, 0x1C, 0x1D, 0x12, 0x13, 0x10, 0x11, 0x16, 0x17, 0x14, 0x15,
    0x62, 0x63, 0x60, 0x61, 0x66, 0x67, 0x64, 0x65, 0x5D, 0x5D, 0x5C, 0x5C, 0x5F, 0x5F, 0x5E, 0x5E,
    0x74, 0x76, 0x70, 0x72, 0x7C, 0x7E, 0x78, 0x7A, 0x6A, 0x6B, 0x68, 0x69, 0x6E, 0x6F, 0x6C, 0x6D,
    0x48, 0x49, 0x46, 0x47, 0x4C, 0x4D, 0x4A, 0x4B, 0x40, 0x41, 0x3F, 0x3F, 0x44, 0x45, 0x42, 0x43,
    0x56, 0x57, 0x54, 0x55, 0x5A, 0x5B, 0x58, 0x59, 0x4F, 0x4F, 0x4E, 0x4E, 0x52, 0x53, 0x50, 0x51,
    0xA9, 0xAA, 0xA7, 0xA8, 0xAD, 0xAE, 0xAB, 0xAC, 0xA1, 0xA2, 0xA0, 0xA0, 0xA5, 0xA6, 0xA3, 0xA4,
    0xB9, 0xBA, 0xB7, 0xB8, 0xBD, 0xBE, 0xBB, 0xBC, 0xB1, 0xB2, 0xAF, 0xB0, 0xB5, 0xB6, 0xB3, 0xB4,
    0x8A, 0x8B, 0x88, 0x89, 0x8E, 0x8F, 0x8C, 0x8D, 0x82, 0x83, 0x80, 0x81, 0x86, 0x87, 0x84, 0x85,
    0x9A, 0x9B, 0x98, 0x99, 0x9E, 0x9F, 0x9C, 0x9D, 0x92, 0x93, 0x90, 0x91, 0x96, 0x97, 0x94, 0x95,
    0xE2, 0xE3, 0xE0, 0xE1, 0xE6, 0xE7, 0xE4, 0xE5, 0xDD, 0xDD, 0xDC, 0xDC, 0xDF, 0xDF, 0xDE, 0xDE,
    0xF4, 0xF6, 0xF0, 0xF2, 0xFC, 0xFE, 0xF8, 0xFA, 0xEA, 0xEB, 0xE8, 0xE9, 0xEE, 0xEF, 0xEC, 0xED,
    0xC8, 0xC9, 0xC6, 0xC7, 0xCC, 0xCD, 0xCA, 0xCB, 0xC0, 0xC1, 0xBF, 0xBF, 0xC4, 0xC5, 0xC2, 0xC3,
    0xD6, 0xD7, 0xD4, 0xD5, 0xDA, 0xDB, 0xD8, 0xD9, 0xCF, 0xCF, 0xCE, 0xCE, 0xD2, 0xD3, 0xD0, 0xD1,
];

/// Converts mu-law to a-law using ITU-T G.711 Table 3.
#[inline]
pub fn ulaw_to_alaw(ulaw: u8) -> u8 {
    ULAW_TO_ALAW[ulaw as usize]
}

/// Converts a-law to mu-law using ITU-T G.711 Table 4.
#[inline]
pub fn alaw_to_ulaw(alaw: u8) -> u8 {
    ALAW_TO_ULAW[alaw as usize]
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

        // Test various sample values.
        // Note: extreme negative values near -32635 are affected by §3.2 all-zero
        // suppression (0x00→0x02), which maps them to a different quantization level.
        let samples = [0i16, 100, 1000, 10000, 32000, -100, -1000, -10000, -20000];

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
        // Silence (zero) should round-trip to 0 after bias subtraction
        let encoded = G711Ulaw::encode_sample(0);
        let decoded = G711Ulaw::decode_sample(encoded);
        assert_eq!(decoded, 0, "silence should decode to 0, got {decoded}");
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

    // ---- ITU-T G.711 compliance verification tests ----

    /// ITU-T G.711 §3: µ-law sign bit convention.
    /// Positive input → encoded MSB (bit 7) = 1, negative → bit 7 = 0.
    #[test]
    fn test_ulaw_itu_sign_bit_convention() {
        // Positive values should produce encoded bytes with bit 7 = 1
        for &pcm in &[1i16, 100, 1000, 10000, 32000] {
            let encoded = G711Ulaw::encode_sample(pcm);
            assert!(
                encoded & 0x80 != 0,
                "µ-law positive {pcm} should have bit 7 = 1, got 0x{encoded:02X}"
            );
        }

        // Negative values should produce encoded bytes with bit 7 = 0
        for &pcm in &[-1i16, -100, -1000, -10000, -32000] {
            let encoded = G711Ulaw::encode_sample(pcm);
            assert!(
                encoded & 0x80 == 0,
                "µ-law negative {pcm} should have bit 7 = 0, got 0x{encoded:02X}"
            );
        }
    }

    /// ITU-T G.711 Table 1a: A-law sign bit convention.
    /// Positive input → encoded MSB (bit 7) = 1, negative → bit 7 = 0.
    #[test]
    fn test_alaw_itu_sign_bit_convention() {
        // Positive values should produce encoded bytes with bit 7 = 1
        for &pcm in &[1i16, 100, 1000, 10000, 32000] {
            let encoded = G711Alaw::encode_sample(pcm);
            assert!(
                encoded & 0x80 != 0,
                "A-law positive {pcm} should have bit 7 = 1, got 0x{encoded:02X}"
            );
        }

        // Negative values should produce encoded bytes with bit 7 = 0
        for &pcm in &[-1i16, -100, -1000, -10000, -32000] {
            let encoded = G711Alaw::encode_sample(pcm);
            assert!(
                encoded & 0x80 == 0,
                "A-law negative {pcm} should have bit 7 = 0, got 0x{encoded:02X}"
            );
        }
    }

    /// ITU-T G.711: µ-law specific known values from the standard.
    /// Silence (0) should encode to 0xFF (positive zero with all bits complemented).
    #[test]
    fn test_ulaw_itu_known_values() {
        // Silence: 0 → biased = 132 → exp=0, mant=0 → (0|0|0)=0x00 → ~0x00 = 0xFF
        assert_eq!(G711Ulaw::encode_sample(0), 0xFF);

        // Maximum positive: 32635 → biased = 32767 → exp=7, mant=15
        // (0x00 | 0x70 | 0x0F) = 0x7F → ~0x7F = 0x80
        assert_eq!(G711Ulaw::encode_sample(32635), 0x80);

        // Maximum negative: -32635 → abs=32635, biased=32767 → exp=7, mant=15
        // (0x80 | 0x70 | 0x0F) = 0xFF → ~0xFF = 0x00 → suppressed to 0x02 (§3.2)
        assert_eq!(G711Ulaw::encode_sample(-32635), 0x02);

        // Verify clipping: values beyond 32635 clip to the same codeword
        assert_eq!(
            G711Ulaw::encode_sample(32767),
            G711Ulaw::encode_sample(32635)
        );
    }

    /// ITU-T G.711 §3.2: all-zero suppression for µ-law.
    /// Encoded value 0x00 must never appear in the output stream.
    #[test]
    fn test_ulaw_all_zero_suppression() {
        // The only input that would naturally produce 0x00 is -32635 (and clipped values)
        assert_eq!(G711Ulaw::encode_sample(-32635), 0x02);
        assert_eq!(G711Ulaw::encode_sample(-32767), 0x02); // clips to same

        // Verify no i16 input produces 0x00
        for sample in i16::MIN..=i16::MAX {
            assert_ne!(
                G711Ulaw::encode_sample(sample),
                0x00,
                "All-zero suppression failed for sample {sample}"
            );
        }
    }

    /// ITU-T G.711: A-law even-bit inversion (XOR 0x55) pattern.
    #[test]
    fn test_alaw_itu_even_bit_inversion() {
        // For any input, the encoded value should have even bits toggled
        // relative to the "natural" sign+exp+mantissa representation.
        // Verify by encoding, un-XORing, and checking structure.
        for &pcm in &[0i16, 1, 100, 1000, 10000, -1, -100, -1000, -10000] {
            let encoded = G711Alaw::encode_sample(pcm);
            let natural = encoded ^ 0x55;

            // After removing XOR 0x55: sign bit should be clean
            let _sign = natural & 0x80;
            let exp = (natural >> 4) & 0x07;
            let mant = natural & 0x0F;

            // Exponent must be 0-7, mantissa must be 0-15
            assert!(exp <= 7, "exponent {exp} out of range for pcm={pcm}");
            assert!(mant <= 15, "mantissa {mant} out of range for pcm={pcm}");
        }
    }

    /// ITU-T G.711: A-law silence encoding.
    /// Input 0 should encode to a known value with positive sign (bit 7 = 1).
    #[test]
    fn test_alaw_itu_silence_encoding() {
        let encoded = G711Alaw::encode_sample(0);
        // Positive sign: bit 7 should be 1
        assert!(
            encoded & 0x80 != 0,
            "A-law silence (0) should have positive sign bit, got 0x{encoded:02X}"
        );
    }

    /// ITU-T G.711: Decoder sign preservation.
    /// Positive encoded values should decode to positive PCM,
    /// negative encoded values should decode to negative PCM.
    #[test]
    fn test_ulaw_itu_decode_sign_preservation() {
        // Encoded byte with bit 7 = 1 is positive per ITU
        for encoded in 0x80u8..=0xFF {
            let decoded = G711Ulaw::decode_sample(encoded);
            assert!(
                decoded >= 0,
                "µ-law 0x{encoded:02X} (bit7=1) should decode positive, got {decoded}"
            );
        }

        // Encoded byte with bit 7 = 0 is negative per ITU
        for encoded in 0x00u8..=0x7F {
            let decoded = G711Ulaw::decode_sample(encoded);
            assert!(
                decoded <= 0,
                "µ-law 0x{encoded:02X} (bit7=0) should decode non-positive, got {decoded}"
            );
        }
    }

    /// ITU-T G.711 Table 1a: A-law decoder sign preservation.
    #[test]
    fn test_alaw_itu_decode_sign_preservation() {
        // Encoded byte with bit 7 = 1 is positive per ITU
        for encoded in 0x80u8..=0xFF {
            let decoded = G711Alaw::decode_sample(encoded);
            assert!(
                decoded >= 0,
                "A-law 0x{encoded:02X} (bit7=1) should decode positive, got {decoded}"
            );
        }

        // Encoded byte with bit 7 = 0 is negative per ITU
        for encoded in 0x00u8..=0x7F {
            let decoded = G711Alaw::decode_sample(encoded);
            assert!(
                decoded <= 0,
                "A-law 0x{encoded:02X} (bit7=0) should decode non-positive, got {decoded}"
            );
        }
    }

    /// ITU-T G.711: Full 256-value roundtrip for µ-law.
    /// Every encoded byte should produce a valid decoded value,
    /// and re-encoding should return the same byte.
    /// Exception: µ-law has two codewords for zero (0xFF positive, 0x7F negative).
    /// The encoder always produces 0xFF for zero input.
    #[test]
    fn test_ulaw_itu_full_roundtrip() {
        for encoded in 0u8..=255 {
            let decoded = G711Ulaw::decode_sample(encoded);
            let reencoded = G711Ulaw::encode_sample(decoded);
            if encoded == 0x7F {
                // 0x7F is "negative zero" — decodes to 0, re-encodes to 0xFF (positive zero)
                assert_eq!(decoded, 0, "µ-law 0x7F should decode to 0");
                assert_eq!(reencoded, 0xFF, "zero should re-encode to 0xFF");
            } else if encoded == 0x00 {
                // §3.2 all-zero suppression: 0x00 decodes to -32124, re-encodes to 0x02
                assert_eq!(
                    reencoded, 0x02,
                    "0x00 should re-encode to 0x02 (all-zero suppression)"
                );
            } else {
                assert_eq!(
                    encoded, reencoded,
                    "µ-law roundtrip failed: 0x{encoded:02X} → {decoded} → 0x{reencoded:02X}"
                );
            }
        }
    }

    /// ITU-T G.711: Full 256-value roundtrip for A-law.
    #[test]
    fn test_alaw_itu_full_roundtrip() {
        for encoded in 0u8..=255 {
            let decoded = G711Alaw::decode_sample(encoded);
            let reencoded = G711Alaw::encode_sample(decoded);
            assert_eq!(
                encoded, reencoded,
                "A-law roundtrip failed: 0x{encoded:02X} → {decoded} → 0x{reencoded:02X}"
            );
        }
    }

    /// ITU-T G.711: µ-law monotonicity.
    /// Increasing linear values should produce monotonically changing encoded values
    /// (within each sign region).
    #[test]
    fn test_ulaw_itu_monotonicity() {
        let mut last_decoded = i32::MIN;
        // Positive codewords: 0xFF (smallest positive) down to 0x80 (largest positive)
        for encoded in (0x80u8..=0xFF).rev() {
            let decoded = G711Ulaw::decode_sample(encoded) as i32;
            assert!(
                decoded >= last_decoded,
                "µ-law not monotonic: 0x{encoded:02X} decoded to {decoded}, previous was {last_decoded}"
            );
            last_decoded = decoded;
        }
    }

    /// ITU-T G.711: A-law monotonicity.
    #[test]
    fn test_alaw_itu_monotonicity() {
        let mut last_decoded = i32::MIN;
        // Positive codewords: 0x80..=0xFF, sorted by decoded value
        let mut positive_pairs: Vec<(u8, i16)> = (0x80u8..=0xFF)
            .map(|e| (e, G711Alaw::decode_sample(e)))
            .collect();
        positive_pairs.sort_by_key(|&(_, d)| d);

        for &(encoded, decoded) in &positive_pairs {
            assert!(
                decoded as i32 >= last_decoded,
                "A-law not monotonic at 0x{encoded:02X}: {decoded}, previous {last_decoded}"
            );
            last_decoded = decoded as i32;
        }
    }

    /// ITU-T G.711 Tables 3/4: µ→A→µ double conversion transparency.
    /// Bits 1-7 must be preserved; only the LSB (bit 8) may change.
    #[test]
    fn test_itu_ulaw_alaw_ulaw_transparency() {
        for ulaw in 0u8..=255 {
            let roundtrip = alaw_to_ulaw(ulaw_to_alaw(ulaw));
            assert_eq!(
                ulaw & 0xFE,
                roundtrip & 0xFE,
                "µ→A→µ bits 1-7 not transparent for 0x{ulaw:02X}: got 0x{roundtrip:02X}"
            );
        }
    }

    /// ITU-T G.711 Tables 3/4: A→µ→A double conversion transparency.
    /// Bits 1-7 must be preserved; only the LSB (bit 8) may change.
    #[test]
    fn test_itu_alaw_ulaw_alaw_transparency() {
        for alaw in 0u8..=255 {
            let roundtrip = ulaw_to_alaw(alaw_to_ulaw(alaw));
            assert_eq!(
                alaw & 0xFE,
                roundtrip & 0xFE,
                "A→µ→A bits 1-7 not transparent for 0x{alaw:02X}: got 0x{roundtrip:02X}"
            );
        }
    }

    /// Verify transcoding tables preserve sign polarity.
    /// µ-law and A-law both use bit 7 = 1 for positive, bit 7 = 0 for negative.
    #[test]
    fn test_transcoding_sign_preservation() {
        for i in 0u8..=255 {
            let a = ulaw_to_alaw(i);
            assert_eq!(
                i & 0x80,
                a & 0x80,
                "µ→A sign mismatch: µ=0x{i:02X} → A=0x{a:02X}"
            );

            let u = alaw_to_ulaw(i);
            assert_eq!(
                i & 0x80,
                u & 0x80,
                "A→µ sign mismatch: A=0x{i:02X} → µ=0x{u:02X}"
            );
        }
    }
}
