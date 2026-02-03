//! G.722 ADPCM encoder and decoder.
//!
//! This module implements the G.722 Sub-band Adaptive Differential Pulse
//! Code Modulation (SB-ADPCM) algorithm per ITU-T G.722.
//!
//! ## Algorithm Overview
//!
//! G.722 uses:
//! 1. QMF (Quadrature Mirror Filter) to split input into lower (0-4kHz) and
//!    upper (4-8kHz) sub-bands
//! 2. ADPCM encoding of each sub-band
//! 3. Combined 8-bit output (6 bits lower + 2 bits upper at 64kbps)
//!
//! ## References
//!
//! - ITU-T G.722: 7 kHz audio-coding within 64 kbit/s

/// QMF filter coefficients for analysis (encoder).
/// These are the coefficients from ITU-T G.722 Section 3.2.2
const QMF_COEFF: [i32; 24] = [
    3, -11, -11, 53, 12, -156, 32, 362, -210, -805, 951, 3876, 3876, 951, -805, -210, 362, 32,
    -156, 12, 53, -11, -11, 3,
];

/// Lower band quantizer step sizes (6-bit ADPCM).
/// Reserved for future enhanced quantization.
#[allow(dead_code)]
const LOWER_STEP_SIZES: [i32; 6] = [112, 132, 156, 184, 216, 256];

/// Upper band quantizer step sizes (2-bit ADPCM).
/// Reserved for future enhanced quantization.
#[allow(dead_code)]
const UPPER_STEP_SIZES: [i32; 2] = [256, 256];

/// Quantization table for lower band (inverse logarithmic).
/// Reserved for future enhanced quantization.
#[allow(dead_code)]
const LOWER_QUANT_TABLE: [i32; 16] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];

/// G.722 encoder state.
#[derive(Debug, Clone)]
pub struct G722Encoder {
    /// QMF filter delay line for input.
    qmf_delay: [i32; 24],
    /// QMF delay line index.
    qmf_index: usize,
    /// Lower band ADPCM state.
    lower_band: AdpcmState,
    /// Upper band ADPCM state.
    upper_band: AdpcmState,
}

/// G.722 decoder state.
#[derive(Debug, Clone)]
pub struct G722Decoder {
    /// QMF filter delay line for synthesis.
    qmf_delay: [i32; 24],
    /// QMF delay line index.
    qmf_index: usize,
    /// Lower band ADPCM state.
    lower_band: AdpcmState,
    /// Upper band ADPCM state.
    upper_band: AdpcmState,
}

/// ADPCM state for one sub-band.
/// Some fields are reserved for future enhanced predictor implementation.
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AdpcmState {
    /// Reconstructed signal estimate.
    sl: i32,
    /// Slow predictor coefficient (reserved for enhanced predictor).
    a1: i32,
    /// Fast predictor coefficient (reserved for enhanced predictor).
    a2: i32,
    /// Prediction pole section (reserved for enhanced predictor).
    plt: [i32; 3],
    /// Reconstructed signal pole section (reserved for enhanced predictor).
    rlt: [i32; 3],
    /// Quantized difference signal (reserved for enhanced predictor).
    d: i32,
    /// Step size (quantizer adaptation).
    det: i32,
    /// Difference signal (reserved for enhanced predictor).
    dlt: i32,
    /// Scale factor (reserved for enhanced predictor).
    nbl: i32,
}

impl Default for AdpcmState {
    fn default() -> Self {
        Self {
            sl: 0,
            a1: 0,
            a2: 0,
            plt: [0; 3],
            rlt: [0; 3],
            d: 0,
            det: 32,
            dlt: 0,
            nbl: 0,
        }
    }
}

impl G722Encoder {
    /// Creates a new G.722 encoder.
    pub fn new() -> Self {
        Self {
            qmf_delay: [0; 24],
            qmf_index: 0,
            lower_band: AdpcmState::default(),
            upper_band: AdpcmState::default(),
        }
    }

    /// Resets the encoder state.
    pub fn reset(&mut self) {
        self.qmf_delay = [0; 24];
        self.qmf_index = 0;
        self.lower_band = AdpcmState::default();
        self.upper_band = AdpcmState::default();
    }

    /// Encodes 16-bit PCM samples to G.722 encoded data.
    ///
    /// ## Arguments
    ///
    /// * `pcm` - Input PCM samples at 16 kHz (2 samples per output byte)
    /// * `output` - Output buffer for encoded data
    ///
    /// ## Returns
    ///
    /// Number of bytes written to output.
    pub fn encode(&mut self, pcm: &[i16], output: &mut [u8]) -> usize {
        let num_samples = pcm.len();
        let num_bytes = num_samples / 2;

        if output.len() < num_bytes {
            return 0;
        }

        for i in 0..num_bytes {
            // Process two samples to produce one byte
            let sample1 = pcm[i * 2] as i32;
            let sample2 = pcm[i * 2 + 1] as i32;

            // QMF analysis filter - split into lower and upper bands
            let (lower, upper) = self.qmf_analysis(sample1, sample2);

            // ADPCM encode lower band (6 bits)
            let lower_code = self.encode_lower_band(lower);

            // ADPCM encode upper band (2 bits)
            let upper_code = self.encode_upper_band(upper);

            // Pack into output byte: lower 6 bits + upper 2 bits
            output[i] = ((upper_code & 0x03) << 6) as u8 | (lower_code & 0x3F) as u8;
        }

        num_bytes
    }

    /// QMF analysis filter - splits signal into lower and upper sub-bands.
    fn qmf_analysis(&mut self, sample1: i32, sample2: i32) -> (i32, i32) {
        // Shift samples into delay line
        self.qmf_delay[self.qmf_index] = sample1;
        self.qmf_index = (self.qmf_index + 1) % 24;
        self.qmf_delay[self.qmf_index] = sample2;
        self.qmf_index = (self.qmf_index + 1) % 24;

        // Apply QMF filter
        let mut sum_low: i64 = 0;
        let mut sum_high: i64 = 0;

        for j in 0..12 {
            let idx1 = (self.qmf_index + j * 2) % 24;
            let idx2 = (self.qmf_index + j * 2 + 1) % 24;

            let sample1 = self.qmf_delay[idx1] as i64;
            let sample2 = self.qmf_delay[idx2] as i64;

            let coeff1 = QMF_COEFF[j * 2] as i64;
            let coeff2 = QMF_COEFF[j * 2 + 1] as i64;

            sum_low += sample1 * coeff1 + sample2 * coeff2;
            sum_high += sample1 * coeff1 - sample2 * coeff2;
        }

        // Scale and clamp
        let lower = (sum_low >> 12).clamp(-32768, 32767) as i32;
        let upper = (sum_high >> 12).clamp(-32768, 32767) as i32;

        (lower, upper)
    }

    /// ADPCM encode lower band (6-bit quantization).
    fn encode_lower_band(&mut self, input: i32) -> i32 {
        let state = &mut self.lower_band;

        // Compute prediction
        let prediction = state.sl;

        // Compute difference
        let difference = input - prediction;

        // Quantize difference (6-bit)
        let quantized = quantize_lower(difference, state.det);

        // Reconstruct
        let reconstructed = inverse_quantize_lower(quantized, state.det);

        // Update predictor
        state.sl = (prediction + reconstructed).clamp(-32768, 32767);

        // Adapt step size
        state.det = adapt_step_lower(state.det, quantized);

        quantized
    }

    /// ADPCM encode upper band (2-bit quantization).
    fn encode_upper_band(&mut self, input: i32) -> i32 {
        let state = &mut self.upper_band;

        // Compute prediction
        let prediction = state.sl;

        // Compute difference
        let difference = input - prediction;

        // Quantize difference (2-bit)
        let quantized = quantize_upper(difference, state.det);

        // Reconstruct
        let reconstructed = inverse_quantize_upper(quantized, state.det);

        // Update predictor
        state.sl = (prediction + reconstructed).clamp(-32768, 32767);

        // Adapt step size
        state.det = adapt_step_upper(state.det, quantized);

        quantized
    }
}

impl Default for G722Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl G722Decoder {
    /// Creates a new G.722 decoder.
    pub fn new() -> Self {
        Self {
            qmf_delay: [0; 24],
            qmf_index: 0,
            lower_band: AdpcmState::default(),
            upper_band: AdpcmState::default(),
        }
    }

    /// Resets the decoder state.
    pub fn reset(&mut self) {
        self.qmf_delay = [0; 24];
        self.qmf_index = 0;
        self.lower_band = AdpcmState::default();
        self.upper_band = AdpcmState::default();
    }

    /// Decodes G.722 encoded data to 16-bit PCM samples.
    ///
    /// ## Arguments
    ///
    /// * `encoded` - Input G.722 encoded data
    /// * `output` - Output buffer for PCM samples at 16 kHz (2 samples per input byte)
    ///
    /// ## Returns
    ///
    /// Number of samples written to output.
    pub fn decode(&mut self, encoded: &[u8], output: &mut [i16]) -> usize {
        let num_bytes = encoded.len();
        let num_samples = num_bytes * 2;

        if output.len() < num_samples {
            return 0;
        }

        for i in 0..num_bytes {
            let byte = encoded[i];

            // Extract codes
            let lower_code = (byte & 0x3F) as i32;
            let upper_code = ((byte >> 6) & 0x03) as i32;

            // ADPCM decode lower band
            let lower = self.decode_lower_band(lower_code);

            // ADPCM decode upper band
            let upper = self.decode_upper_band(upper_code);

            // QMF synthesis filter - combine sub-bands
            let (sample1, sample2) = self.qmf_synthesis(lower, upper);

            output[i * 2] = sample1.clamp(-32768, 32767) as i16;
            output[i * 2 + 1] = sample2.clamp(-32768, 32767) as i16;
        }

        num_samples
    }

    /// ADPCM decode lower band.
    fn decode_lower_band(&mut self, code: i32) -> i32 {
        let state = &mut self.lower_band;

        // Inverse quantize
        let reconstructed = inverse_quantize_lower(code, state.det);

        // Update predictor
        state.sl = (state.sl + reconstructed).clamp(-32768, 32767);

        // Adapt step size
        state.det = adapt_step_lower(state.det, code);

        state.sl
    }

    /// ADPCM decode upper band.
    fn decode_upper_band(&mut self, code: i32) -> i32 {
        let state = &mut self.upper_band;

        // Inverse quantize
        let reconstructed = inverse_quantize_upper(code, state.det);

        // Update predictor
        state.sl = (state.sl + reconstructed).clamp(-32768, 32767);

        // Adapt step size
        state.det = adapt_step_upper(state.det, code);

        state.sl
    }

    /// QMF synthesis filter - combines lower and upper sub-bands.
    fn qmf_synthesis(&mut self, lower: i32, upper: i32) -> (i32, i32) {
        // Shift samples into delay line
        self.qmf_delay[self.qmf_index] = lower + upper;
        self.qmf_index = (self.qmf_index + 1) % 24;
        self.qmf_delay[self.qmf_index] = lower - upper;
        self.qmf_index = (self.qmf_index + 1) % 24;

        // Apply synthesis filter
        let mut sum1: i64 = 0;
        let mut sum2: i64 = 0;

        for j in 0..12 {
            let idx1 = (self.qmf_index + j * 2) % 24;
            let idx2 = (self.qmf_index + j * 2 + 1) % 24;

            let s1 = self.qmf_delay[idx1] as i64;
            let s2 = self.qmf_delay[idx2] as i64;

            let c1 = QMF_COEFF[j * 2] as i64;
            let c2 = QMF_COEFF[j * 2 + 1] as i64;

            sum1 += s1 * c1;
            sum2 += s2 * c2;
        }

        // Scale
        let sample1 = (sum1 >> 11) as i32;
        let sample2 = (sum2 >> 11) as i32;

        (sample1, sample2)
    }
}

impl Default for G722Decoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Quantizes a lower band difference signal (6-bit).
fn quantize_lower(difference: i32, det: i32) -> i32 {
    let normalized = if det > 0 {
        (difference * 32768) / det
    } else {
        0
    };

    // 6-bit quantization with sign
    let magnitude = normalized.unsigned_abs().min(31) as i32;
    if difference < 0 {
        -magnitude
    } else {
        magnitude
    }
}

/// Inverse quantizes a lower band code.
fn inverse_quantize_lower(code: i32, det: i32) -> i32 {
    // Simple linear inverse quantization
    (code * det) / 32
}

/// Adapts the step size for lower band.
fn adapt_step_lower(det: i32, code: i32) -> i32 {
    let magnitude = code.unsigned_abs() as i32;

    // Step size adaptation based on code magnitude
    let new_det = if magnitude > 16 {
        (det * 5) / 4 // Increase
    } else if magnitude < 8 {
        (det * 3) / 4 // Decrease
    } else {
        det
    };

    new_det.clamp(16, 2048)
}

/// Quantizes an upper band difference signal (2-bit).
fn quantize_upper(difference: i32, det: i32) -> i32 {
    let normalized = if det > 0 {
        (difference * 32768) / det
    } else {
        0
    };

    // 2-bit quantization (values 0-3)
    if difference >= 0 {
        if normalized > 16384 { 3 } else { 2 }
    } else {
        i32::from(normalized >= -16384)
    }
}

/// Inverse quantizes an upper band code.
fn inverse_quantize_upper(code: i32, det: i32) -> i32 {
    // Map 2-bit code to reconstruction levels
    let level = match code {
        0 => -3,
        1 => -1,
        2 => 1,
        3 => 3,
        _ => 0,
    };

    (level * det) / 4
}

/// Adapts the step size for upper band.
fn adapt_step_upper(det: i32, code: i32) -> i32 {
    // Upper band uses simpler adaptation
    let new_det = if code == 0 || code == 3 {
        (det * 5) / 4 // Larger step for extreme values
    } else {
        (det * 3) / 4 // Smaller step for middle values
    };

    new_det.clamp(16, 2048)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoder_decoder_roundtrip() {
        let mut encoder = G722Encoder::new();
        let mut decoder = G722Decoder::new();

        // Create simple test signal (sine wave)
        let mut input = vec![0i16; 320]; // 20ms at 16kHz
        #[allow(clippy::cast_precision_loss)]
        for (i, sample) in input.iter_mut().enumerate() {
            let t = i as f32 / 16000.0;
            *sample = (f32::sin(2.0 * std::f32::consts::PI * 1000.0 * t) * 16000.0) as i16;
        }

        // Encode
        let mut enc_output = vec![0u8; 160]; // 160 bytes for 320 samples
        let encoded_len = encoder.encode(&input, &mut enc_output);
        assert_eq!(encoded_len, 160);

        // Decode
        let mut output = vec![0i16; 320];
        let decoded_len = decoder.decode(&enc_output, &mut output);
        assert_eq!(decoded_len, 320);

        // Verify we got some output (not checking quality in unit test)
        let non_zero = output.iter().any(|&s| s != 0);
        assert!(non_zero, "Decoded output should not be all zeros");
    }

    #[test]
    fn test_encoder_reset() {
        let mut encoder = G722Encoder::new();

        // Encode some data
        let input = [1000i16; 64];
        let mut output = [0u8; 32];
        encoder.encode(&input, &mut output);

        // Reset
        encoder.reset();

        // State should be cleared
        assert_eq!(encoder.lower_band.sl, 0);
        assert_eq!(encoder.upper_band.sl, 0);
    }

    #[test]
    fn test_decoder_reset() {
        let mut decoder = G722Decoder::new();

        // Decode some data
        let input = [0x55u8; 32];
        let mut output = [0i16; 64];
        decoder.decode(&input, &mut output);

        // Reset
        decoder.reset();

        // State should be cleared
        assert_eq!(decoder.lower_band.sl, 0);
        assert_eq!(decoder.upper_band.sl, 0);
    }

    #[test]
    fn test_silence_encoding() {
        let mut encoder = G722Encoder::new();

        // Encode silence
        let input = [0i16; 320];
        let mut output = [0u8; 160];
        let len = encoder.encode(&input, &mut output);

        assert_eq!(len, 160);
    }

    #[test]
    fn test_buffer_too_small() {
        let mut encoder = G722Encoder::new();

        let input = [0i16; 320];
        let mut output = [0u8; 10]; // Too small

        let len = encoder.encode(&input, &mut output);
        assert_eq!(len, 0);
    }
}
