//! G.722 Sub-band ADPCM encoder and decoder (ITU-T G.722, 64 kbit/s).
//!
//! Uses QMF analysis/synthesis filters to split 16 kHz audio into lower
//! (0-4 kHz) and upper (4-8 kHz) sub-bands, with 6-bit lower and 2-bit
//! upper ADPCM encoding. Each sub-band uses a 2nd-order pole + 6th-order
//! zero adaptive predictor with logarithmic step size adaptation per
//! ITU-T G.722 Tables 6-11.

// ============================================================
// ITU-T G.722 constant tables
// ============================================================

/// QMF filter coefficients (24-tap, symmetric).
const QMF_COEFF: [i32; 24] = [
    3, -11, -11, 53, 12, -156, 32, 362, -210, -805, 951, 3876, 3876, 951, -805, -210, 362, 32,
    -156, 12, 53, -11, -11, 3,
];

/// Lower band quantizer decision levels (Table 6/G.722).
const Q6: [i32; 32] = [
    0, 35, 72, 110, 150, 190, 233, 276, 323, 370, 422, 473, 530, 587, 650, 714, 786, 858, 940,
    1023, 1121, 1219, 1339, 1458, 1612, 1765, 1980, 2195, 2557, 2919, 0, 0,
];

/// Lower band quantizer output codes for negative input (Table 7/G.722).
const ILN: [i32; 32] = [
    0, 63, 62, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
    10, 9, 8, 7, 6, 5, 4, 0,
];

/// Lower band quantizer output codes for positive input (Table 7/G.722).
const ILP: [i32; 32] = [
    0, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39,
    38, 37, 36, 35, 34, 33, 32, 0,
];

/// Upper band quantizer output codes for negative input.
const IHN: [i32; 3] = [0, 1, 0];

/// Upper band quantizer output codes for positive input.
const IHP: [i32; 3] = [0, 3, 2];

/// 4-bit inverse quantizer multipliers (predictor update path).
const QM4: [i32; 16] = [
    0, -20456, -12896, -8968, -6288, -4240, -2584, -1200, 20456, 12896, 8968, 6288, 4240, 2584,
    1200, 0,
];

/// 6-bit inverse quantizer multipliers (decoder output path, MODE 1 / 64 kbit/s).
const QM6: [i32; 64] = [
    -136, -136, -136, -136, -24808, -21904, -19008, -16704, -14984, -13512, -12280, -11192, -10232,
    -9360, -8576, -7856, -7192, -6576, -6000, -5456, -4944, -4464, -4008, -3576, -3168, -2776,
    -2400, -2032, -1688, -1360, -1040, -728, 24808, 21904, 19008, 16704, 14984, 13512, 12280,
    11192, 10232, 9360, 8576, 7856, 7192, 6576, 6000, 5456, 4944, 4464, 4008, 3576, 3168, 2776,
    2400, 2032, 1688, 1360, 1040, 728, 432, 136, -432, -136,
];

/// 2-bit upper band inverse quantizer multipliers.
const QM2: [i32; 4] = [-7408, -1616, 7408, 1616];

/// Lower band log scale factor adaptation weights (Table 8/G.722).
const WL: [i32; 8] = [-60, -30, 58, 172, 334, 538, 1198, 3042];

/// Upper band log scale factor adaptation weights.
const WH: [i32; 3] = [0, -214, 798];

/// Log-to-linear step size conversion (Table 11/G.722).
const ILB: [i32; 32] = [
    2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714, 2774, 2834,
    2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676, 3756, 3838, 3922, 4008,
];

/// Lower band code-to-log mapping for step adaptation.
const RL42: [i32; 16] = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0];

/// Upper band code-to-log mapping for step adaptation.
const RH2: [i32; 4] = [2, 1, 2, 1];

/// Saturate value to [min, max] range.
#[inline]
fn saturate(v: i32, max: i32, min: i32) -> i32 {
    if v > max {
        max
    } else if v < min {
        min
    } else {
        v
    }
}

// ============================================================
// Sub-band ADPCM state
// ============================================================

/// 2-pole + 6-zero adaptive predictor state for one sub-band.
#[derive(Debug, Clone)]
struct BandState {
    /// Predictor output.
    s: i32,
    /// Linear step size.
    det: i32,
    /// Pole section output.
    spl: i32,
    /// Zero section output.
    szl: i32,
    /// Reconstructed signal history.
    rlt: [i32; 3],
    /// Pole coefficients.
    al: [i32; 3],
    /// Updated pole coefficients (scratch).
    apl: [i32; 3],
    /// Partial reconstruction history.
    plt: [i32; 3],
    /// Quantized difference history.
    dlt: [i32; 7],
    /// Zero coefficients.
    bl: [i32; 7],
    /// Updated zero coefficients (scratch).
    bpl: [i32; 7],
    /// Sign values (scratch).
    sg: [i32; 7],
    /// Log scale factor.
    nb: i32,
}

impl BandState {
    fn new_lower() -> Self {
        Self {
            s: 0,
            det: 32,
            spl: 0,
            szl: 0,
            rlt: [0; 3],
            al: [0; 3],
            apl: [0; 3],
            plt: [0; 3],
            dlt: [0; 7],
            bl: [0; 7],
            bpl: [0; 7],
            sg: [0; 7],
            nb: 0,
        }
    }

    fn new_upper() -> Self {
        Self {
            s: 0,
            det: 8,
            spl: 0,
            szl: 0,
            rlt: [0; 3],
            al: [0; 3],
            apl: [0; 3],
            plt: [0; 3],
            dlt: [0; 7],
            bl: [0; 7],
            bpl: [0; 7],
            sg: [0; 7],
            nb: 0,
        }
    }
}

// ============================================================
// Shared ADPCM building blocks
// ============================================================

/// INVQAL: Inverse quantize lower band for predictor update (4-bit resolution).
#[inline]
fn block2l(il: i32, detl: i32) -> i32 {
    let ril = il >> 2;
    let wd2 = QM4[ril as usize];
    (detl * wd2) >> 15
}

/// INVQAH: Inverse quantize upper band (2-bit).
#[inline]
fn block2h(ih: i32, deth: i32) -> i32 {
    let wd2 = QM2[ih as usize];
    (deth * wd2) >> 15
}

/// LOGSCL + SCALEL: Lower band log scale factor adaptation.
fn block3l(state: &mut BandState, il: i32) -> i32 {
    let ril = il >> 2;
    let il4 = RL42[ril as usize];
    let wd = (state.nb * 32512) >> 15;
    let nbpl = (wd + WL[il4 as usize]).clamp(0, 18432);

    let wd1 = (nbpl >> 6) & 31;
    let wd2 = nbpl >> 11;
    let wd3 = if (8 - wd2) < 0 {
        ILB[wd1 as usize] << (wd2 - 8)
    } else {
        ILB[wd1 as usize] >> (8 - wd2)
    };

    state.nb = nbpl;
    wd3 << 2
}

/// LOGSCH + SCALEH: Upper band log scale factor adaptation.
fn block3h(state: &mut BandState, ih: i32) -> i32 {
    let ih2 = RH2[ih as usize];
    let wd = (state.nb * 32512) >> 15;
    let nbph = (wd + WH[ih2 as usize]).clamp(0, 22528);

    let wd1 = (nbph >> 6) & 31;
    let wd2 = nbph >> 11;
    let wd3 = if (10 - wd2) < 0 {
        ILB[wd1 as usize] << (wd2 - 10)
    } else {
        ILB[wd1 as usize] >> (10 - wd2)
    };

    state.nb = nbph;
    wd3 << 2
}

/// Adaptive predictor update (block4). Returns new predictor output.
///
/// Implements RECONS, PARREC, UPPOL2, UPPOL1, UPZERO, DELAYA, FILTEP,
/// FILTEZ, and PREDIC from ITU-T G.722.
#[allow(clippy::similar_names)]
fn predictor_update(state: &mut BandState, dl: i32) -> i32 {
    let sl = state.s;

    state.dlt[0] = dl;

    // RECONS
    state.rlt[0] = saturate(sl + state.dlt[0], 32767, -32768);

    // PARREC
    state.plt[0] = saturate(state.dlt[0] + state.szl, 32767, -32768);

    // UPPOL2
    state.sg[0] = state.plt[0] >> 15;
    state.sg[1] = state.plt[1] >> 15;
    state.sg[2] = state.plt[2] >> 15;

    let wd1 = saturate(state.al[1] << 2, 32767, -32768);
    let mut wd2 = if state.sg[0] == state.sg[1] {
        -wd1
    } else {
        wd1
    };
    if wd2 > 32767 {
        wd2 = 32767;
    }
    wd2 >>= 7;

    let wd3 = if state.sg[0] == state.sg[2] {
        128
    } else {
        -128
    };
    let wd4 = wd2 + wd3;
    let wd5 = (state.al[2] * 32512) >> 15;
    state.apl[2] = saturate(wd4 + wd5, 12288, -12288);

    // UPPOL1
    state.sg[0] = state.plt[0] >> 15;
    state.sg[1] = state.plt[1] >> 15;

    let wd1 = if state.sg[0] == state.sg[1] {
        192
    } else {
        -192
    };
    let wd2 = (state.al[1] * 32640) >> 15;
    state.apl[1] = saturate(wd1 + wd2, 32767, -32768);

    let wd3 = saturate(15360 - state.apl[2], 32767, -32768);
    if state.apl[1] > wd3 {
        state.apl[1] = wd3;
    }
    if state.apl[1] < -wd3 {
        state.apl[1] = -wd3;
    }

    // UPZERO
    let wd1 = if state.dlt[0] == 0 { 0 } else { 128 };
    state.sg[0] = state.dlt[0] >> 15;

    for i in 1..7 {
        state.sg[i] = state.dlt[i] >> 15;
        let wd2 = if state.sg[i] == state.sg[0] {
            wd1
        } else {
            -wd1
        };
        let wd3 = (state.bl[i] * 32640) >> 15;
        state.bpl[i] = saturate(wd2 + wd3, 32767, -32768);
    }

    // DELAYA
    for i in (1..7).rev() {
        state.dlt[i] = state.dlt[i - 1];
        state.bl[i] = state.bpl[i];
    }
    for i in (1..3).rev() {
        state.rlt[i] = state.rlt[i - 1];
        state.plt[i] = state.plt[i - 1];
        state.al[i] = state.apl[i];
    }

    // FILTEP
    let mut wd1 = saturate(state.rlt[1] << 1, 32767, -32768);
    wd1 = (state.al[1] * wd1) >> 15;
    let mut wd2 = saturate(state.rlt[2] << 1, 32767, -32768);
    wd2 = (state.al[2] * wd2) >> 15;
    state.spl = saturate(wd1 + wd2, 32767, -32768);

    // FILTEZ
    state.szl = 0;
    for i in (1..7).rev() {
        let wd = saturate(state.dlt[i] << 1, 32767, -32768);
        state.szl += (state.bl[i] * wd) >> 15;
        state.szl = saturate(state.szl, 32767, -32768);
    }

    // PREDIC
    saturate(state.spl + state.szl, 32767, -32768)
}

// ============================================================
// Encoder
// ============================================================

/// G.722 encoder state.
#[derive(Debug, Clone)]
pub struct G722Encoder {
    /// QMF analysis filter delay line.
    x: [i32; 24],
    /// Lower band ADPCM state.
    lower: BandState,
    /// Upper band ADPCM state.
    upper: BandState,
}

impl G722Encoder {
    /// Creates a new G.722 encoder.
    pub fn new() -> Self {
        Self {
            x: [0; 24],
            lower: BandState::new_lower(),
            upper: BandState::new_upper(),
        }
    }

    /// Resets the encoder state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Encodes 16-bit PCM samples at 16 kHz to G.722 (2 samples per byte).
    ///
    /// Returns the number of bytes written to `output`.
    pub fn encode(&mut self, pcm: &[i16], output: &mut [u8]) -> usize {
        let num_samples = pcm.len();
        let num_bytes = num_samples / 2;

        if output.len() < num_bytes {
            return 0;
        }

        for i in (0..num_samples & !1).step_by(2) {
            let (xlow, xhigh) = self.tx_qmf(pcm[i] as i32, pcm[i + 1] as i32);

            // Lower band encoder
            let ilow = self.quantize_lower(xlow);
            let dlowt = block2l(ilow, self.lower.det);
            self.lower.det = block3l(&mut self.lower, ilow);
            self.lower.s = predictor_update(&mut self.lower, dlowt);

            // Upper band encoder
            let ihigh = self.quantize_upper(xhigh);
            let dhigh = block2h(ihigh, self.upper.det);
            self.upper.det = block3h(&mut self.upper, ihigh);
            self.upper.s = predictor_update(&mut self.upper, dhigh);

            output[i / 2] = ((ihigh << 6) | ilow) as u8;
        }

        num_bytes
    }

    /// QMF analysis filter (tx_qmf).
    fn tx_qmf(&mut self, pcm1: i32, pcm2: i32) -> (i32, i32) {
        self.x.copy_within(0..22, 2);
        self.x[1] = pcm1;
        self.x[0] = pcm2;

        let mut sumodd: i64 = 0;
        let mut sumeven: i64 = 0;
        for i in (0..24).step_by(2) {
            sumeven += self.x[i] as i64 * QMF_COEFF[i] as i64;
            sumodd += self.x[i + 1] as i64 * QMF_COEFF[i + 1] as i64;
        }

        let lo = saturate(((sumeven + sumodd) >> 13) as i32, 16383, -16384);
        let hi = saturate(((sumeven - sumodd) >> 13) as i32, 16383, -16383);
        (lo, hi)
    }

    /// QUANTL: Lower band quantizer (6-bit, block1l).
    fn quantize_lower(&self, xl: i32) -> i32 {
        let el = saturate(xl - self.lower.s, 32767, -32768);
        let sil = el >> 15;
        let wd = if sil == 0 { el } else { (32767 - el) & 32767 };

        let mut mil = 1;
        #[allow(clippy::needless_range_loop)]
        for i in 1..30 {
            let hdu = ((Q6[i] << 3) as i64) * (self.lower.det as i64);
            let wd1 = (hdu >> 15) as i32;
            if wd >= wd1 {
                mil = i + 1;
            } else {
                break;
            }
        }

        if sil == -1 { ILN[mil] } else { ILP[mil] }
    }

    /// QUANTH: Upper band quantizer (2-bit, block1h).
    fn quantize_upper(&self, xh: i32) -> i32 {
        let eh = saturate(xh - self.upper.s, 32767, -32768);
        let sih = eh >> 15;
        let wd = if sih == 0 { eh } else { (32767 - eh) & 32767 };

        let hdu = (564_i64 << 3) * (self.upper.det as i64);
        let wd1 = (hdu >> 15) as i32;
        let mih = if wd >= wd1 { 2 } else { 1 };

        if sih == -1 { IHN[mih] } else { IHP[mih] }
    }
}

impl Default for G722Encoder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================
// Decoder
// ============================================================

/// G.722 decoder state.
#[derive(Debug, Clone)]
pub struct G722Decoder {
    /// QMF synthesis filter delay line (difference path).
    xd: [i32; 12],
    /// QMF synthesis filter delay line (sum path).
    xs: [i32; 12],
    /// Lower band ADPCM state.
    lower: BandState,
    /// Upper band ADPCM state.
    upper: BandState,
}

impl G722Decoder {
    /// Creates a new G.722 decoder.
    pub fn new() -> Self {
        Self {
            xd: [0; 12],
            xs: [0; 12],
            lower: BandState::new_lower(),
            upper: BandState::new_upper(),
        }
    }

    /// Resets the decoder state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    /// Decodes G.722 encoded data to 16-bit PCM at 16 kHz (1 byte per 2 samples).
    ///
    /// Returns the number of samples written to `output`.
    pub fn decode(&mut self, encoded: &[u8], output: &mut [i16]) -> usize {
        let num_bytes = encoded.len();
        let num_samples = num_bytes * 2;

        if output.len() < num_samples {
            return 0;
        }

        for i in 0..num_bytes {
            let ilowr = (encoded[i] & 63) as i32;
            let ihigh = ((encoded[i] >> 6) & 3) as i32;

            // Lower band: output uses qm6 (full 6-bit), predictor uses qm4 (4-bit)
            let ylow = self.inv_quantize_lower_output(ilowr);
            let rlow = saturate(ylow, 16383, -16384);
            let dlowt = block2l(ilowr, self.lower.det);
            self.lower.det = block3l(&mut self.lower, ilowr);
            self.lower.s = predictor_update(&mut self.lower, dlowt);

            // Upper band
            let dhigh = block2h(ihigh, self.upper.det);
            let rhigh = saturate(dhigh + self.upper.s, 16383, -16384);
            self.upper.det = block3h(&mut self.upper, ihigh);
            self.upper.s = predictor_update(&mut self.upper, dhigh);

            // QMF synthesis
            let (pcm1, pcm2) = self.rx_qmf(rlow, rhigh);
            output[i * 2] = pcm1 as i16;
            output[i * 2 + 1] = pcm2 as i16;
        }

        num_samples
    }

    /// INVQBL: Inverse quantize lower band for output (6-bit, MODE 1 / 64 kbit/s).
    #[inline]
    fn inv_quantize_lower_output(&self, il: i32) -> i32 {
        let wd2 = QM6[il as usize];
        let dl = (self.lower.det * wd2) >> 15;
        saturate(self.lower.s + dl, 32767, -32768)
    }

    /// QMF synthesis filter (rx_qmf).
    fn rx_qmf(&mut self, rl: i32, rh: i32) -> (i32, i32) {
        self.xd.copy_within(0..11, 1);
        self.xs.copy_within(0..11, 1);

        // RECA
        self.xd[0] = saturate(rl - rh, 16383, -16384);
        // RECB
        self.xs[0] = saturate(rl + rh, 16383, -16384);

        // ACCUMC
        let mut xout1: i64 = 0;
        for j in 0..12 {
            xout1 += self.xd[j] as i64 * QMF_COEFF[2 * j] as i64;
        }
        let pcm1 = saturate((xout1 >> 12) as i32, 16383, -16384);

        // ACCUMD
        let mut xout2: i64 = 0;
        for j in 0..12 {
            xout2 += self.xs[j] as i64 * QMF_COEFF[2 * j + 1] as i64;
        }
        let pcm2 = saturate((xout2 >> 12) as i32, 16383, -16384);

        (pcm1, pcm2)
    }
}

impl Default for G722Decoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::cast_precision_loss)]
mod tests {
    use super::*;

    #[test]
    fn test_encoder_decoder_roundtrip() {
        let mut encoder = G722Encoder::new();
        let mut decoder = G722Decoder::new();

        let mut input = vec![0i16; 320]; // 20ms at 16kHz
        #[allow(clippy::cast_precision_loss)]
        for (i, sample) in input.iter_mut().enumerate() {
            let t = i as f32 / 16000.0;
            *sample = (f32::sin(2.0 * std::f32::consts::PI * 1000.0 * t) * 8000.0) as i16;
        }

        let mut enc_output = vec![0u8; 160];
        let encoded_len = encoder.encode(&input, &mut enc_output);
        assert_eq!(encoded_len, 160);

        let mut output = vec![0i16; 320];
        let decoded_len = decoder.decode(&enc_output, &mut output);
        assert_eq!(decoded_len, 320);

        let non_zero = output.iter().any(|&s| s != 0);
        assert!(non_zero, "Decoded output should not be all zeros");
    }

    #[test]
    fn test_encoder_reset() {
        let mut encoder = G722Encoder::new();

        let input = [1000i16; 64];
        let mut output = [0u8; 32];
        encoder.encode(&input, &mut output);

        encoder.reset();
        assert_eq!(encoder.lower.s, 0);
        assert_eq!(encoder.upper.s, 0);
    }

    #[test]
    fn test_decoder_reset() {
        let mut decoder = G722Decoder::new();

        let input = [0x55u8; 32];
        let mut output = [0i16; 64];
        decoder.decode(&input, &mut output);

        decoder.reset();
        assert_eq!(decoder.lower.s, 0);
        assert_eq!(decoder.upper.s, 0);
    }

    #[test]
    fn test_silence_encoding() {
        let mut encoder = G722Encoder::new();

        let input = [0i16; 320];
        let mut output = [0u8; 160];
        let len = encoder.encode(&input, &mut output);
        assert_eq!(len, 160);
    }

    #[test]
    fn test_buffer_too_small() {
        let mut encoder = G722Encoder::new();

        let input = [0i16; 320];
        let mut output = [0u8; 10];
        let len = encoder.encode(&input, &mut output);
        assert_eq!(len, 0);
    }

    #[test]
    fn test_roundtrip_waveform_quality() {
        let mut encoder = G722Encoder::new();
        let mut decoder = G722Decoder::new();

        // Generate 200ms of 440 Hz sine at 16kHz (10 frames)
        let num_frames = 10;
        let frame_samples = 320;
        let total_samples = num_frames * frame_samples;
        #[allow(clippy::cast_precision_loss)]
        let input: Vec<i16> = (0..total_samples)
            .map(|i| {
                let t = i as f32 / 16000.0;
                (8000.0 * (2.0 * std::f32::consts::PI * 440.0 * t).sin()) as i16
            })
            .collect();

        let mut output = vec![0i16; total_samples];
        let mut enc_buf = vec![0u8; frame_samples / 2];

        for frame in 0..num_frames {
            let start = frame * frame_samples;
            let end = start + frame_samples;
            encoder.encode(&input[start..end], &mut enc_buf);
            decoder.decode(&enc_buf, &mut output[start..end]);
        }

        // Verify output is NOT saturated (the pre-fix bug)
        let max_amp = output.iter().map(|s| s.unsigned_abs()).max().unwrap_or(0);
        assert!(
            max_amp < 32767,
            "Output appears saturated (max={max_amp}), decoder bug may persist"
        );

        // Skip first 2 frames for convergence, then find best lag-compensated
        // cross-correlation. The QMF filter bank introduces ~23 samples of group
        // delay, which at 440 Hz can cause a near-half-period phase shift that
        // makes the zero-lag correlation negative.
        let skip = 2 * frame_samples;
        let max_lag = 40;
        let mut best_corr = -1.0_f64;

        for lag in 0..max_lag {
            let cmp_len = total_samples - skip - lag;
            if cmp_len < frame_samples {
                break;
            }

            let a = &input[skip..skip + cmp_len];
            let b = &output[skip + lag..skip + lag + cmp_len];

            let n = cmp_len as f64;
            let mean_a: f64 = a.iter().map(|&s| s as f64).sum::<f64>() / n;
            let mean_b: f64 = b.iter().map(|&s| s as f64).sum::<f64>() / n;
            let mut cov = 0.0_f64;
            let mut var_a = 0.0_f64;
            let mut var_b = 0.0_f64;
            for i in 0..cmp_len {
                let da = a[i] as f64 - mean_a;
                let db = b[i] as f64 - mean_b;
                cov += da * db;
                var_a += da * da;
                var_b += db * db;
            }
            let corr = if var_a > 0.0 && var_b > 0.0 {
                cov / (var_a.sqrt() * var_b.sqrt())
            } else {
                0.0
            };

            if corr > best_corr {
                best_corr = corr;
            }
        }

        assert!(
            best_corr > 0.80,
            "Cross-correlation too low ({best_corr:.4}), expected >0.80 for G.722 roundtrip"
        );
    }
}
