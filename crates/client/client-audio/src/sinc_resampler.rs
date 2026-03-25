//! Sinc resampler for high-quality sample rate conversion.
//!
//! Provides two implementations:
//! - **Polyphase sinc** for integer ratios (e.g., 6:1 for 8kHz→48kHz):
//!   Pre-computed coefficient tables for maximum efficiency.
//! - **Fractional sinc** for arbitrary ratios (e.g., 5.5125:1 for 8kHz→44.1kHz):
//!   On-the-fly kernel evaluation with Kaiser windowing.
//!
//! Both achieve ~50 dB stopband attenuation, eliminating the imaging artifacts
//! ("static"/"hiss") that linear or cubic interpolation produces.
//!
//! The [`Resampler`] enum automatically selects the best implementation for
//! a given input/output rate pair.
//!
//! ## Why not linear interpolation?
//!
//! Linear interpolation for 6:1 upsampling provides only ~13 dB of
//! stopband attenuation. Spectral images of the 4kHz speech signal
//! appear at 4-8kHz, 8-12kHz, etc., at only 13 dB below the original
//! — clearly audible as "static" or "hiss," especially at speech
//! boundaries where the signal has broadband energy.

use std::f64::consts::PI;

#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::{vaddvq_f32, vfmaq_f32, vld1q_f32, vmulq_f32};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{
    _mm_add_ps, _mm_add_ss, _mm_cvtss_f32, _mm_loadu_ps, _mm_movehl_ps, _mm_mul_ps, _mm_shuffle_ps,
};

/// Number of filter taps per polyphase sub-filter.
/// 16 taps with 6 phases = 96 total taps, achieving ~50 dB stopband
/// attenuation. Cost: 16 multiply-adds per output sample (negligible).
const TAPS_PER_PHASE: usize = 16;

/// Kaiser window beta parameter.
/// beta=5.0 yields ~50 dB sidelobe attenuation.
const KAISER_BETA: f64 = 5.0;

/// Number of taps on each side for fractional sinc interpolation.
/// 8 taps each side = 17-point kernel, matching polyphase filter quality.
const FRAC_HALF_TAPS: usize = 8;

// ─── Integer-ratio polyphase sinc resampler ────────────────────────────

/// Polyphase sinc resampler for fixed integer-ratio upsampling.
///
/// Maintains internal state (input history) for seamless cross-frame
/// filtering. Create one instance per audio session and call
/// [`process`](SincResampler::process) for each frame.
///
/// Uses a double-length circular buffer for history: each new sample is
/// written at two positions, so `history[pos..pos+16]` is always a
/// contiguous view. This replaces the previous `copy_within` shift
/// (60 bytes/sample → 8 bytes/sample).
pub struct SincResampler {
    /// Upsampling ratio (e.g., 6 for 8kHz to 48kHz).
    ratio: usize,
    /// Polyphase sub-filter coefficients: `phases[p][k]` is the k-th tap
    /// of the p-th polyphase sub-filter.
    phases: Vec<[f32; TAPS_PER_PHASE]>,
    /// Double-length circular history buffer. Reading at `pos` gives a
    /// contiguous `TAPS_PER_PHASE`-element view (newest at offset 0).
    history: [f32; TAPS_PER_PHASE * 2],
    /// Current write position; decrements on each new sample, wraps to
    /// `TAPS_PER_PHASE - 1` when it underflows.
    pos: usize,
}

impl SincResampler {
    /// Creates a new sinc resampler for the given integer upsampling ratio.
    pub fn new(ratio: usize) -> Self {
        let ratio = ratio.max(1);
        let phases = compute_polyphase_coefficients(ratio);
        Self {
            ratio,
            phases,
            history: [0.0; TAPS_PER_PHASE * 2],
            pos: 0,
        }
    }

    /// Returns a reference to the current history view (contiguous 16-element slice).
    ///
    /// # Safety
    /// `self.pos` is always in `[0, TAPS_PER_PHASE)`, so `pos..pos+TAPS_PER_PHASE`
    /// is always within the 32-element double buffer.
    #[inline]
    #[allow(unsafe_code, clippy::missing_const_for_fn)]
    fn history_view(&self) -> &[f32; TAPS_PER_PHASE] {
        // SAFETY: pos is maintained in [0, TAPS_PER_PHASE) by wrapping logic,
        // so pos + TAPS_PER_PHASE <= 2 * TAPS_PER_PHASE = history.len().
        // The array is contiguous f32 with proper alignment.
        unsafe {
            &*(self
                .history
                .as_ptr()
                .add(self.pos)
                .cast::<[f32; TAPS_PER_PHASE]>())
        }
    }

    /// Inserts a new sample into the circular history buffer.
    #[inline]
    const fn push_sample(&mut self, sample: f32) {
        self.pos = if self.pos == 0 {
            TAPS_PER_PHASE - 1
        } else {
            self.pos - 1
        };
        self.history[self.pos] = sample;
        self.history[self.pos + TAPS_PER_PHASE] = sample;
    }

    /// Resamples the input, producing exactly `input.len() * ratio` output samples.
    ///
    /// The internal history buffer provides seamless cross-frame continuity.
    #[allow(clippy::cast_possible_truncation)]
    pub fn process(&mut self, input: &[i16]) -> Vec<i16> {
        let output_len = input.len() * self.ratio;
        let mut output = Vec::with_capacity(output_len);

        for &sample in input {
            self.push_sample(f32::from(sample));
            let hist = self.history_view();

            // Compute each polyphase output (SIMD-accelerated dot product)
            for phase in &self.phases {
                let sum = dot_product_16(hist, phase);
                output.push(sum.round().clamp(-32768.0, 32767.0) as i16);
            }
        }

        output
    }

    /// Resamples the input with an adjusted output length for drift compensation.
    ///
    /// Produces `output_len` samples (nominally `input.len() * ratio +/- 1`).
    /// The adjustment is handled by truncating or extending the last sample.
    pub fn process_adjusted(&mut self, input: &[i16], output_len: usize) -> Vec<i16> {
        let mut result = self.process(input);
        let nominal = result.len();

        match output_len.cmp(&nominal) {
            std::cmp::Ordering::Equal => {}
            std::cmp::Ordering::Less => {
                result.truncate(output_len);
            }
            std::cmp::Ordering::Greater => {
                let last = result.last().copied().unwrap_or(0);
                result.resize(output_len, last);
            }
        }

        result
    }

    /// Resamples into a caller-provided buffer, avoiding heap allocation.
    ///
    /// Writes exactly `output.len()` samples. The nominal count is
    /// `input.len() * ratio`; drift adjustment truncates or extends as needed.
    #[allow(clippy::cast_possible_truncation)]
    pub fn process_into(&mut self, input: &[i16], output: &mut [i16]) {
        let output_len = output.len();
        let mut out_pos = 0;

        for &sample in input {
            self.push_sample(f32::from(sample));
            let hist = self.history_view();

            for phase in &self.phases {
                if out_pos >= output_len {
                    return;
                }
                let sum = dot_product_16(hist, phase);
                output[out_pos] = sum.round().clamp(-32768.0, 32767.0) as i16;
                out_pos += 1;
            }
        }

        // If output is longer than nominal, extend with last sample
        if out_pos < output_len {
            let last = if out_pos > 0 { output[out_pos - 1] } else { 0 };
            output[out_pos..].fill(last);
        }
    }

    /// Returns the upsampling ratio.
    pub const fn ratio(&self) -> usize {
        self.ratio
    }
}

// ─── Fractional sinc resampler ─────────────────────────────────────────

/// Sinc resampler for arbitrary (non-integer) ratio sample rate conversion.
///
/// Uses direct windowed-sinc interpolation, evaluating a Kaiser-windowed
/// sinc kernel on-the-fly for each output sample. Processes input
/// sample-by-sample (like the polyphase resampler) to ensure the kernel
/// always has full support within the history buffer — no edge artifacts
/// at frame boundaries.
///
/// Introduces a fixed delay of `FRAC_HALF_TAPS` input samples (~1ms at
/// 8kHz) which is imperceptible for `VoIP`.
///
/// For integer ratios, prefer [`SincResampler`] which pre-computes
/// polyphase coefficient tables for better efficiency.
pub struct FractionalSincResampler {
    /// Output/input sample rate ratio (e.g., 5.5125).
    ratio: f64,
    /// Input-domain advance per output sample (1/ratio).
    step: f64,
    /// Double-length circular history buffer. `history[pos..pos+FRAC_HIST_SIZE]`
    /// is always a contiguous view (newest at offset 0).
    history: Vec<f32>,
    /// Current write position; decrements on each new sample.
    hist_pos: usize,
    /// Fractional position within the current input sample interval.
    /// Range: [0, 1). When phase < 1.0, output samples are produced.
    phase: f64,
    /// Pre-computed Kaiser window LUT (replaces per-tap `bessel_i0()` calls).
    kaiser_lut: KaiserLut,
    /// Pre-computed sinc LUT (replaces per-tap `sin()` + division).
    sinc_lut: SincLut,
}

/// History buffer size for fractional resampler: enough for a symmetric
/// kernel with `FRAC_HALF_TAPS` taps on each side, plus the center.
const FRAC_HIST_SIZE: usize = 2 * FRAC_HALF_TAPS + 1;

/// Number of intervals in the Kaiser window lookup table.
/// 1024 intervals gives linear interpolation error < 10⁻⁶ — inaudible.
const KAISER_LUT_INTERVALS: usize = 1024;

/// Number of intervals in the sinc function lookup table.
/// 2048 intervals over [0, `FRAC_HALF_TAPS`] gives step ≈ 0.004,
/// with interpolation error < 3×10⁻⁵ at the steepest point (x≈0).
const SINC_LUT_INTERVALS: usize = 2048;

/// Pre-computed Kaiser window lookup table.
///
/// Maps normalized distance `|x/half| ∈ [0, 1]` to
/// `I₀(β·√(1-u²)) / I₀(β)` via linear interpolation.
/// Eliminates per-tap `bessel_i0()` calls (~25 iterations each).
struct KaiserLut {
    table: Vec<f64>,
}

impl KaiserLut {
    /// Builds a Kaiser window LUT for the given beta parameter.
    #[allow(clippy::cast_precision_loss)]
    fn new(beta: f64) -> Self {
        let inv_i0_beta = 1.0 / bessel_i0(beta);
        let size = KAISER_LUT_INTERVALS + 1;
        let mut table = Vec::with_capacity(size);
        for i in 0..size {
            let u = i as f64 / KAISER_LUT_INTERVALS as f64;
            let arg = u.mul_add(-u, 1.0).max(0.0).sqrt();
            table.push(bessel_i0(beta * arg) * inv_i0_beta);
        }
        Self { table }
    }

    /// Evaluates the Kaiser window at normalized position `u_abs = |x/half|`.
    ///
    /// Returns 0.0 for `u_abs >= 1.0` (outside the window).
    #[inline]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]
    fn evaluate(&self, u_abs: f64) -> f64 {
        if u_abs >= 1.0 {
            return 0.0;
        }
        let pos = u_abs * KAISER_LUT_INTERVALS as f64;
        let idx = pos as usize;
        let frac = pos - idx as f64;
        self.table[idx].mul_add(1.0 - frac, self.table[idx + 1] * frac)
    }
}

/// Pre-computed sinc function lookup table.
///
/// Maps `|x| ∈ [0, FRAC_HALF_TAPS]` to `sin(πx)/(πx)` via linear
/// interpolation. Eliminates per-tap `sin()` + division.
struct SincLut {
    table: Vec<f64>,
    /// Reciprocal of the step size for fast index computation.
    inv_step: f64,
}

impl SincLut {
    /// Builds a sinc LUT covering `[0, max_x]`.
    #[allow(clippy::cast_precision_loss)]
    fn new(max_x: f64) -> Self {
        let size = SINC_LUT_INTERVALS + 1;
        let step = max_x / SINC_LUT_INTERVALS as f64;
        let mut table = Vec::with_capacity(size);
        for i in 0..size {
            let x = i as f64 * step;
            table.push(if x < 1e-10 {
                1.0
            } else {
                (PI * x).sin() / (PI * x)
            });
        }
        Self {
            table,
            inv_step: 1.0 / step,
        }
    }

    /// Evaluates `sinc(|x|) = sin(π|x|)/(π|x|)`.
    ///
    /// Returns 0.0 for values beyond the table range.
    #[inline]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]
    fn evaluate(&self, x_abs: f64) -> f64 {
        let pos = x_abs * self.inv_step;
        let idx = pos as usize;
        if idx >= SINC_LUT_INTERVALS {
            return 0.0;
        }
        let frac = pos - idx as f64;
        self.table[idx].mul_add(1.0 - frac, self.table[idx + 1] * frac)
    }
}

impl FractionalSincResampler {
    /// Creates a new fractional sinc resampler for the given rate pair.
    ///
    /// Pre-computes Kaiser window and sinc LUTs (~25 KB total) to avoid
    /// per-sample transcendental function evaluation in the inner loop.
    #[allow(clippy::cast_precision_loss)]
    pub fn new(input_rate: u32, output_rate: u32) -> Self {
        let ratio = f64::from(output_rate) / f64::from(input_rate);
        Self {
            ratio,
            step: 1.0 / ratio,
            history: vec![0.0; FRAC_HIST_SIZE * 2],
            hist_pos: 0,
            phase: 0.0,
            kaiser_lut: KaiserLut::new(KAISER_BETA),
            sinc_lut: SincLut::new(FRAC_HALF_TAPS as f64),
        }
    }

    /// Inserts a new sample into the fractional resampler's circular history.
    #[inline]
    fn push_sample(&mut self, sample: f32) {
        self.hist_pos = if self.hist_pos == 0 {
            FRAC_HIST_SIZE - 1
        } else {
            self.hist_pos - 1
        };
        self.history[self.hist_pos] = sample;
        self.history[self.hist_pos + FRAC_HIST_SIZE] = sample;
    }

    /// Resamples the input, producing approximately `input.len() * ratio` output samples.
    ///
    /// The exact count is `round(input.len() * ratio)`. The internal phase
    /// accumulator ensures sample-accurate timing across frames.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    pub fn process(&mut self, input: &[i16]) -> Vec<i16> {
        let output_len = ((input.len() as f64) * self.ratio).round() as usize;
        self.process_inner(input, output_len)
    }

    /// Resamples with an adjusted output length for drift compensation.
    pub fn process_adjusted(&mut self, input: &[i16], output_len: usize) -> Vec<i16> {
        self.process_inner(input, output_len)
    }

    /// Resamples into a caller-provided buffer, avoiding heap allocation.
    ///
    /// Writes exactly `output.len()` samples using windowed-sinc interpolation.
    pub fn process_into(&mut self, input: &[i16], output: &mut [i16]) {
        self.process_inner_into(input, output);
    }

    /// Core resampling: sample-by-sample windowed-sinc interpolation.
    ///
    /// For each input sample, shifts the history buffer and produces output
    /// samples while the phase accumulator is within the current input
    /// interval. The kernel center is placed at `FRAC_HALF_TAPS - 1 + phase`
    /// in the history buffer, ensuring `FRAC_HALF_TAPS` taps on each side
    /// are always available — no edge effects at frame boundaries.
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    fn process_inner(&mut self, input: &[i16], output_len: usize) -> Vec<i16> {
        let half = FRAC_HALF_TAPS as f64;
        let inv_half = 1.0 / half;
        let mut output = Vec::with_capacity(output_len);

        for &sample in input {
            self.push_sample(f32::from(sample));

            // Produce output samples while within current input interval
            while self.phase < 1.0 && output.len() < output_len {
                // Kernel center in history coordinates.
                // phase=0 → center at FRAC_HALF_TAPS (8 taps of "future" history ahead)
                // phase→1 → center at FRAC_HALF_TAPS-1 (approaching next input sample)
                let center_pos = half - self.phase;

                let mut sum = 0.0f64;
                let mut coeff_sum = 0.0f64;

                for k in 0..FRAC_HIST_SIZE {
                    let x = k as f64 - center_pos;
                    let x_abs = x.abs();
                    if x_abs > half {
                        continue;
                    }

                    let sinc_val = self.sinc_lut.evaluate(x_abs);
                    let win = self.kaiser_lut.evaluate(x_abs * inv_half);

                    let coeff = sinc_val * win;
                    sum += f64::from(self.history[self.hist_pos + k]) * coeff;
                    coeff_sum += coeff;
                }

                // Normalize for unity DC gain
                if coeff_sum.abs() > 1e-10 {
                    sum /= coeff_sum;
                }

                output.push(sum.round().clamp(-32768.0, 32767.0) as i16);
                self.phase += self.step;
            }
            self.phase -= 1.0;
        }

        // Adjust output length (rounding may over/under-produce by 1)
        if output.len() < output_len {
            let last = output.last().copied().unwrap_or(0);
            output.resize(output_len, last);
        }
        output.truncate(output_len);

        output
    }

    /// Core resampling into a caller-provided buffer.
    ///
    /// Same algorithm as `process_inner` but writes directly into `output`
    /// instead of allocating a `Vec`.
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    fn process_inner_into(&mut self, input: &[i16], output: &mut [i16]) {
        let half = FRAC_HALF_TAPS as f64;
        let inv_half = 1.0 / half;
        let output_len = output.len();
        let mut out_pos = 0;

        for &sample in input {
            self.push_sample(f32::from(sample));

            while self.phase < 1.0 && out_pos < output_len {
                let center_pos = half - self.phase;

                let mut sum = 0.0f64;
                let mut coeff_sum = 0.0f64;

                for k in 0..FRAC_HIST_SIZE {
                    let x = k as f64 - center_pos;
                    let x_abs = x.abs();
                    if x_abs > half {
                        continue;
                    }

                    let sinc_val = self.sinc_lut.evaluate(x_abs);
                    let win = self.kaiser_lut.evaluate(x_abs * inv_half);

                    let coeff = sinc_val * win;
                    sum += f64::from(self.history[self.hist_pos + k]) * coeff;
                    coeff_sum += coeff;
                }

                if coeff_sum.abs() > 1e-10 {
                    sum /= coeff_sum;
                }

                output[out_pos] = sum.round().clamp(-32768.0, 32767.0) as i16;
                out_pos += 1;
                self.phase += self.step;
            }
            self.phase -= 1.0;
        }

        // Extend if output is longer than produced
        if out_pos < output_len {
            let last = if out_pos > 0 { output[out_pos - 1] } else { 0 };
            output[out_pos..].fill(last);
        }
    }

    /// Returns the resampling ratio (`output_rate` / `input_rate`).
    pub const fn ratio(&self) -> f64 {
        self.ratio
    }
}

// ─── Unified resampler ─────────────────────────────────────────────────

/// Unified resampler that selects the optimal sinc algorithm for any rate pair.
///
/// - **Integer ratios** (e.g., 48000/8000 = 6): uses [`SincResampler`] with
///   pre-computed polyphase coefficients.
/// - **Non-integer ratios** (e.g., 44100/8000 = 5.5125): uses
///   [`FractionalSincResampler`] with on-the-fly kernel evaluation.
/// - **Same rate**: passthrough (zero-copy).
pub enum Resampler {
    /// Pre-computed polyphase sinc for integer ratios.
    Integer(SincResampler),
    /// On-the-fly sinc interpolation for arbitrary ratios.
    Fractional(FractionalSincResampler),
    /// No resampling needed (input rate == output rate).
    Passthrough,
}

impl Resampler {
    /// Creates a resampler for the given input/output rate pair.
    ///
    /// Automatically selects the most efficient algorithm.
    pub fn new(input_rate: u32, output_rate: u32) -> Self {
        if input_rate == output_rate {
            Self::Passthrough
        } else if output_rate >= input_rate && output_rate.is_multiple_of(input_rate) {
            #[allow(clippy::cast_possible_truncation)]
            let ratio = (output_rate / input_rate) as usize;
            Self::Integer(SincResampler::new(ratio))
        } else {
            Self::Fractional(FractionalSincResampler::new(input_rate, output_rate))
        }
    }

    /// Resamples the input to the target rate.
    pub fn process(&mut self, input: &[i16]) -> Vec<i16> {
        match self {
            Self::Integer(r) => r.process(input),
            Self::Fractional(r) => r.process(input),
            Self::Passthrough => input.to_vec(),
        }
    }

    /// Resamples with an adjusted output length for drift compensation.
    pub fn process_adjusted(&mut self, input: &[i16], output_len: usize) -> Vec<i16> {
        match self {
            Self::Integer(r) => r.process_adjusted(input, output_len),
            Self::Fractional(r) => r.process_adjusted(input, output_len),
            Self::Passthrough => {
                let mut result = input.to_vec();
                match output_len.cmp(&result.len()) {
                    std::cmp::Ordering::Equal => {}
                    std::cmp::Ordering::Less => result.truncate(output_len),
                    std::cmp::Ordering::Greater => {
                        let last = result.last().copied().unwrap_or(0);
                        result.resize(output_len, last);
                    }
                }
                result
            }
        }
    }

    /// Resamples into a caller-provided buffer, avoiding heap allocation.
    ///
    /// Writes exactly `output.len()` samples. For passthrough, copies input
    /// with truncation or extension as needed.
    pub fn process_adjusted_into(&mut self, input: &[i16], output: &mut [i16]) {
        match self {
            Self::Integer(r) => r.process_into(input, output),
            Self::Fractional(r) => r.process_into(input, output),
            Self::Passthrough => {
                let out_len = output.len();
                let copy_len = input.len().min(out_len);
                output[..copy_len].copy_from_slice(&input[..copy_len]);
                if copy_len < out_len {
                    let last = if copy_len > 0 { input[copy_len - 1] } else { 0 };
                    output[copy_len..].fill(last);
                }
            }
        }
    }

    /// Returns a description of the algorithm being used.
    pub const fn algorithm_name(&self) -> &'static str {
        match self {
            Self::Integer(_) => "polyphase sinc",
            Self::Fractional(_) => "fractional sinc",
            Self::Passthrough => "passthrough",
        }
    }
}

// ─── Shared filter functions ───────────────────────────────────────────

/// Computes polyphase sub-filter coefficients from a Kaiser-windowed sinc kernel.
///
/// The filter is a low-pass at `1/(2*ratio)` normalized frequency (i.e.,
/// the input Nyquist), with a Kaiser window for sidelobe control.
#[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation)]
fn compute_polyphase_coefficients(ratio: usize) -> Vec<[f32; TAPS_PER_PHASE]> {
    let total_taps = ratio * TAPS_PER_PHASE;
    let center = (total_taps - 1) as f64 / 2.0;

    // Compute the full windowed sinc low-pass filter
    let mut h = vec![0.0f64; total_taps];
    for (n, h_n) in h.iter_mut().enumerate() {
        let x = (n as f64 - center) / ratio as f64;
        let sinc_val = if x.abs() < 1e-10 {
            1.0
        } else {
            (PI * x).sin() / (PI * x)
        };
        *h_n = sinc_val * kaiser_window(n, total_taps, KAISER_BETA);
    }

    // Normalize: scale so that the DC gain through any phase path is unity.
    // Sum all taps and divide by ratio (since each output sample uses
    // only one phase's worth of taps).
    let total_sum: f64 = h.iter().sum();
    if total_sum.abs() > 1e-10 {
        let scale = ratio as f64 / total_sum;
        for h_n in &mut h {
            *h_n *= scale;
        }
    }

    // Decompose into polyphase sub-filters.
    // Phase p uses taps at indices: p, p+L, p+2L, ...
    // where L is the upsampling ratio.
    #[allow(clippy::cast_possible_truncation)]
    let mut phases = vec![[0.0f32; TAPS_PER_PHASE]; ratio];
    for (p, phase) in phases.iter_mut().enumerate() {
        for (k, coeff) in phase.iter_mut().enumerate() {
            let idx = p + k * ratio;
            if idx < total_taps {
                *coeff = h[idx] as f32;
            }
        }
    }

    phases
}

/// Evaluates the Kaiser window function at sample index `n`.
#[allow(clippy::cast_precision_loss)]
fn kaiser_window(n: usize, length: usize, beta: f64) -> f64 {
    if length <= 1 {
        return 1.0;
    }
    let m = (length - 1) as f64 / 2.0;
    let x = (n as f64 - m) / m;
    let inner = (1.0 - x * x).max(0.0).sqrt();
    bessel_i0(beta * inner) / bessel_i0(beta)
}

/// Approximates the modified Bessel function of the first kind, order 0.
///
/// Uses the power series expansion which converges rapidly for moderate arguments.
fn bessel_i0(x: f64) -> f64 {
    let mut sum = 1.0;
    let mut term = 1.0;
    let x_half = x / 2.0;
    for k in 1..25 {
        let k_f = f64::from(k);
        term *= (x_half / k_f) * (x_half / k_f);
        sum += term;
        if term < 1e-15 * sum {
            break;
        }
    }
    sum
}

// ─── SIMD-accelerated dot product ─────────────────────────────────────

/// Computes the dot product of `history[0..16]` and `coeffs[0..16]`.
///
/// Dispatches to NEON (aarch64), SSE2 (`x86_64`), or scalar fallback.
#[inline]
fn dot_product_16(history: &[f32; TAPS_PER_PHASE], coeffs: &[f32; TAPS_PER_PHASE]) -> f32 {
    #[cfg(target_arch = "aarch64")]
    {
        dot_product_16_neon(history, coeffs)
    }

    #[cfg(target_arch = "x86_64")]
    {
        dot_product_16_sse2(history, coeffs)
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        dot_product_16_scalar(history, coeffs)
    }
}

/// NEON-accelerated 16-element f32 dot product.
///
/// NEON is mandatory on all aarch64 targets (ARMv8-A baseline).
/// Uses `vfmaq_f32` fused multiply-add and `vaddvq_f32` horizontal sum.
#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
#[inline]
fn dot_product_16_neon(history: &[f32; TAPS_PER_PHASE], coeffs: &[f32; TAPS_PER_PHASE]) -> f32 {
    // SAFETY: NEON is always available on aarch64. vld1q_f32 supports
    // unaligned loads. Arrays are exactly 16 elements so all loads are in-bounds.
    unsafe {
        let h0 = vld1q_f32(history.as_ptr());
        let h1 = vld1q_f32(history.as_ptr().add(4));
        let h2 = vld1q_f32(history.as_ptr().add(8));
        let h3 = vld1q_f32(history.as_ptr().add(12));

        let c0 = vld1q_f32(coeffs.as_ptr());
        let c1 = vld1q_f32(coeffs.as_ptr().add(4));
        let c2 = vld1q_f32(coeffs.as_ptr().add(8));
        let c3 = vld1q_f32(coeffs.as_ptr().add(12));

        let mut acc = vmulq_f32(h0, c0);
        acc = vfmaq_f32(acc, h1, c1);
        acc = vfmaq_f32(acc, h2, c2);
        acc = vfmaq_f32(acc, h3, c3);

        vaddvq_f32(acc)
    }
}

/// SSE2-accelerated 16-element f32 dot product.
///
/// `SSE2` is mandatory on all `x86_64` targets (AMD64 baseline).
/// Uses `_mm_mul_ps` + `_mm_add_ps` (no FMA requirement).
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code, clippy::inline_always)]
#[inline(always)]
fn dot_product_16_sse2(history: &[f32; TAPS_PER_PHASE], coeffs: &[f32; TAPS_PER_PHASE]) -> f32 {
    // SAFETY: SSE2 is always available on x86_64. _mm_loadu_ps supports
    // unaligned loads. Arrays are exactly 16 elements so all loads are in-bounds.
    unsafe {
        let h0 = _mm_loadu_ps(history.as_ptr());
        let h1 = _mm_loadu_ps(history.as_ptr().add(4));
        let h2 = _mm_loadu_ps(history.as_ptr().add(8));
        let h3 = _mm_loadu_ps(history.as_ptr().add(12));

        let c0 = _mm_loadu_ps(coeffs.as_ptr());
        let c1 = _mm_loadu_ps(coeffs.as_ptr().add(4));
        let c2 = _mm_loadu_ps(coeffs.as_ptr().add(8));
        let c3 = _mm_loadu_ps(coeffs.as_ptr().add(12));

        let mut acc = _mm_mul_ps(h0, c0);
        acc = _mm_add_ps(acc, _mm_mul_ps(h1, c1));
        acc = _mm_add_ps(acc, _mm_mul_ps(h2, c2));
        acc = _mm_add_ps(acc, _mm_mul_ps(h3, c3));

        // Horizontal sum: [a, b, c, d] → a+b+c+d
        let hi = _mm_movehl_ps(acc, acc); // [c, d, c, d]
        let sum01 = _mm_add_ps(acc, hi); // [a+c, b+d, ?, ?]
        let shuf = _mm_shuffle_ps(sum01, sum01, 1); // [b+d, ?, ?, ?]
        let total = _mm_add_ss(sum01, shuf); // [a+b+c+d, ?, ?, ?]

        _mm_cvtss_f32(total)
    }
}

/// Scalar fallback using 4-lane accumulation order for consistency with SIMD paths.
#[cfg(any(not(any(target_arch = "aarch64", target_arch = "x86_64")), test))]
fn dot_product_16_scalar(history: &[f32; TAPS_PER_PHASE], coeffs: &[f32; TAPS_PER_PHASE]) -> f32 {
    let mut acc0 = history[0] * coeffs[0];
    let mut acc1 = history[1] * coeffs[1];
    let mut acc2 = history[2] * coeffs[2];
    let mut acc3 = history[3] * coeffs[3];

    acc0 = history[4].mul_add(coeffs[4], acc0);
    acc1 = history[5].mul_add(coeffs[5], acc1);
    acc2 = history[6].mul_add(coeffs[6], acc2);
    acc3 = history[7].mul_add(coeffs[7], acc3);

    acc0 = history[8].mul_add(coeffs[8], acc0);
    acc1 = history[9].mul_add(coeffs[9], acc1);
    acc2 = history[10].mul_add(coeffs[10], acc2);
    acc3 = history[11].mul_add(coeffs[11], acc3);

    acc0 = history[12].mul_add(coeffs[12], acc0);
    acc1 = history[13].mul_add(coeffs[13], acc1);
    acc2 = history[14].mul_add(coeffs[14], acc2);
    acc3 = history[15].mul_add(coeffs[15], acc3);

    (acc0 + acc2) + (acc1 + acc3)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── SIMD dot product tests ───────────────────────────────────

    #[test]
    fn test_dot_product_16_known_values() {
        let history = [1.0f32; TAPS_PER_PHASE];
        let coeffs = [2.0f32; TAPS_PER_PHASE];
        let result = dot_product_16(&history, &coeffs);
        assert!(
            (result - 32.0).abs() < 1e-5,
            "1.0 * 2.0 * 16 = 32.0, got {result}"
        );
    }

    #[test]
    fn test_dot_product_16_matches_scalar() {
        let mut history = [0.0f32; TAPS_PER_PHASE];
        let mut coeffs = [0.0f32; TAPS_PER_PHASE];
        #[allow(clippy::cast_precision_loss)]
        for i in 0..TAPS_PER_PHASE {
            history[i] = (i as f32).mul_add(1234.5, -8000.0);
            coeffs[i] = (i as f32).mul_add(0.0625, -0.5);
        }

        let simd_result = dot_product_16(&history, &coeffs);
        let scalar_result = dot_product_16_scalar(&history, &coeffs);

        assert!(
            (simd_result - scalar_result).abs() < 1.0,
            "SIMD={simd_result}, scalar={scalar_result}"
        );
    }

    #[test]
    fn test_dot_product_16_zeros() {
        let history = [0.0f32; TAPS_PER_PHASE];
        let coeffs = [1.0f32; TAPS_PER_PHASE];
        let result = dot_product_16(&history, &coeffs);
        assert!(
            result.abs() < 1e-10,
            "Zero input should produce zero: {result}"
        );
    }

    // ─── Integer polyphase tests ───────────────────────────────────

    #[test]
    fn test_new_resampler() {
        let resampler = SincResampler::new(6);
        assert_eq!(resampler.ratio(), 6);
    }

    #[test]
    fn test_output_length() {
        let mut resampler = SincResampler::new(6);
        let input = vec![0i16; 160];
        let output = resampler.process(&input);
        assert_eq!(output.len(), 960);
    }

    #[test]
    fn test_silence_in_silence_out() {
        let mut resampler = SincResampler::new(6);
        let input = vec![0i16; 160];
        let output = resampler.process(&input);
        assert!(
            output.iter().all(|&s| s == 0),
            "Silence should produce silence"
        );
    }

    #[test]
    fn test_dc_preservation() {
        let mut resampler = SincResampler::new(6);
        let dc_value = 10000i16;
        let input = vec![dc_value; 160];

        // First frame: filter is settling
        let _ = resampler.process(&input);
        // Second frame: should be close to DC
        let output = resampler.process(&input);

        let tolerance = 500i16; // ~5% of 10000
        let close_count = output
            .iter()
            .filter(|&&s| (s - dc_value).abs() <= tolerance)
            .count();
        assert!(
            close_count > output.len() * 9 / 10,
            "DC should be preserved: {close_count}/{} samples within tolerance",
            output.len()
        );
    }

    #[test]
    fn test_adjusted_output_longer() {
        let mut resampler = SincResampler::new(6);
        let input = vec![1000i16; 160];
        let output = resampler.process_adjusted(&input, 961);
        assert_eq!(output.len(), 961);
    }

    #[test]
    fn test_adjusted_output_shorter() {
        let mut resampler = SincResampler::new(6);
        let input = vec![1000i16; 160];
        let output = resampler.process_adjusted(&input, 959);
        assert_eq!(output.len(), 959);
    }

    #[test]
    fn test_cross_frame_continuity() {
        let mut resampler = SincResampler::new(6);

        let frame1: Vec<i16> = (0..160)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let s = (f64::sin(2.0 * PI * 400.0 * f64::from(i) / 8000.0) * 10000.0) as i16;
                s
            })
            .collect();
        let frame2: Vec<i16> = (160..320)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let s = (f64::sin(2.0 * PI * 400.0 * f64::from(i) / 8000.0) * 10000.0) as i16;
                s
            })
            .collect();

        let out1 = resampler.process(&frame1);
        let out2 = resampler.process(&frame2);

        // Check boundary: last sample of frame1 and first sample of frame2
        // should not have a large discontinuity
        let boundary_diff = (i32::from(out2[0]) - i32::from(out1[out1.len() - 1])).abs();
        assert!(
            boundary_diff < 2000,
            "Cross-frame boundary should be smooth: diff={boundary_diff}"
        );
    }

    #[test]
    fn test_ratio_2() {
        let mut resampler = SincResampler::new(2);
        let input = vec![5000i16; 80];
        let output = resampler.process(&input);
        assert_eq!(output.len(), 160);
    }

    #[test]
    fn test_ratio_1_passthrough_length() {
        let mut resampler = SincResampler::new(1);
        let input = vec![1000i16; 160];
        let output = resampler.process(&input);
        assert_eq!(output.len(), 160);
    }

    #[test]
    fn test_kaiser_window_center() {
        let val = kaiser_window(24, 49, 5.0);
        assert!((val - 1.0).abs() < 0.001, "Center should be 1.0, got {val}");
    }

    #[test]
    fn test_kaiser_window_symmetry() {
        let n = 49;
        let beta = 5.0;
        for i in 0..n / 2 {
            let left = kaiser_window(i, n, beta);
            let right = kaiser_window(n - 1 - i, n, beta);
            assert!(
                (left - right).abs() < 1e-10,
                "Window should be symmetric at {i}: {left} vs {right}"
            );
        }
    }

    #[test]
    fn test_bessel_i0_zero() {
        assert!((bessel_i0(0.0) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_bessel_i0_known() {
        // I0(1) = 1.2660658...
        assert!((bessel_i0(1.0) - 1.266_065_8).abs() < 1e-5);
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn test_sine_energy_preserved() {
        let mut resampler = SincResampler::new(6);
        // 400 Hz sine at 8kHz → expect similar energy at 48kHz
        let input: Vec<i16> = (0..160)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let s = (f64::sin(2.0 * PI * 400.0 * f64::from(i) / 8000.0) * 10000.0) as i16;
                s
            })
            .collect();

        // Warm up filter
        let _ = resampler.process(&input);
        let output = resampler.process(&input);

        // Compare RMS energy
        let input_rms: f64 = (input
            .iter()
            .map(|&s| f64::from(s) * f64::from(s))
            .sum::<f64>()
            / input.len() as f64)
            .sqrt();
        let output_rms: f64 = (output
            .iter()
            .map(|&s| f64::from(s) * f64::from(s))
            .sum::<f64>()
            / output.len() as f64)
            .sqrt();

        // Energy should be within 20% (filter settling + window effects)
        let ratio = output_rms / input_rms;
        assert!(
            (0.7..=1.3).contains(&ratio),
            "RMS ratio should be near 1.0, got {ratio:.3} (in={input_rms:.0}, out={output_rms:.0})"
        );
    }

    // ─── Fractional sinc tests ─────────────────────────────────────

    #[test]
    fn test_fractional_output_length() {
        // 8kHz → 44.1kHz: 160 input → round(160 * 5.5125) = 882 output
        let mut resampler = FractionalSincResampler::new(8000, 44100);
        let input = vec![0i16; 160];
        let output = resampler.process(&input);
        assert_eq!(output.len(), 882);
    }

    #[test]
    fn test_fractional_silence() {
        let mut resampler = FractionalSincResampler::new(8000, 44100);
        let input = vec![0i16; 160];
        let output = resampler.process(&input);
        assert!(
            output.iter().all(|&s| s == 0),
            "Silence should produce silence"
        );
    }

    #[test]
    fn test_fractional_dc_preservation() {
        let mut resampler = FractionalSincResampler::new(8000, 44100);
        let dc_value = 10000i16;
        let input = vec![dc_value; 160];

        // Warm up
        let _ = resampler.process(&input);
        let output = resampler.process(&input);

        let tolerance = 500i16;
        let close_count = output
            .iter()
            .filter(|&&s| (s - dc_value).abs() <= tolerance)
            .count();
        assert!(
            close_count > output.len() * 9 / 10,
            "DC should be preserved: {close_count}/{} within tolerance",
            output.len()
        );
    }

    #[test]
    fn test_fractional_cross_frame_continuity() {
        let mut resampler = FractionalSincResampler::new(8000, 44100);

        let frame1: Vec<i16> = (0..160)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let s = (f64::sin(2.0 * PI * 400.0 * f64::from(i) / 8000.0) * 10000.0) as i16;
                s
            })
            .collect();
        let frame2: Vec<i16> = (160..320)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let s = (f64::sin(2.0 * PI * 400.0 * f64::from(i) / 8000.0) * 10000.0) as i16;
                s
            })
            .collect();

        let out1 = resampler.process(&frame1);
        let out2 = resampler.process(&frame2);

        let boundary_diff = (i32::from(out2[0]) - i32::from(out1[out1.len() - 1])).abs();
        assert!(
            boundary_diff < 2000,
            "Cross-frame boundary should be smooth: diff={boundary_diff}"
        );
    }

    #[test]
    fn test_fractional_adjusted_length() {
        let mut resampler = FractionalSincResampler::new(8000, 44100);
        let input = vec![1000i16; 160];

        let output_short = resampler.process_adjusted(&input, 880);
        assert_eq!(output_short.len(), 880);

        let output_long = resampler.process_adjusted(&input, 884);
        assert_eq!(output_long.len(), 884);
    }

    #[test]
    #[allow(clippy::cast_precision_loss)]
    fn test_fractional_sine_energy() {
        let mut resampler = FractionalSincResampler::new(8000, 44100);
        let input: Vec<i16> = (0..160)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let s = (f64::sin(2.0 * PI * 400.0 * f64::from(i) / 8000.0) * 10000.0) as i16;
                s
            })
            .collect();

        let _ = resampler.process(&input);
        let output = resampler.process(&input);

        let input_rms: f64 = (input
            .iter()
            .map(|&s| f64::from(s) * f64::from(s))
            .sum::<f64>()
            / input.len() as f64)
            .sqrt();
        let output_rms: f64 = (output
            .iter()
            .map(|&s| f64::from(s) * f64::from(s))
            .sum::<f64>()
            / output.len() as f64)
            .sqrt();

        let ratio = output_rms / input_rms;
        assert!(
            (0.7..=1.3).contains(&ratio),
            "RMS ratio should be near 1.0, got {ratio:.3} (in={input_rms:.0}, out={output_rms:.0})"
        );
    }

    // ─── Unified Resampler enum tests ──────────────────────────────

    #[test]
    fn test_resampler_selects_integer() {
        let r = Resampler::new(8000, 48000);
        assert_eq!(r.algorithm_name(), "polyphase sinc");
    }

    #[test]
    fn test_resampler_selects_fractional() {
        let r = Resampler::new(8000, 44100);
        assert_eq!(r.algorithm_name(), "fractional sinc");
    }

    #[test]
    fn test_resampler_passthrough() {
        let mut r = Resampler::new(8000, 8000);
        assert_eq!(r.algorithm_name(), "passthrough");
        let input = vec![1234i16; 160];
        let output = r.process(&input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_resampler_unified_output_lengths() {
        // Integer ratio: 160 * 6 = 960
        let mut r_int = Resampler::new(8000, 48000);
        assert_eq!(r_int.process(&vec![0i16; 160]).len(), 960);

        // Fractional: 160 * 5.5125 = 882
        let mut r_frac = Resampler::new(8000, 44100);
        assert_eq!(r_frac.process(&vec![0i16; 160]).len(), 882);

        // Passthrough: 160
        let mut r_pass = Resampler::new(8000, 8000);
        assert_eq!(r_pass.process(&vec![0i16; 160]).len(), 160);
    }

    #[test]
    fn test_resampler_adjusted_passthrough() {
        let mut r = Resampler::new(8000, 8000);
        let input = vec![5000i16; 160];
        let output = r.process_adjusted(&input, 162);
        assert_eq!(output.len(), 162);
    }

    // ─── process_into / process_adjusted_into tests ───────────────

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_integer_process_into_matches_process() {
        let input: Vec<i16> = (0..160).map(|i| (i * 100) as i16).collect();

        let mut r1 = SincResampler::new(6);
        let expected = r1.process(&input);

        let mut r2 = SincResampler::new(6);
        let mut output = vec![0i16; 960];
        r2.process_into(&input, &mut output);

        assert_eq!(output, expected);
    }

    #[test]
    fn test_integer_process_into_shorter() {
        let mut r = SincResampler::new(6);
        let input = vec![1000i16; 160];
        let mut output = vec![0i16; 959];
        r.process_into(&input, &mut output);
        assert_eq!(output.len(), 959);
    }

    #[test]
    fn test_integer_process_into_longer() {
        let mut r = SincResampler::new(6);
        let input = vec![1000i16; 160];
        let mut output = vec![0i16; 961];
        r.process_into(&input, &mut output);
        assert_eq!(output.len(), 961);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_fractional_process_into_matches_process_adjusted() {
        let input: Vec<i16> = (0..160).map(|i| (i * 50) as i16).collect();

        let mut r1 = FractionalSincResampler::new(8000, 44100);
        let expected = r1.process_adjusted(&input, 882);

        let mut r2 = FractionalSincResampler::new(8000, 44100);
        let mut output = vec![0i16; 882];
        r2.process_into(&input, &mut output);

        assert_eq!(output, expected);
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_resampler_adjusted_into_integer() {
        let input: Vec<i16> = (0..160).map(|i| (i * 100) as i16).collect();

        let mut r1 = Resampler::new(8000, 48000);
        let expected = r1.process_adjusted(&input, 960);

        let mut r2 = Resampler::new(8000, 48000);
        let mut output = vec![0i16; 960];
        r2.process_adjusted_into(&input, &mut output);

        assert_eq!(output, expected);
    }

    #[test]
    fn test_resampler_adjusted_into_passthrough() {
        let mut r = Resampler::new(8000, 8000);
        let input = vec![5000i16; 160];
        let mut output = vec![0i16; 162];
        r.process_adjusted_into(&input, &mut output);
        assert_eq!(output[..160], input[..]);
        assert_eq!(output[160], 5000);
        assert_eq!(output[161], 5000);
    }
}
