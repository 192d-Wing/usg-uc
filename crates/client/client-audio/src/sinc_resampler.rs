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
pub struct SincResampler {
    /// Upsampling ratio (e.g., 6 for 8kHz to 48kHz).
    ratio: usize,
    /// Polyphase sub-filter coefficients: `phases[p][k]` is the k-th tap
    /// of the p-th polyphase sub-filter.
    phases: Vec<[f32; TAPS_PER_PHASE]>,
    /// Input sample history buffer (newest at index 0).
    history: [f32; TAPS_PER_PHASE],
}

impl SincResampler {
    /// Creates a new sinc resampler for the given integer upsampling ratio.
    pub fn new(ratio: usize) -> Self {
        let ratio = ratio.max(1);
        let phases = compute_polyphase_coefficients(ratio);
        Self {
            ratio,
            phases,
            history: [0.0; TAPS_PER_PHASE],
        }
    }

    /// Resamples the input, producing exactly `input.len() * ratio` output samples.
    ///
    /// The internal history buffer provides seamless cross-frame continuity.
    #[allow(clippy::cast_possible_truncation)]
    pub fn process(&mut self, input: &[i16]) -> Vec<i16> {
        let output_len = input.len() * self.ratio;
        let mut output = Vec::with_capacity(output_len);

        for &sample in input {
            // Shift history right by 1 and insert new sample at [0]
            self.history.copy_within(0..TAPS_PER_PHASE - 1, 1);
            self.history[0] = f32::from(sample);

            // Compute each polyphase output
            for phase in &self.phases {
                let mut sum = 0.0f32;
                for k in 0..TAPS_PER_PHASE {
                    sum = self.history[k].mul_add(phase[k], sum);
                }
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
/// 8kHz) which is imperceptible for VoIP.
///
/// For integer ratios, prefer [`SincResampler`] which pre-computes
/// polyphase coefficient tables for better efficiency.
pub struct FractionalSincResampler {
    /// Output/input sample rate ratio (e.g., 5.5125).
    ratio: f64,
    /// Input-domain advance per output sample (1/ratio).
    step: f64,
    /// Input sample history buffer (newest at index 0, oldest at end).
    /// Size = 2 * FRAC_HALF_TAPS + 1, giving FRAC_HALF_TAPS taps on
    /// each side of the kernel center for full symmetric support.
    history: Vec<f32>,
    /// Fractional position within the current input sample interval.
    /// Range: [0, 1). When phase < 1.0, output samples are produced.
    phase: f64,
    /// Pre-computed 1/I0(beta) for Kaiser window evaluation.
    inv_bessel: f64,
}

/// History buffer size for fractional resampler: enough for a symmetric
/// kernel with FRAC_HALF_TAPS taps on each side, plus the center.
const FRAC_HIST_SIZE: usize = 2 * FRAC_HALF_TAPS + 1;

impl FractionalSincResampler {
    /// Creates a new fractional sinc resampler for the given rate pair.
    pub fn new(input_rate: u32, output_rate: u32) -> Self {
        let ratio = f64::from(output_rate) / f64::from(input_rate);
        Self {
            ratio,
            step: 1.0 / ratio,
            history: vec![0.0; FRAC_HIST_SIZE],
            phase: 0.0,
            inv_bessel: 1.0 / bessel_i0(KAISER_BETA),
        }
    }

    /// Resamples the input, producing approximately `input.len() * ratio` output samples.
    ///
    /// The exact count is `round(input.len() * ratio)`. The internal phase
    /// accumulator ensures sample-accurate timing across frames.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn process(&mut self, input: &[i16]) -> Vec<i16> {
        let output_len = ((input.len() as f64) * self.ratio).round() as usize;
        self.process_inner(input, output_len)
    }

    /// Resamples with an adjusted output length for drift compensation.
    pub fn process_adjusted(&mut self, input: &[i16], output_len: usize) -> Vec<i16> {
        self.process_inner(input, output_len)
    }

    /// Core resampling: sample-by-sample windowed-sinc interpolation.
    ///
    /// For each input sample, shifts the history buffer and produces output
    /// samples while the phase accumulator is within the current input
    /// interval. The kernel center is placed at `FRAC_HALF_TAPS - 1 + phase`
    /// in the history buffer, ensuring FRAC_HALF_TAPS taps on each side
    /// are always available — no edge effects at frame boundaries.
    #[allow(clippy::cast_possible_truncation)]
    fn process_inner(&mut self, input: &[i16], output_len: usize) -> Vec<i16> {
        let half = FRAC_HALF_TAPS as f64;
        let mut output = Vec::with_capacity(output_len);

        for &sample in input {
            // Shift history right by 1 and insert new sample at [0]
            // (newest at index 0, oldest at index FRAC_HIST_SIZE-1)
            self.history.copy_within(0..FRAC_HIST_SIZE - 1, 1);
            self.history[0] = f32::from(sample);

            // Produce output samples while within current input interval
            while self.phase < 1.0 && output.len() < output_len {
                // Kernel center in history coordinates.
                // phase=0 → center at FRAC_HALF_TAPS (8 taps of "future" history ahead)
                // phase→1 → center at FRAC_HALF_TAPS-1 (approaching next input sample)
                // This ensures the output advances forward in time as phase increases,
                // with FRAC_HALF_TAPS taps on each side for full kernel support.
                let center_pos = half - self.phase;

                let mut sum = 0.0f64;
                let mut coeff_sum = 0.0f64;

                for k in 0..FRAC_HIST_SIZE {
                    let x = k as f64 - center_pos;
                    if x.abs() > half {
                        continue;
                    }

                    let sinc_val = if x.abs() < 1e-10 {
                        1.0
                    } else {
                        (PI * x).sin() / (PI * x)
                    };

                    let arg = (1.0 - (x / half).powi(2)).max(0.0).sqrt();
                    let win = bessel_i0(KAISER_BETA * arg) * self.inv_bessel;

                    let coeff = sinc_val * win;
                    sum += f64::from(self.history[k]) * coeff;
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

    /// Returns the resampling ratio (output_rate / input_rate).
    pub fn ratio(&self) -> f64 {
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
            Resampler::Passthrough
        } else if output_rate >= input_rate && output_rate % input_rate == 0 {
            #[allow(clippy::cast_possible_truncation)]
            let ratio = (output_rate / input_rate) as usize;
            Resampler::Integer(SincResampler::new(ratio))
        } else {
            Resampler::Fractional(FractionalSincResampler::new(input_rate, output_rate))
        }
    }

    /// Resamples the input to the target rate.
    pub fn process(&mut self, input: &[i16]) -> Vec<i16> {
        match self {
            Resampler::Integer(r) => r.process(input),
            Resampler::Fractional(r) => r.process(input),
            Resampler::Passthrough => input.to_vec(),
        }
    }

    /// Resamples with an adjusted output length for drift compensation.
    pub fn process_adjusted(&mut self, input: &[i16], output_len: usize) -> Vec<i16> {
        match self {
            Resampler::Integer(r) => r.process_adjusted(input, output_len),
            Resampler::Fractional(r) => r.process_adjusted(input, output_len),
            Resampler::Passthrough => {
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

    /// Returns a description of the algorithm being used.
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Resampler::Integer(_) => "polyphase sinc",
            Resampler::Fractional(_) => "fractional sinc",
            Resampler::Passthrough => "passthrough",
        }
    }
}

// ─── Shared filter functions ───────────────────────────────────────────

/// Computes polyphase sub-filter coefficients from a Kaiser-windowed sinc kernel.
///
/// The filter is a low-pass at `1/(2*ratio)` normalized frequency (i.e.,
/// the input Nyquist), with a Kaiser window for sidelobe control.
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
        let k_f = k as f64;
        term *= (x_half / k_f) * (x_half / k_f);
        sum += term;
        if term < 1e-15 * sum {
            break;
        }
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(output.iter().all(|&s| s == 0), "Silence should produce silence");
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
        assert!(
            (val - 1.0).abs() < 0.001,
            "Center should be 1.0, got {val}"
        );
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
        assert!((bessel_i0(1.0) - 1.2660658).abs() < 1e-5);
    }

    #[test]
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
}
