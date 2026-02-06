//! Packet Loss Concealment using Linear Predictive Coding (LPC).
//!
//! When an RTP packet is lost, the decoder has no data to decode.
//! This module generates synthetic audio that sounds like a natural
//! continuation of the previous speech, significantly reducing the
//! audible artifact compared to simple silence or fade-out.
//!
//! ## Algorithm
//!
//! 1. Maintain a history buffer of the last decoded frame.
//! 2. On loss, compute LPC coefficients via Levinson-Durbin autocorrelation.
//! 3. Synthesize a replacement frame using the all-pole LPC filter.
//! 4. Apply progressive attenuation for consecutive losses (fade to
//!    silence after ~3 lost frames to avoid metallic artifacts).
//! 5. On recovery, cross-fade from the synthetic tail into the real
//!    decoded frame.

/// LPC order — 10 is standard for narrowband (8 kHz) speech.
const LPC_ORDER: usize = 10;

/// Maximum consecutive concealment frames before full mute.
/// At 20ms per frame, 5 frames = 100ms — enough to mask short bursts
/// without producing long stretches of robotic synthesis.
const MAX_CONCEAL_FRAMES: u32 = 5;

/// Cross-fade length in samples when transitioning from concealment
/// back to real audio. 40 samples at 8 kHz = 5ms.
const CROSSFADE_SAMPLES: usize = 40;

/// Packet loss concealer using LPC-based prediction.
pub struct PacketLossConcealer {
    /// History: the last successfully decoded frame (codec-rate samples).
    history: Vec<i16>,
    /// LPC filter state (previous output samples for the all-pole filter).
    filter_state: Vec<f32>,
    /// Number of consecutive concealment frames generated.
    consecutive_losses: u32,
    /// Frame size in samples (e.g., 160 for G.711 at 8 kHz).
    frame_size: usize,
}

impl PacketLossConcealer {
    /// Creates a new concealer for the given frame size.
    pub fn new(frame_size: usize) -> Self {
        Self {
            history: vec![0i16; frame_size],
            filter_state: vec![0.0; LPC_ORDER],
            consecutive_losses: 0,
            frame_size,
        }
    }

    /// Records a successfully decoded frame.
    ///
    /// Must be called for every good frame so the concealer has
    /// up-to-date speech statistics.
    pub fn good_frame(&mut self, pcm: &[i16]) {
        self.consecutive_losses = 0;
        // Store the frame as history
        let len = pcm.len().min(self.frame_size);
        self.history[..len].copy_from_slice(&pcm[..len]);
        if len < self.frame_size {
            self.history[len..].fill(0);
        }
        // Update filter state from the tail of the real frame
        update_filter_state(&mut self.filter_state, pcm);
    }

    /// Generates a concealment frame to replace a lost packet.
    ///
    /// Returns a buffer of `frame_size` samples.
    pub fn conceal(&mut self) -> Vec<i16> {
        self.consecutive_losses += 1;

        if self.consecutive_losses > MAX_CONCEAL_FRAMES {
            // Too many consecutive losses — output silence to avoid
            // extended robotic artifacts.
            self.filter_state.fill(0.0);
            return vec![0i16; self.frame_size];
        }

        // Compute LPC coefficients from history
        let coeffs = levinson_durbin(&self.history);

        // Synthesize replacement frame using LPC all-pole filter
        let mut output = vec![0.0f32; self.frame_size];
        synthesize(&coeffs, &mut self.filter_state, &mut output);

        // Apply progressive attenuation: energy decays with each
        // consecutive loss so long bursts fade naturally.
        let attenuation = attenuation_factor(self.consecutive_losses);

        let mut result = vec![0i16; self.frame_size];
        #[allow(clippy::cast_possible_truncation)]
        for (i, &s) in output.iter().enumerate() {
            result[i] = (s * attenuation).clamp(-32768.0, 32767.0) as i16;
        }

        // Update filter state for potential next concealment frame
        update_filter_state(&mut self.filter_state, &result);

        // Update history so consecutive concealments chain smoothly
        self.history.copy_from_slice(&result);

        result
    }

    /// Cross-fades from the concealment tail into a recovered real frame.
    ///
    /// Call this instead of `good_frame()` on the first good frame
    /// after one or more lost frames to avoid a discontinuity.
    pub fn recover(&mut self, real_frame: &mut [i16]) {
        if self.consecutive_losses == 0 {
            // No loss occurred — just record the frame normally
            self.good_frame(real_frame);
            return;
        }

        // Generate what the concealer would have produced
        let synthetic_tail = &self.history;

        // Cross-fade: blend synthetic tail → real frame over CROSSFADE_SAMPLES
        let fade_len = CROSSFADE_SAMPLES.min(real_frame.len()).min(synthetic_tail.len());
        #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
        for i in 0..fade_len {
            let t = (i as f32 + 1.0) / (fade_len as f32 + 1.0);
            let blended = f32::from(synthetic_tail[i])
                .mul_add(1.0 - t, f32::from(real_frame[i]) * t);
            real_frame[i] = blended.clamp(-32768.0, 32767.0) as i16;
        }

        self.good_frame(real_frame);
    }

    /// Returns the number of consecutive losses.
    pub const fn consecutive_losses(&self) -> u32 {
        self.consecutive_losses
    }
}

/// Computes LPC coefficients from a PCM buffer using autocorrelation +
/// Levinson-Durbin recursion.
///
/// Returns `LPC_ORDER` coefficients (a1..a10).
fn levinson_durbin(signal: &[i16]) -> [f32; LPC_ORDER] {
    let mut coeffs = [0.0f32; LPC_ORDER];
    let n = signal.len();
    if n <= LPC_ORDER {
        return coeffs;
    }

    // Compute autocorrelation R[0..LPC_ORDER]
    let mut r = [0.0f64; LPC_ORDER + 1];
    for lag in 0..=LPC_ORDER {
        let mut sum = 0.0f64;
        for i in lag..n {
            sum += f64::from(signal[i]) * f64::from(signal[i - lag]);
        }
        r[lag] = sum;
    }

    // Guard against silence (R[0] ≈ 0)
    if r[0].abs() < 1.0 {
        return coeffs;
    }

    // Levinson-Durbin recursion
    let mut a = [0.0f64; LPC_ORDER + 1]; // a[0] is unused (implicitly 1.0)
    let mut a_prev = [0.0f64; LPC_ORDER + 1];
    let mut error = r[0];

    for i in 1..=LPC_ORDER {
        // Compute reflection coefficient
        let mut lambda = 0.0f64;
        for j in 1..i {
            lambda += a_prev[j] * r[i - j];
        }
        lambda = (r[i] - lambda) / error;

        // Update coefficients
        a[i] = lambda;
        for j in 1..i {
            a[j] = lambda.mul_add(-a_prev[i - j], a_prev[j]);
        }

        error *= lambda.mul_add(-lambda, 1.0);
        if error <= 0.0 {
            // Unstable — return what we have so far
            break;
        }

        a_prev[..=i].copy_from_slice(&a[..=i]);
    }

    // Convert to f32
    #[allow(clippy::cast_possible_truncation)]
    for (i, c) in coeffs.iter_mut().enumerate() {
        *c = a[i + 1] as f32;
    }

    coeffs
}

/// Synthesizes audio using the all-pole LPC filter.
///
/// `state` contains the previous `LPC_ORDER` output samples (filter memory).
/// `output` is filled with synthesized samples.
fn synthesize(coeffs: &[f32; LPC_ORDER], state: &mut Vec<f32>, output: &mut [f32]) {
    for sample in output.iter_mut() {
        // All-pole filter: y[n] = sum(a[k] * y[n-k]) for k=1..ORDER
        let mut val = 0.0f32;
        for (k, &coeff) in coeffs.iter().enumerate() {
            if k < state.len() {
                val += coeff * state[state.len() - 1 - k];
            }
        }

        *sample = val;

        // Shift state and append new sample
        if state.len() >= LPC_ORDER {
            state.remove(0);
        }
        state.push(val);
    }
}

/// Computes the attenuation factor for progressive energy decay.
///
/// First concealment frame: 90% energy. Each subsequent: 20% less.
/// By frame 5: ~33% energy. Beyond `MAX_CONCEAL_FRAMES`: muted.
#[allow(clippy::cast_precision_loss)]
fn attenuation_factor(consecutive: u32) -> f32 {
    if consecutive == 0 {
        return 1.0;
    }
    #[allow(clippy::cast_possible_wrap)]
    let exp = consecutive as i32 - 1;
    0.9 * 0.8_f32.powi(exp)
}

/// Updates filter state from the tail of a PCM buffer.
fn update_filter_state(state: &mut Vec<f32>, pcm: &[i16]) {
    let take = LPC_ORDER.min(pcm.len());
    let start = pcm.len().saturating_sub(take);
    state.clear();
    for &s in &pcm[start..] {
        state.push(f32::from(s));
    }
    // Pad if pcm was shorter than LPC_ORDER
    while state.len() < LPC_ORDER {
        state.insert(0, 0.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_concealer() {
        let plc = PacketLossConcealer::new(160);
        assert_eq!(plc.frame_size, 160);
        assert_eq!(plc.consecutive_losses, 0);
        assert_eq!(plc.history.len(), 160);
    }

    #[test]
    fn test_conceal_from_silence() {
        let mut plc = PacketLossConcealer::new(160);
        // No prior audio → concealment should produce silence
        let frame = plc.conceal();
        assert_eq!(frame.len(), 160);
        assert!(frame.iter().all(|&s| s == 0));
    }

    #[test]
    fn test_good_frame_resets_losses() {
        let mut plc = PacketLossConcealer::new(160);
        let _ = plc.conceal();
        let _ = plc.conceal();
        assert_eq!(plc.consecutive_losses, 2);

        plc.good_frame(&vec![100i16; 160]);
        assert_eq!(plc.consecutive_losses, 0);
    }

    #[test]
    fn test_consecutive_loss_attenuation() {
        let mut plc = PacketLossConcealer::new(160);

        // Feed a non-trivial signal
        let signal: Vec<i16> = (0..160)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let s = (f64::sin(2.0 * std::f64::consts::PI * 440.0 * f64::from(i) / 8000.0)
                    * 10000.0) as i16;
                s
            })
            .collect();
        plc.good_frame(&signal);

        // Each consecutive concealment should have less energy
        let mut prev_energy = f64::MAX;
        for _ in 0..MAX_CONCEAL_FRAMES {
            let frame = plc.conceal();
            let energy: f64 = frame.iter().map(|&s| f64::from(s) * f64::from(s)).sum();
            assert!(
                energy <= prev_energy,
                "Energy should decrease: {energy} > {prev_energy}"
            );
            prev_energy = energy;
        }

        // After MAX_CONCEAL_FRAMES, should be silence
        let frame = plc.conceal();
        assert!(frame.iter().all(|&s| s == 0), "Should be silent after max losses");
    }

    #[test]
    fn test_recover_crossfade() {
        let mut plc = PacketLossConcealer::new(160);

        // Feed a signal
        let signal: Vec<i16> = vec![1000i16; 160];
        plc.good_frame(&signal);

        // Lose a frame
        let _concealed = plc.conceal();
        assert_eq!(plc.consecutive_losses, 1);

        // Recover with a different signal
        let mut recovery = vec![500i16; 160];
        plc.recover(&mut recovery);

        // After recover, losses should be reset
        assert_eq!(plc.consecutive_losses, 0);
    }

    #[test]
    fn test_levinson_durbin_silence() {
        let silence = vec![0i16; 160];
        let coeffs = levinson_durbin(&silence);
        assert!(coeffs.iter().all(|&c| c == 0.0));
    }

    #[test]
    fn test_levinson_durbin_sine() {
        // Sine wave should produce non-zero coefficients
        let signal: Vec<i16> = (0..160)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let s = (f64::sin(2.0 * std::f64::consts::PI * 300.0 * f64::from(i) / 8000.0)
                    * 10000.0) as i16;
                s
            })
            .collect();

        let coeffs = levinson_durbin(&signal);
        // At least some coefficients should be non-zero for a sine wave
        assert!(coeffs.iter().any(|&c| c.abs() > 0.01));
    }

    #[test]
    fn test_attenuation_factors() {
        assert!((attenuation_factor(0) - 1.0).abs() < f32::EPSILON);
        assert!((attenuation_factor(1) - 0.9).abs() < f32::EPSILON);
        assert!((attenuation_factor(2) - 0.72).abs() < 0.01);
        assert!((attenuation_factor(3) - 0.576).abs() < 0.01);
    }
}
