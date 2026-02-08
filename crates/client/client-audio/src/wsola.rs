//! WSOLA (Waveform Similarity Overlap-Add) Packet Loss Concealment.
//!
//! When an RTP packet is lost, this module generates a replacement frame by
//! finding the best pitch-period match in recent audio history and repeating
//! it with smooth overlap-add blending. This produces more natural-sounding
//! concealment than LPC synthesis for voiced speech (sustained vowels, etc.).
//!
//! Algorithm based on pjproject's WSOLA implementation, adapted for our
//! 8 kHz / 160-sample (20 ms) frame pipeline.
//!
//! ## Operation
//!
//! 1. Maintain a circular buffer of recent decoded audio (history).
//! 2. On loss, use the tail of the buffer as a template and search the
//!    history for the best pitch-period match via cross-correlation.
//! 3. Overlap-add the matched segment with a Hanning window to produce
//!    a smooth synthetic continuation.
//! 4. Apply progressive linear fade-out for extended losses.
//! 5. On recovery, Hanning cross-fade from synthetic tail into real frame.

use std::f32::consts::PI;

/// Number of frames held in the circular buffer.
const BUF_FRAMES: usize = 6;

/// History size in frames (1.5 frames for pitch search depth).
const HIST_FRAMES_NUM: usize = 3;
const HIST_FRAMES_DEN: usize = 2;

/// Hanning window size in samples (5 ms at 8 kHz = 40 samples).
/// Used for overlap-add blending and recovery cross-fade.
const HANNING_SIZE: usize = 40;

/// Maximum expansion duration in milliseconds before full mute.
/// After this many ms of continuous loss, output fades to silence.
const MAX_EXPAND_MS: usize = 80;

/// Minimum pitch search distance in frames (0.5 frame).
/// Prevents matching the template against itself.
const MIN_PITCH_FRAMES_NUM: usize = 1;
const MIN_PITCH_FRAMES_DEN: usize = 2;

/// WSOLA-based packet loss concealer.
///
/// Drop-in replacement for LPC-based `PacketLossConcealer` with the same
/// public API: `good_frame()`, `conceal()`, `recover()`.
pub struct WsolaPlc {
    /// Circular audio buffer holding history + extra.
    buf: Vec<i16>,
    /// Total buffer capacity in samples.
    buf_size: usize,
    /// Number of valid samples currently in the buffer.
    cur_cnt: usize,
    /// History portion size in samples.
    hist_size: usize,
    /// Minimum extra samples (Hanning window size) for crossfade.
    min_extra: usize,
    /// Pre-computed Hanning window for overlap-add.
    hanning: Vec<f32>,
    /// Template size for pitch matching (= `frame_size`).
    template_size: usize,
    /// Samples per frame.
    frame_size: usize,
    /// Current fade-out position (samples of expansion generated so far).
    fade_out_pos: usize,
    /// Maximum samples of expansion before full mute.
    max_expand_cnt: usize,
    /// Minimum pitch search distance in samples.
    min_pitch_dist: usize,
    /// Number of consecutive lost frames.
    consecutive_losses: u32,
    /// Whether the previous frame was lost (for recovery cross-fade).
    prev_lost: bool,
}

impl WsolaPlc {
    /// Creates a new WSOLA PLC for the given frame size.
    ///
    /// Standard: `frame_size = 160` for G.711 at 8 kHz (20 ms).
    pub fn new(frame_size: usize) -> Self {
        let buf_size = BUF_FRAMES * frame_size;
        let hist_size = HIST_FRAMES_NUM * frame_size / HIST_FRAMES_DEN;
        let min_extra = HANNING_SIZE;
        let template_size = frame_size;
        let max_expand_cnt = MAX_EXPAND_MS * 8; // 8 samples/ms at 8 kHz
        let min_pitch_dist = MIN_PITCH_FRAMES_NUM * frame_size / MIN_PITCH_FRAMES_DEN;

        // Pre-compute Hanning window
        let hanning = create_hanning_window(HANNING_SIZE);

        Self {
            buf: vec![0i16; buf_size],
            buf_size,
            cur_cnt: hist_size + min_extra, // Start with minimum valid content
            hist_size,
            min_extra,
            hanning,
            template_size,
            frame_size,
            fade_out_pos: 0,
            max_expand_cnt,
            min_pitch_dist,
            consecutive_losses: 0,
            prev_lost: false,
        }
    }

    /// Records a successfully decoded frame.
    ///
    /// Must be called for every good frame to keep the history buffer current.
    pub fn good_frame(&mut self, pcm: &[i16]) {
        let len = pcm.len().min(self.frame_size);

        if self.prev_lost {
            // Cross-fade the transition region: blend buffer tail with
            // the start of the real frame using the Hanning window.
            self.crossfade_in(pcm);
        }

        // Append new frame to the buffer
        self.append_to_buf(pcm, len);

        // Shift buffer to maintain history at front
        self.shift_buf();

        self.consecutive_losses = 0;
        self.prev_lost = false;
        self.fade_out_pos = 0;
    }

    /// Generates a concealment frame to replace a lost packet.
    ///
    /// Returns a buffer of `frame_size` samples.
    #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
    pub fn conceal(&mut self) -> Vec<i16> {
        self.consecutive_losses += 1;
        self.prev_lost = true;

        // If we've been expanding too long, output silence
        if self.fade_out_pos >= self.max_expand_cnt {
            return vec![0i16; self.frame_size];
        }

        // Expand: synthesize new samples via pitch matching
        self.expand();

        // Extract the synthesized frame from the buffer
        // (it's after the history + min_extra region)
        let read_start = self.hist_size + self.min_extra;
        let read_end = (read_start + self.frame_size).min(self.cur_cnt);
        let mut output = vec![0i16; self.frame_size];
        let available = read_end.saturating_sub(read_start);
        if available > 0 {
            output[..available].copy_from_slice(&self.buf[read_start..read_end]);
        }

        // Apply linear fade-out for extended losses
        let fade_start = self.fade_out_pos;
        self.fade_out_pos += self.frame_size;
        for (i, sample) in output.iter_mut().enumerate() {
            let pos = fade_start + i;
            if pos >= self.max_expand_cnt {
                *sample = 0;
            } else {
                let gain = 1.0 - (pos as f32 / self.max_expand_cnt as f32);
                *sample = (f32::from(*sample) * gain) as i16;
            }
        }

        // Shift buffer for next iteration
        self.shift_buf();

        output
    }

    /// Cross-fades from the concealment tail into a recovered real frame.
    ///
    /// Call this instead of `good_frame()` on the first good frame after
    /// one or more lost frames to avoid a click/discontinuity.
    pub fn recover(&mut self, real_frame: &mut [i16]) {
        if !self.prev_lost {
            self.good_frame(real_frame);
            return;
        }

        // The good_frame call will handle the cross-fade internally
        // (it checks prev_lost and calls crossfade_in)
        self.good_frame(real_frame);
    }

    /// Returns the number of consecutive losses.
    pub const fn consecutive_losses(&self) -> u32 {
        self.consecutive_losses
    }

    // --- Private methods ---

    /// Expands the buffer by one frame using pitch-matched waveform repetition.
    fn expand(&mut self) {
        // Template: the last template_size samples in the valid buffer
        let template_end = self.cur_cnt.min(self.buf_size);
        let template_start = template_end.saturating_sub(self.template_size);
        if template_start >= template_end {
            return;
        }

        // Search region: history portion, offset by min pitch distance
        let search_end = template_start.saturating_sub(self.min_pitch_dist);
        let search_start = search_end.saturating_sub(self.hist_size);
        if search_start >= search_end || search_end - search_start < self.template_size {
            // Not enough history for pitch matching — repeat last frame
            self.repeat_last_frame();
            return;
        }

        // Find the best pitch match
        let best_offset = self.find_pitch(template_start, template_end, search_start, search_end);

        // Overlap-add the matched segment into the buffer
        let match_start = search_start + best_offset;
        let match_end = (match_start + self.frame_size + self.min_extra).min(self.buf_size);
        let copy_len = match_end.saturating_sub(match_start);

        if copy_len == 0 {
            self.repeat_last_frame();
            return;
        }

        // Build the expanded segment: overlap-add at the junction
        let write_start = self.cur_cnt.min(self.buf_size);
        let write_end = (write_start + copy_len).min(self.buf_size);
        let actual_copy = write_end - write_start;

        if actual_copy == 0 {
            return;
        }

        // Copy matched segment, applying Hanning overlap at the start
        let overlap_len = self.min_extra.min(actual_copy);
        let junction = write_start;

        // Overlap region: blend buffer tail with matched segment start
        if junction >= overlap_len {
            for i in 0..overlap_len {
                let buf_idx = junction - overlap_len + i;
                let match_idx = match_start + i;
                if buf_idx < self.buf_size && match_idx < self.buf_size {
                    let left = f32::from(self.buf[buf_idx]);
                    let right = f32::from(self.buf[match_idx]);
                    let w = self.hanning[i];
                    let blended = left.mul_add(1.0 - w, right * w);
                    #[allow(clippy::cast_possible_truncation)]
                    { self.buf[buf_idx] = blended.clamp(-32768.0, 32767.0) as i16; }
                }
            }
        }

        // Copy the rest of the matched segment after the overlap
        for i in overlap_len..actual_copy {
            let src = match_start + i;
            // The overlap replaced the tail, so new data goes after
            let dst = junction + i - overlap_len;
            if dst < self.buf_size && src < self.buf_size {
                self.buf[dst] = self.buf[src];
            }
        }

        self.cur_cnt = (junction + actual_copy - overlap_len).min(self.buf_size);
    }

    /// Finds the best pitch match via normalized cross-correlation.
    ///
    /// Returns the offset (relative to `search_start`) of the best match.
    fn find_pitch(
        &self,
        template_start: usize,
        template_end: usize,
        search_start: usize,
        search_end: usize,
    ) -> usize {
        let template_len = template_end - template_start;
        let search_len = search_end - search_start;

        if search_len < template_len {
            return 0;
        }

        let max_offset = search_len - template_len;
        let mut best_corr = f64::NEG_INFINITY;
        let mut best_offset = 0;

        for offset in 0..=max_offset {
            let mut corr = 0.0f64;
            let mut energy = 0.0f64;
            for i in 0..template_len {
                let t = f64::from(self.buf[template_start + i]);
                let s = f64::from(self.buf[search_start + offset + i]);
                corr += t * s;
                energy += s * s;
            }

            // Normalize by candidate energy to prevent bias toward loud segments
            let norm_corr = if energy > 1.0 { corr / energy.sqrt() } else { 0.0 };

            if norm_corr > best_corr {
                best_corr = norm_corr;
                best_offset = offset;
            }
        }

        best_offset
    }

    /// Fallback: repeats the last frame when not enough history for pitch matching.
    fn repeat_last_frame(&mut self) {
        let end = self.cur_cnt.min(self.buf_size);
        let start = end.saturating_sub(self.frame_size);
        if start >= end {
            return;
        }

        // Copy the last frame to a temp buffer, then append
        let frame: Vec<i16> = self.buf[start..end].to_vec();
        let write_start = end;
        let write_end = (write_start + frame.len()).min(self.buf_size);
        let copy_len = write_end - write_start;
        if copy_len > 0 {
            self.buf[write_start..write_end].copy_from_slice(&frame[..copy_len]);
            self.cur_cnt = write_end;
        }
    }

    /// Cross-fades the real frame into the buffer's tail region.
    #[allow(clippy::cast_possible_truncation)]
    fn crossfade_in(&mut self, real_frame: &[i16]) {
        let fade_len = self.min_extra.min(real_frame.len());
        let buf_end = self.cur_cnt.min(self.buf_size);
        let buf_start = buf_end.saturating_sub(fade_len);

        for (i, (&real_sample, &w)) in real_frame.iter().zip(&self.hanning).take(fade_len).enumerate() {
            let buf_idx = buf_start + i;
            if buf_idx < self.buf_size {
                let synthetic = f32::from(self.buf[buf_idx]);
                let real = f32::from(real_sample);
                let blended = synthetic.mul_add(1.0 - w, real * w);
                self.buf[buf_idx] = blended.clamp(-32768.0, 32767.0) as i16;
            }
        }
    }

    /// Appends samples to the buffer.
    fn append_to_buf(&mut self, pcm: &[i16], len: usize) {
        let write_start = self.cur_cnt;
        let write_end = (write_start + len).min(self.buf_size);
        let copy_len = write_end - write_start;
        if copy_len > 0 {
            self.buf[write_start..write_end].copy_from_slice(&pcm[..copy_len]);
            self.cur_cnt = write_end;
        }
    }

    /// Shifts the buffer so that history stays at the front.
    /// Removes old data beyond the history + content region.
    fn shift_buf(&mut self) {
        let target = self.hist_size + self.min_extra + self.frame_size;
        if self.cur_cnt > target {
            let shift = self.cur_cnt - target;
            self.buf.copy_within(shift..self.cur_cnt, 0);
            self.cur_cnt -= shift;
        }
    }
}

/// Creates a Hanning window of the given size.
///
/// `w[i] = 0.5 - 0.5 * cos(2π * i / (2*N - 1))`
///
/// This produces a half-window ramp from 0 to 1, suitable for overlap-add
/// blending where left uses `(1-w)` and right uses `w`.
fn create_hanning_window(size: usize) -> Vec<f32> {
    #[allow(clippy::cast_precision_loss)]
    let denom = (2 * size - 1) as f32;
    (0..size)
        .map(|i| {
            #[allow(clippy::cast_precision_loss)]
            let phase = (2.0 * PI * i as f32 / denom).cos();
            0.5f32.mul_add(-phase, 0.5)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_wsola() {
        let plc = WsolaPlc::new(160);
        assert_eq!(plc.frame_size, 160);
        assert_eq!(plc.consecutive_losses, 0);
        assert!(!plc.prev_lost);
    }

    #[test]
    fn test_conceal_from_silence() {
        let mut plc = WsolaPlc::new(160);
        // No prior audio — concealment should produce near-silence
        let frame = plc.conceal();
        assert_eq!(frame.len(), 160);
        // Buffer starts zeroed, so concealment from silence = silence
        assert!(frame.iter().all(|&s| s.abs() < 10));
    }

    #[test]
    fn test_good_frame_resets_losses() {
        let mut plc = WsolaPlc::new(160);
        let _ = plc.conceal();
        let _ = plc.conceal();
        assert_eq!(plc.consecutive_losses, 2);

        plc.good_frame(&vec![100i16; 160]);
        assert_eq!(plc.consecutive_losses, 0);
    }

    #[test]
    fn test_good_frame_resets_prev_lost() {
        let mut plc = WsolaPlc::new(160);
        let _ = plc.conceal();
        assert!(plc.prev_lost);
        plc.good_frame(&vec![100i16; 160]);
        assert!(!plc.prev_lost);
    }

    #[test]
    fn test_consecutive_loss_fade_out() {
        let mut plc = WsolaPlc::new(160);

        // Feed a non-trivial signal so concealment isn't all zeros
        let signal: Vec<i16> = (0..160)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let s = (f64::sin(2.0 * std::f64::consts::PI * 440.0 * f64::from(i) / 8000.0)
                    * 10000.0) as i16;
                s
            })
            .collect();
        // Feed several frames to build up history
        for _ in 0..4 {
            plc.good_frame(&signal);
        }

        // Each consecutive concealment should eventually have less energy
        let mut energies = Vec::new();
        for _ in 0..8 {
            let frame = plc.conceal();
            let energy: f64 = frame.iter().map(|&s| f64::from(s) * f64::from(s)).sum();
            energies.push(energy);
        }

        // Energy should trend downward (fade-out)
        // The last frame should have significantly less energy than the first
        let first_energy = energies[0];
        let last_energy = energies[energies.len() - 1];
        assert!(
            last_energy <= first_energy,
            "Energy should fade: first={first_energy}, last={last_energy}"
        );
    }

    #[test]
    fn test_full_mute_after_max_expand() {
        let mut plc = WsolaPlc::new(160);

        // Feed audio
        let signal: Vec<i16> = vec![1000i16; 160];
        for _ in 0..4 {
            plc.good_frame(&signal);
        }

        // Conceal many frames until fully muted
        // MAX_EXPAND_MS=80 → 640 samples → 4 frames of 160
        let mut all_silent = false;
        for _ in 0..10 {
            let frame = plc.conceal();
            if frame.iter().all(|&s| s == 0) {
                all_silent = true;
                break;
            }
        }
        assert!(all_silent, "Should reach full mute after max expansion");
    }

    #[test]
    fn test_recover_resets_state() {
        let mut plc = WsolaPlc::new(160);

        let signal: Vec<i16> = vec![500i16; 160];
        plc.good_frame(&signal);

        // Lose a frame
        let _ = plc.conceal();
        assert!(plc.prev_lost);
        assert_eq!(plc.consecutive_losses, 1);

        // Recover
        let mut recovery = vec![500i16; 160];
        plc.recover(&mut recovery);

        assert!(!plc.prev_lost);
        assert_eq!(plc.consecutive_losses, 0);
    }

    #[test]
    fn test_hanning_window() {
        let win = create_hanning_window(40);
        assert_eq!(win.len(), 40);
        // First sample should be near 0
        assert!(win[0] < 0.05, "First sample should be near 0, got {}", win[0]);
        // Last sample should be near 1
        assert!(
            win[39] > 0.95,
            "Last sample should be near 1, got {}",
            win[39]
        );
        // Window should be monotonically increasing (half-window)
        for i in 1..40 {
            assert!(
                win[i] >= win[i - 1],
                "Window not monotonic at {i}: {} < {}",
                win[i],
                win[i - 1]
            );
        }
    }

    #[test]
    fn test_pitch_matching_sine() {
        let mut plc = WsolaPlc::new(160);

        // Feed a pure sine wave — pitch matching should find the period
        let freq = 400.0; // 400 Hz → 20 sample period at 8 kHz
        let signal: Vec<i16> = (0..160)
            .map(|i| {
                #[allow(clippy::cast_possible_truncation)]
                let s =
                    (f64::sin(2.0 * std::f64::consts::PI * freq * f64::from(i) / 8000.0) * 10000.0)
                        as i16;
                s
            })
            .collect();

        // Feed multiple frames to build up history
        for _ in 0..4 {
            plc.good_frame(&signal);
        }

        // Concealed frame should have non-trivial energy (not silence)
        let concealed = plc.conceal();
        let energy: f64 = concealed.iter().map(|&s| f64::from(s) * f64::from(s)).sum();
        assert!(
            energy > 1000.0,
            "Concealed sine should have significant energy, got {energy}"
        );
    }

    #[test]
    fn test_conceal_frame_size() {
        let mut plc = WsolaPlc::new(160);
        let frame = plc.conceal();
        assert_eq!(frame.len(), 160);

        let mut plc80 = WsolaPlc::new(80);
        let frame = plc80.conceal();
        assert_eq!(frame.len(), 80);
    }
}
