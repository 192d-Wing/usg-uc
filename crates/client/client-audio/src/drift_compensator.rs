//! Clock drift compensation between remote sender and local hardware clock.
//!
//! VoIP audio has two independent clocks: the remote sender generates
//! packets at its clock rate, and the local hardware consumes samples at
//! its own rate. Even small differences (e.g., 50 ppm) accumulate over
//! a call, causing the jitter buffer to either grow (remote faster) or
//! empty (remote slower).
//!
//! This module tracks jitter buffer depth over a sliding window and
//! computes a sample-level adjustment for the resampler: occasionally
//! producing one more or one fewer output sample per frame to keep the
//! buffer centered at its target depth.

/// Sliding window size for depth measurements.
/// At ~25ms per measurement, 200 slots ≈ 5 seconds of history.
const WINDOW_SIZE: usize = 200;

/// Threshold for depth trend (ms/sec) before triggering compensation.
/// Set above normal network jitter (~0.5-1 ms/sec) to avoid constant
/// micro-corrections. Only real clock drift (>2 ms/sec) triggers adjustment.
const DRIFT_THRESHOLD_MS_PER_SEC: f32 = 2.0;

/// Maximum adjustment: +/- 1 sample per frame.
const MAX_ADJUSTMENT: i32 = 1;

/// Tracks jitter buffer depth and computes resampler adjustments.
pub struct DriftCompensator {
    /// Circular buffer of jitter buffer depth measurements (in ms).
    depth_history: Vec<f32>,
    /// Write index into depth_history.
    write_idx: usize,
    /// Number of samples collected so far.
    sample_count: usize,
    /// Measurement interval counter.
    measure_counter: u32,
    /// How many decode cycles between measurements.
    measure_interval: u32,
    /// Cumulative fractional adjustment.
    fractional_accumulator: f32,
}

impl DriftCompensator {
    /// Creates a new drift compensator.
    ///
    /// # Arguments
    /// * `measure_interval` - Number of decode cycles between depth measurements.
    ///   For a decode thread checking every ~5ms, `measure_interval=5` gives
    ///   one measurement per ~25ms, filling the 200-slot window in ~5 seconds.
    pub fn new(measure_interval: u32) -> Self {
        Self {
            depth_history: vec![0.0; WINDOW_SIZE],
            write_idx: 0,
            sample_count: 0,
            measure_counter: 0,
            measure_interval: measure_interval.max(1),
            fractional_accumulator: 0.0,
        }
    }

    /// Records a jitter buffer depth measurement and returns the sample
    /// count adjustment for the next resample operation.
    ///
    /// Returns 0 (no adjustment), +1 (produce one extra sample to slow
    /// consumption), or -1 (produce one fewer sample to speed consumption).
    pub fn update(&mut self, current_depth_ms: f32) -> i32 {
        self.measure_counter += 1;
        if self.measure_counter < self.measure_interval {
            return 0;
        }
        self.measure_counter = 0;

        // Record measurement
        self.depth_history[self.write_idx] = current_depth_ms;
        self.write_idx = (self.write_idx + 1) % WINDOW_SIZE;
        self.sample_count = (self.sample_count + 1).min(WINDOW_SIZE);

        // Need at least a quarter of the window before making adjustments
        // (50 measurements × ~25ms ≈ 1.25 seconds warmup)
        if self.sample_count < WINDOW_SIZE / 4 {
            return 0;
        }

        // Compute linear regression slope over the window
        let slope = self.compute_slope();

        // slope is in ms per measurement.
        // Convert to ms/sec: slope * measurements_per_sec.
        // Each measurement is taken every (measure_interval * ~10ms) ≈ 100ms,
        // so ~10 measurements per second.
        let measurements_per_sec = 1000.0 / (self.measure_interval as f32 * 10.0);
        let drift_ms_per_sec = slope * measurements_per_sec;

        if drift_ms_per_sec > DRIFT_THRESHOLD_MS_PER_SEC {
            // Buffer growing → remote clock faster → consume faster → fewer output samples
            self.fractional_accumulator -= 0.1;
        } else if drift_ms_per_sec < -DRIFT_THRESHOLD_MS_PER_SEC {
            // Buffer shrinking → remote clock slower → consume slower → more output samples
            self.fractional_accumulator += 0.1;
        } else {
            // Within threshold, slowly decay accumulator toward zero
            self.fractional_accumulator *= 0.95;
        }

        // Extract integer adjustment when accumulator reaches ±1.0
        if self.fractional_accumulator >= 1.0 {
            self.fractional_accumulator -= 1.0;
            MAX_ADJUSTMENT
        } else if self.fractional_accumulator <= -1.0 {
            self.fractional_accumulator += 1.0;
            -MAX_ADJUSTMENT
        } else {
            0
        }
    }

    /// Computes the linear regression slope of depth measurements.
    fn compute_slope(&self) -> f32 {
        let n = self.sample_count as f32;
        let mut sum_x: f32 = 0.0;
        let mut sum_y: f32 = 0.0;
        let mut sum_xy: f32 = 0.0;
        let mut sum_x2: f32 = 0.0;

        let start = if self.sample_count == WINDOW_SIZE {
            self.write_idx
        } else {
            0
        };

        for i in 0..self.sample_count {
            let idx = (start + i) % WINDOW_SIZE;
            let x = i as f32;
            let y = self.depth_history[idx];
            sum_x += x;
            sum_y += y;
            sum_xy += x * y;
            sum_x2 += x * x;
        }

        let denominator = n * sum_x2 - sum_x * sum_x;
        if denominator.abs() < f32::EPSILON {
            return 0.0;
        }

        (n * sum_xy - sum_x * sum_y) / denominator
    }

    /// Resets the compensator state.
    pub fn reset(&mut self) {
        self.depth_history.fill(0.0);
        self.write_idx = 0;
        self.sample_count = 0;
        self.measure_counter = 0;
        self.fractional_accumulator = 0.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_adjustment_initially() {
        let mut dc = DriftCompensator::new(1);

        // First WINDOW_SIZE/4 measurements should return 0 (warmup period)
        for i in 0..WINDOW_SIZE / 4 {
            let adj = dc.update(60.0);
            assert_eq!(adj, 0, "Expected no adjustment at measurement {i}");
        }
    }

    #[test]
    fn test_stable_depth_no_adjustment() {
        let mut dc = DriftCompensator::new(1);

        // Fill the window with constant depth — no drift
        for _ in 0..WINDOW_SIZE * 2 {
            let adj = dc.update(60.0);
            assert_eq!(adj, 0);
        }
    }

    #[test]
    fn test_growing_buffer_negative_adjustment() {
        let mut dc = DriftCompensator::new(1);
        let mut total_adj: i32 = 0;

        // Simulate a growing jitter buffer (remote clock faster)
        for i in 0..WINDOW_SIZE * 3 {
            let depth = 60.0 + (i as f32 * 0.05); // Steadily growing
            total_adj += dc.update(depth);
        }

        // Over time, should produce negative adjustments (speed up consumption)
        assert!(
            total_adj < 0,
            "Expected negative total adjustment for growing buffer, got {total_adj}"
        );
    }

    #[test]
    fn test_shrinking_buffer_positive_adjustment() {
        let mut dc = DriftCompensator::new(1);
        let mut total_adj: i32 = 0;

        // Simulate a shrinking jitter buffer (remote clock slower)
        for i in 0..WINDOW_SIZE * 3 {
            let depth = 120.0 - (i as f32 * 0.05); // Steadily shrinking
            total_adj += dc.update(depth);
        }

        // Over time, should produce positive adjustments (slow down consumption)
        assert!(
            total_adj > 0,
            "Expected positive total adjustment for shrinking buffer, got {total_adj}"
        );
    }

    #[test]
    fn test_reset() {
        let mut dc = DriftCompensator::new(1);
        for i in 0..WINDOW_SIZE {
            dc.update(60.0 + i as f32 * 0.1);
        }
        dc.reset();
        assert_eq!(dc.sample_count, 0);
        assert_eq!(dc.write_idx, 0);
        assert_eq!(dc.fractional_accumulator, 0.0);
    }

    #[test]
    fn test_measure_interval_skipping() {
        let mut dc = DriftCompensator::new(10);

        // With interval=10, first 9 calls should always return 0
        for _ in 0..9 {
            assert_eq!(dc.update(60.0), 0);
        }
        // 10th call actually records a measurement
        assert_eq!(dc.update(60.0), 0); // Still 0 because not enough data
        assert_eq!(dc.sample_count, 1);
    }
}
