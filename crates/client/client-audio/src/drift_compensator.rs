//! Clock drift compensation between remote sender and local hardware clock.
//!
//! `VoIP` audio has two independent clocks: the remote sender generates
//! packets at its clock rate, and the local hardware consumes samples at
//! its own rate. Even small differences (e.g., 50 ppm) accumulate over
//! a call, causing the jitter buffer to either grow (remote faster) or
//! empty (remote slower).
//!
//! This module uses an EMA-smoothed jitter buffer depth compared to a
//! target depth established during warmup. When the smoothed depth
//! deviates beyond a dead zone, proportional corrections are applied
//! to the resampler output length (±1 sample per frame).

/// Number of measurements during warmup to establish the target depth.
/// At ~5ms per measurement (measure_interval=1 in decode thread),
/// 40 measurements ≈ 200ms warmup.
const WARMUP_MEASUREMENTS: usize = 40;

/// EMA smoothing factor. Lower values = heavier smoothing.
/// 0.05 gives a time constant of ~20 measurements (≈100ms at 5ms/measurement).
/// This filters out per-packet jitter (8-16ms) while tracking real drift.
const SMOOTHING_ALPHA: f32 = 0.05;

/// Dead zone: ignore depth errors smaller than this (in ms).
/// Normal network jitter causes ±3ms fluctuation. Only correct
/// when the smoothed depth deviates beyond this threshold.
const DEAD_ZONE_MS: f32 = 3.0;

/// Proportional correction gain.
/// Higher values correct faster but may overshoot.
/// At gain 0.15 with error 10ms: accumulator += 1.5 per measurement.
/// With ~200 measurements/sec (measure_interval=1), that's ~300/sec,
/// yielding ~300 corrections/sec = ~300/44100 ≈ 6.8 ms/sec correction rate.
const CORRECTION_GAIN: f32 = 0.15;

/// Maximum adjustment: +/- 1 sample per frame.
const MAX_ADJUSTMENT: i32 = 1;

/// Tracks jitter buffer depth and computes resampler adjustments.
pub struct DriftCompensator {
    /// EMA-smoothed jitter buffer depth (ms).
    smoothed_depth: f32,
    /// Target depth established during warmup (ms).
    target_depth: f32,
    /// Sum of depth measurements during warmup.
    warmup_sum: f32,
    /// Number of measurements collected so far.
    measurement_count: usize,
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
    ///   Use 1 for every decode cycle (~5ms), giving ~200 measurements/sec.
    pub fn new(measure_interval: u32) -> Self {
        Self {
            smoothed_depth: 0.0,
            target_depth: 0.0,
            warmup_sum: 0.0,
            measurement_count: 0,
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

        self.measurement_count += 1;

        // --- Warmup phase: establish target depth ---
        if self.measurement_count <= WARMUP_MEASUREMENTS {
            self.warmup_sum += current_depth_ms;

            if self.measurement_count == WARMUP_MEASUREMENTS {
                #[allow(clippy::cast_precision_loss)]
                let avg = self.warmup_sum / WARMUP_MEASUREMENTS as f32;
                self.target_depth = avg;
                self.smoothed_depth = avg;
            }
            return 0;
        }

        // --- Active phase: EMA smooth and correct ---
        self.smoothed_depth += SMOOTHING_ALPHA * (current_depth_ms - self.smoothed_depth);

        let error = self.smoothed_depth - self.target_depth;

        if error > DEAD_ZONE_MS {
            // Buffer growing → produce fewer output samples to consume faster
            // Negative accumulator → negative adjustment
            self.fractional_accumulator -= (error - DEAD_ZONE_MS) * CORRECTION_GAIN;
        } else if error < -DEAD_ZONE_MS {
            // Buffer shrinking → produce more output samples to slow consumption
            // Positive accumulator → positive adjustment
            self.fractional_accumulator -= (error + DEAD_ZONE_MS) * CORRECTION_GAIN;
        } else {
            // Within dead zone — slowly decay accumulator to avoid residual bias
            self.fractional_accumulator *= 0.99;
        }

        // Clamp accumulator to prevent runaway after sustained drift
        self.fractional_accumulator = self.fractional_accumulator.clamp(-5.0, 5.0);

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

    /// Resets the compensator state.
    pub fn reset(&mut self) {
        self.smoothed_depth = 0.0;
        self.target_depth = 0.0;
        self.warmup_sum = 0.0;
        self.measurement_count = 0;
        self.measure_counter = 0;
        self.fractional_accumulator = 0.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_adjustment_during_warmup() {
        let mut dc = DriftCompensator::new(1);

        // All warmup measurements should return 0
        for i in 0..WARMUP_MEASUREMENTS {
            let adj = dc.update(60.0);
            assert_eq!(adj, 0, "Expected no adjustment at warmup measurement {i}");
        }
    }

    #[test]
    fn test_stable_depth_no_adjustment() {
        let mut dc = DriftCompensator::new(1);

        // Warmup + many stable measurements → no drift, no correction
        for _ in 0..WARMUP_MEASUREMENTS + 500 {
            let adj = dc.update(60.0);
            assert_eq!(adj, 0);
        }
    }

    #[test]
    fn test_growing_buffer_negative_adjustment() {
        let mut dc = DriftCompensator::new(1);
        let mut total_adj: i32 = 0;

        // Warmup at 60ms
        for _ in 0..WARMUP_MEASUREMENTS {
            dc.update(60.0);
        }

        // Simulate growing jitter buffer (remote clock faster)
        // Depth increases from 60ms toward 80ms over 600 measurements
        for i in 0..600 {
            #[allow(clippy::cast_precision_loss)]
            let depth = 60.0 + (i as f32 * 0.05);
            total_adj += dc.update(depth);
        }

        // Should produce negative adjustments (speed up consumption)
        assert!(
            total_adj < 0,
            "Expected negative total adjustment for growing buffer, got {total_adj}"
        );
    }

    #[test]
    fn test_shrinking_buffer_positive_adjustment() {
        let mut dc = DriftCompensator::new(1);
        let mut total_adj: i32 = 0;

        // Warmup at 80ms
        for _ in 0..WARMUP_MEASUREMENTS {
            dc.update(80.0);
        }

        // Simulate shrinking jitter buffer (remote clock slower)
        for i in 0..600 {
            #[allow(clippy::cast_precision_loss)]
            let depth = 80.0 - (i as f32 * 0.05);
            total_adj += dc.update(depth);
        }

        // Should produce positive adjustments (slow down consumption)
        assert!(
            total_adj > 0,
            "Expected positive total adjustment for shrinking buffer, got {total_adj}"
        );
    }

    #[test]
    fn test_jittery_but_stable_no_correction() {
        let mut dc = DriftCompensator::new(1);

        // Warmup at 60ms
        for _ in 0..WARMUP_MEASUREMENTS {
            dc.update(60.0);
        }

        // Jittery depth ±2ms around target (within dead zone)
        let mut total_adj: i32 = 0;
        for i in 0..1000 {
            #[allow(clippy::cast_precision_loss)]
            let jitter = 2.0 * (i as f32 * 0.1).sin();
            total_adj += dc.update(60.0 + jitter);
        }

        // Should be zero or very near zero
        assert!(
            total_adj.abs() <= 2,
            "Expected near-zero adjustment for jittery-but-stable depth, got {total_adj}"
        );
    }

    #[test]
    fn test_reset() {
        let mut dc = DriftCompensator::new(1);
        for _ in 0..WARMUP_MEASUREMENTS + 100 {
            dc.update(60.0);
        }
        dc.reset();
        assert_eq!(dc.measurement_count, 0);
        assert_eq!(dc.fractional_accumulator, 0.0);
        assert_eq!(dc.target_depth, 0.0);
    }

    #[test]
    fn test_measure_interval_skipping() {
        let mut dc = DriftCompensator::new(10);

        // With interval=10, first 9 calls should always return 0
        for _ in 0..9 {
            assert_eq!(dc.update(60.0), 0);
        }
        // 10th call records a measurement
        assert_eq!(dc.update(60.0), 0); // Still 0 because in warmup
        assert_eq!(dc.measurement_count, 1);
    }

    #[test]
    fn test_accumulator_clamped() {
        let mut dc = DriftCompensator::new(1);

        // Warmup at 20ms
        for _ in 0..WARMUP_MEASUREMENTS {
            dc.update(20.0);
        }

        // Huge spike — accumulator should not run away
        for _ in 0..100 {
            dc.update(200.0);
        }

        assert!(
            dc.fractional_accumulator.abs() <= 5.0,
            "Accumulator should be clamped, got {}",
            dc.fractional_accumulator
        );
    }
}
