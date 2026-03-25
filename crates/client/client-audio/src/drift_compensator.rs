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

/// Configuration for clock drift compensation.
#[derive(Debug, Clone)]
pub struct DriftConfig {
    /// Number of measurements during warmup to establish the target depth.
    /// At ~5ms per measurement, 40 measurements ≈ 200ms warmup.
    pub warmup_measurements: usize,
    /// EMA smoothing factor (0.0-1.0). Lower = heavier smoothing.
    pub smoothing_alpha: f32,
    /// Dead zone: ignore depth errors smaller than this (ms).
    pub dead_zone_ms: f32,
    /// Proportional correction gain. Higher = faster correction but may overshoot.
    pub correction_gain: f32,
    /// Maximum adjustment per frame in samples.
    pub max_adjustment: i32,
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self {
            warmup_measurements: 40,
            smoothing_alpha: 0.05,
            dead_zone_ms: 3.0,
            correction_gain: 0.15,
            max_adjustment: 1,
        }
    }
}

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
    /// Configuration parameters.
    cfg: DriftConfig,
}

impl DriftCompensator {
    /// Creates a new drift compensator with default configuration.
    ///
    /// # Arguments
    /// * `measure_interval` - Number of decode cycles between depth measurements.
    ///   Use 1 for every decode cycle (~5ms), giving ~200 measurements/sec.
    pub fn new(measure_interval: u32) -> Self {
        Self::with_config(measure_interval, DriftConfig::default())
    }

    /// Creates a drift compensator with custom configuration.
    pub fn with_config(measure_interval: u32, cfg: DriftConfig) -> Self {
        Self {
            smoothed_depth: 0.0,
            target_depth: 0.0,
            warmup_sum: 0.0,
            measurement_count: 0,
            measure_counter: 0,
            measure_interval: measure_interval.max(1),
            fractional_accumulator: 0.0,
            cfg,
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
        if self.measurement_count <= self.cfg.warmup_measurements {
            self.warmup_sum += current_depth_ms;

            if self.measurement_count == self.cfg.warmup_measurements {
                #[allow(clippy::cast_precision_loss)]
                let avg = self.warmup_sum / self.cfg.warmup_measurements as f32;
                self.target_depth = avg;
                self.smoothed_depth = avg;
            }
            return 0;
        }

        // --- Active phase: EMA smooth and correct ---
        self.smoothed_depth += self.cfg.smoothing_alpha * (current_depth_ms - self.smoothed_depth);

        let error = self.smoothed_depth - self.target_depth;

        if error > self.cfg.dead_zone_ms {
            // Buffer growing → produce fewer output samples to consume faster
            // Negative accumulator → negative adjustment
            self.fractional_accumulator -=
                (error - self.cfg.dead_zone_ms) * self.cfg.correction_gain;
        } else if error < -self.cfg.dead_zone_ms {
            // Buffer shrinking → produce more output samples to slow consumption
            // Positive accumulator → positive adjustment
            self.fractional_accumulator -=
                (error + self.cfg.dead_zone_ms) * self.cfg.correction_gain;
        } else {
            // Within dead zone — slowly decay accumulator to avoid residual bias
            self.fractional_accumulator *= 0.99;
        }

        // Clamp accumulator to prevent runaway after sustained drift
        self.fractional_accumulator = self.fractional_accumulator.clamp(-5.0, 5.0);

        // Extract integer adjustment when accumulator reaches ±1.0
        if self.fractional_accumulator >= 1.0 {
            self.fractional_accumulator -= 1.0;
            self.cfg.max_adjustment
        } else if self.fractional_accumulator <= -1.0 {
            self.fractional_accumulator += 1.0;
            -self.cfg.max_adjustment
        } else {
            0
        }
    }

    /// Resets the compensator state.
    pub const fn reset(&mut self) {
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
        for i in 0..DriftConfig::default().warmup_measurements {
            let adj = dc.update(60.0);
            assert_eq!(adj, 0, "Expected no adjustment at warmup measurement {i}");
        }
    }

    #[test]
    fn test_stable_depth_no_adjustment() {
        let mut dc = DriftCompensator::new(1);

        // Warmup + many stable measurements → no drift, no correction
        for _ in 0..DriftConfig::default().warmup_measurements + 500 {
            let adj = dc.update(60.0);
            assert_eq!(adj, 0);
        }
    }

    #[test]
    fn test_growing_buffer_negative_adjustment() {
        let mut dc = DriftCompensator::new(1);
        let mut total_adj: i32 = 0;

        // Warmup at 60ms
        for _ in 0..DriftConfig::default().warmup_measurements {
            dc.update(60.0);
        }

        // Simulate growing jitter buffer (remote clock faster)
        // Depth increases from 60ms toward 80ms over 600 measurements
        for i in 0..600 {
            #[allow(clippy::cast_precision_loss)]
            let depth = (i as f32).mul_add(0.05, 60.0);
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
        for _ in 0..DriftConfig::default().warmup_measurements {
            dc.update(80.0);
        }

        // Simulate shrinking jitter buffer (remote clock slower)
        for i in 0..600 {
            #[allow(clippy::cast_precision_loss)]
            let depth = (i as f32).mul_add(-0.05, 80.0);
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
        for _ in 0..DriftConfig::default().warmup_measurements {
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
        for _ in 0..DriftConfig::default().warmup_measurements + 100 {
            dc.update(60.0);
        }
        dc.reset();
        assert_eq!(dc.measurement_count, 0);
        assert!(dc.fractional_accumulator.abs() < f32::EPSILON);
        assert!(dc.target_depth.abs() < f32::EPSILON);
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
        for _ in 0..DriftConfig::default().warmup_measurements {
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
