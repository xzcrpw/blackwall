/// Gradient defense module: Model Inversion & poisoning detection.
///
/// Monitors gradient distributions for anomalies that indicate:
/// - **Model Inversion attacks**: adversary infers training data from gradients
/// - **Free-rider attacks**: peer submits zero/near-zero gradients to leech
/// - **Gradient explosion/manipulation**: malicious extreme values
///
/// # Biological Analogy
/// This is the **Thymus** — where T-cells are educated to distinguish
/// self from non-self. Gradients that "look wrong" are quarantined.
use common::hivemind;
use tracing::{debug, warn};

/// Result of gradient safety check.
#[derive(Debug, PartialEq, Eq)]
pub enum GradientVerdict {
    /// Gradient passed all checks — safe to aggregate.
    Safe,
    /// Gradient is anomalous — z-score exceeded threshold.
    Anomalous,
    /// Gradient is near-zero — suspected free-rider.
    FreeRider,
    /// Gradient norm exceeds maximum — possible manipulation.
    NormExceeded,
}

/// Checks a gradient vector against multiple defense heuristics.
pub struct GradientDefense {
    /// Running mean of gradient norms (exponential moving average).
    mean_norm: f64,
    /// Running variance of gradient norms (Welford's algorithm).
    variance_norm: f64,
    /// Number of gradient samples observed.
    sample_count: u64,
}

impl Default for GradientDefense {
    fn default() -> Self {
        Self::new()
    }
}

impl GradientDefense {
    /// Create a new defense checker with no prior observations.
    pub fn new() -> Self {
        Self {
            mean_norm: 0.0,
            variance_norm: 0.0,
            sample_count: 0,
        }
    }

    /// Run all gradient safety checks.
    ///
    /// Returns the first failing verdict, or `Safe` if all pass.
    pub fn check(&mut self, gradients: &[f32]) -> GradientVerdict {
        // Check 1: Free-rider detection (near-zero gradients)
        if Self::is_free_rider(gradients) {
            warn!("Free-rider detected: gradient is near-zero");
            return GradientVerdict::FreeRider;
        }

        // Check 2: Gradient norm bound
        let norm_sq = Self::norm_squared(gradients);
        if norm_sq > hivemind::FL_MAX_GRADIENT_NORM_SQ as f64 {
            warn!(
                norm_sq,
                max = hivemind::FL_MAX_GRADIENT_NORM_SQ,
                "Gradient norm exceeded maximum"
            );
            return GradientVerdict::NormExceeded;
        }

        // Check 3: Z-score anomaly detection (needs history)
        let norm = norm_sq.sqrt();
        if self.sample_count >= 3 {
            let z_score = self.compute_z_score(norm);
            let threshold = hivemind::GRADIENT_ANOMALY_ZSCORE_THRESHOLD as f64 / 1000.0;
            if z_score > threshold {
                warn!(z_score, threshold, "Gradient anomaly detected via z-score");
                return GradientVerdict::Anomalous;
            }
        }

        // Update running statistics
        self.update_stats(norm);

        debug!(norm, sample_count = self.sample_count, "Gradient check passed");
        GradientVerdict::Safe
    }

    /// Detect free-rider: all gradient values near zero.
    ///
    /// A peer contributing zero gradients gains model updates without
    /// providing training knowledge — parasitic behavior.
    fn is_free_rider(gradients: &[f32]) -> bool {
        const EPSILON: f32 = 1e-8;

        if gradients.is_empty() {
            return true;
        }

        let max_abs = gradients.iter()
            .map(|g| g.abs())
            .fold(0.0_f32, f32::max);

        max_abs < EPSILON
    }

    /// Squared L2 norm of gradient vector.
    fn norm_squared(gradients: &[f32]) -> f64 {
        gradients.iter()
            .map(|&g| (g as f64) * (g as f64))
            .sum()
    }

    /// Compute z-score of a gradient norm against running statistics.
    ///
    /// Uses Welford's online algorithm for numerically stable
    /// variance computation.
    fn compute_z_score(&self, norm: f64) -> f64 {
        if self.sample_count < 2 {
            return 0.0;
        }

        let stddev = (self.variance_norm / self.sample_count as f64).sqrt();
        if stddev < 1e-10 {
            return 0.0;
        }

        ((norm - self.mean_norm) / stddev).abs()
    }

    /// Update running mean and variance using Welford's online algorithm.
    fn update_stats(&mut self, norm: f64) {
        self.sample_count += 1;
        let n = self.sample_count as f64;

        let delta = norm - self.mean_norm;
        self.mean_norm += delta / n;
        let delta2 = norm - self.mean_norm;
        self.variance_norm += delta * delta2;
    }

    /// Get the current running mean gradient norm.
    pub fn mean_norm(&self) -> f64 {
        self.mean_norm
    }

    /// Number of samples observed.
    pub fn sample_count(&self) -> u64 {
        self.sample_count
    }

    /// Reset all statistics (e.g., on model reset).
    pub fn reset(&mut self) {
        self.mean_norm = 0.0;
        self.variance_norm = 0.0;
        self.sample_count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_gradient() {
        let mut defense = GradientDefense::new();
        let grad = vec![0.1, -0.2, 0.3, 0.05];
        assert_eq!(defense.check(&grad), GradientVerdict::Safe);
    }

    #[test]
    fn detects_free_rider() {
        let mut defense = GradientDefense::new();
        let zero_grad = vec![0.0, 0.0, 0.0, 0.0];
        assert_eq!(defense.check(&zero_grad), GradientVerdict::FreeRider);
    }

    #[test]
    fn detects_near_zero_free_rider() {
        let mut defense = GradientDefense::new();
        let near_zero = vec![1e-10, -1e-10, 1e-11, 0.0];
        assert_eq!(defense.check(&near_zero), GradientVerdict::FreeRider);
    }

    #[test]
    fn detects_norm_exceeded() {
        let mut defense = GradientDefense::new();
        // FL_MAX_GRADIENT_NORM_SQ = 1_000_000, so sqrt = 1000
        // A single value of 1001 gives norm_sq = 1_002_001 > 1_000_000
        let big = vec![1001.0];
        assert_eq!(defense.check(&big), GradientVerdict::NormExceeded);
    }

    #[test]
    fn detects_anomaly_via_zscore() {
        let mut defense = GradientDefense::new();

        // Build a baseline with slightly varying small gradients
        for i in 0..20 {
            let scale = 0.1 + (i as f32) * 0.005;
            let normal = vec![scale, -scale, scale * 0.5, -scale * 0.5];
            assert_eq!(defense.check(&normal), GradientVerdict::Safe);
        }

        // Now submit a gradient with ~100× normal magnitude
        let anomalous = vec![50.0, -50.0, 50.0, -50.0];
        let verdict = defense.check(&anomalous);
        assert_eq!(verdict, GradientVerdict::Anomalous);
    }

    #[test]
    fn empty_gradient_is_free_rider() {
        let mut defense = GradientDefense::new();
        assert_eq!(defense.check(&[]), GradientVerdict::FreeRider);
    }

    #[test]
    fn stats_accumulate_correctly() {
        let mut defense = GradientDefense::new();
        let grad = vec![1.0, 0.0, 0.0];
        defense.check(&grad);
        assert_eq!(defense.sample_count(), 1);
        assert!((defense.mean_norm() - 1.0).abs() < 0.01);
    }

    #[test]
    fn reset_clears_state() {
        let mut defense = GradientDefense::new();
        defense.check(&[1.0, 2.0, 3.0]);
        defense.check(&[0.5, 0.5, 0.5]);
        assert_eq!(defense.sample_count(), 2);

        defense.reset();
        assert_eq!(defense.sample_count(), 0);
        assert!((defense.mean_norm() - 0.0).abs() < f64::EPSILON);
    }
}
