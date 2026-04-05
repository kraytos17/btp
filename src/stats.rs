//! Statistical computation utilities for benchmark rigor.
//!
//! Follows SUPERCOP/eBACS best practices:
//! - Outlier removal using IQR method (Tukey's fences)
//! - Confidence intervals for the median
//! - Coefficient of variation (CV) for stability assessment
//! - Interquartile range (IQR) as robust spread measure
//! - Sample variance (Bessel's correction, n-1)
//!
//! Percentile computation uses Hyndman & Fan Type 7 (R/NumPy default).

/// Asymptotic relative efficiency factor for median vs. mean under normality.
/// Equal to sqrt(pi/2) ≈ 1.2533.
const MEDIAN_SE_FACTOR: f64 = 1.253_314_137_315_500_1;

/// Z-scores for common confidence levels.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::match_same_arms
)]
fn z_score(confidence: f64) -> f64 {
    match (confidence * 100.0).round() as u32 {
        90 => 1.645,
        95 => 1.96,
        99 => 2.576,
        _ => 1.96,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BenchmarkStats {
    pub samples_before_outliers: usize,
    pub samples_after_outliers: usize,
    pub min: f64,
    pub max: f64,
    pub median: f64,
    pub mean: f64,
    pub stddev: f64,
    pub cv: f64,
    pub iqr: f64,
    pub q1: f64,
    pub q3: f64,
    pub p95: f64,
    pub p99: f64,
    pub confidence_95_lower: f64,
    pub confidence_95_upper: f64,
}

impl Default for BenchmarkStats {
    fn default() -> Self {
        Self {
            samples_before_outliers: 0,
            samples_after_outliers: 0,
            min: 0.0,
            max: 0.0,
            median: 0.0,
            mean: 0.0,
            stddev: 0.0,
            cv: 0.0,
            iqr: 0.0,
            q1: 0.0,
            q3: 0.0,
            p95: 0.0,
            p99: 0.0,
            confidence_95_lower: 0.0,
            confidence_95_upper: 0.0,
        }
    }
}

impl BenchmarkStats {
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::if_not_else,
        clippy::redundant_closure_for_method_calls,
        clippy::suboptimal_flops
    )]
    pub fn compute(timings: &[f64]) -> Self {
        if timings.is_empty() {
            return Self::default();
        }

        let original_count = timings.len();

        // Reject NaN and inf
        for &t in timings {
            if !t.is_finite() {
                return Self::default();
            }
        }

        // Single sort pass: compute fences from sorted data, filter, keep sorted
        let mut sorted = timings.to_vec();
        sorted.sort_by(|a, b| a.total_cmp(b));

        let cleaned = if original_count < 4 {
            sorted
        } else {
            let q1 = Self::percentile_sorted(&sorted, 25.0);
            let q3 = Self::percentile_sorted(&sorted, 75.0);
            let iqr = q3 - q1;
            let lower = q1 - 1.5 * iqr;
            let upper = q3 + 1.5 * iqr;

            sorted
                .into_iter()
                .filter(|&x| x >= lower && x <= upper)
                .collect()
        };

        let n = cleaned.len();
        if n == 0 {
            return Self::default();
        }

        // cleaned is already sorted
        let min = cleaned[0];
        let max = cleaned[n - 1];

        let sum: f64 = cleaned.iter().sum();
        let mean = sum / n as f64;
        let median = Self::percentile_sorted(&cleaned, 50.0);

        // Sample variance (Bessel's correction: n-1)
        let variance = if n > 1 {
            cleaned.iter().map(|x| (*x - mean).powi(2)).sum::<f64>() / (n - 1) as f64
        } else {
            0.0
        };

        let stddev = variance.sqrt();
        let cv = if mean != 0.0 {
            (stddev / mean).abs() * 100.0
        } else {
            0.0
        };

        let q1 = Self::percentile_sorted(&cleaned, 25.0);
        let q3 = Self::percentile_sorted(&cleaned, 75.0);
        let iqr = q3 - q1;

        let p95 = Self::percentile_sorted(&cleaned, 95.0);
        let p99 = Self::percentile_sorted(&cleaned, 99.0);
        let (ci_lower, ci_upper) = Self::median_confidence_interval(&cleaned, 0.95);

        Self {
            samples_before_outliers: original_count,
            samples_after_outliers: n,
            min,
            max,
            median,
            mean,
            stddev,
            cv,
            iqr,
            q1,
            q3,
            p95,
            p99,
            confidence_95_lower: ci_lower,
            confidence_95_upper: ci_upper,
        }
    }

    /// Compute the p-th percentile using linear interpolation (Hyndman & Fan Type 7).
    /// Input must be sorted.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
        let n = sorted.len();
        if n == 0 {
            return 0.0;
        }
        if n == 1 {
            return sorted[0];
        }

        let rank = (p / 100.0) * (n as f64 - 1.0);
        let lower = rank.floor() as usize;
        let upper = rank.ceil() as usize;
        let frac = rank - lower as f64;

        if lower == upper {
            sorted[lower]
        } else {
            sorted[lower].mul_add(1.0 - frac, sorted[upper] * frac)
        }
    }

    /// Compute confidence interval for the median.
    /// For n >= 20, uses normal approximation: median ± z * sqrt(pi/2) * sigma / sqrt(n)
    /// For n < 20, uses order statistics bounds.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn median_confidence_interval(sorted: &[f64], confidence: f64) -> (f64, f64) {
        let n = sorted.len();
        if n == 0 {
            return (0.0, 0.0);
        }
        if n == 1 {
            return (sorted[0], sorted[0]);
        }

        let median = Self::percentile_sorted(sorted, 50.0);
        let z = z_score(confidence);
        if n < 20 {
            // Order statistics method
            let k = (z.mul_add(-(n as f64).sqrt(), n as f64) / 2.0)
                .floor()
                .max(0.0) as usize;
            let lower_idx = k.min(n - 1);
            let upper_idx = (n - 1 - k).min(n - 1).max(lower_idx);
            (sorted[lower_idx], sorted[upper_idx])
        } else {
            // Normal approximation (sample variance, n-1)
            let mean: f64 = sorted.iter().sum::<f64>() / n as f64;
            let variance = sorted.iter().map(|x| (*x - mean).powi(2)).sum::<f64>() / (n - 1) as f64;
            let stddev = variance.sqrt();
            let se_median = MEDIAN_SE_FACTOR * stddev / (n as f64).sqrt();
            let margin = z * se_median;
            (median - margin, median + margin)
        }
    }

    /// Assess measurement stability.
    /// "stable" if CV < 5%, "acceptable" if CV < 10%, "unstable" otherwise.
    #[must_use]
    pub fn stability_label(&self) -> &'static str {
        if self.cv < 5.0 {
            "stable"
        } else if self.cv < 10.0 {
            "acceptable"
        } else {
            "unstable"
        }
    }

    /// Compute required sample size for desired precision.
    /// Uses n = (Z * sigma / E)^2 where E is the desired margin of error as fraction of mean.
    /// Returns None if computation is not meaningful (zero variance or zero mean).
    #[must_use]
    pub fn required_sample_size(&self, confidence: f64, margin_fraction: f64) -> Option<usize> {
        let z = z_score(confidence);
        let e = margin_fraction * self.mean;
        if e <= 0.0 || self.stddev <= 0.0 {
            return None;
        }
        Some(((z * self.stddev / e).powi(2)).ceil() as usize)
    }

    /// Compute stats for an inverted distribution (1/x transform).
    /// Used when converting ns/block to blocks/sec (throughput).
    #[must_use]
    #[allow(clippy::if_not_else)]
    pub fn invert(&self) -> Self {
        if self.mean == 0.0 {
            return Self::default();
        }

        // For y = 1/x: E[y] ≈ 1/E[x], Var[y] ≈ Var[x] / E[x]^4
        let inv_mean = 1.0 / self.mean;
        let inv_variance = self.stddev.powi(2) / self.mean.powi(4);
        let inv_stddev = inv_variance.sqrt();
        let inv_cv = if inv_mean != 0.0 {
            (inv_stddev / inv_mean).abs() * 100.0
        } else {
            0.0
        };

        // Invert percentiles: p-th percentile of 1/x = 1 / ((100-p)-th percentile of x)
        Self {
            samples_before_outliers: self.samples_before_outliers,
            samples_after_outliers: self.samples_after_outliers,
            min: if self.max != 0.0 {
                1.0 / self.max
            } else {
                f64::INFINITY
            },
            max: if self.min != 0.0 {
                1.0 / self.min
            } else {
                f64::INFINITY
            },
            median: if self.median != 0.0 {
                1.0 / self.median
            } else {
                0.0
            },
            mean: inv_mean,
            stddev: inv_stddev,
            cv: inv_cv,
            iqr: if self.q1 != 0.0 && self.q3 != 0.0 {
                (1.0 / self.q1 - 1.0 / self.q3).abs()
            } else {
                0.0
            },
            q1: if self.q3 == 0.0 { 0.0 } else { 1.0 / self.q3 },
            q3: if self.q1 == 0.0 { 0.0 } else { 1.0 / self.q1 },
            p95: if self.p95 == 0.0 { 0.0 } else { 1.0 / self.p95 },
            p99: if self.p99 == 0.0 { 0.0 } else { 1.0 / self.p99 },
            confidence_95_lower: if self.confidence_95_upper == 0.0 {
                0.0
            } else {
                1.0 / self.confidence_95_upper
            },
            confidence_95_upper: if self.confidence_95_lower == 0.0 {
                0.0
            } else {
                1.0 / self.confidence_95_lower
            },
        }
    }

    /// Scale all values by a factor (e.g., convert ns to per-byte).
    #[must_use]
    pub fn scale(&self, factor: f64) -> Self {
        Self {
            samples_before_outliers: self.samples_before_outliers,
            samples_after_outliers: self.samples_after_outliers,
            min: self.min * factor,
            max: self.max * factor,
            median: self.median * factor,
            mean: self.mean * factor,
            stddev: self.stddev * factor,
            cv: self.cv,
            iqr: self.iqr * factor,
            q1: self.q1 * factor,
            q3: self.q3 * factor,
            p95: self.p95 * factor,
            p99: self.p99 * factor,
            confidence_95_lower: self.confidence_95_lower * factor,
            confidence_95_upper: self.confidence_95_upper * factor,
        }
    }
}
