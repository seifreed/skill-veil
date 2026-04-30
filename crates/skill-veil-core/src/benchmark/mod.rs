//! Benchmark and corpus evaluation helpers.

mod calibration;
mod evaluation;
mod loader;
mod thresholds;
mod types;

pub use evaluation::{classify_verdict, compute_metrics, evaluate_corpus};
pub use loader::load_manifest;
pub use types::{
    AttackFamilyMetrics, BenchmarkError, BenchmarkHistory, BenchmarkHistoryEntry,
    CalibrationBucket, CalibrationSummary, CorpusCoverage, CorpusEvaluation, CorpusManifest,
    CoverageBucket, DeduplicationMetrics, LabeledSample, RegressionMetrics, SampleEvaluation,
    SampleLabel, ThresholdRecommendation,
};
