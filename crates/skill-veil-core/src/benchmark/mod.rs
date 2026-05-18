//! Benchmark and corpus evaluation helpers.

mod calibration;
mod evaluation;
mod gold;
mod loader;
mod thresholds;
mod types;

pub use evaluation::{classify_verdict, compute_metrics, evaluate_corpus, evaluate_manifest};
pub use gold::{evaluate_gold_corpus, GoldCorpusManifest, GoldSample};
pub use loader::load_manifest;
pub use types::{
    AttackFamilyMetrics, BenchmarkError, BenchmarkHistory, BenchmarkHistoryEntry,
    CalibrationBucket, CalibrationSummary, CorpusCoverage, CorpusEvaluation, CorpusManifest,
    CoverageBucket, DeduplicationMetrics, LabeledSample, RegressionMetrics, SampleEvaluation,
    SampleLabel, ThresholdRecommendation,
};
