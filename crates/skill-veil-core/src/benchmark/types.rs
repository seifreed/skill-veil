use crate::{RecommendedAction, ThreatCategory, Verdict};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use strum_macros::Display;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusManifest {
    pub samples: Vec<LabeledSample>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabeledSample {
    pub id: String,
    pub path: PathBuf,
    pub label: SampleLabel,
    #[serde(default)]
    pub focus_category: Option<ThreatCategory>,
    #[serde(default)]
    pub attack_family: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SampleLabel {
    Benign,
    Suspicious,
    Malicious,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEvaluation {
    pub metrics: RegressionMetrics,
    pub coverage: CorpusCoverage,
    pub deduplication: DeduplicationMetrics,
    pub confidence_calibration: CalibrationSummary,
    pub threshold_recommendation: ThresholdRecommendation,
    #[serde(default)]
    pub family_metrics: Vec<AttackFamilyMetrics>,
    pub samples: Vec<SampleEvaluation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleEvaluation {
    pub id: String,
    pub expected: SampleLabel,
    pub actual: SampleLabel,
    pub verdict: Verdict,
    pub focus_category: Option<ThreatCategory>,
    #[serde(default)]
    pub attack_family: Option<String>,
    pub recommended_action: RecommendedAction,
    pub risk_score: u32,
    pub finding_count: usize,
    pub primary_finding_count: usize,
    pub supporting_finding_count: usize,
    pub duplicates_removed: usize,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CorpusCoverage {
    pub total_samples: u32,
    pub by_label: Vec<CoverageBucket>,
    pub by_focus_category: Vec<CoverageBucket>,
    #[serde(default)]
    pub by_attack_family: Vec<CoverageBucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageBucket {
    pub key: String,
    pub samples: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RegressionMetrics {
    pub precision: f32,
    pub recall: f32,
    pub false_positive_rate: f32,
    pub accuracy: f32,
    pub exact_label_accuracy: f32,
    pub true_positive: u32,
    pub false_positive: u32,
    pub true_negative: u32,
    pub false_negative: u32,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct DeduplicationMetrics {
    pub original_findings: u32,
    pub unique_findings: u32,
    pub duplicates_removed: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CalibrationSummary {
    pub by_evidence_kind: Vec<CalibrationBucket>,
    pub by_category: Vec<CalibrationBucket>,
    pub by_signal_pair: Vec<CalibrationBucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationBucket {
    pub key: String,
    pub findings: u32,
    pub true_positive: u32,
    pub false_positive: u32,
    pub observed_precision: f32,
    pub recommended_confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdRecommendation {
    pub current_approval_threshold: u32,
    pub current_block_threshold: u32,
    pub recommended_approval_threshold: u32,
    pub recommended_block_threshold: u32,
    /// Metrics computed using score-based threshold classification.
    /// May differ from top-level `CorpusEvaluation.metrics` which uses the
    /// full verdict pipeline (calibration, compound detection, taint analysis).
    pub current_metrics: RegressionMetrics,
    /// Metrics for the recommended thresholds, using score-based classification.
    pub recommended_metrics: RegressionMetrics,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackFamilyMetrics {
    pub family: String,
    pub sample_count: u32,
    pub metrics: RegressionMetrics,
    pub threshold_recommendation: ThresholdRecommendation,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchmarkHistory {
    pub schema_version: String,
    pub releases: Vec<BenchmarkHistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkHistoryEntry {
    pub release_id: String,
    pub generated_at: DateTime<Utc>,
    pub metrics: RegressionMetrics,
    pub coverage: CorpusCoverage,
    pub deduplication: DeduplicationMetrics,
    pub confidence_calibration: CalibrationSummary,
    pub threshold_recommendation: ThresholdRecommendation,
    #[serde(default)]
    pub family_metrics: Vec<AttackFamilyMetrics>,
}

#[derive(thiserror::Error, Debug)]
pub enum BenchmarkError {
    #[error("failed to read corpus manifest: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse corpus manifest: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("failed to scan sample {id} at {path}: {message}")]
    SampleScan {
        id: String,
        path: PathBuf,
        message: String,
    },
}
