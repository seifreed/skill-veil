use crate::benchmark_output::{render_benchmark_dashboard, render_benchmark_tuning_report};
use anyhow::{Context, Result};
use skill_veil_core::{
    benchmark::{BenchmarkHistory, BenchmarkHistoryEntry, CorpusEvaluation},
    POLICY_SCHEMA_VERSION,
};
use std::path::{Path, PathBuf};

pub(super) fn load_benchmark_history(history_path: &Path) -> Result<BenchmarkHistory> {
    let content = std::fs::read_to_string(history_path)
        .with_context(|| format!("Failed to read {}", history_path.display()))?;
    serde_json::from_str::<BenchmarkHistory>(&content)
        .with_context(|| format!("Failed to parse {}", history_path.display()))
}

pub(super) fn empty_benchmark_history() -> BenchmarkHistory {
    BenchmarkHistory {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        releases: Vec::new(),
    }
}

pub(super) fn update_benchmark_history(
    history_path: &PathBuf,
    release_id: &str,
    evaluation: &CorpusEvaluation,
) -> Result<BenchmarkHistory> {
    let mut history = if history_path.exists() {
        load_benchmark_history(history_path)?
    } else {
        empty_benchmark_history()
    };

    let entry = BenchmarkHistoryEntry {
        release_id: release_id.to_string(),
        generated_at: chrono::Utc::now(),
        metrics: evaluation.metrics,
        coverage: evaluation.coverage.clone(),
        deduplication: evaluation.deduplication,
        confidence_calibration: evaluation.confidence_calibration.clone(),
        threshold_recommendation: evaluation.threshold_recommendation.clone(),
        family_metrics: evaluation.family_metrics.clone(),
    };

    history
        .releases
        .retain(|existing| existing.release_id != release_id);
    history.releases.push(entry);
    history
        .releases
        .sort_by(|left, right| left.release_id.cmp(&right.release_id));

    let content =
        serde_json::to_string_pretty(&history).context("Failed to serialize benchmark history")?;
    if let Some(parent) = history_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    std::fs::write(history_path, content)
        .with_context(|| format!("Failed to write {}", history_path.display()))?;

    Ok(history)
}

pub(super) fn write_benchmark_dashboard(
    dashboard_path: &Path,
    history: &BenchmarkHistory,
    evaluation: &CorpusEvaluation,
) -> Result<()> {
    if let Some(parent) = dashboard_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    std::fs::write(
        dashboard_path,
        render_benchmark_dashboard(history, evaluation),
    )
    .with_context(|| format!("Failed to write {}", dashboard_path.display()))?;
    Ok(())
}

pub(super) fn write_benchmark_tuning_report(
    report_path: &Path,
    evaluation: &CorpusEvaluation,
) -> Result<()> {
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    std::fs::write(report_path, render_benchmark_tuning_report(evaluation))
        .with_context(|| format!("Failed to write {}", report_path.display()))?;
    Ok(())
}
