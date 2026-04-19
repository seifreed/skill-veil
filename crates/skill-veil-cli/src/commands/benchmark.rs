use crate::{
    benchmark_output::{
        format_benchmark_text, render_benchmark_dashboard, render_benchmark_tuning_report,
    },
    cli_args::{BenchmarkArgs, OutputFormat},
};
use anyhow::{Context, Result};
use skill_veil_core::{
    benchmark::{evaluate_corpus, BenchmarkHistory, BenchmarkHistoryEntry, CorpusEvaluation},
    Scanner, POLICY_SCHEMA_VERSION,
};
use std::path::{Path, PathBuf};

pub(crate) fn run_benchmark(args: BenchmarkArgs) -> Result<()> {
    let scanner = Scanner::new().context("Failed to initialize scanner")?;
    let evaluation =
        evaluate_corpus(&scanner, &args.corpus).context("Failed to evaluate benchmark corpus")?;
    let mut dashboard_history = None;

    if let Some(history_path) = &args.history_file {
        let release_id = args
            .release_id
            .clone()
            .context("`--release-id` is required when `--history-file` is set")?;
        dashboard_history = Some(update_benchmark_history(
            history_path,
            &release_id,
            &evaluation,
        )?);
    }

    if let Some(dashboard_path) = args.dashboard_output.as_ref() {
        let history = if let Some(history) = dashboard_history.clone() {
            history
        } else if let Some(history_path) = args.history_file.as_ref() {
            let content = std::fs::read_to_string(history_path)
                .with_context(|| format!("Failed to read {}", history_path.display()))?;
            serde_json::from_str::<BenchmarkHistory>(&content)
                .with_context(|| format!("Failed to parse {}", history_path.display()))?
        } else {
            BenchmarkHistory {
                schema_version: POLICY_SCHEMA_VERSION.to_string(),
                releases: Vec::new(),
            }
        };
        write_benchmark_report_files(dashboard_path, &history, &evaluation)?;
    } else if let Some(history_path) = args.history_file.as_ref() {
        let dashboard_path = history_path.with_file_name("benchmark-dashboard.md");
        let history = dashboard_history.unwrap_or_else(|| BenchmarkHistory {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            releases: Vec::new(),
        });
        write_benchmark_report_files(&dashboard_path, &history, &evaluation)?;
    }

    let output_content = match args.format {
        OutputFormat::Json => serde_json::to_string_pretty(&evaluation)
            .context("Failed to serialize benchmark output")?,
        OutputFormat::Text => format_benchmark_text(&evaluation),
        OutputFormat::Sarif | OutputFormat::Shield => {
            anyhow::bail!("Benchmark only supports text or json output")
        }
    };

    if let Some(output_path) = args.output {
        std::fs::write(&output_path, output_content).context("Failed to write output file")?;
    } else {
        print!("{}", output_content);
    }

    Ok(())
}

pub(crate) fn update_benchmark_history(
    history_path: &PathBuf,
    release_id: &str,
    evaluation: &CorpusEvaluation,
) -> Result<BenchmarkHistory> {
    let mut history = if history_path.exists() {
        let content = std::fs::read_to_string(history_path)
            .with_context(|| format!("Failed to read {}", history_path.display()))?;
        serde_json::from_str::<BenchmarkHistory>(&content)
            .with_context(|| format!("Failed to parse {}", history_path.display()))?
    } else {
        BenchmarkHistory {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            releases: Vec::new(),
        }
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

pub(crate) fn write_benchmark_dashboard(
    dashboard_path: &Path,
    history: &BenchmarkHistory,
    evaluation: &CorpusEvaluation,
) -> Result<()> {
    write_file_ensuring_parent(
        dashboard_path,
        render_benchmark_dashboard(history, evaluation),
    )
}

pub(crate) fn write_benchmark_tuning_report(
    report_path: &Path,
    evaluation: &CorpusEvaluation,
) -> Result<()> {
    write_file_ensuring_parent(report_path, render_benchmark_tuning_report(evaluation))
}

fn write_benchmark_report_files(
    dashboard_path: &Path,
    history: &BenchmarkHistory,
    evaluation: &CorpusEvaluation,
) -> Result<()> {
    write_benchmark_dashboard(dashboard_path, history, evaluation)?;
    let tuning_path = dashboard_path.with_file_name("benchmark-tuning-report.md");
    write_benchmark_tuning_report(&tuning_path, evaluation)
}

fn write_file_ensuring_parent(path: &Path, content: String) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    std::fs::write(path, content).with_context(|| format!("Failed to write {}", path.display()))
}
