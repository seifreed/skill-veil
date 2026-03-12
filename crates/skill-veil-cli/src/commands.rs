use crate::{
    benchmark_output::{
        format_benchmark_text, render_benchmark_dashboard, render_benchmark_tuning_report,
    },
    cli_args::{
        BaselineCreateArgs, BaselineUpdateArgs, BenchmarkArgs, DiffArgs, DiffFailPolicyArg,
        OutputFormat, PolicyProfileArg, PolicyValidateArgs, ScanArgs, ScanPresetArg, SeverityArg,
        WaiversValidateArgs,
    },
};
use anyhow::{Context, Result};
use crate::text_output::{format_diff_ci_summary, format_diff_text, TextOutputOptions};
use skill_veil_core::{
    benchmark::{evaluate_corpus, BenchmarkHistory, BenchmarkHistoryEntry, CorpusEvaluation},
    baseline_from_reports, diff_reports_with_policy_state, finding_fingerprint, load_baseline, load_waivers,
    validate_policy, validate_waivers, BaselineEntry, BaselineFile, JsonReport, PolicyFile,
    POLICY_SCHEMA_VERSION, RecommendedAction, ScanOptions, ScanTargetMode, Scanner,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use crate::text_output::format_results;

pub(crate) fn load_rule_engine_from_dir(rules_dir: &Path) -> Result<skill_veil_core::RuleEngine> {
    let mut engine = skill_veil_core::RuleEngine::new();
    engine
        .load_from_dir(rules_dir)
        .with_context(|| format!("Failed to load rules from {}", rules_dir.display()))?;
    Ok(engine)
}

pub(crate) fn apply_scan_preset(mut args: ScanArgs) -> ScanArgs {
    match args.preset {
        Some(ScanPresetArg::Local) | None => {}
        Some(ScanPresetArg::Ci) => {
            args.quiet_summary = true;
            args.finding_limit.get_or_insert(10);
            args.profile.get_or_insert(PolicyProfileArg::Team);
        }
        Some(ScanPresetArg::Strict) => {
            args.quiet_summary = true;
            args.finding_limit.get_or_insert(10);
            args.profile.get_or_insert(PolicyProfileArg::Enterprise);
            args.fail_on.get_or_insert(SeverityArg::High);
            args.min_severity.get_or_insert(SeverityArg::Medium);
        }
        Some(ScanPresetArg::Enterprise) => {
            args.quiet_summary = true;
            args.finding_limit.get_or_insert(20);
            args.profile.get_or_insert(PolicyProfileArg::Enterprise);
            args.min_severity.get_or_insert(SeverityArg::Medium);
        }
    }
    args
}

pub(crate) fn run_scan(args: ScanArgs, target_mode: ScanTargetMode, quiet: bool) -> Result<()> {
    let args = apply_scan_preset(args);
    let text_options = TextOutputOptions {
        quiet_summary: args.quiet_summary,
        explain_policy: args.explain_policy,
        finding_limit: args.finding_limit,
    };
    let options = ScanOptions {
        min_severity: args.min_severity.map(Into::into),
        fail_on: args.fail_on.map(Into::into),
        rules_dir: args.rules_dir,
        profile: args.profile.map(Into::into),
        baseline_path: args.baseline,
        waivers_path: args.waivers,
        policy_path: args.policy,
        recursive: !args.no_recursive,
        target_mode,
        ..Default::default()
    };

    let scanner = Scanner::with_std_adapters(options).context("Failed to initialize scanner")?;
    let results = scanner.scan(&args.path).context("Failed to scan path")?;
    let output_content = format_results(&results, args.format, text_options)?;

    if let Some(output_path) = args.output {
        std::fs::write(&output_path, &output_content).context("Failed to write output file")?;
        if !quiet {
            eprintln!("Output written to: {}", output_path.display());
        }
    } else {
        print!("{}", output_content);
    }

    if results.iter().any(|r| r.should_fail) {
        std::process::exit(1);
    }

    Ok(())
}

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
        dashboard_history = Some(update_benchmark_history(history_path, &release_id, &evaluation)?);
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
        write_benchmark_dashboard(dashboard_path, &history, &evaluation)?;
        let tuning_path = dashboard_path.with_file_name("benchmark-tuning-report.md");
        write_benchmark_tuning_report(&tuning_path, &evaluation)?;
    } else if let Some(history_path) = args.history_file.as_ref() {
        let dashboard_path = history_path.with_file_name("benchmark-dashboard.md");
        let tuning_path = history_path.with_file_name("benchmark-tuning-report.md");
        let history = dashboard_history.unwrap_or_else(|| BenchmarkHistory {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            releases: Vec::new(),
        });
        write_benchmark_dashboard(&dashboard_path, &history, &evaluation)?;
        write_benchmark_tuning_report(&tuning_path, &evaluation)?;
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

    history.releases.retain(|existing| existing.release_id != release_id);
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
    if let Some(parent) = dashboard_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    std::fs::write(dashboard_path, render_benchmark_dashboard(history, evaluation))
        .with_context(|| format!("Failed to write {}", dashboard_path.display()))?;
    Ok(())
}

pub(crate) fn write_benchmark_tuning_report(
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

pub(crate) fn run_baseline_create(args: BaselineCreateArgs) -> Result<()> {
    let reports = load_json_reports(&args.report)?;
    let baseline = baseline_from_reports(&reports);
    let content =
        serde_json::to_string_pretty(&baseline).context("Failed to serialize baseline")?;
    std::fs::write(&args.output, content).context("Failed to write baseline file")?;
    Ok(())
}

pub(crate) fn run_baseline_update(args: BaselineUpdateArgs) -> Result<()> {
    let reports = load_json_reports(&args.report)?;
    let existing = load_baseline(&args.baseline).context("Failed to load baseline file")?;
    let current = baseline_from_reports(&reports);

    let existing_map: BTreeMap<_, _> = existing
        .entries
        .into_iter()
        .map(|entry| (entry.fingerprint.clone(), entry))
        .collect();
    let current_map: BTreeMap<_, _> = current
        .entries
        .into_iter()
        .map(|entry| (entry.fingerprint.clone(), entry))
        .collect();

    let new_entries: Vec<_> = current_map
        .iter()
        .filter(|(fingerprint, _)| !existing_map.contains_key(*fingerprint))
        .map(|(_, entry)| entry.clone())
        .collect();

    if !new_entries.is_empty() && !args.allow_new_findings {
        anyhow::bail!(
            "Baseline update would add {} new finding(s). Re-run with --allow-new-findings to accept them.",
            new_entries.len()
        );
    }

    let merged_entries: Vec<BaselineEntry> = current_map.into_values().collect();
    let updated = BaselineFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        entries: merged_entries,
    };
    let content =
        serde_json::to_string_pretty(&updated).context("Failed to serialize updated baseline")?;
    std::fs::write(&args.output, content).context("Failed to write updated baseline file")?;
    Ok(())
}

pub(crate) fn run_waivers_validate(args: WaiversValidateArgs) -> Result<()> {
    let waivers = load_waivers(&args.path).context("Failed to load waivers file")?;
    validate_waivers(&waivers).map_err(anyhow::Error::msg)?;
    println!("Waivers file is valid");
    Ok(())
}

pub(crate) fn run_policy_validate(args: PolicyValidateArgs) -> Result<()> {
    let content = std::fs::read_to_string(&args.path)
        .with_context(|| format!("Failed to read {}", args.path.display()))?;
    let policy: PolicyFile = serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .with_context(|| format!("Failed to parse {}", args.path.display()))?;
    validate_policy(&policy).map_err(anyhow::Error::msg)?;
    println!("Policy file is valid");
    Ok(())
}

pub(crate) fn run_diff(args: DiffArgs) -> Result<()> {
    let previous = load_json_reports(&args.previous)?;
    let current = load_json_reports(&args.current)?;
    let baseline = args
        .baseline
        .as_ref()
        .map(|path| load_baseline(path))
        .transpose()
        .context("Failed to load baseline file")?;
    let waivers = args
        .waivers
        .as_ref()
        .map(|path| load_waivers(path))
        .transpose()
        .context("Failed to load waivers file")?;
    let diff = diff_reports_with_policy_state(
        &previous,
        &current,
        baseline.as_ref(),
        waivers.as_ref(),
    );

    let output = match args.format {
        OutputFormat::Text => {
            if args.ci_summary {
                format_diff_ci_summary(&diff)
            } else {
                format_diff_text(&diff)
            }
        }
        OutputFormat::Json => {
            serde_json::to_string_pretty(&diff).context("Failed to serialize diff")?
        }
        OutputFormat::Sarif | OutputFormat::Shield => {
            anyhow::bail!("Diff only supports text or json output")
        }
    };

    print!("{}", output);
    if let Some(policy) = args.fail_on {
        match policy {
            DiffFailPolicyArg::NewActive if !diff.new_findings.is_empty() => {
                anyhow::bail!(
                    "Detected {} new active finding(s) in diff",
                    diff.new_findings.len()
                );
            }
            DiffFailPolicyArg::NewBlocking => {
                let has_new_blocking = current
                    .iter()
                    .flat_map(|report| report.findings.iter())
                    .any(|finding| {
                        diff.new_findings.iter().any(|entry| {
                            entry.fingerprint == finding_fingerprint(finding)
                        }) && finding.recommended_action == RecommendedAction::Block
                    });
                if has_new_blocking {
                    anyhow::bail!("Detected new blocking findings in diff");
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn load_json_reports(path: &PathBuf) -> Result<Vec<JsonReport>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON report {}", path.display()))
}
