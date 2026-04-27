mod aggregation;
mod filtering;
mod formatting;
mod preparation;

use crate::color::ColorMode;
use crate::text_output::{format_results, TextOutputOptions};
use crate::{
    cli_args::{ColorChoiceArg, DatasetViewArg, OutputFormat, ScanArgs},
    commands::apply_scan_preset,
};
use anyhow::{Context, Result};
use rayon::prelude::*;
use skill_veil_core::{JsonReport, PackageHealth, ScanOptions, ScanTargetMode, Scanner, Verdict};
use std::fs;
use std::io::IsTerminal;
use std::sync::Arc;

#[allow(unused_imports)]
pub(crate) use formatting::format_dataset_verdicts_text;

/// Default `ScanOptions` for dataset-mode runs: package target, recursive,
/// no policy/profile/baseline. Use this when the caller has no user flags
/// to propagate (e.g. internal cross-check pipeline).
#[must_use]
pub(crate) fn default_dataset_scan_options() -> ScanOptions {
    ScanOptions {
        recursive: true,
        target_mode: ScanTargetMode::Package,
        ..Default::default()
    }
}

/// Run the dataset preparation + scan pipeline and return raw
/// `PackageScanResult`s without any aggregation, filtering, or output
/// formatting. Used by the `vt cross-check` flow, which needs the
/// per-artifact scan state to cross-reference with VT reports.
///
/// Accepts a `ScanOptions` so callers can propagate user-facing flags
/// (`--strict-rules`, `--min-severity`, profile, policy, …) end-to-end.
/// Pass `default_dataset_scan_options()` for the historical "package mode,
/// recursive, no policy" behaviour.
pub(crate) fn scan_dataset_to_results(
    path: &std::path::Path,
    options: ScanOptions,
) -> Result<Vec<skill_veil_core::PackageScanResult>> {
    let scanner =
        Arc::new(Scanner::with_std_adapters(options).context("Failed to initialize scanner")?);
    let prepared = preparation::prepare_dataset_packages(path)?;
    if prepared.package_roots.is_empty() {
        anyhow::bail!(
            "No package roots with SKILL.md were found under {}",
            path.display()
        );
    }
    let results: Vec<_> = prepared
        .package_roots
        .par_iter()
        .filter_map(|package_root| match scanner.scan(package_root) {
            Ok(pkg_result) => Some(pkg_result),
            Err(skill_veil_core::scanner::ScanError::NoSkillEntrypoints(_)) => None,
            Err(err) => {
                tracing::warn!("scan failed for {}: {}", package_root.display(), err);
                None
            }
        })
        .collect();
    Ok(results)
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct DatasetJsonReport {
    root: String,
    package_count: usize,
    skipped_packages: usize,
    packages_with_failures: usize,
    benign_reports: usize,
    suspicious_reports: usize,
    malicious_reports: usize,
    decode_warnings: usize,
    parse_warnings: usize,
    non_agent_reports: usize,
    top_malicious_reasons: Vec<DatasetMaliciousReason>,
    reports: Vec<DatasetJsonEntry>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct DatasetVerdictsJsonReport {
    root: String,
    package_count: usize,
    skipped_packages: usize,
    packages_with_failures: usize,
    archive_extraction_warnings: usize,
    benign_reports: usize,
    suspicious_reports: usize,
    malicious_reports: usize,
    decode_warnings: usize,
    parse_warnings: usize,
    top_malicious_reasons: Vec<DatasetMaliciousReason>,
    verdicts: Vec<DatasetPackageVerdictEntry>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct DatasetJsonEntry {
    pub(crate) package_id: Option<String>,
    pub(crate) report: JsonReport,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct DatasetPackageVerdictEntry {
    pub(crate) package_id: Option<String>,
    pub(crate) final_verdict: Verdict,
    pub(crate) package_health: Option<PackageHealth>,
    pub(crate) blast_radius: Option<skill_veil_core::BlastRadiusLevel>,
    pub(crate) declared_permissions: Vec<skill_veil_core::DeclaredPermission>,
    pub(crate) strongest_reason: Option<String>,
    pub(crate) top_rule: Option<String>,
    pub(crate) representative_path: String,
    pub(crate) main_summary: Vec<String>,
    pub(crate) supporting_summary: Vec<String>,
    pub(crate) package_root_summary: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct DatasetMaliciousReason {
    pub(crate) package_id: Option<String>,
    pub(crate) skill_path: String,
    pub(crate) scope: String,
    pub(crate) representative_rules: Vec<String>,
    pub(crate) category: String,
    pub(crate) signal_class: String,
    pub(crate) strongest_action: String,
}

pub(crate) fn run_scan_dataset(
    args: ScanArgs,
    quiet: bool,
    color_choice: ColorChoiceArg,
) -> Result<bool> {
    let args = apply_scan_preset(args);
    let color = ColorMode::from_choice(
        color_choice,
        args.output.is_none() && std::io::stdout().is_terminal(),
    );
    let text_options = TextOutputOptions {
        quiet_summary: args.quiet_summary,
        explain_policy: args.explain_policy,
        finding_limit: args.finding_limit.map(std::num::NonZeroUsize::get),
        color,
    };
    let options = ScanOptions {
        min_severity: args.min_severity.map(Into::into),
        fail_on: args.fail_on.map(Into::into),
        rules_dir: args.rules_dir.clone(),
        profile: args.profile.map(Into::into),
        baseline_path: args.baseline.clone(),
        waivers_path: args.waivers.clone(),
        policy_path: args.policy.clone(),
        recursive: !args.no_recursive,
        target_mode: ScanTargetMode::Package,
        // Propagate `--strict-rules` so dataset-mode CI runs honour the
        // collision-detection contract documented in `ScanOptions`. The
        // legacy `..Default::default()` left this at `false`, silently
        // dropping the flag the user asked for.
        strict_rules: args.strict_rules,
        ..Default::default()
    };

    let scanner =
        Arc::new(Scanner::with_std_adapters(options).context("Failed to initialize scanner")?);
    let prepared_dataset = preparation::prepare_dataset_packages(&args.path)?;
    let package_roots = prepared_dataset.package_roots.clone();
    if package_roots.is_empty() {
        anyhow::bail!(
            "No package roots with SKILL.md were found under {}",
            args.path.display()
        );
    }

    enum DatasetScanOutcome {
        Results(skill_veil_core::PackageScanResult),
        Skipped,
        Failed(String),
    }

    let outcomes: Vec<_> = package_roots
        .par_iter()
        .map(|package_root| match scanner.scan(package_root) {
            Ok(pkg_result) => DatasetScanOutcome::Results(pkg_result),
            Err(skill_veil_core::scanner::ScanError::NoSkillEntrypoints(_)) => {
                DatasetScanOutcome::Skipped
            }
            Err(err) => DatasetScanOutcome::Failed(format!("{}: {}", package_root.display(), err)),
        })
        .collect();

    let mut all_results = Vec::new();
    let mut packages_with_failures = 0_usize;
    let mut skipped_packages = 0_usize;
    for outcome in outcomes {
        match outcome {
            DatasetScanOutcome::Results(pkg_result) => {
                let has_errors = !pkg_result.errors.is_empty();
                if !quiet && has_errors {
                    for err_entry in &pkg_result.errors {
                        eprintln!(
                            "Dataset package scan warning: Failed to scan {}: {}",
                            err_entry.path.display(),
                            err_entry.error
                        );
                    }
                }
                let results = pkg_result.results;
                if has_errors || results.iter().any(|result| result.should_fail) {
                    packages_with_failures += 1;
                }
                all_results.extend(results);
            }
            DatasetScanOutcome::Skipped => skipped_packages += 1,
            DatasetScanOutcome::Failed(message) => {
                packages_with_failures += 1;
                if !quiet {
                    eprintln!("Dataset package scan warning: {message}");
                }
            }
        }
    }

    let dataset_results = filtering::filter_dataset_results(&all_results, args.dataset_view);
    let dataset_reports: Vec<_> = dataset_results
        .iter()
        .map(|result| result.policy_generator().generate_json())
        .collect();
    let dataset_entries: Vec<_> = dataset_reports
        .iter()
        .cloned()
        .map(|report| DatasetJsonEntry {
            package_id: report
                .package_id
                .clone()
                .or_else(|| filtering::extract_package_id_from_skill_path(&report.skill_path)),
            report,
        })
        .collect();
    let aggregated_package_verdicts = aggregation::aggregate_package_verdicts(&dataset_entries);
    let verdict_counts = if args.dataset_view == DatasetViewArg::Verdicts {
        aggregation::count_aggregated_verdicts(&aggregated_package_verdicts)
    } else {
        filtering::count_verdicts(&dataset_reports)
    };
    let decode_warnings =
        filtering::count_warning_rule(&dataset_reports, "ARTIFACT_DECODE_WARNING");
    let parse_warnings = filtering::count_warning_rule(&dataset_reports, "ARTIFACT_PARSE_WARNING");
    let non_agent_packages = dataset_reports
        .iter()
        .filter(|report| {
            report.classification == skill_veil_core::ArtifactClassification::GenericMarkdown
        })
        .count();
    let top_malicious_reasons = filtering::top_malicious_reasons(&dataset_reports);

    let output_content = match args.format {
        OutputFormat::Text => {
            let mut output = String::new();
            output.push_str("--- Dataset Summary ---\n");
            output.push_str(&format!(
                "Root: {}\nPackages discovered: {}\nPackages skipped: {}\nPackages with failures: {}\nArchive extraction warnings: {}\nView: {:?}\nVerdicts: benign={} suspicious={} malicious={}\nWarnings: decode={} parse={}\nNon-agent reports: {}\n",
                args.path.display(),
                package_roots.len(),
                skipped_packages,
                packages_with_failures,
                prepared_dataset.skipped_archives,
                args.dataset_view,
                verdict_counts.0,
                verdict_counts.1,
                verdict_counts.2,
                decode_warnings,
                parse_warnings,
                non_agent_packages,
            ));
            if !top_malicious_reasons.is_empty() {
                output.push_str("Top malicious reasons:\n");
                for reason in top_malicious_reasons.iter().take(8) {
                    output.push_str(&format!(
                        "  - package={} scope={} rules={} category={} signal={} action={}\n",
                        reason.package_id.as_deref().unwrap_or("unknown"),
                        reason.scope,
                        reason.representative_rules.join(","),
                        reason.category,
                        reason.signal_class,
                        reason.strongest_action,
                    ));
                }
            }
            if args.dataset_view == DatasetViewArg::Verdicts {
                output.push_str(&formatting::format_dataset_verdicts_text(
                    &aggregated_package_verdicts,
                    args.analyst_summary,
                    color,
                ));
            } else {
                output.push_str(&format_results(
                    &dataset_results,
                    OutputFormat::Text,
                    text_options,
                )?);
            }
            output
        }
        OutputFormat::Json => {
            if args.dataset_view == DatasetViewArg::Verdicts {
                serde_json::to_string_pretty(&DatasetVerdictsJsonReport {
                    root: args.path.display().to_string(),
                    package_count: package_roots.len(),
                    skipped_packages,
                    packages_with_failures,
                    archive_extraction_warnings: prepared_dataset.skipped_archives,
                    benign_reports: verdict_counts.0,
                    suspicious_reports: verdict_counts.1,
                    malicious_reports: verdict_counts.2,
                    decode_warnings,
                    parse_warnings,
                    top_malicious_reasons,
                    verdicts: aggregated_package_verdicts,
                })
                .context("Failed to serialize compact verdict dataset JSON")?
            } else {
                serde_json::to_string_pretty(&DatasetJsonReport {
                    root: args.path.display().to_string(),
                    package_count: package_roots.len(),
                    skipped_packages,
                    packages_with_failures,
                    benign_reports: verdict_counts.0,
                    suspicious_reports: verdict_counts.1,
                    malicious_reports: verdict_counts.2,
                    decode_warnings,
                    parse_warnings,
                    non_agent_reports: non_agent_packages,
                    top_malicious_reasons,
                    reports: dataset_entries,
                })
                .context("Failed to serialize dataset JSON")?
            }
        }
        OutputFormat::Sarif | OutputFormat::Shield => {
            format_results(&dataset_results, args.format, text_options)?
        }
    };

    if let Some(output_path) = args.output {
        fs::write(&output_path, &output_content).context("Failed to write output file")?;
        if !quiet {
            eprintln!("Output written to: {}", output_path.display());
        }
    } else {
        print!("{}", output_content);
    }

    let any_failed = dataset_results.iter().any(|result| result.should_fail);
    Ok(any_failed)
}
