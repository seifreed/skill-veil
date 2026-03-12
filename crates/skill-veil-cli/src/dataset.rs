use crate::text_output::{format_results, TextOutputOptions};
use crate::{
    cli_args::{DatasetViewArg, OutputFormat, ScanArgs},
    commands::apply_scan_preset,
};
use anyhow::{Context, Result};
use rayon::prelude::*;
use skill_veil_core::{
    ArtifactScope, JsonReport, PackageHealth, RecommendedAction, RootCauseGroup, ScanOptions,
    ScanResult, ScanTargetMode, Scanner, Severity, SignalClass, Verdict,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    package_id: Option<String>,
    report: JsonReport,
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
    package_id: Option<String>,
    skill_path: String,
    scope: String,
    representative_rules: Vec<String>,
    category: String,
    signal_class: String,
    strongest_action: String,
}

#[derive(Debug)]
struct DatasetPreparation {
    package_roots: Vec<PathBuf>,
    skipped_archives: usize,
}

pub(crate) fn run_scan_dataset(args: ScanArgs, quiet: bool) -> Result<()> {
    let args = apply_scan_preset(args);
    let text_options = TextOutputOptions {
        quiet_summary: args.quiet_summary,
        explain_policy: args.explain_policy,
        finding_limit: args.finding_limit,
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
        ..Default::default()
    };

    let scanner =
        Arc::new(Scanner::with_std_adapters(options).context("Failed to initialize scanner")?);
    let prepared_dataset = prepare_dataset_packages(&args.path)?;
    let package_roots = prepared_dataset.package_roots.clone();
    if package_roots.is_empty() {
        anyhow::bail!(
            "No package roots with SKILL.md were found under {}",
            args.path.display()
        );
    }

    enum DatasetScanOutcome {
        Results(Vec<ScanResult>),
        Skipped,
        Failed(String),
    }

    let outcomes: Vec<_> = package_roots
        .par_iter()
        .map(|package_root| match scanner.scan(package_root) {
            Ok(results) => DatasetScanOutcome::Results(results),
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
            DatasetScanOutcome::Results(results) => {
                if results.iter().any(|result| result.should_fail) {
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

    let dataset_results = filter_dataset_results(&all_results, args.dataset_view);
    let dataset_reports: Vec<_> = dataset_results
        .iter()
        .map(|result| result.to_json_report())
        .collect();
    let dataset_entries: Vec<_> = dataset_reports
        .iter()
        .cloned()
        .map(|report| DatasetJsonEntry {
            package_id: report
                .package_id
                .clone()
                .or_else(|| extract_package_id_from_skill_path(&report.skill_path)),
            report,
        })
        .collect();
    let aggregated_package_verdicts = aggregate_package_verdicts(&dataset_entries);
    let verdict_counts = if args.dataset_view == DatasetViewArg::Verdicts {
        count_aggregated_verdicts(&aggregated_package_verdicts)
    } else {
        count_verdicts(&dataset_reports)
    };
    let decode_warnings = count_warning_rule(&dataset_reports, "ARTIFACT_DECODE_WARNING");
    let parse_warnings = count_warning_rule(&dataset_reports, "ARTIFACT_PARSE_WARNING");
    let non_agent_packages = dataset_reports
        .iter()
        .filter(|report| {
            report.classification == skill_veil_core::ArtifactClassification::GenericMarkdown
        })
        .count();
    let top_malicious_reasons = top_malicious_reasons(&dataset_reports);

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
                output.push_str(&format_dataset_verdicts_text(
                    &aggregated_package_verdicts,
                    args.analyst_summary,
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

    if dataset_results.iter().any(|result| result.should_fail) {
        std::process::exit(1);
    }

    Ok(())
}

fn filter_dataset_results(results: &[ScanResult], view: DatasetViewArg) -> Vec<ScanResult> {
    results
        .iter()
        .filter(|result| match view {
            DatasetViewArg::Full => true,
            DatasetViewArg::Entrypoints => {
                result.classification != skill_veil_core::ArtifactClassification::GenericMarkdown
            }
            DatasetViewArg::PackageRisk => {
                result.classification == skill_veil_core::ArtifactClassification::GenericMarkdown
                    || !result.supporting_findings.is_empty()
            }
            DatasetViewArg::Verdicts => result.verdict != Verdict::Benign,
        })
        .cloned()
        .collect()
}

fn count_verdicts(reports: &[JsonReport]) -> (usize, usize, usize) {
    reports.iter().fold((0, 0, 0), |mut acc, report| {
        match report.verdict {
            Verdict::Benign => acc.0 += 1,
            Verdict::Suspicious => acc.1 += 1,
            Verdict::Malicious => acc.2 += 1,
        }
        acc
    })
}

fn count_warning_rule(reports: &[JsonReport], rule_id: &str) -> usize {
    reports
        .iter()
        .map(|report| {
            report
                .findings
                .iter()
                .filter(|finding| finding.rule_id == rule_id)
                .count()
        })
        .sum()
}

fn extract_package_id_from_skill_path(skill_path: &str) -> Option<String> {
    skill_path
        .split('/')
        .find(|segment| segment.len() == 64 && segment.chars().all(|c| c.is_ascii_hexdigit()))
        .map(ToOwned::to_owned)
}

fn top_malicious_reasons(reports: &[JsonReport]) -> Vec<DatasetMaliciousReason> {
    let mut reasons: Vec<_> = reports
        .iter()
        .filter(|report| report.verdict == Verdict::Malicious)
        .flat_map(|report| {
            report
                .verdict_report
                .root_cause_groups
                .iter()
                .filter(|group| group.strongest_action == RecommendedAction::Block)
                .map(|group| DatasetMaliciousReason {
                    package_id: report
                        .package_id
                        .clone()
                        .or_else(|| extract_package_id_from_skill_path(&report.skill_path)),
                    skill_path: report.skill_path.clone(),
                    scope: group.scope.to_string(),
                    representative_rules: group.representative_rules.clone(),
                    category: group.category.to_string(),
                    signal_class: group.signal_class.to_string(),
                    strongest_action: group.strongest_action.to_string(),
                })
        })
        .collect();
    reasons.sort_by(|left, right| {
        left.package_id
            .cmp(&right.package_id)
            .then_with(|| left.scope.cmp(&right.scope))
            .then_with(|| left.category.cmp(&right.category))
    });
    reasons
}

fn prepare_dataset_packages(root: &Path) -> Result<DatasetPreparation> {
    let immediate_subdirs: Vec<_> = fs::read_dir(root)
        .with_context(|| format!("Failed to read dataset root {}", root.display()))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let hidden = name.to_str().is_some_and(|name| name.starts_with('.'));
            entry
                .file_type()
                .ok()
                .filter(|ft| ft.is_dir() && !hidden)
                .map(|_| entry.path())
        })
        .collect();
    if !immediate_subdirs.is_empty() {
        return Ok(DatasetPreparation {
            package_roots: immediate_subdirs,
            skipped_archives: 0,
        });
    }

    let archive_files: Vec<_> = fs::read_dir(root)
        .with_context(|| format!("Failed to read dataset root {}", root.display()))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            if !entry.file_type().ok().is_some_and(|ft| ft.is_file()) {
                return None;
            }
            if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
                || is_zip_archive(&path)
            {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    if !archive_files.is_empty() {
        let cache_root = root.join(".skill-veil-cache").join("extracted");
        fs::create_dir_all(&cache_root)
            .with_context(|| format!("Failed to create {}", cache_root.display()))?;

        let extraction_results: Vec<_> = archive_files
            .par_iter()
            .map(|zip_path| extract_zip_package_cached(zip_path, &cache_root))
            .collect();

        let mut skipped_archives = 0_usize;
        for result in extraction_results {
            match result {
                Ok(()) => {}
                Err(err) => {
                    skipped_archives += 1;
                    tracing::warn!("{err:#}");
                }
            }
        }

        let extracted_roots: Vec<_> = fs::read_dir(&cache_root)
            .with_context(|| format!("Failed to read {}", cache_root.display()))?
            .filter_map(Result::ok)
            .filter_map(|entry| {
                entry
                    .file_type()
                    .ok()
                    .filter(|ft| ft.is_dir())
                    .map(|_| entry.path())
            })
            .collect();
        return Ok(DatasetPreparation {
            package_roots: extracted_roots,
            skipped_archives,
        });
    }

    let mut packages = BTreeSet::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
    {
        if entry
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("SKILL.md"))
        {
            if let Some(parent) = entry.path().parent() {
                packages.insert(parent.to_path_buf());
            }
        }
    }
    Ok(DatasetPreparation {
        package_roots: packages.into_iter().collect(),
        skipped_archives: 0,
    })
}

fn is_zip_archive(path: &Path) -> bool {
    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    zip::ZipArchive::new(file).is_ok()
}

fn extract_zip_package(zip_path: &Path, output_dir: &Path) -> Result<()> {
    let file = fs::File::open(zip_path)
        .with_context(|| format!("Failed to open {}", zip_path.display()))?;
    let mut archive = zip::ZipArchive::new(file)
        .with_context(|| format!("Invalid zip {}", zip_path.display()))?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("Failed to read zip entry {}", zip_path.display()))?;
        let Some(relative_path) = entry.enclosed_name().map(|path| path.to_path_buf()) else {
            continue;
        };
        let destination = output_dir.join(relative_path);
        if entry.is_dir() {
            fs::create_dir_all(&destination)
                .with_context(|| format!("Failed to create {}", destination.display()))?;
            continue;
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        let mut outfile = fs::File::create(&destination)
            .with_context(|| format!("Failed to create {}", destination.display()))?;
        std::io::copy(&mut entry, &mut outfile)
            .with_context(|| format!("Failed to extract {}", destination.display()))?;
    }
    Ok(())
}

fn extract_zip_package_cached(zip_path: &Path, cache_root: &Path) -> Result<()> {
    let package_name = zip_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("package");
    let output_dir = cache_root.join(package_name);
    let marker_path = output_dir.join(".skill-veil-source");
    let source_signature = zip_source_signature(zip_path)?;

    if output_dir.is_dir()
        && marker_path.exists()
        && fs::read_to_string(&marker_path).ok().as_deref() == Some(source_signature.as_str())
    {
        return Ok(());
    }

    let staging_dir = cache_root.join(format!(".{}.tmp", package_name));
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .with_context(|| format!("Failed to clean {}", staging_dir.display()))?;
    }
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("Failed to create {}", staging_dir.display()))?;
    extract_zip_package(zip_path, &staging_dir)?;
    fs::write(staging_dir.join(".skill-veil-source"), &source_signature)
        .with_context(|| format!("Failed to write marker for {}", zip_path.display()))?;

    if output_dir.exists() {
        fs::remove_dir_all(&output_dir)
            .with_context(|| format!("Failed to replace {}", output_dir.display()))?;
    }
    fs::rename(&staging_dir, &output_dir)
        .or_else(|_| {
            fs::create_dir_all(&output_dir)?;
            for entry in fs::read_dir(&staging_dir)? {
                let entry = entry?;
                let source = entry.path();
                let destination = output_dir.join(entry.file_name());
                fs::rename(source, destination)?;
            }
            fs::remove_dir_all(&staging_dir)
        })
        .with_context(|| {
            format!(
                "Failed to finalize cached extraction for {}",
                zip_path.display()
            )
        })?;
    Ok(())
}

fn zip_source_signature(zip_path: &Path) -> Result<String> {
    let metadata =
        fs::metadata(zip_path).with_context(|| format!("Failed to stat {}", zip_path.display()))?;
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    Ok(format!(
        "{}:{}:{}",
        zip_path.display(),
        metadata.len(),
        modified
    ))
}

pub(crate) fn format_dataset_verdicts_text(
    entries: &[DatasetPackageVerdictEntry],
    analyst_summary: bool,
) -> String {
    let mut lines = String::new();
    lines.push_str("\n--- Verdict Triage ---\n");

    for entry in entries {
        if analyst_summary {
            lines.push_str(&format_dataset_verdict_analyst_line(entry));
        } else {
            lines.push_str(&format!(
                "{} package={} health={} blast_radius={} declared_permissions={} rule={} why={} main={} supporting={} package_root={} path={}\n",
                entry.final_verdict,
                entry.package_id.as_deref().unwrap_or("unknown"),
                entry
                    .package_health
                    .map(|health| health.to_string())
                    .unwrap_or_else(|| "healthy".to_string()),
                entry
                    .blast_radius
                    .map(|level| level.to_string())
                    .unwrap_or_else(|| "low".to_string()),
                render_declared_permissions(&entry.declared_permissions),
                entry.top_rule.as_deref().unwrap_or("none"),
                entry.strongest_reason.as_deref().unwrap_or("no_strong_cause"),
                render_scope_summary(&entry.main_summary),
                render_scope_summary(&entry.supporting_summary),
                render_scope_summary(&entry.package_root_summary),
                entry.representative_path
            ));
        }
    }

    lines
}

fn format_dataset_verdict_analyst_line(entry: &DatasetPackageVerdictEntry) -> String {
    let scope = strongest_scope(entry);
    let top_reason = entry
        .strongest_reason
        .as_deref()
        .unwrap_or("no_strong_cause");
    format!(
        "[{verdict}] package={package} health={health} blast={blast} scope={scope} rule={rule} perms={perms} reason={reason}\n",
        verdict = entry.final_verdict,
        package = entry.package_id.as_deref().unwrap_or("unknown"),
        health = entry
            .package_health
            .map(|health| health.to_string())
            .unwrap_or_else(|| "healthy".to_string()),
        scope = scope,
        rule = entry.top_rule.as_deref().unwrap_or("none"),
        blast = entry
            .blast_radius
            .map(|level| level.to_string())
            .unwrap_or_else(|| "low".to_string()),
        perms = render_declared_permissions(&entry.declared_permissions),
        reason = top_reason,
    )
}

fn strongest_scope(entry: &DatasetPackageVerdictEntry) -> &'static str {
    if let Some(reason) = &entry.strongest_reason {
        if let Some(scope) = reason.split('/').next() {
            return match scope {
                "agent_entrypoint" => "agent_entrypoint",
                "supporting_artifact" => "supporting_artifact",
                "package_root_artifact" => "package_root_artifact",
                _ => "unknown",
            };
        }
    }
    if !entry.main_summary.is_empty() {
        "agent_entrypoint"
    } else if !entry.supporting_summary.is_empty() {
        "supporting_artifact"
    } else if !entry.package_root_summary.is_empty() {
        "package_root_artifact"
    } else {
        "unknown"
    }
}

fn render_declared_permissions(
    declared_permissions: &[skill_veil_core::DeclaredPermission],
) -> String {
    if declared_permissions.is_empty() {
        "none".to_string()
    } else {
        declared_permissions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn verdict_priority(verdict: &Verdict) -> u8 {
    match verdict {
        Verdict::Malicious => 3,
        Verdict::Suspicious => 2,
        Verdict::Benign => 1,
    }
}

fn signal_class_priority(signal_class: &SignalClass) -> u8 {
    match signal_class {
        SignalClass::MaliciousBehavior => 4,
        SignalClass::SuspiciousPackageBehavior => 3,
        SignalClass::ReviewSignal => 2,
        SignalClass::Hygiene => 1,
    }
}

fn action_priority(action: &RecommendedAction) -> u8 {
    match action {
        RecommendedAction::Log => 1,
        RecommendedAction::RequireApproval => 2,
        RecommendedAction::Block => 3,
    }
}

fn strongest_root_cause<'a>(group: &[&'a DatasetJsonEntry]) -> Option<&'a RootCauseGroup> {
    group
        .iter()
        .flat_map(|entry| entry.report.verdict_report.root_cause_groups.iter())
        .max_by(|left, right| {
            action_priority(&left.strongest_action)
                .cmp(&action_priority(&right.strongest_action))
                .then_with(|| {
                    signal_class_priority(&left.signal_class)
                        .cmp(&signal_class_priority(&right.signal_class))
                })
                .then_with(|| left.finding_count.cmp(&right.finding_count))
        })
}

fn strongest_finding_rule(group: &[&DatasetJsonEntry]) -> Option<String> {
    group
        .iter()
        .flat_map(|entry| entry.report.findings.iter())
        .max_by(|left, right| {
            action_priority(&left.recommended_action)
                .cmp(&action_priority(&right.recommended_action))
                .then_with(|| {
                    signal_class_priority(&left.signal_class)
                        .cmp(&signal_class_priority(&right.signal_class))
                })
                .then_with(|| {
                    severity_priority(&left.severity).cmp(&severity_priority(&right.severity))
                })
        })
        .map(|finding| finding.rule_id.clone())
}

fn severity_priority(severity: &Severity) -> u8 {
    match severity {
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

fn aggregate_package_verdicts(entries: &[DatasetJsonEntry]) -> Vec<DatasetPackageVerdictEntry> {
    let mut grouped = BTreeMap::<String, Vec<&DatasetJsonEntry>>::new();
    for entry in entries {
        let key = entry
            .package_id
            .clone()
            .unwrap_or_else(|| entry.report.skill_path.clone());
        grouped.entry(key).or_default().push(entry);
    }

    let mut verdicts = Vec::new();
    for (key, group) in grouped {
        let representative = group
            .iter()
            .max_by(|left, right| {
                verdict_priority(&left.report.verdict)
                    .cmp(&verdict_priority(&right.report.verdict))
                    .then_with(|| {
                        left.report
                            .summary
                            .risk_score
                            .cmp(&right.report.summary.risk_score)
                    })
                    .then_with(|| {
                        left.report
                            .heuristic_score
                            .cmp(&right.report.heuristic_score)
                    })
            })
            .expect("group is not empty");

        let final_verdict = group
            .iter()
            .map(|entry| entry.report.verdict)
            .max_by_key(verdict_priority)
            .unwrap_or(Verdict::Benign);
        let package_health = group
            .iter()
            .map(|entry| entry.report.verdict_report.package_health)
            .max_by_key(package_health_priority);
        let strongest_root_cause = strongest_root_cause(&group);
        verdicts.push(DatasetPackageVerdictEntry {
            package_id: Some(key),
            final_verdict,
            package_health,
            blast_radius: representative
                .report
                .verdict_report
                .blast_radius_summary
                .level,
            declared_permissions: representative
                .report
                .verdict_report
                .declared_permissions
                .clone(),
            strongest_reason: strongest_root_cause
                .map(|group| format!("{}/{}/{}", group.scope, group.category, group.signal_class)),
            top_rule: strongest_finding_rule(&group).or_else(|| {
                strongest_root_cause
                    .and_then(|group| group.representative_rules.first())
                    .cloned()
            }),
            representative_path: representative.report.skill_path.clone(),
            main_summary: summarize_scope(&group, ArtifactScope::AgentEntrypoint),
            supporting_summary: summarize_scope(&group, ArtifactScope::SupportingArtifact),
            package_root_summary: summarize_scope(&group, ArtifactScope::PackageRootArtifact),
        });
    }

    verdicts.sort_by(|left, right| {
        verdict_priority(&right.final_verdict)
            .cmp(&verdict_priority(&left.final_verdict))
            .then_with(|| {
                package_health_priority(&right.package_health.unwrap_or(PackageHealth::Healthy))
                    .cmp(&package_health_priority(
                        &left.package_health.unwrap_or(PackageHealth::Healthy),
                    ))
            })
            .then_with(|| left.package_id.cmp(&right.package_id))
    });
    verdicts
}

fn summarize_scope(entries: &[&DatasetJsonEntry], scope: ArtifactScope) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for entry in entries {
        for group in &entry.report.verdict_report.root_cause_groups {
            if group.scope == scope {
                seen.insert(format!("{}/{}", group.category, group.signal_class));
            }
        }
    }
    seen.into_iter().take(3).collect()
}

fn render_scope_summary(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(",")
    }
}

fn count_aggregated_verdicts(entries: &[DatasetPackageVerdictEntry]) -> (usize, usize, usize) {
    entries.iter().fold((0, 0, 0), |mut acc, entry| {
        match entry.final_verdict {
            Verdict::Benign => acc.0 += 1,
            Verdict::Suspicious => acc.1 += 1,
            Verdict::Malicious => acc.2 += 1,
        }
        acc
    })
}

fn package_health_priority(health: &PackageHealth) -> u8 {
    match health {
        PackageHealth::Healthy => 1,
        PackageHealth::NeedsReview => 2,
        PackageHealth::Elevated => 3,
    }
}
