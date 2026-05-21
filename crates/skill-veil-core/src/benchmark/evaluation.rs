//! Corpus-evaluation orchestrator: runs the scanner across a labelled
//! sample set, aggregates per-sample metrics, and assembles the
//! [`CorpusEvaluation`] report. Threshold tuning lives in
//! [`super::thresholds`]; confidence calibration in
//! [`super::calibration`]; serializable result types in
//! [`super::types`].

use super::calibration::calibrate_confidence;
use super::loader::load_manifest;
use super::thresholds::recommend_thresholds;
use super::types::{
    AttackFamilyMetrics, BenchmarkError, CorpusCoverage, CorpusEvaluation, CorpusManifest,
    CoverageBucket, DeduplicationMetrics, LabeledSample, RegressionMetrics, SampleEvaluation,
    SampleLabel,
};
use crate::ports::FileSystemProvider;
use crate::scanner::PackageScanResult;
use crate::{Finding, RecommendedAction, Scanner, ThreatCategory, Verdict};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Per-sample aggregation extracted from a `PackageScanResult`. Keeps
/// the inner loop of `evaluate_corpus` focused on routing data into
/// the right bucket instead of computing it in line.
struct SampleAggregate {
    recommended_action: RecommendedAction,
    package_verdict: Verdict,
    risk_score: u32,
    finding_count: usize,
    primary_finding_count: usize,
    supporting_finding_count: usize,
    duplicates_removed: usize,
}

/// Coverage tally used by `evaluate_corpus` to build the final
/// `CorpusCoverage`. Wraps three logically-related maps so they can be
/// updated through a single helper without leaking the per-bucket
/// vocabulary into the orchestration loop.
#[derive(Default)]
struct CoverageBuckets {
    by_label: BTreeMap<String, u32>,
    by_focus_category: BTreeMap<String, u32>,
    by_attack_family: BTreeMap<String, u32>,
}

impl CoverageBuckets {
    fn finalize(self, total_samples: u32) -> CorpusCoverage {
        CorpusCoverage {
            total_samples,
            by_label: finalize_coverage_buckets(self.by_label),
            by_focus_category: finalize_coverage_buckets(self.by_focus_category),
            by_attack_family: finalize_coverage_buckets(self.by_attack_family),
        }
    }
}

pub fn evaluate_corpus<F: FileSystemProvider>(
    fs: &F,
    scanner: &Scanner,
    manifest_path: &Path,
) -> Result<CorpusEvaluation, BenchmarkError> {
    let manifest = load_manifest(fs, manifest_path)?;
    let root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    evaluate_manifest(fs, scanner, manifest, root)
}

/// Evaluate an already-loaded [`CorpusManifest`] whose sample paths
/// are relative to `root`. The path-based [`evaluate_corpus`] is a
/// thin wrapper; this is the reusable core so a curated manifest
/// (e.g. the gold corpus) is scored by the identical pipeline and
/// metric definition.
pub fn evaluate_manifest<F: FileSystemProvider>(
    fs: &F,
    scanner: &Scanner,
    manifest: CorpusManifest,
    root: &Path,
) -> Result<CorpusEvaluation, BenchmarkError> {
    if scanner.honor_inline_suppressions() {
        return Err(BenchmarkError::InvalidScannerOptions {
            message: "corpus evaluation requires inline suppressions disabled".to_string(),
        });
    }
    debug_assert!(
        !scanner.honor_inline_suppressions(),
        "corpus evaluation scanner must ignore inline suppressions"
    );

    let mut expected = Vec::new();
    let mut actual = Vec::new();
    let mut samples = Vec::new();
    let mut all_findings = Vec::<(SampleLabel, Finding)>::new();
    let mut deduplication = DeduplicationMetrics::default();
    let mut coverage = CoverageBuckets::default();

    for sample in manifest.samples {
        let sample_path = resolve_corpus_sample_path(&sample, root)?;
        let pkg_result = scan_corpus_sample(fs, scanner, &sample, &sample_path)?;
        let results = &pkg_result.results;

        let aggregate = aggregate_sample_metrics(results);
        let actual_label = classify_verdict(aggregate.package_verdict);
        expected.push(sample.label);
        actual.push(actual_label);

        accumulate_deduplication_metrics(
            &mut deduplication,
            &mut all_findings,
            results,
            sample.label,
        );
        update_coverage_buckets(&mut coverage, &sample);

        samples.push(SampleEvaluation {
            id: sample.id,
            expected: sample.label,
            actual: actual_label,
            verdict: aggregate.package_verdict,
            focus_category: sample.focus_category,
            attack_family: sample.attack_family,
            recommended_action: aggregate.recommended_action,
            risk_score: aggregate.risk_score,
            finding_count: aggregate.finding_count,
            primary_finding_count: aggregate.primary_finding_count,
            supporting_finding_count: aggregate.supporting_finding_count,
            duplicates_removed: aggregate.duplicates_removed,
            path: sample_path,
        });
    }

    let metrics = compute_metrics(&expected, &actual);
    let coverage = coverage.finalize(u32::try_from(samples.len()).unwrap_or(u32::MAX));
    let confidence_calibration = calibrate_confidence(&all_findings);
    let threshold_recommendation = recommend_thresholds(&samples);
    let family_metrics = build_family_metrics(&samples);

    Ok(CorpusEvaluation {
        metrics,
        coverage,
        deduplication,
        confidence_calibration,
        threshold_recommendation,
        family_metrics,
        samples,
    })
}

fn resolve_corpus_sample_path(
    sample: &LabeledSample,
    root: &Path,
) -> Result<PathBuf, BenchmarkError> {
    if sample.path.is_absolute() {
        return Err(BenchmarkError::SampleScan {
            id: sample.id.clone(),
            path: sample.path.clone(),
            message: "sample path must be relative to the corpus manifest".to_string(),
        });
    }
    Ok(root.join(&sample.path))
}

/// Run the scanner on one corpus sample and validate the result.
///
/// Routes the file-vs-directory discrimination through the
/// `FileSystemProvider` port (pre-fix it called `Path::is_dir`
/// directly, breaking the hexagonal contract that test mocks rely on).
/// Surfaces an error when the scanner returns partial failures or when
/// no scan results were produced — both states would otherwise be
/// silently ignored downstream and skew the metrics.
fn scan_corpus_sample<F: FileSystemProvider>(
    fs: &F,
    scanner: &Scanner,
    sample: &LabeledSample,
    sample_path: &Path,
) -> Result<PackageScanResult, BenchmarkError> {
    let pkg_result = if fs.is_dir(sample_path) {
        scanner.scan_package(sample_path)
    } else {
        scanner
            .scan_file(sample_path)
            .map(|result| PackageScanResult {
                results: vec![result],
                errors: Vec::new(),
            })
    }
    .map_err(|error| BenchmarkError::SampleScan {
        id: sample.id.clone(),
        path: sample_path.to_path_buf(),
        message: error.to_string(),
    })?;

    if !pkg_result.errors.is_empty() {
        let message = pkg_result
            .errors
            .iter()
            .map(|entry| format!("{}: {}", entry.path.display(), entry.error))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(BenchmarkError::SampleScan {
            id: sample.id.clone(),
            path: sample_path.to_path_buf(),
            message: format!("partial scan failure: {message}"),
        });
    }

    if pkg_result.results.is_empty() {
        return Err(BenchmarkError::SampleScan {
            id: sample.id.clone(),
            path: sample_path.to_path_buf(),
            message: "sample produced no scan results".to_string(),
        });
    }

    Ok(pkg_result)
}

/// Fold per-result fields (verdict, action, risk score, finding
/// counts) into a single [`SampleAggregate`]. The package-level
/// verdict is the strongest among the per-result verdicts; the
/// recommended action is the strongest as well.
fn aggregate_sample_metrics(results: &[crate::scanner::ScanResult]) -> SampleAggregate {
    let recommended_action = results
        .iter()
        .fold(RecommendedAction::Log, |current, result| {
            current.max(result.summary.recommended_action)
        });
    let package_verdict = results.iter().fold(Verdict::Benign, |current, result| {
        match (current, result.verdict) {
            (Verdict::Malicious, _) | (_, Verdict::Malicious) => Verdict::Malicious,
            (Verdict::Suspicious, _) | (_, Verdict::Suspicious) => Verdict::Suspicious,
            _ => Verdict::Benign,
        }
    });
    let risk_score = results
        .iter()
        .map(|result| result.summary.risk_score)
        .max()
        .unwrap_or(0);
    let finding_count = results.iter().map(|result| result.findings.len()).sum();
    let primary_finding_count = results
        .iter()
        .map(|result| result.primary_findings.len())
        .sum();
    let supporting_finding_count = results
        .iter()
        .map(|result| result.supporting_findings.len())
        .sum();
    let duplicates_removed = results
        .iter()
        .map(|result| result.deduplication_summary.duplicates_removed)
        .sum();
    SampleAggregate {
        recommended_action,
        package_verdict,
        risk_score,
        finding_count,
        primary_finding_count,
        supporting_finding_count,
        duplicates_removed,
    }
}

/// Accumulate per-result deduplication counters and append every
/// finding to `all_findings` paired with the sample label so the
/// confidence calibrator can cluster TP/FP per evidence/category.
fn accumulate_deduplication_metrics(
    deduplication: &mut DeduplicationMetrics,
    all_findings: &mut Vec<(SampleLabel, Finding)>,
    results: &[crate::scanner::ScanResult],
    label: SampleLabel,
) {
    for result in results {
        deduplication.original_findings = deduplication
            .original_findings
            .saturating_add(result.deduplication_summary.original_findings as u32);
        deduplication.unique_findings = deduplication
            .unique_findings
            .saturating_add(result.deduplication_summary.unique_findings as u32);
        deduplication.duplicates_removed = deduplication
            .duplicates_removed
            .saturating_add(result.deduplication_summary.duplicates_removed as u32);
        all_findings.extend(
            result
                .findings
                .iter()
                .cloned()
                .map(|finding| (label, finding)),
        );
    }
}

/// Update the three coverage buckets (label / attack family / focus
/// category) for one sample. Attack family falls back to the focus
/// category when the sample carries no explicit family — keeps the
/// derived family histogram comparable across mixed-source corpora.
fn update_coverage_buckets(coverage: &mut CoverageBuckets, sample: &LabeledSample) {
    *coverage
        .by_label
        .entry(sample.label.to_string())
        .or_insert(0) += 1;
    let derived_family = sample.attack_family.clone().or_else(|| {
        sample
            .focus_category
            .map(|category| attack_family_for_category(category).to_string())
    });
    if let Some(family) = derived_family {
        *coverage.by_attack_family.entry(family).or_insert(0) += 1;
    }
    if let Some(category) = sample.focus_category {
        *coverage
            .by_focus_category
            .entry(category.to_string())
            .or_insert(0) += 1;
    }
}

fn build_family_metrics(samples: &[SampleEvaluation]) -> Vec<AttackFamilyMetrics> {
    let mut by_family = BTreeMap::<String, Vec<SampleEvaluation>>::new();
    for sample in samples {
        if let Some(family) = sample.attack_family.clone().or_else(|| {
            sample
                .focus_category
                .map(|category| attack_family_for_category(category).to_string())
        }) {
            by_family.entry(family).or_default().push(sample.clone());
        }
    }

    by_family
        .into_iter()
        .map(|(family, family_samples)| {
            let expected: Vec<_> = family_samples
                .iter()
                .map(|sample| sample.expected)
                .collect();
            let actual: Vec<_> = family_samples.iter().map(|sample| sample.actual).collect();
            let metrics = compute_metrics(&expected, &actual);
            let threshold_recommendation = recommend_thresholds(&family_samples);
            AttackFamilyMetrics {
                family,
                sample_count: u32::try_from(family_samples.len()).unwrap_or(u32::MAX),
                metrics,
                threshold_recommendation,
            }
        })
        .collect()
}

fn attack_family_for_category(category: ThreatCategory) -> &'static str {
    match category {
        ThreatCategory::RemoteExec => "remote_exec",
        ThreatCategory::DataExfiltration => "exfiltration",
        ThreatCategory::AutonomyEscalation | ThreatCategory::PersistentPromptTampering => {
            "autonomy_bypass"
        }
        ThreatCategory::ScopeCreep => "scope_abuse",
        ThreatCategory::ToolAbuse => "tool_abuse",
        ThreatCategory::SupplyChain => "supply_chain",
        ThreatCategory::CredentialExposure => "credential_access",
        ThreatCategory::PrivilegeEscalation => "privilege_escalation",
        ThreatCategory::SocialManipulation | ThreatCategory::PersuasiveLanguage => {
            "social_manipulation"
        }
        ThreatCategory::Obfuscation => "obfuscation",
        ThreatCategory::UnsafeBinary => "unsafe_binary",
        ThreatCategory::Generic => "generic",
    }
}

pub fn classify_verdict(verdict: Verdict) -> SampleLabel {
    match verdict {
        Verdict::Benign => SampleLabel::Benign,
        Verdict::Suspicious => SampleLabel::Suspicious,
        Verdict::Malicious => SampleLabel::Malicious,
    }
}

/// Compute precision/recall/FPR/accuracy from labelled corpus output.
///
/// # Empty-corpus contract
///
/// When `expected.is_empty()`, sample-level rates (`accuracy`,
/// `exact_label_accuracy`) return `f32::NAN` to signal "nothing to
/// evaluate" — distinguishable from `0.0` ("scanner got everything
/// wrong on a real corpus"). The pre-fix `.max(1)` clamp on the
/// total-sample denominator collapsed both cases to `0.0`, leaving
/// callers unable to tell apart an empty input from a universally-failed
/// scan.
///
/// Per-class rates (`precision`, `recall`, `false_positive_rate`) keep
/// the `.max(1)` clamp and surface as `0.0` when their respective class
/// has no examples, since callers compare these against thresholds and
/// NaN comparisons (always `false` under `<` / `>`) would silently
/// short-circuit threshold checks.
pub fn compute_metrics(expected: &[SampleLabel], actual: &[SampleLabel]) -> RegressionMetrics {
    let mut true_positive = 0_u32;
    let mut false_positive = 0_u32;
    let mut true_negative = 0_u32;
    let mut false_negative = 0_u32;

    for (expected_label, actual_label) in expected.iter().zip(actual.iter()) {
        let expected_risky = *expected_label != SampleLabel::Benign;
        let actual_risky = *actual_label != SampleLabel::Benign;

        match (expected_risky, actual_risky) {
            (true, true) => true_positive += 1,
            (false, true) => false_positive += 1,
            (false, false) => true_negative += 1,
            (true, false) => false_negative += 1,
        }
    }

    let precision_denominator = (true_positive + false_positive).max(1) as f32;
    let recall_denominator = (true_positive + false_negative).max(1) as f32;
    let fpr_denominator = (false_positive + true_negative).max(1) as f32;

    let total = expected.len() as f32;
    let accuracy = if expected.is_empty() {
        f32::NAN
    } else {
        (true_positive + true_negative) as f32 / total
    };
    let exact_label_accuracy = if expected.is_empty() {
        f32::NAN
    } else {
        expected
            .iter()
            .zip(actual.iter())
            .filter(|(expected_label, actual_label)| expected_label == actual_label)
            .count() as f32
            / total
    };

    RegressionMetrics {
        precision: true_positive as f32 / precision_denominator,
        recall: true_positive as f32 / recall_denominator,
        false_positive_rate: false_positive as f32 / fpr_denominator,
        accuracy,
        exact_label_accuracy,
        true_positive,
        false_positive,
        true_negative,
        false_negative,
    }
}

fn finalize_coverage_buckets(buckets: BTreeMap<String, u32>) -> Vec<CoverageBucket> {
    buckets
        .into_iter()
        .map(|(key, samples)| CoverageBucket { key, samples })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::ScanTargetMode;
    use crate::{ScanOptions, Scanner};
    use tempfile::tempdir;

    fn corpus_scanner() -> Scanner {
        Scanner::with_std_adapters(ScanOptions {
            honor_inline_suppressions: false,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn test_evaluate_corpus_fails_on_partial_package_scan_errors() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let dir = tempdir().unwrap();
            let corpus_path = dir.path().join("corpus.yaml");
            let sample_dir = dir.path().join("sample");
            std::fs::create_dir_all(&sample_dir).unwrap();
            std::fs::write(
                sample_dir.join("SKILL.md"),
                "# Skill\n\n## Setup\nInstall dependencies.\n",
            )
            .unwrap();
            let package_json = sample_dir.join("package.json");
            std::fs::write(&package_json, r#"{"dependencies":{"chalk":"^5.0.0"}}"#).unwrap();
            let mut permissions = std::fs::metadata(&package_json).unwrap().permissions();
            permissions.set_mode(0o000);
            std::fs::set_permissions(&package_json, permissions).unwrap();
            std::fs::write(
                &corpus_path,
                "samples:\n  - id: partial\n    path: sample\n    label: suspicious\n",
            )
            .unwrap();

            let scanner = Scanner::with_std_adapters(ScanOptions {
                target_mode: ScanTargetMode::Package,
                honor_inline_suppressions: false,
                ..Default::default()
            })
            .unwrap();
            let fs = crate::adapters::StdFileSystemProvider::new();
            let error = evaluate_corpus(&fs, &scanner, &corpus_path).unwrap_err();

            let mut restore_permissions = std::fs::metadata(&package_json).unwrap().permissions();
            restore_permissions.set_mode(0o644);
            let _ = std::fs::set_permissions(&package_json, restore_permissions);

            match error {
                BenchmarkError::SampleScan { id, message, .. } => {
                    assert_eq!(id, "partial");
                    assert!(message.contains("partial scan failure"));
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }

    /// Contract: corpus metrics must not honor inline suppressions from
    /// samples under measurement.
    #[test]
    fn evaluate_corpus_rejects_suppression_honoring_scanner() {
        let dir = tempdir().unwrap();
        let corpus_path = dir.path().join("corpus.yaml");
        std::fs::write(&corpus_path, "samples: []\n").unwrap();

        let scanner = Scanner::new().unwrap();
        let fs = crate::adapters::StdFileSystemProvider::new();
        let error = evaluate_corpus(&fs, &scanner, &corpus_path).unwrap_err();

        match error {
            BenchmarkError::InvalidScannerOptions { message } => {
                assert!(message.contains("inline suppressions disabled"));
            }
            other => panic!("expected InvalidScannerOptions error, got {other:?}"),
        }
    }

    /// Contract: corpus sample paths are relative. Absolute paths would
    /// make `Path::join(root, sample)` discard the manifest root entirely.
    #[test]
    fn evaluate_corpus_rejects_absolute_sample_path() {
        let dir = tempdir().unwrap();
        let outside_dir = dir.path().join("outside");
        std::fs::create_dir_all(&outside_dir).unwrap();
        let sample_path = outside_dir.join("SKILL.md");
        std::fs::write(&sample_path, "# Skill\n\n## Setup\nSafe docs.\n").unwrap();
        let corpus_path = dir.path().join("corpus.yaml");
        let manifest = CorpusManifest {
            samples: vec![LabeledSample {
                id: "absolute".to_string(),
                path: sample_path,
                label: SampleLabel::Benign,
                focus_category: None,
                attack_family: None,
            }],
        };
        std::fs::write(&corpus_path, serde_yaml::to_string(&manifest).unwrap()).unwrap();

        let scanner = corpus_scanner();
        let fs = crate::adapters::StdFileSystemProvider::new();
        let error = evaluate_corpus(&fs, &scanner, &corpus_path).unwrap_err();

        match error {
            BenchmarkError::SampleScan { id, message, .. } => {
                assert_eq!(id, "absolute");
                assert!(
                    message.contains("must be relative"),
                    "error should name the relative-path contract; got {message}"
                );
            }
            other => panic!("expected SampleScan error, got {other:?}"),
        }
    }

    /// Contract: repository corpora may share fixtures with relative
    /// parent components, as long as the manifest does not use an
    /// absolute path.
    #[test]
    fn evaluate_corpus_accepts_relative_parent_sample_path() {
        let dir = tempdir().unwrap();
        let corpus_dir = dir.path().join("corpus");
        let examples_dir = dir.path().join("examples");
        std::fs::create_dir_all(&corpus_dir).unwrap();
        std::fs::create_dir_all(&examples_dir).unwrap();
        std::fs::write(
            examples_dir.join("SKILL.md"),
            "# Skill\n\n## Usage\nThis skill documents normal setup.\n",
        )
        .unwrap();
        let corpus_path = corpus_dir.join("corpus.yaml");
        std::fs::write(
            &corpus_path,
            "samples:\n  - id: shared\n    path: ../examples/SKILL.md\n    label: benign\n",
        )
        .unwrap();

        let scanner = corpus_scanner();
        let fs = crate::adapters::StdFileSystemProvider::new();
        let evaluation = evaluate_corpus(&fs, &scanner, &corpus_path).unwrap();

        assert_eq!(evaluation.samples.len(), 1);
        assert_eq!(evaluation.samples[0].id, "shared");
    }

    /// Contract: ordinary in-root sample paths still evaluate normally.
    #[test]
    fn evaluate_corpus_accepts_sample_path_inside_manifest_root() {
        let dir = tempdir().unwrap();
        let corpus_path = dir.path().join("corpus.yaml");
        let sample_path = dir.path().join("SKILL.md");
        std::fs::write(
            &sample_path,
            "# Skill\n\n## Usage\nThis skill documents normal setup.\n",
        )
        .unwrap();
        std::fs::write(
            &corpus_path,
            "samples:\n  - id: inside\n    path: SKILL.md\n    label: benign\n",
        )
        .unwrap();

        let scanner = corpus_scanner();
        let fs = crate::adapters::StdFileSystemProvider::new();
        let evaluation = evaluate_corpus(&fs, &scanner, &corpus_path).unwrap();

        assert_eq!(evaluation.samples.len(), 1);
        assert_eq!(evaluation.samples[0].id, "inside");
    }

    /// Contract: empty corpus yields NaN for sample-level rates so
    /// callers can tell apart "no data" from "0% correct on real data".
    #[test]
    fn compute_metrics_returns_nan_accuracy_for_empty_corpus() {
        let m = compute_metrics(&[], &[]);
        assert!(
            m.accuracy.is_nan(),
            "empty corpus must yield NaN accuracy, got {}",
            m.accuracy
        );
        assert!(
            m.exact_label_accuracy.is_nan(),
            "empty corpus must yield NaN exact_label_accuracy, got {}",
            m.exact_label_accuracy
        );
    }

    /// Contract: per-class rates stay at 0.0 on empty corpus. Callers
    /// compare these against thresholds and NaN would silently
    /// short-circuit those comparisons. Pins the deliberate split
    /// between sample-level NaN and per-class 0.0.
    #[test]
    fn compute_metrics_keeps_zero_for_per_class_rates_on_empty_corpus() {
        let m = compute_metrics(&[], &[]);
        assert!(
            !m.precision.is_nan() && m.precision.abs() < f32::EPSILON,
            "precision must be 0.0 (not NaN) on empty corpus"
        );
        assert!(
            !m.recall.is_nan() && m.recall.abs() < f32::EPSILON,
            "recall must be 0.0 (not NaN) on empty corpus"
        );
        assert!(
            !m.false_positive_rate.is_nan() && m.false_positive_rate.abs() < f32::EPSILON,
            "false_positive_rate must be 0.0 (not NaN) on empty corpus"
        );
    }

    /// Contract: non-empty input produces finite, predictable metrics —
    /// pins the no-op case so the empty-input fix does not regress the
    /// populated path.
    #[test]
    fn compute_metrics_unchanged_for_non_empty_input() {
        // 3 samples: 2 risky/risky agreement (TP), 1 benign/benign agreement (TN).
        let expected = &[
            SampleLabel::Malicious,
            SampleLabel::Suspicious,
            SampleLabel::Benign,
        ];
        let actual = &[
            SampleLabel::Malicious,
            SampleLabel::Suspicious,
            SampleLabel::Benign,
        ];
        let m = compute_metrics(expected, actual);
        assert_eq!(m.true_positive, 2);
        assert_eq!(m.false_positive, 0);
        assert_eq!(m.true_negative, 1);
        assert_eq!(m.false_negative, 0);
        assert!((m.accuracy - 1.0).abs() < f32::EPSILON);
        assert!((m.exact_label_accuracy - 1.0).abs() < f32::EPSILON);
        assert!((m.precision - 1.0).abs() < f32::EPSILON);
        assert!((m.recall - 1.0).abs() < f32::EPSILON);
        assert!(m.false_positive_rate.abs() < f32::EPSILON);
    }

    /// Architectural contract: `evaluate_corpus` and the helper it
    /// delegates to (`scan_corpus_sample`) MUST route the
    /// file-vs-directory discrimination through the
    /// `FileSystemProvider` port. Pre-fix the orchestration loop
    /// called `sample_path.is_dir()` directly, breaking the hexagonal
    /// contract: a test mock could not influence whether the scanner
    /// took the file or the package branch. Mirrors the source-level
    /// contract test in `scanner/mod.rs`.
    #[test]
    fn evaluate_corpus_does_not_call_path_is_dir_directly() {
        let body = include_str!("evaluation.rs");
        let production = body.split("#[cfg(test)]").next().unwrap_or(body);
        for (idx, line) in production.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if trimmed.contains(".is_dir(")
                && !trimmed.contains("fs.is_dir(")
                && !trimmed.contains("fs_provider().is_dir(")
            {
                panic!(
                    "benchmark/evaluation.rs line {} calls .is_dir() outside the FileSystemProvider port: {line}",
                    idx + 1,
                );
            }
        }
    }
}
