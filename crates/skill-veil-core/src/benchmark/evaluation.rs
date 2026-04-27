use super::loader::load_manifest;
use super::types::{
    AttackFamilyMetrics, BenchmarkError, CalibrationBucket, CalibrationSummary, CorpusCoverage,
    CorpusEvaluation, CoverageBucket, DeduplicationMetrics, RegressionMetrics, SampleEvaluation,
    SampleLabel, ThresholdRecommendation,
};
use crate::{EvidenceKind, Finding, Scanner, ThreatCategory, Verdict};
use std::collections::BTreeMap;
use std::path::Path;

pub fn evaluate_corpus(
    scanner: &Scanner,
    manifest_path: &Path,
) -> Result<CorpusEvaluation, BenchmarkError> {
    let manifest = load_manifest(manifest_path)?;
    let root = manifest_path.parent().unwrap_or_else(|| Path::new("."));

    let mut expected = Vec::new();
    let mut actual = Vec::new();
    let mut samples = Vec::new();
    let mut all_findings = Vec::<(SampleLabel, Finding)>::new();
    let mut deduplication = DeduplicationMetrics::default();
    let mut coverage_by_label = BTreeMap::<String, u32>::new();
    let mut coverage_by_focus_category = BTreeMap::<String, u32>::new();
    let mut coverage_by_attack_family = BTreeMap::<String, u32>::new();

    for sample in manifest.samples {
        let sample_path = root.join(&sample.path);
        let pkg_result = if sample_path.is_dir() {
            scanner.scan_package(&sample_path)
        } else {
            scanner
                .scan_file(&sample_path)
                .map(|result| crate::scanner::PackageScanResult {
                    results: vec![result],
                    errors: Vec::new(),
                })
        }
        .map_err(|error| BenchmarkError::SampleScan {
            id: sample.id.clone(),
            path: sample_path.clone(),
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
                path: sample_path.clone(),
                message: format!("partial scan failure: {message}"),
            });
        }

        let results = &pkg_result.results;
        if results.is_empty() {
            return Err(BenchmarkError::SampleScan {
                id: sample.id.clone(),
                path: sample_path.clone(),
                message: "sample produced no scan results".to_string(),
            });
        }
        let recommended_action = results
            .iter()
            .fold(crate::RecommendedAction::Log, |current, result| {
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
        let actual_label = classify_verdict(package_verdict);
        expected.push(sample.label);
        actual.push(actual_label);
        for result in results {
            deduplication.original_findings +=
                result.deduplication_summary.original_findings as u32;
            deduplication.unique_findings += result.deduplication_summary.unique_findings as u32;
            deduplication.duplicates_removed +=
                result.deduplication_summary.duplicates_removed as u32;
            all_findings.extend(
                result
                    .findings
                    .iter()
                    .cloned()
                    .map(|finding| (sample.label, finding)),
            );
        }
        *coverage_by_label
            .entry(sample.label.to_string())
            .or_insert(0) += 1;
        if let Some(family) = sample.attack_family.clone().or_else(|| {
            sample
                .focus_category
                .map(|category| attack_family_for_category(category).to_string())
        }) {
            *coverage_by_attack_family.entry(family).or_insert(0) += 1;
        }
        if let Some(category) = sample.focus_category {
            *coverage_by_focus_category
                .entry(category.to_string())
                .or_insert(0) += 1;
        }
        samples.push(SampleEvaluation {
            id: sample.id,
            expected: sample.label,
            actual: actual_label,
            verdict: package_verdict,
            focus_category: sample.focus_category,
            attack_family: sample.attack_family,
            recommended_action,
            risk_score,
            finding_count,
            primary_finding_count,
            supporting_finding_count,
            duplicates_removed,
            path: sample_path,
        });
    }

    let metrics = compute_metrics(&expected, &actual);
    let coverage = CorpusCoverage {
        total_samples: samples.len() as u32,
        by_label: finalize_coverage_buckets(coverage_by_label),
        by_focus_category: finalize_coverage_buckets(coverage_by_focus_category),
        by_attack_family: finalize_coverage_buckets(coverage_by_attack_family),
    };
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
                sample_count: family_samples.len() as u32,
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

fn calibrate_confidence(findings: &[(SampleLabel, Finding)]) -> CalibrationSummary {
    CalibrationSummary {
        by_evidence_kind: calibration_buckets_by_evidence(findings),
        by_category: calibration_buckets_by_category(findings),
        by_signal_pair: calibration_buckets_by_signal_pair(findings),
    }
}

fn calibration_buckets_by_evidence(findings: &[(SampleLabel, Finding)]) -> Vec<CalibrationBucket> {
    let mut buckets = BTreeMap::<String, Vec<bool>>::new();
    for (label, finding) in findings {
        buckets
            .entry(evidence_key(finding.evidence_kind))
            .or_default()
            .push(*label != SampleLabel::Benign);
    }
    finalize_calibration_buckets(buckets)
}

fn calibration_buckets_by_category(findings: &[(SampleLabel, Finding)]) -> Vec<CalibrationBucket> {
    let mut buckets = BTreeMap::<String, Vec<bool>>::new();
    for (label, finding) in findings {
        buckets
            .entry(category_key(finding.category))
            .or_default()
            .push(*label != SampleLabel::Benign);
    }
    finalize_calibration_buckets(buckets)
}

fn calibration_buckets_by_signal_pair(
    findings: &[(SampleLabel, Finding)],
) -> Vec<CalibrationBucket> {
    let mut buckets = BTreeMap::<String, Vec<bool>>::new();
    for (label, finding) in findings {
        let key = format!(
            "{}+{}",
            evidence_key(finding.evidence_kind),
            category_key(finding.category)
        );
        buckets
            .entry(key)
            .or_default()
            .push(*label != SampleLabel::Benign);
    }
    finalize_calibration_buckets(buckets)
}

fn finalize_calibration_buckets(buckets: BTreeMap<String, Vec<bool>>) -> Vec<CalibrationBucket> {
    buckets
        .into_iter()
        .map(|(key, labels)| {
            let findings = labels.len() as u32;
            let true_positive = labels.iter().filter(|is_positive| **is_positive).count() as u32;
            let false_positive = findings.saturating_sub(true_positive);
            let observed_precision = if findings == 0 {
                0.0
            } else {
                true_positive as f32 / findings as f32
            };
            CalibrationBucket {
                key,
                findings,
                true_positive,
                false_positive,
                observed_precision,
                recommended_confidence: calibrate_confidence_value(observed_precision, findings),
            }
        })
        .collect()
}

fn calibrate_confidence_value(observed_precision: f32, findings: u32) -> f32 {
    // An empty bucket (no labelled findings) carries no statistical
    // signal; pre-fix the `findings.max(1)` coercion produced
    // `recommended_confidence = 0.35` which downstream readers cannot
    // distinguish from a real 0.35 calibration. NaN is the right
    // sentinel — `f32::is_nan()` flips clean and serializes to JSON
    // `null` via serde, so consumers can render "no data".
    if findings == 0 {
        return f32::NAN;
    }
    let lower_bound = wilson_lower_bound(observed_precision, findings);
    (0.35 + (lower_bound * 0.6)).clamp(0.1, 0.99)
}

fn wilson_lower_bound(observed_precision: f32, findings: u32) -> f32 {
    debug_assert!(
        findings > 0,
        "wilson_lower_bound: callers must guard `findings == 0` themselves",
    );
    let n = findings.max(1) as f32;
    let z = 1.96_f32;
    let z2 = z * z;
    let center = observed_precision + z2 / (2.0 * n);
    let margin =
        z * ((observed_precision * (1.0 - observed_precision) + z2 / (4.0 * n)) / n).sqrt();
    let denominator = 1.0 + z2 / n;
    ((center - margin) / denominator).clamp(0.0, 1.0)
}

fn finalize_coverage_buckets(buckets: BTreeMap<String, u32>) -> Vec<CoverageBucket> {
    buckets
        .into_iter()
        .map(|(key, samples)| CoverageBucket { key, samples })
        .collect()
}

fn recommend_thresholds(samples: &[SampleEvaluation]) -> ThresholdRecommendation {
    let current_approval_threshold = crate::findings::RISK_THRESHOLD_APPROVAL;
    let current_block_threshold = crate::findings::RISK_THRESHOLD_BLOCK;
    let expected: Vec<_> = samples.iter().map(|sample| sample.expected).collect();
    let current_actual: Vec<_> = samples
        .iter()
        .map(|sample| {
            classify_with_thresholds(
                sample.risk_score,
                current_approval_threshold,
                current_block_threshold,
            )
        })
        .collect();
    let current_metrics = compute_metrics(&expected, &current_actual);
    let mut best_score = threshold_objective(&current_metrics, samples, &current_actual);

    let mut best_approval = current_approval_threshold;
    let mut best_block = current_block_threshold;
    let mut best_metrics = current_metrics;

    for approval in (10..=50).step_by(2) {
        for block in (30..=90).step_by(2) {
            if block <= approval {
                continue;
            }

            let actual: Vec<_> = samples
                .iter()
                .map(|sample| classify_with_thresholds(sample.risk_score, approval, block))
                .collect();
            let metrics = compute_metrics(&expected, &actual);
            let score = threshold_objective(&metrics, samples, &actual);
            let acceptable_recall =
                current_metrics.recall == 0.0 || metrics.recall + 0.02 >= current_metrics.recall;

            if acceptable_recall && score > best_score {
                best_approval = approval;
                best_block = block;
                best_metrics = metrics;
                best_score = score;
            }
        }
    }

    ThresholdRecommendation {
        current_approval_threshold,
        current_block_threshold,
        recommended_approval_threshold: best_approval,
        recommended_block_threshold: best_block,
        current_metrics,
        recommended_metrics: best_metrics,
        rationale: format!(
            "Selected thresholds using a weighted objective that prefers low false-positive rate, preserves recall, and penalizes label jumps around benign and suspicious samples (score {:.3}).",
            best_score
        ),
    }
}

fn threshold_objective(
    metrics: &RegressionMetrics,
    samples: &[SampleEvaluation],
    actual: &[SampleLabel],
) -> f32 {
    let label_error_penalty = samples
        .iter()
        .zip(actual.iter())
        .map(|(sample, predicted)| label_distance(sample.expected, *predicted) as f32)
        .sum::<f32>();

    (metrics.precision * 0.35) + (metrics.recall * 0.35) + (metrics.accuracy * 0.20)
        - (metrics.false_positive_rate * 0.55)
        - (label_error_penalty * 0.01)
}

fn label_distance(expected: SampleLabel, actual: SampleLabel) -> u32 {
    let rank = |label| match label {
        SampleLabel::Benign => 0_u32,
        SampleLabel::Suspicious => 1_u32,
        SampleLabel::Malicious => 2_u32,
    };
    rank(expected).abs_diff(rank(actual))
}

fn classify_with_thresholds(
    risk_score: u32,
    approval_threshold: u32,
    block_threshold: u32,
) -> SampleLabel {
    if risk_score >= block_threshold {
        SampleLabel::Malicious
    } else if risk_score >= approval_threshold {
        SampleLabel::Suspicious
    } else {
        SampleLabel::Benign
    }
}

fn evidence_key(kind: EvidenceKind) -> String {
    kind.to_string()
}

fn category_key(category: ThreatCategory) -> String {
    category.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    // The `Scanner`/`ScanOptions`/`ScanTargetMode` and `tempdir` imports are
    // only consumed by the unix-gated permission-denied test below. On
    // Windows the bracketed `#[cfg(unix)]` block compiles to nothing, so
    // unused-import would fire under `-D warnings`. Mirror the gate on the
    // imports themselves to keep the cross-platform build clean.
    #[cfg(unix)]
    use crate::{ScanOptions, ScanTargetMode, Scanner};
    #[cfg(unix)]
    use tempfile::tempdir;

    #[test]
    fn test_recommend_thresholds_can_reduce_false_positive_rate() {
        use crate::{RecommendedAction, Verdict};
        use std::path::PathBuf;
        let samples = vec![
            SampleEvaluation {
                id: "benign-doc".to_string(),
                expected: SampleLabel::Benign,
                actual: SampleLabel::Suspicious,
                verdict: Verdict::Suspicious,
                focus_category: None,
                attack_family: None,
                recommended_action: RecommendedAction::RequireApproval,
                risk_score: 22,
                finding_count: 1,
                primary_finding_count: 1,
                supporting_finding_count: 0,
                duplicates_removed: 0,
                path: PathBuf::from("benign-doc/SKILL.md"),
            },
            SampleEvaluation {
                id: "benign-safe".to_string(),
                expected: SampleLabel::Benign,
                actual: SampleLabel::Benign,
                verdict: Verdict::Benign,
                focus_category: None,
                attack_family: None,
                recommended_action: RecommendedAction::Log,
                risk_score: 10,
                finding_count: 0,
                primary_finding_count: 0,
                supporting_finding_count: 0,
                duplicates_removed: 0,
                path: PathBuf::from("benign-safe/SKILL.md"),
            },
            SampleEvaluation {
                id: "malicious".to_string(),
                expected: SampleLabel::Malicious,
                actual: SampleLabel::Malicious,
                verdict: Verdict::Malicious,
                focus_category: Some(ThreatCategory::RemoteExec),
                attack_family: Some("remote_exec".to_string()),
                recommended_action: RecommendedAction::Block,
                risk_score: 72,
                finding_count: 3,
                primary_finding_count: 2,
                supporting_finding_count: 1,
                duplicates_removed: 0,
                path: PathBuf::from("malicious/SKILL.md"),
            },
        ];

        let recommendation = recommend_thresholds(&samples);
        assert!(
            recommendation.recommended_metrics.false_positive_rate
                <= recommendation.current_metrics.false_positive_rate
        );
        assert!(!recommendation.rationale.is_empty());
    }

    #[test]
    fn test_calibrate_confidence_groups_by_evidence() {
        use crate::{EvidenceKind, Finding, ThreatCategory};
        let findings = vec![
            (
                SampleLabel::Malicious,
                Finding::builder("A", ThreatCategory::RemoteExec)
                    .evidence_kind(EvidenceKind::Behavior)
                    .reason("x")
                    .match_value("x")
                    .build(),
            ),
            (
                SampleLabel::Benign,
                Finding::builder("B", ThreatCategory::SocialManipulation)
                    .evidence_kind(EvidenceKind::Intent)
                    .reason("y")
                    .match_value("y")
                    .build(),
            ),
        ];

        let calibration = calibrate_confidence(&findings);
        assert_eq!(calibration.by_evidence_kind.len(), 2);
        assert!(calibration
            .by_evidence_kind
            .iter()
            .any(|bucket| bucket.key == "behavior" && bucket.true_positive == 1));
        assert!(calibration
            .by_signal_pair
            .iter()
            .any(|bucket| bucket.key == "behavior+remote_exec"));
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
                ..Default::default()
            })
            .unwrap();
            let error = evaluate_corpus(&scanner, &corpus_path).unwrap_err();

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

    /// Contract: `calibrate_confidence_value` returns NaN for an empty
    /// bucket. Pre-fix `findings.max(1)` coerced the empty case to 1 and
    /// returned `0.35` — a plausible-looking number that downstream
    /// consumers couldn't distinguish from a real low-precision bucket.
    /// NaN is the unambiguous "no data" sentinel.
    #[test]
    fn calibrate_confidence_value_returns_nan_for_empty_bucket() {
        let result = calibrate_confidence_value(0.0, 0);
        assert!(
            result.is_nan(),
            "empty bucket must produce NaN; got {result}",
        );
    }

    /// Contract: a non-empty bucket produces a finite confidence in
    /// `[0.1, 0.99]`. Positive-case regression guard so the NaN
    /// early-return doesn't accidentally widen.
    #[test]
    fn calibrate_confidence_value_finite_for_non_empty_bucket() {
        let result = calibrate_confidence_value(0.5, 10);
        assert!(result.is_finite(), "non-empty bucket must be finite");
        assert!((0.1..=0.99).contains(&result));
    }
}
