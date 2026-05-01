use skill_veil_core::{BenchmarkHistory, CorpusEvaluation, Verdict};

/// Top-N families with the weakest exact-label accuracy shown under
/// "Families needing tuning". The same cap is used by both the markdown
/// dashboard and the plain-text benchmark report so they stay aligned.
const MAX_DISPLAY_WEAKEST_FAMILIES: usize = 4;

/// Top-N signal-pair calibration buckets surfaced under "Strongest
/// Signal Pairs" in the dashboard.
const MAX_DISPLAY_SIGNAL_PAIRS: usize = 8;

pub fn render_benchmark_dashboard(
    history: &BenchmarkHistory,
    evaluation: &CorpusEvaluation,
) -> String {
    let mut output = String::new();
    let benign = evaluation
        .samples
        .iter()
        .filter(|sample| sample.verdict == Verdict::Benign)
        .count();
    let suspicious = evaluation
        .samples
        .iter()
        .filter(|sample| sample.verdict == Verdict::Suspicious)
        .count();
    let malicious = evaluation
        .samples
        .iter()
        .filter(|sample| sample.verdict == Verdict::Malicious)
        .count();
    let primary_findings: usize = evaluation
        .samples
        .iter()
        .map(|sample| sample.primary_finding_count)
        .sum();
    let supporting_findings: usize = evaluation
        .samples
        .iter()
        .map(|sample| sample.supporting_finding_count)
        .sum();
    output.push_str("# Benchmark Dashboard\n\n");
    output.push_str("## Current Corpus\n\n");
    output.push_str(&format!(
        "- Samples: {}\n- Precision: {:.2}\n- Recall: {:.2}\n- False positive rate: {:.2}\n- Accuracy: {:.2}\n- Exact label accuracy: {:.2}\n- Deduplicated findings removed: {}\n\n",
        evaluation.coverage.total_samples,
        evaluation.metrics.precision,
        evaluation.metrics.recall,
        evaluation.metrics.false_positive_rate,
        evaluation.metrics.accuracy,
        evaluation.metrics.exact_label_accuracy,
        evaluation.deduplication.duplicates_removed
    ));
    output.push_str(&format!(
        "- Verdicts: benign={} suspicious={} malicious={}\n- Findings by scope: primary={} supporting={}\n\n",
        benign, suspicious, malicious, primary_findings, supporting_findings
    ));
    for (title, buckets) in [
        ("Coverage by Label", &evaluation.coverage.by_label),
        (
            "Coverage by Focus Category",
            &evaluation.coverage.by_focus_category,
        ),
        (
            "Coverage by Attack Family",
            &evaluation.coverage.by_attack_family,
        ),
    ] {
        if !buckets.is_empty() {
            output.push_str(&format!("### {title}\n\n"));
            for bucket in buckets {
                output.push_str(&format!("- `{}`: {}\n", bucket.key, bucket.samples));
            }
            output.push('\n');
        }
    }
    if !evaluation.family_metrics.is_empty() {
        output.push_str("### Family Metrics\n\n");
        output.push_str(
            "| Family | Samples | Precision | Recall | FPR | Exact Label | Approval | Block |\n",
        );
        output.push_str("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
        for family in &evaluation.family_metrics {
            output.push_str(&format!(
                "| {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {} | {} |\n",
                family.family,
                family.sample_count,
                family.metrics.precision,
                family.metrics.recall,
                family.metrics.false_positive_rate,
                family.metrics.exact_label_accuracy,
                family
                    .threshold_recommendation
                    .recommended_approval_threshold,
                family.threshold_recommendation.recommended_block_threshold,
            ));
        }
        output.push('\n');
        // Skip families with `sample_count == 0` before sorting / rendering.
        // Without this guard, an empty family's precision/recall divisions
        // produce NaN, which downstream sorters mask with `Ordering::Equal`
        // but the markdown render emits literal `"NaN"` strings — breaking
        // CI parsers that consume the dashboard. Round-5 audit Bug 2.4.
        let mut weakest_families: Vec<_> = evaluation
            .family_metrics
            .iter()
            .filter(|f| f.sample_count > 0)
            .cloned()
            .collect();
        weakest_families.sort_by(|left, right| {
            left.metrics
                .exact_label_accuracy
                .partial_cmp(&right.metrics.exact_label_accuracy)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    right
                        .metrics
                        .false_positive_rate
                        .partial_cmp(&left.metrics.false_positive_rate)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });
        output.push_str("### Families Needing Tuning\n\n");
        for family in weakest_families.iter().take(MAX_DISPLAY_WEAKEST_FAMILIES) {
            output.push_str(&format!(
                "- `{}`: exact_label={:.2} fpr={:.2} thresholds={}→{}\n",
                family.family,
                family.metrics.exact_label_accuracy,
                family.metrics.false_positive_rate,
                family
                    .threshold_recommendation
                    .recommended_approval_threshold,
                family.threshold_recommendation.recommended_block_threshold,
            ));
        }
        output.push('\n');
    }
    output.push_str("### Threshold Recommendation\n\n");
    output.push_str(&format!(
        "- Approval: {} -> {}\n- Block: {} -> {}\n- Rationale: {}\n\n",
        evaluation
            .threshold_recommendation
            .current_approval_threshold,
        evaluation
            .threshold_recommendation
            .recommended_approval_threshold,
        evaluation.threshold_recommendation.current_block_threshold,
        evaluation
            .threshold_recommendation
            .recommended_block_threshold,
        evaluation.threshold_recommendation.rationale
    ));
    if !evaluation.confidence_calibration.by_signal_pair.is_empty() {
        output.push_str("### Strongest Signal Pairs\n\n");
        for bucket in evaluation
            .confidence_calibration
            .by_signal_pair
            .iter()
            .take(MAX_DISPLAY_SIGNAL_PAIRS)
        {
            output.push_str(&format!(
                "- `{}`: findings={} observed_precision={:.2} recommended_confidence={:.2}\n",
                bucket.key,
                bucket.findings,
                bucket.observed_precision,
                bucket.recommended_confidence
            ));
        }
        output.push('\n');
    }
    output.push_str("## Release History\n\n");
    if history.releases.is_empty() {
        output.push_str("_No release history yet._\n");
        return output;
    }
    output.push_str("| Release | Generated | Precision | Recall | FPR | Accuracy | Samples |\n");
    output.push_str("| --- | --- | ---: | ---: | ---: | ---: | ---: |\n");
    for entry in &history.releases {
        output.push_str(&format!(
            "| {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {} |\n",
            entry.release_id,
            entry.generated_at.format("%Y-%m-%d"),
            entry.metrics.precision,
            entry.metrics.recall,
            entry.metrics.false_positive_rate,
            entry.metrics.accuracy,
            entry.coverage.total_samples
        ));
    }
    if history.releases.len() >= 2 {
        let previous = &history.releases[history.releases.len() - 2];
        let current = &history.releases[history.releases.len() - 1];
        output.push_str("\n### Latest Delta\n\n");
        output.push_str(&format!(
            "- Precision delta: {:+.2}\n- Recall delta: {:+.2}\n- FPR delta: {:+.2}\n- Accuracy delta: {:+.2}\n",
            current.metrics.precision - previous.metrics.precision,
            current.metrics.recall - previous.metrics.recall,
            current.metrics.false_positive_rate - previous.metrics.false_positive_rate,
            current.metrics.accuracy - previous.metrics.accuracy
        ));
    }
    output
}

pub fn render_benchmark_tuning_report(evaluation: &CorpusEvaluation) -> String {
    let mut output = String::new();
    output.push_str("# Benchmark Tuning Report\n\n");
    output.push_str("## Global Recommendation\n\n");
    output.push_str(&format!(
        "- Approval threshold: {} -> {}\n- Block threshold: {} -> {}\n- Rationale: {}\n\n",
        evaluation
            .threshold_recommendation
            .current_approval_threshold,
        evaluation
            .threshold_recommendation
            .recommended_approval_threshold,
        evaluation.threshold_recommendation.current_block_threshold,
        evaluation
            .threshold_recommendation
            .recommended_block_threshold,
        evaluation.threshold_recommendation.rationale
    ));
    if !evaluation.family_metrics.is_empty() {
        output.push_str("## Family Recommendations\n\n");
        output.push_str(
            "| Family | Samples | Precision | Recall | FPR | Exact Label | Approval | Block |\n",
        );
        output.push_str("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
        for family in &evaluation.family_metrics {
            output.push_str(&format!(
                "| {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {} | {} |\n",
                family.family,
                family.sample_count,
                family.metrics.precision,
                family.metrics.recall,
                family.metrics.false_positive_rate,
                family.metrics.exact_label_accuracy,
                family
                    .threshold_recommendation
                    .recommended_approval_threshold,
                family.threshold_recommendation.recommended_block_threshold,
            ));
        }
        output.push('\n');
        for family in &evaluation.family_metrics {
            output.push_str(&format!("### {}\n\n", family.family));
            output.push_str(&format!(
                "- Samples: {}\n- Precision: {:.2}\n- Recall: {:.2}\n- False positive rate: {:.2}\n- Exact label accuracy: {:.2}\n- Recommended thresholds: approval {} block {}\n- Rationale: {}\n\n",
                family.sample_count,
                family.metrics.precision,
                family.metrics.recall,
                family.metrics.false_positive_rate,
                family.metrics.exact_label_accuracy,
                family.threshold_recommendation.recommended_approval_threshold,
                family.threshold_recommendation.recommended_block_threshold,
                family.threshold_recommendation.rationale
            ));
        }
    }
    output
}

pub fn format_benchmark_text(evaluation: &CorpusEvaluation) -> String {
    let mut output = String::new();
    output.push_str("--- Benchmark ---\n");
    append_overview_section(&mut output, evaluation);
    append_coverage_buckets(&mut output, evaluation);
    append_family_metrics(&mut output, evaluation);
    append_dedup_line(&mut output, evaluation);
    output
}

fn append_overview_section(output: &mut String, evaluation: &CorpusEvaluation) {
    let benign = count_samples(evaluation, Verdict::Benign);
    let suspicious = count_samples(evaluation, Verdict::Suspicious);
    let malicious = count_samples(evaluation, Verdict::Malicious);
    let primary_findings: usize = evaluation
        .samples
        .iter()
        .map(|sample| sample.primary_finding_count)
        .sum();
    let supporting_findings: usize = evaluation
        .samples
        .iter()
        .map(|sample| sample.supporting_finding_count)
        .sum();
    output.push_str(&format!(
        "Precision: {:.2}\nRecall: {:.2}\nFalse positive rate: {:.2}\nAccuracy: {:.2}\nExact label accuracy: {:.2}\nVerdicts: benign={} suspicious={} malicious={}\nScope findings: primary={} supporting={}\nTP: {} FP: {} TN: {} FN: {}\n",
        evaluation.metrics.precision,
        evaluation.metrics.recall,
        evaluation.metrics.false_positive_rate,
        evaluation.metrics.accuracy,
        evaluation.metrics.exact_label_accuracy,
        benign,
        suspicious,
        malicious,
        primary_findings,
        supporting_findings,
        evaluation.metrics.true_positive,
        evaluation.metrics.false_positive,
        evaluation.metrics.true_negative,
        evaluation.metrics.false_negative
    ));
    output.push_str(&format!("Samples: {}\n", evaluation.coverage.total_samples));
}

fn count_samples(evaluation: &CorpusEvaluation, verdict: Verdict) -> usize {
    evaluation
        .samples
        .iter()
        .filter(|sample| sample.verdict == verdict)
        .count()
}

fn append_coverage_buckets(output: &mut String, evaluation: &CorpusEvaluation) {
    for (title, buckets) in [
        ("Coverage by label", &evaluation.coverage.by_label),
        (
            "Coverage by focus category",
            &evaluation.coverage.by_focus_category,
        ),
        (
            "Coverage by attack family",
            &evaluation.coverage.by_attack_family,
        ),
    ] {
        if buckets.is_empty() {
            continue;
        }
        output.push_str(&format!("{title}:\n"));
        for bucket in buckets {
            output.push_str(&format!("  - {}={}\n", bucket.key, bucket.samples));
        }
    }
}

fn append_family_metrics(output: &mut String, evaluation: &CorpusEvaluation) {
    // Skip families with `sample_count == 0` before rendering. Without this
    // guard, an empty family's precision/recall divisions produce NaN, which
    // the `partial_cmp().unwrap_or(Equal)` sort hides from the developer but
    // surfaces verbatim as the literal string `"NaN"` in the rendered text
    // report — breaking CI parsers that consume the benchmark output. The
    // markdown dashboard already filters this case (Round-5 audit Bug 2.4);
    // mirror the same guard here so the two output paths stay aligned.
    let populated_families: Vec<_> = evaluation
        .family_metrics
        .iter()
        .filter(|f| f.sample_count > 0)
        .cloned()
        .collect();
    if populated_families.is_empty() {
        return;
    }
    output.push_str("Family metrics:\n");
    for family in &populated_families {
        output.push_str(&format!(
            "  - {}: samples={} precision={:.2} recall={:.2} fpr={:.2} exact_label={:.2} thresholds={}→{}\n",
            family.family,
            family.sample_count,
            family.metrics.precision,
            family.metrics.recall,
            family.metrics.false_positive_rate,
            family.metrics.exact_label_accuracy,
            family.threshold_recommendation.recommended_approval_threshold,
            family.threshold_recommendation.recommended_block_threshold,
        ));
    }
    let mut weakest_families = populated_families;
    weakest_families.sort_by(|left, right| {
        left.metrics
            .exact_label_accuracy
            .partial_cmp(&right.metrics.exact_label_accuracy)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                right
                    .metrics
                    .false_positive_rate
                    .partial_cmp(&left.metrics.false_positive_rate)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
    output.push_str("Families needing tuning:\n");
    for family in weakest_families.iter().take(MAX_DISPLAY_WEAKEST_FAMILIES) {
        output.push_str(&format!(
            "  - {}: exact_label={:.2} fpr={:.2}\n",
            family.family, family.metrics.exact_label_accuracy, family.metrics.false_positive_rate
        ));
    }
}

fn append_dedup_line(output: &mut String, evaluation: &CorpusEvaluation) {
    output.push_str(&format!(
        "Deduplication: original={} unique={} removed={}\n",
        evaluation.deduplication.original_findings,
        evaluation.deduplication.unique_findings,
        evaluation.deduplication.duplicates_removed
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_veil_core::{
        AttackFamilyMetrics, CalibrationSummary, CorpusCoverage, DeduplicationMetrics,
        RegressionMetrics, ThresholdRecommendation,
    };

    fn empty_metrics() -> RegressionMetrics {
        // sample_count == 0 produces these NaN values upstream — pin the
        // shape so the test reproduces the bug exactly.
        RegressionMetrics {
            precision: f32::NAN,
            recall: f32::NAN,
            false_positive_rate: f32::NAN,
            accuracy: f32::NAN,
            exact_label_accuracy: f32::NAN,
            true_positive: 0,
            false_positive: 0,
            true_negative: 0,
            false_negative: 0,
        }
    }

    fn finite_metrics() -> RegressionMetrics {
        RegressionMetrics {
            precision: 0.85,
            recall: 0.75,
            false_positive_rate: 0.10,
            accuracy: 0.80,
            exact_label_accuracy: 0.78,
            true_positive: 8,
            false_positive: 1,
            true_negative: 2,
            false_negative: 2,
        }
    }

    fn threshold_recommendation_default() -> ThresholdRecommendation {
        ThresholdRecommendation {
            current_approval_threshold: 30,
            current_block_threshold: 70,
            recommended_approval_threshold: 30,
            recommended_block_threshold: 70,
            current_metrics: finite_metrics(),
            recommended_metrics: finite_metrics(),
            rationale: String::new(),
        }
    }

    fn family(name: &str, sample_count: u32, metrics: RegressionMetrics) -> AttackFamilyMetrics {
        AttackFamilyMetrics {
            family: name.into(),
            sample_count,
            metrics,
            threshold_recommendation: threshold_recommendation_default(),
        }
    }

    fn corpus_with_families(family_metrics: Vec<AttackFamilyMetrics>) -> CorpusEvaluation {
        CorpusEvaluation {
            metrics: finite_metrics(),
            coverage: CorpusCoverage::default(),
            deduplication: DeduplicationMetrics::default(),
            confidence_calibration: CalibrationSummary::default(),
            threshold_recommendation: threshold_recommendation_default(),
            family_metrics,
            samples: Vec::new(),
        }
    }

    /// # Contract
    ///
    /// `append_family_metrics` MUST drop families whose `sample_count == 0`
    /// before rendering. Pre-fix the markdown dashboard already filtered
    /// these (Round-5 audit Bug 2.4) but the plain-text report did not, so
    /// CI parsers consuming the text format would choke on literal "NaN"
    /// strings emitted from precision/recall divisions on zero samples.
    /// The two output paths must stay aligned because `cargo run -- benchmark`
    /// can render either format depending on the `--format` flag.
    #[test]
    fn append_family_metrics_omits_empty_families_to_avoid_nan_in_text_report() {
        let corpus = corpus_with_families(vec![
            family("ghost", 0, empty_metrics()),
            family("real", 5, finite_metrics()),
        ]);

        let mut output = String::new();
        append_family_metrics(&mut output, &corpus);

        assert!(
            !output.contains("NaN"),
            "text report must not emit literal NaN; got:\n{output}",
        );
        assert!(
            !output.contains("ghost"),
            "empty families must be dropped from the rendered list; got:\n{output}",
        );
        assert!(
            output.contains("real"),
            "populated families must still be rendered; got:\n{output}",
        );
    }

    /// # Contract
    ///
    /// When EVERY family is empty, the function MUST emit nothing — the
    /// "Family metrics:" header is itself meaningless without rows.
    /// Pre-fix the function emitted the header followed by NaN rows,
    /// pretending the corpus had family data when it really had none.
    #[test]
    fn append_family_metrics_emits_nothing_when_all_families_are_empty() {
        let corpus = corpus_with_families(vec![
            family("ghost1", 0, empty_metrics()),
            family("ghost2", 0, empty_metrics()),
        ]);

        let mut output = String::new();
        append_family_metrics(&mut output, &corpus);

        assert!(output.is_empty(), "no rows means no header; got:\n{output}",);
    }
}
