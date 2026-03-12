use skill_veil_core::{BenchmarkHistory, CorpusEvaluation, Verdict};

pub fn render_benchmark_dashboard(
    history: &BenchmarkHistory,
    evaluation: &CorpusEvaluation,
) -> String {
    let mut output = String::new();
    let benign = evaluation.samples.iter().filter(|sample| sample.verdict == Verdict::Benign).count();
    let suspicious = evaluation.samples.iter().filter(|sample| sample.verdict == Verdict::Suspicious).count();
    let malicious = evaluation.samples.iter().filter(|sample| sample.verdict == Verdict::Malicious).count();
    let primary_findings: usize = evaluation.samples.iter().map(|sample| sample.primary_finding_count).sum();
    let supporting_findings: usize = evaluation.samples.iter().map(|sample| sample.supporting_finding_count).sum();
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
        ("Coverage by Focus Category", &evaluation.coverage.by_focus_category),
        ("Coverage by Attack Family", &evaluation.coverage.by_attack_family),
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
        output.push_str("| Family | Samples | Precision | Recall | FPR | Exact Label | Approval | Block |\n");
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
                family.threshold_recommendation.recommended_approval_threshold,
                family.threshold_recommendation.recommended_block_threshold,
            ));
        }
        output.push('\n');
        let mut weakest_families = evaluation.family_metrics.clone();
        weakest_families.sort_by(|left, right| {
            left.metrics
                .exact_label_accuracy
                .partial_cmp(&right.metrics.exact_label_accuracy)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    right.metrics
                        .false_positive_rate
                        .partial_cmp(&left.metrics.false_positive_rate)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });
        output.push_str("### Families Needing Tuning\n\n");
        for family in weakest_families.iter().take(4) {
            output.push_str(&format!(
                "- `{}`: exact_label={:.2} fpr={:.2} thresholds={}→{}\n",
                family.family,
                family.metrics.exact_label_accuracy,
                family.metrics.false_positive_rate,
                family.threshold_recommendation.recommended_approval_threshold,
                family.threshold_recommendation.recommended_block_threshold,
            ));
        }
        output.push('\n');
    }
    output.push_str("### Threshold Recommendation\n\n");
    output.push_str(&format!(
        "- Approval: {} -> {}\n- Block: {} -> {}\n- Rationale: {}\n\n",
        evaluation.threshold_recommendation.current_approval_threshold,
        evaluation.threshold_recommendation.recommended_approval_threshold,
        evaluation.threshold_recommendation.current_block_threshold,
        evaluation.threshold_recommendation.recommended_block_threshold,
        evaluation.threshold_recommendation.rationale
    ));
    if !evaluation.confidence_calibration.by_signal_pair.is_empty() {
        output.push_str("### Strongest Signal Pairs\n\n");
        for bucket in evaluation.confidence_calibration.by_signal_pair.iter().take(8) {
            output.push_str(&format!(
                "- `{}`: findings={} observed_precision={:.2} recommended_confidence={:.2}\n",
                bucket.key, bucket.findings, bucket.observed_precision, bucket.recommended_confidence
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
        evaluation.threshold_recommendation.current_approval_threshold,
        evaluation.threshold_recommendation.recommended_approval_threshold,
        evaluation.threshold_recommendation.current_block_threshold,
        evaluation.threshold_recommendation.recommended_block_threshold,
        evaluation.threshold_recommendation.rationale
    ));
    if !evaluation.family_metrics.is_empty() {
        output.push_str("## Family Recommendations\n\n");
        output.push_str("| Family | Samples | Precision | Recall | FPR | Exact Label | Approval | Block |\n");
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
                family.threshold_recommendation.recommended_approval_threshold,
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
    let benign = evaluation.samples.iter().filter(|sample| sample.verdict == Verdict::Benign).count();
    let suspicious = evaluation.samples.iter().filter(|sample| sample.verdict == Verdict::Suspicious).count();
    let malicious = evaluation.samples.iter().filter(|sample| sample.verdict == Verdict::Malicious).count();
    let primary_findings: usize = evaluation.samples.iter().map(|sample| sample.primary_finding_count).sum();
    let supporting_findings: usize = evaluation.samples.iter().map(|sample| sample.supporting_finding_count).sum();
    output.push_str("--- Benchmark ---\n");
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
    for (title, buckets) in [
        ("Coverage by label", &evaluation.coverage.by_label),
        ("Coverage by focus category", &evaluation.coverage.by_focus_category),
        ("Coverage by attack family", &evaluation.coverage.by_attack_family),
    ] {
        if !buckets.is_empty() {
            output.push_str(&format!("{title}:\n"));
            for bucket in buckets {
                output.push_str(&format!("  - {}={}\n", bucket.key, bucket.samples));
            }
        }
    }
    if !evaluation.family_metrics.is_empty() {
        output.push_str("Family metrics:\n");
        for family in &evaluation.family_metrics {
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
        let mut weakest_families = evaluation.family_metrics.clone();
        weakest_families.sort_by(|left, right| {
            left.metrics
                .exact_label_accuracy
                .partial_cmp(&right.metrics.exact_label_accuracy)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    right.metrics
                        .false_positive_rate
                        .partial_cmp(&left.metrics.false_positive_rate)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
        });
        output.push_str("Families needing tuning:\n");
        for family in weakest_families.iter().take(4) {
            output.push_str(&format!(
                "  - {}: exact_label={:.2} fpr={:.2}\n",
                family.family,
                family.metrics.exact_label_accuracy,
                family.metrics.false_positive_rate
            ));
        }
    }
    output.push_str(&format!(
        "Deduplication: original={} unique={} removed={}\n",
        evaluation.deduplication.original_findings,
        evaluation.deduplication.unique_findings,
        evaluation.deduplication.duplicates_removed
    ));
    output
}
