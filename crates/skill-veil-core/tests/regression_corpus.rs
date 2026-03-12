use skill_veil_core::{benchmark::evaluate_corpus, Scanner};
use std::path::Path;

#[test]
fn labeled_corpus_meets_phase1_baseline() {
    let scanner = Scanner::new().unwrap();
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("regression_corpus.yaml");

    let evaluation = evaluate_corpus(&scanner, &manifest_path).unwrap();
    let metrics = evaluation.metrics;

    assert!(
        evaluation.samples.len() >= 12,
        "regression corpus unexpectedly shrank: {}",
        evaluation.samples.len()
    );
    let benign_count = evaluation
        .samples
        .iter()
        .filter(|sample| sample.expected == skill_veil_core::SampleLabel::Benign)
        .count();
    let suspicious_count = evaluation
        .samples
        .iter()
        .filter(|sample| sample.expected == skill_veil_core::SampleLabel::Suspicious)
        .count();
    let malicious_count = evaluation
        .samples
        .iter()
        .filter(|sample| sample.expected == skill_veil_core::SampleLabel::Malicious)
        .count();
    assert!(
        benign_count >= 7,
        "benign coverage too small: {benign_count}"
    );
    assert!(
        suspicious_count >= 3,
        "suspicious coverage too small: {suspicious_count}"
    );
    assert!(
        malicious_count >= 2,
        "malicious coverage too small: {malicious_count}"
    );
    assert!(
        metrics.precision >= 0.66,
        "precision too low: {}",
        metrics.precision
    );
    assert!(metrics.recall >= 0.6, "recall too low: {}", metrics.recall);
    assert!(
        metrics.false_positive_rate <= 0.15,
        "false positive rate too high: {}",
        metrics.false_positive_rate
    );
    assert!(
        evaluation
            .threshold_recommendation
            .recommended_metrics
            .false_positive_rate
            <= evaluation
                .threshold_recommendation
                .current_metrics
                .false_positive_rate,
        "threshold tuning regressed false positives"
    );
}
