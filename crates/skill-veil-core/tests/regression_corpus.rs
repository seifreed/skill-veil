use skill_veil_core::{benchmark::evaluate_corpus, StdFileSystemProvider};
use std::path::Path;

mod common;
use common::corpus_scanner;

#[test]
fn labeled_corpus_meets_phase1_baseline() {
    let scanner = corpus_scanner();
    let fs = StdFileSystemProvider::new();
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("regression_corpus.yaml");

    let evaluation = evaluate_corpus(&fs, &scanner, &manifest_path).unwrap();
    let metrics = evaluation.metrics;

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
    // Validate the corpus shape against per-class minimums in a single
    // assertion so a future relabeling cannot satisfy a generic
    // `samples.len() >= N` while skewing the distribution. Round-5
    // audit Bug 3.17 — the prior `samples.len() >= 12` could pass
    // with all samples labeled Benign.
    assert!(
        evaluation.samples.len() >= 12
            && benign_count >= 7
            && suspicious_count >= 3
            && malicious_count >= 2,
        "regression corpus shape regressed (must satisfy ≥12 samples and \
         benign≥7 / suspicious≥3 / malicious≥2): \
         total={}, benign={benign_count}, suspicious={suspicious_count}, \
         malicious={malicious_count}",
        evaluation.samples.len()
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
