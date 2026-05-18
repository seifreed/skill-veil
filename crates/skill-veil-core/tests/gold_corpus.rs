//! Env-gated gold-corpus truth baseline.
//!
//! Set `SKILL_VEIL_GOLD_CORPUS` to a curated gold manifest path to
//! enforce metrics against ground truth. Unset — the CI default with
//! no heavy curated dataset checked out — skips silently, mirroring
//! the `nova_real_corpus` / `NOVA_RULES_DIR` precedent. The phase-1
//! regression baseline (`regression_corpus.rs`) is intentionally NOT
//! touched: the gold corpus is strictly additive.

use skill_veil_core::{evaluate_gold_corpus, Scanner, StdFileSystemProvider};
use std::path::PathBuf;

#[test]
fn gold_corpus_meets_truth_baseline() {
    let Ok(manifest) = std::env::var("SKILL_VEIL_GOLD_CORPUS") else {
        eprintln!(
            "skipping gold_corpus_meets_truth_baseline: set SKILL_VEIL_GOLD_CORPUS \
             to a curated gold manifest path to enforce the truth baseline"
        );
        return;
    };
    let scanner = Scanner::new().unwrap();
    let fs = StdFileSystemProvider::new();
    let evaluation =
        evaluate_gold_corpus(&fs, &scanner, &PathBuf::from(manifest)).expect("gold corpus");
    let m = evaluation.metrics;
    assert!(
        m.precision >= 0.66,
        "gold precision too low: {}",
        m.precision
    );
    assert!(m.recall >= 0.6, "gold recall too low: {}", m.recall);
    assert!(
        m.false_positive_rate <= 0.15,
        "gold FPR too high: {}",
        m.false_positive_rate
    );
}
