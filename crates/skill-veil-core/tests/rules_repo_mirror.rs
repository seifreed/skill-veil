//! Drift check: the embedded rule baseline MUST stay a byte-identical
//! mirror of the canonical `skill-veil-rules` repo.
//!
//! The embedded copies are `include_str!`'d into the binary so `scan`
//! works before `init`; the canonical source is the separate
//! `skill-veil-rules` repo. This test fails if the two drift.
//!
//! Env-gated like `nova_real_corpus` / `gold_corpus`: resolve the repo
//! via `SKILL_VEIL_RULES_REPO`, else the conventional sibling
//! checkout; if neither is present (the hermetic CI default) it skips
//! silently so a clone is never a hard CI dependency.

use std::path::PathBuf;

fn rules_repo() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SKILL_VEIL_RULES_REPO") {
        let p = PathBuf::from(p);
        return p.is_dir().then_some(p);
    }
    // CARGO_MANIFEST_DIR = .../skill-veil/crates/skill-veil-core
    let sibling = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../skill-veil-rules");
    sibling.is_dir().then_some(sibling)
}

#[test]
fn embedded_baseline_mirrors_canonical_rules_repo() {
    let Some(repo) = rules_repo() else {
        eprintln!(
            "skipping embedded_baseline_mirrors_canonical_rules_repo: set \
             SKILL_VEIL_RULES_REPO or clone skill-veil-rules as a sibling \
             to enforce the embedded↔canonical drift check"
        );
        return;
    };
    let core = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // (embedded path, canonical path within the rules repo)
    let pairs = [
        ("resources/official/core.yaml", "official/core.yaml"),
        (
            "resources/official/behavioral.yaml",
            "official/behavioral.yaml",
        ),
        ("src/taint_rules.yaml", "taint/taint.yaml"),
    ];
    for (embedded_rel, canonical_rel) in pairs {
        let embedded = std::fs::read(core.join(embedded_rel))
            .unwrap_or_else(|e| panic!("read embedded {embedded_rel}: {e}"));
        let canonical = std::fs::read(repo.join(canonical_rel))
            .unwrap_or_else(|e| panic!("read canonical {canonical_rel}: {e}"));
        assert!(
            embedded == canonical,
            "DRIFT: embedded `{embedded_rel}` differs from canonical \
             `skill-veil-rules/{canonical_rel}`. The rules repo is the \
             source of truth — resync the embedded mirror (and re-cut a \
             signed rules release) rather than editing the embedded copy \
             directly."
        );
    }
}
