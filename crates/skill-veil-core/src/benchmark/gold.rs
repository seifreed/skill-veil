//! Curated gold corpus — ground truth, not VT noise.
//!
//! Every metric the project calibrates against (`evaluate_corpus`,
//! the regression baseline) is only as trustworthy as its labels.
//! VT labels are noisy; that noise is the floor of both precision and
//! recall. The gold corpus records, per sample, the noisy VT label,
//! the ≥2-of-3 LLM consensus label, and a human adjudication for the
//! cases where those disagree — so future changes are measured
//! against truth.
//!
//! It is strictly ADDITIVE: a separate manifest and a separate,
//! env-gated test. `evaluate_corpus` / the phase-1 regression
//! baseline and `tests/fixtures/regression_corpus.yaml` are
//! untouched, so the sacred baseline keeps passing.

use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::evaluation::evaluate_manifest;
use super::loader::load_yaml;
use super::types::{BenchmarkError, CorpusEvaluation, CorpusManifest, LabeledSample, SampleLabel};
use crate::ports::FileSystemProvider;
use crate::scanner::Scanner;
use crate::ThreatCategory;

fn default_schema_version() -> String {
    "1".to_string()
}

/// One curated sample with full label provenance. New fields are
/// `#[serde(default)]` so an older on-disk manifest still loads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldSample {
    pub id: String,
    pub path: PathBuf,
    /// The curated ground-truth label used for scoring. For a resolved
    /// dispute this equals the human adjudication.
    pub final_label: SampleLabel,
    /// Noisy upstream VT label, retained for provenance/audit.
    #[serde(default)]
    pub vt_label: Option<SampleLabel>,
    /// ≥2-of-3 LLM consensus label; `None` when no consensus formed.
    #[serde(default)]
    pub llm_consensus: Option<SampleLabel>,
    /// A human reviewer's adjudication of a disputed case.
    #[serde(default)]
    pub human_review: Option<SampleLabel>,
    /// VT and LLM consensus disagreed (or consensus was absent):
    /// requires `human_review` before the sample is admitted to
    /// scoring.
    #[serde(default)]
    pub disputed: bool,
    #[serde(default)]
    pub focus_category: Option<ThreatCategory>,
    #[serde(default)]
    pub attack_family: Option<String>,
}

impl GoldSample {
    /// A sample is admitted to scoring iff it is not disputed, or it
    /// is disputed but a human has reviewed it. Disputed-and-unreviewed
    /// samples are excluded so an unadjudicated VT/LLM disagreement can
    /// never pollute the curated truth.
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        !self.disputed || self.human_review.is_some()
    }

    /// Decide whether a sample is disputed from its provenance: VT and
    /// LLM consensus disagree, or consensus is absent while a VT label
    /// exists. Pure — the build/review tooling uses this so the
    /// dispute flag is derived, not hand-set.
    #[must_use]
    pub fn derive_disputed(&self) -> bool {
        match (self.vt_label, self.llm_consensus) {
            (Some(vt), Some(llm)) => vt != llm,
            (Some(_), None) => true,
            _ => false,
        }
    }
}

/// A curated gold-corpus manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoldCorpusManifest {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub samples: Vec<GoldSample>,
}

impl GoldCorpusManifest {
    /// The admitted samples mapped to the scoring [`CorpusManifest`],
    /// so the gold corpus is scored by the identical pipeline + metric
    /// definition as the regression corpus.
    #[must_use]
    pub fn to_corpus_manifest(&self) -> CorpusManifest {
        CorpusManifest {
            samples: self
                .samples
                .iter()
                .filter(|s| s.is_admitted())
                .map(|s| LabeledSample {
                    id: s.id.clone(),
                    path: s.path.clone(),
                    label: s.final_label,
                    focus_category: s.focus_category,
                    attack_family: s.attack_family.clone(),
                })
                .collect(),
        }
    }
}

/// Evaluate a gold-corpus manifest at `manifest_path`. Sample paths
/// are relative to the manifest's directory, identical to
/// [`super::evaluate_corpus`]. Disputed-and-unreviewed samples are
/// excluded before scoring.
pub fn evaluate_gold_corpus<F: FileSystemProvider>(
    fs: &F,
    scanner: &Scanner,
    manifest_path: &Path,
) -> Result<CorpusEvaluation, BenchmarkError> {
    let gold: GoldCorpusManifest = load_yaml(fs, manifest_path)?;
    let root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    evaluate_manifest(fs, scanner, gold.to_corpus_manifest(), root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str, disputed: bool, human: Option<SampleLabel>) -> GoldSample {
        GoldSample {
            id: id.to_string(),
            path: PathBuf::from(format!("{id}.md")),
            final_label: SampleLabel::Malicious,
            vt_label: Some(SampleLabel::Benign),
            llm_consensus: Some(SampleLabel::Malicious),
            human_review: human,
            disputed,
            focus_category: None,
            attack_family: None,
        }
    }

    /// Contract (negative): a disputed sample with no human review is
    /// excluded from the scoring manifest — an unadjudicated VT/LLM
    /// disagreement must never reach the curated truth.
    #[test]
    fn disputed_sample_excluded_until_reviewed() {
        let m = GoldCorpusManifest {
            schema_version: "1".into(),
            samples: vec![sample("a", true, None)],
        };
        assert!(m.to_corpus_manifest().samples.is_empty());
    }

    /// Contract: a disputed sample becomes admitted once a human has
    /// reviewed it, scored by its `final_label`.
    #[test]
    fn reviewed_dispute_is_admitted() {
        let m = GoldCorpusManifest {
            schema_version: "1".into(),
            samples: vec![sample("a", true, Some(SampleLabel::Malicious))],
        };
        let cm = m.to_corpus_manifest();
        assert_eq!(cm.samples.len(), 1);
        assert_eq!(cm.samples[0].label, SampleLabel::Malicious);
    }

    /// Contract: an undisputed sample is admitted without review.
    #[test]
    fn undisputed_sample_is_admitted() {
        let mut s = sample("a", false, None);
        s.vt_label = Some(SampleLabel::Malicious);
        let m = GoldCorpusManifest {
            schema_version: "1".into(),
            samples: vec![s],
        };
        assert_eq!(m.to_corpus_manifest().samples.len(), 1);
    }

    /// Contract: dispute is DERIVED from provenance — VT vs LLM
    /// disagreement, or consensus absent with a VT label present —
    /// not hand-set. Both directions.
    #[test]
    fn derive_disputed_from_provenance() {
        let mut s = sample("a", false, None);
        s.vt_label = Some(SampleLabel::Benign);
        s.llm_consensus = Some(SampleLabel::Malicious);
        assert!(s.derive_disputed(), "VT≠LLM is a dispute");

        s.llm_consensus = Some(SampleLabel::Benign);
        assert!(!s.derive_disputed(), "VT==LLM agreement is not a dispute");

        s.llm_consensus = None;
        assert!(s.derive_disputed(), "VT present, no consensus is a dispute");

        s.vt_label = None;
        assert!(
            !s.derive_disputed(),
            "no VT label and no consensus is not a dispute"
        );
    }

    /// Contract: new provenance fields are additive — a minimal
    /// manifest (only id/path/final_label) still deserialises.
    #[test]
    fn minimal_manifest_deserialises_additively() {
        let yaml = "samples:\n  - id: a\n    path: a.md\n    final_label: benign\n";
        let m: GoldCorpusManifest = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(m.samples.len(), 1);
        assert_eq!(m.samples[0].final_label, SampleLabel::Benign);
        assert!(!m.samples[0].disputed);
        assert_eq!(m.schema_version, "1");
    }
}
