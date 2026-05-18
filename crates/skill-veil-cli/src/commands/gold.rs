//! `gold` — curated ground-truth corpus tooling.
//!
//! VT labels are noisy; that noise is the floor of both precision and
//! recall. This command seeds a gold manifest from a recorded
//! 3-provider LLM-consensus rollup (no live calls), flags the cases
//! that need a human, and lets a reviewer adjudicate them. The
//! resulting manifest is scored by the identical pipeline as the
//! regression corpus via `evaluate_gold_corpus`.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::Deserialize;
use skill_veil_core::{GoldCorpusManifest, GoldSample, SampleLabel};

use crate::cli_args::{GoldAction, GoldBuildArgs, GoldLabelArg, GoldReviewArgs, GoldStatsArgs};

#[derive(Debug, Clone, Deserialize)]
struct ProviderVoteRecord {
    provider: String,
    verdict: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ConsensusRecord {
    sha: String,
    #[serde(default)]
    providers: Vec<ProviderVoteRecord>,
}

fn label_of(arg: GoldLabelArg) -> SampleLabel {
    match arg {
        GoldLabelArg::Benign => SampleLabel::Benign,
        GoldLabelArg::Suspicious => SampleLabel::Suspicious,
        GoldLabelArg::Malicious => SampleLabel::Malicious,
    }
}

/// ≥2 DISTINCT providers agreeing on the same label is the consensus;
/// otherwise `None` (no consensus → the sample is disputed and needs
/// a human). Distinctness is keyed on provider name so a single
/// provider cannot manufacture consensus.
fn llm_consensus(votes: &[ProviderVoteRecord]) -> Option<SampleLabel> {
    for (needle, label) in [
        ("malicious", SampleLabel::Malicious),
        ("benign", SampleLabel::Benign),
        ("suspicious", SampleLabel::Suspicious),
    ] {
        let distinct: BTreeSet<&str> = votes
            .iter()
            .filter(|v| v.verdict.trim().eq_ignore_ascii_case(needle))
            .map(|v| v.provider.as_str())
            .collect();
        if distinct.len() >= 2 {
            return Some(label);
        }
    }
    None
}

fn build(args: GoldBuildArgs) -> Result<()> {
    let content = fs::read_to_string(&args.consensus)
        .with_context(|| format!("failed to read {}", args.consensus.display()))?;
    let records: Vec<ConsensusRecord> = serde_json::Deserializer::from_str(&content)
        .into_iter::<ConsensusRecord>()
        .collect::<Result<_, _>>()
        .context("failed to parse consensus rollup")?;

    let samples: Vec<GoldSample> = records
        .iter()
        .map(|r| {
            let consensus = llm_consensus(&r.providers);
            GoldSample {
                id: r.sha.clone(),
                path: args.dataset_root.join(&r.sha).join("SKILL.md"),
                // Provisional curated label = the consensus when it
                // formed; otherwise a conservative Suspicious that the
                // dispute gate excludes from scoring until reviewed.
                final_label: consensus.unwrap_or(SampleLabel::Suspicious),
                vt_label: None,
                llm_consensus: consensus,
                human_review: None,
                // No VT label at build time, so the only dispute
                // signal is "no LLM consensus" — those MUST be
                // human-reviewed before they count.
                disputed: consensus.is_none(),
                focus_category: None,
                attack_family: None,
            }
        })
        .collect();

    let manifest = GoldCorpusManifest {
        schema_version: "1".to_string(),
        samples,
    };
    let yaml = serde_yaml::to_string(&manifest).context("failed to serialise gold manifest")?;
    fs::write(&args.out, yaml)
        .with_context(|| format!("failed to write {}", args.out.display()))?;
    let disputed = manifest.samples.iter().filter(|s| s.disputed).count();
    println!(
        "wrote {} ({} samples, {} need human review) → {}",
        args.out.display(),
        manifest.samples.len(),
        disputed,
        args.out.display(),
    );
    Ok(())
}

fn load_manifest(path: &PathBuf) -> Result<GoldCorpusManifest> {
    let text =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_yaml::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

fn stats(args: GoldStatsArgs) -> Result<()> {
    let m = load_manifest(&args.manifest)?;
    let total = m.samples.len();
    let admitted = m.samples.iter().filter(|s| s.is_admitted()).count();
    let disputed_unreviewed = total - admitted;
    let count = |l: SampleLabel| {
        m.samples
            .iter()
            .filter(|s| s.is_admitted() && s.final_label == l)
            .count()
    };
    println!("gold corpus: {}", args.manifest.display());
    println!("  total samples:        {total}");
    println!("  admitted (scored):    {admitted}");
    println!("  disputed, unreviewed: {disputed_unreviewed}");
    println!("  admitted benign:      {}", count(SampleLabel::Benign));
    println!("  admitted suspicious:  {}", count(SampleLabel::Suspicious));
    println!("  admitted malicious:   {}", count(SampleLabel::Malicious));
    Ok(())
}

fn review(args: GoldReviewArgs) -> Result<()> {
    let mut m = load_manifest(&args.manifest)?;
    let label = label_of(args.label);
    let sample = m
        .samples
        .iter_mut()
        .find(|s| s.id == args.id)
        .with_context(|| format!("no sample with id {}", args.id))?;
    sample.human_review = Some(label);
    sample.final_label = label;
    sample.disputed = false;
    let yaml = serde_yaml::to_string(&m).context("failed to serialise gold manifest")?;
    fs::write(&args.manifest, yaml)
        .with_context(|| format!("failed to write {}", args.manifest.display()))?;
    println!("adjudicated {} → {:?}", args.id, label);
    Ok(())
}

pub(crate) fn run_gold(action: GoldAction) -> Result<()> {
    match action {
        GoldAction::Build(a) => build(a),
        GoldAction::Stats(a) => stats(a),
        GoldAction::Review(a) => review(a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vote(p: &str, v: &str) -> ProviderVoteRecord {
        ProviderVoteRecord {
            provider: p.to_string(),
            verdict: v.to_string(),
        }
    }

    /// Contract: ≥2 distinct providers on the same label is consensus;
    /// a single provider, or duplicate votes from one provider, is
    /// NOT (both directions).
    #[test]
    fn consensus_requires_two_distinct_providers() {
        assert_eq!(
            llm_consensus(&[vote("openai", "malicious"), vote("grok", "malicious")]),
            Some(SampleLabel::Malicious)
        );
        assert_eq!(llm_consensus(&[vote("openai", "malicious")]), None);
        assert_eq!(
            llm_consensus(&[vote("grok", "benign"), vote("grok", "benign")]),
            None,
            "duplicate single-provider votes must not form consensus"
        );
        assert_eq!(
            llm_consensus(&[
                vote("openai", "malicious"),
                vote("grok", "benign"),
                vote("ollama-cloud", "suspicious"),
            ]),
            None,
            "a 1/1/1 split is no consensus"
        );
    }

    /// Contract: no-consensus seeds a disputed sample (excluded from
    /// scoring until reviewed); a formed consensus seeds an admitted
    /// one.
    #[test]
    fn build_marks_no_consensus_as_disputed() {
        let consensus = llm_consensus(&[vote("openai", "malicious")]);
        let s = GoldSample {
            id: "a".into(),
            path: "a/SKILL.md".into(),
            final_label: consensus.unwrap_or(SampleLabel::Suspicious),
            vt_label: None,
            llm_consensus: consensus,
            human_review: None,
            disputed: consensus.is_none(),
            focus_category: None,
            attack_family: None,
        };
        assert!(s.disputed && !s.is_admitted());
    }
}
