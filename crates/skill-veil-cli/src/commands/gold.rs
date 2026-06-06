//! `gold` — curated ground-truth corpus tooling.
//!
//! VT labels are noisy; that noise is the floor of both precision and
//! recall. This command seeds a gold manifest from a recorded
//! 3-provider LLM-consensus rollup (no live calls), flags the cases
//! that need a human, and lets a reviewer adjudicate them. The
//! resulting manifest is scored by the identical pipeline as the
//! regression corpus via `evaluate_gold_corpus`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use skill_veil_core::{GoldCorpusManifest, GoldSample, SampleLabel};

use crate::cli_args::{GoldAction, GoldBuildArgs, GoldLabelArg, GoldReviewArgs, GoldStatsArgs};
use crate::util::bounded_read::read_operator_text_file;
use crate::util::output_file::write_output_file_atomic;
use crate::util::terminal_safe::sanitise_for_terminal;
use crate::vt::types::CachedReport;

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

/// Derive a coarse VT label from a cached report. Prefers the Code
/// Insight / crowdsourced-AI verdict string (the signal the dataset is
/// built around); falls back to `last_analysis_stats` (any malicious
/// engine → Malicious, else any suspicious → Suspicious, else
/// Benign). `None` when the report carries no usable signal.
fn sample_label_from_vt(report: &CachedReport) -> Option<SampleLabel> {
    if let Some(ai) = report.attributes.primary_ai_verdict() {
        match ai.verdict.trim().to_ascii_lowercase().as_str() {
            "malicious" => return Some(SampleLabel::Malicious),
            "suspicious" => return Some(SampleLabel::Suspicious),
            "benign" | "harmless" => return Some(SampleLabel::Benign),
            _ => {}
        }
    }
    let stats = report.attributes.last_analysis_stats.as_ref()?;
    if stats.malicious > 0 {
        Some(SampleLabel::Malicious)
    } else if stats.suspicious > 0 {
        Some(SampleLabel::Suspicious)
    } else if stats.harmless > 0 || stats.undetected > 0 {
        Some(SampleLabel::Benign)
    } else {
        None
    }
}

/// Read `<dir>/<sha>.json` (the `.vt-reports` layout written by
/// `vt download`) and derive its label. Missing / unparseable reports
/// yield `None` (best-effort enrichment, never fatal).
fn vt_label_for(dir: &Path, sha: &str) -> Option<SampleLabel> {
    let path = dir.join(format!("{sha}.json"));
    let text = read_operator_text_file(&path).ok()?;
    let report: CachedReport = serde_json::from_str(&text).ok()?;
    if report.sha256.to_ascii_lowercase() != sha {
        return None;
    }
    sample_label_from_vt(&report)
}

fn validate_sample_sha(sha: &str) -> Result<()> {
    if sha.len() == 64
        && sha
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        anyhow::bail!("gold consensus id `{sha}` must be a lowercase 64-character SHA-256")
    }
}

/// ≥2 DISTINCT providers agreeing on the same label is the consensus;
/// otherwise `None` (no consensus → the sample is disputed and needs
/// a human). Distinctness is keyed on provider name so a single
/// provider cannot manufacture consensus; conflicting duplicate rows
/// from one provider are ambiguous and do not count for any label.
fn llm_consensus(votes: &[ProviderVoteRecord]) -> Option<SampleLabel> {
    let mut by_provider: BTreeMap<String, Option<SampleLabel>> = BTreeMap::new();
    for vote in votes {
        let Some(label) = sample_label_from_llm_verdict(&vote.verdict) else {
            continue;
        };
        by_provider
            .entry(normalized_provider_key(&vote.provider))
            .and_modify(|existing| {
                if *existing != Some(label) {
                    *existing = None;
                }
            })
            .or_insert(Some(label));
    }
    debug_assert!(
        by_provider.len() <= votes.len(),
        "normalized provider buckets cannot outnumber raw votes",
    );

    // A label is a candidate when at least two distinct providers agree on it.
    // With the documented 3-provider rollup at most one label can qualify, but
    // a 4+-provider cohort can produce a genuine tie (e.g. 2 malicious / 2
    // benign). Resolving that to the first label in iteration order would
    // silently manufacture consensus, so a tie (or no qualifier) is `None` —
    // the sample stays disputed and is sent to human review.
    let qualifying: Vec<SampleLabel> = [
        SampleLabel::Malicious,
        SampleLabel::Benign,
        SampleLabel::Suspicious,
    ]
    .into_iter()
    .filter(|&label| by_provider.values().filter(|v| **v == Some(label)).count() >= 2)
    .collect();
    match qualifying.as_slice() {
        [single] => Some(*single),
        _ => None,
    }
}

fn sample_label_from_llm_verdict(raw: &str) -> Option<SampleLabel> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "malicious" => Some(SampleLabel::Malicious),
        "benign" => Some(SampleLabel::Benign),
        "suspicious" => Some(SampleLabel::Suspicious),
        _ => None,
    }
}

fn normalized_provider_key(provider: &str) -> String {
    provider.trim().to_ascii_lowercase()
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn absolute_lexical(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to resolve current directory")?
            .join(path)
    };
    Ok(normalize_lexical(&absolute))
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() && !normalized.has_root() {
                    normalized.push("..");
                }
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn split_path_parts(path: &Path) -> (Vec<OsString>, Vec<OsString>) {
    let mut root = Vec::new();
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                root.push(component.as_os_str().to_os_string());
            }
            Component::Normal(part) => parts.push(part.to_os_string()),
            Component::CurDir => {}
            Component::ParentDir => parts.push(OsString::from("..")),
        }
    }
    (root, parts)
}

fn relative_path_between(base_dir: &Path, target: &Path) -> Result<PathBuf> {
    let base_dir = absolute_lexical(base_dir)?;
    let target = absolute_lexical(target)?;
    let (base_root, base_parts) = split_path_parts(&base_dir);
    let (target_root, target_parts) = split_path_parts(&target);

    if base_root != target_root {
        anyhow::bail!(
            "{} and {} do not share a filesystem root",
            base_dir.display(),
            target.display()
        );
    }

    let common = base_parts
        .iter()
        .zip(target_parts.iter())
        .take_while(|(left, right)| left == right)
        .count();
    let mut relative = PathBuf::new();
    for _ in common..base_parts.len() {
        relative.push("..");
    }
    for part in target_parts.iter().skip(common) {
        relative.push(part);
    }
    if relative.as_os_str().is_empty() {
        relative.push(".");
    }
    Ok(relative)
}

fn sample_path_for_manifest(dataset_root: &Path, out: &Path, sha: &str) -> Result<PathBuf> {
    let sample_path = dataset_root.join(sha).join("SKILL.md");
    let manifest_path = relative_path_between(output_parent(out), &sample_path)?;
    debug_assert!(
        !manifest_path.is_absolute(),
        "gold manifest sample paths must be relative"
    );
    Ok(manifest_path)
}

fn build(args: GoldBuildArgs) -> Result<()> {
    let content = read_operator_text_file(&args.consensus)
        .with_context(|| format!("failed to read {}", args.consensus.display()))?;
    let records: Vec<ConsensusRecord> = serde_json::Deserializer::from_str(&content)
        .into_iter::<ConsensusRecord>()
        .collect::<Result<_, _>>()
        .context("failed to parse consensus rollup")?;

    let samples: Vec<GoldSample> = records
        .iter()
        .map(|r| {
            validate_sample_sha(&r.sha)?;
            let consensus = llm_consensus(&r.providers);
            let vt_label = args
                .vt_reports
                .as_deref()
                .and_then(|dir| vt_label_for(dir, &r.sha));
            let mut s = GoldSample {
                id: r.sha.clone(),
                path: sample_path_for_manifest(&args.dataset_root, &args.out, &r.sha)?,
                // Provisional curated label = the consensus when it
                // formed; otherwise a conservative Suspicious that the
                // dispute gate excludes from scoring until reviewed.
                final_label: consensus.unwrap_or(SampleLabel::Suspicious),
                vt_label,
                llm_consensus: consensus,
                human_review: None,
                disputed: false,
                focus_category: None,
                attack_family: None,
            };
            // Dispute is DERIVED from provenance (VT vs LLM, or no
            // consensus). When no VT label is available the
            // derive_disputed (VT=None, LLM=None) path returns false,
            // so a no-consensus sample must still be flagged.
            s.disputed = s.derive_disputed() || consensus.is_none();
            Ok(s)
        })
        .collect::<Result<_>>()?;

    let manifest = GoldCorpusManifest {
        schema_version: "1".to_string(),
        samples,
    };
    let yaml = serde_yaml::to_string(&manifest).context("failed to serialise gold manifest")?;
    write_output_file_atomic(&args.out, yaml.as_bytes())
        .with_context(|| format!("failed to write {}", args.out.display()))?;
    let disputed = manifest.samples.iter().filter(|s| s.disputed).count();
    println!(
        "wrote {} ({} samples, {} need human review) → {}",
        terminal_path(&args.out),
        manifest.samples.len(),
        disputed,
        terminal_path(&args.out),
    );
    Ok(())
}

fn load_manifest(path: &Path) -> Result<GoldCorpusManifest> {
    let text = read_operator_text_file(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
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
    println!("gold corpus: {}", terminal_path(&args.manifest));
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
    write_output_file_atomic(&args.manifest, yaml.as_bytes())
        .with_context(|| format!("failed to write {}", args.manifest.display()))?;
    println!(
        "adjudicated {} → {:?}",
        sanitise_for_terminal(&args.id),
        label
    );
    Ok(())
}

pub(crate) fn run_gold(action: GoldAction) -> Result<()> {
    match action {
        GoldAction::Build(a) => build(a),
        GoldAction::Stats(a) => stats(a),
        GoldAction::Review(a) => review(a),
    }
}

fn terminal_path(path: &Path) -> String {
    sanitise_for_terminal(&path.display().to_string())
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

    /// # Contract
    ///
    /// Gold sample ids are lowercase SHA-256 strings because they become
    /// filesystem path segments.
    #[test]
    fn validate_sample_sha_accepts_lowercase_sha256() {
        assert!(validate_sample_sha(&"a".repeat(64)).is_ok());
        assert!(validate_sample_sha(&"0".repeat(64)).is_ok());
    }

    /// # Contract
    ///
    /// Gold sample ids must reject path syntax before any VT report or
    /// dataset path is constructed.
    #[test]
    fn validate_sample_sha_rejects_path_syntax() {
        for bad in [
            String::new(),
            "a".to_string(),
            "A".repeat(64),
            "../../etc/passwd".to_string(),
            "/tmp/escape".to_string(),
            "a/b".to_string(),
            "a".repeat(63),
            "g".repeat(64),
        ] {
            assert!(
                validate_sample_sha(&bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn terminal_path_removes_gold_status_control_sequences() {
        let path = Path::new("gold\x1b[2J.yaml");
        let cleaned = terminal_path(path);

        assert!(!cleaned.contains('\x1b'));
        assert!(cleaned.contains("gold?[2J.yaml"));
    }

    /// # Contract
    ///
    /// `gold build` rejects malformed ids before writing the output
    /// manifest.
    #[test]
    fn build_rejects_path_like_consensus_id() {
        let tmp = tempfile::tempdir().unwrap();
        let consensus = tmp.path().join("consensus.jsonl");
        let out = tmp.path().join("gold.yaml");
        std::fs::write(
            &consensus,
            r#"{"sha":"../../escape","providers":[{"provider":"openai","verdict":"malicious"},{"provider":"grok","verdict":"malicious"}]}"#,
        )
        .unwrap();

        let result = build(GoldBuildArgs {
            consensus,
            dataset_root: tmp.path().join("dataset"),
            vt_reports: Some(tmp.path().join("vt-reports")),
            out: out.clone(),
        });

        assert!(result.is_err());
        assert!(!out.exists());
    }

    /// # Contract
    ///
    /// `gold build` writes sample paths relative to the output manifest
    /// directory. Absolute operator input must not leak into the
    /// manifest because the scorer resolves paths from the manifest
    /// location.
    #[test]
    fn build_writes_sample_paths_relative_to_manifest_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let sha = "a".repeat(64);
        let consensus = tmp.path().join("consensus.jsonl");
        let out = tmp.path().join("manifests").join("gold.yaml");
        std::fs::write(
            &consensus,
            format!(
                r#"{{"sha":"{sha}","providers":[{{"provider":"openai","verdict":"malicious"}},{{"provider":"grok","verdict":"malicious"}}]}}"#
            ),
        )
        .unwrap();

        build(GoldBuildArgs {
            consensus,
            dataset_root: tmp.path().join("dataset"),
            vt_reports: None,
            out: out.clone(),
        })
        .unwrap();

        let manifest: GoldCorpusManifest =
            serde_yaml::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let path = &manifest.samples[0].path;
        assert!(!path.is_absolute());
        assert_eq!(
            path,
            &PathBuf::from("..")
                .join("dataset")
                .join(&sha)
                .join("SKILL.md")
        );
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
            llm_consensus(&[vote("grok", "benign"), vote(" Grok ", "benign")]),
            None,
            "case/whitespace variants of one provider must not form consensus"
        );
        assert_eq!(
            llm_consensus(&[
                vote("openai", "malicious"),
                vote(" OpenAI ", "benign"),
                vote("grok", "malicious"),
            ]),
            None,
            "conflicting duplicate provider votes must not support consensus"
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

    /// Contract: a 4+-provider cohort with a tie (two labels each reaching the
    /// ≥2 threshold) is NOT consensus — it stays disputed rather than being
    /// silently resolved to whichever label sorts first in iteration order.
    #[test]
    fn consensus_tie_is_not_resolved_to_first_label() {
        assert_eq!(
            llm_consensus(&[
                vote("openai", "malicious"),
                vote("grok", "malicious"),
                vote("anthropic", "benign"),
                vote("ollama-cloud", "benign"),
            ]),
            None,
            "a 2-2 malicious/benign tie must be disputed, not silently Malicious"
        );
        assert_eq!(
            llm_consensus(&[
                vote("openai", "benign"),
                vote("grok", "benign"),
                vote("anthropic", "benign"),
                vote("ollama-cloud", "malicious"),
            ]),
            Some(SampleLabel::Benign),
            "a clear 3-1 majority still forms consensus"
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

    /// Contract: the Code Insight / crowdsourced-AI verdict string
    /// drives the VT label (both directions).
    #[test]
    fn vt_label_from_code_insight_verdict() {
        let json = r#"{"sha256":"x","fetched_at":"t","attributes":{"crowdsourced_ai_results":[{"source":"Code Insight","verdict":"malicious"}]}}"#;
        let r: CachedReport = serde_json::from_str(json).unwrap();
        assert_eq!(sample_label_from_vt(&r), Some(SampleLabel::Malicious));

        let json = r#"{"sha256":"x","fetched_at":"t","attributes":{"crowdsourced_ai_results":[{"source":"Code Insight","verdict":"benign"}]}}"#;
        let r: CachedReport = serde_json::from_str(json).unwrap();
        assert_eq!(sample_label_from_vt(&r), Some(SampleLabel::Benign));

        let json = r#"{"sha256":"x","fetched_at":"t","attributes":{"crowdsourced_ai_results":[{"source":"Code Insight","verdict":" harmless "}]}}"#;
        let r: CachedReport = serde_json::from_str(json).unwrap();
        assert_eq!(sample_label_from_vt(&r), Some(SampleLabel::Benign));
    }

    /// Contract: Code Insight labels must be exact normalized verdict
    /// values, not substring matches. Free-form strings such as
    /// "not malicious" are not ground-truth labels.
    #[test]
    fn vt_label_rejects_verdict_substring_matches() {
        let json = r#"{"sha256":"x","fetched_at":"t","attributes":{"crowdsourced_ai_results":[{"source":"Code Insight","verdict":"not malicious"}]}}"#;
        let r: CachedReport = serde_json::from_str(json).unwrap();
        assert_eq!(sample_label_from_vt(&r), None);

        let json = r#"{"sha256":"x","fetched_at":"t","attributes":{"crowdsourced_ai_results":[{"source":"Code Insight","verdict":"unsuspicious"}]}}"#;
        let r: CachedReport = serde_json::from_str(json).unwrap();
        assert_eq!(sample_label_from_vt(&r), None);
    }

    /// Contract: with no AI verdict, `last_analysis_stats` is the
    /// fallback; an all-zero / empty report yields `None` (no signal
    /// — never a fabricated label).
    #[test]
    fn vt_label_falls_back_to_analysis_stats_then_none() {
        let json = r#"{"sha256":"x","fetched_at":"t","attributes":{"last_analysis_stats":{"malicious":3}}}"#;
        let r: CachedReport = serde_json::from_str(json).unwrap();
        assert_eq!(sample_label_from_vt(&r), Some(SampleLabel::Malicious));

        let json = r#"{"sha256":"x","fetched_at":"t","attributes":{}}"#;
        let r: CachedReport = serde_json::from_str(json).unwrap();
        assert_eq!(sample_label_from_vt(&r), None);
    }

    /// Contract: `<sha>.json` must carry the same payload `sha256`.
    /// A poisoned VT report cache file must not label a gold sample
    /// using a report fetched for a different sample.
    #[test]
    fn vt_label_for_rejects_payload_sha_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let requested = "a".repeat(64);
        let payload = "b".repeat(64);
        let report = format!(
            r#"{{"sha256":"{payload}","fetched_at":"t","attributes":{{"crowdsourced_ai_results":[{{"source":"Code Insight","verdict":"malicious"}}]}}}}"#
        );
        std::fs::write(tmp.path().join(format!("{requested}.json")), report).unwrap();

        assert_eq!(vt_label_for(tmp.path(), &requested), None);
    }

    /// Contract: a VT label that disagrees with the LLM consensus
    /// marks the sample disputed (must be human-reviewed before it
    /// scores); agreement does not.
    #[test]
    fn vt_vs_llm_disagreement_marks_disputed() {
        let mut s = GoldSample {
            id: "a".into(),
            path: "a/SKILL.md".into(),
            final_label: SampleLabel::Malicious,
            vt_label: Some(SampleLabel::Benign),
            llm_consensus: Some(SampleLabel::Malicious),
            human_review: None,
            disputed: false,
            focus_category: None,
            attack_family: None,
        };
        s.disputed = s.derive_disputed();
        assert!(s.disputed, "VT≠LLM must be disputed");

        s.vt_label = Some(SampleLabel::Malicious);
        s.disputed = s.derive_disputed();
        assert!(!s.disputed, "VT==LLM agreement is not disputed");
    }
}
