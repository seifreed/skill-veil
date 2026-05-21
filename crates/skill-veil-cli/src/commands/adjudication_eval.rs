//! Offline replay of recorded LLM-provider verdicts against the
//! labelled triage corpora.
//!
//! # Why this exists
//!
//! ADR 0029's downgrade and its symmetric FN upgrade both trade a
//! controlled amount of precision for recall (or vice-versa). Before
//! either lever is wired default-on (the `triage` preset) the trade
//! MUST be quantified — on recorded data, not by calling providers
//! again. This command replays the provider verdicts already captured
//! in the in-repo triage JSONL and reports the effect of each lever
//! using the **same pure reconciliation functions the runtime uses**
//! (`effective_verdict` / `provider_consensus_benign`). It never
//! constructs a network client.
//!
//! # The Suspicious-collapse caveat
//!
//! `skill_veil_core::benchmark::compute_metrics` collapses Suspicious
//! into "risky" (non-Benign). A downgrade `Malicious → Suspicious`
//! therefore does NOT move the binary FP count, and an upgrade
//! `Suspicious → Malicious` does NOT move the binary FN count. The
//! binary table is reported for continuity with the regression
//! baseline; the lever's real effect is the **exact-label transition**
//! breakdown (`softened` / `escalated`, split by true label), which is
//! what the operator-facing exit-code semantics actually key off.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use skill_veil_core::{benchmark::compute_metrics, RegressionMetrics, SampleLabel, Verdict};
use std::collections::BTreeMap;

use crate::cli_args::{AdjudicationEvalArgs, OutputFormat};
use crate::llm::taint_adjudication::{
    effective_verdict, parse_provider_verdict, provider_consensus_benign,
};
use crate::util::bounded_read::read_operator_text_file;
use crate::util::output_file::write_output_file_atomic;

/// One recorded provider vote in the flat triage JSONL
/// (`taint-fp-triage.jsonl`, `taint-fn-triage.jsonl`): one object per
/// `(sha, provider)`.
#[derive(Debug, Clone, Deserialize)]
struct FlatTriageRecord {
    sha: String,
    provider: String,
    verdict: String,
}

/// One provider vote nested inside a consensus rollup record.
#[derive(Debug, Clone, Deserialize)]
struct ProviderVoteRecord {
    provider: String,
    verdict: String,
}

/// One aggregated per-sha record in `residual-fn-consensus.jsonl`
/// (concatenated pretty-printed JSON values). Each record is already
/// one sha, so only the provider votes are needed here; other fields
/// (`sha`, vote tallies, `consensus`) are ignored by serde.
#[derive(Debug, Clone, Deserialize)]
struct ConsensusRecord {
    #[serde(default)]
    providers: Vec<ProviderVoteRecord>,
}

/// A sample to score: the ground-truth label, the scanner's baseline
/// verdict, and the distinct provider votes recorded for it.
#[derive(Debug, Clone)]
struct EvalSample {
    expected: SampleLabel,
    baseline: Verdict,
    votes: Vec<(String, Verdict)>,
}

/// Metrics for one scenario (baseline / a lever applied).
#[derive(Debug, Clone, Serialize)]
struct ScenarioMetrics {
    name: String,
    metrics: RegressionMetrics,
    /// Samples whose effective verdict moved to a *less* severe label
    /// than baseline, split by true label.
    softened_benign: usize,
    softened_malicious: usize,
    /// Samples whose effective verdict moved to a *more* severe label.
    escalated_benign: usize,
    escalated_malicious: usize,
}

/// The full offline-eval report. Stable serialised schema consumed by
/// CI.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AdjudicationEvalReport {
    sample_count: usize,
    scenarios: Vec<ScenarioMetrics>,
}

/// Parse a stream of JSON values (handles both newline-delimited
/// compact JSONL and concatenated pretty-printed objects — serde's
/// stream deserializer treats inter-value whitespace identically).
fn parse_json_stream<T: for<'de> Deserialize<'de>>(content: &str) -> Result<Vec<T>> {
    serde_json::Deserializer::from_str(content)
        .into_iter::<T>()
        .collect::<Result<Vec<T>, _>>()
        .context("failed to parse recorded triage JSON stream")
}

/// Group flat triage records by sha into distinct provider votes,
/// dropping unparseable / `error` verdicts (a provider that did not
/// return a usable verdict is simply not a vote).
fn group_flat(records: &[FlatTriageRecord]) -> BTreeMap<String, Vec<(String, Verdict)>> {
    let mut by_sha: BTreeMap<String, Vec<(String, Verdict)>> = BTreeMap::new();
    for r in records {
        if let Some(v) = parse_provider_verdict(&r.verdict) {
            by_sha
                .entry(r.sha.clone())
                .or_default()
                .push((r.provider.clone(), v));
        }
    }
    by_sha
}

fn consensus_votes(rec: &ConsensusRecord) -> Vec<(String, Verdict)> {
    rec.providers
        .iter()
        .filter_map(|p| parse_provider_verdict(&p.verdict).map(|v| (p.provider.clone(), v)))
        .collect()
}

const fn verdict_to_label(v: Verdict) -> SampleLabel {
    match v {
        Verdict::Benign => SampleLabel::Benign,
        Verdict::Suspicious => SampleLabel::Suspicious,
        Verdict::Malicious => SampleLabel::Malicious,
    }
}

/// Total order on severity so transitions can be classified.
/// `Benign < Suspicious < Malicious`.
const fn severity_rank(v: Verdict) -> u8 {
    match v {
        Verdict::Benign => 0,
        Verdict::Suspicious => 1,
        Verdict::Malicious => 2,
    }
}

/// Build the sample set. `taint-fp` is the benign-labelled corpus that
/// the taint rules FP'd on (baseline `Malicious`); `taint-fn` is the
/// true-malicious that the downgrade would soften (baseline
/// `Malicious`); `residual-fn` is the soft-FN bucket the scanner held
/// at `Suspicious`.
fn build_samples(
    taint_fp: &[FlatTriageRecord],
    taint_fn: &[FlatTriageRecord],
    residual_fn: &[ConsensusRecord],
) -> Vec<EvalSample> {
    let mut samples = Vec::new();
    for (_, votes) in group_flat(taint_fp) {
        samples.push(EvalSample {
            expected: SampleLabel::Benign,
            baseline: Verdict::Malicious,
            votes,
        });
    }
    for (_, votes) in group_flat(taint_fn) {
        samples.push(EvalSample {
            expected: SampleLabel::Malicious,
            baseline: Verdict::Malicious,
            votes,
        });
    }
    for rec in residual_fn {
        samples.push(EvalSample {
            expected: SampleLabel::Malicious,
            baseline: Verdict::Suspicious,
            votes: consensus_votes(rec),
        });
    }
    samples
}

/// Apply the ADR-0029 downgrade to one sample. Eligibility is implied
/// by bucket membership (every recorded sha matched a taint rule);
/// `effective_verdict` is a no-op for any non-`Malicious` baseline, so
/// residual-FN samples pass through unchanged.
fn downgraded_verdict(s: &EvalSample) -> Verdict {
    effective_verdict(s.baseline, true, true, provider_consensus_benign(&s.votes))
}

fn scenario(
    name: &str,
    samples: &[EvalSample],
    effective: impl Fn(&EvalSample) -> Verdict,
) -> ScenarioMetrics {
    let expected: Vec<SampleLabel> = samples.iter().map(|s| s.expected).collect();
    let actual: Vec<SampleLabel> = samples
        .iter()
        .map(|s| verdict_to_label(effective(s)))
        .collect();

    let mut softened_benign = 0;
    let mut softened_malicious = 0;
    let mut escalated_benign = 0;
    let mut escalated_malicious = 0;
    for s in samples {
        let after = effective(s);
        let before_rank = severity_rank(s.baseline);
        let after_rank = severity_rank(after);
        let benign_truth = s.expected == SampleLabel::Benign;
        if after_rank < before_rank {
            if benign_truth {
                softened_benign += 1;
            } else {
                softened_malicious += 1;
            }
        } else if after_rank > before_rank {
            if benign_truth {
                escalated_benign += 1;
            } else {
                escalated_malicious += 1;
            }
        }
    }

    ScenarioMetrics {
        name: name.to_string(),
        metrics: compute_metrics(&expected, &actual),
        softened_benign,
        softened_malicious,
        escalated_benign,
        escalated_malicious,
    }
}

fn evaluate(
    taint_fp: &[FlatTriageRecord],
    taint_fn: &[FlatTriageRecord],
    residual_fn: &[ConsensusRecord],
) -> AdjudicationEvalReport {
    let samples = build_samples(taint_fp, taint_fn, residual_fn);
    let scenarios = vec![
        scenario("baseline", &samples, |s| s.baseline),
        scenario("+taint-downgrade", &samples, downgraded_verdict),
    ];
    AdjudicationEvalReport {
        sample_count: samples.len(),
        scenarios,
    }
}

fn render_text(report: &AdjudicationEvalReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Adjudication offline-eval — {} samples (recorded provider votes, zero live calls)\n",
        report.sample_count
    );
    let _ = writeln!(
        out,
        "{:<18} {:>9} {:>7} {:>7} {:>8} {:>9}  softened(B/M)  escalated(B/M)",
        "scenario", "precision", "recall", "fpr", "accuracy", "exact_acc"
    );
    for sc in &report.scenarios {
        let m = &sc.metrics;
        let _ = writeln!(
            out,
            "{:<18} {:>9.4} {:>7.4} {:>7.4} {:>8.4} {:>9.4}      {:>3}/{:<3}       {:>3}/{:<3}",
            sc.name,
            m.precision,
            m.recall,
            m.false_positive_rate,
            m.accuracy,
            m.exact_label_accuracy,
            sc.softened_benign,
            sc.softened_malicious,
            sc.escalated_benign,
            sc.escalated_malicious,
        );
    }
    out.push_str(
        "\nsoftened(B) = benign-labelled no longer hard-Malicious (recovered FP); \
         softened(M) = true-malicious weakened to Suspicious (cost, still surfaced).\n",
    );
    out
}

/// Offline-eval entry point. Pure file-in / report-out; never
/// constructs a network client.
pub(crate) fn run_adjudication_eval(args: AdjudicationEvalArgs) -> Result<()> {
    let read = |p: &std::path::Path| -> Result<String> {
        read_operator_text_file(p).with_context(|| format!("failed to read {}", p.display()))
    };
    let taint_fp: Vec<FlatTriageRecord> = parse_json_stream(&read(&args.taint_fp)?)?;
    let taint_fn: Vec<FlatTriageRecord> = parse_json_stream(&read(&args.taint_fn)?)?;
    let residual_fn: Vec<ConsensusRecord> = parse_json_stream(&read(&args.residual_fn)?)?;

    let report = evaluate(&taint_fp, &taint_fn, &residual_fn);

    let rendered = match args.format {
        OutputFormat::Json => {
            serde_json::to_string_pretty(&report).context("failed to serialise eval report")?
        }
        _ => render_text(&report),
    };

    if let Some(path) = &args.output {
        write_output_file_atomic(path, rendered.as_bytes())
            .with_context(|| format!("failed to write {}", path.display()))?;
    } else {
        println!("{rendered}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flat(sha: &str, provider: &str, verdict: &str) -> FlatTriageRecord {
        FlatTriageRecord {
            sha: sha.to_string(),
            provider: provider.to_string(),
            verdict: verdict.to_string(),
        }
    }

    /// Contract: a benign-labelled sample with ≥2 distinct providers
    /// voting benign is softened `Malicious → Suspicious` purely from
    /// recorded votes — the function takes records only, never a
    /// client.
    #[test]
    fn downgrade_lever_replays_recorded_consensus_without_live_calls() {
        let fp = [
            flat("a", "openai", "benign"),
            flat("a", "grok", "benign"),
            flat("a", "ollama-cloud", "malicious"),
        ];
        let report = evaluate(&fp, &[], &[]);
        let downgrade = report
            .scenarios
            .iter()
            .find(|s| s.name == "+taint-downgrade")
            .unwrap();
        assert_eq!(
            downgrade.softened_benign, 1,
            "2-of-3 benign consensus must soften the benign-labelled FP",
        );
        assert_eq!(downgrade.softened_malicious, 0);
    }

    /// Contract (negative): without a ≥2 distinct-benign consensus the
    /// verdict stays `Malicious` — the lever must not soften on a
    /// single benign vote.
    #[test]
    fn downgrade_lever_keeps_malicious_when_consensus_not_reached() {
        let fp = [
            flat("a", "openai", "benign"),
            flat("a", "grok", "malicious"),
            flat("a", "ollama-cloud", "malicious"),
        ];
        let report = evaluate(&fp, &[], &[]);
        let downgrade = report
            .scenarios
            .iter()
            .find(|s| s.name == "+taint-downgrade")
            .unwrap();
        assert_eq!(
            downgrade.softened_benign, 0,
            "a single benign vote must not reach consensus",
        );
    }

    /// Contract: the report's baseline metrics are byte-identical to a
    /// direct `compute_metrics` call on the same labels — the eval
    /// reuses the core metric definition, it does not re-implement it.
    #[test]
    fn eval_uses_core_compute_metrics_definition() {
        let fp = [
            flat("a", "openai", "benign"),
            flat("a", "grok", "benign"),
            flat("b", "openai", "malicious"),
            flat("b", "grok", "malicious"),
        ];
        let report = evaluate(&fp, &[], &[]);
        let baseline = report
            .scenarios
            .iter()
            .find(|s| s.name == "baseline")
            .unwrap();
        // Two benign-labelled samples, baseline verdict Malicious → 2 FP.
        let expected = [SampleLabel::Benign, SampleLabel::Benign];
        let actual = [SampleLabel::Malicious, SampleLabel::Malicious];
        assert_eq!(
            baseline.metrics.false_positive,
            compute_metrics(&expected, &actual).false_positive,
        );
        assert_eq!(baseline.metrics.false_positive, 2);
    }

    /// Contract: the JSON report round-trips with a stable field
    /// schema CI can key off.
    #[test]
    fn eval_report_serializes_stable_schema() {
        let report = evaluate(&[flat("a", "openai", "benign")], &[], &[]);
        let json = serde_json::to_value(&report).unwrap();
        assert!(json.get("sample_count").is_some());
        let scenarios = json.get("scenarios").unwrap().as_array().unwrap();
        let first = &scenarios[0];
        for key in [
            "name",
            "metrics",
            "softened_benign",
            "softened_malicious",
            "escalated_benign",
            "escalated_malicious",
        ] {
            assert!(first.get(key).is_some(), "missing scenario field {key}");
        }
    }

    /// Contract: concatenated pretty-printed JSON (the
    /// `residual-fn-consensus.jsonl` shape) parses via the same stream
    /// reader as compact JSONL.
    #[test]
    fn parses_concatenated_pretty_json_consensus() {
        let content = "{\n  \"sha\": \"a\",\n  \"providers\": [\n    {\"provider\":\"openai\",\"verdict\":\"malicious\"}\n  ]\n}\n{\n  \"sha\": \"b\",\n  \"providers\": []\n}";
        let recs: Vec<ConsensusRecord> = parse_json_stream(content).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(
            consensus_votes(&recs[0]),
            vec![("openai".into(), Verdict::Malicious)]
        );
        assert!(consensus_votes(&recs[1]).is_empty());
    }
}
