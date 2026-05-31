//! Advisory, multi-provider LLM false-positive review (`--llm-fp-review`).
//!
//! # Why this exists
//!
//! The native scanner is tuned for recall: a `Suspicious` verdict
//! surfaces borderline packages for an analyst. A fraction of those are
//! false positives a human resolves by reading context the static rules
//! cannot. This module generalises the consensus-LLM pattern proven by
//! the ADR-0029 taint adjudication into a BROAD review that flags the
//! likely false positives in that `Suspicious` bucket — so an operator
//! triaging a queue knows which packages an independent LLM panel judged
//! benign.
//!
//! # Security model — read this before touching anything
//!
//! Unlike the taint adjudication, this layer is ADVISORY ONLY. It NEVER
//! changes:
//! - the core scanner verdict (`ScanResult::verdict`),
//! - the `risk_score`,
//! - the process exit code (`should_fail`),
//! - the JSON / SARIF / Shield structured payload.
//!
//! It works on clones, produces a separate rendered block plus an
//! opt-in JSON sidecar, and leaves the `verdict_snapshot` anti-tamper
//! assertion in `commands::scan` valid. Because nothing here is
//! verdict- or exit-affecting, it needs no `adjudication-eval` corpus
//! calibration — the contract that gates the taint downgrade's eligible
//! rule set does not apply.
//!
//! The panel sees skill text and could be prompt-injected. The
//! mitigations are inherited verbatim by reusing `enrich_scan_result`
//! (hardened system prompt, untrusted-blob markers) and reinforced by
//! the same single-provider-flip injection guard the taint path uses: a
//! lone provider flipping to `benign` while the others disagree is
//! reported as `injection_suspected`, NOT as a false positive.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use skill_veil_core::{
    ConsensusDiscrepancy, Finding, PackageScanResult, ProviderVote, RecommendedAction, ScanResult,
    SignalClass, Verdict,
};

use crate::commands::scan::llm::{prepare_llm_inputs, LlmInputs};
use crate::config::LlmProviderKind;
use crate::llm::enrich::enrich_scan_result;
use crate::llm::taint_adjudication::{
    parse_provider_verdict, provider_consensus_benign, resolve_consensus_providers,
};
use crate::util::terminal_safe::sanitise_for_terminal;

/// Maximum chars of a filesystem path rendered in the review block.
const PATH_DISPLAY_CHARS: usize = 200;

/// Verdict classes whose findings are reviewable as candidate false
/// positives. `MaliciousBehavior` is deliberately excluded: softening a
/// Block-strength malicious driver is the taint adjudication's
/// calibrated job, not this broad advisory layer's.
#[must_use]
fn is_fp_candidate_finding(f: &Finding) -> bool {
    matches!(
        f.signal_class,
        SignalClass::ReviewSignal | SignalClass::SuspiciousPackageBehavior
    )
}

/// `true` when the verdict / findings are in the advisory review's
/// eligible shape: a core `Suspicious` verdict with at least one
/// reviewable (`ReviewSignal` / `SuspiciousPackageBehavior`) finding.
/// `Malicious` and `Benign` packages are out of scope by construction.
#[must_use]
pub(crate) fn fp_eligible(verdict: Verdict, findings: &[Finding]) -> bool {
    verdict == Verdict::Suspicious && findings.iter().any(is_fp_candidate_finding)
}

/// Thin [`ScanResult`] wrapper over [`fp_eligible`].
#[must_use]
pub(crate) fn result_fp_eligible(r: &ScanResult) -> bool {
    fp_eligible(r.verdict, &r.findings)
}

/// The consensus the LLM panel reached for one package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FpReviewConsensus {
    /// ≥2 distinct providers judged the package benign.
    SuspectedFalsePositive,
    /// No ≥2 benign consensus; the verdict stands unreviewed.
    NoConsensus,
    /// Exactly one provider flipped to benign while ≥2 disagreed — the
    /// prompt-injection signature. Never reported as a false positive.
    InjectionSuspected,
}

/// Pure reconciliation of one package's provider votes into a review
/// consensus plus, for the injection case, the flipped provider name.
/// `injection_suspected` is checked FIRST so a manipulation attempt can
/// never be laundered into a benign consensus.
#[must_use]
pub(crate) fn review_outcome_for(
    parsed: &[(String, Verdict)],
    error_votes: usize,
) -> (FpReviewConsensus, Option<String>) {
    let provider_votes: Vec<ProviderVote> = parsed
        .iter()
        .map(|(p, v)| ProviderVote {
            provider: p.clone(),
            verdict: *v,
            confidence: 0.0,
        })
        .collect();
    let discrepancy = ConsensusDiscrepancy::from_votes(provider_votes, error_votes);
    if discrepancy.is_single_provider_benign_flip() {
        return (
            FpReviewConsensus::InjectionSuspected,
            discrepancy.flipped_provider().map(str::to_string),
        );
    }
    if provider_consensus_benign(parsed) {
        (FpReviewConsensus::SuspectedFalsePositive, None)
    } else {
        (FpReviewConsensus::NoConsensus, None)
    }
}

/// Distinct rule ids of the package's reviewable findings, preserving
/// first-seen order via a dedup set.
#[must_use]
fn fp_candidate_rule_ids(findings: &[Finding]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    findings
        .iter()
        .filter(|f| is_fp_candidate_finding(f))
        .map(|f| f.rule_id.clone())
        .filter(|id| seen.insert(id.clone()))
        .collect()
}

/// One provider's vote on one package, with `None` for an
/// unparseable / errored response.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct FpProviderVote {
    pub(crate) provider: String,
    pub(crate) verdict: Option<String>,
}

/// Advisory review of a single `Suspicious` package. Carries no mutated
/// scan state — `core_verdict` is a copy for context and is never
/// written back.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct FpReviewItem {
    pub(crate) package: String,
    pub(crate) package_id: Option<String>,
    pub(crate) core_verdict: Verdict,
    pub(crate) consensus: FpReviewConsensus,
    pub(crate) provider_votes: Vec<FpProviderVote>,
    pub(crate) suspected_fp_rule_ids: Vec<String>,
    /// `Log` when the panel suspects a false positive; `None` otherwise.
    /// A SUGGESTION for the analyst — never applied to the scan result.
    pub(crate) suggested_action: Option<RecommendedAction>,
    pub(crate) flipped_provider: Option<String>,
}

/// Result of an advisory review pass. The caller prints `report_block`
/// (text format only) and may serialise `items` to a JSON sidecar.
/// Never carries a mutated `ScanResult`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct FpReviewOutcome {
    pub(crate) items: Vec<FpReviewItem>,
    #[serde(skip)]
    pub(crate) report_block: String,
}

fn truncate_path(path: &str) -> String {
    let safe = sanitise_for_terminal(path);
    if safe.chars().count() <= PATH_DISPLAY_CHARS {
        return safe;
    }
    let kept: String = safe.chars().take(PATH_DISPLAY_CHARS).collect();
    format!("{kept}…")
}

fn render_votes(votes: &[FpProviderVote]) -> String {
    votes
        .iter()
        .map(|v| format!("{}={}", v.provider, v.verdict.as_deref().unwrap_or("?")))
        .collect::<Vec<_>>()
        .join(", ")
}

#[must_use]
fn render_block(items: &[FpReviewItem]) -> String {
    let mut out = String::from("\n--- LLM false-positive review (advisory) ---\n");
    if items.is_empty() {
        out.push_str("No Suspicious packages were eligible for LLM false-positive review.\n");
        return out;
    }
    for item in items {
        let path = truncate_path(&item.package);
        match item.consensus {
            FpReviewConsensus::SuspectedFalsePositive => {
                let _ = writeln!(out, "[likely false positive] {path}");
                let _ = writeln!(
                    out,
                    "    core verdict: {} (UNCHANGED — advisory only)",
                    item.core_verdict
                );
                let _ = writeln!(
                    out,
                    "    ≥2 providers independently judged this package benign"
                );
                if !item.suspected_fp_rule_ids.is_empty() {
                    let _ = writeln!(
                        out,
                        "    suspected-FP findings: {}",
                        item.suspected_fp_rule_ids.join(", ")
                    );
                }
                let _ = writeln!(
                    out,
                    "    suggested triage action: log (review before suppressing)"
                );
            }
            FpReviewConsensus::InjectionSuspected => {
                let who = item.flipped_provider.as_deref().unwrap_or("?");
                let _ = writeln!(out, "[prompt-injection suspected] {path}");
                let _ = writeln!(
                    out,
                    "    one provider ({who}) flipped to benign while others disagreed"
                );
                let _ = writeln!(
                    out,
                    "    NOT marked a false positive — treat as a louder signal"
                );
            }
            FpReviewConsensus::NoConsensus => {
                let _ = writeln!(out, "[no benign consensus] {path}");
                let _ = writeln!(
                    out,
                    "    providers did not reach a ≥2 benign consensus; verdict stands"
                );
            }
        }
        let _ = writeln!(out, "    votes: {}", render_votes(&item.provider_votes));
    }
    out.push_str("This review never changes the skill-veil verdict, risk score, or exit code.\n");
    out
}

/// Serialise the advisory review to a stable JSON sidecar document.
/// `advisory_only: true` is part of the schema contract: a consumer can
/// assert this artifact never carries a verdict change.
pub(crate) fn to_json(outcome: &FpReviewOutcome) -> Result<String> {
    #[derive(Serialize)]
    struct Doc<'a> {
        schema: &'static str,
        advisory_only: bool,
        items: &'a [FpReviewItem],
    }

    let doc = Doc {
        schema: "skill-veil.fp-review.v1",
        advisory_only: true,
        items: &outcome.items,
    };
    serde_json::to_string_pretty(&doc).context("serialising FP review JSON")
}

/// Run the advisory, multi-provider LLM false-positive review. Returns
/// `Ok(None)` when not opted in, nothing is eligible, LLM enrichment is
/// unconfigured, or fewer than two consensus providers are configured.
/// Reuses `enrich_scan_result` per provider so the validated
/// prompt-injection hardening is inherited verbatim. Works on clones
/// only — the core scan result (and the `verdict_snapshot` anti-tamper
/// assertion) is never touched.
pub(crate) fn run_fp_review(
    scan_result: &PackageScanResult,
    scan_path: &Path,
    cache_dir_override: Option<&Path>,
    quiet: bool,
    opt_in: bool,
) -> Result<Option<FpReviewOutcome>> {
    if !opt_in {
        return Ok(None);
    }

    let eligible_idx: Vec<usize> = scan_result
        .results
        .iter()
        .enumerate()
        .filter(|(_, r)| result_fp_eligible(r))
        .map(|(i, _)| i)
        .collect();
    if eligible_idx.is_empty() {
        return Ok(None);
    }

    let filtered = PackageScanResult {
        results: eligible_idx
            .iter()
            .map(|&i| scan_result.results[i].clone())
            .collect(),
        errors: Vec::new(),
    };

    let Some(inputs): Option<LlmInputs> =
        prepare_llm_inputs(&filtered, scan_path, cache_dir_override, quiet)?
    else {
        return Ok(None);
    };

    let providers: Vec<LlmProviderKind> = resolve_consensus_providers(&inputs.section)
        .into_iter()
        .filter(|k| inputs.section.provider_configs.contains_key(k))
        .collect();
    if providers.len() < 2 {
        if !quiet {
            eprintln!(
                "LLM FP review skipped: needs ≥2 of openai/grok/ollama-cloud configured \
                 (found {}); no review applied",
                providers.len()
            );
        }
        return Ok(None);
    }

    let n = filtered.results.len();
    let mut votes: Vec<Vec<(String, Option<Verdict>)>> = vec![Vec::new(); n];
    for kind in &providers {
        let enrichment = match enrich_scan_result(
            &inputs.section,
            &inputs.opts(Some(*kind)),
            &filtered,
            inputs.bundles(),
        ) {
            Ok(e) => e,
            Err(e) => {
                if !quiet {
                    eprintln!("LLM FP review: provider {} failed: {e:#}", kind.as_str());
                }
                continue;
            }
        };
        for (i, pkg) in enrichment.packages.iter().take(n).enumerate() {
            let v = pkg
                .verdict
                .as_ref()
                .and_then(|lv| parse_provider_verdict(&lv.verdict));
            votes[i].push((kind.as_str().to_string(), v));
        }
    }

    let mut items = Vec::with_capacity(eligible_idx.len());
    for (fi, &orig_i) in eligible_idx.iter().enumerate() {
        let parsed: Vec<(String, Verdict)> = votes[fi]
            .iter()
            .filter_map(|(p, ov)| ov.map(|v| (p.clone(), v)))
            .collect();
        let error_votes = votes[fi].iter().filter(|(_, ov)| ov.is_none()).count();
        let (consensus, flipped_provider) = review_outcome_for(&parsed, error_votes);

        let r = &scan_result.results[orig_i];
        let suspected_fp_rule_ids = if consensus == FpReviewConsensus::SuspectedFalsePositive {
            fp_candidate_rule_ids(&r.findings)
        } else {
            Vec::new()
        };
        let suggested_action = if consensus == FpReviewConsensus::SuspectedFalsePositive {
            Some(RecommendedAction::Log)
        } else {
            None
        };
        let provider_votes = votes[fi]
            .iter()
            .map(|(p, ov)| FpProviderVote {
                provider: p.clone(),
                verdict: ov.map(|v| v.to_string()),
            })
            .collect();

        items.push(FpReviewItem {
            package: r
                .findings
                .first()
                .and_then(|f| f.artifact_path.clone())
                .unwrap_or_else(|| scan_path.display().to_string()),
            package_id: r.metadata.package_id.clone(),
            core_verdict: r.verdict,
            consensus,
            provider_votes,
            suspected_fp_rule_ids,
            suggested_action,
            flipped_provider,
        });
    }

    let report_block = render_block(&items);
    Ok(Some(FpReviewOutcome {
        items,
        report_block,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_veil_core::{Severity, ThreatCategory};

    fn finding(rule_id: &str, signal: SignalClass) -> Finding {
        Finding::builder(rule_id, ThreatCategory::SupplyChain)
            .severity(Severity::Medium)
            .signal_class(signal)
            .reason("test")
            .build()
    }

    #[test]
    fn fp_eligible_requires_suspicious_and_reviewable_finding() {
        assert!(fp_eligible(
            Verdict::Suspicious,
            &[finding("R1", SignalClass::ReviewSignal)]
        ));
    }

    #[test]
    fn fp_eligible_rejects_benign_and_malicious_verdicts() {
        let findings = [finding("R1", SignalClass::ReviewSignal)];
        assert!(!fp_eligible(Verdict::Benign, &findings));
        assert!(!fp_eligible(Verdict::Malicious, &findings));
    }

    #[test]
    fn fp_eligible_rejects_suspicious_with_only_malicious_or_hygiene_findings() {
        assert!(!fp_eligible(
            Verdict::Suspicious,
            &[
                finding("M1", SignalClass::MaliciousBehavior),
                finding("H1", SignalClass::Hygiene),
            ]
        ));
    }

    #[test]
    fn two_benign_providers_yield_suspected_false_positive() {
        let parsed = vec![
            ("openai".to_string(), Verdict::Benign),
            ("grok".to_string(), Verdict::Benign),
        ];
        let (consensus, flipped) = review_outcome_for(&parsed, 0);
        assert_eq!(consensus, FpReviewConsensus::SuspectedFalsePositive);
        assert!(flipped.is_none());
    }

    #[test]
    fn single_benign_flip_is_injection_not_false_positive() {
        let parsed = vec![
            ("openai".to_string(), Verdict::Benign),
            ("grok".to_string(), Verdict::Malicious),
            ("ollama-cloud".to_string(), Verdict::Suspicious),
        ];
        let (consensus, flipped) = review_outcome_for(&parsed, 0);
        assert_eq!(consensus, FpReviewConsensus::InjectionSuspected);
        assert_eq!(flipped.as_deref(), Some("openai"));
    }

    #[test]
    fn no_benign_majority_is_no_consensus() {
        let parsed = vec![
            ("openai".to_string(), Verdict::Suspicious),
            ("grok".to_string(), Verdict::Suspicious),
        ];
        let (consensus, flipped) = review_outcome_for(&parsed, 0);
        assert_eq!(consensus, FpReviewConsensus::NoConsensus);
        assert!(flipped.is_none());
    }

    #[test]
    fn candidate_rule_ids_dedup_and_exclude_non_reviewable() {
        let findings = vec![
            finding("R1", SignalClass::ReviewSignal),
            finding("R1", SignalClass::ReviewSignal),
            finding("S1", SignalClass::SuspiciousPackageBehavior),
            finding("M1", SignalClass::MaliciousBehavior),
        ];
        let ids = fp_candidate_rule_ids(&findings);
        assert_eq!(ids, vec!["R1".to_string(), "S1".to_string()]);
    }

    #[test]
    fn json_sidecar_marks_advisory_only() {
        let outcome = FpReviewOutcome {
            items: vec![FpReviewItem {
                package: "pkg/SKILL.md".to_string(),
                package_id: None,
                core_verdict: Verdict::Suspicious,
                consensus: FpReviewConsensus::SuspectedFalsePositive,
                provider_votes: vec![FpProviderVote {
                    provider: "openai".to_string(),
                    verdict: Some("benign".to_string()),
                }],
                suspected_fp_rule_ids: vec!["R1".to_string()],
                suggested_action: Some(RecommendedAction::Log),
                flipped_provider: None,
            }],
            report_block: String::new(),
        };
        let json = to_json(&outcome).unwrap();
        assert!(json.contains("\"advisory_only\": true"));
        assert!(json.contains("skill-veil.fp-review.v1"));
        assert!(json.contains("suspected_false_positive"));
    }

    #[test]
    fn render_block_states_advisory_contract() {
        let items = vec![FpReviewItem {
            package: "pkg/SKILL.md".to_string(),
            package_id: None,
            core_verdict: Verdict::Suspicious,
            consensus: FpReviewConsensus::SuspectedFalsePositive,
            provider_votes: vec![],
            suspected_fp_rule_ids: vec!["R1".to_string()],
            suggested_action: Some(RecommendedAction::Log),
            flipped_provider: None,
        }];
        let block = render_block(&items);
        assert!(block.contains("advisory only"));
        assert!(block.contains("never changes the skill-veil verdict"));
        assert!(block.contains("likely false positive"));
    }
}
