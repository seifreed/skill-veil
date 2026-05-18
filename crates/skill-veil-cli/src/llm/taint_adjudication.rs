//! Gated LLM adjudication for the `ARTIFACT_TAINT_*` false-positive
//! bucket (ADR 0029).
//!
//! # Why this exists
//!
//! `ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK` fires on the modal
//! benign skill that reads an API key and POSTs to its upstream API.
//! Static allowlists provably cannot separate "secret → obscure-but-
//! legitimate vendor API" from "secret → attacker host" (two
//! independent reverted rule experiments; see ADR 0029). A focused
//! cross-LLM triage validated that a tightly-gated downgrade recovers
//! 126 / 461 benign-corpus FPs while softening only 8 / 194
//! true-malicious (Malicious → Suspicious, still surfaced) — a
//! 15.75:1 favourable trade.
//!
//! # Security model — read this before touching anything
//!
//! The core scanner verdict (`ScanResult::verdict`) is and stays
//! IMMUTABLE. The `verdict_snapshot` anti-tamper assertion in
//! `commands::scan` remains valid because nothing here mutates the
//! scan result. This module only computes a *separate*, explicitly
//! labelled, opt-in (default-OFF) effective verdict used for an
//! appended report block and the process exit code. With the flag
//! off — the default, and what the regression corpus and every
//! existing operator see — behaviour is byte-identical to before.
//!
//! Letting a (potentially prompt-injectable) LLM soften a Block is a
//! deliberate trust trade the operator opts into. It is fenced by:
//! 1. A strict structural gate (taint-only Block driver, no
//!    conclusive rule, no compound chain).
//! 2. ≥2-of-3 distinct-provider `benign` consensus.
//! 3. A hardened adjudication prompt — inherited verbatim by reusing
//!    `enrich_scan_result` (the exact code path the validation triage
//!    exercised), whose system prompt mandates ignoring instructions
//!    embedded in the skill and wraps skill text in untrusted-blob
//!    markers.
//! 4. Downgrade target `Suspicious` (RequireApproval), NEVER
//!    `Benign`: analyst visibility is preserved.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;
use skill_veil_core::services::ScanFilterService;
use skill_veil_core::{
    Finding, PackageScanResult, RecommendedAction, ScanOptions, ScanResult, SignalClass, Verdict,
    VerdictReason,
};

use crate::commands::scan::llm::{prepare_llm_inputs, LlmInputs};
use crate::config::LlmProviderKind;
use crate::llm::enrich::enrich_scan_result;
use crate::util::terminal_safe::sanitise_for_terminal;

/// The two taint rules eligible for LLM-adjudicated downgrade. Kept
/// in sync with
/// `artifact_taint::analysis::TRUSTED_HOST_DOWNGRADE_RULE_IDS` — the
/// SECRET/IDENTITY external-network pair the corpus measured as the
/// dominant FP source.
pub(crate) const TAINT_DOWNGRADE_RULE_IDS: &[&str] = &[
    "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK",
    "ARTIFACT_TAINT_IDENTITY_TO_EXTERNAL_NETWORK",
];

/// Compound-chain verdict reasons carry this rationale prefix
/// (`verdict::compound`). A taint finding that only reached Malicious
/// *via* a compound chain is not a sole-taint-driver case.
const COMPOUND_RATIONALE_PREFIX: &str = "Compound verdict:";

/// The validated consensus trio. Adjudication requires ≥2 of these to
/// be configured AND ≥2 to independently return `benign`.
const CONSENSUS_PROVIDERS: &[LlmProviderKind] = &[
    LlmProviderKind::OpenAi,
    LlmProviderKind::Grok,
    LlmProviderKind::OllamaCloud,
];

/// Maximum chars of a filesystem path rendered in the adjudication
/// block. Long enough to identify the package, short enough to keep
/// the operator summary scannable.
const PATH_DISPLAY_CHARS: usize = 200;

/// `true` when the trio is the precise shape the validated downgrade
/// targets: core verdict `Malicious`, every Block-strength
/// `MaliciousBehavior` finding is one of [`TAINT_DOWNGRADE_RULE_IDS`]
/// (≥1 present), and no `MaliciousBehavior` compound-chain reason
/// contributed. A single non-taint Block-strength malicious finding,
/// a conclusive rule (different `rule_id`, excluded by the subset
/// check), or a compound chain defeats eligibility.
#[must_use]
pub(crate) fn taint_downgrade_eligible(
    verdict: Verdict,
    findings: &[Finding],
    verdict_reasons: &[VerdictReason],
) -> bool {
    if verdict != Verdict::Malicious {
        return false;
    }

    let mut saw_taint_block = false;
    for f in findings {
        if f.signal_class == SignalClass::MaliciousBehavior
            && f.recommended_action == RecommendedAction::Block
        {
            if TAINT_DOWNGRADE_RULE_IDS.contains(&f.rule_id.as_str()) {
                saw_taint_block = true;
            } else {
                return false;
            }
        }
    }
    if !saw_taint_block {
        return false;
    }

    let compound_malicious = verdict_reasons.iter().any(|r| {
        r.signal_class == SignalClass::MaliciousBehavior
            && r.rationale.starts_with(COMPOUND_RATIONALE_PREFIX)
    });
    !compound_malicious
}

/// Thin [`ScanResult`] wrapper over [`taint_downgrade_eligible`].
#[must_use]
pub(crate) fn result_eligible(r: &ScanResult) -> bool {
    taint_downgrade_eligible(r.verdict, &r.findings, &r.verdict_report.verdict_reasons)
}

/// Parse a provider verdict string into a [`Verdict`].
/// Case-insensitive, **fail-closed**: `malicious` is matched first so
/// a hedged "not malicious, looks benign" conservatively counts as
/// malicious; unknown / unparseable text returns `None` (the caller
/// treats `None` as a non-benign vote so an ambiguous provider
/// response can never drive a downgrade).
#[must_use]
pub(crate) fn parse_provider_verdict(raw: &str) -> Option<Verdict> {
    let s = raw.trim().to_ascii_lowercase();
    if s.contains("malicious") {
        Some(Verdict::Malicious)
    } else if s.contains("suspicious") {
        Some(Verdict::Suspicious)
    } else if s.contains("benign") {
        Some(Verdict::Benign)
    } else {
        None
    }
}

/// `true` when ≥2 DISTINCT providers returned `Benign`. Distinctness
/// is enforced via a set keyed on provider name so duplicate votes
/// from one provider cannot inflate the count.
#[must_use]
pub(crate) fn provider_consensus_benign(provider_verdicts: &[(String, Verdict)]) -> bool {
    let benign: BTreeSet<&str> = provider_verdicts
        .iter()
        .filter(|(_, v)| *v == Verdict::Benign)
        .map(|(p, _)| p.as_str())
        .collect();
    benign.len() >= 2
}

/// Pure reconciliation. Returns the verdict to use for the appended
/// report block / exit code. Returns `Suspicious` iff ALL hold:
/// `opt_in`, core == `Malicious`, `eligible`, `consensus_benign`;
/// otherwise `core` unchanged. NEVER returns `Benign`.
#[must_use]
pub(crate) fn effective_verdict(
    core: Verdict,
    opt_in: bool,
    eligible: bool,
    consensus_benign: bool,
) -> Verdict {
    if opt_in && eligible && consensus_benign && core == Verdict::Malicious {
        Verdict::Suspicious
    } else {
        core
    }
}

/// Outcome of an adjudication pass. Never carries a mutated
/// `ScanResult`; the caller prints `report_block` and uses
/// `effective_should_fail` for the exit code only.
pub(crate) struct AdjudicationOutcome {
    /// `OR` of (non-downgraded `r.should_fail`) and (downgraded
    /// packages' `should_fail` recomputed with taint Block findings
    /// lowered to RequireApproval). Correct under any `--fail-on`.
    pub(crate) effective_should_fail: bool,
    /// Sanitised, operator-facing block. Empty string ⇒ nothing
    /// downgraded (caller still prints it; it states "no packages
    /// met the gate / consensus").
    pub(crate) report_block: String,
}

/// Lower the action of this package's eligible-taint findings from
/// `Block` to `RequireApproval` in a CLONE, then ask the real filter
/// service whether the package still fails under the operator's
/// `--fail-on`. Never mutates the scan result.
fn downgraded_should_fail(filter: &ScanFilterService, result: &ScanResult) -> bool {
    let adjusted: Vec<Finding> = result
        .findings
        .iter()
        .map(|f| {
            let mut c = f.clone();
            if TAINT_DOWNGRADE_RULE_IDS.contains(&c.rule_id.as_str())
                && c.signal_class == SignalClass::MaliciousBehavior
                && c.recommended_action == RecommendedAction::Block
            {
                c.recommended_action = RecommendedAction::RequireApproval;
            }
            c
        })
        .collect();
    filter.should_fail(&adjusted)
}

/// Run the gated, multi-provider taint adjudication. Returns
/// `Ok(None)` (nothing to do) when no package is eligible, LLM
/// enrichment is unconfigured, or fewer than two consensus providers
/// are configured. Reuses `enrich_scan_result` per provider so the
/// validated prompt-injection hardening is inherited verbatim.
pub(crate) fn run_taint_adjudication(
    scan_result: &PackageScanResult,
    scan_path: &Path,
    cache_dir_override: Option<&Path>,
    scan_options: &ScanOptions,
    quiet: bool,
) -> Result<Option<AdjudicationOutcome>> {
    // 1. Eligible original indices.
    let eligible_idx: Vec<usize> = scan_result
        .results
        .iter()
        .enumerate()
        .filter(|(_, r)| result_eligible(r))
        .map(|(i, _)| i)
        .collect();
    if eligible_idx.is_empty() {
        return Ok(None);
    }

    // 2. Filtered scan result (clones only — core untouched).
    let filtered = PackageScanResult {
        results: eligible_idx
            .iter()
            .map(|&i| scan_result.results[i].clone())
            .collect(),
        errors: Vec::new(),
    };

    // 3. Owned inputs (reuses the committed prepare_llm_inputs).
    let Some(inputs): Option<LlmInputs> =
        prepare_llm_inputs(&filtered, scan_path, cache_dir_override, quiet)?
    else {
        return Ok(None);
    };

    // 4. Consensus providers actually configured.
    let providers: Vec<LlmProviderKind> = CONSENSUS_PROVIDERS
        .iter()
        .copied()
        .filter(|k| inputs.section.provider_configs.contains_key(k))
        .collect();
    if providers.len() < 2 {
        if !quiet {
            eprintln!(
                "taint adjudication skipped: needs ≥2 of openai/grok/ollama-cloud configured \
                 (found {}); no downgrade applied",
                providers.len()
            );
        }
        return Ok(None);
    }

    // 5. Per-provider enrichment → votes keyed by filtered index.
    let n = filtered.results.len();
    let mut votes: Vec<Vec<(String, Verdict)>> = vec![Vec::new(); n];
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
                    eprintln!(
                        "taint adjudication: provider {} failed: {e:#}",
                        kind.as_str()
                    );
                }
                continue;
            }
        };
        // enrich_scan_result preserves result order (it zips
        // scan_result.results with bundles), so index alignment is
        // safe even when package_id is None.
        for (i, pkg) in enrichment.packages.iter().take(n).enumerate() {
            let v = pkg
                .verdict
                .as_ref()
                .and_then(|lv| parse_provider_verdict(&lv.verdict))
                // Fail-closed: a missing / unparseable verdict is a
                // non-benign vote and cannot help reach consensus.
                .unwrap_or(Verdict::Malicious);
            votes[i].push((kind.as_str().to_string(), v));
        }
    }

    // 6. Consensus → downgraded original indices.
    let mut downgraded: BTreeMap<usize, Vec<(String, Verdict)>> = BTreeMap::new();
    for (fi, &orig_i) in eligible_idx.iter().enumerate() {
        let consensus = provider_consensus_benign(&votes[fi]);
        let eff = effective_verdict(Verdict::Malicious, true, true, consensus);
        if eff == Verdict::Suspicious {
            downgraded.insert(orig_i, votes[fi].clone());
        }
    }

    // 7. Effective exit code (clones only; verdict_snapshot intact).
    let filter = ScanFilterService::new(scan_options.clone());
    let mut effective_should_fail = false;
    for (i, r) in scan_result.results.iter().enumerate() {
        let fails = if downgraded.contains_key(&i) {
            downgraded_should_fail(&filter, r)
        } else {
            r.should_fail
        };
        effective_should_fail |= fails;
    }

    // 8. Sanitised operator-facing block.
    let report_block = render_block(scan_result, &downgraded, &providers);

    Ok(Some(AdjudicationOutcome {
        effective_should_fail,
        report_block,
    }))
}

fn render_block(
    scan_result: &PackageScanResult,
    downgraded: &BTreeMap<usize, Vec<(String, Verdict)>>,
    providers: &[LlmProviderKind],
) -> String {
    let mut out = String::new();
    out.push_str(
        "\n=== Taint adjudication (LLM consensus; AFFECTS effective verdict + exit code) ===\n",
    );
    let trio: Vec<&str> = providers.iter().map(|p| p.as_str()).collect();
    let _ = writeln!(
        out,
        "consensus providers: {} | gate: taint-only Block driver, no conclusive/compound \
         | downgrade: Malicious → Suspicious (never Benign)",
        trio.join("+")
    );
    if downgraded.is_empty() {
        out.push_str(
            "no Malicious package met the gate + ≥2-of-3 benign consensus; \
                      no downgrade applied\n",
        );
        return out;
    }
    let _ = writeln!(
        out,
        "{} package(s) softened Malicious → Suspicious (still surfaced for review):",
        downgraded.len()
    );
    for (&i, votes) in downgraded {
        let r = &scan_result.results[i];
        let id = r
            .metadata
            .package_id
            .as_deref()
            .map(|s| sanitise_for_terminal(&s.chars().take(12).collect::<String>()))
            .unwrap_or_else(|| "(no id)".to_string());
        let path = sanitise_for_terminal(
            &r.metadata
                .path
                .display()
                .to_string()
                .chars()
                .take(PATH_DISPLAY_CHARS)
                .collect::<String>(),
        );
        let taint_rules: BTreeSet<&str> = r
            .findings
            .iter()
            .filter(|f| {
                TAINT_DOWNGRADE_RULE_IDS.contains(&f.rule_id.as_str())
                    && f.signal_class == SignalClass::MaliciousBehavior
            })
            .map(|f| f.rule_id.as_str())
            .collect();
        let votes_str: Vec<String> = votes.iter().map(|(p, v)| format!("{p}={v:?}")).collect();
        let _ = writeln!(
            out,
            "  {id}… {path}\n    rule(s): {} | votes: {}",
            taint_rules.into_iter().collect::<Vec<_>>().join(","),
            votes_str.join(" ")
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_veil_core::{ArtifactKind, EvidenceKind, MatchTarget, Severity, ThreatCategory};

    fn finding(rule_id: &str, sc: SignalClass, act: RecommendedAction) -> Finding {
        Finding::builder(rule_id, ThreatCategory::DataExfiltration)
            .severity(Severity::Critical)
            .confidence(0.9)
            .action(act)
            .evidence_kind(EvidenceKind::Behavior)
            .artifact(ArtifactKind::SkillDocument, Some("SKILL.md".to_string()))
            .matched_on(MatchTarget::Document)
            .signal_class(sc)
            .build()
    }

    fn compound_reason() -> VerdictReason {
        VerdictReason {
            scope: skill_veil_core::ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::DataExfiltration,
            signal_class: SignalClass::MaliciousBehavior,
            rationale: "Compound verdict: token or session access is paired with outbound \
                        transmission"
                .to_string(),
        }
    }

    /// Contract: with opt-in OFF the effective verdict is ALWAYS the
    /// core verdict — the byte-identical default-path guarantee.
    #[test]
    fn opt_in_off_is_always_identity() {
        for core in [Verdict::Benign, Verdict::Suspicious, Verdict::Malicious] {
            for e in [false, true] {
                for c in [false, true] {
                    assert_eq!(effective_verdict(core, false, e, c), core);
                }
            }
        }
    }

    /// Contract: downgrade fires only for Malicious+eligible+consensus
    /// and only to Suspicious — never Benign.
    #[test]
    fn downgrade_only_malicious_and_only_to_suspicious() {
        assert_eq!(
            effective_verdict(Verdict::Malicious, true, true, true),
            Verdict::Suspicious
        );
        assert_eq!(
            effective_verdict(Verdict::Malicious, true, false, true),
            Verdict::Malicious
        );
        assert_eq!(
            effective_verdict(Verdict::Malicious, true, true, false),
            Verdict::Malicious
        );
        assert_eq!(
            effective_verdict(Verdict::Benign, true, true, true),
            Verdict::Benign
        );
        assert_eq!(
            effective_verdict(Verdict::Suspicious, true, true, true),
            Verdict::Suspicious
        );
    }

    /// Contract: ≥2 DISTINCT providers must vote benign.
    #[test]
    fn consensus_requires_two_distinct_providers() {
        assert!(!provider_consensus_benign(&[(
            "openai".into(),
            Verdict::Benign
        )]));
        assert!(!provider_consensus_benign(&[
            ("grok".into(), Verdict::Benign),
            ("grok".into(), Verdict::Benign),
        ]));
        assert!(provider_consensus_benign(&[
            ("openai".into(), Verdict::Benign),
            ("grok".into(), Verdict::Benign),
        ]));
        assert!(!provider_consensus_benign(&[
            ("openai".into(), Verdict::Benign),
            ("grok".into(), Verdict::Malicious),
            ("ollama-cloud".into(), Verdict::Suspicious),
        ]));
    }

    /// Contract: provider verdict parsing is case-insensitive and
    /// fails closed.
    #[test]
    fn provider_verdict_parsing_fails_closed() {
        assert_eq!(parse_provider_verdict("benign"), Some(Verdict::Benign));
        assert_eq!(parse_provider_verdict("  BENIGN "), Some(Verdict::Benign));
        assert_eq!(
            parse_provider_verdict("verdict: malicious"),
            Some(Verdict::Malicious)
        );
        assert_eq!(
            parse_provider_verdict("Suspicious — review"),
            Some(Verdict::Suspicious)
        );
        assert_eq!(parse_provider_verdict(""), None);
        assert_eq!(parse_provider_verdict("cannot determine"), None);
        assert_eq!(
            parse_provider_verdict("not malicious, looks benign"),
            Some(Verdict::Malicious)
        );
    }

    /// Contract: a Malicious package whose only Block-strength
    /// malicious finding is a taint rule, with no compound reason, is
    /// eligible.
    #[test]
    fn gate_taint_only_block_is_eligible() {
        let f = vec![
            finding(
                "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK",
                SignalClass::MaliciousBehavior,
                RecommendedAction::Block,
            ),
            // Non-block noise must not disqualify.
            finding(
                "SOME_HYGIENE_RULE",
                SignalClass::Hygiene,
                RecommendedAction::Log,
            ),
        ];
        assert!(taint_downgrade_eligible(Verdict::Malicious, &f, &[]));
    }

    /// Contract (negative): a second, non-taint Block-strength
    /// malicious finding defeats eligibility (not the FP shape).
    #[test]
    fn gate_extra_block_rule_not_eligible() {
        let f = vec![
            finding(
                "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK",
                SignalClass::MaliciousBehavior,
                RecommendedAction::Block,
            ),
            finding(
                "SKILL_MACOS_BASE64_RCE",
                SignalClass::MaliciousBehavior,
                RecommendedAction::Block,
            ),
        ];
        assert!(!taint_downgrade_eligible(Verdict::Malicious, &f, &[]));
    }

    /// Contract (negative): a MaliciousBehavior compound-chain reason
    /// defeats eligibility even when the only Block finding is taint.
    #[test]
    fn gate_compound_malicious_reason_not_eligible() {
        let f = vec![finding(
            "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK",
            SignalClass::MaliciousBehavior,
            RecommendedAction::Block,
        )];
        assert!(!taint_downgrade_eligible(
            Verdict::Malicious,
            &f,
            &[compound_reason()]
        ));
    }

    /// Contract (negative): a non-Malicious core verdict, or no taint
    /// Block driver at all, is never eligible.
    #[test]
    fn gate_non_malicious_not_eligible() {
        let taint = vec![finding(
            "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK",
            SignalClass::MaliciousBehavior,
            RecommendedAction::Block,
        )];
        assert!(!taint_downgrade_eligible(Verdict::Suspicious, &taint, &[]));
        assert!(!taint_downgrade_eligible(Verdict::Benign, &taint, &[]));
        // Malicious but no taint Block driver → not eligible.
        let other = vec![finding(
            "SKILL_MACOS_BASE64_RCE",
            SignalClass::MaliciousBehavior,
            RecommendedAction::Block,
        )];
        assert!(!taint_downgrade_eligible(Verdict::Malicious, &other, &[]));
    }
}
