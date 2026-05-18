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
    is_conclusive_single_rule_id, ConsensusDiscrepancy, Finding, PackageScanResult, ProviderVote,
    RecommendedAction, ScanOptions, ScanResult, SignalClass, Verdict, VerdictReason,
};

use crate::commands::scan::llm::{prepare_llm_inputs, LlmInputs};
use crate::config::{LlmConfigSection, LlmProviderKind};
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

/// The exfil/credential rule families whose single-rule fire is held
/// at `Suspicious` by the corroboration gate but is a confirmed
/// soft-FN when ≥2-of-3 providers independently judge it malicious.
///
/// Mirror of [`TAINT_DOWNGRADE_RULE_IDS`] in the false-NEGATIVE
/// direction. Chosen conservatively from `residual-fn-by-rule.tsv`:
/// only families with a non-zero recovered-FN count AND zero recorded
/// benign FP in the triage snapshot. The LLM consensus is precisely
/// the FP guard these static single-regex rules individually lack —
/// the upgrade fires ONLY when 2+ independent providers confirm
/// malicious, never on the static signal alone.
///
/// `ARTIFACT_TAINT_*` is deliberately EXCLUDED: it is the *downgrade*
/// target, so upgrading it would directly contradict ADR 0029.
/// Broad/hygiene families are excluded (unacceptable benign FP cost,
/// zero recoverable signal). The list is expandable ONLY with fresh
/// `adjudication-eval` corpus evidence — the snapshot it was derived
/// from is stale by construction.
pub(crate) const FN_UPGRADE_RULE_IDS: &[&str] = &[
    "SKILL_CREDENTIAL_FORWARDING_POST",
    "SCRIPT_NODE_SECRET_OR_FS_ACCESS",
    "SCRIPT_PYTHON_SECRET_OR_SYSTEM_ACCESS",
    "SKILL_CRED_HARDCODED_KEY",
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

/// The consensus provider set for this run. The validated trio
/// ([`CONSENSUS_PROVIDERS`]) unless the operator set a non-empty
/// `[llm.limits] consensus_providers` override (gate any such change
/// through `skill-veil adjudication-eval` — broadening it trades the
/// validated 15.75:1 calibration). The single resolution point so the
/// default stays byte-identical.
#[must_use]
pub(crate) fn resolve_consensus_providers(section: &LlmConfigSection) -> Vec<LlmProviderKind> {
    match section.limits.consensus_providers.as_deref() {
        Some(p) if !p.is_empty() => p.to_vec(),
        _ => CONSENSUS_PROVIDERS.to_vec(),
    }
}

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

/// `true` when the package is the FN soft-negative shape the symmetric
/// upgrade targets: core verdict `Suspicious`, at least one
/// [`FN_UPGRADE_RULE_IDS`] `MaliciousBehavior` finding that materially
/// drove the verdict (action ≥ `RequireApproval`), no conclusive
/// single-rule finding (else the core would already be `Malicious`),
/// and no Block-strength `MaliciousBehavior` driver from a rule
/// OUTSIDE the FN set (mirror of the downgrade gate's second-driver
/// disqualifier — a package borderline for unrelated reasons is not
/// this shape).
#[must_use]
pub(crate) fn fn_upgrade_eligible(
    verdict: Verdict,
    findings: &[Finding],
    has_conclusive_single_rule: bool,
) -> bool {
    if verdict != Verdict::Suspicious || has_conclusive_single_rule {
        return false;
    }

    let mut saw_fn_driver = false;
    for f in findings {
        if f.signal_class != SignalClass::MaliciousBehavior {
            continue;
        }
        let is_fn_rule = FN_UPGRADE_RULE_IDS.contains(&f.rule_id.as_str());
        if f.recommended_action == RecommendedAction::Block && !is_fn_rule {
            return false;
        }
        if is_fn_rule && f.recommended_action >= RecommendedAction::RequireApproval {
            saw_fn_driver = true;
        }
    }
    saw_fn_driver
}

/// Thin [`ScanResult`] wrapper over [`fn_upgrade_eligible`]. Derives
/// the conclusive-rule precondition from the curated core set via the
/// public accessor so the gate cannot drift from it.
#[must_use]
pub(crate) fn result_upgrade_eligible(r: &ScanResult) -> bool {
    let has_conclusive = r
        .findings
        .iter()
        .any(|f| is_conclusive_single_rule_id(&f.rule_id));
    fn_upgrade_eligible(r.verdict, &r.findings, has_conclusive)
}

/// `true` when ≥2 DISTINCT providers returned `Malicious`. Distinctness
/// is enforced via a set keyed on provider name. The symmetric
/// fail-closed direction to [`provider_consensus_benign`]: an
/// ambiguous / unparseable provider response is NOT a malicious vote,
/// so it can never drive an upgrade.
#[must_use]
pub(crate) fn provider_consensus_malicious(provider_verdicts: &[(String, Verdict)]) -> bool {
    let malicious: BTreeSet<&str> = provider_verdicts
        .iter()
        .filter(|(_, v)| *v == Verdict::Malicious)
        .map(|(p, _)| p.as_str())
        .collect();
    malicious.len() >= 2
}

/// Pure reconciliation for the FN upgrade. Returns `Malicious` iff ALL
/// hold: `opt_in`, core == `Suspicious`, `eligible`,
/// `consensus_malicious`; otherwise `core` unchanged. NEVER upgrades
/// `Benign` (a two-step jump) and NEVER touches an existing
/// `Malicious`.
#[must_use]
pub(crate) fn effective_verdict_upgrade(
    core: Verdict,
    opt_in: bool,
    eligible: bool,
    consensus_malicious: bool,
) -> Verdict {
    if opt_in && eligible && consensus_malicious && core == Verdict::Suspicious {
        Verdict::Malicious
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

/// Raise this package's eligible FN-upgrade findings to `Block` in a
/// CLONE, then ask the filter whether it now fails under the
/// operator's `--fail-on`. The symmetric mirror of
/// [`downgraded_should_fail`]. Never mutates the scan result.
fn upgraded_should_fail(filter: &ScanFilterService, result: &ScanResult) -> bool {
    let adjusted: Vec<Finding> = result
        .findings
        .iter()
        .map(|f| {
            let mut c = f.clone();
            if FN_UPGRADE_RULE_IDS.contains(&c.rule_id.as_str())
                && c.signal_class == SignalClass::MaliciousBehavior
                && c.recommended_action < RecommendedAction::Block
            {
                c.recommended_action = RecommendedAction::Block;
            }
            c
        })
        .collect();
    filter.should_fail(&adjusted)
}

/// Run the gated, multi-provider LLM adjudication. Composes the
/// ADR-0029 downgrade (`Malicious → Suspicious`) and its symmetric FN
/// upgrade (`Suspicious → Malicious`); each is independently opt-in.
/// Returns `Ok(None)` when neither lever is enabled, nothing is
/// eligible, LLM enrichment is unconfigured, or fewer than two
/// consensus providers are configured. Reuses `enrich_scan_result`
/// per provider so the validated prompt-injection hardening is
/// inherited verbatim. Works on clones only — the core scan result
/// (and the `verdict_snapshot` anti-tamper assertion) is never
/// touched. The two gates are partitioned by core verdict
/// (`Malicious` vs `Suspicious`) so no package is ever both.
pub(crate) fn run_adjudication(
    scan_result: &PackageScanResult,
    scan_path: &Path,
    cache_dir_override: Option<&Path>,
    scan_options: &ScanOptions,
    quiet: bool,
    downgrade_opt_in: bool,
    upgrade_opt_in: bool,
) -> Result<Option<AdjudicationOutcome>> {
    if !downgrade_opt_in && !upgrade_opt_in {
        return Ok(None);
    }

    // 1. Eligible original indices, partitioned by direction. The
    //    gates are mutually exclusive (Malicious vs Suspicious core),
    //    so a package lands in at most one set.
    let mut is_downgrade: BTreeSet<usize> = BTreeSet::new();
    let mut is_upgrade: BTreeSet<usize> = BTreeSet::new();
    for (i, r) in scan_result.results.iter().enumerate() {
        if downgrade_opt_in && result_eligible(r) {
            is_downgrade.insert(i);
        } else if upgrade_opt_in && result_upgrade_eligible(r) {
            is_upgrade.insert(i);
        }
    }
    let eligible_idx: Vec<usize> = is_downgrade
        .iter()
        .chain(is_upgrade.iter())
        .copied()
        .collect::<BTreeSet<usize>>()
        .into_iter()
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
    let providers: Vec<LlmProviderKind> = resolve_consensus_providers(&inputs.section)
        .into_iter()
        .filter(|k| inputs.section.provider_configs.contains_key(k))
        .collect();
    if providers.len() < 2 {
        if !quiet {
            eprintln!(
                "LLM adjudication skipped: needs ≥2 of openai/grok/ollama-cloud configured \
                 (found {}); no adjudication applied",
                providers.len()
            );
        }
        return Ok(None);
    }

    // 5. Per-provider enrichment → votes keyed by filtered index. A
    //    missing / unparseable verdict is recorded as `None` and
    //    dropped from BOTH consensus computations, so the fail-closed
    //    guarantee holds in BOTH directions: an ambiguous provider can
    //    neither force a downgrade (not a benign vote) nor an upgrade
    //    (not a malicious vote).
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
                    eprintln!("LLM adjudication: provider {} failed: {e:#}", kind.as_str());
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
                .and_then(|lv| parse_provider_verdict(&lv.verdict));
            votes[i].push((kind.as_str().to_string(), v));
        }
    }

    // 6. Consensus → per-direction changed maps.
    let mut downgraded: BTreeMap<usize, Vec<(String, Option<Verdict>)>> = BTreeMap::new();
    let mut upgraded: BTreeMap<usize, Vec<(String, Option<Verdict>)>> = BTreeMap::new();
    // Packages where exactly one provider flipped to benign while ≥2
    // disagreed (no errors). This is the prompt-injection signature
    // ADR 0029's softening is vulnerable to — we BLOCK the downgrade
    // and fail, turning the manipulation into a louder signal rather
    // than a free path to a softer verdict.
    let mut injection_suspected: BTreeMap<usize, String> = BTreeMap::new();
    for (fi, &orig_i) in eligible_idx.iter().enumerate() {
        let parsed: Vec<(String, Verdict)> = votes[fi]
            .iter()
            .filter_map(|(p, ov)| ov.map(|v| (p.clone(), v)))
            .collect();
        if is_downgrade.contains(&orig_i) {
            let provider_votes: Vec<ProviderVote> = parsed
                .iter()
                .map(|(p, v)| ProviderVote {
                    provider: p.clone(),
                    verdict: *v,
                    confidence: 0.0,
                })
                .collect();
            let error_votes = votes[fi].iter().filter(|(_, ov)| ov.is_none()).count();
            let discrepancy = ConsensusDiscrepancy::from_votes(provider_votes, error_votes);
            if discrepancy.is_single_provider_benign_flip() {
                let flipped = discrepancy.flipped_provider().unwrap_or("?").to_string();
                injection_suspected.insert(orig_i, flipped);
                // Do NOT downgrade a flip-detected package, even if a
                // (counterfactually impossible) benign consensus were
                // reached — the explicit guard documents the contract.
                continue;
            }
            let eff = effective_verdict(
                Verdict::Malicious,
                true,
                true,
                provider_consensus_benign(&parsed),
            );
            if eff == Verdict::Suspicious {
                downgraded.insert(orig_i, votes[fi].clone());
            }
        } else if is_upgrade.contains(&orig_i) {
            let eff = effective_verdict_upgrade(
                Verdict::Suspicious,
                true,
                true,
                provider_consensus_malicious(&parsed),
            );
            if eff == Verdict::Malicious {
                upgraded.insert(orig_i, votes[fi].clone());
            }
        }
    }

    // 7. Effective exit code (clones only; verdict_snapshot intact).
    let filter = ScanFilterService::new(scan_options.clone());
    let mut effective_should_fail = false;
    for (i, r) in scan_result.results.iter().enumerate() {
        let fails = if injection_suspected.contains_key(&i) {
            // A flip-detected package ALWAYS fails — the injection
            // signal raises the effective verdict, never softens it.
            true
        } else if downgraded.contains_key(&i) {
            downgraded_should_fail(&filter, r)
        } else if upgraded.contains_key(&i) {
            upgraded_should_fail(&filter, r)
        } else {
            r.should_fail
        };
        effective_should_fail |= fails;
    }

    // 8. Sanitised operator-facing block.
    let report_block = render_block(
        scan_result,
        downgrade_opt_in,
        upgrade_opt_in,
        &downgraded,
        &upgraded,
        &injection_suspected,
        &providers,
    );

    Ok(Some(AdjudicationOutcome {
        effective_should_fail,
        report_block,
    }))
}

fn render_votes(votes: &[(String, Option<Verdict>)]) -> String {
    votes
        .iter()
        .map(|(p, ov)| match ov {
            Some(v) => format!("{p}={v:?}"),
            None => format!("{p}=error"),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn render_changed_section(
    out: &mut String,
    transition: &str,
    rule_ids: &[&str],
    scan_result: &PackageScanResult,
    changed: &BTreeMap<usize, Vec<(String, Option<Verdict>)>>,
) {
    let _ = writeln!(
        out,
        "{} package(s) {} — core verdict unchanged (JSON/SARIF unaffected):",
        changed.len(),
        transition
    );
    for (&i, votes) in changed {
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
        let rules: BTreeSet<&str> = r
            .findings
            .iter()
            .filter(|f| {
                rule_ids.contains(&f.rule_id.as_str())
                    && f.signal_class == SignalClass::MaliciousBehavior
            })
            .map(|f| f.rule_id.as_str())
            .collect();
        let _ = writeln!(
            out,
            "  {id}… {path}\n    rule(s): {} | votes: {}",
            rules.into_iter().collect::<Vec<_>>().join(","),
            render_votes(votes)
        );
    }
}

/// Synthetic rule id surfaced (in the report + exit code only — never
/// injected into the immutable scan result) when a single provider was
/// flipped benign against ≥2 dissenters.
const INJECTION_RULE_ID: &str = "LLM_CONSENSUS_PROMPT_INJECTION_SUSPECTED";

fn render_block(
    scan_result: &PackageScanResult,
    downgrade_opt_in: bool,
    upgrade_opt_in: bool,
    downgraded: &BTreeMap<usize, Vec<(String, Option<Verdict>)>>,
    upgraded: &BTreeMap<usize, Vec<(String, Option<Verdict>)>>,
    injection_suspected: &BTreeMap<usize, String>,
    providers: &[LlmProviderKind],
) -> String {
    let mut out = String::new();
    out.push_str("\n=== LLM adjudication (consensus; AFFECTS effective verdict + exit code) ===\n");
    let trio: Vec<&str> = providers.iter().map(|p| p.as_str()).collect();
    let _ = writeln!(out, "consensus providers: {}", trio.join("+"));

    if !injection_suspected.is_empty() {
        let _ = writeln!(
            out,
            "⚠ {INJECTION_RULE_ID}: {} package(s) had a single-provider benign \
             flip (≥2 dissenters, no errors) — downgrade BLOCKED, exit code \
             FAILS:",
            injection_suspected.len()
        );
        for (&i, flipped) in injection_suspected {
            let id = scan_result.results[i]
                .metadata
                .package_id
                .as_deref()
                .map(|s| sanitise_for_terminal(&s.chars().take(12).collect::<String>()))
                .unwrap_or_else(|| "(no id)".to_string());
            let _ = writeln!(
                out,
                "  {id}… flipped provider: {}",
                sanitise_for_terminal(flipped)
            );
        }
    }

    if downgrade_opt_in {
        out.push_str(
            "downgrade gate: taint-only Block driver, no conclusive/compound \
             | Malicious → Suspicious (never Benign)\n",
        );
        if downgraded.is_empty() {
            out.push_str("  no Malicious package met the gate + ≥2-of-3 benign consensus\n");
        } else {
            render_changed_section(
                &mut out,
                "softened Malicious → Suspicious",
                TAINT_DOWNGRADE_RULE_IDS,
                scan_result,
                downgraded,
            );
        }
    }
    if upgrade_opt_in {
        out.push_str(
            "upgrade gate: FN-rule single driver, no conclusive, core Suspicious \
             | Suspicious → Malicious (never from Benign)\n",
        );
        if upgraded.is_empty() {
            out.push_str("  no Suspicious package met the gate + ≥2-of-3 malicious consensus\n");
        } else {
            render_changed_section(
                &mut out,
                "escalated Suspicious → Malicious",
                FN_UPGRADE_RULE_IDS,
                scan_result,
                upgraded,
            );
        }
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

    /// Contract: with the upgrade lever OFF the effective verdict is
    /// ALWAYS the core verdict — the byte-identical default-path
    /// guarantee, mirror of `opt_in_off_is_always_identity`.
    #[test]
    fn upgrade_off_is_always_identity() {
        for core in [Verdict::Benign, Verdict::Suspicious, Verdict::Malicious] {
            for e in [false, true] {
                for c in [false, true] {
                    assert_eq!(effective_verdict_upgrade(core, false, e, c), core);
                }
            }
        }
    }

    /// Contract: the upgrade fires only for
    /// Suspicious+eligible+consensus and only to Malicious — never
    /// from Benign (a two-step jump) and never onto an existing
    /// Malicious.
    #[test]
    fn upgrade_only_suspicious_and_only_to_malicious() {
        assert_eq!(
            effective_verdict_upgrade(Verdict::Suspicious, true, true, true),
            Verdict::Malicious
        );
        assert_eq!(
            effective_verdict_upgrade(Verdict::Suspicious, true, false, true),
            Verdict::Suspicious
        );
        assert_eq!(
            effective_verdict_upgrade(Verdict::Suspicious, true, true, false),
            Verdict::Suspicious
        );
        assert_eq!(
            effective_verdict_upgrade(Verdict::Benign, true, true, true),
            Verdict::Benign
        );
        assert_eq!(
            effective_verdict_upgrade(Verdict::Malicious, true, true, true),
            Verdict::Malicious
        );
    }

    /// Contract: ≥2 DISTINCT providers must vote malicious; duplicate
    /// votes from one provider and mixed/benign votes do not reach
    /// consensus (symmetric to `consensus_requires_two_distinct_providers`).
    #[test]
    fn upgrade_consensus_requires_two_distinct_malicious() {
        assert!(!provider_consensus_malicious(&[(
            "openai".into(),
            Verdict::Malicious
        )]));
        assert!(!provider_consensus_malicious(&[
            ("grok".into(), Verdict::Malicious),
            ("grok".into(), Verdict::Malicious),
        ]));
        assert!(provider_consensus_malicious(&[
            ("openai".into(), Verdict::Malicious),
            ("grok".into(), Verdict::Malicious),
        ]));
        assert!(!provider_consensus_malicious(&[
            ("openai".into(), Verdict::Malicious),
            ("grok".into(), Verdict::Benign),
            ("ollama-cloud".into(), Verdict::Suspicious),
        ]));
    }

    /// Contract: a Suspicious package whose driver is a single
    /// FN-upgrade rule (MaliciousBehavior, action ≥ RequireApproval),
    /// with no conclusive rule present, is upgrade-eligible.
    #[test]
    fn fn_upgrade_gate_single_fn_rule_no_conclusive_is_eligible() {
        let f = vec![
            finding(
                "SKILL_CREDENTIAL_FORWARDING_POST",
                SignalClass::MaliciousBehavior,
                RecommendedAction::RequireApproval,
            ),
            finding(
                "SOME_HYGIENE_RULE",
                SignalClass::Hygiene,
                RecommendedAction::Log,
            ),
        ];
        assert!(fn_upgrade_eligible(Verdict::Suspicious, &f, false));
    }

    /// Contract (negative): a conclusive single-rule finding means the
    /// core would already be Malicious — never upgrade-eligible.
    #[test]
    fn fn_upgrade_gate_conclusive_rule_present_not_eligible() {
        let f = vec![finding(
            "SKILL_CREDENTIAL_FORWARDING_POST",
            SignalClass::MaliciousBehavior,
            RecommendedAction::RequireApproval,
        )];
        assert!(!fn_upgrade_eligible(Verdict::Suspicious, &f, true));
    }

    /// Contract (negative): a Block-strength MaliciousBehavior driver
    /// from a rule OUTSIDE the FN set defeats eligibility (mirror of
    /// the downgrade gate's second-driver disqualifier).
    #[test]
    fn fn_upgrade_gate_non_fn_block_rule_not_eligible() {
        let f = vec![
            finding(
                "SKILL_CREDENTIAL_FORWARDING_POST",
                SignalClass::MaliciousBehavior,
                RecommendedAction::RequireApproval,
            ),
            finding(
                "SKILL_SOME_OTHER_RULE",
                SignalClass::MaliciousBehavior,
                RecommendedAction::Block,
            ),
        ];
        assert!(!fn_upgrade_eligible(Verdict::Suspicious, &f, false));
    }

    /// Contract (negative): a non-Suspicious core (Benign or
    /// Malicious) is never upgrade-eligible.
    #[test]
    fn fn_upgrade_gate_non_suspicious_core_not_eligible() {
        let f = vec![finding(
            "SCRIPT_PYTHON_SECRET_OR_SYSTEM_ACCESS",
            SignalClass::MaliciousBehavior,
            RecommendedAction::RequireApproval,
        )];
        assert!(!fn_upgrade_eligible(Verdict::Benign, &f, false));
        assert!(!fn_upgrade_eligible(Verdict::Malicious, &f, false));
    }

    /// Contract: the two gates are mutually exclusive — for ANY
    /// finding set and ANY core verdict, a package is never
    /// simultaneously downgrade- and upgrade-eligible (the gates are
    /// partitioned by `Malicious` vs `Suspicious` core). Proves the
    /// composition in `run_adjudication` is conflict-free.
    #[test]
    fn downgrade_and_upgrade_gates_are_mutually_exclusive() {
        let mixed = vec![
            finding(
                "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK",
                SignalClass::MaliciousBehavior,
                RecommendedAction::Block,
            ),
            finding(
                "SKILL_CREDENTIAL_FORWARDING_POST",
                SignalClass::MaliciousBehavior,
                RecommendedAction::RequireApproval,
            ),
        ];
        for v in [Verdict::Benign, Verdict::Suspicious, Verdict::Malicious] {
            let down = taint_downgrade_eligible(v, &mixed, &[]);
            let up = fn_upgrade_eligible(v, &mixed, false);
            assert!(
                !(down && up),
                "verdict {v:?}: a package must never be both downgrade- and upgrade-eligible",
            );
        }
    }

    /// Mirror of the run_adjudication step-6 decision built from a
    /// `votes[fi]`-shaped vector: (parsed votes, error count).
    fn discrepancy_from(votes: &[(&str, Option<Verdict>)]) -> ConsensusDiscrepancy {
        let provider_votes: Vec<ProviderVote> = votes
            .iter()
            .filter_map(|(p, ov)| {
                ov.map(|v| ProviderVote {
                    provider: (*p).to_string(),
                    verdict: v,
                    confidence: 0.0,
                })
            })
            .collect();
        let errors = votes.iter().filter(|(_, ov)| ov.is_none()).count();
        ConsensusDiscrepancy::from_votes(provider_votes, errors)
    }

    /// Contract: a single-provider benign flip is detected on the
    /// exact vote shape run_adjudication builds, so the downgrade is
    /// blocked and the package fails (the injection vector ADR 0029
    /// opens is closed, not widened).
    #[test]
    fn flip_signature_blocks_downgrade_path() {
        let d = discrepancy_from(&[
            ("openai", Some(Verdict::Benign)),
            ("grok", Some(Verdict::Malicious)),
            ("ollama-cloud", Some(Verdict::Malicious)),
        ]);
        assert!(d.is_single_provider_benign_flip());
        // The downgrade consensus is NOT reached either (only 1 benign),
        // so blocking is strictly additive: a flipped package can never
        // reach a softer verdict.
        assert!(!provider_consensus_benign(&[
            ("openai".into(), Verdict::Benign),
            ("grok".into(), Verdict::Malicious),
            ("ollama-cloud".into(), Verdict::Malicious),
        ]));
    }

    /// Contract (regression): the validated 2-of-3 benign consensus is
    /// NOT a flip — it still downgrades. Pins that Phase 7 does not
    /// break the 15.75:1 ADR-0029 trade.
    #[test]
    fn validated_two_benign_consensus_is_not_a_flip() {
        let d = discrepancy_from(&[
            ("openai", Some(Verdict::Benign)),
            ("grok", Some(Verdict::Benign)),
            ("ollama-cloud", Some(Verdict::Malicious)),
        ]);
        assert!(
            !d.is_single_provider_benign_flip(),
            "the validated downgrade consensus must NEVER be flagged as injection"
        );
        assert!(provider_consensus_benign(&[
            ("openai".into(), Verdict::Benign),
            ("grok".into(), Verdict::Benign),
            ("ollama-cloud".into(), Verdict::Malicious),
        ]));
    }

    /// Contract (negative): an error vote masks the round →
    /// fail-closed, NOT treated as a flip (no injection finding
    /// manufactured on ambiguous evidence).
    #[test]
    fn error_masked_round_is_not_a_flip() {
        let d = discrepancy_from(&[
            ("openai", Some(Verdict::Benign)),
            ("grok", Some(Verdict::Malicious)),
            ("ollama-cloud", None),
        ]);
        assert!(!d.is_single_provider_benign_flip());
    }

    fn section_with(consensus: Option<Vec<LlmProviderKind>>) -> LlmConfigSection {
        LlmConfigSection {
            provider: LlmProviderKind::OpenAi,
            provider_configs: BTreeMap::new(),
            limits: crate::config::LlmLimits {
                max_prompt_chars: None,
                request_timeout_secs: 0,
                consensus_providers: consensus,
            },
        }
    }

    /// Contract: with no override the resolver returns the validated
    /// trio — the default path is byte-identical.
    #[test]
    fn resolve_consensus_providers_defaults_to_validated_trio() {
        assert_eq!(
            resolve_consensus_providers(&section_with(None)),
            vec![
                LlmProviderKind::OpenAi,
                LlmProviderKind::Grok,
                LlmProviderKind::OllamaCloud,
            ],
        );
    }

    /// Contract: a non-empty operator override is honoured verbatim
    /// (the ≥2-configured guard still applies downstream).
    #[test]
    fn resolve_consensus_providers_honours_nonempty_override() {
        let over = vec![LlmProviderKind::Anthropic, LlmProviderKind::OpenAi];
        assert_eq!(
            resolve_consensus_providers(&section_with(Some(over.clone()))),
            over,
        );
    }

    /// Contract (negative): an empty override falls back to the
    /// validated trio rather than disabling adjudication silently.
    #[test]
    fn resolve_consensus_providers_empty_override_falls_back_to_trio() {
        assert_eq!(
            resolve_consensus_providers(&section_with(Some(vec![]))).len(),
            3
        );
    }
}
