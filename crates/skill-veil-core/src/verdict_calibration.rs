//! Verdict calibration logic for adjusting root cause groups.
//!
//! This module implements the calibration step that runs after root cause groups
//! are derived from findings. Calibration adjusts verdicts to prevent false positives
//! from isolated weak signals.
//!
//! # Calibration Ordering
//!
//! Calibration rules are applied **sequentially** in the order they appear in the
//! `for group in &mut groups` loop. Each rule may modify `group.strongest_action`
//! and `group.signal_class`. Rules check **snapshotted** pre-mutation state to
//! ensure independence.
//!
//! This ordering is intentional and documented:
//!
//! 1. **DECLARED_PERMISSION_NETWORK_ACCESS** - Downgrades to `Log` if no stronger
//!    behavior exists. This prevents network access declarations from escalating
//!    verdicts on their own.
//!
//! 2. **CAPABILITY_PERMISSION_MISMATCH** - Downgrades to `Log` if no stronger
//!    behavior exists. Capability mismatches are retained for explainability
//!    but don't escalate without corroboration.
//!
//! 3. **INTERNAL_NETWORK_ACCESS** - Downgrades to `Log` if no network chain
//!    evidence exists. Internal network access alone is not actionable.
//!
//! 4. **MCP_NO_AUTH_MODEL** - Downgrades to `Log` if no remote execution surface
//!    is present. MCP servers without auth are a concern only when combined with
//!    other risky capabilities.
//!
//! # Rule Independence
//!
//! Each calibration rule's **firing condition** checks the group's original state
//! (via snapshotted `original_signal_class`), so earlier downgrades cannot prevent
//! a later rule from firing on the same group. However, the **effect measurement**
//! (`changed_from_previous`) compares against the action before *that specific rule*
//! (not the original), which is intentional to avoid double-counting risk adjustments
//! when multiple rules apply to the same group.

use crate::findings::{
    Finding, RecommendedAction, RootCauseGroup, SignalClass, ThreatCategory, VerdictCalibrationNote,
};

/// Rule IDs that verdict calibration may downgrade or reclassify.
///
/// This is the single source of truth used by both calibration logic and the
/// compound verdict detector in `verdict.rs` to guard against accidentally
/// checking a calibrated rule's raw finding action.
pub(crate) const CALIBRATED_RULE_IDS: &[&str] = &[
    "DECLARED_PERMISSION_NETWORK_ACCESS",
    "CAPABILITY_PERMISSION_MISMATCH",
    "INTERNAL_NETWORK_ACCESS",
    "MCP_NO_AUTH_MODEL",
    "OFFICIAL_MCP_NO_AUTH_REMOTE_ENDPOINT",
];

#[derive(Debug, Clone)]
pub(crate) struct VerdictCalibration {
    pub(crate) root_cause_groups: Vec<RootCauseGroup>,
    pub(crate) risk_adjustment: i32,
    pub(crate) notes: Vec<VerdictCalibrationNote>,
}

/// Static configuration for a single calibration rule.
struct CalibrationRule {
    /// Rule IDs whose presence in a group triggers this calibration rule.
    trigger_rule_ids: &'static [&'static str],
    /// Rule IDs to add to the accumulated exclusion list when this rule fires.
    rule_ids: &'static [&'static str],
    /// Risk score reduction when the calibration downgrade takes effect.
    risk_delta: i32,
    /// Whether to reclassify the group's signal_class to `ReviewSignal` on downgrade.
    reclassify_signal: bool,
    effect_downgraded: &'static str,
    effect_unchanged: &'static str,
    rationale: &'static str,
    /// Rule ID written into the calibration note (may differ from the matched IDs).
    note_rule_id: &'static str,
}

/// Ordered calibration pipeline. Rules are applied sequentially; see module-level docs
/// for the ordering rationale and independence guarantees.
///
/// # How to read each tier
///
/// Each `CalibrationRule` has two distinct knobs that encode the engineering
/// decision for that tier:
///
/// - `risk_delta` — how much score this signal *contributed* to the original
///   verdict, expressed as a negative number to back it out when the
///   calibration fires. Larger absolute values mean the rule was an
///   over-amplifier in the corpus and needs a deeper rollback.
/// - `reclassify_signal` — whether the *isolated* finding should also lose
///   its `MaliciousBehavior` / `SuspiciousPackageBehavior` classification
///   and become a `ReviewSignal`. `false` means "still counts toward the
///   verdict if anything else corroborates"; `true` means "downstream
///   `verdict.rs` must not treat this finding as a primary driver, period".
///
/// `trigger_rule_ids` is what *causes* the tier to fire, and `rule_ids` is
/// what gets *added to the accumulated exclusion list* so that subsequent
/// tiers see the calibrated state. They are usually equal — they diverge
/// only when one tier needs to suppress an alias rule that other tiers
/// would otherwise re-amplify (none currently do, but the schema supports
/// it).
/// Risk-score rollback applied when an isolated `DECLARED_PERMISSION_NETWORK_ACCESS`
/// finding fires without corroborating behaviour. Sized to exactly cancel the
/// original scoring path's contribution for declared network access.
const TIER1_DECLARED_NETWORK_ROLLBACK: i32 = -10;

/// Rollback for an isolated `CAPABILITY_PERMISSION_MISMATCH`. Smaller than
/// Tier 1 because the original score contribution is also smaller (one
/// weighted finding, not a multi-signal declared permission).
const TIER2_CAPABILITY_MISMATCH_ROLLBACK: i32 = -8;

/// Rollback for an isolated `INTERNAL_NETWORK_ACCESS` (loopback / 127.x /
/// 169.254.x). The largest rollback in the pipeline because the original
/// `INTERNAL_NETWORK_ACCESS` weight was calibrated for "external network
/// access on a sensitive port" and was over-firing on local traffic.
const TIER3_INTERNAL_NETWORK_ROLLBACK: i32 = -12;

/// Rollback for the remote-MCP-without-auth tier (`MCP_NO_AUTH_MODEL` and
/// `OFFICIAL_MCP_NO_AUTH_REMOTE_ENDPOINT`). The smallest rollback in the
/// pipeline: leaves a residual signal so packages with multiple weak
/// hygiene markers still tip into Suspicious.
const TIER4_REMOTE_MCP_NO_AUTH_ROLLBACK: i32 = -6;

const CALIBRATION_PIPELINE: &[CalibrationRule] = &[
    // Tier 1 — declared network access (manifest-level, no behavior).
    //
    // Why this tier exists: pre-calibration the corpus produced a wave of
    // false-positive `Suspicious` verdicts on benign packages that simply
    // declared `network` in their permission manifest without any
    // network-using code. The declaration is still useful for blast-radius
    // reporting, so we keep the finding but stop letting it drive the
    // verdict on its own.
    //
    // Why `risk_delta = -10`: empirically the original scoring path added
    // ~10 points for declared network access. Rolling back exactly that
    // amount restores the package's score to "no network signal at all"
    // when nothing else corroborates.
    //
    // Why `reclassify_signal = false`: the finding is genuinely a
    // `ReviewSignal` already (Hygiene-tier), so we leave the classification
    // intact. Downgrading to context-only just lowers the action; the
    // signal class doesn't need to change.
    CalibrationRule {
        trigger_rule_ids: &["DECLARED_PERMISSION_NETWORK_ACCESS"],
        rule_ids: &["DECLARED_PERMISSION_NETWORK_ACCESS"],
        risk_delta: TIER1_DECLARED_NETWORK_ROLLBACK,
        reclassify_signal: false,
        effect_downgraded: "downgraded_to_context",
        effect_unchanged: "remains_context_only",
        rationale: "Declared network access remains useful for blast-radius reporting, but it no longer drives package escalation without corroborating behavior.",
        note_rule_id: "DECLARED_PERMISSION_NETWORK_ACCESS",
    },
    // Tier 2 — capability vs declared permission mismatch.
    //
    // Why this tier exists: a permission/capability mismatch alone (e.g.
    // code reads files but the manifest didn't declare it) is a common
    // benign drift in well-meaning packages. It's a strong *explainability*
    // signal but a weak *threat* signal. Pre-calibration these mismatches
    // were re-routing into Suspicious verdicts in benign packages.
    //
    // Why `risk_delta = -8`: smaller than the network case (-10) because
    // the original score contribution is also smaller — capability
    // mismatch is one weighted finding, not a multi-signal declared
    // permission. The corpus showed -8 was the right rollback to bring
    // benign mismatches back to baseline.
    //
    // Why `reclassify_signal = false`: same reasoning as Tier 1 — the
    // signal class is already correct, only the action needs damping.
    CalibrationRule {
        trigger_rule_ids: &["CAPABILITY_PERMISSION_MISMATCH"],
        rule_ids: &["CAPABILITY_PERMISSION_MISMATCH"],
        risk_delta: TIER2_CAPABILITY_MISMATCH_ROLLBACK,
        reclassify_signal: false,
        effect_downgraded: "downgraded_to_context",
        effect_unchanged: "remains_context_only",
        rationale: "Capability mismatch is retained as an explainability signal, but it no longer escalates verdicts without stronger intent or behavioral evidence.",
        note_rule_id: "CAPABILITY_PERMISSION_MISMATCH",
    },
    // Tier 3 — internal / loopback network access.
    //
    // Why this tier exists: localhost / 127.x / 169.254.x calls in
    // skills are overwhelmingly benign developer tooling (talking to a
    // local LLM, an internal MCP host, a metadata service for legitimate
    // cloud introspection). Pre-calibration the corpus marked many such
    // packages as Suspicious. True positives — exfiltration, metadata
    // theft — *always* show up alongside fetch/exec/exfil chain rules,
    // so we wait for those before escalating.
    //
    // Why `risk_delta = -12`: this is the largest rollback in the
    // pipeline because the original `INTERNAL_NETWORK_ACCESS` weight was
    // calibrated for "external network access on a sensitive port" and
    // happened to also fire on loopback. Pulling -12 effectively
    // neutralises the misweighting.
    //
    // Why `reclassify_signal = true`: critical asymmetry vs. Tiers 1–2.
    // We must downgrade not just the action but the **signal class**, so
    // that `verdict::predicates::is_isolated_weak_package_root_signal`
    // can recognise the finding as `ReviewSignal` and emit a Benign
    // verdict. Without `true`, an isolated loopback hit still presents
    // as `MaliciousBehavior` to verdict.rs and bypasses the Benign
    // downgrade path the Tier was designed to enable.
    CalibrationRule {
        trigger_rule_ids: &["INTERNAL_NETWORK_ACCESS"],
        rule_ids: &["INTERNAL_NETWORK_ACCESS"],
        risk_delta: TIER3_INTERNAL_NETWORK_ROLLBACK,
        reclassify_signal: true,
        effect_downgraded: "downgraded_to_review_only",
        effect_unchanged: "remains_review_only",
        rationale: "Internal or loopback network targets are treated as review-only unless paired with fetch, execution, exfiltration, or metadata-service behavior.",
        note_rule_id: "INTERNAL_NETWORK_ACCESS",
    },
    // Tier 4 — remote MCP server without auth.
    //
    // Why this tier exists: the MCP_NO_AUTH_MODEL and the official-MCP
    // alias OFFICIAL_MCP_NO_AUTH_REMOTE_ENDPOINT were originally each
    // weighted high enough to drive Suspicious verdicts standalone. In
    // practice "no auth" is a hygiene problem on remote MCPs, not a
    // direct attack vector — the threat materialises only when the MCP
    // also exposes command-execution or arbitrary-transport tools.
    //
    // Why both rule IDs: they describe the same risk surface from two
    // detection paths (generic vs. official-MCP catalog match). Grouping
    // them in one tier means a finding from either path triggers the
    // calibration, and *both* are added to the exclusion list so a later
    // tier can't double-deduct on the alias.
    //
    // Why `risk_delta = -6`: the smallest rollback in the pipeline. The
    // corpus showed that even after calibration these findings should
    // still nudge the score upward when present (they ARE risky), just
    // not enough to escalate alone. -6 leaves a residual signal so
    // packages with multiple weak hygiene markers still tip into
    // Suspicious.
    //
    // Why `reclassify_signal = true`: like Tier 3, we need verdict.rs to
    // see this as a `ReviewSignal` so its presence alone doesn't keep
    // a package in `SuspiciousPackageBehavior`.
    CalibrationRule {
        trigger_rule_ids: &["MCP_NO_AUTH_MODEL", "OFFICIAL_MCP_NO_AUTH_REMOTE_ENDPOINT"],
        rule_ids: &["MCP_NO_AUTH_MODEL", "OFFICIAL_MCP_NO_AUTH_REMOTE_ENDPOINT"],
        risk_delta: TIER4_REMOTE_MCP_NO_AUTH_ROLLBACK,
        reclassify_signal: true,
        effect_downgraded: "downgraded_to_context",
        effect_unchanged: "remains_context_only",
        rationale: "Remote MCP without auth is still risky, but it is not treated as standalone malicious behavior unless it widens into command or transport execution semantics.",
        note_rule_id: "MCP_NO_AUTH_MODEL",
    },
];

fn is_permission_model_rule(rule_id: &str) -> bool {
    crate::findings::is_declared_permission_rule(rule_id)
        || rule_id == "CAPABILITY_PERMISSION_MISMATCH"
}

pub(crate) fn calibrate_verdict_inputs(
    findings: &[Finding],
    root_cause_groups: &[RootCauseGroup],
) -> VerdictCalibration {
    let mut groups = root_cause_groups.to_vec();
    let gates = compute_calibration_gates(findings);

    // Snapshot original actions and signal classes so each calibration rule checks pre-mutation state.
    // This makes rules independent: earlier downgrades don't prevent later rules from firing.
    let original_snapshots: Vec<(RecommendedAction, SignalClass)> = groups
        .iter()
        .map(|group| (group.strongest_action, group.signal_class))
        .collect();

    let (risk_adjustment, mut notes) =
        apply_calibration_rules(&mut groups, findings, &gates, &original_snapshots);

    // Remove groups that lost all their findings during calibration.
    // These phantom groups would otherwise inflate root_cause_groups counts
    // and produce confusing "0 finding(s)" entries in verdict reasons.
    groups.retain(|g| g.finding_count > 0);

    dedup_notes(&mut notes);

    VerdictCalibration {
        root_cause_groups: groups,
        risk_adjustment,
        notes,
    }
}

/// Compute the boolean gate conditions that guard each entry in `CALIBRATION_PIPELINE`.
/// Order matches `CALIBRATION_PIPELINE` index positions.
fn compute_calibration_gates(findings: &[Finding]) -> Vec<bool> {
    let has_stronger_behavior = findings.iter().any(|f| {
        f.recommended_action != RecommendedAction::Log
            && !is_permission_model_rule(&f.rule_id)
            && f.rule_id != "INTERNAL_NETWORK_ACCESS"
            && !matches!(
                f.rule_id.as_str(),
                "MCP_NO_AUTH_MODEL" | "OFFICIAL_MCP_NO_AUTH_REMOTE_ENDPOINT"
            )
            && matches!(
                f.signal_class,
                SignalClass::SuspiciousPackageBehavior | SignalClass::MaliciousBehavior
            )
    });
    let has_network_chain = findings.iter().any(|f| {
        let is_known_chain_rule = matches!(
            f.rule_id.as_str(),
            "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK"
                | "ARTIFACT_TAINT_DOWNLOAD_TO_EXECUTION"
                | "SSRF_LIKE_FETCH"
                | "SKILL_REMOTE_EXEC_CURL_BASH"
                | "SKILL_REMOTE_EXEC_POWERSHELL_IEX"
                | "OFFICIAL_REMOTE_FETCH_EXEC_POLYGLOT"
                | "OFFICIAL_SECRET_EXFIL_WEBHOOK"
        ) && f.recommended_action != RecommendedAction::Log;
        let is_actionable_chain_category = matches!(
            f.category,
            ThreatCategory::RemoteExec
                | ThreatCategory::DataExfiltration
                | ThreatCategory::CredentialExposure
        ) && f.recommended_action != RecommendedAction::Log;
        is_known_chain_rule || is_actionable_chain_category
    });
    let has_remote_mcp_exec_pair = findings.iter().any(|f| {
        matches!(
            f.rule_id.as_str(),
            "MCP_REMOTE_EXEC_SURFACE"
                | "MCP_TOOLING_TRANSPORT_DECLARED"
                | "OFFICIAL_MCP_REMOTE_TUNNEL_WITH_EXEC"
                | "OFFICIAL_MCP_REMOTE_BRIDGE_WITH_COMMAND"
        ) && f.recommended_action != RecommendedAction::Log
    });
    vec![
        !has_stronger_behavior,
        !has_stronger_behavior,
        !has_network_chain,
        !has_remote_mcp_exec_pair,
    ]
}

/// Mutable per-group state threaded through each calibration rule application.
struct GroupCalibrationState<'f> {
    original_signal_class: SignalClass,
    /// Rule IDs already excluded by earlier rules in this group's calibration pass.
    accumulated_exclusions: Vec<&'f str>,
    /// Group's strongest action before the current rule fires (updated after each rule).
    pre_rule_action: RecommendedAction,
}

/// Apply all `CALIBRATION_PIPELINE` rules to each group and return the cumulative
/// risk adjustment and calibration notes.
///
/// Uses `original_snapshots` to check pre-mutation signal class (rule independence) and
/// accumulates excluded rule IDs per group so successive rules don't re-count already-calibrated findings.
///
/// Each calibration rule contributes its `risk_delta` at most once per package
/// (tracked via `counted_rules`), regardless of how many groups it matches.
/// Without this, a rule matching N groups (e.g. `DECLARED_PERMISSION_NETWORK_ACCESS`
/// in both `AgentEntrypoint` and `PackageRootArtifact`) would multiply its credit
/// N×, doubling or tripling the calibration effect on the package risk score.
fn apply_calibration_rules<'f>(
    groups: &mut [RootCauseGroup],
    findings: &'f [Finding],
    gates: &[bool],
    original_snapshots: &[(RecommendedAction, SignalClass)],
) -> (i32, Vec<VerdictCalibrationNote>) {
    debug_assert_eq!(
        CALIBRATION_PIPELINE.len(),
        gates.len(),
        "gate count must match pipeline length"
    );
    let mut risk_adjustment = 0_i32;
    let mut notes = Vec::new();
    let mut counted_rules: std::collections::HashSet<&'static str> =
        std::collections::HashSet::new();
    let mut states: Vec<GroupCalibrationState<'f>> = groups
        .iter()
        .zip(original_snapshots.iter())
        .map(|(g, &(_, original_signal_class))| GroupCalibrationState {
            original_signal_class,
            accumulated_exclusions: Vec::new(),
            pre_rule_action: g.strongest_action,
        })
        .collect();

    for (i, group) in groups.iter_mut().enumerate() {
        for (rule, &gate) in CALIBRATION_PIPELINE.iter().zip(gates.iter()) {
            let (delta, note) =
                apply_single_rule_to_group(group, rule, gate, findings, &mut states[i]);
            // Only count each rule's risk delta once across all groups in a
            // single calibration pass. Notes still emit per-group so the
            // audit trail records every match.
            if delta != 0 && counted_rules.insert(rule.note_rule_id) {
                risk_adjustment += delta;
            }
            notes.extend(note);
        }
    }

    (risk_adjustment, notes)
}

/// Apply one calibration rule to one group, updating group state in place.
///
/// Returns the risk delta (negative or zero) and an optional calibration note.
/// `state.accumulated_exclusions` is extended when the rule fires, ensuring
/// successive rules in the same group don't re-count already-calibrated findings.
fn apply_single_rule_to_group<'f>(
    group: &mut RootCauseGroup,
    rule: &CalibrationRule,
    gate: bool,
    findings: &'f [Finding],
    state: &mut GroupCalibrationState<'f>,
) -> (i32, Option<VerdictCalibrationNote>) {
    // Check findings directly instead of representative_rules (truncated to
    // MAX_REPRESENTATIVE_RULES, which could exclude calibration-relevant rules).
    let group_matches = findings.iter().any(|f| {
        f.artifact_scope == group.scope
            && f.category == group.category
            && f.signal_class == state.original_signal_class
            && rule.trigger_rule_ids.contains(&f.rule_id.as_str())
    });
    if !gate || !group_matches {
        return (0, None);
    }

    state
        .accumulated_exclusions
        .extend_from_slice(rule.rule_ids);
    let (new_action, remaining_count) = recalculate_group_action_excluding(
        findings,
        group,
        state.original_signal_class,
        &state.accumulated_exclusions,
    );
    group.strongest_action = new_action;
    group.finding_count = remaining_count;
    let changed_from_previous = group.strongest_action < state.pre_rule_action;
    let risk_delta = if changed_from_previous {
        rule.risk_delta
    } else {
        0
    };
    if rule.reclassify_signal
        && (changed_from_previous || group.strongest_action == RecommendedAction::Log)
    {
        group.signal_class = SignalClass::ReviewSignal;
    }
    state.pre_rule_action = group.strongest_action;
    let was_reclassified =
        rule.reclassify_signal && group.signal_class != state.original_signal_class;
    let note = VerdictCalibrationNote {
        rule_id: rule.note_rule_id.to_string(),
        effect: if changed_from_previous {
            rule.effect_downgraded.to_string()
        } else if was_reclassified {
            "reclassified_only".to_string()
        } else {
            rule.effect_unchanged.to_string()
        },
        rationale: rule.rationale.to_string(),
        // Tag the note with the group it applied to so verdict predicates
        // can filter notes per-group (see `is_isolated_weak_package_root_signal`
        // in `verdict/predicates.rs`). Without this, an unrelated `downgraded_*`
        // note from another group blocks the Benign downgrade path for an
        // isolated weak signal — even when calibration didn't actually
        // touch that signal's group.
        scope: group.scope,
        category: group.category,
        // Use the POST-reclassification signal_class so that verdict
        // predicates filtering on (scope, category, signal_class) see the
        // value that matches the calibrated root cause groups. The
        // pre-fix code recorded `state.original_signal_class`, which
        // caused `calibration_left_isolated_group_intact` to produce
        // empty matches (the note carried the old class but the group
        // had been reclassified), making the predicate vacuously
        // satisfied and allowing a Benign downgrade that should have
        // been blocked by a reclassification.
        signal_class: group.signal_class,
    };
    (risk_delta, Some(note))
}

/// Recalculate a group's strongest action and remaining finding count from findings
/// that are NOT in the excluded set.
/// This prevents calibration of one rule from silencing other legitimate rules in the same group.
fn recalculate_group_action_excluding(
    findings: &[Finding],
    group: &RootCauseGroup,
    original_signal_class: SignalClass,
    excluded_rule_ids: &[&str],
) -> (RecommendedAction, usize) {
    let remaining: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.artifact_scope == group.scope
                && f.category == group.category
                && f.signal_class == original_signal_class
                && !excluded_rule_ids.contains(&f.rule_id.as_str())
        })
        .collect();
    let action = remaining.iter().fold(RecommendedAction::Log, |acc, f| {
        acc.max(f.recommended_action)
    });
    (action, remaining.len())
}

/// Collapse identical calibration notes.
///
/// # Identity contract
///
/// Two notes are duplicates only when ALL FIVE fields match: `rule_id`, `effect`,
/// `rationale`, **`scope`**, and **`category`**. The `scope`+`category` pair is
/// load-bearing: `verdict::predicates::verdict()` filters notes by `(scope, category)`
/// to decide whether calibration affects a specific isolated weak group. Collapsing
/// per-group notes here would let an unrelated `downgraded_*` note in another group
/// vacuously satisfy the Benign-path filter and silently downgrade `Suspicious` to
/// `Benign`. See `dedup_notes_preserves_per_group_distinctions`.
fn dedup_notes(notes: &mut Vec<VerdictCalibrationNote>) {
    notes.sort_by(|a, b| {
        a.scope
            .cmp(&b.scope)
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.effect.cmp(&b.effect))
            .then_with(|| a.rationale.cmp(&b.rationale))
            .then_with(|| a.signal_class.cmp(&b.signal_class))
    });
    notes.dedup_by(|a, b| {
        a.scope == b.scope
            && a.category == b.category
            && a.rule_id == b.rule_id
            && a.effect == b.effect
            && a.rationale == b.rationale
            && a.signal_class == b.signal_class
    });
}

#[cfg(test)]
#[path = "verdict_calibration_tests.rs"]
mod verdict_calibration_tests;
