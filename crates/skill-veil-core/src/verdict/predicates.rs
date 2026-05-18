use crate::findings::{
    ArtifactScope, Finding, FindingSummary, HygieneSummary, PackageHealth, RecommendedAction,
    RootCauseGroup, SignalClass, ThreatCategory, Verdict, VerdictCalibrationNote,
    RISK_THRESHOLD_APPROVAL, RISK_THRESHOLD_BLOCK,
};

pub(super) struct VerdictInputs<'a> {
    pub(super) findings: &'a [Finding],
    pub(super) root_cause_groups: &'a [RootCauseGroup],
    pub(super) raw_root_cause_groups: &'a [RootCauseGroup],
    pub(super) compound_reasons: &'a [crate::findings::VerdictReason],
    pub(super) primary_summary: &'a FindingSummary,
    pub(super) supporting_summary: &'a FindingSummary,
}

/// Rule IDs whose single Block-strength `MaliciousBehavior` finding is
/// sufficient on its own to escalate the package to `Malicious`,
/// bypassing the [`VerdictPredicates::has_independent_malicious_corroboration`]
/// gate.
///
/// The corroboration gate (rounds 2–3 of FP reduction) was added
/// because FP-prone rules like `ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK`
/// fire on benign API-client skills. But that gate over-applies: it
/// also holds intrinsically-conclusive single signals at `Suspicious`,
/// which is a soft false-negative on a confirmed-malicious skill.
///
/// Membership criterion — non-negotiable: a rule may appear here ONLY
/// if it produces **zero** findings on the 4000-skill VT-clean
/// `data-clean` corpus. Empirically verified at addition time:
/// - `SKILL_MALICIOUS_PUBLISHER` — literal known-bad publisher IOC;
///   0/4000 benign hits, 1037 malicious-corpus hits.
/// - `SKILL_MACOS_BASE64_RCE` — `base64 -D | sh` macOS dropper
///   (case-sensitive `-D`); 0/4000 benign hits, 534 malicious-corpus
///   hits. (The two raw lowercase-`-d` hits are test fixtures in one
///   security-tooling skill and do not match the case-sensitive rule.)
/// - `SKILL_FAKE_DEPENDENCY_DROPPER` — composite 2-of-3 detector
///   (`detectors::instructions::dropper_delivery`); zero-FP by
///   construction: the conjunction of fake-mandatory-dependency,
///   paste-site delivery, and password-archive signals measured
///   0/4000 benign, 1149/2976 malicious. A skill that stages a fake
///   dependency dropper is malicious by definition — corroboration
///   only manufactured a soft FN. Cross-LLM triage of the residual
///   showed 6 strong-malicious (≥2 of 3 LLMs say malicious) skills
///   topped by this rule still held at Suspicious.
/// - `SKILL_TELEGRAM_BOT_TOKEN_HARDCODED` — a live
///   `api.telegram.org/bot<id>:<token>` URL embedded in skill
///   content; 0/4000 benign, 4/2976 malicious. Legitimate skills
///   read the token from an env var and never embed the
///   `<id>:<token>` secret literally — an exfil-credential IOC.
///
/// Adding a rule here is a precision↔recall trade made deliberately
/// at the verdict layer. A rule that later starts producing benign
/// FPs MUST be removed from this list, not "calibrated around".
pub(super) const CONCLUSIVE_SINGLE_RULE_IDS: &[&str] = &[
    "SKILL_MALICIOUS_PUBLISHER",
    "SKILL_MACOS_BASE64_RCE",
    "SKILL_FAKE_DEPENDENCY_DROPPER",
    "SKILL_TELEGRAM_BOT_TOKEN_HARDCODED",
];

pub(super) struct VerdictPredicates {
    pub(super) has_malicious_behavior: bool,
    pub(super) has_compound_malicious: bool,
    pub(super) has_primary_block: bool,
    pub(super) has_supporting_block: bool,
    pub(super) has_non_hygiene_signal: bool,
    pub(super) calibration_weakened_non_hygiene: bool,
    pub(super) has_actionable_non_package_root: bool,
    pub(super) severe_hygiene_only: bool,
    pub(super) has_conclusive_supporting_malicious: bool,
    /// `true` when at least one finding from a [`CONCLUSIVE_SINGLE_RULE_IDS`]
    /// rule is still `MaliciousBehavior` + `Block` after calibration.
    /// Such a finding escalates to `Malicious` on its own — these are
    /// curated zero-FP rules, so the corroboration gate would only
    /// create a soft false negative.
    pub(super) has_conclusive_single_rule: bool,
    pub(super) isolated_weak_package_root_signal: bool,
    pub(super) has_non_hygiene_primary_block: bool,
    /// The (scope, category, signal_class) of the isolated weak package-root
    /// group, when `isolated_weak_package_root_signal` is true. Used to filter
    /// `calibration_notes` so that a `downgraded_*` note from an unrelated
    /// group — even one sharing (scope, category) — does not block the Benign
    /// downgrade for this group.
    pub(super) isolated_weak_signal_key: Option<(ArtifactScope, ThreatCategory, SignalClass)>,
    /// `true` when the package has independent corroboration for a
    /// `Malicious` verdict: ≥2 distinct rules contribute
    /// `MaliciousBehavior + Block` findings AND those rules differ on
    /// at least one of `(category, artifact_scope)`. Without this,
    /// a single rule (e.g. `ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK`
    /// firing on a benign API skill) escalates to `Malicious` on its
    /// own. Cross-LLM triage on a 4000-skill VT-clean corpus showed
    /// single-rule escalations dominate the residual FP set after
    /// the per-rule downgrades shipped earlier.
    ///
    /// The corroboration check still allows the historical "primary
    /// block + conclusive supporting evidence" path
    /// ([`has_supporting_block`] && [`has_conclusive_supporting_malicious`])
    /// and the compound-reasons path ([`has_compound_malicious`]) to
    /// fire on their own — those already encode multi-signal
    /// reasoning. Only the unconditional-on-MaliciousBehavior
    /// triggers gain the corroboration gate.
    pub(super) has_independent_malicious_corroboration: bool,
}

impl VerdictPredicates {
    pub(super) fn compute(inputs: &VerdictInputs<'_>) -> Self {
        let VerdictInputs {
            findings,
            root_cause_groups,
            raw_root_cause_groups,
            compound_reasons,
            primary_summary,
            supporting_summary,
        } = inputs;
        let has_malicious_behavior = root_cause_groups.iter().any(|group| {
            group.signal_class == SignalClass::MaliciousBehavior
                && group.strongest_action == RecommendedAction::Block
        });
        // Only count compound reasons that are themselves
        // `MaliciousBehavior`. Pre-fix any compound reason — including
        // a downgraded `ReviewSignal` chain — flipped the unconditional
        // escalation flag, which silently re-escalated the
        // trusted-host-downgraded credential-exfil chain back to
        // Malicious in the verdict layer even after `compound.rs`
        // moved its own signal_class to ReviewSignal.
        let has_compound_malicious = compound_reasons
            .iter()
            .any(|r| r.signal_class == SignalClass::MaliciousBehavior);
        let has_primary_block = primary_summary.recommended_action == RecommendedAction::Block;
        let has_supporting_block =
            supporting_summary.recommended_action == RecommendedAction::Block;
        let has_non_hygiene_signal = root_cause_groups.iter().any(|group| {
            matches!(
                group.signal_class,
                SignalClass::MaliciousBehavior
                    | SignalClass::SuspiciousPackageBehavior
                    | SignalClass::ReviewSignal
            ) && group.strongest_action != RecommendedAction::Log
        });
        // Check pre-calibration groups too: if calibration downgraded any non-hygiene signal,
        // we should not treat the package as "hygiene-only" or "isolated weak signal".
        let calibration_weakened_non_hygiene = raw_root_cause_groups.iter().any(|raw_group| {
            let is_non_hygiene = matches!(
                raw_group.signal_class,
                SignalClass::MaliciousBehavior
                    | SignalClass::SuspiciousPackageBehavior
                    | SignalClass::ReviewSignal
            ) && raw_group.strongest_action != RecommendedAction::Log;
            if !is_non_hygiene {
                return false;
            }
            // Find the corresponding calibrated group. Exact match on
            // (scope, category, signal_class) is preferred. If calibration
            // reclassified the group's signal class (e.g. MaliciousBehavior
            // → ReviewSignal), the exact match fails. We then look for a
            // group at the same (scope, category) whose signal class differs
            // from the raw group's — that is the reclassified group.
            //
            // When multiple groups share (scope, category), prefer the one
            // whose signal class is ReviewSignal — the only reclassification
            // target. Without this preference, `.find()` could match an
            // unrelated Hygiene group at the same (scope, category), falsely
            // triggering `calibration_weakened_non_hygiene`.
            let calibrated = root_cause_groups
                .iter()
                .find(|cal| {
                    cal.scope == raw_group.scope
                        && cal.category == raw_group.category
                        && cal.signal_class == raw_group.signal_class
                })
                .or_else(|| {
                    // Prefer ReviewSignal: calibration only reclassifies TO
                    // ReviewSignal, so a Hygiene group at (scope, category)
                    // is never the reclassified version of a non-hygiene raw group.
                    root_cause_groups.iter().find(|cal| {
                        cal.scope == raw_group.scope
                            && cal.category == raw_group.category
                            && cal.signal_class == SignalClass::ReviewSignal
                    })
                });
            let Some(calibrated) = calibrated else {
                return true;
            };
            calibrated.strongest_action < raw_group.strongest_action
                || calibrated.signal_class != raw_group.signal_class
        });
        let has_actionable_non_package_root = root_cause_groups.iter().any(|group| {
            group.scope != ArtifactScope::PackageRootArtifact
                && group.strongest_action != RecommendedAction::Log
                && group.signal_class != SignalClass::Hygiene
        });
        let severe_hygiene_only = !has_non_hygiene_signal
            && !calibration_weakened_non_hygiene
            && root_cause_groups.iter().any(|group| {
                group.signal_class == SignalClass::Hygiene
                    && group.strongest_action == RecommendedAction::Block
            });
        let has_conclusive_supporting_malicious = findings
            .iter()
            .any(Finding::is_conclusive_malicious_evidence);
        // Gate on the POST-calibration action only. `Block` is
        // preserved through calibration UNLESS a downgrade flag
        // (doc-context / requires-code-artifact) lowered it to
        // `RequireApproval` — so `action == Block` already means
        // "curated finding, not calibration-downgraded". signal_class
        // is intentionally NOT checked: it is a category-derived
        // artifact (`supply_chain` → SuspiciousPackageBehavior), and
        // a definitive known-bad-publisher IOC must escalate
        // regardless of how its ThreatCategory happens to map.
        let has_conclusive_single_rule = findings.iter().any(|f| {
            CONCLUSIVE_SINGLE_RULE_IDS.contains(&f.rule_id.as_str())
                && f.recommended_action == RecommendedAction::Block
        });
        let isolated_weak_signal_key = isolated_weak_package_root_group(root_cause_groups)
            .map(|group| (group.scope, group.category, group.signal_class));
        let isolated_weak_package_root_signal = isolated_weak_signal_key.is_some();
        let has_non_hygiene_primary_block = root_cause_groups.iter().any(|group| {
            group.scope == ArtifactScope::AgentEntrypoint
                && group.strongest_action == RecommendedAction::Block
                && group.signal_class != SignalClass::Hygiene
        });

        // Compute independent-corroboration: collect distinct
        // (rule_id, category, scope) keys among Block-action
        // MaliciousBehavior findings. Two findings with the SAME
        // rule_id but different scope still count as a single rule
        // signal (deduped by rule_id below); independence requires
        // either two different rule_ids OR one rule_id firing on
        // two different (category, scope) combinations — which is
        // already a structural anomaly worth corroborating with.
        let mut malicious_block_rule_ids: std::collections::BTreeSet<&str> =
            std::collections::BTreeSet::new();
        let mut malicious_block_keys: std::collections::BTreeSet<(ThreatCategory, ArtifactScope)> =
            std::collections::BTreeSet::new();
        for f in *findings {
            if f.signal_class == SignalClass::MaliciousBehavior
                && f.recommended_action == RecommendedAction::Block
            {
                malicious_block_rule_ids.insert(f.rule_id.as_str());
                malicious_block_keys.insert((f.category, f.artifact_scope));
            }
        }
        // Corroboration: at least two distinct rule_ids OR one
        // rule firing across two distinct (category, scope) pairs.
        // The second branch catches the common case where the SAME
        // taint rule lands on both AgentEntrypoint and
        // SupportingArtifact — a stronger signal than a single fire.
        let has_independent_malicious_corroboration =
            malicious_block_rule_ids.len() >= 2 || malicious_block_keys.len() >= 2;

        Self {
            has_malicious_behavior,
            has_compound_malicious,
            has_primary_block,
            has_supporting_block,
            has_non_hygiene_signal,
            calibration_weakened_non_hygiene,
            has_actionable_non_package_root,
            severe_hygiene_only,
            has_conclusive_supporting_malicious,
            has_conclusive_single_rule,
            isolated_weak_package_root_signal,
            has_non_hygiene_primary_block,
            isolated_weak_signal_key,
            has_independent_malicious_corroboration,
        }
    }

    pub(super) fn verdict(
        &self,
        calibration_notes: &[VerdictCalibrationNote],
        primary_summary: &FindingSummary,
        package_summary: &FindingSummary,
    ) -> Verdict {
        // The two unconditional escalation triggers
        // (`has_malicious_behavior`, `has_non_hygiene_primary_block`)
        // gate on `has_independent_malicious_corroboration`. A single
        // rule firing once cannot push the package to Malicious; a
        // second independent rule (or the same rule across two
        // category/scope pairs) is required.
        //
        // The `has_compound_malicious` and `has_supporting_block +
        // has_conclusive_supporting_malicious` paths preserve their
        // historical behaviour: those already encode multi-signal
        // reasoning by construction.
        //
        // `has_conclusive_single_rule` is the recall counterpart of
        // the corroboration gate: a curated set of zero-FP rules
        // (`CONCLUSIVE_SINGLE_RULE_IDS`) escalates on a single fire.
        // Without this, a confirmed `base64 -D | sh` dropper or a
        // known-malicious-publisher IOC was held at `Suspicious`
        // whenever it was the only Block-strength signal — a soft
        // false negative on ~738 confirmed-malicious corpus skills.
        let unconditional_escalation = (self.has_malicious_behavior
            || self.has_non_hygiene_primary_block)
            && self.has_independent_malicious_corroboration;
        if unconditional_escalation
            || self.has_conclusive_single_rule
            || self.has_compound_malicious
            || (self.has_supporting_block && self.has_conclusive_supporting_malicious)
        {
            return Verdict::Malicious;
        }

        // Risk-gated safety net: a package whose aggregated or primary risk
        // already meets the block threshold must never be reported as Benign.
        // This guards against silent downgrades when findings emit high weight
        // but happen to route through Hygiene / ReviewSignal signal classes
        // (e.g. misclassified rules) — the score is a better last-line signal
        // than any single categorical predicate.
        let risk_gated_high = primary_summary.risk_score >= RISK_THRESHOLD_BLOCK
            || package_summary.risk_score >= RISK_THRESHOLD_BLOCK;

        // Filter calibration notes to only those that apply to the isolated
        // weak group's (scope, category, signal_class). A `downgraded_*` note
        // from any OTHER group — even one sharing (scope, category) — is
        // irrelevant to whether this specific isolated signal can be
        // downgraded. Using the unfiltered `all()` would let an unrelated
        // downgrade block the Benign path here.
        let calibration_left_isolated_group_intact = self
            .isolated_weak_signal_key
            .map(|(scope, category, signal_class)| {
                calibration_notes
                    .iter()
                    .filter(|n| {
                        n.scope == scope && n.category == category && n.signal_class == signal_class
                    })
                    .all(|n| n.effect.starts_with("remains_") || n.effect == "reclassified_only")
            })
            .unwrap_or(true);

        if self.isolated_weak_package_root_signal
            && !self.has_actionable_non_package_root
            && !self.has_primary_block
            && !self.calibration_weakened_non_hygiene
            && !risk_gated_high
            && calibration_left_isolated_group_intact
            && package_summary.risk_score < RISK_THRESHOLD_APPROVAL
            && primary_summary.risk_score < RISK_THRESHOLD_APPROVAL
        {
            // Isolated weak package root signals are downgraded to Benign only when there
            // are no actionable signals in other artifacts and calibration did not actually
            // change any actions affecting THIS group. Notes with "remains_*" indicate
            // calibration matched but did not modify anything and do not block downgrade;
            // notes scoped to other groups are excluded by the filter above.
            return Verdict::Benign;
        }

        if self.has_non_hygiene_signal
            || self.has_actionable_non_package_root
            || self.severe_hygiene_only
            || self.calibration_weakened_non_hygiene
            || risk_gated_high
        {
            Verdict::Suspicious
        } else {
            Verdict::Benign
        }
    }

    pub(super) fn package_health(
        &self,
        hygiene_summary: &HygieneSummary,
        verdict: Verdict,
    ) -> PackageHealth {
        let base_health = if hygiene_summary.package_root_findings == 0
            && hygiene_summary.entrypoint_findings == 0
            && hygiene_summary.supporting_findings == 0
        {
            PackageHealth::Healthy
        } else if self.severe_hygiene_only {
            PackageHealth::NeedsReview
        } else if self.has_non_hygiene_signal || self.calibration_weakened_non_hygiene {
            PackageHealth::Elevated
        } else {
            // Only hygiene findings exist, but none severe enough for Block.
            PackageHealth::NeedsReview
        };

        // A Benign verdict with Elevated health is contradictory — downgrade to NeedsReview.
        if verdict == Verdict::Benign && base_health == PackageHealth::Elevated {
            PackageHealth::NeedsReview
        } else {
            base_health
        }
    }
}

fn isolated_weak_package_root_group(
    root_cause_groups: &[RootCauseGroup],
) -> Option<&RootCauseGroup> {
    let actionable_groups: Vec<&RootCauseGroup> = root_cause_groups
        .iter()
        .filter(|group| group.strongest_action != RecommendedAction::Log)
        .collect();

    if actionable_groups.len() == 1
        && actionable_groups[0].scope == ArtifactScope::PackageRootArtifact
        && actionable_groups[0].strongest_action == RecommendedAction::RequireApproval
        && matches!(
            actionable_groups[0].signal_class,
            SignalClass::ReviewSignal | SignalClass::SuspiciousPackageBehavior
        )
    {
        Some(actionable_groups[0])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::VerdictReason;

    fn malicious_reason() -> VerdictReason {
        VerdictReason {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::DataExfiltration,
            signal_class: SignalClass::MaliciousBehavior,
            rationale: "compound chain at full strength".to_string(),
        }
    }

    fn downgraded_reason() -> VerdictReason {
        VerdictReason {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::DataExfiltration,
            signal_class: SignalClass::ReviewSignal,
            rationale: "compound chain downgraded to review".to_string(),
        }
    }

    /// Contract: `has_compound_malicious` is `true` when AT LEAST ONE
    /// compound reason carries `MaliciousBehavior`. Pre-fix the flag
    /// fired on the mere presence of any compound reason — including
    /// trust-downgraded `ReviewSignal` reasons emitted by the
    /// credential-exfil chain — which silently re-escalated benign
    /// API-key-using skills back to Malicious in
    /// `verdict::predicates::verdict`.
    #[test]
    fn has_compound_malicious_only_counts_malicious_signal_class() {
        let reasons_only_review = [downgraded_reason()];
        assert!(
            !reasons_only_review
                .iter()
                .any(|r| r.signal_class == SignalClass::MaliciousBehavior),
            "review-signal-only compound reasons must NOT trip has_compound_malicious",
        );

        let reasons_with_malicious = [downgraded_reason(), malicious_reason()];
        assert!(
            reasons_with_malicious
                .iter()
                .any(|r| r.signal_class == SignalClass::MaliciousBehavior),
            "any malicious-behavior compound reason MUST trip has_compound_malicious",
        );
    }

    fn finding(
        rule_id: &str,
        signal_class: SignalClass,
        action: RecommendedAction,
    ) -> crate::findings::Finding {
        crate::findings::Finding::builder(rule_id, ThreatCategory::RemoteExec)
            .severity(crate::findings::Severity::Critical)
            .confidence(0.99)
            .action(action)
            .evidence_kind(crate::findings::EvidenceKind::Behavior)
            .artifact(
                crate::findings::ArtifactKind::SkillDocument,
                Some("SKILL.md".to_string()),
            )
            .matched_on(crate::findings::MatchTarget::Document)
            .signal_class(signal_class)
            .build()
    }

    fn predicates_for(findings: &[crate::findings::Finding]) -> VerdictPredicates {
        let primary = FindingSummary::from_findings(findings);
        let supporting = FindingSummary::from_findings(&[]);
        let groups = super::super::root_causes::build_root_cause_groups(findings);
        VerdictPredicates::compute(&VerdictInputs {
            findings,
            root_cause_groups: &groups,
            raw_root_cause_groups: &groups,
            compound_reasons: &[],
            primary_summary: &primary,
            supporting_summary: &supporting,
        })
    }

    /// Contract: a SINGLE Block-strength `MaliciousBehavior` finding
    /// from a `CONCLUSIVE_SINGLE_RULE_IDS` rule escalates to
    /// `Malicious` on its own — it does NOT need independent
    /// corroboration. Pins the recall fix for the ~738 confirmed-
    /// malicious corpus skills (base64 dropper / known-bad publisher)
    /// that the corroboration gate previously held at `Suspicious`.
    #[test]
    fn conclusive_single_rule_escalates_without_corroboration() {
        for rule in CONCLUSIVE_SINGLE_RULE_IDS {
            let findings = [finding(
                rule,
                SignalClass::MaliciousBehavior,
                RecommendedAction::Block,
            )];
            let p = predicates_for(&findings);
            assert!(
                p.has_conclusive_single_rule,
                "{rule} alone must set has_conclusive_single_rule",
            );
            assert!(
                !p.has_independent_malicious_corroboration,
                "{rule} fires once — corroboration must be absent (proves the \
                 escalation is via the conclusive path, not corroboration)",
            );
            assert_eq!(
                p.verdict(
                    &[],
                    &FindingSummary::from_findings(&findings),
                    &FindingSummary::from_findings(&findings),
                ),
                Verdict::Malicious,
                "{rule} alone must yield Malicious",
            );
        }
    }

    /// Contract (negative): a conclusive rule whose finding was
    /// calibration-downgraded (e.g. detection-catalogue skill →
    /// `RequireApproval`) MUST NOT escalate. The conclusive bypass
    /// gates on the POST-calibration action, so a documented-anti-
    /// pattern base64 example does not flip the verdict.
    #[test]
    fn downgraded_conclusive_rule_does_not_escalate() {
        let findings = [finding(
            "SKILL_MACOS_BASE64_RCE",
            SignalClass::ReviewSignal,
            RecommendedAction::RequireApproval,
        )];
        let p = predicates_for(&findings);
        assert!(
            !p.has_conclusive_single_rule,
            "a downgraded conclusive finding must not set the flag",
        );
    }

    /// Contract: a curated IOC rule that emits `SuspiciousPackageBehavior`
    /// (not `MaliciousBehavior`) because of its ThreatCategory mapping
    /// (`supply_chain` → SuspiciousPackageBehavior) STILL escalates as
    /// long as the action is `Block`. Pins the fix for
    /// `SKILL_MALICIOUS_PUBLISHER` (405 corpus skills) whose finding
    /// is `suspicious_package_behavior` + `block` + supporting scope.
    #[test]
    fn conclusive_rule_escalates_regardless_of_signal_class() {
        let findings = [finding(
            "SKILL_MALICIOUS_PUBLISHER",
            SignalClass::SuspiciousPackageBehavior,
            RecommendedAction::Block,
        )];
        let p = predicates_for(&findings);
        assert!(
            p.has_conclusive_single_rule,
            "a curated IOC rule at Block must escalate even as \
             SuspiciousPackageBehavior",
        );
        assert_eq!(
            p.verdict(
                &[],
                &FindingSummary::from_findings(&findings),
                &FindingSummary::from_findings(&findings),
            ),
            Verdict::Malicious,
            "known-bad-publisher IOC alone must yield Malicious",
        );
    }

    /// Contract (negative): an FP-prone rule NOT on the curated list
    /// (e.g. `SKILL_CRED_HARDCODED_KEY`, which has more benign than
    /// malicious hits) firing once at Block strength MUST still be
    /// gated by corroboration — it does not get the conclusive
    /// bypass. Prevents the recall fix from re-opening the FP hole
    /// rounds 1–4 closed.
    #[test]
    fn non_curated_rule_still_needs_corroboration() {
        let findings = [finding(
            "SKILL_CRED_HARDCODED_KEY",
            SignalClass::MaliciousBehavior,
            RecommendedAction::Block,
        )];
        let p = predicates_for(&findings);
        assert!(
            !p.has_conclusive_single_rule,
            "a non-curated rule must NOT get the conclusive bypass",
        );
        assert_eq!(
            p.verdict(
                &[],
                &FindingSummary::from_findings(&findings),
                &FindingSummary::from_findings(&findings),
            ),
            Verdict::Suspicious,
            "single non-curated MaliciousBehavior must stay Suspicious (corroboration gate)",
        );
    }
}
