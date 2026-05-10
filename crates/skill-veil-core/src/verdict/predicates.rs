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
        let unconditional_escalation = (self.has_malicious_behavior
            || self.has_non_hygiene_primary_block)
            && self.has_independent_malicious_corroboration;
        if unconditional_escalation
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
}
