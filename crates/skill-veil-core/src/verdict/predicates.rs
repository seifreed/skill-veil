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
        let has_compound_malicious = !compound_reasons.is_empty();
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
            // Find the corresponding calibrated group (exact match first, then
            // scope+category+signal_class via reclassification). Absence of the
            // original signal_class counts as weakening.
            let calibrated = root_cause_groups
                .iter()
                .find(|cal| {
                    cal.scope == raw_group.scope
                        && cal.category == raw_group.category
                        && cal.signal_class == raw_group.signal_class
                })
                .or_else(|| {
                    // After reclassification, a group originally labelled
                    // MaliciousBehavior may appear as ReviewSignal. Match on
                    // (scope, category) alone, but only if the surviving group
                    // was actually weakened (action lowered or class changed).
                    root_cause_groups.iter().find(|cal| {
                        cal.scope == raw_group.scope && cal.category == raw_group.category
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
        }
    }

    pub(super) fn verdict(
        &self,
        calibration_notes: &[VerdictCalibrationNote],
        primary_summary: &FindingSummary,
        package_summary: &FindingSummary,
    ) -> Verdict {
        if self.has_malicious_behavior
            || self.has_compound_malicious
            || (self.has_supporting_block && self.has_conclusive_supporting_malicious)
            || self.has_non_hygiene_primary_block
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
                    .all(|n| n.effect.starts_with("remains_"))
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
