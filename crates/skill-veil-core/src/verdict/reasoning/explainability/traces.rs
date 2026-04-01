use crate::findings::{
    ExplainabilityTrace, RecommendedAction, RootCauseGroup, VerdictCalibrationNote, VerdictReason,
};

pub(super) fn triggered_by_label(group: &RootCauseGroup) -> String {
    format!(
        "{}/{}/{} via {}",
        group.scope,
        group.category,
        group.signal_class,
        group.representative_rules.join(",")
    )
}

pub(super) fn escalation_chain_label(reason: &VerdictReason) -> String {
    format!(
        "{}/{}/{}: {}",
        reason.scope, reason.category, reason.signal_class, reason.rationale
    )
}

pub(super) fn collect_traces(
    root_cause_groups: &[RootCauseGroup],
    compound_reasons: &[VerdictReason],
    calibration_notes: &[VerdictCalibrationNote],
    top_risk_drivers: &[crate::findings::RiskFactor],
) -> Vec<ExplainabilityTrace> {
    let mut traces = root_cause_traces(root_cause_groups);
    traces.extend(compound_traces(compound_reasons));
    traces.extend(calibration_traces(calibration_notes));
    traces.extend(factor_traces(top_risk_drivers));
    traces
}

fn trace_from_factor(factor: &crate::findings::RiskFactor) -> ExplainabilityTrace {
    super::sources::risk_factor_trace(factor)
}

fn root_cause_trace(group: &RootCauseGroup) -> ExplainabilityTrace {
    ExplainabilityTrace {
        source: "root_cause_group".to_string(),
        label: reason_label(group.scope, group.category, group.signal_class),
        rationale: format!(
            "{} finding(s) with strongest action {}",
            group.finding_count, group.strongest_action
        ),
        rule_ids: group.representative_rules.clone(),
        scope: Some(group.scope.to_string()),
        contribution: None,
    }
}

fn compound_reason_trace(reason: &VerdictReason) -> ExplainabilityTrace {
    ExplainabilityTrace {
        source: "compound_reason".to_string(),
        label: reason_label(reason.scope, reason.category, reason.signal_class),
        rationale: reason.rationale.clone(),
        rule_ids: Vec::new(),
        scope: Some(reason.scope.to_string()),
        contribution: None,
    }
}

fn calibration_trace(note: &VerdictCalibrationNote) -> ExplainabilityTrace {
    ExplainabilityTrace {
        source: "calibration".to_string(),
        label: note.rule_id.clone(),
        rationale: note.rationale.clone(),
        rule_ids: vec![note.rule_id.clone()],
        scope: None,
        contribution: None,
    }
}

fn calibration_traces(
    calibration_notes: &[VerdictCalibrationNote],
) -> impl Iterator<Item = ExplainabilityTrace> + '_ {
    calibration_notes.iter().map(calibration_trace)
}

fn non_log_root_cause_groups(
    root_cause_groups: &[RootCauseGroup],
) -> impl Iterator<Item = &RootCauseGroup> {
    root_cause_groups
        .iter()
        .filter(|group| group.strongest_action != RecommendedAction::Log)
}

fn root_cause_traces(root_cause_groups: &[RootCauseGroup]) -> Vec<ExplainabilityTrace> {
    non_log_root_cause_groups(root_cause_groups)
        .take(5)
        .map(root_cause_trace)
        .collect()
}

fn compound_traces(
    compound_reasons: &[VerdictReason],
) -> impl Iterator<Item = ExplainabilityTrace> + '_ {
    compound_reasons.iter().map(compound_reason_trace)
}

fn factor_traces(
    top_risk_drivers: &[crate::findings::RiskFactor],
) -> impl Iterator<Item = ExplainabilityTrace> + '_ {
    top_risk_drivers.iter().map(trace_from_factor)
}

fn reason_label(
    scope: crate::findings::ArtifactScope,
    category: crate::findings::ThreatCategory,
    signal_class: crate::findings::SignalClass,
) -> String {
    format!("{scope}/{category}/{signal_class}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{ArtifactScope, SignalClass, ThreatCategory};

    #[test]
    fn root_cause_trace_uses_scope_and_rules() {
        let trace = root_cause_trace(&RootCauseGroup {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::RemoteExec,
            signal_class: SignalClass::MaliciousBehavior,
            finding_count: 2,
            strongest_action: RecommendedAction::Block,
            representative_rules: vec!["RULE_A".to_string(), "RULE_B".to_string()],
        });
        assert_eq!(trace.source, "root_cause_group");
        assert_eq!(trace.scope.as_deref(), Some("agent_entrypoint"));
        assert_eq!(trace.rule_ids, vec!["RULE_A".to_string(), "RULE_B".to_string()]);
    }

    #[test]
    fn collect_traces_skips_log_only_root_cause_groups() {
        let traces = collect_traces(
            &[RootCauseGroup {
                scope: ArtifactScope::SupportingArtifact,
                category: ThreatCategory::Generic,
                signal_class: SignalClass::ReviewSignal,
                finding_count: 1,
                strongest_action: RecommendedAction::Log,
                representative_rules: vec!["RULE_LOG".to_string()],
            }],
            &[],
            &[],
            &[],
        );
        assert!(traces.is_empty());
    }

    #[test]
    fn triggered_by_label_includes_scope_category_and_rules() {
        let label = triggered_by_label(&RootCauseGroup {
            scope: ArtifactScope::SupportingArtifact,
            category: ThreatCategory::SupplyChain,
            signal_class: SignalClass::ReviewSignal,
            finding_count: 2,
            strongest_action: RecommendedAction::RequireApproval,
            representative_rules: vec!["RULE_A".to_string(), "RULE_B".to_string()],
        });
        assert!(label.contains("supporting_artifact/supply_chain/review_signal"));
        assert!(label.contains("RULE_A,RULE_B"));
    }

    #[test]
    fn non_log_root_cause_iterator_excludes_log_actions() {
        let groups = vec![
            RootCauseGroup {
                scope: ArtifactScope::SupportingArtifact,
                category: ThreatCategory::Generic,
                signal_class: SignalClass::ReviewSignal,
                finding_count: 1,
                strongest_action: RecommendedAction::Log,
                representative_rules: vec!["RULE_LOG".to_string()],
            },
            RootCauseGroup {
                scope: ArtifactScope::AgentEntrypoint,
                category: ThreatCategory::RemoteExec,
                signal_class: SignalClass::MaliciousBehavior,
                finding_count: 1,
                strongest_action: RecommendedAction::Block,
                representative_rules: vec!["RULE_BLOCK".to_string()],
            },
        ];
        let kept = non_log_root_cause_groups(&groups).collect::<Vec<_>>();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].representative_rules, vec!["RULE_BLOCK".to_string()]);
    }

    #[test]
    fn collect_traces_limits_root_cause_groups_to_five_before_other_entries() {
        let groups = (0..6)
            .map(|index| RootCauseGroup {
                scope: ArtifactScope::AgentEntrypoint,
                category: ThreatCategory::RemoteExec,
                signal_class: SignalClass::MaliciousBehavior,
                finding_count: 1,
                strongest_action: RecommendedAction::Block,
                representative_rules: vec![format!("RULE_{index}")],
            })
            .collect::<Vec<_>>();

        let traces = collect_traces(
            &groups,
            &[VerdictReason {
                scope: ArtifactScope::AgentEntrypoint,
                category: ThreatCategory::RemoteExec,
                signal_class: SignalClass::MaliciousBehavior,
                rationale: "compound".to_string(),
            }],
            &[],
            &[],
        );

        assert_eq!(
            traces
                .iter()
                .filter(|trace| trace.source == "root_cause_group")
                .count(),
            5
        );
        assert_eq!(traces[5].source, "compound_reason");
    }

    #[test]
    fn root_cause_traces_keeps_first_five_non_log_groups() {
        let groups = (0..7)
            .map(|index| RootCauseGroup {
                scope: ArtifactScope::AgentEntrypoint,
                category: ThreatCategory::RemoteExec,
                signal_class: SignalClass::MaliciousBehavior,
                finding_count: 1,
                strongest_action: if index == 0 {
                    RecommendedAction::Log
                } else {
                    RecommendedAction::Block
                },
                representative_rules: vec![format!("RULE_{index}")],
            })
            .collect::<Vec<_>>();

        let traces = root_cause_traces(&groups);
        assert_eq!(traces.len(), 5);
        assert_eq!(traces[0].rule_ids, vec!["RULE_1".to_string()]);
    }

    #[test]
    fn trace_from_factor_delegates_to_source_classifier() {
        let trace = trace_from_factor(&crate::findings::RiskFactor {
            factor: "provenance:review".to_string(),
            contribution: 3,
            rationale: "review: external provenance".to_string(),
        });
        assert_eq!(trace.source, "provenance");
        assert_eq!(trace.contribution, Some(3));
    }

    #[test]
    fn factor_traces_preserve_factor_order() {
        let traces = factor_traces(&[
            crate::findings::RiskFactor {
                factor: "network:download".to_string(),
                contribution: 6,
                rationale: "review: outbound fetch".to_string(),
            },
            crate::findings::RiskFactor {
                factor: "provenance:review".to_string(),
                contribution: 3,
                rationale: "review: external provenance".to_string(),
            },
        ])
        .collect::<Vec<_>>();

        assert_eq!(traces[0].label, "network:download");
        assert_eq!(traces[1].label, "provenance:review");
    }

    #[test]
    fn compound_traces_preserve_reason_order() {
        let traces = compound_traces(&[
            VerdictReason {
                scope: ArtifactScope::AgentEntrypoint,
                category: ThreatCategory::RemoteExec,
                signal_class: SignalClass::MaliciousBehavior,
                rationale: "first".to_string(),
            },
            VerdictReason {
                scope: ArtifactScope::SupportingArtifact,
                category: ThreatCategory::SupplyChain,
                signal_class: SignalClass::ReviewSignal,
                rationale: "second".to_string(),
            },
        ])
        .collect::<Vec<_>>();

        assert_eq!(traces[0].rationale, "first");
        assert_eq!(traces[1].rationale, "second");
    }

    #[test]
    fn collect_traces_appends_calibration_before_risk_factor_traces() {
        let traces = collect_traces(
            &[],
            &[],
            &[VerdictCalibrationNote {
                rule_id: "CAL_NOTE".to_string(),
                effect: "review_only_without_chain".to_string(),
                rationale: "review: calibration".to_string(),
            }],
            &[crate::findings::RiskFactor {
                factor: "network:download".to_string(),
                contribution: 6,
                rationale: "review: outbound fetch".to_string(),
            }],
        );

        assert_eq!(traces[0].source, "calibration");
        assert_eq!(traces[1].source, "network");
    }

    #[test]
    fn collect_traces_keeps_compound_reasons_before_calibration_and_factors() {
        let traces = collect_traces(
            &[],
            &[VerdictReason {
                scope: ArtifactScope::AgentEntrypoint,
                category: ThreatCategory::RemoteExec,
                signal_class: SignalClass::MaliciousBehavior,
                rationale: "compound".to_string(),
            }],
            &[VerdictCalibrationNote {
                rule_id: "CAL_NOTE".to_string(),
                effect: "review_only_without_chain".to_string(),
                rationale: "review: calibration".to_string(),
            }],
            &[crate::findings::RiskFactor {
                factor: "network:download".to_string(),
                contribution: 6,
                rationale: "review: outbound fetch".to_string(),
            }],
        );

        assert_eq!(traces[0].source, "compound_reason");
        assert_eq!(traces[1].source, "calibration");
        assert_eq!(traces[2].source, "network");
    }

    #[test]
    fn root_cause_trace_rationale_mentions_strongest_action() {
        let trace = root_cause_trace(&RootCauseGroup {
            scope: ArtifactScope::AgentEntrypoint,
            category: ThreatCategory::RemoteExec,
            signal_class: SignalClass::MaliciousBehavior,
            finding_count: 3,
            strongest_action: RecommendedAction::Block,
            representative_rules: vec!["RULE_A".to_string()],
        });

        assert!(trace.rationale.contains("strongest action block"));
    }

    #[test]
    fn reason_label_uses_scope_category_and_signal_class_format() {
        assert_eq!(
            reason_label(
                ArtifactScope::AgentEntrypoint,
                ThreatCategory::RemoteExec,
                SignalClass::MaliciousBehavior
            ),
            "agent_entrypoint/remote_exec/malicious_behavior"
        );
    }

    #[test]
    fn calibration_traces_preserve_note_order() {
        let traces = calibration_traces(&[
            VerdictCalibrationNote {
                rule_id: "FIRST".to_string(),
                effect: "review_only_without_chain".to_string(),
                rationale: "first".to_string(),
            },
            VerdictCalibrationNote {
                rule_id: "SECOND".to_string(),
                effect: "review_only_without_chain".to_string(),
                rationale: "second".to_string(),
            },
        ])
        .collect::<Vec<_>>();

        assert_eq!(traces[0].label, "FIRST");
        assert_eq!(traces[1].label, "SECOND");
    }
}
