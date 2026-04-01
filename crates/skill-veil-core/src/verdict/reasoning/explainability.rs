mod sources;
mod traces;

use super::model::CalibrationAdjustment;
use crate::findings::{
    VerdictCalibrationNote, VerdictExplainability, VerdictReason,
};
use self::sources::{is_drift_sensitive_driver, summarize_source_contributions};
use self::traces::{collect_traces, escalation_chain_label, triggered_by_label};

pub(crate) fn build_verdict_explainability(
    root_cause_groups: &[crate::findings::RootCauseGroup],
    compound_reasons: &[VerdictReason],
    calibration_notes: &[VerdictCalibrationNote],
    top_risk_drivers: &[crate::findings::RiskFactor],
    calibration_adjustment: CalibrationAdjustment,
) -> VerdictExplainability {
    let triggered_by = root_cause_groups
        .iter()
        .filter(|group| group.strongest_action != crate::findings::RecommendedAction::Log)
        .take(5)
        .map(triggered_by_label)
        .collect();
    let escalated_by = compound_reasons
        .iter()
        .map(|reason| reason.rationale.clone())
        .collect();
    let escalation_chain = compound_reasons.iter().map(escalation_chain_label).collect();
    let dampened_by = calibration_notes
        .iter()
        .map(|note| format!("{}: {}", note.rule_id, note.rationale))
        .collect();
    let traces = collect_traces(
        root_cause_groups,
        compound_reasons,
        calibration_notes,
        top_risk_drivers,
    );
    let source_contributions = summarize_source_contributions(top_risk_drivers);
    let drift_sensitive_drivers = top_risk_drivers
        .iter()
        .filter(|factor| is_drift_sensitive_driver(factor))
        .map(|factor| factor.factor.clone())
        .collect();

    VerdictExplainability {
        triggered_by,
        escalated_by,
        dampened_by,
        escalation_chain,
        score_contributions: top_risk_drivers.to_vec(),
        source_contributions,
        calibration_adjustment: calibration_adjustment.points(),
        traces,
        drift_sensitive_drivers,
    }
}
