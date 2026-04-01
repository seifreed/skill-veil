pub(crate) use crate::domain_types::{CalibrationAdjustment, HeuristicSeverity};

#[derive(Debug, Clone, Copy)]
pub(super) struct RiskContributionSpec {
    pub(super) factor: &'static str,
    pub(super) contribution: u32,
    pub(super) severity: HeuristicSeverity,
    pub(super) rationale: &'static str,
}

impl RiskContributionSpec {
    pub(super) fn into_risk_factor(self) -> crate::findings::RiskFactor {
        crate::findings::RiskFactor {
            factor: self.factor.to_string(),
            contribution: self.contribution,
            rationale: format!("{}: {}", self.severity.label(), self.rationale),
        }
    }
}
