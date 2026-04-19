//! Policy generation and stable public policy contract.

pub(crate) mod baseline;
mod eval;
pub(crate) mod reports;
pub(crate) mod sarif;
pub(crate) mod serializers;
pub(crate) mod state;
pub(crate) mod types;

#[cfg(test)]
mod tests_filtering;
#[cfg(test)]
mod tests_generation;

use crate::findings::{OperationalContext, RecommendedAction, Severity};

pub use self::baseline::{BaselineEntry, BaselineFile, WaiverEntry, WaiverFile};
pub use self::reports::{JsonReport, PolicyGenerator};
pub(crate) use self::sarif::{
    SarifArtifactLocation, SarifConfiguration, SarifDriver, SarifLocation, SarifMessage,
    SarifPhysicalLocation, SarifRegion, SarifReport, SarifResult, SarifRule, SarifRun, SarifTool,
};
pub use self::serializers::empty_sarif_report;
pub use self::state::{
    apply_baseline, apply_policy_overrides, apply_policy_overrides_with_audit, apply_waivers,
    baseline_from_reports, count_baseline_matches, diff_reports, diff_reports_with_policy_state,
    finding_fingerprint, load_baseline, load_policy, load_waivers, validate_policy,
    validate_waivers,
};
pub(crate) use self::types::{default_policy_schema_version, empty_finding_summary};
pub use self::types::{
    AppliedPolicyOverride, ConfiguredProfile, ContextActionOverride, ContextPolicy, DiffEntry,
    DiffReport, PolicyAudit, PolicyFile, PolicyOverride, PolicyProfile, PolicyProfiles,
    ShieldPolicy, SuppressionSummary, POLICY_AUDIT_PRECEDENCE,
};

/// Default number of days until a shield policy expires.
pub(crate) const POLICY_EXPIRY_DAYS: i64 = 365;
/// Version string for persisted policy-related schemas.
pub const POLICY_SCHEMA_VERSION: &str = "skill-veil.dev/v1alpha1";

impl PolicyProfile {
    #[must_use]
    pub fn default_fail_on(self) -> Option<Severity> {
        match self {
            Self::Personal => Some(Severity::Critical),
            Self::Team => Some(Severity::High),
            Self::Enterprise => Some(Severity::Medium),
            Self::Research => None,
        }
    }

    #[must_use]
    pub fn default_action_for_context(self, context: OperationalContext) -> RecommendedAction {
        match self {
            Self::Personal => RecommendedAction::RequireApproval,
            Self::Team => match context {
                OperationalContext::Secrets => RecommendedAction::Block,
                _ => RecommendedAction::RequireApproval,
            },
            Self::Enterprise => match context {
                OperationalContext::Install
                | OperationalContext::Secrets
                | OperationalContext::ExternalComms => RecommendedAction::Block,
                OperationalContext::Network | OperationalContext::CodeModification => {
                    RecommendedAction::RequireApproval
                }
            },
            Self::Research => match context {
                OperationalContext::Secrets | OperationalContext::ExternalComms => {
                    RecommendedAction::RequireApproval
                }
                _ => RecommendedAction::Log,
            },
        }
    }
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            schema_version: self::types::default_policy_schema_version(),
            profiles: PolicyProfiles::default(),
            overrides: Vec::new(),
        }
    }
}

impl PolicyFile {
    #[must_use]
    pub fn profile_config(&self, profile: PolicyProfile) -> Option<&ConfiguredProfile> {
        match profile {
            PolicyProfile::Personal => self.profiles.personal.as_ref(),
            PolicyProfile::Team => self.profiles.team.as_ref(),
            PolicyProfile::Enterprise => self.profiles.enterprise.as_ref(),
            PolicyProfile::Research => self.profiles.research.as_ref(),
        }
    }

    #[must_use]
    pub fn resolve_fail_on(&self, profile: PolicyProfile) -> Option<Severity> {
        self.profile_config(profile)
            .and_then(|config| config.fail_on)
            .or_else(|| profile.default_fail_on())
    }

    #[must_use]
    pub fn resolve_context_action(
        &self,
        profile: PolicyProfile,
        context: OperationalContext,
    ) -> RecommendedAction {
        self.profile_config(profile)
            .and_then(|config| {
                config
                    .context_actions
                    .iter()
                    .find(|entry| entry.context == context)
                    .map(|entry| entry.action)
            })
            .unwrap_or_else(|| profile.default_action_for_context(context))
    }
}

impl Default for PolicyAudit {
    fn default() -> Self {
        Self {
            precedence_order: POLICY_AUDIT_PRECEDENCE
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            effective_fail_on: None,
            applied_overrides: Vec::new(),
        }
    }
}

pub(crate) fn context_label(context: OperationalContext) -> &'static str {
    match context {
        OperationalContext::Install => "install",
        OperationalContext::Network => "network",
        OperationalContext::Secrets => "secrets",
        OperationalContext::CodeModification => "code_modification",
        OperationalContext::ExternalComms => "external_comms",
    }
}

pub(crate) fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}
