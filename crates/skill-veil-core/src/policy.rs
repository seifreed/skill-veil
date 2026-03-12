//! Policy generation and stable public policy contract.

use crate::analyzer::{
    AgentExtensionKind, ArtifactClassification, ArtifactIdentitySource, StructuralValidity,
};
use crate::artifact_graph::ArtifactGraph;
use crate::findings::{Finding, OperationalContext as PolicyContext, RecommendedAction, Severity};

pub use crate::policy_state::{
    apply_baseline, apply_policy_overrides, apply_policy_overrides_with_audit, apply_waivers,
    baseline_from_reports, diff_reports, diff_reports_with_policy_state, finding_fingerprint,
    load_baseline, load_policy, load_waivers, validate_policy, validate_waivers,
};
pub use crate::policy_types::{
    AppliedPolicyOverride, BaselineEntry, BaselineFile, ConfiguredProfile, ContextActionOverride,
    ContextPolicy, DiffEntry, DiffReport, JsonReport, PolicyAudit, PolicyFile, PolicyGenerator,
    PolicyOverride, PolicyProfile, PolicyProfiles, SarifArtifactLocation, SarifConfiguration,
    SarifDriver, SarifLocation, SarifMessage, SarifPhysicalLocation, SarifRegion, SarifReport,
    SarifResult, SarifRule, SarifRun, SarifTool, ShieldPolicy, SuppressionSummary, WaiverEntry,
    WaiverFile,
};

/// Default number of days until a shield policy expires.
pub(crate) const POLICY_EXPIRY_DAYS: i64 = 365;
/// Version string for persisted policy-related schemas.
pub const POLICY_SCHEMA_VERSION: &str = "skill-veil.dev/v1alpha1";
/// Human-readable precedence order applied by the policy engine.
pub const POLICY_PRECEDENCE_ORDER: [&str; 5] = [
    "waiver",
    "baseline",
    "override",
    "profile_context",
    "graph_escalation",
];

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
    pub fn default_action_for_context(self, context: PolicyContext) -> RecommendedAction {
        match self {
            Self::Personal => RecommendedAction::RequireApproval,
            Self::Team => match context {
                PolicyContext::Secrets => RecommendedAction::Block,
                _ => RecommendedAction::RequireApproval,
            },
            Self::Enterprise => match context {
                PolicyContext::Install | PolicyContext::Secrets | PolicyContext::ExternalComms => {
                    RecommendedAction::Block
                }
                PolicyContext::Network | PolicyContext::CodeModification => {
                    RecommendedAction::RequireApproval
                }
            },
            Self::Research => match context {
                PolicyContext::Secrets | PolicyContext::ExternalComms => {
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
            schema_version: crate::policy_types::default_policy_schema_version(),
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
        context: PolicyContext,
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
            precedence_order: POLICY_PRECEDENCE_ORDER
                .iter()
                .map(ToString::to_string)
                .collect(),
            effective_fail_on: None,
            applied_overrides: Vec::new(),
        }
    }
}

impl PolicyGenerator {
    pub fn new(
        skill_name: impl Into<String>,
        skill_path: impl Into<String>,
        findings: Vec<Finding>,
        artifact_graph: ArtifactGraph,
    ) -> Self {
        Self {
            skill_name: skill_name.into(),
            skill_path: skill_path.into(),
            extension_kind: AgentExtensionKind::Skill,
            classification: ArtifactClassification::ConfirmedSkill,
            package_id: None,
            identity_source: ArtifactIdentitySource::ExplicitName,
            structural_validity: StructuralValidity::Confirmed,
            heuristic_score: 0,
            findings,
            artifact_graph,
            profile: None,
            policy: None,
            suppression_summary: SuppressionSummary::default(),
            policy_audit: PolicyAudit::default(),
        }
    }

    #[must_use]
    pub fn with_profile(mut self, profile: PolicyProfile) -> Self {
        self.profile = Some(profile);
        self
    }

    #[must_use]
    pub fn with_extension_kind(mut self, extension_kind: AgentExtensionKind) -> Self {
        self.extension_kind = extension_kind;
        self
    }

    #[must_use]
    pub fn with_artifact_classification(
        mut self,
        classification: ArtifactClassification,
        package_id: Option<String>,
        identity_source: ArtifactIdentitySource,
        structural_validity: StructuralValidity,
        heuristic_score: u8,
    ) -> Self {
        self.classification = classification;
        self.package_id = package_id;
        self.identity_source = identity_source;
        self.structural_validity = structural_validity;
        self.heuristic_score = heuristic_score;
        self
    }

    #[must_use]
    pub fn with_policy(mut self, policy: PolicyFile) -> Self {
        self.policy = Some(policy);
        self
    }

    #[must_use]
    pub fn with_suppression_summary(mut self, suppression_summary: SuppressionSummary) -> Self {
        self.suppression_summary = suppression_summary;
        self
    }

    #[must_use]
    pub fn with_policy_audit(mut self, policy_audit: PolicyAudit) -> Self {
        self.policy_audit = policy_audit;
        self
    }

    pub fn generate_shield_md(&self) -> String {
        crate::policy_serializers::generate_shield_md(self)
    }

    pub fn generate_json(&self) -> JsonReport {
        crate::policy_serializers::generate_json(self)
    }

    pub fn generate_sarif(&self) -> SarifReport {
        crate::policy_serializers::generate_sarif(self)
    }
}

pub(crate) fn context_label(context: PolicyContext) -> &'static str {
    match context {
        PolicyContext::Install => "install",
        PolicyContext::Network => "network",
        PolicyContext::Secrets => "secrets",
        PolicyContext::CodeModification => "code_modification",
        PolicyContext::ExternalComms => "external_comms",
    }
}

pub(crate) fn severity_to_sarif_level(severity: Severity) -> String {
    match severity {
        Severity::Critical | Severity::High => "error".to_string(),
        Severity::Medium => "warning".to_string(),
        Severity::Low => "note".to_string(),
    }
}

#[path = "policy_tests.rs"]
#[cfg(test)]
mod policy_tests;
