use super::model::*;
use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilitySource, ArtifactGraph};
use crate::domain_types::{
    DomainReputation, LockfileCoverageSummary, LockfileInventoryEntry, ManifestInventoryEntry,
    ProvenanceTrustLevel, PublisherConsistency,
};
use serde::{Deserialize, Serialize};
use strum_macros::Display;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub total_findings: usize,
    pub by_severity: SeverityCounts,
    pub by_category: Vec<(ThreatCategory, usize)>,
    pub risk_score: u32,
    pub recommended_action: RecommendedAction,
    pub score_breakdown: Vec<RiskFactor>,
    pub action_triggers: Vec<ActionTrigger>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor: String,
    pub contribution: u32,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerdictCalibrationNote {
    pub rule_id: String,
    pub effect: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainabilityTrace {
    pub source: String,
    pub label: String,
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contribution: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerdictExplainability {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub triggered_by: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalated_by: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dampened_by: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalation_chain: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub score_contributions: Vec<RiskFactor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_contributions: Vec<ExplainabilityContribution>,
    #[serde(default)]
    pub calibration_adjustment: i32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub traces: Vec<ExplainabilityTrace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub drift_sensitive_drivers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainabilityContribution {
    pub source: String,
    pub contribution: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTrigger {
    pub action: RecommendedAction,
    pub factor: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageVerdictReport {
    pub verdict: Verdict,
    pub risk_score: u32,
    pub risk_band: RiskBand,
    pub package_health: PackageHealth,
    pub hygiene_summary: HygieneSummary,
    pub declared_permissions: Vec<DeclaredPermission>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_capabilities: Vec<SkillCapability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_capabilities: Vec<SkillCapability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_capabilities: Vec<SkillCapability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub composite_capabilities: Vec<CompositeCapability>,
    #[serde(default)]
    pub provenance: ProvenanceSummary,
    pub blast_radius_summary: BlastRadiusSummary,
    pub verdict_reasons: Vec<VerdictReason>,
    pub root_cause_groups: Vec<RootCauseGroup>,
    pub top_risk_drivers: Vec<RiskFactor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calibration_notes: Vec<VerdictCalibrationNote>,
    #[serde(default)]
    pub explainability: VerdictExplainability,
}

impl Default for PackageVerdictReport {
    fn default() -> Self {
        Self {
            verdict: Verdict::Benign,
            risk_score: 0,
            risk_band: RiskBand::Low,
            package_health: PackageHealth::Healthy,
            hygiene_summary: HygieneSummary::default(),
            declared_permissions: Vec::new(),
            declared_capabilities: Vec::new(),
            observed_capabilities: Vec::new(),
            effective_capabilities: Vec::new(),
            composite_capabilities: Vec::new(),
            provenance: ProvenanceSummary::default(),
            blast_radius_summary: BlastRadiusSummary::default(),
            verdict_reasons: Vec::new(),
            root_cause_groups: Vec::new(),
            top_risk_drivers: Vec::new(),
            top_reasons: Vec::new(),
            calibration_notes: Vec::new(),
            explainability: VerdictExplainability::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum RiskBand {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskBand {
    #[must_use]
    pub fn from_score(score: u32) -> Self {
        if score >= 80 {
            Self::Critical
        } else if score >= 50 {
            Self::High
        } else if score >= 20 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum DeclaredPermission {
    BrowserFull,
    FileWrite,
    ShellExec,
    NetworkAccess,
    SecretsAccess,
    OAuthScopes,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Display,
)]
pub enum SkillCapability {
    #[serde(rename = "filesystem.read")]
    #[strum(serialize = "filesystem.read")]
    FilesystemRead,
    #[serde(rename = "filesystem.write")]
    #[strum(serialize = "filesystem.write")]
    FilesystemWrite,
    #[serde(rename = "shell.exec")]
    #[strum(serialize = "shell.exec")]
    ShellExec,
    #[serde(rename = "process.spawn")]
    #[strum(serialize = "process.spawn")]
    ProcessSpawn,
    #[serde(rename = "network.http")]
    #[strum(serialize = "network.http")]
    NetworkHttp,
    #[serde(rename = "network.websocket")]
    #[strum(serialize = "network.websocket")]
    NetworkWebsocket,
    #[serde(rename = "network.internal")]
    #[strum(serialize = "network.internal")]
    NetworkInternal,
    #[serde(rename = "secrets.access")]
    #[strum(serialize = "secrets.access")]
    SecretsAccess,
    #[serde(rename = "identity.oauth")]
    #[strum(serialize = "identity.oauth")]
    IdentityOauth,
    #[serde(rename = "inbound.webhook")]
    #[strum(serialize = "inbound.webhook")]
    InboundWebhook,
    #[serde(rename = "persistence.semantic")]
    #[strum(serialize = "persistence.semantic")]
    PersistenceSemantic,
    #[serde(rename = "tools.browser")]
    #[strum(serialize = "tools.browser")]
    ToolsBrowser,
    #[serde(rename = "tools.mcp.remote")]
    #[strum(serialize = "tools.mcp.remote")]
    ToolsMcpRemote,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Display,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum CompositeCapability {
    SecretExfiltration,
    ShellDownloadExec,
    BrowserWriteChain,
    BrowserSessionExfiltration,
    RemoteMcpNoAuth,
    IdentityNetworkChain,
    WorkflowRemoteExec,
    WorkflowExecPersistence,
    InstallHookPersistence,
    RemoteMcpExec,
    RemoteMcpNoAuthExec,
    WritePersistenceChain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteDomainSignal {
    pub domain: String,
    pub reputation: DomainReputation,
    pub rationale: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProvenanceSummary {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub publishers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub package_sources: Vec<String>,
    #[serde(default)]
    pub trust_level: ProvenanceTrustLevel,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_factors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub package_identities: Vec<String>,
    #[serde(default)]
    pub publisher_consistency: PublisherConsistency,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_domain_signals: Vec<RemoteDomainSignal>,
    #[serde(default)]
    pub lockfile_coverage: LockfileCoverageSummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_mix_notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub manifests: Vec<ManifestInventoryEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lockfiles: Vec<LockfileInventoryEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum BlastRadiusLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlastRadiusSummary {
    pub level: Option<BlastRadiusLevel>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub factors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_targets: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_permissions: Vec<DeclaredPermission>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum PackageHealth {
    Healthy,
    NeedsReview,
    Elevated,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HygieneSummary {
    pub package_root_findings: usize,
    pub supporting_findings: usize,
    pub top_rules: Vec<String>,
}

impl FindingSummary {
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        Self::from_findings_and_graph(findings, &ArtifactGraph::new())
    }

    #[must_use]
    pub fn from_findings_and_graph(findings: &[Finding], artifact_graph: &ArtifactGraph) -> Self {
        let mut by_severity = SeverityCounts::default();
        let mut category_map = std::collections::HashMap::new();
        let mut factor_map = std::collections::HashMap::<String, RiskFactor>::new();

        let mut total_score: f32 = 0.0;

        for finding in findings {
            match finding.severity {
                Severity::Low => by_severity.low += 1,
                Severity::Medium => by_severity.medium += 1,
                Severity::High => by_severity.high += 1,
                Severity::Critical => by_severity.critical += 1,
            }

            *category_map.entry(finding.category).or_insert(0) += 1;
            total_score += finding.weighted_score();

            let evidence_factor = format!("evidence:{}", finding.evidence_kind);
            let evidence_weight = finding.evidence_kind.weight();
            factor_map
                .entry(evidence_factor.clone())
                .and_modify(|factor| factor.contribution += evidence_weight)
                .or_insert(RiskFactor {
                    factor: evidence_factor,
                    contribution: evidence_weight,
                    rationale: finding.evidence_kind.description().to_string(),
                });

            let artifact_factor = format!("artifact:{}", finding.artifact_kind);
            factor_map
                .entry(artifact_factor.clone())
                .and_modify(|factor| factor.contribution += 1)
                .or_insert(RiskFactor {
                    factor: artifact_factor,
                    contribution: 1,
                    rationale: "Risk observed in this artifact class".to_string(),
                });
        }

        let (graph_score, graph_action, graph_factors, mut action_triggers) =
            graph_risk_context(artifact_graph);
        total_score += graph_score as f32;

        for factor in graph_factors {
            factor_map
                .entry(factor.factor.clone())
                .and_modify(|existing| existing.contribution += factor.contribution)
                .or_insert(factor);
        }

        let risk_score = (total_score.min(100.0)) as u32;

        let score_based_action = if risk_score > RISK_THRESHOLD_BLOCK {
            RecommendedAction::Block
        } else if risk_score > RISK_THRESHOLD_APPROVAL {
            RecommendedAction::RequireApproval
        } else {
            RecommendedAction::Log
        };

        let finding_based_action = findings
            .iter()
            .fold(RecommendedAction::Log, |current, finding| {
                RecommendedAction::max(current, finding.recommended_action)
            });
        let recommended_action = RecommendedAction::max(
            RecommendedAction::max(score_based_action, finding_based_action),
            graph_action,
        );

        let by_category: Vec<_> = category_map.into_iter().collect();
        let mut score_breakdown: Vec<_> = factor_map.into_values().collect();
        score_breakdown.sort_by(|left, right| right.contribution.cmp(&left.contribution));

        Self {
            total_findings: findings.len(),
            by_severity,
            by_category,
            risk_score,
            recommended_action,
            score_breakdown,
            action_triggers: {
                action_triggers
                    .sort_by(|left, right| right.action.priority().cmp(&left.action.priority()));
                action_triggers
            },
        }
    }
}

fn graph_risk_context(
    artifact_graph: &ArtifactGraph,
) -> (u32, RecommendedAction, Vec<RiskFactor>, Vec<ActionTrigger>) {
    let mut total_score = 0;
    let mut action = RecommendedAction::Log;
    let mut factors = Vec::new();
    let mut triggers = Vec::new();

    for node in &artifact_graph.nodes {
        for capability in &node.capabilities {
            let source_label = match capability.source {
                ArtifactCapabilitySource::Declared => "declared",
                ArtifactCapabilitySource::Observed => "observed",
            };
            let (factor, contribution, rationale) = match capability.capability {
                ArtifactCapability::InstallExecution => (
                    format!("capability:{source_label}:install_execution"),
                    CAPABILITY_WEIGHT_INSTALL_EXECUTION,
                    format!("Artifact can execute code during installation ({source_label})"),
                ),
                ArtifactCapability::BrowserAccess => (
                    format!("capability:{source_label}:browser_access"),
                    CAPABILITY_WEIGHT_BROWSER_ACCESS,
                    format!("Artifact requests broad browser automation access ({source_label})"),
                ),
                ArtifactCapability::NetworkAccess => (
                    format!("capability:{source_label}:network_access"),
                    CAPABILITY_WEIGHT_NETWORK_ACCESS,
                    format!("Artifact can expose or request network connectivity ({source_label})"),
                ),
                ArtifactCapability::ExposesBinary => (
                    format!("capability:{source_label}:exposes_binary"),
                    CAPABILITY_WEIGHT_EXPOSES_BINARY,
                    format!("Artifact exposes executable entrypoints ({source_label})"),
                ),
                ArtifactCapability::PrivilegedRuntime => (
                    format!("capability:{source_label}:privileged_runtime"),
                    CAPABILITY_WEIGHT_PRIVILEGED_RUNTIME,
                    format!("Artifact requests privileged runtime access ({source_label})"),
                ),
                ArtifactCapability::HostFilesystemAccess => (
                    format!("capability:{source_label}:host_filesystem_access"),
                    CAPABILITY_WEIGHT_HOST_FILESYSTEM_ACCESS,
                    format!("Artifact can access host filesystem paths ({source_label})"),
                ),
                ArtifactCapability::ProcessExecution => (
                    format!("capability:{source_label}:process_execution"),
                    CAPABILITY_WEIGHT_PROCESS_EXECUTION,
                    format!("Artifact can execute child processes ({source_label})"),
                ),
                ArtifactCapability::SecretAccess => (
                    format!("capability:{source_label}:secret_access"),
                    CAPABILITY_WEIGHT_SECRET_ACCESS,
                    format!("Artifact can access or expose secrets ({source_label})"),
                ),
                ArtifactCapability::PersistenceSurface => (
                    format!("capability:{source_label}:persistence_surface"),
                    CAPABILITY_WEIGHT_PERSISTENCE_SURFACE,
                    format!("Artifact can establish persistence ({source_label})"),
                ),
                ArtifactCapability::FilesystemWrite => (
                    format!("capability:{source_label}:filesystem_write"),
                    CAPABILITY_WEIGHT_FILESYSTEM_WRITE,
                    format!("Artifact can write to the filesystem ({source_label})"),
                ),
                ArtifactCapability::IdentityAccess => (
                    format!("capability:{source_label}:identity_access"),
                    CAPABILITY_WEIGHT_IDENTITY_ACCESS,
                    format!(
                        "Artifact requests access to OAuth or identity-linked resources ({source_label})"
                    ),
                ),
                ArtifactCapability::InboundNetworkSurface => (
                    format!("capability:{source_label}:inbound_network_surface"),
                    CAPABILITY_WEIGHT_INBOUND_SURFACE,
                    format!(
                        "Artifact exposes an inbound network or webhook surface ({source_label})"
                    ),
                ),
            };

            total_score += contribution;
            factors.push(RiskFactor {
                factor,
                contribution,
                rationale: format!("{rationale}: {}", node.path),
            });
        }

        let has_privileged = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::PrivilegedRuntime);
        let has_host_fs = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::HostFilesystemAccess);
        let has_install = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::InstallExecution);
        let has_network = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::NetworkAccess);
        let has_binary = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::ExposesBinary);
        let has_secret_access = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::SecretAccess);
        let has_persistence = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::PersistenceSurface);
        let has_browser_access = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::BrowserAccess);
        let has_identity_access = node
            .capabilities
            .iter()
            .any(|fact| fact.capability == ArtifactCapability::IdentityAccess);

        if has_privileged && has_host_fs {
            total_score += CAPABILITY_COMBO_WEIGHT_PRIVILEGED_HOST;
            action = RecommendedAction::max(action, RecommendedAction::Block);
            factors.push(RiskFactor {
                factor: "capability_combo:privileged_host_filesystem".to_string(),
                contribution: CAPABILITY_COMBO_WEIGHT_PRIVILEGED_HOST,
                rationale: format!(
                    "Artifact combines privileged runtime with host filesystem access: {}",
                    node.path
                ),
            });
            triggers.push(ActionTrigger {
                action: RecommendedAction::Block,
                factor: "capability_combo:privileged_host_filesystem".to_string(),
                rationale: format!(
                    "Block forced because {} combines privileged runtime with host filesystem access",
                    node.path
                ),
            });
        }

        if has_install && has_network {
            total_score += CAPABILITY_COMBO_WEIGHT_INSTALL_NETWORK;
            action = RecommendedAction::max(action, RecommendedAction::RequireApproval);
            factors.push(RiskFactor {
                factor: "capability_combo:install_network".to_string(),
                contribution: CAPABILITY_COMBO_WEIGHT_INSTALL_NETWORK,
                rationale: format!(
                    "Artifact combines install-time execution with network access: {}",
                    node.path
                ),
            });
            triggers.push(ActionTrigger {
                action: RecommendedAction::RequireApproval,
                factor: "capability_combo:install_network".to_string(),
                rationale: format!(
                    "Approval forced because {} combines install-time execution with network access",
                    node.path
                ),
            });
        }

        if has_install && has_binary {
            total_score += CAPABILITY_COMBO_WEIGHT_INSTALL_BINARY;
            action = RecommendedAction::max(action, RecommendedAction::RequireApproval);
            factors.push(RiskFactor {
                factor: "capability_combo:install_binary".to_string(),
                contribution: CAPABILITY_COMBO_WEIGHT_INSTALL_BINARY,
                rationale: format!(
                    "Artifact combines install-time execution with exposed binaries: {}",
                    node.path
                ),
            });
            triggers.push(ActionTrigger {
                action: RecommendedAction::RequireApproval,
                factor: "capability_combo:install_binary".to_string(),
                rationale: format!(
                    "Approval forced because {} combines install-time execution with exposed binaries",
                    node.path
                ),
            });
        }

        if has_secret_access && has_network {
            action = RecommendedAction::max(action, RecommendedAction::RequireApproval);
            triggers.push(ActionTrigger {
                action: RecommendedAction::RequireApproval,
                factor: "capability_combo:secret_access_network".to_string(),
                rationale: format!(
                    "Approval forced because {} combines secret access with network connectivity",
                    node.path
                ),
            });
        }

        if has_persistence && has_network {
            action = RecommendedAction::max(action, RecommendedAction::RequireApproval);
            triggers.push(ActionTrigger {
                action: RecommendedAction::RequireApproval,
                factor: "capability_combo:persistence_network".to_string(),
                rationale: format!(
                    "Approval forced because {} combines persistence with network connectivity",
                    node.path
                ),
            });
        }

        if has_browser_access && has_identity_access {
            action = RecommendedAction::max(action, RecommendedAction::RequireApproval);
            triggers.push(ActionTrigger {
                action: RecommendedAction::RequireApproval,
                factor: "capability_combo:browser_identity_scope".to_string(),
                rationale: format!(
                    "Approval forced because {} combines broad browser automation with identity-linked access",
                    node.path
                ),
            });
        }
    }

    (total_score, action, factors, triggers)
}
