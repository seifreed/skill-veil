use super::{ArtifactLink, ArtifactOrchestratorService};
use crate::analyzer::SkillDocument;
use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact};
use crate::detectors::instructions::dropper_delivery;
use crate::detectors::instructions::intent_policy;
use crate::detectors::instructions::signals::{
    RE_BROWSER_FULL, RE_COGNITIVE_ROOTKIT, RE_NETWORK, RE_OAUTH, RE_PERSISTENCE,
    RE_PRIVILEGED_ROLE, RE_SECRET,
};
use crate::detectors::network::findings::network_and_intent_findings;
use crate::detectors::network::webhook::classify_webhook_exposure;
use crate::detectors::permissions::{
    capability_permission_mismatch_finding, explicit_declared_permission_rules,
    over_provisioning_finding,
};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::ports::CompiledPattern;
use std::path::Path;
use std::sync::LazyLock;

fn analyze_with_kind(
    service: &ArtifactOrchestratorService,
    path: &Path,
    content: &str,
    kind: ArtifactKind,
    document: Option<&SkillDocument>,
) -> Vec<Finding> {
    let mut findings = semantic_persistence_findings(service, path, content, kind);
    findings.extend(permission_and_network_findings(
        service, path, content, kind, document,
    ));
    findings
}

pub(super) fn analyze_instruction_file(
    service: &ArtifactOrchestratorService,
    path: &Path,
    content: &str,
    document: Option<&SkillDocument>,
) -> Vec<Finding> {
    analyze_with_kind(
        service,
        path,
        content,
        ArtifactKind::AgentInstruction,
        document,
    )
}

pub(super) fn analyze_skill_document(
    service: &ArtifactOrchestratorService,
    path: &Path,
    content: &str,
    document: Option<&SkillDocument>,
) -> Vec<Finding> {
    analyze_with_kind(
        service,
        path,
        content,
        ArtifactKind::SkillDocument,
        document,
    )
}

pub(super) fn analyze_prompt_pack(
    service: &ArtifactOrchestratorService,
    path: &Path,
    content: &str,
    document: Option<&SkillDocument>,
) -> Vec<Finding> {
    analyze_with_kind(
        service,
        path,
        content,
        ArtifactKind::PromptPackDocument,
        document,
    )
}

pub(super) fn instruction_relations(
    service: &ArtifactOrchestratorService,
    content: &str,
) -> Vec<ArtifactLink> {
    service.generic_url_relations(content)
}

pub(super) fn instruction_capabilities(
    _service: &ArtifactOrchestratorService,
    content: &str,
) -> Vec<ArtifactCapabilityFact> {
    let mut capabilities = Vec::new();
    if RE_BROWSER_FULL.is_match(content) {
        capabilities.push(ArtifactOrchestratorService::declared_capability(
            ArtifactCapability::BrowserAccess,
        ));
    }
    if RE_PERSISTENCE.is_match(content) {
        capabilities.push(ArtifactOrchestratorService::declared_capability(
            ArtifactCapability::PersistenceSurface,
        ));
    }
    if RE_NETWORK.is_match(content) {
        capabilities.push(ArtifactOrchestratorService::observed_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if RE_SECRET.is_match(content) {
        capabilities.push(ArtifactOrchestratorService::observed_capability(
            ArtifactCapability::SecretAccess,
        ));
    }
    if RE_OAUTH.is_match(content) {
        capabilities.push(ArtifactOrchestratorService::declared_capability(
            ArtifactCapability::IdentityAccess,
        ));
    }
    if classify_webhook_exposure(content).is_some() {
        capabilities.push(ArtifactOrchestratorService::observed_capability(
            ArtifactCapability::InboundNetworkSurface,
        ));
    }
    capabilities
}

struct PersistenceSpec {
    regex: &'static LazyLock<CompiledPattern>,
    rule_id: &'static str,
    category: ThreatCategory,
    severity: Severity,
    match_value: &'static str,
    reason: &'static str,
}

fn persistence_finding_if_match(
    spec: &PersistenceSpec,
    content: &str,
    artifact_path: &str,
    artifact_kind: ArtifactKind,
) -> Option<Finding> {
    spec.regex.is_match(content).then(|| {
        Finding::builder(spec.rule_id, spec.category)
            .severity(spec.severity)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Intent)
            .artifact(artifact_kind, Some(artifact_path.to_string()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.to_string(),
            })
            .match_value(spec.match_value)
            .reason(spec.reason)
            .build()
    })
}

fn semantic_persistence_findings(
    _service: &ArtifactOrchestratorService,
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let specs = [
        PersistenceSpec {
            regex: &RE_COGNITIVE_ROOTKIT,
            rule_id: "SEMANTIC_PERSISTENCE_COGNITIVE_ROOTKIT",
            category: ThreatCategory::PersistentPromptTampering,
            severity: Severity::High,
            match_value: "persistent instruction override",
            reason: "Artifact contains persistent instruction behavior consistent with a cognitive rootkit",
        },
        PersistenceSpec {
            regex: &RE_PRIVILEGED_ROLE,
            rule_id: "AGENT_EXTENSION_PRIVILEGED_PROMPT_ROLE",
            category: ThreatCategory::AutonomyEscalation,
            severity: Severity::Medium,
            match_value: "privileged agent role prompt",
            reason: "Artifact attempts to elevate the agent role or bypass existing control boundaries",
        },
    ];
    specs
        .iter()
        .filter_map(|spec| {
            persistence_finding_if_match(spec, content, &artifact_path, artifact_kind)
        })
        .collect()
}

fn declared_permission_scope_findings(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let permission_rules = explicit_declared_permission_rules(content);
    let mut findings =
        explicit_permission_findings(&permission_rules, &artifact_path, artifact_kind);
    findings.extend(over_provisioning_finding(
        &permission_rules,
        &artifact_path,
        artifact_kind,
    ));
    findings.extend(capability_permission_mismatch_finding(
        &permission_rules,
        content,
        &artifact_path,
        artifact_kind,
    ));
    findings
}

fn explicit_permission_findings(
    permission_rules: &[(&str, &str, &str)],
    artifact_path: &str,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    permission_rules
        .iter()
        .map(|(rule_id, match_value, reason)| {
            Finding::builder(*rule_id, ThreatCategory::ScopeCreep)
                .severity(Severity::Low)
                .action(RecommendedAction::Log)
                .evidence_kind(EvidenceKind::Context)
                .artifact(artifact_kind, Some(artifact_path.to_string()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.to_string(),
                })
                .match_value(*match_value)
                .reason(*reason)
                .build()
        })
        .collect()
}

pub(super) fn permission_and_network_findings(
    _service: &ArtifactOrchestratorService,
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
    document: Option<&SkillDocument>,
) -> Vec<Finding> {
    let mut findings = declared_permission_scope_findings(path, content, artifact_kind);
    findings.extend(network_and_intent_findings(path, content, artifact_kind));
    if let Some(doc) = document {
        findings.extend(intent_policy::remote_instruction_download_findings(
            path,
            doc,
            artifact_kind,
        ));
        findings.extend(dropper_delivery::fake_dependency_dropper_findings(
            path,
            doc,
            artifact_kind,
        ));
    }
    findings
}
