use super::{ArtifactLink, ArtifactOrchestratorService};
use crate::analyzer::SkillDocument;
use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact};
use crate::detectors::instructions::intent_policy;
use crate::detectors::instructions::signals::{
    RE_BROWSER_FULL, RE_COGNITIVE_ROOTKIT, RE_NETWORK, RE_OAUTH, RE_PERSISTENCE,
    RE_PRIVILEGED_ROLE, RE_SECRET,
};
use crate::detectors::network::targets::{
    contains_internal_network_action, contains_internal_network_target,
    contains_ssrf_like_fetch_line, looks_like_local_control_plane_reference,
    looks_like_local_dev_reference,
};
use crate::detectors::network::webhook::{classify_webhook_exposure, WebhookExposure};
use crate::detectors::permissions::{explicit_declared_permission_rules, infer_declared_intent};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::ports::CompiledPattern;
use std::path::Path;
use std::sync::LazyLock;

const BROAD_PERMISSION_THRESHOLD: usize = 3;

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

fn over_provisioning_finding(
    permission_rules: &[(&str, &str, &str)],
    artifact_path: &str,
    artifact_kind: ArtifactKind,
) -> Option<Finding> {
    (permission_rules.len() >= BROAD_PERMISSION_THRESHOLD).then(|| {
        Finding::builder("SCOPE_OVERPROVISIONING", ThreatCategory::ScopeCreep)
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Context)
            .artifact(artifact_kind, Some(artifact_path.to_string()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.to_string(),
            })
            .match_value("broad declared permissions")
            .reason("Artifact declares broad permissions or scopes relative to its apparent task")
            .build()
    })
}

fn capability_permission_mismatch_finding(
    permission_rules: &[(&str, &str, &str)],
    content: &str,
    artifact_path: &str,
    artifact_kind: ArtifactKind,
) -> Option<Finding> {
    let (intent_kind, intent_strength) = infer_declared_intent(content);
    let has_dangerous_permission_combo = permission_rules.iter().any(|(rule_id, _, _)| {
        matches!(
            *rule_id,
            "DECLARED_PERMISSION_BROWSER_FULL"
                | "DECLARED_PERMISSION_FILE_WRITE"
                | "DECLARED_PERMISSION_SHELL_EXEC"
        )
    });
    (intent_kind == "narrow" && intent_strength > 0 && has_dangerous_permission_combo).then(|| {
        Finding::builder("CAPABILITY_PERMISSION_MISMATCH", ThreatCategory::ScopeCreep)
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Intent)
            .artifact(artifact_kind, Some(artifact_path.to_string()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.to_string(),
            })
            .match_value("narrow intent with broad capability request")
            .reason(
                "Artifact intent appears narrower than the capabilities or permissions it requests",
            )
            .build()
    })
}

fn check_internal_network_target(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Option<Finding> {
    let target = contains_internal_network_target(content)?;
    if !(matches!(
        artifact_kind,
        ArtifactKind::ReferencedArtifact | ArtifactKind::McpServerManifest
    ) || contains_internal_network_action(content))
        || looks_like_local_dev_reference(content)
    {
        return None;
    }
    let artifact_path = path.display().to_string();
    Some(
        Finding::builder(target.rule_id(), target.threat_category())
            .severity(Severity::Medium)
            .action(target.action())
            .evidence_kind(EvidenceKind::Behavior)
            .signal_class(target.signal_class())
            .artifact(artifact_kind, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value(target.label())
            .reason(target.reason())
            .build(),
    )
}

fn check_ssrf_like_fetch(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
    has_internal_target: bool,
) -> Option<Finding> {
    if !contains_ssrf_like_fetch_line(content)
        || !has_internal_target
        || looks_like_local_dev_reference(content)
        || looks_like_local_control_plane_reference(content)
    {
        return None;
    }
    let artifact_path = path.display().to_string();
    Some(
        Finding::builder("SSRF_LIKE_FETCH", ThreatCategory::ToolAbuse)
            .severity(Severity::High)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Behavior)
            .signal_class(crate::findings::SignalClass::SuspiciousPackageBehavior)
            .artifact(artifact_kind, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value("internal fetch target")
            .reason("Artifact combines fetch-style behavior with internal network targets")
            .build(),
    )
}

fn check_webhook_without_auth(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Option<Finding> {
    let kind = classify_webhook_exposure(content)?;
    let artifact_path = path.display().to_string();
    let action = match kind {
        WebhookExposure::AuthBypass => RecommendedAction::Block,
        WebhookExposure::PublicInboundEndpoint => RecommendedAction::RequireApproval,
    };
    Some(
        Finding::builder(kind.finding_rule_id(), ThreatCategory::ToolAbuse)
            .severity(Severity::Medium)
            .action(action)
            .evidence_kind(EvidenceKind::Context)
            .artifact(artifact_kind, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value(kind.label())
            .reason(kind.finding_reason())
            .build(),
    )
}

fn network_and_intent_findings(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    let has_internal_target = contains_internal_network_target(content).is_some();
    [
        check_internal_network_target(path, content, artifact_kind),
        check_ssrf_like_fetch(path, content, artifact_kind, has_internal_target),
        check_webhook_without_auth(path, content, artifact_kind),
    ]
    .into_iter()
    .flatten()
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
    }
    findings
}
