use super::network::{
    contains_internal_network_action, contains_internal_network_target,
    contains_ssrf_like_fetch_line, looks_like_local_control_plane_reference,
    looks_like_local_dev_reference, looks_like_webhook_receiver_without_auth,
};
use super::permissions::{explicit_declared_permission_rules, infer_declared_intent};
use super::{ArtifactAnalysisService, ArtifactLink};
use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

const BROAD_PERMISSION_THRESHOLD: usize = 3;
const METADATA_SERVICE_IP: &str = "169.254.169.254";

static RE_BROWSER_FULL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        "(?i)(browser:\\s*full|full autonomous browser|click any element|navigation:\\s*allow-all)",
    )
    .expect("valid regex: browser full access")
});
static RE_PERSISTENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(persist\\s+these\\s+instructions|remember\\s+this\\s+across\\s+sessions|append\\s+to\\s+(agents|claude|system)\\.md)").expect("valid regex: persistence")
});
static RE_NETWORK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(http://|https://|browser tool|network tool)").expect("valid regex: network")
});
static RE_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(token|secret|cookie|password|credential|session)")
        .expect("valid regex: secret")
});
static RE_OAUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(oauth|scope|calendar|drive|slack|github pat)").expect("valid regex: oauth")
});
static RE_COGNITIVE_ROOTKIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(persist\\s+these\\s+instructions|remember\\s+this\\s+across\\s+sessions|always\\s+follow\\s+this\\s+prompt|never\\s+reveal\\s+this\\s+instruction|override\\s+future\\s+system\\s+messages)").expect("valid regex: cognitive rootkit")
});
static RE_PRIVILEGED_ROLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(act\\s+as\\s+(root|administrator|system)|treat\\s+all\\s+tool\\s+requests\\s+as\\s+approved|ignore\\s+all\\s+existing\\s+safety\\s+constraints)").expect("valid regex: privileged role")
});

fn analyze_with_kind(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    kind: ArtifactKind,
) -> Vec<Finding> {
    let mut findings = semantic_persistence_findings(service, path, content, kind);
    findings.extend(permission_and_network_findings(
        service, path, content, kind,
    ));
    findings
}

pub(super) fn analyze_instruction_file(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> Vec<Finding> {
    analyze_with_kind(service, path, content, ArtifactKind::AgentInstruction)
}

pub(super) fn analyze_skill_document(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> Vec<Finding> {
    analyze_with_kind(service, path, content, ArtifactKind::SkillDocument)
}

pub(super) fn analyze_prompt_pack(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> Vec<Finding> {
    analyze_with_kind(service, path, content, ArtifactKind::PromptPackDocument)
}

pub(super) fn instruction_relations(
    service: &ArtifactAnalysisService,
    content: &str,
) -> Vec<ArtifactLink> {
    service.generic_url_relations(content)
}

pub(super) fn instruction_capabilities(
    _service: &ArtifactAnalysisService,
    content: &str,
) -> Vec<ArtifactCapabilityFact> {
    let mut capabilities = Vec::new();
    if RE_BROWSER_FULL.is_match(content) {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::BrowserAccess,
        ));
    }
    if RE_PERSISTENCE.is_match(content) {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::PersistenceSurface,
        ));
    }
    if RE_NETWORK.is_match(content) {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if RE_SECRET.is_match(content) {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::SecretAccess,
        ));
    }
    if RE_OAUTH.is_match(content) {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::IdentityAccess,
        ));
    }
    if looks_like_webhook_receiver_without_auth(content).is_some() {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::InboundNetworkSurface,
        ));
    }
    capabilities
}

struct PersistenceSpec {
    regex: &'static LazyLock<Regex>,
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
    _service: &ArtifactAnalysisService,
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
    let mut findings = Vec::new();

    let permission_rules = explicit_declared_permission_rules(content);
    for (rule_id, match_value, reason) in &permission_rules {
        findings.push(
            Finding::builder(*rule_id, ThreatCategory::ScopeCreep)
                .severity(Severity::Low)
                .action(RecommendedAction::Log)
                .evidence_kind(EvidenceKind::Context)
                .artifact(artifact_kind, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value(*match_value)
                .reason(*reason)
                .build(),
        );
    }

    if permission_rules.len() >= BROAD_PERMISSION_THRESHOLD {
        findings.push(
            Finding::builder("SCOPE_OVERPROVISIONING", ThreatCategory::ScopeCreep)
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Context)
                .artifact(artifact_kind, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value("broad declared permissions")
                .reason(
                    "Artifact declares broad permissions or scopes relative to its apparent task",
                )
                .build(),
        );
    }

    let (intent_kind, intent_strength) = infer_declared_intent(content);
    let has_dangerous_permission_combo = permission_rules.iter().any(|(rule_id, _, _)| {
        matches!(
            *rule_id,
            "DECLARED_PERMISSION_BROWSER_FULL"
                | "DECLARED_PERMISSION_FILE_WRITE"
                | "DECLARED_PERMISSION_SHELL_EXEC"
        )
    });
    if intent_kind == "narrow" && intent_strength > 0 && has_dangerous_permission_combo {
        findings.push(
            Finding::builder("CAPABILITY_PERMISSION_MISMATCH", ThreatCategory::ScopeCreep)
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Intent)
                .artifact(artifact_kind, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value("narrow intent with broad capability request")
                .reason("Artifact intent appears narrower than the capabilities or permissions it requests")
                .build(),
        );
    }

    findings
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
    let is_metadata_service = target == METADATA_SERVICE_IP;
    let (rule_id, category, reason) = if is_metadata_service {
        (
            "METADATA_SERVICE_ACCESS",
            ThreatCategory::CredentialExposure,
            "Artifact references a metadata service target commonly used for credential discovery",
        )
    } else {
        (
            "INTERNAL_NETWORK_ACCESS",
            ThreatCategory::ToolAbuse,
            "Artifact references internal or loopback network targets",
        )
    };
    Some(
        Finding::builder(rule_id, category)
            .severity(Severity::Medium)
            .action(if is_metadata_service {
                RecommendedAction::RequireApproval
            } else {
                RecommendedAction::Log
            })
            .evidence_kind(EvidenceKind::Behavior)
            .signal_class(if is_metadata_service {
                crate::findings::SignalClass::SuspiciousPackageBehavior
            } else {
                crate::findings::SignalClass::ReviewSignal
            })
            .artifact(artifact_kind, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value(target)
            .reason(reason)
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
    let kind = looks_like_webhook_receiver_without_auth(content)?;
    let artifact_path = path.display().to_string();
    let (rule_id, reason) = match kind {
        "webhook_auth_bypass" => (
            "WEBHOOK_AUTH_BYPASS",
            "Artifact appears to define a webhook or inbound endpoint without verification or signature checks",
        ),
        _ => (
            "PUBLIC_INBOUND_ENDPOINT",
            "Artifact appears to expose a public inbound endpoint without visible authentication controls",
        ),
    };
    Some(
        Finding::builder(rule_id, ThreatCategory::ToolAbuse)
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Context)
            .artifact(artifact_kind, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value(kind)
            .reason(reason)
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
    _service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    let mut findings = declared_permission_scope_findings(path, content, artifact_kind);
    findings.extend(network_and_intent_findings(path, content, artifact_kind));
    findings
}
