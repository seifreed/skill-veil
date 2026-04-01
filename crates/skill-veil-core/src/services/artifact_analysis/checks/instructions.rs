use super::super::{
    ArtifactAnalysisService, explicit_declared_permission_rules, infer_declared_intent,
    looks_like_webhook_receiver_without_auth,
};
use crate::analysis_model::{
    ObservationBatch, ObservationFinding, ObservationSource, ObservedCapability, ObservedEvidence,
    ObservedIntent,
};
use crate::findings::{
    ArtifactKind, EvidenceKind, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use std::path::Path;

pub(crate) fn observe_instruction_family(
    _service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> ObservationBatch {
    let artifact_path = path.display().to_string();
    let mut observations = ObservationBatch::default();

    let make_finding = |rule_id: &str,
                        category: ThreatCategory,
                        severity: Severity,
                        action: RecommendedAction,
                        evidence_kind: EvidenceKind,
                        match_value: &str,
                        reason: &str| ObservationFinding {
        rule_id: rule_id.to_string(),
        category,
        severity,
        action,
        evidence_kind,
        artifact_kind,
        artifact_path: Some(artifact_path.clone()),
        match_target: MatchTarget::ReferencedFile {
            path: artifact_path.clone(),
        },
        match_value: match_value.to_string(),
        reason: reason.to_string(),
    };

    if regex::Regex::new("(?i)(persist\\s+these\\s+instructions|remember\\s+this\\s+across\\s+sessions|always\\s+follow\\s+this\\s+prompt|never\\s+reveal\\s+this\\s+instruction|override\\s+future\\s+system\\s+messages)")
        .expect("valid regex")
        .is_match(content)
    {
        observations.push_observation(ObservedEvidence::Intent(ObservedIntent {
            intent: "persistent_prompt_override".to_string(),
            source: ObservationSource::Detector("instruction_persistence".to_string()),
            finding: make_finding(
                "SEMANTIC_PERSISTENCE_COGNITIVE_ROOTKIT",
                ThreatCategory::PersistentPromptTampering,
                Severity::High,
                RecommendedAction::RequireApproval,
                EvidenceKind::Intent,
                "persistent instruction override",
                "Artifact contains persistent instruction behavior consistent with a cognitive rootkit",
            ),
        }));
    }

    if regex::Regex::new("(?i)(act\\s+as\\s+(root|administrator|system)|treat\\s+all\\s+tool\\s+requests\\s+as\\s+approved|ignore\\s+all\\s+existing\\s+safety\\s+constraints)")
        .expect("valid regex")
        .is_match(content)
    {
        observations.push_observation(ObservedEvidence::Intent(ObservedIntent {
            intent: "privileged_role_prompt".to_string(),
            source: ObservationSource::Detector("instruction_role_escalation".to_string()),
            finding: make_finding(
                "AGENT_EXTENSION_PRIVILEGED_PROMPT_ROLE",
                ThreatCategory::AutonomyEscalation,
                Severity::Medium,
                RecommendedAction::RequireApproval,
                EvidenceKind::Intent,
                "privileged agent role prompt",
                "Artifact attempts to elevate the agent role or bypass existing control boundaries",
            ),
        }));
    }

    for (rule_id, match_value, reason) in explicit_declared_permission_rules(content) {
        observations.push_observation(ObservedEvidence::Capability(ObservedCapability {
            capability: match_value.to_string(),
            source: ObservationSource::Detector("declared_permissions".to_string()),
            finding: make_finding(
                rule_id,
                ThreatCategory::ScopeCreep,
                Severity::Low,
                RecommendedAction::Log,
                EvidenceKind::Context,
                match_value,
                reason,
            ),
        }));
    }

    let (_, declared_intent_score) = infer_declared_intent(content);
    if declared_intent_score <= 1
        && observations
            .evidence
            .iter()
            .filter(|e| matches!(e, ObservedEvidence::Capability(_)))
            .count()
            >= 3
    {
        observations.push_observation(ObservedEvidence::Capability(ObservedCapability {
            capability: "broad_declared_permissions".to_string(),
            source: ObservationSource::Detector("scope_overprovisioning".to_string()),
            finding: make_finding(
                "SCOPE_OVERPROVISIONING",
                ThreatCategory::ScopeCreep,
                Severity::Medium,
                RecommendedAction::RequireApproval,
                EvidenceKind::Context,
                "broad declared permissions",
                "Artifact declares broad permissions or scopes relative to its apparent task",
            ),
        }));
    }

    if let Some(webhook_signal) = looks_like_webhook_receiver_without_auth(content) {
        observations.push_observation(ObservedEvidence::Capability(ObservedCapability {
            capability: webhook_signal.to_string(),
            source: ObservationSource::Detector("webhook_receiver".to_string()),
            finding: make_finding(
                "PUBLIC_INBOUND_ENDPOINT",
                ThreatCategory::ToolAbuse,
                Severity::Medium,
                RecommendedAction::RequireApproval,
                EvidenceKind::Behavior,
                webhook_signal,
                "Artifact describes an inbound webhook or callback receiver without clear authentication controls",
            ),
        }));
    }

    observations
}
