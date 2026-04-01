use super::super::super::signals::InstructionSignals;
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity,
    ThreatCategory,
};
use std::path::Path;

pub(super) fn semantic_persistence_findings(
    path: &Path,
    signals: InstructionSignals,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings = Vec::new();

    if signals.cognitive_rootkit {
        findings.push(
            Finding::builder(
                "SEMANTIC_PERSISTENCE_COGNITIVE_ROOTKIT",
                ThreatCategory::PersistentPromptTampering,
            )
            .severity(Severity::High)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Intent)
            .artifact(artifact_kind, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .match_value("persistent instruction override")
            .reason(
                "Artifact contains persistent instruction behavior consistent with a cognitive rootkit",
            )
            .build(),
        );
    }

    if signals.privileged_role {
        findings.push(
            Finding::builder(
                "AGENT_EXTENSION_PRIVILEGED_PROMPT_ROLE",
                ThreatCategory::AutonomyEscalation,
            )
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Intent)
            .artifact(artifact_kind, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value("privileged agent role prompt")
            .reason(
                "Artifact attempts to elevate the agent role or bypass existing control boundaries",
            )
            .build(),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cognitive_rootkit_signal_emits_persistence_finding() {
        let findings = semantic_persistence_findings(
            Path::new("AGENTS.md"),
            InstructionSignals {
                cognitive_rootkit: true,
                ..InstructionSignals::default()
            },
            ArtifactKind::AgentInstruction,
        );
        assert!(findings.iter().any(|f| f.rule_id == "SEMANTIC_PERSISTENCE_COGNITIVE_ROOTKIT"));
    }
}
