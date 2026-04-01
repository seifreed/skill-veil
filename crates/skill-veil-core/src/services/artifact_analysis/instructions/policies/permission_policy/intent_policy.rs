use super::profile_policy::DeclaredPermissionProfile;
use super::super::super::super::permissions::infer_declared_intent;
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstructionIntentScope {
    Narrow,
    Broad,
    Unknown,
}

impl InstructionIntentScope {
    fn inspect(content: &str) -> (Self, usize) {
        match infer_declared_intent(content) {
            ("narrow", score) => (Self::Narrow, score),
            ("broad", score) => (Self::Broad, score),
            _ => (Self::Unknown, 0),
        }
    }
}

pub(super) fn intent_mismatch_findings(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let (intent_scope, intent_strength) = InstructionIntentScope::inspect(content);
    let permission_profile = DeclaredPermissionProfile::inspect(content);

    if intent_scope == InstructionIntentScope::Narrow
        && intent_strength > 0
        && permission_profile.has_dangerous_combo()
    {
        vec![
            Finding::builder(
                "CAPABILITY_PERMISSION_MISMATCH",
                ThreatCategory::ScopeCreep,
            )
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Intent)
            .artifact(artifact_kind, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value("narrow intent with broad capability request")
            .reason("Artifact intent appears narrower than the capabilities or permissions it requests")
            .build(),
        ]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn narrow_intent_with_dangerous_permissions_flags_mismatch() {
        let findings = intent_mismatch_findings(
            Path::new("AGENTS.md"),
            "purpose: summarize changes\nnotes: read-only review\nexamples: inspect output\n\n\npermissions: browser: full\npermissions: write files\npermissions: run command",
            ArtifactKind::AgentInstruction,
        );
        assert!(findings.iter().any(|f| f.rule_id == "CAPABILITY_PERMISSION_MISMATCH"));
    }
}
