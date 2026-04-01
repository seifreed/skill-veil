use super::super::super::super::permissions::{explicit_declared_permission_rules, DeclaredPermissionRule};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use std::path::Path;

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct DeclaredPermissionProfile {
    declared_count: usize,
    has_dangerous_combo: bool,
}

impl DeclaredPermissionProfile {
    pub(super) fn inspect(content: &str) -> Self {
        let rules = explicit_declared_permission_rules(content);
        Self {
            declared_count: rules.len(),
            has_dangerous_combo: rules.iter().any(Self::is_dangerous_rule),
        }
    }

    pub(super) fn is_overprovisioned(self) -> bool {
        self.declared_count >= 3
    }

    pub(super) fn has_dangerous_combo(self) -> bool {
        self.has_dangerous_combo
    }

    fn is_dangerous_rule(rule: &DeclaredPermissionRule) -> bool {
        matches!(
            rule.rule_id,
            "DECLARED_PERMISSION_BROWSER_FULL"
                | "DECLARED_PERMISSION_FILE_WRITE"
                | "DECLARED_PERMISSION_SHELL_EXEC"
        )
    }
}

pub(super) fn declared_permission_findings(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings = explicit_declared_permission_rules(content)
        .into_iter()
        .map(|rule| {
            declared_permission_finding(
                artifact_kind,
                &artifact_path,
                rule.rule_id,
                rule.match_value,
                rule.reason,
            )
        })
        .collect::<Vec<_>>();

    if DeclaredPermissionProfile::inspect(content).is_overprovisioned() {
        findings.push(
            Finding::builder("SCOPE_OVERPROVISIONING", ThreatCategory::ScopeCreep)
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Context)
                .artifact(artifact_kind, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path,
                })
                .match_value("broad declared permissions")
                .reason(
                    "Artifact declares broad permissions or scopes relative to its apparent task",
                )
                .build(),
        );
    }

    findings
}

fn declared_permission_finding(
    artifact_kind: ArtifactKind,
    artifact_path: &str,
    rule_id: &'static str,
    match_value: &'static str,
    reason: &'static str,
) -> Finding {
    Finding::builder(rule_id, ThreatCategory::ScopeCreep)
        .severity(Severity::Low)
        .action(RecommendedAction::Log)
        .evidence_kind(EvidenceKind::Context)
        .artifact(artifact_kind, Some(artifact_path.to_string()))
        .matched_on(MatchTarget::ReferencedFile {
            path: artifact_path.to_string(),
        })
        .match_value(match_value)
        .reason(reason)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_marks_broad_permission_sets_as_overprovisioned() {
        let profile = DeclaredPermissionProfile::inspect(
            "permissions: browser: full\npermissions: write files\npermissions: run command",
        );
        assert!(profile.is_overprovisioned());
        assert!(profile.has_dangerous_combo());
    }
}
