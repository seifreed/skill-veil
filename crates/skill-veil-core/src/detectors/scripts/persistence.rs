//! Detectors covering deferred / scheduled / boot-time execution and
//! sentinel writes that establish persistence.

use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};

use super::match_helpers::original_match_str;
use crate::services::artifact_analysis::scripts::patterns::DEFERRED_PATTERNS;

pub(crate) fn detect_deferred_execution(
    lower: &str,
    original: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rule_id, regex) in DEFERRED_PATTERNS.iter() {
        for matched in regex.find_matches(lower) {
            let evidence = original_match_str(original, lower, &matched);
            findings.push(
                Finding::builder(*rule_id, ThreatCategory::PrivilegeEscalation)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::Block)
                    .evidence_kind(EvidenceKind::Behavior)
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.to_string(),
                    })
                    .artifact(
                        ArtifactKind::ReferencedArtifact,
                        Some(artifact_path.to_string()),
                    )
                    .match_value(evidence)
                    .reason("Script configures deferred execution or persistence")
                    .build(),
            );
        }
    }
    findings
}

pub(crate) fn detect_powershell_persistence(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if language != "ps1"
        || !(content_lower.contains("new-itemproperty")
            || content_lower.contains("set-itemproperty")
            || content_lower.contains("scheduledtask")
            || content_lower.contains("register-scheduledtask"))
    {
        return Vec::new();
    }
    vec![Finding::builder(
        "SCRIPT_POWERSHELL_PERSISTENCE",
        ThreatCategory::PrivilegeEscalation,
    )
    .severity(Severity::High)
    .action(RecommendedAction::RequireApproval)
    .evidence_kind(EvidenceKind::Behavior)
    .matched_on(MatchTarget::ReferencedFile {
        path: artifact_path.to_string(),
    })
    .artifact(
        ArtifactKind::ReferencedArtifact,
        Some(artifact_path.to_string()),
    )
    .match_value("registry/scheduled task persistence")
    .reason("PowerShell script configures persistence via registry or scheduled tasks")
    .build()]
}

pub(crate) fn detect_shell_persistence_write(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if !matches!(language, "sh" | "bash" | "zsh")
        || !(content_lower.contains("> /etc/")
            || content_lower.contains("tee /etc/")
            || content_lower
                .lines()
                .any(|line| line.contains("echo ") && line.contains(">> ~/.")))
    {
        return Vec::new();
    }
    vec![Finding::builder(
        "SCRIPT_SHELL_PERSISTENCE_WRITE",
        ThreatCategory::PrivilegeEscalation,
    )
    .severity(Severity::High)
    .action(RecommendedAction::RequireApproval)
    .evidence_kind(EvidenceKind::Behavior)
    .matched_on(MatchTarget::ReferencedFile {
        path: artifact_path.to_string(),
    })
    .artifact(
        ArtifactKind::ReferencedArtifact,
        Some(artifact_path.to_string()),
    )
    .match_value("shell persistence write")
    .reason("Shell script writes to startup or system configuration paths")
    .build()]
}
