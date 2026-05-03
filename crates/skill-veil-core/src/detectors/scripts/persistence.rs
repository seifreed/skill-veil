//! Detectors covering deferred / scheduled / boot-time execution and
//! sentinel writes that establish persistence.

use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};

use super::match_helpers::original_match_str;
use super::patterns::DEFERRED_PATTERNS;

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
    if !matches!(language, "ps1" | "psm1" | "psd1")
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
    if !matches!(language, "sh" | "bash" | "zsh" | "ksh" | "fish")
        || !(content_lower.contains("> /etc/")
            || content_lower.contains("tee /etc/")
            || content_lower
                .lines()
                .any(|line| {
                    let has_dotfile_append = line.contains(">> ~/.");
                    if !has_dotfile_append {
                        return false;
                    }
                    // Accept common write verbs that precede `>> ~/.`:
                    // echo, printf, cat, tee -a. Pre-fix only `echo `
                    // was accepted, so `printf >> ~/.bashrc`, `cat x >> ~/.zshrc`,
                    // and `tee -a ~/.profile` all escaped detection.
                    line.contains("echo ")
                        || line.contains("printf ")
                        || line.contains("cat ")
                        || line.contains("tee ")
                }))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: `detect_shell_persistence_write` MUST fire on KornShell
    /// (`.ksh`) and Fish (`.fish`) scripts. Pre-fix only `sh | bash | zsh`
    /// were accepted, so a `.ksh` script writing to `/etc/` or `>> ~/.`
    /// escaped detection entirely.
    #[test]
    fn detect_shell_persistence_write_fires_for_ksh_and_fish() {
        let content = "echo 'malicious' >> ~/.bashrc\n";
        let lower = content.to_ascii_lowercase();
        for lang in ["sh", "bash", "zsh", "ksh", "fish"] {
            let findings = detect_shell_persistence_write(&lower, lang, "/tmp/install.sh");
            assert!(
                !findings.is_empty(),
                "{lang}: detect_shell_persistence_write must fire on >> ~/.bashrc; got {findings:?}",
            );
        }
    }

    /// Contract: `detect_powershell_persistence` MUST fire on `.psm1`
    /// (PowerShell module) files. Pre-fix only `"ps1"` was accepted, so a
    /// `.psm1` module with `Register-ScheduledTask` escaped detection.
    #[test]
    fn detect_powershell_persistence_fires_for_psm1() {
        let content = "Register-ScheduledTask -TaskName 'evil'\n";
        let lower = content.to_ascii_lowercase();
        for lang in ["ps1", "psm1", "psd1"] {
            let findings = detect_powershell_persistence(&lower, lang, "/tmp/mod.psm1");
            assert!(
                !findings.is_empty(),
                "{lang}: detect_powershell_persistence must fire on Register-ScheduledTask; got {findings:?}",
            );
        }
    }
}
