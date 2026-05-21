//! Detectors covering deferred / scheduled / boot-time execution and
//! sentinel writes that establish persistence.

use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};

use crate::detectors::patterns::line_contains_command_token;

use super::match_helpers::original_match_str;
use super::patterns::DEFERRED_PATTERNS;

const SHELL_PERSISTENCE_WRITE_TOKENS: &[&str] = &["echo", "printf", "cat", "tee"];

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
            || content_lower.lines().any(is_shell_persistence_write_line))
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

fn is_shell_persistence_write_line(line: &str) -> bool {
    line_invokes_tee_to_startup_target(line)
        || (line.contains(">> ~/.")
            && SHELL_PERSISTENCE_WRITE_TOKENS
                .iter()
                .any(|token| line_contains_command_token(line, token)))
}

fn line_invokes_tee_to_startup_target(line: &str) -> bool {
    line_contains_command_token(line, "tee")
        && line.split_whitespace().any(|token| {
            let target = token.trim_matches(['"', '\'']);
            target.starts_with("/etc/") || target.starts_with("~/.")
        })
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

    /// # Contract
    ///
    /// Shell startup writes are detected when the write command is separated
    /// from its first argument by a tab.
    #[test]
    fn detect_shell_persistence_write_accepts_tab_separated_dotfile_write() {
        let content = "printf\t'payload' >> ~/.profile\n";
        let lower = content.to_ascii_lowercase();
        let findings = detect_shell_persistence_write(&lower, "sh", "/tmp/install.sh");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0].recommended_action,
            RecommendedAction::RequireApproval
        );
    }

    /// # Contract
    ///
    /// `tee` writes to startup targets are persistence writes even when the
    /// target is separated by a tab or by an option.
    #[test]
    fn detect_shell_persistence_write_accepts_tee_startup_targets() {
        for content in ["tee\t/etc/profile\n", "tee -a ~/.profile\n"] {
            let lower = content.to_ascii_lowercase();
            let findings = detect_shell_persistence_write(&lower, "bash", "/tmp/install.sh");
            assert_eq!(findings.len(), 1, "{content:?} must be detected");
        }
    }

    /// # Contract (negative)
    ///
    /// Shell persistence write command matching is token-aware. Lookalike
    /// command names do not make a startup-file write by themselves.
    #[test]
    fn detect_shell_persistence_write_rejects_command_substrings() {
        for content in [
            "myprintf\t'payload' >> ~/.profile\n",
            "guarantee\t/etc/profile\n",
        ] {
            let lower = content.to_ascii_lowercase();
            let findings = detect_shell_persistence_write(&lower, "sh", "/tmp/install.sh");
            assert!(findings.is_empty(), "{content:?} must not be detected");
        }
    }
}
