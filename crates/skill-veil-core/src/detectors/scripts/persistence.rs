//! Detectors covering deferred / scheduled / boot-time execution and
//! sentinel writes that establish persistence.

use crate::findings::{Finding, RecommendedAction, Severity, ThreatCategory};

use crate::detectors::patterns::line_contains_command_token;

use super::match_helpers::{
    findings_from_pattern_table, referenced_artifact_behavior_finding, FindingSpec,
};
use super::patterns::DEFERRED_PATTERNS;

const SHELL_PERSISTENCE_WRITE_TOKENS: &[&str] = &["echo", "printf", "cat", "tee"];

/// Lowercased path prefixes that denote a per-user home dotfile. `~` is the
/// interactive shorthand; install scripts overwhelmingly use the `$HOME` /
/// `${HOME}` environment-variable forms, which expand to the same place, so
/// the persistence detector must treat all three as the same surface. (The
/// detector runs on the ASCII-lowercased view, hence the lowercase `home`.)
const HOME_DOTFILE_PREFIXES: &[&str] = &["~/.", "$home/.", "${home}/."];

pub(crate) fn detect_deferred_execution(
    lower: &str,
    original: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    findings_from_pattern_table(
        &DEFERRED_PATTERNS,
        lower,
        original,
        artifact_path,
        FindingSpec {
            category: ThreatCategory::PrivilegeEscalation,
            severity: Severity::Medium,
            action: RecommendedAction::Block,
            reason: "Script configures deferred execution or persistence",
        },
    )
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
    vec![referenced_artifact_behavior_finding(
        "SCRIPT_POWERSHELL_PERSISTENCE",
        ThreatCategory::PrivilegeEscalation,
        Severity::High,
        RecommendedAction::RequireApproval,
        artifact_path,
        "registry/scheduled task persistence",
        "PowerShell script configures persistence via registry or scheduled tasks",
    )]
}

pub(crate) fn detect_shell_persistence_write(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if !matches!(language, "sh" | "bash" | "zsh" | "ksh" | "fish")
        || !content_lower.lines().any(is_shell_persistence_write_line)
    {
        return Vec::new();
    }
    vec![referenced_artifact_behavior_finding(
        "SCRIPT_SHELL_PERSISTENCE_WRITE",
        ThreatCategory::PrivilegeEscalation,
        Severity::High,
        RecommendedAction::RequireApproval,
        artifact_path,
        "shell persistence write",
        "Shell script writes to startup or system configuration paths",
    )]
}

fn is_shell_persistence_write_line(line: &str) -> bool {
    line_invokes_tee_to_startup_target(line)
        // A redirect into a system config path is high-signal on its own.
        || line_redirects_to(line, "/etc/")
        // A redirect into a home dotfile is more common benignly, so it
        // additionally requires a write-command token.
        || (line_redirects_to_home_dotfile(line)
            && SHELL_PERSISTENCE_WRITE_TOKENS
                .iter()
                .any(|token| line_contains_command_token(line, token)))
}

fn line_redirects_to_home_dotfile(line: &str) -> bool {
    HOME_DOTFILE_PREFIXES
        .iter()
        .any(|prefix| line_redirects_to(line, prefix))
}

/// True when `line` redirects (`>` or `>>`) into a target beginning with
/// `prefix`, tolerating any whitespace between the operator and the
/// target and an optional opening quote. Pre-fix the detector matched
/// `contains("> /etc/")` / `contains(">> ~/.")`, which assumed an exact
/// operator+space layout and missed `>/etc/profile`, `>>~/.bashrc`, and
/// single-`>` truncating writes to a startup file — all standard shell.
fn line_redirects_to(line: &str, prefix: &str) -> bool {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'>' {
            let mut j = i + 1;
            if j < bytes.len() && bytes[j] == b'>' {
                j += 1;
            }
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t') {
                j += 1;
            }
            if line[j..]
                .trim_start_matches(['"', '\''])
                .starts_with(prefix)
            {
                return true;
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    false
}

fn line_invokes_tee_to_startup_target(line: &str) -> bool {
    line_contains_command_token(line, "tee")
        && line.split_whitespace().any(|token| {
            let target = token.trim_matches(['"', '\'']);
            target.starts_with("/etc/")
                || HOME_DOTFILE_PREFIXES
                    .iter()
                    .any(|prefix| target.starts_with(prefix))
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

    /// Contract: a dotfile persistence write addressed via `$HOME` /
    /// `${HOME}` (the form install scripts actually use) MUST fire, just
    /// like the `~/.` shorthand. Pre-fix the home arm matched only literal
    /// `~/.`, so `echo evil >> $HOME/.bashrc` — textbook scripted
    /// persistence — evaded `SCRIPT_SHELL_PERSISTENCE_WRITE`. Covers the
    /// redirect and `tee` forms; a non-dotfile `$HOME` write stays clean.
    #[test]
    fn detect_shell_persistence_write_fires_on_home_env_var_dotfiles() {
        for content in [
            "echo 'evil' >> $HOME/.bashrc\n",
            "echo 'evil' >> ${HOME}/.zshrc\n",
            "printf x >> $HOME/.profile\n",
            "echo 'evil' | tee -a $HOME/.bash_profile\n",
        ] {
            let lower = content.to_ascii_lowercase();
            let findings = detect_shell_persistence_write(&lower, "sh", "/tmp/install.sh");
            assert!(
                !findings.is_empty(),
                "must fire on {content:?}; got {findings:?}",
            );
        }
        // A non-dotfile write under $HOME is not persistence — stays clean.
        let benign = "echo data >> $HOME/output.log\n".to_ascii_lowercase();
        assert!(
            detect_shell_persistence_write(&benign, "sh", "/tmp/x.sh").is_empty(),
            "a non-dotfile $HOME write must not fire",
        );
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
    /// Space-less and single-`>` redirects to startup/system paths are
    /// persistence writes too. Pre-fix `contains("> /etc/")` /
    /// `contains(">> ~/.")` assumed an exact operator+space layout and
    /// missed `>/etc/profile`, `>>~/.bashrc`, and truncating `> ~/.zshrc`.
    #[test]
    fn detect_shell_persistence_write_accepts_spaceless_and_single_redirect() {
        for content in [
            "echo 'evil' >/etc/profile\n",
            "echo 'evil' >>/etc/cron.d/x\n",
            "echo 'evil' >>~/.bashrc\n",
            "echo 'evil' > ~/.zshrc\n",
            "echo 'evil' >~/.profile\n",
        ] {
            let lower = content.to_ascii_lowercase();
            let findings = detect_shell_persistence_write(&lower, "sh", "/tmp/install.sh");
            assert_eq!(findings.len(), 1, "{content:?} must be detected");
        }
    }

    /// # Contract (negative)
    ///
    /// A stderr redirect (`2>&1`) and a redirect to a non-startup path
    /// must NOT be flagged as persistence.
    #[test]
    fn detect_shell_persistence_write_ignores_non_startup_redirects() {
        for content in ["run 2>&1 >/tmp/out.log\n", "echo hi > ./local.txt\n"] {
            let lower = content.to_ascii_lowercase();
            let findings = detect_shell_persistence_write(&lower, "sh", "/tmp/install.sh");
            assert!(findings.is_empty(), "{content:?} must not be flagged");
        }
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
