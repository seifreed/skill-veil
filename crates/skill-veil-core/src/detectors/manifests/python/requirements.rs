//! `requirements.txt` detector: unpinned-dependency findings and
//! capability inference (NetworkAccess for known network libs,
//! ProcessExecution for known exec libs).

use std::path::Path;

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_orchestration::manifests::strip_inline_hash_comment;
use crate::services::artifact_orchestration::ArtifactOrchestratorService;

use super::{parse_python_dep_name, PYTHON_EXEC_DEPS, PYTHON_NETWORK_DEPS, PYTHON_VCS_PREFIXES};

pub(crate) fn analyze_requirements_txt(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    content
        .lines()
        // `requirements.txt` uses `#` for comments. `;` is the PEP 508
        // environment-marker separator (`requests; python_version>='3.6'`)
        // and MUST NOT be treated as a comment marker — that's why we use
        // the `#`-only stripper here, not the INI variant.
        .map(|line| strip_inline_hash_comment(line).trim())
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("-r ") && !line.starts_with("--requirement"))
        .filter(|line| !line.starts_with("git+") && !line.starts_with("http"))
        .filter(|line| !line.starts_with("-c ") && !line.starts_with("--"))
        // `==` and `~=` are pinning operators; `!=` is exclusion
        // (`requests!=2.0` means "any version except 2.0") and is NOT a
        // pin — pre-fix it was lumped in here, so deps that combined an
        // exclusion with no real pin (e.g. `requests!=2.0`) silently
        // escaped MANIFEST_REQUIREMENTS_UNPINNED_DEP.
        .filter(|line| !line.contains("==") && !line.contains("~="))
        .map(|line| {
            Finding::builder(
                "MANIFEST_REQUIREMENTS_UNPINNED_DEP",
                ThreatCategory::SupplyChain,
            )
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .evidence_kind(EvidenceKind::Context)
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .match_value(line)
            .reason("Python requirement is not strictly pinned")
            .build()
        })
        .collect()
}

pub(crate) fn requirements_txt_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut capabilities = Vec::new();

    for raw_line in content.lines() {
        // VCS specs use `#egg=NAME` as a meaningful URL fragment, NOT a
        // comment — strip-on-`#` would discard the only place the package
        // name appears. Keep the line verbatim when it starts with a VCS
        // scheme, and strip the inline `#` comment everywhere else so
        // `requests # http client` still resolves to `requests`. `;` is
        // kept as a splitter, not a comment marker, so the PEP 508 env
        // marker (`requests; python_version>='3.6'`) cuts at the right spot.
        let trimmed = raw_line.trim();
        let line = if PYTHON_VCS_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
            trimmed
        } else {
            strip_inline_hash_comment(raw_line).trim()
        };
        if line.is_empty() {
            continue;
        }
        let Some(dep_name) = parse_python_dep_name(line) else {
            continue;
        };
        if PYTHON_NETWORK_DEPS.iter().any(|d| dep_name == *d) {
            capabilities.push(ArtifactOrchestratorService::observed_capability(
                ArtifactCapability::NetworkAccess,
            ));
        }
        if PYTHON_EXEC_DEPS.iter().any(|d| dep_name == *d) {
            capabilities.push(ArtifactOrchestratorService::observed_capability(
                ArtifactCapability::ProcessExecution,
            ));
        }
    }
    // `dedup_by_key` only collapses adjacent runs; deps emit interleaved
    // capabilities (e.g. requests, fabric, httpx, invoke), so sort first.
    capabilities.sort_by_key(|c| c.capability);
    capabilities.dedup_by_key(|c| c.capability);
    capabilities
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

    /// Contract: an inline `#` comment in `requirements.txt` is the
    /// comment portion. The pre-fix code applied the `!line.contains("==")`
    /// filter to the whole line including the comment, so a line like
    /// `requests # was: requests==2.0.0` was silently classified as
    /// pinned (the historical `==` in the comment satisfied the filter)
    /// and the real `requests` (unpinned) was never reported.
    #[test]
    fn analyze_requirements_txt_does_not_treat_comment_pin_as_pin() {
        let content = "requests # was: requests==2.0.0\n";
        let path = std::path::Path::new("/pkg/requirements.txt");
        let findings = analyze_requirements_txt(path, content);
        assert!(
            finding_present(&findings, "MANIFEST_REQUIREMENTS_UNPINNED_DEP"),
            "real unpinned dep must fire even when a comment contains `==`; got {findings:?}",
        );
    }

    /// Contract: a real `==` pin (no surrounding comment) suppresses the
    /// unpinned finding. Pins the positive case so the inline-comment
    /// strip doesn't accidentally widen the unpinned set.
    #[test]
    fn analyze_requirements_txt_respects_real_pin() {
        let content = "requests==2.31.0\n";
        let path = std::path::Path::new("/pkg/requirements.txt");
        let findings = analyze_requirements_txt(path, content);
        assert!(
            !finding_present(&findings, "MANIFEST_REQUIREMENTS_UNPINNED_DEP"),
            "real `==` pin must suppress the unpinned finding; got {findings:?}",
        );
    }

    /// Contract: `!=` is exclusion, NOT a pin. A line like `requests!=2.0`
    /// constrains the resolver to exclude 2.0 but still resolves the latest
    /// compatible release at install time, so it MUST fire the unpinned
    /// finding. Pre-fix the `.contains("!=")` clause silently swallowed
    /// these lines as if they were pinned.
    #[test]
    fn analyze_requirements_txt_flags_not_equal_as_unpinned() {
        let content = "requests!=2.0\n";
        let path = std::path::Path::new("/pkg/requirements.txt");
        let findings = analyze_requirements_txt(path, content);
        assert!(
            finding_present(&findings, "MANIFEST_REQUIREMENTS_UNPINNED_DEP"),
            "`!=` exclusion is not a pin and MUST fire MANIFEST_REQUIREMENTS_UNPINNED_DEP; \
             got {findings:?}",
        );
    }

    /// Contract: a line that combines an exclusion with a real pin (e.g.
    /// `requests==2.31.0,!=2.30.0`) is still pinned and does NOT fire.
    /// Negative case to ensure the `!=` fix didn't accidentally inflate
    /// the unpinned set when a `==` pin co-exists.
    #[test]
    fn analyze_requirements_txt_keeps_compound_pin_with_exclusion() {
        let content = "requests==2.31.0,!=2.30.0\n";
        let path = std::path::Path::new("/pkg/requirements.txt");
        let findings = analyze_requirements_txt(path, content);
        assert!(
            !finding_present(&findings, "MANIFEST_REQUIREMENTS_UNPINNED_DEP"),
            "compound spec containing `==` is pinned; must not fire; got {findings:?}",
        );
    }

    /// Contract: `requirements_txt_capabilities` parses the dep name
    /// after stripping any inline `#` comment, so `requests # http
    /// client` still flips `NetworkAccess`. Pre-fix the whole line
    /// (with comment) became the dep_name and the exact-match check
    /// against `"requests"` failed silently.
    #[test]
    fn requirements_txt_capabilities_handles_inline_hash_comment() {
        let content = "requests # http client\nsubprocess32 # back-port\n";
        let caps = requirements_txt_capabilities(content);
        assert!(
            capability_present(&caps, ArtifactCapability::NetworkAccess),
            "inline-commented `requests` must still flip NetworkAccess; got {caps:?}",
        );
        assert!(
            capability_present(&caps, ArtifactCapability::ProcessExecution),
            "inline-commented `subprocess32` must still flip ProcessExecution; got {caps:?}",
        );
    }

    /// Contract: PEP 508 environment markers like `requests;
    /// python_version=="3.6"` MUST still split the dep_name correctly —
    /// for `requirements.txt` we treat `;` as a version-spec splitter,
    /// NOT as a comment marker. Pins that the inline-`#` strip didn't
    /// accidentally swap to the INI-style strip.
    #[test]
    fn requirements_txt_capabilities_keeps_pep508_env_marker_as_splitter() {
        let content = "requests; python_version >= \"3.6\"\n";
        let caps = requirements_txt_capabilities(content);
        assert!(
            capability_present(&caps, ArtifactCapability::NetworkAccess),
            "PEP 508 marker must split dep_name correctly; got {caps:?}",
        );
    }

    /// Contract: `parse_python_dep_name` recovers the package name from the
    /// legacy VCS form `git+https://host/repo.git#egg=NAME` (also `hg+`,
    /// `svn+`, `bzr+`). Pre-fix the split-on-`=` parser produced
    /// `git+https://github.com/psf/requests.git#egg` as the dep_name, which
    /// silently failed the exact-match check against `requests`, so VCS deps
    /// for known network libs never flipped `NetworkAccess`.
    #[test]
    fn requirements_txt_capabilities_detects_vcs_egg_fragment() {
        let content = "git+https://github.com/psf/requests.git#egg=requests\n";
        let caps = requirements_txt_capabilities(content);
        assert!(
            capability_present(&caps, ArtifactCapability::NetworkAccess),
            "VCS egg=requests must flip NetworkAccess; got {caps:?}",
        );
    }

    /// Contract: PEP 508 direct reference `NAME @ URL` MUST extract `NAME`
    /// even when the URL is a VCS spec. Without the ` @ ` split, the parser
    /// falls back to splitting on `=` inside the URL and produces garbage.
    #[test]
    fn requirements_txt_capabilities_detects_pep508_direct_reference() {
        let content = "requests @ git+https://github.com/psf/requests.git\n";
        let caps = requirements_txt_capabilities(content);
        assert!(
            capability_present(&caps, ArtifactCapability::NetworkAccess),
            "PEP 508 `NAME @ URL` must flip NetworkAccess; got {caps:?}",
        );
    }

    /// Contract: VCS specs WITHOUT a recoverable name (no `egg=`, no PEP 508
    /// prefix) are not silently mapped to a wrong package — they yield
    /// `None` from `parse_python_dep_name` and contribute no capability.
    /// Negative case to ensure the VCS branch doesn't over-fire.
    #[test]
    fn requirements_txt_capabilities_skips_vcs_without_name() {
        let content = "git+https://github.com/example/internal-tool.git\n";
        let caps = requirements_txt_capabilities(content);
        assert!(
            !capability_present(&caps, ArtifactCapability::NetworkAccess),
            "anonymous VCS spec must not flip NetworkAccess; got {caps:?}",
        );
    }

    /// # Contract
    /// `requirements_txt_capabilities` must collapse capabilities to a unique
    /// set even when matching deps are interleaved across the file. Pre-fix
    /// `Vec::dedup_by_key` only removed adjacent duplicates, so a file like
    /// `requests / fabric / httpx / invoke` produced `[Net, Exec, Net, Exec]`
    /// (four facts) instead of `[Net, Exec]`, inflating the artifact graph
    /// and the capability-bonus risk score.
    #[test]
    fn requirements_txt_capabilities_collapses_interleaved_capabilities() {
        let content = "requests\nfabric\nhttpx\ninvoke\n";
        let caps = requirements_txt_capabilities(content);
        let net_count = caps
            .iter()
            .filter(|c| c.capability == ArtifactCapability::NetworkAccess)
            .count();
        let exec_count = caps
            .iter()
            .filter(|c| c.capability == ArtifactCapability::ProcessExecution)
            .count();
        assert_eq!(net_count, 1, "NetworkAccess must appear once; got {caps:?}");
        assert_eq!(
            exec_count, 1,
            "ProcessExecution must appear once; got {caps:?}",
        );
    }
}
