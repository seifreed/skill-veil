//! `pip.conf` detector: extra-index-url / trusted-host findings,
//! NetworkAccess capability for any index directive, and
//! SecretAccess capability when a client cert is configured.

use std::path::Path;

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_orchestration::manifests::strip_inline_ini_comment;
use crate::services::artifact_orchestration::{ArtifactLink, ArtifactOrchestratorService};

/// Yields trimmed `pip.conf` lines with their inline comment portion
/// removed and any blank-only result discarded.
///
/// `pip.conf` follows INI syntax: `#` and `;` start comments — both as
/// full-line markers AND inline trailing markers — and blank lines are
/// ignored. Directives like `extra-index-url=...` only take effect on
/// the non-comment portion. Stripping inline comments here keeps
/// downstream substring scans honest: a line like
/// `extra-index-url=https://internal.example/simple ; rotate quarterly`
/// would otherwise let the `;`-tail leak through, and a documentation
/// line like `# do NOT enable extra-index-url here` would otherwise
/// match before the helper got a chance to filter it (it now collapses
/// to empty and is skipped).
fn pip_conf_significant_lines(content: &str) -> impl Iterator<Item = &str> {
    content
        .lines()
        .map(|line| strip_inline_ini_comment(line).trim())
        .filter(|line| !line.is_empty())
}

fn pip_conf_directive_key(line: &str) -> Option<&str> {
    line.split_once('=').map(|(key, _)| key.trim())
}

fn pip_conf_key_is(line: &str, expected: &str) -> bool {
    pip_conf_directive_key(line).is_some_and(|key| key.eq_ignore_ascii_case(expected))
}

fn pip_conf_key_in(line: &str, expected: &[&str]) -> bool {
    pip_conf_directive_key(line).is_some_and(|key| {
        expected
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate))
    })
}

pub(crate) fn analyze_pip_conf(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings: Vec<_> = pip_conf_significant_lines(content)
        .filter(|line| pip_conf_key_is(line, "extra-index-url"))
        .map(|line| {
            Finding::builder("MANIFEST_PIP_CONF_EXTRA_INDEX", ThreatCategory::SupplyChain)
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Context)
                .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value(line)
                .reason("pip configuration adds an extra package index")
                .build()
        })
        .collect();

    if pip_conf_significant_lines(content).any(|line| pip_conf_key_is(line, "trusted-host")) {
        findings.push(
            Finding::builder(
                "MANIFEST_PIP_CONF_TRUSTED_HOST",
                ThreatCategory::SupplyChain,
            )
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Context)
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .match_value("trusted-host")
            .reason("pip configuration trusts a custom package host")
            .build(),
        );
    }

    findings
}

pub(crate) fn pip_conf_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut capabilities = Vec::new();
    let mut has_index_directive = false;
    let mut has_client_cert = false;
    for line in pip_conf_significant_lines(content) {
        if pip_conf_key_in(line, &["extra-index-url", "index-url"]) {
            has_index_directive = true;
        }
        if pip_conf_key_is(line, "client-cert") {
            has_client_cert = true;
        }
    }
    if has_index_directive {
        capabilities.push(ArtifactOrchestratorService::declared_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if has_client_cert {
        capabilities.push(ArtifactOrchestratorService::declared_capability(
            ArtifactCapability::SecretAccess,
        ));
    }
    capabilities
}

pub(crate) fn pip_conf_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    let mut has_index_directive = false;
    let mut has_client_cert = false;
    for line in pip_conf_significant_lines(content) {
        if pip_conf_key_in(line, &["extra-index-url", "index-url"]) {
            has_index_directive = true;
        }
        if pip_conf_key_is(line, "client-cert") {
            has_client_cert = true;
        }
    }
    if has_index_directive {
        links.push(ArtifactLink {
            target: "package-index".to_string(),
            relation: ArtifactRelation::ConnectsTo,
        });
    }
    if has_client_cert {
        links.push(ArtifactLink {
            target: "client-cert".to_string(),
            relation: ArtifactRelation::AccessesSecrets,
        });
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability_present(caps: &[ArtifactCapabilityFact], target: ArtifactCapability) -> bool {
        caps.iter().any(|fact| fact.capability == target)
    }

    fn relation_target_present(links: &[ArtifactLink], target: &str) -> bool {
        links.iter().any(|link| link.target == target)
    }

    fn finding_present(findings: &[Finding], rule_id: &str) -> bool {
        findings.iter().any(|finding| finding.rule_id == rule_id)
    }

    /// Contract: a `pip.conf` directive that appears only inside a `#` comment
    /// is documentation, not configuration; it must NOT raise NetworkAccess.
    #[test]
    fn pip_conf_capabilities_ignores_extra_index_url_inside_comment() {
        let content = "# Don't enable extra-index-url here\n";
        let caps = pip_conf_capabilities(content);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
    }

    /// Contract: an uncommented `extra-index-url=...` directive raises NetworkAccess
    /// (positive case to pin the happy path).
    #[test]
    fn pip_conf_capabilities_fires_for_uncommented_extra_index_url() {
        let content = "[global]\nextra-index-url = https://internal.example.com/simple\n";
        let caps = pip_conf_capabilities(content);
        assert!(capability_present(&caps, ArtifactCapability::NetworkAccess));
    }

    /// Contract: a `client-cert` directive only mentioned in a comment must NOT
    /// raise SecretAccess.
    #[test]
    fn pip_conf_capabilities_ignores_client_cert_inside_comment() {
        let content = "# client-cert support is documented in the README\n";
        let caps = pip_conf_capabilities(content);
        assert!(!capability_present(&caps, ArtifactCapability::SecretAccess));
    }

    /// Contract: a commented `index-url` does not produce a `package-index`
    /// relation either — relations and capabilities use the same gate.
    #[test]
    fn pip_conf_relations_ignores_commented_index_url() {
        let content = "# index-url = https://internal.example.com/simple\n";
        let links = pip_conf_relations(content);
        assert!(!relation_target_present(&links, "package-index"));
    }

    /// Contract: `analyze_pip_conf` ignores `extra-index-url` inside a `#`
    /// comment — same comment-aware contract as the capability/relation paths.
    #[test]
    fn analyze_pip_conf_ignores_extra_index_url_inside_comment() {
        let content = "# extra-index-url is risky, see security notes\n";
        let path = std::path::Path::new("/pkg/pip.conf");
        let findings = analyze_pip_conf(path, content);
        assert!(!finding_present(&findings, "MANIFEST_PIP_CONF_EXTRA_INDEX"));
    }

    /// Contract: `trusted-host` mentioned only in a comment does not fire the
    /// trusted-host finding.
    #[test]
    fn analyze_pip_conf_ignores_trusted_host_inside_comment() {
        let content = "# trusted-host should not be set in shared configs\n";
        let path = std::path::Path::new("/pkg/pip.conf");
        let findings = analyze_pip_conf(path, content);
        assert!(!finding_present(
            &findings,
            "MANIFEST_PIP_CONF_TRUSTED_HOST"
        ));
    }

    /// Contract: `;` is the alternate INI comment marker (matches the syntax
    /// pip itself uses); directives on `;`-prefixed lines must NOT fire.
    #[test]
    fn analyze_pip_conf_treats_semicolon_comments_as_comments() {
        let content = "; extra-index-url = https://internal.example.com/simple\n";
        let path = std::path::Path::new("/pkg/pip.conf");
        let findings = analyze_pip_conf(path, content);
        let caps = pip_conf_capabilities(content);
        assert!(!finding_present(&findings, "MANIFEST_PIP_CONF_EXTRA_INDEX"));
        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
    }

    /// Contract: `pip_conf_significant_lines` strips inline `;` comments
    /// before yielding lines, so `extra-index-url=https://x ; rotate
    /// quarterly` is reported via `analyze_pip_conf` without the
    /// `;`-tail leaking into the `match_value`.
    #[test]
    fn analyze_pip_conf_strips_inline_semicolon_comment_in_match_value() {
        let content = "extra-index-url=https://internal.example/simple ; rotate quarterly\n";
        let path = std::path::Path::new("/pkg/pip.conf");
        let findings = analyze_pip_conf(path, content);
        let finding = findings
            .iter()
            .find(|f| f.rule_id == "MANIFEST_PIP_CONF_EXTRA_INDEX")
            .expect("uncommented extra-index-url must still fire");
        assert!(
            !finding.match_value.contains(';'),
            "inline `;` comment must be stripped from match_value; got {:?}",
            finding.match_value,
        );
    }

    /// Contract: exact pip.conf directive keys still drive the expected
    /// findings, capabilities, and graph relations.
    #[test]
    fn pip_conf_accepts_exact_directive_keys() {
        let content = "\
index-url = https://internal.example/simple
extra-index-url = https://mirror.example/simple
trusted-host = internal.example
client-cert = /tmp/client.pem
";
        let path = std::path::Path::new("/pkg/pip.conf");
        let findings = analyze_pip_conf(path, content);
        let caps = pip_conf_capabilities(content);
        let links = pip_conf_relations(content);

        assert!(finding_present(&findings, "MANIFEST_PIP_CONF_EXTRA_INDEX"));
        assert!(finding_present(&findings, "MANIFEST_PIP_CONF_TRUSTED_HOST"));
        assert!(capability_present(&caps, ArtifactCapability::NetworkAccess));
        assert!(capability_present(&caps, ArtifactCapability::SecretAccess));
        assert!(relation_target_present(&links, "package-index"));
        assert!(relation_target_present(&links, "client-cert"));
    }

    /// Contract: directive detection is key-exact. Lookalike keys must not
    /// raise findings, capabilities, or graph relations.
    #[test]
    fn pip_conf_rejects_lookalike_directive_keys() {
        let content = "\
not-extra-index-url = https://internal.example/simple
trusted-hostname = internal.example
client-cert-path = /tmp/client.pem
";
        let path = std::path::Path::new("/pkg/pip.conf");
        let findings = analyze_pip_conf(path, content);
        let caps = pip_conf_capabilities(content);
        let links = pip_conf_relations(content);

        assert!(
            !finding_present(&findings, "MANIFEST_PIP_CONF_EXTRA_INDEX"),
            "lookalike extra-index key must not fire; got {findings:?}",
        );
        assert!(
            !finding_present(&findings, "MANIFEST_PIP_CONF_TRUSTED_HOST"),
            "lookalike trusted-host key must not fire; got {findings:?}",
        );
        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
        assert!(!capability_present(&caps, ArtifactCapability::SecretAccess));
        assert!(!relation_target_present(&links, "package-index"));
        assert!(!relation_target_present(&links, "client-cert"));
    }
}
