//! `.npmrc` detector: surfaces embedded `_authToken=` credentials and
//! custom registries pointing at non-default endpoints.

use std::path::Path;

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::artifact_orchestration::manifests::strip_inline_ini_comment;
use crate::services::artifact_orchestration::{ArtifactLink, ArtifactOrchestratorService};

/// Whether a single `.npmrc` line carries non-comment, non-empty content
/// after stripping any inline `#` or `;` INI comment.
fn npmrc_code_lines(content: &str) -> impl Iterator<Item = &str> {
    content
        .lines()
        .map(|line| strip_inline_ini_comment(line).trim())
        .filter(|line| !line.is_empty())
}

fn redact_npmrc_auth_token(line: &str) -> String {
    line.split_once('=').map_or_else(
        || "_authToken=<redacted>".to_string(),
        |(key, _)| format!("{}=<redacted>", key.trim()),
    )
}

pub(crate) fn analyze_npmrc(path: &Path, content: &str) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings: Vec<_> = npmrc_code_lines(content)
        .filter(|line| line.to_ascii_lowercase().contains("_authtoken="))
        .map(|line| {
            Finding::builder(
                "MANIFEST_NPMRC_EMBEDDED_TOKEN",
                ThreatCategory::CredentialExposure,
            )
            .severity(Severity::High)
            .action(RecommendedAction::Block)
            .evidence_kind(EvidenceKind::Behavior)
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .match_value(redact_npmrc_auth_token(line))
            .reason("npm configuration embeds an authentication token")
            .build()
        })
        .collect();

    if npmrc_code_lines(content).any(|line| line.to_ascii_lowercase().starts_with("registry=http"))
    {
        findings.push(
            Finding::builder(
                "MANIFEST_NPMRC_CUSTOM_REGISTRY",
                ThreatCategory::SupplyChain,
            )
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Context)
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .match_value("registry")
            .reason("npm configuration overrides the default registry")
            .build(),
        );
    }

    findings
}

pub(crate) fn npmrc_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let mut has_token = false;
    let mut has_registry = false;
    for line in npmrc_code_lines(content) {
        let lower = line.to_ascii_lowercase();
        if !has_token && lower.contains("_authtoken=") {
            has_token = true;
        }
        if !has_registry && lower.starts_with("registry=http") {
            has_registry = true;
        }
    }
    let mut capabilities = Vec::new();
    if has_token {
        capabilities.push(ArtifactOrchestratorService::declared_capability(
            ArtifactCapability::SecretAccess,
        ));
    }
    if has_registry {
        capabilities.push(ArtifactOrchestratorService::declared_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    capabilities
}

pub(crate) fn npmrc_relations(content: &str) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    let mut has_token = false;
    let mut has_registry = false;
    for line in npmrc_code_lines(content) {
        let lower = line.to_ascii_lowercase();
        if !has_token && lower.contains("_authtoken=") {
            has_token = true;
        }
        if !has_registry && lower.starts_with("registry=http") {
            has_registry = true;
        }
    }
    if has_token {
        links.push(ArtifactLink {
            target: "credential-store".to_string(),
            relation: ArtifactRelation::AccessesSecrets,
        });
    }
    if has_registry {
        links.push(ArtifactLink {
            target: "package-registry".to_string(),
            relation: ArtifactRelation::ConnectsTo,
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

    fn finding_present(findings: &[Finding], rule_id: &str) -> bool {
        findings.iter().any(|finding| finding.rule_id == rule_id)
    }

    /// Contract: a `;`-prefixed `.npmrc` line is a full-line INI comment
    /// and MUST NOT raise `MANIFEST_NPMRC_EMBEDDED_TOKEN`. The pre-fix
    /// code only treated `#` as a comment marker, so a documentation
    /// line showing a token setting would fire a High-severity Block
    /// finding.
    #[test]
    fn analyze_npmrc_treats_semicolon_lines_as_comments() {
        let content = format!(
            "; example for ops handoff\n; {}={}\n",
            "_authToken", "PROD_TOKEN_PLACEHOLDER"
        );
        let path = std::path::Path::new("/pkg/.npmrc");
        let findings = analyze_npmrc(path, &content);
        assert!(
            !finding_present(&findings, "MANIFEST_NPMRC_EMBEDDED_TOKEN"),
            "`;`-prefixed lines must be treated as comments; got {findings:?}",
        );
    }

    /// Contract: an inline `;` after a real `_authtoken=` is the comment
    /// portion. The match_value preserves only the code before the
    /// inline comment.
    #[test]
    fn analyze_npmrc_strips_inline_semicolon_comment_in_match_value() {
        let content = format!("{}={} ; rotate quarterly\n", "_authToken", "secret123");
        let path = std::path::Path::new("/pkg/.npmrc");
        let findings = analyze_npmrc(path, &content);
        assert_eq!(findings.len(), 1, "the real token must still fire");
        assert!(
            !findings[0].match_value.contains(';'),
            "match_value must not include the inline `;` comment portion; got {:?}",
            findings[0].match_value,
        );
    }

    /// # Contract
    ///
    /// Token findings must not echo the credential value into reports.
    #[test]
    fn analyze_npmrc_redacts_token_value_in_match_value() {
        let content = format!("{}={}\n", "_authToken", "secret123");
        let path = std::path::Path::new("/pkg/.npmrc");
        let findings = analyze_npmrc(path, &content);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].match_value, "_authToken=<redacted>");
        assert!(!findings[0].match_value.contains("secret123"));
    }

    /// # Contract
    ///
    /// Registry-scoped token keys are preserved while the token value is
    /// redacted.
    #[test]
    fn redact_npmrc_auth_token_preserves_registry_prefix() {
        let line = format!("//registry.npmjs.org/:{}={}", "_authToken", "secret123");

        assert_eq!(
            redact_npmrc_auth_token(&line),
            "//registry.npmjs.org/:_authToken=<redacted>"
        );
    }

    /// Contract: `npmrc_capabilities` ignores `_authtoken=` mentions
    /// inside `;` comments. Pre-fix the helper substring-scanned the
    /// raw lowercase content, so a doc-only token leaked the
    /// `SecretAccess` capability.
    #[test]
    fn npmrc_capabilities_skip_authtoken_in_semicolon_comment() {
        let content = format!("; {}={}\n", "_authToken", "PLACEHOLDER");
        let caps = npmrc_capabilities(&content);
        assert!(!capability_present(&caps, ArtifactCapability::SecretAccess));
    }
}
