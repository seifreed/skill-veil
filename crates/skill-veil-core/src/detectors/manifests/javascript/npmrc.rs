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

fn npmrc_registry_directive(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    let value = value.trim();
    let key_lower = key.to_ascii_lowercase();
    let is_registry_key = key_lower == "registry" || key_lower.ends_with(":registry");
    if is_registry_key && starts_with_http_scheme(value) && !is_default_npm_registry(value) {
        Some((key, value))
    } else {
        None
    }
}

fn starts_with_http_scheme(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn is_default_npm_registry(value: &str) -> bool {
    let Ok(parsed) = url::Url::parse(value) else {
        return false;
    };
    parsed.scheme() == "https"
        && parsed
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case("registry.npmjs.org"))
        && parsed.path() == "/"
        && parsed.query().is_none()
        && parsed.fragment().is_none()
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

    if npmrc_code_lines(content).any(|line| npmrc_registry_directive(line).is_some()) {
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
        if !has_registry && npmrc_registry_directive(line).is_some() {
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
        if !has_registry && npmrc_registry_directive(line).is_some() {
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

    fn relation_target_present(links: &[ArtifactLink], target: &str) -> bool {
        links.iter().any(|link| link.target == target)
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
    /// Scoped npm registry directives with normal INI spacing are real
    /// custom registries and must raise the same finding, capability,
    /// and relation as the unscoped `registry=` form.
    #[test]
    fn npmrc_detects_scoped_registry_with_spacing() {
        let content = "@internal:registry = HTTPS://npm.pkg.github.com\n";
        let path = std::path::Path::new("/pkg/.npmrc");
        let findings = analyze_npmrc(path, content);
        let caps = npmrc_capabilities(content);
        let links = npmrc_relations(content);

        assert!(
            finding_present(&findings, "MANIFEST_NPMRC_CUSTOM_REGISTRY"),
            "scoped registry directive must emit finding; got {findings:?}",
        );
        assert!(capability_present(&caps, ArtifactCapability::NetworkAccess));
        assert!(relation_target_present(&links, "package-registry"));
    }

    /// # Contract
    ///
    /// The exact npm default registry is not a custom registry override
    /// and must not raise supply-chain findings, network capabilities, or
    /// package-registry relations.
    #[test]
    fn npmrc_registry_parsing_ignores_default_registry() {
        let content = "\
registry=https://registry.npmjs.org/
@public:registry = HTTPS://registry.npmjs.org
";
        let path = std::path::Path::new("/pkg/.npmrc");
        let findings = analyze_npmrc(path, content);
        let caps = npmrc_capabilities(content);
        let links = npmrc_relations(content);

        assert!(
            !finding_present(&findings, "MANIFEST_NPMRC_CUSTOM_REGISTRY"),
            "default npm registry must not emit custom-registry finding; got {findings:?}",
        );
        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
        assert!(!relation_target_present(&links, "package-registry"));
    }

    /// # Contract
    ///
    /// Default-registry suppression is authority-exact. Suffix attacks and
    /// non-root paths remain custom registry overrides.
    #[test]
    fn npmrc_registry_parsing_rejects_default_registry_lookalikes() {
        for content in [
            "registry=https://registry.npmjs.org.evil.example/\n",
            "registry=https://attacker.example/registry.npmjs.org/\n",
            "registry=https://registry.npmjs.org/mirror/\n",
        ] {
            let path = std::path::Path::new("/pkg/.npmrc");
            let findings = analyze_npmrc(path, content);
            assert!(
                finding_present(&findings, "MANIFEST_NPMRC_CUSTOM_REGISTRY"),
                "non-default registry must emit finding for {content:?}; got {findings:?}",
            );
        }
    }

    /// # Contract (negative)
    ///
    /// Registry parsing is key-aware. Lookalike keys and non-HTTP
    /// scheme lookalikes must not raise custom-registry signals.
    #[test]
    fn npmrc_registry_parsing_rejects_lookalike_keys_and_schemes() {
        let content = "\
notregistry=https://attacker.example
registry-path=https://attacker.example
@internal:registry=HTXP://attacker.example
";
        let path = std::path::Path::new("/pkg/.npmrc");
        let findings = analyze_npmrc(path, content);
        let caps = npmrc_capabilities(content);
        let links = npmrc_relations(content);

        assert!(
            !finding_present(&findings, "MANIFEST_NPMRC_CUSTOM_REGISTRY"),
            "lookalike registry lines must not emit finding; got {findings:?}",
        );
        assert!(!capability_present(
            &caps,
            ArtifactCapability::NetworkAccess
        ));
        assert!(!relation_target_present(&links, "package-registry"));
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
