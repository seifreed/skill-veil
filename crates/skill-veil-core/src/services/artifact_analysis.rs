//! Artifact analysis service for manifests and referenced files.

mod dispatch;
mod instructions;
mod lockfiles;
mod manifests;
mod mcp;
mod network;
mod patterns;
mod permissions;
mod scripts;

use crate::artifact_graph::{
    ArtifactCapability, ArtifactCapabilityFact, ArtifactCapabilitySource, ArtifactRelation,
};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use std::path::{Path, PathBuf};

pub struct ArtifactAnalysisService;

#[derive(Debug, Clone)]
pub struct ArtifactLink {
    pub target: String,
    pub relation: ArtifactRelation,
}

impl ArtifactAnalysisService {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, path: &Path, content: &str, sibling_files: &[PathBuf]) -> Vec<Finding> {
        dispatch::analyze(self, path, content, sibling_files)
    }

    pub(crate) fn is_opaque_mcp_endpoint(&self, content: &str) -> bool {
        patterns::RE_OPAQUE_MCP_ENDPOINT.is_match(content)
    }

    pub(crate) fn mcp_declares_no_auth(&self, content: &str) -> bool {
        patterns::RE_MCP_NO_AUTH.is_match(content)
    }

    pub(crate) fn mcp_declares_inline_secret(&self, content: &str) -> bool {
        patterns::RE_MCP_INLINE_SECRET.is_match(content)
    }

    pub(crate) fn mcp_declares_permissive_tools(&self, content: &str) -> bool {
        patterns::RE_MCP_PERMISSIVE_TOOLS.is_match(content)
    }

    pub(crate) fn extract_mcp_tool_names(&self, content: &str) -> Vec<String> {
        let mut tools = Vec::new();
        if let Some(array_match) = patterns::RE_MCP_TOOLS_ARRAY
            .captures(content)
            .and_then(|captures| captures.get(1))
        {
            for capture in patterns::RE_QUOTED_TOOL_NAME.captures_iter(array_match.as_str()) {
                if let Some(name) = capture.get(1) {
                    let value = name.as_str().to_string();
                    if !tools.contains(&value) {
                        tools.push(value);
                    }
                }
            }
        }
        tools
    }

    pub fn infer_relations(&self, path: &Path, content: &str) -> Vec<ArtifactLink> {
        dispatch::infer_relations(self, path, content)
    }

    pub fn infer_capabilities(&self, path: &Path, content: &str) -> Vec<ArtifactCapabilityFact> {
        dispatch::infer_capabilities(self, path, content)
    }

    pub fn expected_lockfiles(&self, path: &Path, content: &str) -> Vec<&'static str> {
        dispatch::expected_lockfiles(self, path, content)
    }

    pub(crate) fn permission_and_network_findings(
        &self,
        path: &Path,
        content: &str,
        artifact_kind: ArtifactKind,
    ) -> Vec<Finding> {
        instructions::permission_and_network_findings(self, path, content, artifact_kind)
    }

    pub(crate) fn declared_capability(capability: ArtifactCapability) -> ArtifactCapabilityFact {
        ArtifactCapabilityFact {
            capability,
            source: ArtifactCapabilitySource::Declared,
        }
    }

    pub(crate) fn observed_capability(capability: ArtifactCapability) -> ArtifactCapabilityFact {
        ArtifactCapabilityFact {
            capability,
            source: ArtifactCapabilitySource::Observed,
        }
    }

    fn missing_lockfile_findings(
        &self,
        path: &Path,
        sibling_files: &[PathBuf],
        expected_lockfiles: &[&str],
        rule_id: &str,
        reason: &str,
    ) -> Vec<Finding> {
        let artifact_path = path.display().to_string();
        let has_lockfile = sibling_files.iter().any(|candidate| {
            candidate
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| {
                    expected_lockfiles
                        .iter()
                        .any(|expected| name.eq_ignore_ascii_case(expected))
                })
                .unwrap_or(false)
        });

        if has_lockfile {
            return Vec::new();
        }

        vec![Finding::builder(rule_id, ThreatCategory::SupplyChain)
            .severity(Severity::Low)
            .action(RecommendedAction::Log)
            .evidence_kind(EvidenceKind::Context)
            .artifact(ArtifactKind::PackageManifest, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value(expected_lockfiles.join(", "))
            .reason(reason)
            .build()]
    }

    pub(crate) fn generic_url_relations(&self, content: &str) -> Vec<ArtifactLink> {
        let mut links = Vec::new();
        for matched in patterns::RE_GENERIC_URL.find_iter(content) {
            links.push(ArtifactLink {
                target: matched.as_str().to_string(),
                relation: ArtifactRelation::ConnectsTo,
            });
        }
        links
    }
}

impl Default for ArtifactAnalysisService {
    fn default() -> Self {
        Self::new()
    }
}
