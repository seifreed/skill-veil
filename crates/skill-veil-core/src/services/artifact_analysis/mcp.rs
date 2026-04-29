use super::network::looks_like_webhook_receiver_without_auth;
use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::lazy_pattern;
use crate::services::ArtifactAnalysisService;
use std::path::Path;

lazy_pattern!(RE_REMOTE_ENDPOINT, r"(?i)(https?://|wss?://)");
lazy_pattern!(
    RE_EXEC_SURFACE_TRANSPORT,
    r"(?i)(command|stdio|args|transport)"
);
lazy_pattern!(RE_EXEC_SURFACE, r"(?i)(command|stdio|args)");
lazy_pattern!(
    RE_IDENTITY_SCOPE,
    r"(?i)(oauth|scope|scopes|bearer|authorization)"
);
lazy_pattern!(
    RE_AUTH_OR_APIKEY,
    r"(?i)(oauth|scope|authorization|bearer|api[_-]?key)"
);
lazy_pattern!(
    RE_IDENTITY_ACCESS,
    r"(?i)(oauth|scope|authorization|bearer)"
);

const MCP_BROAD_TOOL_COUNT_THRESHOLD: usize = 5;

fn mcp_remote_endpoint_findings(
    artifact_analysis: &ArtifactAnalysisService,
    content: &str,
    artifact_path: &str,
    has_remote_endpoint: bool,
    has_exec_surface: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if has_remote_endpoint {
        findings.push(
            Finding::builder("MCP_REMOTE_SERVER_ENDPOINT", ThreatCategory::SupplyChain)
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Behavior)
                .artifact(
                    ArtifactKind::McpServerManifest,
                    Some(artifact_path.to_string()),
                )
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.to_string(),
                })
                .match_value("remote MCP endpoint")
                .reason("MCP manifest references a remote server endpoint")
                .build(),
        );
    }

    if has_exec_surface {
        findings.push(
            Finding::builder("MCP_TOOLING_TRANSPORT_DECLARED", ThreatCategory::ToolAbuse)
                .severity(Severity::Low)
                .action(if has_remote_endpoint {
                    RecommendedAction::RequireApproval
                } else {
                    RecommendedAction::Log
                })
                .evidence_kind(EvidenceKind::Context)
                .artifact(
                    ArtifactKind::McpServerManifest,
                    Some(artifact_path.to_string()),
                )
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.to_string(),
                })
                .match_value("mcp transport")
                .reason("MCP manifest declares transport or command execution behavior")
                .build(),
        );
    }

    if has_remote_endpoint && has_exec_surface {
        findings.push(
            Finding::builder("MCP_REMOTE_EXEC_SURFACE", ThreatCategory::RemoteExec)
                .severity(Severity::High)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Behavior)
                .artifact(ArtifactKind::McpServerManifest, Some(artifact_path.to_string()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.to_string(),
                })
                .match_value("remote endpoint with command transport")
                .reason(
                    "MCP manifest combines a remote endpoint with command or stdio execution semantics",
                )
                .build(),
        );
    }

    if has_remote_endpoint && artifact_analysis.is_opaque_mcp_endpoint(content) {
        findings.push(
            Finding::builder("MCP_OPAQUE_REMOTE_CONTROL_PLANE", ThreatCategory::ToolAbuse)
                .severity(Severity::High)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Context)
                .artifact(ArtifactKind::McpServerManifest, Some(artifact_path.to_string()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.to_string(),
                })
                .match_value("opaque remote MCP endpoint")
                .reason("MCP manifest uses a transient or opaque remote endpoint commonly associated with tunnelled control planes")
                .build(),
        );
    }

    findings
}

fn mcp_auth_findings(
    artifact_analysis: &ArtifactAnalysisService,
    content: &str,
    artifact_path: &str,
    has_remote_endpoint: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if has_remote_endpoint && artifact_analysis.mcp_declares_no_auth(content) {
        findings.push(
            Finding::builder("MCP_NO_AUTH_MODEL", ThreatCategory::ToolAbuse)
                .severity(Severity::High)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Context)
                .artifact(
                    ArtifactKind::McpServerManifest,
                    Some(artifact_path.to_string()),
                )
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.to_string(),
                })
                .match_value("auth: none")
                .reason(
                    "MCP manifest exposes a remote endpoint without a visible authentication model",
                )
                .build(),
        );
    }

    if artifact_analysis.mcp_declares_inline_secret(content) {
        findings.push(
            Finding::builder("MCP_INLINE_AUTH_SECRET", ThreatCategory::CredentialExposure)
                .severity(Severity::High)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Behavior)
                .artifact(ArtifactKind::McpServerManifest, Some(artifact_path.to_string()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.to_string(),
                })
                .match_value("inline MCP auth secret")
                .reason("MCP manifest appears to embed bearer, token, or API key material directly in configuration")
                .build(),
        );
    }

    findings
}

fn mcp_scope_and_tool_findings(
    artifact_analysis: &ArtifactAnalysisService,
    content: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if RE_IDENTITY_SCOPE.is_match(content) {
        findings.push(
            Finding::builder("MCP_BROAD_IDENTITY_SCOPE", ThreatCategory::ScopeCreep)
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Context)
                .artifact(ArtifactKind::McpServerManifest, Some(artifact_path.to_string()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.to_string(),
                })
                .match_value("oauth scope")
                .reason("MCP manifest references identity or OAuth scopes that may exceed the task intent")
                .build(),
        );
    }

    let mcp_tools = artifact_analysis.extract_mcp_tool_names(content);
    if artifact_analysis.mcp_declares_permissive_tools(content)
        || mcp_tools.len() >= MCP_BROAD_TOOL_COUNT_THRESHOLD
    {
        findings.push(
            Finding::builder("MCP_PERMISSIVE_TOOL_EXPOSURE", ThreatCategory::ToolAbuse)
                .severity(Severity::High)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Context)
                .artifact(
                    ArtifactKind::McpServerManifest,
                    Some(artifact_path.to_string()),
                )
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.to_string(),
                })
                .match_value(if mcp_tools.is_empty() {
                    "all tools".to_string()
                } else {
                    mcp_tools.join(", ")
                })
                .reason("MCP manifest exposes an unusually broad tool surface to the agent")
                .build(),
        );
    }

    findings
}

pub(crate) fn analyze_mcp_manifest(
    artifact_analysis: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let has_remote_endpoint = RE_REMOTE_ENDPOINT.is_match(content);
    let has_exec_surface = RE_EXEC_SURFACE_TRANSPORT.is_match(content);

    let mut findings = mcp_remote_endpoint_findings(
        artifact_analysis,
        content,
        &artifact_path,
        has_remote_endpoint,
        has_exec_surface,
    );
    findings.extend(mcp_auth_findings(
        artifact_analysis,
        content,
        &artifact_path,
        has_remote_endpoint,
    ));
    findings.extend(artifact_analysis.permission_and_network_findings(
        path,
        content,
        ArtifactKind::McpServerManifest,
    ));
    findings.extend(mcp_scope_and_tool_findings(
        artifact_analysis,
        content,
        &artifact_path,
    ));
    findings
}

pub(crate) fn mcp_manifest_relations(
    artifact_analysis: &ArtifactAnalysisService,
    content: &str,
) -> Vec<crate::services::artifact_analysis::ArtifactLink> {
    let mut links = artifact_analysis.generic_url_relations(content);

    if RE_EXEC_SURFACE.is_match(content) {
        links.push(crate::services::artifact_analysis::ArtifactLink {
            target: "mcp-process-transport".to_string(),
            relation: ArtifactRelation::Executes,
        });
    }
    if artifact_analysis.mcp_declares_inline_secret(content) || RE_AUTH_OR_APIKEY.is_match(content)
    {
        links.push(crate::services::artifact_analysis::ArtifactLink {
            target: "mcp-auth".to_string(),
            relation: ArtifactRelation::AccessesSecrets,
        });
    }
    for tool in artifact_analysis.extract_mcp_tool_names(content) {
        links.push(crate::services::artifact_analysis::ArtifactLink {
            target: format!("tool:{tool}"),
            relation: ArtifactRelation::Loads,
        });
    }

    links
}

pub(crate) fn mcp_manifest_capabilities(
    artifact_analysis: &ArtifactAnalysisService,
    content: &str,
) -> Vec<ArtifactCapabilityFact> {
    let mut capabilities = Vec::new();
    if RE_EXEC_SURFACE.is_match(content) {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::ProcessExecution,
        ));
    }
    if RE_REMOTE_ENDPOINT.is_match(content) {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }
    if RE_IDENTITY_ACCESS.is_match(content) {
        capabilities.push(ArtifactAnalysisService::declared_capability(
            ArtifactCapability::IdentityAccess,
        ));
    }
    if artifact_analysis.mcp_declares_inline_secret(content) {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::SecretAccess,
        ));
    }
    if looks_like_webhook_receiver_without_auth(content).is_some() {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::InboundNetworkSurface,
        ));
    }
    capabilities
}
