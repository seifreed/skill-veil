use std::collections::BTreeMap;

use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilitySource, ArtifactGraph};
use crate::findings::{
    CompositeCapability, DeclaredPermission, Finding, FindingSummary, SkillCapability,
    ThreatCategory,
};

pub(super) fn derive_declared_permissions(
    findings: &[Finding],
    _primary_summary: &FindingSummary,
    _supporting_summary: &FindingSummary,
) -> Vec<DeclaredPermission> {
    let mut permissions = Vec::new();

    for finding in findings
        .iter()
        .filter(|finding| finding.artifact_scope == crate::findings::ArtifactScope::AgentEntrypoint)
    {
        let permission = match finding.rule_id.as_str() {
            "DECLARED_PERMISSION_BROWSER_FULL" => Some(DeclaredPermission::BrowserFull),
            "DECLARED_PERMISSION_FILE_WRITE" => Some(DeclaredPermission::FileWrite),
            "DECLARED_PERMISSION_SHELL_EXEC" => Some(DeclaredPermission::ShellExec),
            "DECLARED_PERMISSION_NETWORK_ACCESS" => Some(DeclaredPermission::NetworkAccess),
            "DECLARED_PERMISSION_SECRETS_ACCESS" => Some(DeclaredPermission::SecretsAccess),
            "DECLARED_PERMISSION_OAUTH_SCOPES" => Some(DeclaredPermission::OAuthScopes),
            _ => None,
        };

        if let Some(permission) = permission {
            if !permissions.contains(&permission) {
                permissions.push(permission);
            }
        }
    }

    permissions.sort();
    permissions
}

pub(super) fn derive_declared_capabilities(
    declared_permissions: &[DeclaredPermission],
    artifact_graph: &ArtifactGraph,
) -> Vec<SkillCapability> {
    let mut capabilities = BTreeMap::<SkillCapability, usize>::new();

    for permission in declared_permissions {
        let capability = match permission {
            DeclaredPermission::BrowserFull => SkillCapability::ToolsBrowser,
            DeclaredPermission::FileWrite => SkillCapability::FilesystemWrite,
            DeclaredPermission::ShellExec => SkillCapability::ShellExec,
            DeclaredPermission::NetworkAccess => SkillCapability::NetworkHttp,
            DeclaredPermission::SecretsAccess => SkillCapability::SecretsAccess,
            DeclaredPermission::OAuthScopes => SkillCapability::IdentityOauth,
        };
        *capabilities.entry(capability).or_insert(0) += 1;
    }

    for node in &artifact_graph.nodes {
        for fact in &node.capabilities {
            if fact.source != ArtifactCapabilitySource::Declared {
                continue;
            }
            if let Some(capability) = map_artifact_capability(fact.capability, &node.path) {
                *capabilities.entry(capability).or_insert(0) += 1;
            }
        }
    }

    capabilities.into_keys().collect()
}

pub(super) fn derive_observed_capabilities(artifact_graph: &ArtifactGraph) -> Vec<SkillCapability> {
    let mut capabilities = BTreeMap::<SkillCapability, usize>::new();

    for node in &artifact_graph.nodes {
        for fact in &node.capabilities {
            if fact.source != ArtifactCapabilitySource::Observed {
                continue;
            }
            if let Some(capability) = map_artifact_capability(fact.capability, &node.path) {
                *capabilities.entry(capability).or_insert(0) += 1;
            }
        }
    }

    capabilities.into_keys().collect()
}

pub(super) fn derive_effective_capabilities(
    findings: &[Finding],
    declared_capabilities: &[SkillCapability],
    observed_capabilities: &[SkillCapability],
    artifact_graph: &ArtifactGraph,
) -> Vec<SkillCapability> {
    let mut capabilities = BTreeMap::<SkillCapability, usize>::new();
    for capability in declared_capabilities
        .iter()
        .chain(observed_capabilities.iter())
    {
        *capabilities.entry(*capability).or_insert(0) += 1;
    }

    for finding in findings {
        let match_value = finding.match_value.to_ascii_lowercase();
        if finding.rule_id == "METADATA_SERVICE_ACCESS"
            || finding.rule_id == "INTERNAL_NETWORK_ACCESS"
            || finding.rule_id == "SSRF_LIKE_FETCH"
            || match_value.contains("169.254.169.254")
            || match_value.contains("localhost")
            || match_value.contains("127.0.0.1")
            || match_value.contains(".internal")
            || match_value.contains(".local")
        {
            *capabilities
                .entry(SkillCapability::NetworkInternal)
                .or_insert(0) += 1;
        }

        if finding.rule_id == "MCP_REMOTE_SERVER_ENDPOINT"
            || finding.rule_id == "MCP_REMOTE_EXEC_SURFACE"
            || finding.rule_id == "MCP_NO_AUTH_MODEL"
        {
            *capabilities
                .entry(SkillCapability::ToolsMcpRemote)
                .or_insert(0) += 1;
        }

        let key = match finding.category {
            ThreatCategory::RemoteExec => Some(SkillCapability::ShellExec),
            ThreatCategory::CredentialExposure => Some(SkillCapability::SecretsAccess),
            ThreatCategory::DataExfiltration => {
                if match_value.contains("169.254.169.254")
                    || match_value.contains("localhost")
                    || match_value.contains("127.0.0.1")
                    || match_value.contains(".internal")
                    || match_value.contains(".local")
                {
                    Some(SkillCapability::NetworkInternal)
                } else {
                    Some(SkillCapability::NetworkHttp)
                }
            }
            ThreatCategory::PersistentPromptTampering => Some(SkillCapability::PersistenceSemantic),
            ThreatCategory::SupplyChain => Some(SkillCapability::ProcessSpawn),
            ThreatCategory::ToolAbuse => tool_abuse_capability(finding),
            ThreatCategory::AutonomyEscalation => Some(SkillCapability::ProcessSpawn),
            ThreatCategory::PrivilegeEscalation => Some(SkillCapability::FilesystemWrite),
            ThreatCategory::ScopeCreep => Some(SkillCapability::IdentityOauth),
            ThreatCategory::SocialManipulation | ThreatCategory::PersuasiveLanguage => None,
            ThreatCategory::Obfuscation => None,
            ThreatCategory::UnsafeBinary => Some(SkillCapability::ShellExec),
            ThreatCategory::Generic => None,
        };
        if let Some(key) = key {
            *capabilities.entry(key).or_insert(0) += 1;
        }
    }

    for edge in &artifact_graph.edges {
        match edge.relation {
            crate::artifact_graph::ArtifactRelation::ConnectsTo => {
                let target = edge.to.to_ascii_lowercase();
                let capability = if target.contains("ws://") || target.contains("wss://") {
                    Some(SkillCapability::NetworkWebsocket)
                } else if target.contains("localhost")
                    || target.contains("127.0.0.1")
                    || target.contains("169.254.169.254")
                    || target.contains(".internal")
                    || target.contains(".local")
                {
                    Some(SkillCapability::NetworkInternal)
                } else if target.contains("http://") || target.contains("https://") {
                    Some(SkillCapability::NetworkHttp)
                } else {
                    None
                };
                if let Some(capability) = capability {
                    *capabilities.entry(capability).or_insert(0) += 1;
                }
            }
            crate::artifact_graph::ArtifactRelation::Reads => {
                *capabilities
                    .entry(SkillCapability::FilesystemRead)
                    .or_insert(0) += 1;
            }
            crate::artifact_graph::ArtifactRelation::Writes => {
                *capabilities
                    .entry(SkillCapability::FilesystemWrite)
                    .or_insert(0) += 1;
            }
            crate::artifact_graph::ArtifactRelation::Executes => {
                *capabilities
                    .entry(SkillCapability::ProcessSpawn)
                    .or_insert(0) += 1;
            }
            crate::artifact_graph::ArtifactRelation::Persists => {
                *capabilities
                    .entry(SkillCapability::PersistenceSemantic)
                    .or_insert(0) += 1;
            }
            crate::artifact_graph::ArtifactRelation::AccessesSecrets => {
                *capabilities
                    .entry(SkillCapability::SecretsAccess)
                    .or_insert(0) += 1;
            }
            _ => {}
        }
    }

    capabilities.into_keys().collect()
}

pub(super) fn derive_composite_capabilities(
    findings: &[Finding],
    effective_capabilities: &[SkillCapability],
    artifact_graph: &ArtifactGraph,
) -> Vec<CompositeCapability> {
    let has_external_network = effective_capabilities.contains(&SkillCapability::NetworkHttp)
        || effective_capabilities.contains(&SkillCapability::NetworkWebsocket);
    let has_download = artifact_graph.edges.iter().any(|edge| {
        matches!(
            edge.relation,
            crate::artifact_graph::ArtifactRelation::Downloads
        )
    });
    let has_no_auth_mcp = findings
        .iter()
        .any(|finding| finding.rule_id == "MCP_NO_AUTH_MODEL");
    let has_exec = effective_capabilities.contains(&SkillCapability::ShellExec)
        || effective_capabilities.contains(&SkillCapability::ProcessSpawn);
    let has_persistence = effective_capabilities.contains(&SkillCapability::PersistenceSemantic)
        || artifact_graph.edges.iter().any(|edge| {
            matches!(
                edge.relation,
                crate::artifact_graph::ArtifactRelation::Persists
            )
        });
    let has_install_hook = artifact_graph.edges.iter().any(|edge| {
        matches!(
            edge.relation,
            crate::artifact_graph::ArtifactRelation::Loads
        ) && edge.from.to_ascii_lowercase().contains("package")
    }) || findings.iter().any(|finding| {
        matches!(
            finding.rule_id.as_str(),
            "MANIFEST_PACKAGE_JSON_INSTALL_HOOK"
                | "MANIFEST_INSTALL_HOOK_DETECTED"
                | "OFFICIAL_INSTALL_HOOK_REMOTE_FETCH"
                | "OFFICIAL_INSTALL_HOOK_SHELL_EXEC"
        ) || finding
            .match_value
            .to_ascii_lowercase()
            .contains("postinstall")
            || finding
                .match_value
                .to_ascii_lowercase()
                .contains("preinstall")
    });
    let has_workflow_context = artifact_graph.nodes.iter().any(|node| {
        matches!(node.kind, crate::findings::ArtifactKind::PackageManifest)
            && node.path.contains(".github/workflows")
    }) || findings.iter().any(|finding| {
        finding
            .artifact_path
            .as_deref()
            .is_some_and(|path| path.contains(".github/workflows"))
    });

    let mut composite = Vec::new();

    if effective_capabilities.contains(&SkillCapability::SecretsAccess) && has_external_network {
        composite.push(CompositeCapability::SecretExfiltration);
    }
    if (effective_capabilities.contains(&SkillCapability::ShellExec)
        || effective_capabilities.contains(&SkillCapability::ProcessSpawn))
        && has_download
    {
        composite.push(CompositeCapability::ShellDownloadExec);
    }
    if effective_capabilities.contains(&SkillCapability::ToolsBrowser)
        && effective_capabilities.contains(&SkillCapability::FilesystemWrite)
    {
        composite.push(CompositeCapability::BrowserWriteChain);
    }
    if effective_capabilities.contains(&SkillCapability::ToolsBrowser)
        && has_external_network
        && (effective_capabilities.contains(&SkillCapability::SecretsAccess)
            || effective_capabilities.contains(&SkillCapability::IdentityOauth))
    {
        composite.push(CompositeCapability::BrowserSessionExfiltration);
    }
    if effective_capabilities.contains(&SkillCapability::ToolsMcpRemote) && has_no_auth_mcp {
        composite.push(CompositeCapability::RemoteMcpNoAuth);
    }
    if effective_capabilities.contains(&SkillCapability::IdentityOauth) && has_external_network {
        composite.push(CompositeCapability::IdentityNetworkChain);
    }
    if has_workflow_context && has_download && has_exec {
        composite.push(CompositeCapability::WorkflowRemoteExec);
    }
    if has_workflow_context && has_download && has_exec && has_persistence {
        composite.push(CompositeCapability::WorkflowExecPersistence);
    }
    if has_install_hook && effective_capabilities.contains(&SkillCapability::PersistenceSemantic) {
        composite.push(CompositeCapability::InstallHookPersistence);
    }
    if effective_capabilities.contains(&SkillCapability::ToolsMcpRemote) && has_exec {
        composite.push(CompositeCapability::RemoteMcpExec);
    }
    if effective_capabilities.contains(&SkillCapability::ToolsMcpRemote)
        && has_no_auth_mcp
        && has_exec
    {
        composite.push(CompositeCapability::RemoteMcpNoAuthExec);
    }
    if effective_capabilities.contains(&SkillCapability::FilesystemWrite)
        && effective_capabilities.contains(&SkillCapability::PersistenceSemantic)
    {
        composite.push(CompositeCapability::WritePersistenceChain);
    }

    composite.sort();
    composite.dedup();
    composite
}

fn map_artifact_capability(
    capability: ArtifactCapability,
    artifact_path: &str,
) -> Option<SkillCapability> {
    match capability {
        ArtifactCapability::BrowserAccess => Some(SkillCapability::ToolsBrowser),
        ArtifactCapability::NetworkAccess => {
            let path = artifact_path.to_ascii_lowercase();
            if path.contains("websocket") || path.contains("ws://") || path.contains("wss://") {
                Some(SkillCapability::NetworkWebsocket)
            } else {
                Some(SkillCapability::NetworkHttp)
            }
        }
        ArtifactCapability::InstallExecution => Some(SkillCapability::ShellExec),
        ArtifactCapability::ExposesBinary => Some(SkillCapability::ProcessSpawn),
        ArtifactCapability::PrivilegedRuntime => Some(SkillCapability::ProcessSpawn),
        ArtifactCapability::HostFilesystemAccess => Some(SkillCapability::FilesystemRead),
        ArtifactCapability::ProcessExecution => Some(SkillCapability::ProcessSpawn),
        ArtifactCapability::SecretAccess => Some(SkillCapability::SecretsAccess),
        ArtifactCapability::PersistenceSurface => Some(SkillCapability::PersistenceSemantic),
        ArtifactCapability::FilesystemWrite => Some(SkillCapability::FilesystemWrite),
        ArtifactCapability::IdentityAccess => Some(SkillCapability::IdentityOauth),
        ArtifactCapability::InboundNetworkSurface => Some(SkillCapability::InboundWebhook),
    }
}

fn tool_abuse_capability(finding: &Finding) -> Option<SkillCapability> {
    let text = format!(
        "{} {} {}",
        finding.rule_id.to_ascii_lowercase(),
        finding.reason.to_ascii_lowercase(),
        finding.match_value.to_ascii_lowercase()
    );
    if text.contains("browser") || text.contains("navigation") || text.contains("click") {
        Some(SkillCapability::ToolsBrowser)
    } else {
        None
    }
}
