mod detectors;
mod patterns;

use super::patterns::RE_SHELL_SOURCE;
use super::ArtifactLink;
use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::ArtifactKind;
use crate::services::ArtifactAnalysisService;
use detectors::{
    detect_deferred_execution, detect_injection_patterns, detect_node_process_exec,
    detect_node_secret_fs_access, detect_powershell_dynamic_exec, detect_powershell_persistence,
    detect_python_exec_network, detect_python_secret_system_access, detect_remote_binary_downloads,
    detect_shell_persistence_write, detect_shell_side_effects,
};
use std::path::Path;

pub(crate) fn analyze_script(
    artifact_analysis: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> Vec<crate::findings::Finding> {
    let artifact_path = path.display().to_string();
    let language = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let lower = content.to_ascii_lowercase();
    let mut findings = Vec::new();

    findings.extend(detect_remote_binary_downloads(
        &lower,
        content,
        &artifact_path,
    ));
    findings.extend(detect_deferred_execution(&lower, content, &artifact_path));
    findings.extend(detect_node_process_exec(&lower, &language, &artifact_path));
    findings.extend(detect_python_exec_network(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_python_secret_system_access(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_powershell_dynamic_exec(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_powershell_persistence(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_shell_side_effects(&lower, &language, &artifact_path));
    findings.extend(detect_shell_persistence_write(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_node_secret_fs_access(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_injection_patterns(
        &lower,
        content,
        &language,
        &artifact_path,
    ));
    findings.extend(artifact_analysis.permission_and_network_findings(
        path,
        content,
        ArtifactKind::ReferencedArtifact,
    ));

    findings
}

pub(crate) fn script_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let lower = content.to_ascii_lowercase();
    let mut capabilities = Vec::new();

    if lower.contains("curl ")
        || lower.contains("wget ")
        || lower.contains("invoke-webrequest")
        || lower.contains("http://")
        || lower.contains("https://")
    {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }

    if lower.contains("bash ")
        || lower.contains(" sh ")
        || lower.contains("node ")
        || lower.contains("python ")
        || lower.contains("npm install")
        || lower.contains("pip install")
        || lower.contains("cargo install")
    {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::InstallExecution,
        ));
    }

    if lower.contains("subprocess.")
        || lower.contains("os.system(")
        || lower.contains("exec(")
        || lower.contains("spawn(")
        || lower.contains("start-process")
        || lower.contains("iex ")
    {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::ProcessExecution,
        ));
    }

    if lower.contains("process.env")
        || lower.contains("os.environ")
        || lower.contains("getenv(")
        || lower.contains(".env")
        || lower.contains("access_token")
        || lower.contains("api_token")
        || lower.contains("auth_token")
        || lower.contains("bearer_token")
        || lower.contains("secret_key")
        || lower.contains("client_secret")
        || lower.contains("_authtoken")
    {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::SecretAccess,
        ));
    }

    if lower.contains("crontab")
        || lower.contains("schtasks")
        || lower.contains("launchctl")
        || lower.contains("runonce")
        || lower.contains("autostart")
        || lower.contains("register-scheduledtask")
    {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::PersistenceSurface,
        ));
    }

    if lower.contains("writefilesync(")
        || lower.contains("tee ")
        || lower.contains(">>")
        || lower.contains("> /etc/")
        || lower.contains("set-content")
    {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::FilesystemWrite,
        ));
    }

    capabilities
}

pub(crate) fn script_relations(content: &str) -> Vec<ArtifactLink> {
    let lower = content.to_ascii_lowercase();
    let mut links = Vec::new();
    if lower.contains("curl ") || lower.contains("wget ") || lower.contains("invoke-webrequest") {
        links.push(ArtifactLink {
            target: "remote-resource".to_string(),
            relation: ArtifactRelation::Downloads,
        });
    }
    if lower.contains("bash ")
        || lower.contains("sh ")
        || lower.contains("python ")
        || lower.contains("node ")
        || lower.contains("start-process")
        || lower.contains("subprocess.")
        || lower.contains("child_process")
    {
        links.push(ArtifactLink {
            target: "process".to_string(),
            relation: ArtifactRelation::Executes,
        });
    }
    if lower.contains("import ")
        || lower.contains("require(")
        || lower.contains("source ")
        || RE_SHELL_SOURCE.is_match(&lower)
    {
        links.push(ArtifactLink {
            target: "runtime-module".to_string(),
            relation: ArtifactRelation::Loads,
        });
    }
    if lower.contains("crontab")
        || lower.contains("schtasks")
        || lower.contains("launchctl")
        || lower.contains("autostart")
    {
        links.push(ArtifactLink {
            target: "persistence-surface".to_string(),
            relation: ArtifactRelation::Persists,
        });
    }
    if lower.contains("http://") || lower.contains("https://") || lower.contains("socket.") {
        links.push(ArtifactLink {
            target: "network".to_string(),
            relation: ArtifactRelation::ConnectsTo,
        });
    }
    if lower.contains("open(")
        || lower.contains("readfilesync(")
        || lower.contains("cat ")
        || lower.contains("rg ")
    {
        links.push(ArtifactLink {
            target: "filesystem".to_string(),
            relation: ArtifactRelation::Reads,
        });
    }
    if lower.contains("writefilesync(")
        || lower.contains("tee ")
        || lower.contains(">>")
        || lower.contains("set-content")
    {
        links.push(ArtifactLink {
            target: "filesystem".to_string(),
            relation: ArtifactRelation::Writes,
        });
    }
    if lower.contains("process.env")
        || lower.contains("os.environ")
        || lower.contains("getenv(")
        || lower.contains(".env")
    {
        links.push(ArtifactLink {
            target: "secrets".to_string(),
            relation: ArtifactRelation::AccessesSecrets,
        });
    }
    links
}
