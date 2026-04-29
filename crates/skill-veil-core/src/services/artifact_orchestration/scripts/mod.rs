use super::ArtifactLink;
use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::detectors::patterns::{line_invokes_shell_or_interpreter, RE_SHELL_SOURCE};
use crate::detectors::scripts::{
    detect_deferred_execution, detect_file_secret_to_network_flow, detect_injection_patterns,
    detect_node_process_exec, detect_node_secret_fs_access, detect_powershell_dynamic_exec,
    detect_powershell_persistence, detect_python_exec_network, detect_python_secret_system_access,
    detect_remote_binary_downloads, detect_shell_persistence_write, detect_shell_side_effects,
    detect_typosquatted_install,
};
use crate::findings::ArtifactKind;
use crate::services::ArtifactOrchestratorService;
use std::path::Path;

pub(crate) fn analyze_script(
    artifact_orchestration: &ArtifactOrchestratorService,
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
    findings.extend(detect_file_secret_to_network_flow(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_typosquatted_install(
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
    findings.extend(artifact_orchestration.permission_and_network_findings(
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
        capabilities.push(ArtifactOrchestratorService::observed_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }

    if lower.lines().any(line_invokes_shell_or_interpreter)
        || lower.contains("npm install")
        || lower.contains("pip install")
        || lower.contains("cargo install")
    {
        capabilities.push(ArtifactOrchestratorService::observed_capability(
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
        capabilities.push(ArtifactOrchestratorService::observed_capability(
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
        capabilities.push(ArtifactOrchestratorService::observed_capability(
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
        capabilities.push(ArtifactOrchestratorService::observed_capability(
            ArtifactCapability::PersistenceSurface,
        ));
    }

    if lower.contains("writefilesync(")
        || lower.contains("tee ")
        || lower.contains(">>")
        || lower.contains("> /etc/")
        || lower.contains("set-content")
    {
        capabilities.push(ArtifactOrchestratorService::observed_capability(
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
    // Mirror `script_capabilities`: `iex ` is the PowerShell alias for
    // `Invoke-Expression` and is treated as `ProcessExecution` there
    // (mod.rs:114). Pre-fix `script_relations` omitted it, so a script
    // calling `iex $payload` declared the capability without producing
    // the matching `Executes` edge — composite capabilities downstream
    // (`ShellDownloadExec`, taint chains) silently lost the link.
    if lower.lines().any(line_invokes_shell_or_interpreter)
        || lower.contains("start-process")
        || lower.contains("subprocess.")
        || lower.contains("child_process")
        || lower.contains("iex ")
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

#[cfg(test)]
mod tests {
    use super::*;

    fn capability_present(caps: &[ArtifactCapabilityFact], target: ArtifactCapability) -> bool {
        caps.iter().any(|fact| fact.capability == target)
    }

    fn relation_target_present(links: &[ArtifactLink], target: &str) -> bool {
        links.iter().any(|link| link.target == target)
    }

    /// Contract: a script invoking `bash install.sh` produces InstallExecution.
    #[test]
    fn script_capabilities_detects_bash_token() {
        let content = "bash install.sh\n";
        let caps = script_capabilities(content);
        assert!(capability_present(
            &caps,
            ArtifactCapability::InstallExecution
        ));
    }

    /// Contract: a script that begins with bare `sh install.sh` (column 0,
    /// no leading space) produces InstallExecution. Anchors the column-0
    /// false-negative fix from the prior conservative `" sh "` pattern.
    #[test]
    fn script_capabilities_detects_sh_at_column_zero() {
        let content = "sh install.sh\n";
        let caps = script_capabilities(content);
        assert!(capability_present(
            &caps,
            ArtifactCapability::InstallExecution
        ));
    }

    /// Contract: an `npm run publish` script must NOT produce
    /// InstallExecution via the shell-token detector — `publish` is an
    /// English word, not a shell invocation.
    #[test]
    fn script_capabilities_skips_publish_word() {
        let content = "npm run publish\n";
        let caps = script_capabilities(content);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::InstallExecution
        ));
    }

    /// Contract: the multi-word phrase `npm install` still produces
    /// InstallExecution via the dedicated phrase clause, separate from
    /// the shell-token helper. Pins the separation so a future refactor
    /// doesn't accidentally fold install phrases into the helper.
    #[test]
    fn script_capabilities_keeps_npm_install_phrase() {
        let content = "npm install foo\n";
        let caps = script_capabilities(content);
        assert!(capability_present(
            &caps,
            ArtifactCapability::InstallExecution
        ));
    }

    /// Contract: a script invoking `bash` produces an Executes relation.
    #[test]
    fn script_relations_detects_bash_token() {
        let content = "bash install.sh\n";
        let links = script_relations(content);
        assert!(relation_target_present(&links, "process"));
    }

    /// Contract: an `npm run publish` script must NOT produce an Executes
    /// relation. Anchors the false-positive fix on the relations side.
    #[test]
    fn script_relations_skips_publish_word() {
        let content = "npm run publish\n";
        let links = script_relations(content);
        assert!(!relation_target_present(&links, "process"));
    }

    /// Contract: text mentioning `make finish` (English usage) must NOT
    /// produce an Executes relation.
    #[test]
    fn script_relations_skips_finish_step() {
        let content = "echo \"please finish setup\"\n";
        let links = script_relations(content);
        assert!(!relation_target_present(&links, "process"));
    }

    /// Contract: a script invoking `iex $cmd` (PowerShell alias for
    /// `Invoke-Expression`) MUST produce an `Executes` relation, paralleling
    /// the `ProcessExecution` capability flag in `script_capabilities`.
    /// Pre-fix the relations omitted `iex `, so a script declared the
    /// capability without the matching graph edge — composite capabilities
    /// (e.g. `ShellDownloadExec`) silently lost the chain.
    #[test]
    fn script_relations_records_executes_for_iex_alias() {
        let content = "iex $payload\n";
        let links = script_relations(content);
        assert!(
            relation_target_present(&links, "process"),
            "`iex $payload` must produce an Executes edge; got {links:?}",
        );
    }

    /// Contract: capability and relation paths agree on `iex `. Positive
    /// pin so a future refactor cannot silently drop one but keep the
    /// other.
    #[test]
    fn iex_flips_both_capability_and_relation() {
        let content = "iex $payload\n";
        let caps = script_capabilities(content);
        let links = script_relations(content);
        assert!(caps
            .iter()
            .any(|c| c.capability == ArtifactCapability::ProcessExecution));
        assert!(relation_target_present(&links, "process"));
    }
}
