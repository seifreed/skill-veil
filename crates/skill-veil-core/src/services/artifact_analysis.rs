//! Artifact analysis service for manifests and referenced files.

mod dispatch;
mod instructions;
mod lockfiles;
mod manifests;
mod mcp;
mod network;
mod permissions;
mod scripts;

use crate::artifact_graph::{
    ArtifactCapability, ArtifactCapabilityFact, ArtifactCapabilitySource, ArtifactRelation,
};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use regex::Regex;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

static RE_OPAQUE_MCP_ENDPOINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        "(?i)(ngrok|trycloudflare|workers\\.dev|raw\\.githubusercontent\\.com|pastebin\\.com)",
    )
    .expect("valid regex: opaque MCP endpoint")
});
static RE_MCP_NO_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?is)(\"auth\"\\s*:\\s*\"none\"|authentication\\s*:\\s*none|no auth|without auth|auth\\s*:\\s*none)")
        .expect("valid regex: MCP no auth")
});
static RE_MCP_INLINE_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?is)(bearer\\s+[A-Za-z0-9._-]{8,}|authorization\\s*:\\s*bearer|api[_-]?key|_authtoken=|token\\s*[:=]\\s*[A-Za-z0-9._-]{8,})")
        .expect("valid regex: MCP inline secret")
});
static RE_MCP_PERMISSIVE_TOOLS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?is)(\"tools\"\\s*:\\s*\\[[^\\]]*\"\\*\"|allow_all_tools|all_tools|tool_permissions\\s*:\\s*\"all\"|expose all tools)")
        .expect("valid regex: MCP permissive tools")
});
static RE_QUOTED_TOOL_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""([A-Za-z0-9._:-]{2,})""#).expect("valid regex: quoted tool name")
});
static RE_MCP_TOOLS_ARRAY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)"tools"\s*:\s*\[([^\]]+)\]"#).expect("valid regex: MCP tools array")
});
static RE_GENERIC_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s"']+"#).expect("valid regex: generic URL"));
static RE_SHELL_SOURCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*\.\s+\S").expect("valid regex: shell source command"));

fn extract_http_urls(content: &str) -> Vec<String> {
    network::extract_http_urls(content)
}

fn is_common_lockfile_source(url: &str) -> bool {
    network::is_common_lockfile_source(url)
}

fn contains_internal_network_target(content: &str) -> Option<&'static str> {
    network::contains_internal_network_target(content)
}

fn contains_internal_network_action(content: &str) -> bool {
    network::contains_internal_network_action(content)
}

fn looks_like_local_dev_reference(content: &str) -> bool {
    network::looks_like_local_dev_reference(content)
}

fn looks_like_local_control_plane_reference(content: &str) -> bool {
    network::looks_like_local_control_plane_reference(content)
}

fn looks_like_webhook_receiver_without_auth(content: &str) -> Option<&'static str> {
    network::looks_like_webhook_receiver_without_auth(content)
}

fn contains_ssrf_like_fetch_line(content: &str) -> bool {
    network::contains_ssrf_like_fetch_line(content)
}

fn explicit_declared_permission_rules(
    content: &str,
) -> Vec<(&'static str, &'static str, &'static str)> {
    permissions::explicit_declared_permission_rules(content)
}

fn infer_declared_intent(content: &str) -> (&'static str, usize) {
    permissions::infer_declared_intent(content)
}

fn is_opaque_mcp_endpoint(content: &str) -> bool {
    RE_OPAQUE_MCP_ENDPOINT.is_match(content)
}

fn mcp_declares_no_auth(content: &str) -> bool {
    RE_MCP_NO_AUTH.is_match(content)
}

fn mcp_declares_inline_secret(content: &str) -> bool {
    RE_MCP_INLINE_SECRET.is_match(content)
}

fn mcp_declares_permissive_tools(content: &str) -> bool {
    RE_MCP_PERMISSIVE_TOOLS.is_match(content)
}

fn extract_mcp_tool_names(content: &str) -> Vec<String> {
    let mut tools = Vec::new();
    if let Some(array_match) = RE_MCP_TOOLS_ARRAY
        .captures(content)
        .and_then(|captures| captures.get(1))
    {
        for capture in RE_QUOTED_TOOL_NAME.captures_iter(array_match.as_str()) {
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
        is_opaque_mcp_endpoint(content)
    }

    pub(crate) fn mcp_declares_no_auth(&self, content: &str) -> bool {
        mcp_declares_no_auth(content)
    }

    pub(crate) fn mcp_declares_inline_secret(&self, content: &str) -> bool {
        mcp_declares_inline_secret(content)
    }

    pub(crate) fn mcp_declares_permissive_tools(&self, content: &str) -> bool {
        mcp_declares_permissive_tools(content)
    }

    pub(crate) fn extract_mcp_tool_names(&self, content: &str) -> Vec<String> {
        extract_mcp_tool_names(content)
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

    fn analyze_package_json(
        &self,
        path: &Path,
        content: &str,
        sibling_files: &[PathBuf],
    ) -> Vec<Finding> {
        manifests::analyze_package_json(self, path, content, sibling_files)
    }

    fn analyze_requirements_txt(
        &self,
        path: &Path,
        content: &str,
        _sibling_files: &[PathBuf],
    ) -> Vec<Finding> {
        manifests::analyze_requirements_txt(path, content)
    }

    fn analyze_dockerfile(&self, path: &Path, content: &str) -> Vec<Finding> {
        manifests::analyze_dockerfile(path, content)
    }

    fn analyze_pyproject_toml(
        &self,
        path: &Path,
        content: &str,
        sibling_files: &[PathBuf],
    ) -> Vec<Finding> {
        manifests::analyze_pyproject_toml(self, path, content, sibling_files)
    }

    fn analyze_cargo_toml(
        &self,
        path: &Path,
        content: &str,
        sibling_files: &[PathBuf],
    ) -> Vec<Finding> {
        manifests::analyze_cargo_toml(self, path, content, sibling_files)
    }

    fn analyze_docker_compose(&self, path: &Path, content: &str) -> Vec<Finding> {
        manifests::analyze_docker_compose(path, content)
    }

    fn analyze_makefile(&self, path: &Path, content: &str) -> Vec<Finding> {
        manifests::analyze_makefile(path, content)
    }

    fn analyze_npmrc(&self, path: &Path, content: &str) -> Vec<Finding> {
        manifests::analyze_npmrc(path, content)
    }

    fn analyze_pip_conf(&self, path: &Path, content: &str) -> Vec<Finding> {
        manifests::analyze_pip_conf(path, content)
    }

    fn analyze_script(&self, path: &Path, content: &str) -> Vec<Finding> {
        scripts::analyze_script(self, path, content)
    }

    fn analyze_package_lock(&self, path: &Path, content: &str) -> Vec<Finding> {
        lockfiles::analyze_package_lock(path, content)
    }

    fn analyze_cargo_lock(&self, path: &Path, content: &str) -> Vec<Finding> {
        lockfiles::analyze_cargo_lock(path, content)
    }

    fn analyze_poetry_lock(&self, path: &Path, content: &str) -> Vec<Finding> {
        lockfiles::analyze_poetry_lock(path, content)
    }

    fn analyze_uv_lock(&self, path: &Path, content: &str) -> Vec<Finding> {
        lockfiles::analyze_uv_lock(path, content)
    }

    fn analyze_yarn_lock(&self, path: &Path, content: &str) -> Vec<Finding> {
        lockfiles::analyze_yarn_lock(path, content)
    }

    fn analyze_pnpm_lock(&self, path: &Path, content: &str) -> Vec<Finding> {
        lockfiles::analyze_pnpm_lock(path, content)
    }

    fn package_json_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        manifests::package_json_capabilities(content)
    }

    fn requirements_txt_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        manifests::requirements_txt_capabilities(content)
    }

    fn pyproject_toml_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        manifests::pyproject_toml_capabilities(content)
    }

    fn cargo_toml_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        manifests::cargo_toml_capabilities(content)
    }

    fn package_json_expected_lockfiles(&self, content: &str) -> Vec<&'static str> {
        manifests::package_json_expected_lockfiles(content)
    }

    fn pyproject_expected_lockfiles(&self, content: &str) -> Vec<&'static str> {
        manifests::pyproject_expected_lockfiles(content)
    }

    fn dockerfile_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        manifests::dockerfile_capabilities(content)
    }

    fn docker_compose_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        manifests::docker_compose_capabilities(content)
    }

    fn script_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        let lower = content.to_ascii_lowercase();
        let mut capabilities = Vec::new();

        if lower.contains("curl ")
            || lower.contains("wget ")
            || lower.contains("invoke-webrequest")
            || lower.contains("http://")
            || lower.contains("https://")
        {
            capabilities.push(Self::observed_capability(ArtifactCapability::NetworkAccess));
        }

        if lower.contains("bash ")
            || lower.contains(" sh ")
            || lower.contains("node ")
            || lower.contains("python ")
            || lower.contains("npm install")
            || lower.contains("pip install")
            || lower.contains("cargo install")
        {
            capabilities.push(Self::observed_capability(
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
            capabilities.push(Self::observed_capability(
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
            capabilities.push(Self::observed_capability(ArtifactCapability::SecretAccess));
        }

        if lower.contains("crontab")
            || lower.contains("schtasks")
            || lower.contains("launchctl")
            || lower.contains("runonce")
            || lower.contains("autostart")
            || lower.contains("register-scheduledtask")
        {
            capabilities.push(Self::observed_capability(
                ArtifactCapability::PersistenceSurface,
            ));
        }

        if lower.contains("writefilesync(")
            || lower.contains("tee ")
            || lower.contains(">>")
            || lower.contains("> /etc/")
            || lower.contains("set-content")
        {
            capabilities.push(Self::observed_capability(
                ArtifactCapability::FilesystemWrite,
            ));
        }

        capabilities
    }

    fn makefile_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        manifests::makefile_capabilities(content)
    }

    fn npmrc_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        manifests::npmrc_capabilities(content)
    }

    fn pip_conf_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        manifests::pip_conf_capabilities(content)
    }

    fn lockfile_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        lockfiles::lockfile_capabilities(content)
    }

    fn dockerfile_relations(&self, content: &str) -> Vec<ArtifactLink> {
        manifests::dockerfile_relations(content)
    }

    fn docker_compose_relations(&self, content: &str) -> Vec<ArtifactLink> {
        manifests::docker_compose_relations(content)
    }

    fn package_json_relations(&self, content: &str) -> Vec<ArtifactLink> {
        manifests::package_json_relations(content)
    }

    fn makefile_relations(&self, content: &str) -> Vec<ArtifactLink> {
        manifests::makefile_relations(content)
    }

    fn npmrc_relations(&self, content: &str) -> Vec<ArtifactLink> {
        manifests::npmrc_relations(content)
    }

    fn pip_conf_relations(&self, content: &str) -> Vec<ArtifactLink> {
        manifests::pip_conf_relations(content)
    }

    fn lockfile_relations(&self, content: &str) -> Vec<ArtifactLink> {
        lockfiles::lockfile_relations(content)
    }

    fn script_relations(&self, content: &str) -> Vec<ArtifactLink> {
        let lower = content.to_ascii_lowercase();
        let mut links = Vec::new();
        if lower.contains("curl ") || lower.contains("wget ") || lower.contains("invoke-webrequest")
        {
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

    fn analyze_mcp_manifest(&self, path: &Path, content: &str) -> Vec<Finding> {
        mcp::analyze_mcp_manifest(self, path, content)
    }

    fn mcp_manifest_relations(&self, content: &str) -> Vec<ArtifactLink> {
        mcp::mcp_manifest_relations(self, content)
    }

    pub(crate) fn generic_url_relations(&self, content: &str) -> Vec<ArtifactLink> {
        let mut links = Vec::new();
        for matched in RE_GENERIC_URL.find_iter(content) {
            links.push(ArtifactLink {
                target: matched.as_str().to_string(),
                relation: ArtifactRelation::ConnectsTo,
            });
        }
        links
    }

    fn mcp_manifest_capabilities(&self, content: &str) -> Vec<ArtifactCapabilityFact> {
        mcp::mcp_manifest_capabilities(self, content)
    }
}

impl Default for ArtifactAnalysisService {
    fn default() -> Self {
        Self::new()
    }
}
