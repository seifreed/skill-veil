use super::{lockfiles, manifests, mcp, scripts, ArtifactAnalysisService, ArtifactLink};
use crate::analyzer::SkillDocument;
use crate::artifact_graph::ArtifactCapabilityFact;
use crate::findings::Finding;
use std::path::{Path, PathBuf};

pub(crate) const MCP_NAMES: &[&str] = &["mcp.json", "mcp.yaml", "mcp.yml"];
pub(crate) const DOCKER_COMPOSE_NAMES: &[&str] = &["docker-compose.yml", "docker-compose.yaml"];
pub(crate) const TOML_ARTIFACT_NAMES: &[&str] = &["cargo.toml", "pyproject.toml"];
pub(crate) const INSTRUCTION_NAMES: &[&str] = &[
    "agents.md",
    "claude.md",
    "system.md",
    "persona.md",
    "soul.md",
];
const LOCKFILE_NAMES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "cargo.lock",
    "poetry.lock",
    "pipfile.lock",
    "uv.lock",
    "yarn.lock",
    "pnpm-lock.yaml",
];

pub(super) fn analyze(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
    document: Option<&SkillDocument>,
) -> Vec<Finding> {
    use super::instructions;

    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return Vec::new();
    };

    let name = file_name.to_ascii_lowercase();
    let name = name.as_str();
    match name {
        "package.json" => manifests::analyze_package_json(service, path, content, sibling_files),
        _ if MCP_NAMES.contains(&name) => mcp::analyze_mcp_manifest(service, path, content),
        "skill.md" => instructions::analyze_skill_document(service, path, content, document),
        "requirements.txt" => manifests::analyze_requirements_txt(path, content),
        "pyproject.toml" => {
            manifests::analyze_pyproject_toml(service, path, content, sibling_files)
        }
        "cargo.toml" => manifests::analyze_cargo_toml(service, path, content, sibling_files),
        "package-lock.json" | "npm-shrinkwrap.json" => {
            lockfiles::analyze_package_lock(path, content)
        }
        "cargo.lock" => lockfiles::analyze_cargo_lock(path, content),
        "poetry.lock" | "pipfile.lock" => lockfiles::analyze_poetry_lock(path, content),
        "uv.lock" => lockfiles::analyze_uv_lock(path, content),
        "yarn.lock" => lockfiles::analyze_yarn_lock(path, content),
        "pnpm-lock.yaml" => lockfiles::analyze_pnpm_lock(path, content),
        "dockerfile" => manifests::analyze_dockerfile(path, content),
        _ if DOCKER_COMPOSE_NAMES.contains(&name) => {
            manifests::analyze_docker_compose(path, content)
        }
        "makefile" => manifests::analyze_makefile(path, content),
        ".npmrc" => manifests::analyze_npmrc(path, content),
        "pip.conf" => manifests::analyze_pip_conf(path, content),
        _ if INSTRUCTION_NAMES.contains(&name) => {
            instructions::analyze_instruction_file(service, path, content, document)
        }
        _ if file_name.to_ascii_lowercase().ends_with(".skill.md") => {
            instructions::analyze_skill_document(service, path, content, document)
        }
        _ if is_prompt_pack_document(path) => {
            instructions::analyze_prompt_pack(service, path, content, document)
        }
        _ if looks_like_script(path) => scripts::analyze_script(service, path, content),
        _ => Vec::new(),
    }
}

pub(super) fn infer_relations(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> Vec<ArtifactLink> {
    use super::instructions;

    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return Vec::new();
    };

    let name = file_name.to_ascii_lowercase();
    let name = name.as_str();
    match name {
        _ if MCP_NAMES.contains(&name) => mcp::mcp_manifest_relations(service, content),
        _ if DOCKER_COMPOSE_NAMES.contains(&name) => manifests::docker_compose_relations(content),
        "dockerfile" => manifests::dockerfile_relations(content),
        "package.json" => manifests::package_json_relations(content),
        _ if LOCKFILE_NAMES.contains(&name) => lockfiles::lockfile_relations(content),
        "makefile" => manifests::makefile_relations(content),
        ".npmrc" => manifests::npmrc_relations(content),
        "pip.conf" => manifests::pip_conf_relations(content),
        _ if INSTRUCTION_NAMES.contains(&name) => {
            instructions::instruction_relations(service, content)
        }
        _ if is_prompt_pack_document(path) => instructions::instruction_relations(service, content),
        _ if looks_like_script(path) => scripts::script_relations(content),
        _ => Vec::new(),
    }
}

pub(super) fn infer_capabilities(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> Vec<ArtifactCapabilityFact> {
    use super::instructions;

    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return Vec::new();
    };

    let name = file_name.to_ascii_lowercase();
    let name = name.as_str();
    match name {
        "package.json" => manifests::package_json_capabilities(content),
        _ if MCP_NAMES.contains(&name) => mcp::mcp_manifest_capabilities(service, content),
        "dockerfile" => manifests::dockerfile_capabilities(content),
        _ if DOCKER_COMPOSE_NAMES.contains(&name) => {
            manifests::docker_compose_capabilities(content)
        }
        "requirements.txt" => manifests::requirements_txt_capabilities(content),
        "pyproject.toml" => manifests::pyproject_toml_capabilities(content),
        "cargo.toml" => manifests::cargo_toml_capabilities(content),
        "makefile" => manifests::makefile_capabilities(content),
        ".npmrc" => manifests::npmrc_capabilities(content),
        "pip.conf" => manifests::pip_conf_capabilities(content),
        _ if INSTRUCTION_NAMES.contains(&name) => {
            instructions::instruction_capabilities(service, content)
        }
        _ if is_prompt_pack_document(path) => {
            instructions::instruction_capabilities(service, content)
        }
        _ if LOCKFILE_NAMES.contains(&name) => lockfiles::lockfile_capabilities(content),
        _ if looks_like_script(path) => scripts::script_capabilities(content),
        _ => Vec::new(),
    }
}

pub(super) fn expected_lockfiles(
    _service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> Vec<&'static str> {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return Vec::new();
    };

    match file_name.to_ascii_lowercase().as_str() {
        "package.json" => manifests::package_json_expected_lockfiles(content),
        "pyproject.toml" => manifests::pyproject_expected_lockfiles(content),
        "cargo.toml" => vec!["Cargo.lock"],
        _ => Vec::new(),
    }
}

pub(crate) fn is_prompt_pack_document(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name.to_ascii_lowercase().ends_with(".prompt.md"))
        || (path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("md"))
            && path
                .parent()
                .and_then(|parent| parent.file_name())
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.eq_ignore_ascii_case("prompts")))
}

pub(super) fn looks_like_script(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("sh" | "bash" | "zsh" | "ps1" | "py" | "js" | "ts" | "mjs" | "cjs" | "mts" | "cts")
    )
}
