use super::*;

pub(super) fn analyze(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
    sibling_files: &[PathBuf],
) -> Vec<Finding> {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return Vec::new();
    };

    match file_name.to_ascii_lowercase().as_str() {
        "package.json" => service.analyze_package_json(path, content, sibling_files),
        "mcp.json" | "mcp.yaml" | "mcp.yml" => service.analyze_mcp_manifest(path, content),
        "skill.md" => instructions::analyze_skill_document(service, path, content),
        "requirements.txt" => service.analyze_requirements_txt(path, content, sibling_files),
        "pyproject.toml" => service.analyze_pyproject_toml(path, content, sibling_files),
        "cargo.toml" => service.analyze_cargo_toml(path, content, sibling_files),
        "package-lock.json" | "npm-shrinkwrap.json" => service.analyze_package_lock(path, content),
        "cargo.lock" => service.analyze_cargo_lock(path, content),
        "poetry.lock" | "pipfile.lock" => service.analyze_poetry_lock(path, content),
        "uv.lock" => service.analyze_uv_lock(path, content),
        "yarn.lock" => service.analyze_yarn_lock(path, content),
        "pnpm-lock.yaml" => service.analyze_pnpm_lock(path, content),
        "dockerfile" => service.analyze_dockerfile(path, content),
        "docker-compose.yml" | "docker-compose.yaml" => {
            service.analyze_docker_compose(path, content)
        }
        "makefile" => service.analyze_makefile(path, content),
        ".npmrc" => service.analyze_npmrc(path, content),
        "pip.conf" => service.analyze_pip_conf(path, content),
        "agents.md" | "claude.md" | "system.md" | "persona.md" | "soul.md" => {
            instructions::analyze_instruction_file(service, path, content)
        }
        _ if file_name.to_ascii_lowercase().ends_with(".skill.md") => {
            instructions::analyze_skill_document(service, path, content)
        }
        _ if is_prompt_pack_document(path) => {
            instructions::analyze_prompt_pack(service, path, content)
        }
        _ if looks_like_script(path) => service.analyze_script(path, content),
        _ => Vec::new(),
    }
}

pub(super) fn infer_relations(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> Vec<ArtifactLink> {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return Vec::new();
    };

    match file_name.to_ascii_lowercase().as_str() {
        "mcp.json" | "mcp.yaml" | "mcp.yml" => service.mcp_manifest_relations(content),
        "docker-compose.yml" | "docker-compose.yaml" => service.docker_compose_relations(content),
        "dockerfile" => service.dockerfile_relations(content),
        "package.json" => service.package_json_relations(content),
        "package-lock.json"
        | "npm-shrinkwrap.json"
        | "cargo.lock"
        | "poetry.lock"
        | "pipfile.lock"
        | "uv.lock"
        | "yarn.lock"
        | "pnpm-lock.yaml" => service.lockfile_relations(content),
        "makefile" => service.makefile_relations(content),
        ".npmrc" => service.npmrc_relations(content),
        "pip.conf" => service.pip_conf_relations(content),
        "agents.md" | "claude.md" | "system.md" | "persona.md" | "soul.md" => {
            instructions::instruction_relations(service, content)
        }
        _ if is_prompt_pack_document(path) => instructions::instruction_relations(service, content),
        _ if looks_like_script(path) => service.script_relations(content),
        _ => Vec::new(),
    }
}

pub(super) fn infer_capabilities(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> Vec<ArtifactCapabilityFact> {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return Vec::new();
    };

    match file_name.to_ascii_lowercase().as_str() {
        "package.json" => service.package_json_capabilities(content),
        "mcp.json" | "mcp.yaml" | "mcp.yml" => service.mcp_manifest_capabilities(content),
        "dockerfile" => service.dockerfile_capabilities(content),
        "docker-compose.yml" | "docker-compose.yaml" => {
            service.docker_compose_capabilities(content)
        }
        "requirements.txt" => service.requirements_txt_capabilities(content),
        "pyproject.toml" => service.pyproject_toml_capabilities(content),
        "cargo.toml" => service.cargo_toml_capabilities(content),
        "makefile" => service.makefile_capabilities(content),
        ".npmrc" => service.npmrc_capabilities(content),
        "pip.conf" => service.pip_conf_capabilities(content),
        "agents.md" | "claude.md" | "system.md" | "persona.md" | "soul.md" => {
            instructions::instruction_capabilities(service, content)
        }
        _ if is_prompt_pack_document(path) => {
            instructions::instruction_capabilities(service, content)
        }
        "package-lock.json"
        | "npm-shrinkwrap.json"
        | "cargo.lock"
        | "poetry.lock"
        | "pipfile.lock"
        | "uv.lock"
        | "yarn.lock"
        | "pnpm-lock.yaml" => service.lockfile_capabilities(content),
        _ if looks_like_script(path) => service.script_capabilities(content),
        _ => Vec::new(),
    }
}

pub(super) fn expected_lockfiles(
    service: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> Vec<&'static str> {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return Vec::new();
    };

    match file_name.to_ascii_lowercase().as_str() {
        "package.json" => service.package_json_expected_lockfiles(content),
        "pyproject.toml" => service.pyproject_expected_lockfiles(content),
        "cargo.toml" => vec!["Cargo.lock"],
        _ => Vec::new(),
    }
}

pub(super) fn is_prompt_pack_document(path: &Path) -> bool {
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
