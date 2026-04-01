use super::FileDiscoveryService;
use crate::findings::ArtifactKind;
use crate::ports::FileSystemProvider;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const PACKAGE_MANIFEST_NAMES: &[&str] = &[
    "package.json",
    "requirements.txt",
    "pyproject.toml",
    "cargo.toml",
    "gemfile",
    "go.mod",
    "composer.json",
    "pnpm-workspace.yaml",
    ".env.example",
    "docker-bake.hcl",
    ".pre-commit-config.yaml",
    ".pre-commit-config.yml",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "makefile",
    ".npmrc",
    "pip.conf",
];

const LOCKFILE_NAMES: &[&str] = &[
    "cargo.lock",
    "poetry.lock",
    "uv.lock",
    "pipfile.lock",
    "yarn.lock",
    "pnpm-lock.yaml",
    "npm-shrinkwrap.json",
    "package-lock.json",
    "go.sum",
    "gemfile.lock",
    "composer.lock",
];

const MCP_MANIFEST_NAMES: &[&str] = &["mcp.json", "mcp.yaml", "mcp.yml"];

const RELEVANT_SIBLING_NAMES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "requirements.txt",
    "pyproject.toml",
    "cargo.toml",
    "gemfile",
    "go.mod",
    "go.sum",
    "composer.json",
    "composer.lock",
    "pnpm-workspace.yaml",
    ".env.example",
    "docker-bake.hcl",
    ".pre-commit-config.yaml",
    ".pre-commit-config.yml",
    "cargo.lock",
    "poetry.lock",
    "uv.lock",
    "pipfile.lock",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "makefile",
    ".npmrc",
    "pip.conf",
    "mcp.json",
    "mcp.yaml",
    "mcp.yml",
    "yarn.lock",
    "pnpm-lock.yaml",
    "gemfile.lock",
];

pub(crate) fn artifact_kind_for_path<F: FileSystemProvider>(path: &Path) -> ArtifactKind {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_ascii_lowercase);

    match file_name.as_deref() {
        Some(name) if MCP_MANIFEST_NAMES.contains(&name) => ArtifactKind::McpServerManifest,
        Some(name) if LOCKFILE_NAMES.contains(&name) => ArtifactKind::Lockfile,
        Some(name) if PACKAGE_MANIFEST_NAMES.contains(&name) => ArtifactKind::PackageManifest,
        _ if is_github_workflow(path) => ArtifactKind::PackageManifest,
        Some("agents.md" | "claude.md" | "system.md" | "persona.md" | "soul.md") => {
            ArtifactKind::AgentInstruction
        }
        Some(name) if name.ends_with(".prompt.md") => ArtifactKind::PromptPackDocument,
        _ if is_prompt_pack_document(path) => ArtifactKind::PromptPackDocument,
        _ if FileDiscoveryService::<F>::is_explicit_skill_file(path) => ArtifactKind::SkillDocument,
        _ => ArtifactKind::ReferencedArtifact,
    }
}

pub(crate) fn sibling_files<F: FileSystemProvider>(fs_provider: &F, path: &Path) -> Vec<PathBuf> {
    let Some(parent) = path.parent() else {
        return Vec::new();
    };

    fs_provider
        .list_files(parent, "*", false)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|path| {
            let file_name = path.file_name()?.to_str()?.to_ascii_lowercase();
            let extension = path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(str::to_ascii_lowercase);
            let looks_relevant = RELEVANT_SIBLING_NAMES.contains(&file_name.as_str())
                || is_github_workflow(&path)
                || matches!(
                    extension.as_deref(),
                    Some("sh" | "bash" | "zsh" | "py" | "js" | "ts" | "ps1")
                );
            looks_relevant.then_some(path)
        })
        .collect()
}

pub(crate) fn sibling_package_manifests<F: FileSystemProvider>(
    fs_provider: &F,
    path: &Path,
) -> Vec<PathBuf> {
    fs_provider
        .list_files(path, "*", false)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|path| {
            let file_name = path.file_name()?.to_str()?.to_ascii_lowercase();
            (PACKAGE_MANIFEST_NAMES.contains(&file_name.as_str())
                || MCP_MANIFEST_NAMES.contains(&file_name.as_str()))
            .then_some(path)
        })
        .collect()
}

pub(crate) fn existing_named_siblings<F: FileSystemProvider>(
    fs_provider: &F,
    parent: &Path,
    file_names: &[&str],
) -> Vec<PathBuf> {
    fs_provider
        .list_files(parent, "*", false)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|path| {
            let file_name = path.file_name()?.to_str()?.to_ascii_lowercase();
            file_names.contains(&file_name.as_str()).then_some(path)
        })
        .collect()
}

pub(crate) fn derive_package_id(path: &Path) -> Option<String> {
    path.ancestors()
        .filter_map(|ancestor| ancestor.file_name().and_then(|name| name.to_str()))
        .find(|segment| segment.len() == 64 && segment.chars().all(|c| c.is_ascii_hexdigit()))
        .map(ToOwned::to_owned)
        .or_else(|| derive_stable_package_key(path))
}

pub(crate) fn derive_stable_package_key(path: &Path) -> Option<String> {
    let root = detect_package_root(path)?;
    let manifest_identities = manifest_identities_for_root(&root);
    if !manifest_identities.is_empty() {
        return Some(format!("pkg:{}", manifest_identities.join("+")));
    }

    let fingerprint = root_fingerprint(&root)?;
    Some(format!("local:{fingerprint}"))
}

pub(crate) fn package_inventory_files(root: &Path) -> Vec<PathBuf> {
    let mut inventory = WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| !should_skip_inventory_entry(root, entry.path()))
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            let path = entry.into_path();
            let file_name = path.file_name()?.to_str()?.to_ascii_lowercase();
            let is_relevant = PACKAGE_MANIFEST_NAMES.contains(&file_name.as_str())
                || LOCKFILE_NAMES.contains(&file_name.as_str())
                || MCP_MANIFEST_NAMES.contains(&file_name.as_str())
                || matches!(
                    file_name.as_str(),
                    "agents.md" | "claude.md" | "system.md" | "persona.md" | "soul.md"
                )
                || file_name.ends_with(".prompt.md")
                || is_github_workflow(&path);
            is_relevant.then_some(path)
        })
        .collect::<Vec<_>>();
    inventory.sort();
    inventory.dedup();
    inventory
}

pub(crate) fn is_prompt_pack_document(path: &Path) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name.to_ascii_lowercase().ends_with(".prompt.md"))
        || path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("prompts"))
}

pub(crate) fn is_github_workflow(path: &Path) -> bool {
    matches!(
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("yml" | "yaml")
    ) && path
        .parent()
        .and_then(|parent| parent.file_name())
        .and_then(|name| name.to_str())
        == Some("workflows")
        && path
            .parent()
            .and_then(|parent| parent.parent())
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            == Some(".github")
}

fn should_skip_inventory_entry(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    relative.components().any(|component| {
        component.as_os_str().to_str().is_some_and(|value| {
            matches!(
                value,
                "node_modules"
                    | "vendor"
                    | ".git"
                    | "examples"
                    | "example"
                    | "fixtures"
                    | "fixture"
                    | "testdata"
                    | "tests"
                    | "docs"
                    | "samples"
                    | "sample"
                    | "dist"
                    | "build"
                    | "target"
                    | ".venv"
                    | "venv"
                    | "__pycache__"
                    | ".mypy_cache"
                    | ".pytest_cache"
                    | ".tox"
                    | ".next"
                    | ".turbo"
                    | ".yarn"
                    | ".pnpm-store"
                    | "coverage"
            )
        })
    })
}

fn detect_package_root(path: &Path) -> Option<PathBuf> {
    let start = if path.is_dir() { path } else { path.parent()? };
    for ancestor in start.ancestors() {
        if directory_looks_like_package_root(ancestor) {
            return Some(ancestor.to_path_buf());
        }
    }
    workflow_repo_root_fallback(start)
}

fn workflow_repo_root_fallback(start: &Path) -> Option<PathBuf> {
    let components = start
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    for (index, window) in components.windows(2).enumerate() {
        if window[0] == ".github" && window[1] == "workflows" {
            let mut root = PathBuf::new();
            for component in &components[..index] {
                root.push(component);
            }
            if !root.as_os_str().is_empty() {
                return Some(root);
            }
        }
    }
    None
}

fn directory_looks_like_package_root(dir: &Path) -> bool {
    fs::read_dir(dir)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .any(|entry| {
            let path = entry.path();
            if !entry.file_type().ok().is_some_and(|ft| ft.is_file()) {
                return false;
            }
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .map(str::to_ascii_lowercase);
            file_name.as_deref().is_some_and(|name| {
                PACKAGE_MANIFEST_NAMES.contains(&name)
                    || LOCKFILE_NAMES.contains(&name)
                    || MCP_MANIFEST_NAMES.contains(&name)
                    || matches!(
                        name,
                        "agents.md" | "claude.md" | "system.md" | "persona.md" | "soul.md"
                    )
                    || name.ends_with(".prompt.md")
            })
        })
}

fn manifest_identities_for_root(root: &Path) -> Vec<String> {
    let mut identities = BTreeSet::new();
    for name in PACKAGE_MANIFEST_NAMES
        .iter()
        .chain(MCP_MANIFEST_NAMES.iter())
    {
        let manifest_path = root.join(name);
        let Ok(content) = fs::read_to_string(&manifest_path) else {
            continue;
        };
        if let Some(identity) = derive_manifest_identity(&manifest_path, &content) {
            identities.insert(identity);
        }
    }
    identities.into_iter().collect()
}

fn derive_manifest_identity(path: &Path, content: &str) -> Option<String> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())?
        .to_ascii_lowercase();

    match file_name.as_str() {
        "package.json" | "composer.json" | "mcp.json" => {
            serde_json::from_str::<serde_json::Value>(content)
                .ok()
                .and_then(|json| {
                    let name = json.get("name").and_then(serde_json::Value::as_str)?;
                    let version = json
                        .get("version")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown");
                    Some(format!("{name}@{version}"))
                })
        }
        "pyproject.toml" | "cargo.toml" => {
            toml::from_str::<toml::Value>(content)
                .ok()
                .and_then(|toml| {
                    let package = toml
                        .get("project")
                        .or_else(|| toml.get("package"))
                        .or_else(|| toml.get("tool").and_then(|tool| tool.get("poetry")))?;
                    let name = package.get("name").and_then(toml::Value::as_str)?;
                    let version = package
                        .get("version")
                        .and_then(toml::Value::as_str)
                        .unwrap_or("unknown");
                    Some(format!("{name}@{version}"))
                })
        }
        "go.mod" => content.lines().find_map(|line| {
            line.trim()
                .strip_prefix("module ")
                .map(|module| format!("{}@workspace", module.trim()))
        }),
        "gemfile" => content.lines().find_map(|line| {
            line.trim()
                .strip_prefix("source ")
                .map(|source| format!("gem-source:{}@workspace", source.trim()))
        }),
        _ => None,
    }
}

fn root_fingerprint(root: &Path) -> Option<String> {
    let mut entries = BTreeSet::new();
    for path in package_inventory_files(root) {
        let content = fs::read(&path).ok()?;
        let mut content_hash = Sha256::new();
        content_hash.update(&content);
        let relative = path
            .strip_prefix(root)
            .ok()
            .map(|value| value.display().to_string())
            .unwrap_or_else(|| {
                path.file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or_default()
                    .to_ascii_lowercase()
            });
        entries.insert(format!("{relative}:{:x}", content_hash.finalize()));
    }
    if entries.is_empty() {
        return None;
    }
    Some(format!("{:016x}", fnv1a64(entries.into_iter())))
}

fn fnv1a64(values: impl IntoIterator<Item = String>) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for value in values {
        for byte in value.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        hash ^= u64::from(b'\n');
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
