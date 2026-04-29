//! Pure path-shape classification for skill discovery.
//!
//! No filesystem I/O — every function takes a `&Path` (or a `&DirEntry`,
//! whose `file_type` is cached at walk time) and returns a verdict based
//! on names, suffixes, and parent components. The constants here drive
//! both classification and the discovery walker in the parent module.

use std::path::Path;

// File-name and suffix tables -------------------------------------------------

/// Primary skill file name (case-insensitive match).
const SKILL_FILE_NAME: &str = "skill.md";
const AGENTS_FILE_NAME: &str = "agents.md";
const CLAUDE_FILE_NAME: &str = "claude.md";
const SYSTEM_FILE_NAME: &str = "system.md";
const PERSONA_FILE_NAME: &str = "persona.md";
const SOUL_FILE_NAME: &str = "soul.md";
const MCP_JSON_FILE_NAME: &str = "mcp.json";
const MCP_YAML_FILE_NAME: &str = "mcp.yaml";
const MCP_YML_FILE_NAME: &str = "mcp.yml";
/// Suffix for skill files.
const SKILL_FILE_SUFFIX: &str = ".skill.md";
const PROMPT_FILE_SUFFIX: &str = ".prompt.md";

// Glob patterns shared with the discovery walker -----------------------------

/// Glob pattern for markdown files.
pub(super) const MARKDOWN_GLOB_PATTERN: &str = "*.md";
pub(super) const JSON_GLOB_PATTERN: &str = "*.json";
pub(super) const YAML_GLOB_PATTERN: &str = "*.yaml";
pub(super) const YML_GLOB_PATTERN: &str = "*.yml";

/// Glob patterns used to auto-discover executable/script supporting artifacts
/// co-located with a skill entrypoint. Attackers frequently reference these
/// files via absolute-looking paths (e.g. `~/.openclaw/skills/.../scripts/x.sh`)
/// that do not resolve to the local package root, bypassing markdown-based
/// reference extraction. Enumerating siblings closes that gap.
pub(super) const SCRIPT_GLOB_PATTERNS: &[&str] = &[
    "*.sh", "*.bash", "*.py", "*.ps1", "*.js", "*.cjs", "*.mjs", "*.ts", "*.rb", "*.pl", "*.rs",
    "*.go", "*.php",
];

/// Glob patterns for data-bearing files that are routinely abused as payload
/// carriers (embedded endpoints, base64 blobs, `.pyc` bytecode, config-driven
/// credential exfil). Scanned under the same directory rules as scripts.
pub(super) const DATA_FILE_GLOB_PATTERNS: &[&str] = &[
    "*.json", "*.yaml", "*.yml", "*.toml", "*.txt", "*.env", "*.cfg", "*.ini",
];

/// Subdirectories underneath a skill package root that conventionally hold
/// supporting artifacts. Script/data discovery only walks these, plus the
/// package root itself at a depth of one, to avoid sweeping unrelated files
/// when a caller points the scanner at a loose markdown document outside a
/// real package layout. List derived from observed layouts in the malicious
/// corpus (`references/`, `tools/`, `actions/`, `workflows/` are common hiding
/// spots for scripts and config-embedded payloads).
pub(super) const SCRIPT_DISCOVERY_SUBDIRS: &[&str] = &[
    "scripts",
    "bin",
    "hooks",
    "src",
    "lib",
    "references",
    "tools",
    "actions",
    "commands",
    "workflows",
    "deploy",
    "config",
    ".github",
];

/// Cap on auto-discovered supporting scripts per skill to bound analysis cost
/// on pathological packages.
pub(super) const MAX_DISCOVERED_SCRIPTS: usize = 400;

/// Cap on auto-discovered data files per skill. Lower than script cap because
/// data files are more numerous in legitimate packages and more expensive to
/// parse (YAML / JSON validators) than raw regex scanning.
pub(super) const MAX_DISCOVERED_DATA_FILES: usize = 100;

/// Skip data files larger than this; eliminates large datasets / compressed
/// blobs from the analysis window while retaining anything typical of
/// credential/config exfiltration payloads.
pub(super) const MAX_DATA_FILE_BYTES: u64 = 512 * 1024;

// Pure path classifiers ------------------------------------------------------

/// Decide whether `path` is an explicit skill entrypoint by name alone.
///
/// Matches the canonical list (`SKILL.md`, `AGENTS.md`, `CLAUDE.md`,
/// `SYSTEM.md`, `PERSONA.md`, `SOUL.md`, `mcp.{json,yaml,yml}`), the
/// `.skill.md` and `.prompt.md` suffixes, and any markdown file sitting
/// directly under a `prompts/` parent.
///
/// Pure: no I/O. Used by `FileDiscoveryService::is_explicit_skill_file`
/// (kept as a static-method shim for back-compat) and directly by
/// callers in scanner_execution and scanner_graph.
pub(super) fn is_explicit_skill_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };

    let file_name_lower = file_name.to_ascii_lowercase();
    file_name_lower == SKILL_FILE_NAME
        || file_name_lower == AGENTS_FILE_NAME
        || file_name_lower == CLAUDE_FILE_NAME
        || file_name_lower == SYSTEM_FILE_NAME
        || file_name_lower == PERSONA_FILE_NAME
        || file_name_lower == SOUL_FILE_NAME
        || file_name_lower == MCP_JSON_FILE_NAME
        || file_name_lower == MCP_YAML_FILE_NAME
        || file_name_lower == MCP_YML_FILE_NAME
        || file_name_lower.ends_with(SKILL_FILE_SUFFIX)
        || file_name_lower.ends_with(PROMPT_FILE_SUFFIX)
        || path
            .parent()
            .and_then(|parent| parent.file_name())
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("prompts"))
}

/// Skip directory entries that conventionally hold vendored or generated
/// content (node_modules, vendor, build outputs, virtualenvs, …) so the
/// `WalkDir` discovery walker doesn't pay for trees that never contain
/// skills. Pure: only inspects cached `file_type()` and `file_name()`.
pub(super) fn should_skip_discovery_dir(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    entry.file_name().to_str().is_some_and(|name| {
        matches!(
            name,
            "node_modules"
                | "vendor"
                | ".git"
                | "dist"
                | "build"
                | "target"
                | ".venv"
                | "venv"
                | "__pycache__"
                | ".yarn"
                | ".pnpm-store"
                | ".next"
                | ".turbo"
                | "coverage"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Contract: the canonical entrypoint list (case-insensitive) is
    /// pinned. Locks the explicit-name list so a future rename can't
    /// silently demote one of these to "heuristic".
    #[test]
    fn is_explicit_skill_file_matches_canonical_names_case_insensitive() {
        for name in [
            "SKILL.md",
            "skill.md",
            "Skill.MD",
            "AGENTS.md",
            "CLAUDE.md",
            "SYSTEM.md",
            "PERSONA.md",
            "SOUL.md",
            "mcp.json",
            "mcp.yaml",
            "mcp.yml",
            "my-tool.skill.md",
            "review.prompt.md",
        ] {
            let p = PathBuf::from(format!("/some/path/{name}"));
            assert!(
                is_explicit_skill_file(&p),
                "{name} MUST be recognised as an explicit skill entrypoint"
            );
        }
    }

    /// Contract: a markdown file sitting directly under a `prompts/`
    /// parent is treated as a prompt entrypoint regardless of its
    /// filename. Mirrors the intent of the `.prompt.md` suffix for
    /// skill packs that use a flat `prompts/<name>.md` layout.
    #[test]
    fn is_explicit_skill_file_accepts_files_under_prompts_directory() {
        assert!(is_explicit_skill_file(Path::new("/repo/prompts/review.md")));
        assert!(is_explicit_skill_file(Path::new("/repo/Prompts/Plan.md")));
    }

    /// Contract (negative): plain markdown outside the canonical list
    /// and not under `prompts/` MUST NOT be treated as explicit. Pins
    /// the negative case so a future loosening is caught here.
    #[test]
    fn is_explicit_skill_file_rejects_arbitrary_markdown() {
        assert!(!is_explicit_skill_file(Path::new("/repo/README.md")));
        assert!(!is_explicit_skill_file(Path::new("/repo/docs/notes.md")));
    }
}
