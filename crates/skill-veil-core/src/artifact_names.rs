//! Canonical artifact filename sets shared by the dispatch router, the
//! artifact-kind classifier, and package / data-file discovery.
//!
//! Before centralisation these slices were re-spelled per call site and had
//! begun to drift. Matching is always by lowercased `.contains()`, so entry
//! order is irrelevant — only set membership is part of the contract.

/// Package / build manifest filenames (lowercased). Includes the MCP server
/// manifests, which the discovery and classification layers treat as
/// package-level manifests.
pub(crate) const MANIFEST_NAMES: &[&str] = &[
    "package.json",
    "mcp.json",
    "mcp.yaml",
    "mcp.yml",
    ".mcp.json",
    "claude_desktop_config.json",
    "requirements.txt",
    "pyproject.toml",
    "cargo.toml",
    "dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "makefile",
    "gnumakefile",
    ".npmrc",
    "pip.conf",
];

/// Dependency lockfile filenames (lowercased).
pub(crate) const LOCKFILE_NAMES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "cargo.lock",
    "poetry.lock",
    "pipfile.lock",
    "uv.lock",
    "yarn.lock",
    "pnpm-lock.yaml",
];
