//! File discovery service - finds skill files in directories
//!
//! This service is responsible for discovering skill markdown files within
//! a given path, either recursively or non-recursively. The implementation
//! is split across two cohesive submodules:
//!
//! - [`skill_discovery`]: locates SKILL.md / `*.skill.md` entrypoints,
//!   the AGENTS / CLAUDE / SYSTEM markdown trio, MCP manifests, and
//!   heuristic agent-extension candidates.
//! - [`package_artifacts`]: locates supporting scripts, data files,
//!   manifests, and lockfiles co-located with a skill package.
//!
//! Pure path-shape classification (constant tables,
//! `is_explicit_skill_file`, the directory skip-list) lives in the
//! [`classification`] module so the I/O orchestration here stays focused.

mod classification;
mod package_artifacts;
mod skill_discovery;

use std::path::Path;

use crate::ports::FileSystemProvider;

/// Service for discovering skill markdown files.
///
/// Generic over `FileSystemProvider` so callers (the scanner composition
/// root, or tests with mocked filesystems) inject the adapter explicitly.
/// Keeping `services/` free of concrete adapter imports preserves the
/// hexagonal contract: domain/application code depends only on ports.
///
/// Discovery methods are implemented across [`skill_discovery`] and
/// [`package_artifacts`]; this module owns only the shared struct,
/// constructor, and architectural constants.
pub struct FileDiscoveryService<F: FileSystemProvider> {
    pub(super) recursive: bool,
    pub(super) fs_provider: F,
}

impl<F: FileSystemProvider> FileDiscoveryService<F> {
    /// Create a new file discovery service with a custom filesystem provider
    ///
    /// # Arguments
    /// * `recursive` - Whether to search directories recursively
    /// * `fs_provider` - The filesystem provider to use for file operations
    pub fn with_fs_provider(recursive: bool, fs_provider: F) -> Self {
        Self {
            recursive,
            fs_provider,
        }
    }

    pub(crate) fn fs_provider(&self) -> &F {
        &self.fs_provider
    }

    /// Check whether the provided path is an explicit skill entrypoint.
    /// Thin shim over [`classification::is_explicit_skill_file`] kept on
    /// the service so existing call sites
    /// (`FileDiscoveryService::<F>::is_explicit_skill_file(path)`) keep
    /// resolving without naming the submodule.
    pub fn is_explicit_skill_file(path: &Path) -> bool {
        classification::is_explicit_skill_file(path)
    }
}

/// Hard cap on discovery descent depth. Protects against adversarial
/// or runaway directory trees that would otherwise force the walker
/// into pathological recursion (the `SKIP_DISCOVERY_DIRS` exclude-list
/// only catches well-known names like `node_modules`; an attacker can
/// nest under custom names indefinitely). 20 levels comfortably covers
/// every monorepo layout we have seen in benchmarks/corpus and leaves
/// large headroom over typical skill packages (≤ 6 levels).
pub(super) const MAX_DISCOVERY_DEPTH: usize = 20;
