//! Scanner module for orchestrating skill analysis.
//!
//! This module is the **composition root** for the hexagonal layout: it is
//! the only place in the core domain that legitimately imports concrete
//! adapter types. Everything else in the domain depends on `ports` traits
//! and gets adapters injected through `Scanner::with_custom_adapters`. The
//! `with_std_adapters` / `new` constructors below wire the standard
//! defaults (`StdFileSystemProvider`, `RegexPatternMatcher`,
//! `PulldownMarkdownParser`); CLI code re-uses those defaults rather than
//! reaching into `adapters/` itself. See `CLAUDE.md` → "Clean architecture"
//! for the rule and `patterns.rs` for the façade pattern used elsewhere
//! when an adapter import would otherwise smear across the boundary.

use crate::adapters::{PulldownMarkdownParser, RegexPatternMatcher, StdFileSystemProvider};
use crate::analyzer::SkillDocument;
use crate::artifact_graph::ArtifactGraph;
use crate::policy::{BaselineFile, PolicyFile, WaiverFile};
use crate::ports::{FileSystemProvider, MarkdownParser};
use crate::rules::{default_external_rule_dirs, RuleEngine};
use crate::scanner_support::{load_optional_baseline, load_optional_policy, load_optional_waivers};
pub use crate::scanner_types::{
    ArtifactMetadata, PackageScanResult, ScanError, ScanErrorEntry, ScanOptions, ScanResult,
    ScanTargetMode,
};
use crate::services::{ArtifactOrchestratorService, FileDiscoveryService, ScanFilterService};
use crate::{scanner_execution, scanner_graph};
use std::path::Path;
use std::sync::Arc;

type EngineAndPolicy = (
    RuleEngine<RegexPatternMatcher>,
    Option<BaselineFile>,
    Option<WaiverFile>,
    Option<PolicyFile>,
);

/// Build the rule engine and load optional policy files from scan options.
///
/// Shared by `with_std_adapters` and `with_custom_adapters` to avoid duplicating
/// the engine + policy loading logic. The `fs` provider is required so policy
/// file I/O passes through the same `FileSystemProvider` port the rest of the
/// scanner uses, preserving the hexagonal contract documented in `CLAUDE.md`.
fn build_engine_and_policy<F: FileSystemProvider>(
    fs: &F,
    options: &ScanOptions,
) -> Result<EngineAndPolicy, ScanError> {
    let runtime_overlay_dirs = default_external_rule_dirs();
    let mut engine = RuleEngine::with_defaults_and_matcher(
        Arc::new(RegexPatternMatcher::new()),
        fs,
        &runtime_overlay_dirs,
    )?;
    // Strict mode is only meaningful for external rule packs; built-ins
    // already fail-fast on internal duplicates. Enable before loading the
    // user-supplied rules_dir so collisions there are promoted to errors.
    engine.set_strict_mode(options.strict_rules);
    if let Some(ref rules_dir) = options.rules_dir {
        engine.load_from_dir(fs, rules_dir)?;
    }
    let baseline = load_optional_baseline(fs, options.baseline_path.as_deref())?;
    let waivers = load_optional_waivers(fs, options.waivers_path.as_deref())?;
    let policy = load_optional_policy(fs, options.policy_path.as_deref())?;
    Ok((engine, baseline, waivers, policy))
}

/// Scanner for analyzing skills and related agent-extension packages.
pub struct Scanner<
    F: FileSystemProvider = StdFileSystemProvider,
    P: MarkdownParser = PulldownMarkdownParser,
> {
    engine: RuleEngine<RegexPatternMatcher>,
    artifact_orchestration: ArtifactOrchestratorService,
    file_discovery: FileDiscoveryService<F>,
    filter_service: ScanFilterService,
    parser: P,
}

/// Scanner using the default standard-library filesystem and Pulldown Markdown adapters.
/// Use this in most application code. For injectable adapters, use [`Scanner`] directly.
pub type DefaultScanner = Scanner<StdFileSystemProvider, PulldownMarkdownParser>;

impl Scanner<StdFileSystemProvider, PulldownMarkdownParser> {
    #[must_use = "Scanner::new() returns a Result that should be used"]
    pub fn new() -> Result<Self, ScanError> {
        Self::with_std_adapters(ScanOptions::default())
    }

    #[must_use = "Scanner::with_std_adapters() returns a Result that should be used"]
    pub fn with_std_adapters(options: ScanOptions) -> Result<Self, ScanError> {
        // One `StdFileSystemProvider` shared between rule loading and file
        // discovery: the TOCTOU rationale in `scanner_execution.rs` requires
        // existence checks and reads to go through the same provider, and
        // future stateful adapter implementations (mocks, in-memory overlays,
        // chroot wrappers) would silently disagree if two instances were
        // wired in side-by-side. `with_custom_adapters` already shares a
        // single instance — keep the std path symmetric.
        let fs = StdFileSystemProvider::new();
        let (engine, baseline, waivers, policy) = build_engine_and_policy(&fs, &options)?;
        Ok(Self {
            engine,
            artifact_orchestration: ArtifactOrchestratorService::new(),
            file_discovery: FileDiscoveryService::with_fs_provider(options.recursive, fs),
            filter_service: ScanFilterService::with_policy_state(
                options, baseline, waivers, policy,
            ),
            parser: PulldownMarkdownParser::new(),
        })
    }
}

impl<F: FileSystemProvider, P: MarkdownParser> Scanner<F, P> {
    #[must_use = "Scanner::with_custom_adapters() returns a Result that should be used"]
    pub fn with_custom_adapters(
        options: ScanOptions,
        fs_provider: F,
        parser: P,
    ) -> Result<Self, ScanError> {
        let (engine, baseline, waivers, policy) = build_engine_and_policy(&fs_provider, &options)?;
        Ok(Self {
            engine,
            artifact_orchestration: ArtifactOrchestratorService::new(),
            file_discovery: FileDiscoveryService::with_fs_provider(options.recursive, fs_provider),
            filter_service: ScanFilterService::with_policy_state(
                options, baseline, waivers, policy,
            ),
            parser,
        })
    }

    pub(crate) fn engine(&self) -> &RuleEngine<RegexPatternMatcher> {
        &self.engine
    }

    pub(crate) fn artifact_orchestration(&self) -> &ArtifactOrchestratorService {
        &self.artifact_orchestration
    }

    pub(crate) fn file_discovery(&self) -> &FileDiscoveryService<F> {
        &self.file_discovery
    }

    pub(crate) fn filter_service(&self) -> &ScanFilterService {
        &self.filter_service
    }

    pub(crate) fn parser(&self) -> &P {
        &self.parser
    }

    pub(crate) fn build_artifact_graph(&self, doc: &SkillDocument) -> ArtifactGraph {
        scanner_graph::build_artifact_graph::<F>(
            &self.artifact_orchestration,
            self.file_discovery.fs_provider(),
            doc,
        )
    }

    /// Scan a single document file and return its [`ScanResult`].
    ///
    /// Accepts any path that resolves to a readable file through the
    /// scanner's `FileSystemProvider`. The file does not need to be a
    /// canonical skill entrypoint — use [`scan_skill_file`] when callers
    /// want that stricter precondition. Use [`scan_package`] or [`scan`]
    /// to scan a whole package and aggregate results.
    ///
    /// [`scan_skill_file`]: Scanner::scan_skill_file
    /// [`scan_package`]: Scanner::scan_package
    /// [`scan`]: Scanner::scan
    ///
    /// # Errors
    ///
    /// - [`ScanError::PathNotFound`] if `path` does not exist through `fs`.
    /// - Errors propagated from the analyzer / rule engine pipeline
    ///   (parse failures, rule evaluation errors, …) surface as
    ///   [`ScanError`] variants.
    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<ScanResult, ScanError> {
        let path = path.as_ref();
        if !self.file_discovery.fs_provider().exists(path) {
            return Err(ScanError::PathNotFound(path.to_path_buf()));
        }
        scanner_execution::scan_document_path(self, path)
    }

    /// Scan a path that MUST be a canonical skill entrypoint
    /// (`SKILL.md`, `agent.md`, manifest, etc.). Use this when the
    /// caller already enforces "this is the skill" semantics — `scan` /
    /// `scan_package` discover entrypoints automatically and should be
    /// preferred for general use.
    ///
    /// # Errors
    ///
    /// - [`ScanError::PathNotFound`] if `path` does not exist.
    /// - [`ScanError::InvalidSkillEntrypoint`] if `path` exists but is
    ///   not recognised as a skill entrypoint by
    ///   `FileDiscoveryService::is_explicit_skill_file`.
    /// - Errors propagated from the analyzer / rule pipeline.
    pub fn scan_skill_file(&self, path: impl AsRef<Path>) -> Result<ScanResult, ScanError> {
        let path = path.as_ref();
        if !self.file_discovery.fs_provider().exists(path) {
            return Err(ScanError::PathNotFound(path.to_path_buf()));
        }
        if !FileDiscoveryService::<F>::is_explicit_skill_file(path) {
            return Err(ScanError::InvalidSkillEntrypoint(path.to_path_buf()));
        }
        scanner_execution::scan_document_path(self, path)
    }

    /// Scan an entire package directory (or a single file treated as a
    /// degenerate one-target package). Discovers every target via
    /// `discover_package_targets` and aggregates per-target results
    /// into a [`PackageScanResult`]. Per-target failures are recorded in
    /// `pkg_result.errors` instead of aborting the whole scan, so a
    /// partially malformed package still produces verdicts for the
    /// readable subset.
    ///
    /// # Errors
    ///
    /// - [`ScanError::PathNotFound`] if `path` does not exist.
    /// - Errors from package discovery (only the *initial* discovery
    ///   step bubbles up; per-file errors are captured into
    ///   `PackageScanResult::errors`).
    pub fn scan_package(&self, path: impl AsRef<Path>) -> Result<PackageScanResult, ScanError> {
        let path = path.as_ref();
        let fs = self.file_discovery.fs_provider();
        if !fs.exists(path) {
            return Err(ScanError::PathNotFound(path.to_path_buf()));
        }
        if fs.is_file(path) {
            return Ok(match self.scan_file(path) {
                Ok(result) => PackageScanResult {
                    results: vec![result],
                    errors: Vec::new(),
                },
                Err(err) => PackageScanResult {
                    results: Vec::new(),
                    errors: vec![crate::scanner_types::ScanErrorEntry {
                        path: path.to_path_buf(),
                        error: err.to_string(),
                    }],
                },
            });
        }

        let targets = scanner_execution::discover_package_targets(self, path)?;
        let mut pkg_result = PackageScanResult::new();
        for target in targets {
            match self.scan_file(&target) {
                Ok(result) => pkg_result.results.push(result),
                Err(err) => {
                    pkg_result
                        .errors
                        .push(crate::scanner_types::ScanErrorEntry {
                            path: target.clone(),
                            error: err.to_string(),
                        });
                    tracing::warn!("Failed to scan {}: {}", target.display(), err);
                }
            }
        }
        Ok(pkg_result)
    }

    /// Top-level entry point. Honours the configured `ScanTargetMode`:
    ///
    /// - `Auto` (default) — file paths route to [`scan_file`], directory
    ///   paths to [`scan_package`].
    /// - `File` — always treated as a single document; directories
    ///   produce `PathNotFound`-equivalent errors via the analyzer.
    /// - `Package` — always treated as a package, even when the path
    ///   is a single file. Useful when callers want package-level
    ///   aggregation over a synthetic one-file package.
    ///
    /// [`scan_file`]: Scanner::scan_file
    /// [`scan_package`]: Scanner::scan_package
    ///
    /// # Errors
    ///
    /// - [`ScanError::PathNotFound`] if `path` is missing in `Auto` mode.
    /// - Errors from the underlying `scan_file` / `scan_package` paths.
    pub fn scan(&self, path: impl AsRef<Path>) -> Result<PackageScanResult, ScanError> {
        let path = path.as_ref();
        match self.filter_service.target_mode() {
            ScanTargetMode::Auto => {
                let fs = self.file_discovery.fs_provider();
                if fs.is_file(path) {
                    let result = self.scan_file(path)?;
                    Ok(PackageScanResult {
                        results: vec![result],
                        errors: Vec::new(),
                    })
                } else if fs.is_dir(path) {
                    self.scan_package(path)
                } else {
                    Err(ScanError::PathNotFound(path.to_path_buf()))
                }
            }
            ScanTargetMode::File => {
                let result = self.scan_file(path)?;
                Ok(PackageScanResult {
                    results: vec![result],
                    errors: Vec::new(),
                })
            }
            ScanTargetMode::Package => self.scan_package(path),
        }
    }

    /// Number of compiled rules currently loaded into the underlying
    /// `RuleEngine`. Combines built-in rules with any external packs
    /// loaded via `--rules-dir`. Useful for diagnostics and CLI
    /// `rules count` summaries.
    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    /// Borrow every loaded rule as a slice of references. Order matches
    /// the `RuleEngine`'s internal `Vec<CompiledRule>`: built-ins first,
    /// then external packs in load order. Intended for read-only
    /// inspection (CLI `rules list`, snapshot tests); the engine
    /// retains ownership.
    pub fn rules(&self) -> Vec<&crate::rules::Rule> {
        self.engine.rules()
    }
}

#[cfg(test)]
mod basic_tests;
#[cfg(test)]
mod capabilities_tests;
#[cfg(test)]
mod manifest_tests;
