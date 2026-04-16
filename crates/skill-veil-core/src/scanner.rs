//! Scanner module for orchestrating skill analysis.

use crate::adapters::{PulldownMarkdownParser, StdFileSystemProvider};
use crate::analyzer::SkillDocument;
use crate::artifact_graph::ArtifactGraph;
use crate::policy::{BaselineFile, PolicyFile, WaiverFile};
use crate::ports::{FileSystemProvider, MarkdownParser};
use crate::rules::RuleEngine;
use crate::scanner_support::{load_optional_baseline, load_optional_policy, load_optional_waivers};
pub use crate::scanner_types::{
    PackageScanResult, ScanError, ScanErrorEntry, ScanOptions, ScanResult, ScanTargetMode,
};
use crate::services::{ArtifactAnalysisService, FileDiscoveryService, ScanFilterService};
use crate::{scanner_execution, scanner_graph};
use std::path::Path;

type EngineAndPolicy = (
    RuleEngine,
    Option<BaselineFile>,
    Option<WaiverFile>,
    Option<PolicyFile>,
);

/// Build the rule engine and load optional policy files from scan options.
///
/// Shared by `with_std_adapters` and `with_custom_adapters` to avoid duplicating
/// the engine + policy loading logic.
fn build_engine_and_policy(options: &ScanOptions) -> Result<EngineAndPolicy, ScanError> {
    let mut engine = RuleEngine::with_defaults()?;
    if let Some(ref rules_dir) = options.rules_dir {
        engine.load_from_dir(rules_dir)?;
    }
    let baseline = load_optional_baseline(options.baseline_path.as_deref())?;
    let waivers = load_optional_waivers(options.waivers_path.as_deref())?;
    let policy = load_optional_policy(options.policy_path.as_deref())?;
    Ok((engine, baseline, waivers, policy))
}

/// Scanner for analyzing skills and related agent-extension packages.
pub struct Scanner<
    F: FileSystemProvider = StdFileSystemProvider,
    P: MarkdownParser = PulldownMarkdownParser,
> {
    pub(crate) engine: RuleEngine,
    pub(crate) artifact_analysis: ArtifactAnalysisService,
    pub(crate) file_discovery: FileDiscoveryService<F>,
    pub(crate) filter_service: ScanFilterService,
    pub(crate) parser: P,
}

impl Scanner<StdFileSystemProvider, PulldownMarkdownParser> {
    #[must_use = "Scanner::new() returns a Result that should be used"]
    pub fn new() -> Result<Self, ScanError> {
        Self::with_std_adapters(ScanOptions::default())
    }

    #[must_use = "Scanner::with_std_adapters() returns a Result that should be used"]
    pub fn with_std_adapters(options: ScanOptions) -> Result<Self, ScanError> {
        let (engine, baseline, waivers, policy) = build_engine_and_policy(&options)?;
        Ok(Self {
            engine,
            artifact_analysis: ArtifactAnalysisService::new(),
            file_discovery: FileDiscoveryService::new(options.recursive),
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
        let (engine, baseline, waivers, policy) = build_engine_and_policy(&options)?;
        Ok(Self {
            engine,
            artifact_analysis: ArtifactAnalysisService::new(),
            file_discovery: FileDiscoveryService::with_fs_provider(options.recursive, fs_provider),
            filter_service: ScanFilterService::with_policy_state(
                options, baseline, waivers, policy,
            ),
            parser,
        })
    }

    pub(crate) fn build_artifact_graph(&self, doc: &SkillDocument) -> ArtifactGraph {
        scanner_graph::build_artifact_graph::<F>(&self.artifact_analysis, doc)
    }

    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<ScanResult, ScanError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(ScanError::PathNotFound(path.to_path_buf()));
        }
        scanner_execution::scan_document_path(self, path)
    }

    pub fn scan_skill_file(&self, path: impl AsRef<Path>) -> Result<ScanResult, ScanError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(ScanError::PathNotFound(path.to_path_buf()));
        }
        if !FileDiscoveryService::<F>::is_explicit_skill_file(path) {
            return Err(ScanError::InvalidSkillEntrypoint(path.to_path_buf()));
        }
        scanner_execution::scan_document_path(self, path)
    }

    pub fn scan_package(&self, path: impl AsRef<Path>) -> Result<PackageScanResult, ScanError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(ScanError::PathNotFound(path.to_path_buf()));
        }
        if path.is_file() {
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

    pub fn scan(&self, path: impl AsRef<Path>) -> Result<PackageScanResult, ScanError> {
        let path = path.as_ref();
        match self.filter_service.target_mode() {
            ScanTargetMode::Auto => {
                if path.is_file() {
                    let result = self.scan_file(path)?;
                    Ok(PackageScanResult {
                        results: vec![result],
                        errors: Vec::new(),
                    })
                } else if path.is_dir() {
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

    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    pub fn rules(&self) -> Vec<&crate::rules::Rule> {
        self.engine.rules()
    }
}

#[path = "scanner_tests.rs"]
#[cfg(test)]
mod scanner_tests;
