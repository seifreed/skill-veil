//! skill-veil-core: Behavioral & Supply-Chain Security Analysis for Agent Skills
//!
//! This crate provides the core analysis engine for detecting security risks
//! in agent skills based on Markdown and associated code.
//!
//! # Overview
//!
//! skill-veil-core analyzes agent skill files (typically Markdown) for security
//! risks such as:
//!
//! - Remote code execution patterns (`curl | bash`, PowerShell IEX, etc.)
//! - Supply chain risks (untrusted sources, suspicious packages)
//! - Credential exposure
//! - Privilege escalation attempts
//! - Data exfiltration indicators
//!
//! # Quick Start
//!
//! ```
//! use skill_veil_core::scanner::Scanner;
//! use skill_veil_core::findings::Severity;
//!
//! // Create a scanner with default rules
//! let scanner = Scanner::new().unwrap();
//!
//! // Scan content directly (for demo purposes)
//! # use std::io::Write;
//! # let mut file = tempfile::NamedTempFile::new().unwrap();
//! # writeln!(file, "# Test Skill\n## Setup\n```bash\necho hello\n```").unwrap();
//! let result = scanner.scan_file(file.path()).unwrap();
//!
//! // Check results
//! println!("Found {} findings", result.findings.len());
//! if result.has_severity(Severity::Critical) {
//!     println!("Critical issues detected!");
//! }
//! ```
//!
//! # Architecture
//!
//! The crate follows a hexagonal (ports and adapters) architecture:
//!
//! - **Core Domain**: [`scanner`], [`rules`], [`findings`], [`analyzer`]
//! - **Port Traits**: [`ports`] - Interfaces for dependency injection
//! - **Adapters**: [`adapters`] - Default implementations of port traits
//! - **Services**: [`services`] - Business logic services
//!
//! # Modules
//!
//! - [`scanner`] - High-level scanning orchestration
//! - [`rules`] - Rule engine and rule definitions
//! - [`findings`] - Finding and severity types
//! - [`analyzer`] - Document parsing and analysis
//! - [`policy`] - Policy generation (SHIELD.md, SARIF, JSON)
//! - [`ports`] - Trait definitions for dependency injection
//! - [`adapters`] - Default implementations
//! - [`services`] - File discovery and filtering services

pub mod adapters;
pub mod analyzer;
pub mod artifact_graph;
mod artifact_taint;
pub mod benchmark;
mod deceptive_docs;
mod detectors;
pub mod findings;
mod inline_suppressions;
pub mod ioc_extraction;
pub mod nova;
pub(crate) mod path_safety;
pub(crate) mod patterns;
pub mod policy;
pub mod ports;
pub mod rules;
pub mod scanner;
mod scanner_execution;
mod scanner_graph;
mod scanner_support;
pub(crate) mod scanner_types;
pub mod services;
mod verdict;
mod verdict_calibration;

#[cfg(feature = "yara")]
pub mod yara_engine;

// Domain types
pub use analyzer::{
    AgentExtensionKind, ArtifactAssessment, ArtifactClassification, ArtifactIdentitySource,
    CodeBlock, Section, SkillDocument, StructuralSignals, StructuralValidity,
};
pub use benchmark::{
    evaluate_gold_corpus, AttackFamilyMetrics, BenchmarkError, BenchmarkHistory,
    BenchmarkHistoryEntry, CalibrationBucket, CalibrationSummary, CorpusCoverage, CorpusEvaluation,
    CorpusManifest, CoverageBucket, DeduplicationMetrics, GoldCorpusManifest, GoldSample,
    LabeledSample, RegressionMetrics, SampleEvaluation, SampleLabel, ThresholdRecommendation,
};
pub use findings::{
    artifact_scope_for_kind, signal_class_for, ActionTrigger, ArtifactKind, ArtifactScope,
    BlastRadiusLevel, BlastRadiusSummary, ConsensusClass, ConsensusDiscrepancy, DeclaredPermission,
    DeduplicationSummary, EvidenceKind, Finding, FindingSummary, HygieneSummary, MatchTarget,
    OperationalContext, PackageHealth, PackageVerdictReport, ProviderVote, RecommendedAction,
    RiskFactor, RootCauseGroup, Severity, SeverityCounts, SignalClass, ThreatCategory, Verdict,
    VerdictReason, RISK_THRESHOLD_BLOCK,
};
pub use ioc_extraction::{ExtractedIocs, FileHash};
pub use path_safety::path_stays_within_base;
pub use policy::{
    adjust_confidence, apply_baseline, apply_policy_overrides, apply_policy_overrides_with_audit,
    apply_waivers, baseline_from_reports, count_baseline_matches, diff_reports,
    diff_reports_with_policy_state, empty_sarif_report, finding_fingerprint, learned_allowlist,
    learned_confidence_adjustments, load_baseline, load_policy, load_waivers, validate_policy,
    validate_waivers, AppliedPolicyOverride, BaselineEntry, BaselineFile, ConfiguredProfile,
    ContextActionOverride, ContextPolicy, DiffEntry, DiffReport, Disposition, DispositionOverlay,
    DispositionRecord, JsonReport, PolicyAudit, PolicyFile, PolicyGenerator, PolicyOverride,
    PolicyProfile, PolicyProfiles, ShieldPolicy, SuppressionSummary, WaiverEntry, WaiverFile,
    POLICY_AUDIT_PRECEDENCE, POLICY_SCHEMA_VERSION,
};
pub use rules::{
    default_external_rule_dirs, is_supported_rule_pack_schema, parse_rules_file, IocFeedFile, Rule,
    RuleCondition, RuleEngine, RulePackFile, RulePackKind, RulePackMetadata,
    RULE_PACK_SCHEMA_VERSION,
};
pub use scanner::{
    ArtifactMetadata, DefaultScanner, PackageScanResult, ScanError, ScanErrorEntry, ScanOptions,
    ScanResult, ScanTargetMode, Scanner,
};
pub use scanner_graph::{artifact_kind_for_path, derive_package_id};
pub use verdict::is_conclusive_single_rule_id;

// Port traits (interfaces for dependency injection)
pub use ports::{
    DecodedText, FileContent, FileMeta, FileSystemProvider, MarkdownParser, PatternMatcher,
};

// Default adapters (implementations of port traits)
pub use adapters::{PulldownMarkdownParser, RegexPatternMatcher, StdFileSystemProvider};
pub use artifact_graph::{
    ArtifactCapability, ArtifactCapabilityFact, ArtifactCapabilitySource, ArtifactEdge,
    ArtifactGraph, ArtifactNode, ArtifactRelation, EndpointKind,
};
