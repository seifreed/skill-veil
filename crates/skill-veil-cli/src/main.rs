//! skill-veil CLI
//!
//! Behavioral & Supply-Chain Security Analysis for Agent Skills

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use rayon::prelude::*;
use skill_veil_core::{
    benchmark::evaluate_corpus, baseline_from_reports, diff_reports_with_policy_state,
    load_baseline, load_waivers, validate_policy, validate_waivers, BaselineEntry, BaselineFile,
    BenchmarkHistory, BenchmarkHistoryEntry, CorpusEvaluation, IocFeedFile, JsonReport,
    PolicyProfile, RecommendedAction, RulePackFile, RulePackMetadata, ScanOptions, ScanResult,
    ScanTargetMode, Scanner, Severity, parse_rules_file, POLICY_SCHEMA_VERSION,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::TempDir;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

// ============================================================================
// Severity argument wrapper for CLI
// ============================================================================

/// CLI wrapper for Severity that implements ValueEnum
///
/// This exists because clap::ValueEnum should not be added to the core library.
/// The From impl provides seamless conversion to the core Severity type.
#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum PolicyProfileArg {
    Personal,
    Team,
    Enterprise,
    Research,
}

impl From<PolicyProfileArg> for PolicyProfile {
    fn from(value: PolicyProfileArg) -> Self {
        match value {
            PolicyProfileArg::Personal => PolicyProfile::Personal,
            PolicyProfileArg::Team => PolicyProfile::Team,
            PolicyProfileArg::Enterprise => PolicyProfile::Enterprise,
            PolicyProfileArg::Research => PolicyProfile::Research,
        }
    }
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
            SeverityArg::Critical => Severity::Critical,
        }
    }
}

#[derive(Parser)]
#[command(name = "skill-veil")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Suppress all output except errors
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a skill file or directory using auto-discovery
    Scan(ScanArgs),
    /// Scan a strict skill entrypoint such as `SKILL.md`
    ScanFile(ScanArgs),
    /// Scan a skill package without promoting documentation to entrypoints
    ScanPackage(ScanArgs),
    /// Scan a dataset, marketplace mirror, or monorepo containing many packages
    ScanDataset(ScanArgs),

    /// Run a labeled corpus benchmark and persist metrics
    Benchmark(BenchmarkArgs),
    /// Create or update a baseline file
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Compare two JSON scan reports
    Diff(DiffArgs),
    /// Validate waiver files
    Waivers {
        #[command(subcommand)]
        action: WaiversAction,
    },
    /// Validate policy files
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },

    /// List and manage detection rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
enum DatasetViewArg {
    Full,
    Entrypoints,
    PackageRisk,
    Verdicts,
}

#[derive(Args, Clone)]
struct ScanArgs {
    /// Path to skill file or directory
    path: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Fail if any finding at or above this severity
    #[arg(long, value_enum)]
    fail_on: Option<SeverityArg>,

    /// Minimum severity to report
    #[arg(long, value_enum)]
    min_severity: Option<SeverityArg>,

    /// Custom rules directory
    #[arg(long)]
    rules_dir: Option<PathBuf>,

    /// Optional policy profile
    #[arg(long, value_enum)]
    profile: Option<PolicyProfileArg>,

    /// Baseline file used to suppress accepted findings
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Waiver file used to suppress approved findings
    #[arg(long)]
    waivers: Option<PathBuf>,

    /// Policy file used to configure profiles and action overrides
    #[arg(long)]
    policy: Option<PathBuf>,

    /// Output file (defaults to stdout)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Non-recursive scan
    #[arg(long)]
    no_recursive: bool,

    /// Show a compact text summary suitable for CI logs
    #[arg(long, default_value_t = false)]
    quiet_summary: bool,

    /// Show only policy action and escalation reasons in text output
    #[arg(long, default_value_t = false)]
    explain_policy: bool,

    /// Limit the number of findings shown per file in text output
    #[arg(long)]
    finding_limit: Option<usize>,

    /// Apply a scan/output preset tuned for common environments
    #[arg(long, value_enum)]
    preset: Option<ScanPresetArg>,

    /// Dataset rendering view for scan-dataset
    #[arg(long, value_enum, default_value = "full")]
    dataset_view: DatasetViewArg,

    /// Render dataset verdicts using a compact analyst-friendly summary
    #[arg(long, default_value_t = false)]
    analyst_summary: bool,
}

#[derive(Args, Clone)]
struct BenchmarkArgs {
    /// Path to a labeled corpus manifest in YAML format
    corpus: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "json")]
    format: OutputFormat,

    /// Output file for benchmark metrics
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Optional benchmark history file to update
    #[arg(long)]
    history_file: Option<PathBuf>,

    /// Release identifier used when updating benchmark history
    #[arg(long)]
    release_id: Option<String>,

    /// Optional markdown dashboard path for benchmark history and trends
    #[arg(long)]
    dashboard_output: Option<PathBuf>,
}

#[derive(Args, Clone)]
struct BaselineCreateArgs {
    /// Existing JSON scan report
    report: PathBuf,

    /// Output file for the generated baseline
    #[arg(short, long)]
    output: PathBuf,
}

#[derive(Args, Clone)]
struct BaselineUpdateArgs {
    /// Current JSON scan report
    report: PathBuf,

    /// Existing baseline file
    #[arg(long)]
    baseline: PathBuf,

    /// Output file for the updated baseline
    #[arg(short, long)]
    output: PathBuf,

    /// Explicitly allow adding new findings to the baseline
    #[arg(long, default_value_t = false)]
    allow_new_findings: bool,
}

#[derive(Args, Clone)]
struct DiffArgs {
    /// Previous JSON scan report
    previous: PathBuf,

    /// Current JSON scan report
    current: PathBuf,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Optional baseline file to classify current findings as accepted
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Optional waivers file to classify current findings as waived
    #[arg(long)]
    waivers: Option<PathBuf>,

    /// Print a compact CI-oriented summary instead of the full diff listing
    #[arg(long, default_value_t = false)]
    ci_summary: bool,

    /// Exit policy for diff results
    #[arg(long, value_enum)]
    fail_on: Option<DiffFailPolicyArg>,
}

#[derive(Subcommand)]
enum BaselineAction {
    /// Create a baseline from an existing JSON report
    Create(BaselineCreateArgs),
    /// Update a baseline using a current JSON report
    Update(BaselineUpdateArgs),
}

#[derive(Subcommand)]
enum WaiversAction {
    /// Validate a waivers file
    Validate(WaiversValidateArgs),
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Validate a policy file
    Validate(PolicyValidateArgs),
}

#[derive(Args, Clone)]
struct WaiversValidateArgs {
    /// Waivers file to validate
    path: PathBuf,
}

#[derive(Args, Clone)]
struct PolicyValidateArgs {
    /// Policy file to validate
    path: PathBuf,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum DiffFailPolicyArg {
    NewActive,
    NewBlocking,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum ScanPresetArg {
    Local,
    Ci,
    Strict,
    Enterprise,
}

#[derive(Subcommand)]
enum RulesAction {
    /// List all available rules
    List {
        /// Filter by category
        #[arg(long)]
        category: Option<String>,

        /// Filter by severity
        #[arg(long, value_enum)]
        severity: Option<SeverityArg>,

        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,
    },

    /// Test a rule against sample content
    Test {
        /// Rule ID to test
        rule_id: String,

        /// Sample content file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Sample content string
        #[arg(short, long)]
        content: Option<String>,

        /// Directory containing YAML rules
        #[arg(long, default_value = "rules/official")]
        rules_dir: PathBuf,

        /// Assert whether the rule should match
        #[arg(long)]
        expect_match: Option<bool>,

        /// Assert an exact finding count
        #[arg(long)]
        expected_count: Option<usize>,

        /// Assert severity for produced findings
        #[arg(long, value_enum)]
        expected_severity: Option<SeverityArg>,

        /// Assert action for produced findings
        #[arg(long, value_enum)]
        expected_action: Option<RecommendedActionArg>,

        /// Assert category for produced findings
        #[arg(long)]
        expected_category: Option<String>,
    },

    /// Run a fixture pack against rules loaded from a directory
    TestPack {
        /// Directory containing YAML rules
        #[arg(long, default_value = "rules/official")]
        rules_dir: PathBuf,

        /// YAML fixture file describing expected rule matches
        #[arg(long, default_value = "rules/fixtures/behavioral.yaml")]
        fixtures: PathBuf,
    },

    /// Validate a rules directory for contributor-facing issues
    Validate {
        /// Directory containing YAML rules
        #[arg(long, default_value = "rules/official")]
        rules_dir: PathBuf,

        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,
    },

    /// Show a summary of the rule pack contents
    PackInfo {
        /// Directory containing YAML rules
        #[arg(long, default_value = "rules/official")]
        rules_dir: PathBuf,

        /// Output format
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    /// Human-readable text output
    Text,
    /// JSON output for CI integration
    Json,
    /// SARIF output for GitHub Code Scanning
    Sarif,
    /// SHIELD.md policy format
    Shield,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum RecommendedActionArg {
    Log,
    RequireApproval,
    Block,
}

impl From<RecommendedActionArg> for RecommendedAction {
    fn from(value: RecommendedActionArg) -> Self {
        match value {
            RecommendedActionArg::Log => RecommendedAction::Log,
            RecommendedActionArg::RequireApproval => RecommendedAction::RequireApproval,
            RecommendedActionArg::Block => RecommendedAction::Block,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.quiet {
        "error"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false).without_time())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)))
        .init();

    match cli.command {
        Commands::Scan(args) => run_scan(args, ScanTargetMode::Auto, cli.quiet)?,
        Commands::ScanFile(args) => run_scan(args, ScanTargetMode::File, cli.quiet)?,
        Commands::ScanPackage(args) => run_scan(args, ScanTargetMode::Package, cli.quiet)?,
        Commands::ScanDataset(args) => run_scan_dataset(args, cli.quiet)?,
        Commands::Benchmark(args) => run_benchmark(args)?,
        Commands::Baseline { action } => match action {
            BaselineAction::Create(args) => run_baseline_create(args)?,
            BaselineAction::Update(args) => run_baseline_update(args)?,
        },
        Commands::Diff(args) => run_diff(args)?,
        Commands::Waivers { action } => match action {
            WaiversAction::Validate(args) => run_waivers_validate(args)?,
        },
        Commands::Policy { action } => match action {
            PolicyAction::Validate(args) => run_policy_validate(args)?,
        },

        Commands::Rules { action } => {
            // Create scanner once for all rules actions
            let scanner = Scanner::new().context("Failed to initialize scanner")?;

            match action {
                RulesAction::List {
                    category,
                    severity,
                    format,
                } => {
                    let rules: Vec<_> = scanner
                        .rules()
                        .into_iter()
                        .filter(|r| {
                            if let Some(ref cat) = category {
                                if r.category.to_string() != *cat {
                                    return false;
                                }
                            }
                            if let Some(sev) = severity {
                                if r.severity != Severity::from(sev) {
                                    return false;
                                }
                            }
                            true
                        })
                        .collect();

                    match format {
                        OutputFormat::Text => {
                            println!("Loaded {} rules:\n", rules.len());
                            for rule in &rules {
                                println!(
                                    "  {} [{}/{}] - {}",
                                    rule.id, rule.severity, rule.category, rule.reason
                                );
                            }
                        }
                        OutputFormat::Json => {
                            let json = serde_json::to_string_pretty(&rules)
                                .context("Failed to serialize rules")?;
                            println!("{}", json);
                        }
                        _ => {
                            println!("Format not supported for rules list");
                        }
                    }
                }

                RulesAction::Test {
                    rule_id,
                    file,
                    content,
                    rules_dir,
                    expect_match,
                    expected_count,
                    expected_severity,
                    expected_action,
                    expected_category,
                } => {
                    let test_content = if let Some(file_path) = file {
                        std::fs::read_to_string(&file_path).context("Failed to read test file")?
                    } else if let Some(c) = content {
                        c
                    } else {
                        anyhow::bail!("Either --file or --content must be provided");
                    };

                    let engine = load_rule_engine_from_dir(&rules_dir)?;
                    let findings = engine
                        .test_rule(&rule_id, &test_content)
                        .with_context(|| format!("Failed to test rule {}", rule_id))?;
                    let case = RuleFixtureCase {
                        name: rule_id.clone(),
                        rule_id: rule_id.clone(),
                        content: test_content,
                        expect_match,
                        expected_count,
                        expected_severity: expected_severity.map(Into::into),
                        expected_action: expected_action.map(Into::into),
                        expected_category,
                    };
                    validate_fixture_case(&case, &findings)?;

                    if findings.is_empty() {
                        println!("Rule '{}' did not match the content", rule_id);
                    } else {
                        println!("Rule '{}' matched {} time(s):\n", rule_id, findings.len());
                        for finding in findings {
                            println!("  Match: \"{}\"", finding.match_value);
                            println!("  Severity: {}", finding.severity);
                            println!("  Category: {}", finding.category);
                            println!("  Action: {}", finding.recommended_action);
                            println!("  Reason: {}", finding.reason);
                            if let Some(line) = finding.line_number {
                                println!("  Line: {}", line);
                            }
                            println!();
                        }
                    }
                }
                RulesAction::TestPack { rules_dir, fixtures } => {
                    let engine = load_rule_engine_from_dir(&rules_dir)?;

                    let fixture_content = std::fs::read_to_string(&fixtures)
                        .with_context(|| format!("Failed to read fixtures {}", fixtures.display()))?;
                    let fixture_pack: RuleFixturePack = serde_yaml::from_str(&fixture_content)
                        .context("Failed to parse rule fixtures")?;

                    let mut failures = Vec::new();
                    for case in fixture_pack.cases {
                        let findings = engine
                            .test_rule(&case.rule_id, &case.content)
                            .with_context(|| format!("Failed to test rule {}", case.rule_id))?;
                        if let Err(err) = validate_fixture_case(&case, &findings) {
                            failures.push(format!("{} ({})", case.name, err));
                        }
                    }

                    if failures.is_empty() {
                        println!("All rule fixtures passed");
                    } else {
                        anyhow::bail!("Fixture failures: {}", failures.join(", "));
                    }
                }
                RulesAction::Validate { rules_dir, format } => {
                    let report = validate_rule_pack(&rules_dir)?;
                    match format {
                        OutputFormat::Text => {
                            print!("{}", format_rules_validation_text(&report));
                        }
                        OutputFormat::Json => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&report)
                                    .context("Failed to serialize validation report")?
                            );
                        }
                        OutputFormat::Sarif | OutputFormat::Shield => {
                            anyhow::bail!("rules validate only supports text or json output");
                        }
                    }

                    if !report.valid {
                        anyhow::bail!("Rule pack validation failed");
                    }
                }
                RulesAction::PackInfo { rules_dir, format } => {
                    let info = build_rule_pack_info(&rules_dir)?;
                    match format {
                        OutputFormat::Text => {
                            print!("{}", format_rule_pack_info_text(&info));
                        }
                        OutputFormat::Json => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&info)
                                    .context("Failed to serialize pack info")?
                            );
                        }
                        OutputFormat::Sarif | OutputFormat::Shield => {
                            anyhow::bail!("rules pack-info only supports text or json output");
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct RuleFixturePack {
    cases: Vec<RuleFixtureCase>,
}

#[derive(Debug, serde::Deserialize)]
struct RuleFixtureCase {
    #[serde(alias = "id")]
    name: String,
    rule_id: String,
    content: String,
    #[serde(default)]
    expect_match: Option<bool>,
    #[serde(default)]
    expected_count: Option<usize>,
    #[serde(default)]
    expected_severity: Option<Severity>,
    #[serde(default)]
    expected_action: Option<RecommendedAction>,
    #[serde(default)]
    expected_category: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct RulesValidationReport {
    rules_dir: String,
    total_rules: usize,
    pack_files: usize,
    duplicate_rule_ids: Vec<String>,
    schema_versions: BTreeSet<String>,
    pack_names: BTreeSet<String>,
    pack_kinds: BTreeSet<String>,
    issues: Vec<String>,
    valid: bool,
}

#[derive(Debug, serde::Serialize)]
struct RulePackInfo {
    rules_dir: String,
    total_rules: usize,
    pack_files: usize,
    enabled_rules: usize,
    disabled_rules: usize,
    schema_versions: BTreeSet<String>,
    pack_names: BTreeSet<String>,
    pack_kinds: BTreeSet<String>,
    by_severity: BTreeMap<String, usize>,
    by_category: BTreeMap<String, usize>,
    tags: BTreeSet<String>,
}

#[derive(Debug)]
enum ParsedRuleSource {
    RulePack(RulePackFile),
    IocFeed(IocFeedFile),
    PlainRules(Vec<skill_veil_core::Rule>),
}

fn load_rule_engine_from_dir(rules_dir: &std::path::Path) -> Result<skill_veil_core::RuleEngine> {
    let mut engine = skill_veil_core::RuleEngine::new();
    engine
        .load_from_dir(rules_dir)
        .with_context(|| format!("Failed to load rules from {}", rules_dir.display()))?;
    Ok(engine)
}

fn parse_rule_source(content: &str) -> Result<ParsedRuleSource> {
    if let Ok(pack) = serde_yaml::from_str::<RulePackFile>(content) {
        if !pack.rules.is_empty() {
            return Ok(ParsedRuleSource::RulePack(pack));
        }
    }

    if let Ok(feed) = serde_yaml::from_str::<IocFeedFile>(content) {
        if !(feed.domains.is_empty() && feed.filenames.is_empty() && feed.ips.is_empty()) {
            return Ok(ParsedRuleSource::IocFeed(feed));
        }
    }

    Ok(ParsedRuleSource::PlainRules(parse_rules_file(content)?))
}

fn collect_pack_metadata(
    metadata: &RulePackMetadata,
    pack_names: &mut BTreeSet<String>,
    pack_kinds: &mut BTreeSet<String>,
    issues: &mut Vec<String>,
    path: &std::path::Path,
) {
    if metadata.name.trim().is_empty() {
        issues.push(format!("{} has empty pack metadata.name", path.display()));
    } else {
        pack_names.insert(metadata.name.clone());
    }

    if metadata.compatibility.is_empty() {
        issues.push(format!(
            "{} does not declare metadata.compatibility",
            path.display()
        ));
    }

    if let Some(kind) = metadata.kind {
        pack_kinds.insert(format!("{kind:?}").to_lowercase());
    } else {
        issues.push(format!("{} does not declare metadata.kind", path.display()));
    }
}

fn validate_rule_pack(rules_dir: &std::path::Path) -> Result<RulesValidationReport> {
    let mut seen = BTreeMap::<String, usize>::new();
    let mut issues = Vec::new();
    let mut total_rules = 0_usize;
    let mut pack_files = 0_usize;
    let mut schema_versions = BTreeSet::new();
    let mut pack_names = BTreeSet::new();
    let mut pack_kinds = BTreeSet::new();

    for entry in walkdir::WalkDir::new(rules_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "yaml" || ext == "yml")
                .unwrap_or(false)
        })
    {
        pack_files += 1;
        let path = entry.path();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let parsed = parse_rule_source(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;

        let rules = match parsed {
            ParsedRuleSource::RulePack(pack) => {
                schema_versions.insert(pack.schema_version.clone());
                if !pack.schema_version.is_empty()
                    && pack.schema_version != skill_veil_core::RULE_PACK_SCHEMA_VERSION
                {
                    issues.push(format!(
                        "{} uses unsupported schema version {}",
                        path.display(),
                        pack.schema_version
                    ));
                }
                collect_pack_metadata(
                    &pack.metadata,
                    &mut pack_names,
                    &mut pack_kinds,
                    &mut issues,
                    path,
                );
                pack.rules
            }
            ParsedRuleSource::IocFeed(feed) => {
                schema_versions.insert(feed.schema_version.clone());
                if !feed.schema_version.is_empty()
                    && feed.schema_version != skill_veil_core::RULE_PACK_SCHEMA_VERSION
                {
                    issues.push(format!(
                        "{} uses unsupported schema version {}",
                        path.display(),
                        feed.schema_version
                    ));
                }
                collect_pack_metadata(
                    &feed.metadata,
                    &mut pack_names,
                    &mut pack_kinds,
                    &mut issues,
                    path,
                );
                parse_rules_file(&content)?
            }
            ParsedRuleSource::PlainRules(rules) => {
                issues.push(format!(
                    "{} is a legacy plain rule list; wrap it in a versioned rule pack",
                    path.display()
                ));
                rules
            }
        };

        if rules.is_empty() {
            issues.push(format!("{} does not contain any rules", path.display()));
        }

        total_rules += rules.len();
        for rule in &rules {
            *seen.entry(rule.id.clone()).or_insert(0) += 1;
            if !(0.0..=1.0).contains(&rule.confidence) {
                issues.push(format!(
                    "Rule {} has confidence {} outside the valid range [0.0, 1.0]",
                    rule.id, rule.confidence
                ));
            }
            if rule.reason.trim().is_empty() {
                issues.push(format!("Rule {} has an empty reason", rule.id));
            }
            if rule.tags.iter().any(|tag| tag.trim().is_empty()) {
                issues.push(format!("Rule {} contains empty tags", rule.id));
            }
        }
    }

    if total_rules == 0 {
        issues.push("No rules were loaded from the directory".to_string());
    }

    let duplicate_rule_ids: Vec<String> = seen
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(rule_id, _)| rule_id)
        .collect();

    let valid = issues.is_empty() && duplicate_rule_ids.is_empty();
    Ok(RulesValidationReport {
        rules_dir: rules_dir.display().to_string(),
        total_rules,
        pack_files,
        duplicate_rule_ids,
        schema_versions,
        pack_names,
        pack_kinds,
        issues,
        valid,
    })
}

fn build_rule_pack_info(rules_dir: &std::path::Path) -> Result<RulePackInfo> {
    let mut by_severity = BTreeMap::new();
    let mut by_category = BTreeMap::new();
    let mut tags = BTreeSet::new();
    let mut enabled_rules = 0_usize;
    let mut disabled_rules = 0_usize;
    let mut total_rules = 0_usize;
    let mut pack_files = 0_usize;
    let mut schema_versions = BTreeSet::new();
    let mut pack_names = BTreeSet::new();
    let mut pack_kinds = BTreeSet::new();

    for entry in walkdir::WalkDir::new(rules_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "yaml" || ext == "yml")
                .unwrap_or(false)
        })
    {
        pack_files += 1;
        let path = entry.path();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let parsed = parse_rule_source(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;
        let mut metadata_issues = Vec::new();

        let rules = match parsed {
            ParsedRuleSource::RulePack(pack) => {
                schema_versions.insert(pack.schema_version);
                collect_pack_metadata(
                    &pack.metadata,
                    &mut pack_names,
                    &mut pack_kinds,
                    &mut metadata_issues,
                    path,
                );
                pack.rules
            }
            ParsedRuleSource::IocFeed(feed) => {
                schema_versions.insert(feed.schema_version);
                collect_pack_metadata(
                    &feed.metadata,
                    &mut pack_names,
                    &mut pack_kinds,
                    &mut metadata_issues,
                    path,
                );
                parse_rules_file(&content)?
            }
            ParsedRuleSource::PlainRules(rules) => rules,
        };

        total_rules += rules.len();
        for rule in &rules {
            if rule.enabled {
                enabled_rules += 1;
            } else {
                disabled_rules += 1;
            }
            *by_severity.entry(rule.severity.to_string()).or_insert(0) += 1;
            *by_category.entry(rule.category.to_string()).or_insert(0) += 1;
            for tag in &rule.tags {
                tags.insert(tag.clone());
            }
        }
    }

    Ok(RulePackInfo {
        rules_dir: rules_dir.display().to_string(),
        total_rules,
        pack_files,
        enabled_rules,
        disabled_rules,
        schema_versions,
        pack_names,
        pack_kinds,
        by_severity,
        by_category,
        tags,
    })
}

fn validate_fixture_case(case: &RuleFixtureCase, findings: &[skill_veil_core::Finding]) -> Result<()> {
    if let Some(expect_match) = case.expect_match {
        let matched = !findings.is_empty();
        if matched != expect_match {
            anyhow::bail!(
                "Rule {} expected match={} but got {}",
                case.rule_id,
                expect_match,
                matched
            );
        }
    }

    if let Some(expected_count) = case.expected_count {
        if findings.len() != expected_count {
            anyhow::bail!(
                "Rule {} expected {} findings but got {}",
                case.rule_id,
                expected_count,
                findings.len()
            );
        }
    }

    if let Some(expected_severity) = case.expected_severity {
        if findings.iter().any(|finding| finding.severity != expected_severity) {
            anyhow::bail!("Rule {} expected severity {}", case.rule_id, expected_severity);
        }
    }

    if let Some(expected_action) = case.expected_action {
        if findings
            .iter()
            .any(|finding| finding.recommended_action != expected_action)
        {
            anyhow::bail!("Rule {} expected action {}", case.rule_id, expected_action);
        }
    }

    if let Some(expected_category) = &case.expected_category {
        if findings
            .iter()
            .any(|finding| finding.category.to_string() != *expected_category)
        {
            anyhow::bail!(
                "Rule {} expected category {}",
                case.rule_id,
                expected_category
            );
        }
    }

    Ok(())
}

fn format_rules_validation_text(report: &RulesValidationReport) -> String {
    let mut output = String::new();
    output.push_str("--- Rules Validation ---\n");
    output.push_str(&format!(
        "Directory: {}\nPack files: {}\nTotal rules: {}\nValid: {}\n",
        report.rules_dir, report.pack_files, report.total_rules, report.valid
    ));
    if !report.schema_versions.is_empty() {
        output.push_str("Schema versions:\n");
        for version in &report.schema_versions {
            output.push_str(&format!("  - {}\n", version));
        }
    }
    if !report.pack_names.is_empty() {
        output.push_str("Pack names:\n");
        for name in &report.pack_names {
            output.push_str(&format!("  - {}\n", name));
        }
    }
    if !report.pack_kinds.is_empty() {
        output.push_str("Pack kinds:\n");
        for kind in &report.pack_kinds {
            output.push_str(&format!("  - {}\n", kind));
        }
    }
    if !report.duplicate_rule_ids.is_empty() {
        output.push_str("Duplicate rule IDs:\n");
        for rule_id in &report.duplicate_rule_ids {
            output.push_str(&format!("  - {}\n", rule_id));
        }
    }
    if !report.issues.is_empty() {
        output.push_str("Issues:\n");
        for issue in &report.issues {
            output.push_str(&format!("  - {}\n", issue));
        }
    }
    output
}

fn format_rule_pack_info_text(info: &RulePackInfo) -> String {
    let mut output = String::new();
    output.push_str("--- Rule Pack Info ---\n");
    output.push_str(&format!(
        "Directory: {}\nPack files: {}\nTotal rules: {}\nEnabled: {}\nDisabled: {}\n",
        info.rules_dir, info.pack_files, info.total_rules, info.enabled_rules, info.disabled_rules
    ));
    if !info.schema_versions.is_empty() {
        output.push_str("Schema versions:\n");
        for version in &info.schema_versions {
            output.push_str(&format!("  - {}\n", version));
        }
    }
    if !info.pack_names.is_empty() {
        output.push_str("Pack names:\n");
        for name in &info.pack_names {
            output.push_str(&format!("  - {}\n", name));
        }
    }
    if !info.pack_kinds.is_empty() {
        output.push_str("Pack kinds:\n");
        for kind in &info.pack_kinds {
            output.push_str(&format!("  - {}\n", kind));
        }
    }
    if !info.by_severity.is_empty() {
        output.push_str("By severity:\n");
        for (severity, count) in &info.by_severity {
            output.push_str(&format!("  - {}: {}\n", severity, count));
        }
    }
    if !info.by_category.is_empty() {
        output.push_str("By category:\n");
        for (category, count) in &info.by_category {
            output.push_str(&format!("  - {}: {}\n", category, count));
        }
    }
    if !info.tags.is_empty() {
        output.push_str("Tags:\n");
        for tag in &info.tags {
            output.push_str(&format!("  - {}\n", tag));
        }
    }
    output
}

fn run_scan(args: ScanArgs, target_mode: ScanTargetMode, quiet: bool) -> Result<()> {
    let args = apply_scan_preset(args);
    let text_options = TextOutputOptions {
        quiet_summary: args.quiet_summary,
        explain_policy: args.explain_policy,
        finding_limit: args.finding_limit,
    };
    let options = ScanOptions {
        min_severity: args.min_severity.map(Into::into),
        fail_on: args.fail_on.map(Into::into),
        rules_dir: args.rules_dir,
        profile: args.profile.map(Into::into),
        baseline_path: args.baseline,
        waivers_path: args.waivers,
        policy_path: args.policy,
        recursive: !args.no_recursive,
        target_mode,
        ..Default::default()
    };

    let scanner = Scanner::with_std_adapters(options).context("Failed to initialize scanner")?;
    let results = scanner.scan(&args.path).context("Failed to scan path")?;
    let output_content = format_results(&results, args.format, text_options)?;

    if let Some(output_path) = args.output {
        std::fs::write(&output_path, &output_content).context("Failed to write output file")?;
        if !quiet {
            eprintln!("Output written to: {}", output_path.display());
        }
    } else {
        print!("{}", output_content);
    }

    if results.iter().any(|r| r.should_fail) {
        std::process::exit(1);
    }

    Ok(())
}

#[derive(Debug, serde::Serialize)]
struct DatasetJsonReport {
    root: String,
    package_count: usize,
    skipped_packages: usize,
    packages_with_failures: usize,
    benign_reports: usize,
    suspicious_reports: usize,
    malicious_reports: usize,
    decode_warnings: usize,
    parse_warnings: usize,
    non_agent_reports: usize,
    top_malicious_reasons: Vec<DatasetMaliciousReason>,
    reports: Vec<DatasetJsonEntry>,
}

#[derive(Debug, serde::Serialize)]
struct DatasetVerdictsJsonReport {
    root: String,
    package_count: usize,
    skipped_packages: usize,
    packages_with_failures: usize,
    archive_extraction_warnings: usize,
    benign_reports: usize,
    suspicious_reports: usize,
    malicious_reports: usize,
    decode_warnings: usize,
    parse_warnings: usize,
    top_malicious_reasons: Vec<DatasetMaliciousReason>,
    verdicts: Vec<DatasetPackageVerdictEntry>,
}

#[derive(Debug, serde::Serialize)]
struct DatasetJsonEntry {
    package_id: Option<String>,
    report: JsonReport,
}

#[derive(Debug, serde::Serialize)]
struct DatasetPackageVerdictEntry {
    package_id: Option<String>,
    final_verdict: skill_veil_core::Verdict,
    package_health: Option<skill_veil_core::PackageHealth>,
    blast_radius: Option<skill_veil_core::BlastRadiusLevel>,
    declared_permissions: Vec<skill_veil_core::DeclaredPermission>,
    strongest_reason: Option<String>,
    top_rule: Option<String>,
    representative_path: String,
    main_summary: Vec<String>,
    supporting_summary: Vec<String>,
    package_root_summary: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
struct DatasetMaliciousReason {
    package_id: Option<String>,
    skill_path: String,
    scope: String,
    representative_rules: Vec<String>,
    category: String,
    signal_class: String,
    strongest_action: String,
}

#[derive(Debug)]
struct DatasetPreparation {
    package_roots: Vec<PathBuf>,
    _temp_dir: Option<TempDir>,
    skipped_archives: usize,
}

fn run_scan_dataset(args: ScanArgs, quiet: bool) -> Result<()> {
    let args = apply_scan_preset(args);
    let text_options = TextOutputOptions {
        quiet_summary: args.quiet_summary,
        explain_policy: args.explain_policy,
        finding_limit: args.finding_limit,
    };
    let options = ScanOptions {
        min_severity: args.min_severity.map(Into::into),
        fail_on: args.fail_on.map(Into::into),
        rules_dir: args.rules_dir.clone(),
        profile: args.profile.map(Into::into),
        baseline_path: args.baseline.clone(),
        waivers_path: args.waivers.clone(),
        policy_path: args.policy.clone(),
        recursive: !args.no_recursive,
        target_mode: ScanTargetMode::Package,
        ..Default::default()
    };

    let scanner = Arc::new(
        Scanner::with_std_adapters(options).context("Failed to initialize scanner")?,
    );
    let prepared_dataset = prepare_dataset_packages(&args.path)?;
    let package_roots = prepared_dataset.package_roots.clone();
    if package_roots.is_empty() {
        anyhow::bail!(
            "No package roots with SKILL.md were found under {}",
            args.path.display()
        );
    }

    enum DatasetScanOutcome {
        Results(Vec<ScanResult>),
        Skipped,
        Failed(String),
    }

    let outcomes: Vec<_> = package_roots
        .par_iter()
        .map(|package_root| match scanner.scan(package_root) {
            Ok(results) => DatasetScanOutcome::Results(results),
            Err(skill_veil_core::scanner::ScanError::NoSkillEntrypoints(_)) => {
                DatasetScanOutcome::Skipped
            }
            Err(err) => DatasetScanOutcome::Failed(format!(
                "{}: {}",
                package_root.display(),
                err
            )),
        })
        .collect();

    let mut all_results = Vec::new();
    let mut packages_with_failures = 0_usize;
    let mut skipped_packages = 0_usize;
    for outcome in outcomes {
        match outcome {
            DatasetScanOutcome::Results(results) => {
                if results.iter().any(|result| result.should_fail) {
                    packages_with_failures += 1;
                }
                all_results.extend(results);
            }
            DatasetScanOutcome::Skipped => skipped_packages += 1,
            DatasetScanOutcome::Failed(message) => {
                packages_with_failures += 1;
                if !quiet {
                    eprintln!("Dataset package scan warning: {message}");
                }
            }
        }
    }

    let dataset_results = filter_dataset_results(&all_results, args.dataset_view);
    let dataset_reports: Vec<_> = dataset_results.iter().map(|result| result.to_json_report()).collect();
    let dataset_entries: Vec<_> = dataset_reports
        .iter()
        .cloned()
        .map(|report| DatasetJsonEntry {
            package_id: report
                .package_id
                .clone()
                .or_else(|| extract_package_id_from_skill_path(&report.skill_path)),
            report,
        })
        .collect();
    let aggregated_package_verdicts = aggregate_package_verdicts(&dataset_entries);
    let verdict_counts = if args.dataset_view == DatasetViewArg::Verdicts {
        count_aggregated_verdicts(&aggregated_package_verdicts)
    } else {
        count_verdicts(&dataset_reports)
    };
    let decode_warnings = count_warning_rule(&dataset_reports, "ARTIFACT_DECODE_WARNING");
    let parse_warnings = count_warning_rule(&dataset_reports, "ARTIFACT_PARSE_WARNING");
    let non_agent_packages = dataset_reports
        .iter()
        .filter(|report| report.classification == skill_veil_core::ArtifactClassification::GenericMarkdown)
        .count();
    let top_malicious_reasons = top_malicious_reasons(&dataset_reports);

    let output_content = match args.format {
        OutputFormat::Text => {
            let mut output = String::new();
            output.push_str("--- Dataset Summary ---\n");
            output.push_str(&format!(
                "Root: {}\nPackages discovered: {}\nPackages skipped: {}\nPackages with failures: {}\nArchive extraction warnings: {}\nView: {:?}\nVerdicts: benign={} suspicious={} malicious={}\nWarnings: decode={} parse={}\nNon-agent reports: {}\n",
                args.path.display(),
                package_roots.len(),
                skipped_packages,
                packages_with_failures,
                prepared_dataset.skipped_archives,
                args.dataset_view,
                verdict_counts.0,
                verdict_counts.1,
                verdict_counts.2,
                decode_warnings,
                parse_warnings,
                non_agent_packages,
            ));
            if !top_malicious_reasons.is_empty() {
                output.push_str("Top malicious reasons:\n");
                for reason in top_malicious_reasons.iter().take(8) {
                    output.push_str(&format!(
                        "  - package={} scope={} rules={} category={} signal={} action={}\n",
                        reason.package_id.as_deref().unwrap_or("unknown"),
                        reason.scope,
                        reason.representative_rules.join(","),
                        reason.category,
                        reason.signal_class,
                        reason.strongest_action,
                    ));
                }
            }
            if args.dataset_view == DatasetViewArg::Verdicts {
                output.push_str(&format_dataset_verdicts_text(
                    &aggregated_package_verdicts,
                    args.analyst_summary,
                ));
            } else {
                output.push_str(&format_results(&dataset_results, OutputFormat::Text, text_options)?);
            }
            output
        }
        OutputFormat::Json => {
            if args.dataset_view == DatasetViewArg::Verdicts {
                serde_json::to_string_pretty(&DatasetVerdictsJsonReport {
                    root: args.path.display().to_string(),
                    package_count: package_roots.len(),
                    skipped_packages,
                    packages_with_failures,
                    archive_extraction_warnings: prepared_dataset.skipped_archives,
                    benign_reports: verdict_counts.0,
                    suspicious_reports: verdict_counts.1,
                    malicious_reports: verdict_counts.2,
                    decode_warnings,
                    parse_warnings,
                    top_malicious_reasons,
                    verdicts: aggregated_package_verdicts,
                })
                .context("Failed to serialize compact verdict dataset JSON")?
            } else {
                serde_json::to_string_pretty(&DatasetJsonReport {
                    root: args.path.display().to_string(),
                    package_count: package_roots.len(),
                    skipped_packages,
                    packages_with_failures,
                    benign_reports: verdict_counts.0,
                    suspicious_reports: verdict_counts.1,
                    malicious_reports: verdict_counts.2,
                    decode_warnings,
                    parse_warnings,
                    non_agent_reports: non_agent_packages,
                    top_malicious_reasons,
                    reports: dataset_entries,
                })
                .context("Failed to serialize dataset JSON")?
            }
        }
        OutputFormat::Sarif => format_sarif_output(&dataset_results)?,
        OutputFormat::Shield => format_shield_output(&dataset_results),
    };

    if let Some(output_path) = args.output {
        std::fs::write(&output_path, &output_content).context("Failed to write output file")?;
        if !quiet {
            eprintln!("Output written to: {}", output_path.display());
        }
    } else {
        print!("{}", output_content);
    }

    if dataset_results.iter().any(|result| result.should_fail) {
        std::process::exit(1);
    }

    Ok(())
}

fn filter_dataset_results(results: &[ScanResult], view: DatasetViewArg) -> Vec<ScanResult> {
    results
        .iter()
        .filter(|result| match view {
            DatasetViewArg::Full => true,
            DatasetViewArg::Entrypoints => {
                result.classification != skill_veil_core::ArtifactClassification::GenericMarkdown
            }
            DatasetViewArg::PackageRisk => {
                result.classification == skill_veil_core::ArtifactClassification::GenericMarkdown
                    || !result.supporting_findings.is_empty()
            }
            DatasetViewArg::Verdicts => result.verdict != skill_veil_core::Verdict::Benign,
        })
        .cloned()
        .collect()
}

fn count_verdicts(reports: &[JsonReport]) -> (usize, usize, usize) {
    reports.iter().fold((0, 0, 0), |mut acc, report| {
        match report.verdict {
            skill_veil_core::Verdict::Benign => acc.0 += 1,
            skill_veil_core::Verdict::Suspicious => acc.1 += 1,
            skill_veil_core::Verdict::Malicious => acc.2 += 1,
        }
        acc
    })
}

fn count_warning_rule(reports: &[JsonReport], rule_id: &str) -> usize {
    reports
        .iter()
        .map(|report| report.findings.iter().filter(|finding| finding.rule_id == rule_id).count())
        .sum()
}

fn extract_package_id_from_skill_path(skill_path: &str) -> Option<String> {
    skill_path
        .split('/')
        .find(|segment| segment.len() == 64 && segment.chars().all(|c| c.is_ascii_hexdigit()))
        .map(ToOwned::to_owned)
}

fn top_malicious_reasons(reports: &[JsonReport]) -> Vec<DatasetMaliciousReason> {
    let mut reasons: Vec<_> = reports
        .iter()
        .filter(|report| report.verdict == skill_veil_core::Verdict::Malicious)
        .flat_map(|report| {
            report
                .verdict_report
                .root_cause_groups
                .iter()
                .filter(|group| group.strongest_action == skill_veil_core::RecommendedAction::Block)
                    .map(|group| DatasetMaliciousReason {
                    package_id: report
                        .package_id
                        .clone()
                        .or_else(|| extract_package_id_from_skill_path(&report.skill_path)),
                    skill_path: report.skill_path.clone(),
                    scope: group.scope.to_string(),
                    representative_rules: group.representative_rules.clone(),
                    category: group.category.to_string(),
                    signal_class: group.signal_class.to_string(),
                    strongest_action: group.strongest_action.to_string(),
                })
        })
        .collect();
    reasons.sort_by(|left, right| {
        left.package_id
            .cmp(&right.package_id)
            .then_with(|| left.scope.cmp(&right.scope))
            .then_with(|| left.category.cmp(&right.category))
    });
    reasons
}

fn prepare_dataset_packages(root: &std::path::Path) -> Result<DatasetPreparation> {
    let immediate_subdirs: Vec<_> = std::fs::read_dir(root)
        .with_context(|| format!("Failed to read dataset root {}", root.display()))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let hidden = name.to_str().is_some_and(|name| name.starts_with('.'));
            entry.file_type()
                .ok()
                .filter(|ft| ft.is_dir() && !hidden)
                .map(|_| entry.path())
        })
        .collect();
    if !immediate_subdirs.is_empty() {
        return Ok(DatasetPreparation {
            package_roots: immediate_subdirs,
            _temp_dir: None,
            skipped_archives: 0,
        });
    }

    let archive_files: Vec<_> = std::fs::read_dir(root)
        .with_context(|| format!("Failed to read dataset root {}", root.display()))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            if !entry.file_type().ok().is_some_and(|ft| ft.is_file()) {
                return None;
            }
            if path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"))
                || is_zip_archive(&path)
            {
                Some(path.clone())
            } else {
                None
            }
        })
        .collect();
    if !archive_files.is_empty() {
        let cache_root = root.join(".skill-veil-cache").join("extracted");
        fs::create_dir_all(&cache_root)
            .with_context(|| format!("Failed to create {}", cache_root.display()))?;

        let extraction_results: Vec<_> = archive_files
            .par_iter()
            .map(|zip_path| extract_zip_package_cached(zip_path, &cache_root))
            .collect();

        let mut skipped_archives = 0_usize;
        for result in extraction_results {
            match result {
                Ok(()) => {}
                Err(err) => {
                    skipped_archives += 1;
                    tracing::warn!("{err:#}");
                }
            }
        }

        let extracted_roots: Vec<_> = std::fs::read_dir(&cache_root)
            .with_context(|| format!("Failed to read {}", cache_root.display()))?
            .filter_map(Result::ok)
            .filter_map(|entry| entry.file_type().ok().filter(|ft| ft.is_dir()).map(|_| entry.path()))
            .collect();
        return Ok(DatasetPreparation {
            package_roots: extracted_roots,
            _temp_dir: None,
            skipped_archives,
        });
    }

    let mut packages = BTreeSet::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_type().is_file())
    {
        if entry
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("SKILL.md"))
        {
            if let Some(parent) = entry.path().parent() {
                packages.insert(parent.to_path_buf());
            }
        }
    }
    Ok(DatasetPreparation {
        package_roots: packages.into_iter().collect(),
        _temp_dir: None,
        skipped_archives: 0,
    })
}

fn is_zip_archive(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    zip::ZipArchive::new(file).is_ok()
}

fn extract_zip_package(zip_path: &Path, output_dir: &Path) -> Result<()> {
    let file = std::fs::File::open(zip_path)
        .with_context(|| format!("Failed to open {}", zip_path.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).with_context(|| format!("Invalid zip {}", zip_path.display()))?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("Failed to read zip entry {}", zip_path.display()))?;
        let Some(relative_path) = entry.enclosed_name().map(|path| path.to_path_buf()) else {
            continue;
        };
        let destination = output_dir.join(relative_path);
        if entry.is_dir() {
            std::fs::create_dir_all(&destination)
                .with_context(|| format!("Failed to create {}", destination.display()))?;
            continue;
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }
        let mut outfile = std::fs::File::create(&destination)
            .with_context(|| format!("Failed to create {}", destination.display()))?;
        std::io::copy(&mut entry, &mut outfile)
            .with_context(|| format!("Failed to extract {}", destination.display()))?;
    }
    Ok(())
}

fn extract_zip_package_cached(zip_path: &Path, cache_root: &Path) -> Result<()> {
    let package_name = zip_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("package");
    let output_dir = cache_root.join(package_name);
    let marker_path = output_dir.join(".skill-veil-source");
    let source_signature = zip_source_signature(zip_path)?;

    if output_dir.is_dir()
        && marker_path.exists()
        && fs::read_to_string(&marker_path).ok().as_deref() == Some(source_signature.as_str())
    {
        return Ok(());
    }

    let staging_dir = cache_root.join(format!(".{}.tmp", package_name));
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .with_context(|| format!("Failed to clean {}", staging_dir.display()))?;
    }
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("Failed to create {}", staging_dir.display()))?;
    extract_zip_package(zip_path, &staging_dir)?;
    fs::write(staging_dir.join(".skill-veil-source"), &source_signature)
        .with_context(|| format!("Failed to write marker for {}", zip_path.display()))?;

    if output_dir.exists() {
        fs::remove_dir_all(&output_dir)
            .with_context(|| format!("Failed to replace {}", output_dir.display()))?;
    }
    fs::rename(&staging_dir, &output_dir).or_else(|_| {
        fs::create_dir_all(&output_dir)?;
        for entry in fs::read_dir(&staging_dir)? {
            let entry = entry?;
            let source = entry.path();
            let destination = output_dir.join(entry.file_name());
            fs::rename(source, destination)?;
        }
        fs::remove_dir_all(&staging_dir)
    }).with_context(|| format!("Failed to finalize cached extraction for {}", zip_path.display()))?;
    Ok(())
}

fn zip_source_signature(zip_path: &Path) -> Result<String> {
    let metadata = fs::metadata(zip_path)
        .with_context(|| format!("Failed to stat {}", zip_path.display()))?;
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    Ok(format!("{}:{}:{}", zip_path.display(), metadata.len(), modified))
}

fn format_dataset_verdicts_text(
    entries: &[DatasetPackageVerdictEntry],
    analyst_summary: bool,
) -> String {
    let mut lines = String::new();
    lines.push_str("\n--- Verdict Triage ---\n");

    for entry in entries {
        if analyst_summary {
            lines.push_str(&format_dataset_verdict_analyst_line(entry));
        } else {
            lines.push_str(&format!(
                "{} package={} health={} blast_radius={} declared_permissions={} rule={} why={} main={} supporting={} package_root={} path={}\n",
                entry.final_verdict,
                entry.package_id.as_deref().unwrap_or("unknown"),
                entry
                    .package_health
                    .map(|health| health.to_string())
                    .unwrap_or_else(|| "healthy".to_string()),
                entry
                    .blast_radius
                    .map(|level| level.to_string())
                    .unwrap_or_else(|| "low".to_string()),
                render_declared_permissions(&entry.declared_permissions),
                entry.top_rule.as_deref().unwrap_or("none"),
                entry.strongest_reason.as_deref().unwrap_or("no_strong_cause"),
                render_scope_summary(&entry.main_summary),
                render_scope_summary(&entry.supporting_summary),
                render_scope_summary(&entry.package_root_summary),
                entry.representative_path
            ));
        }
    }

    lines
}

fn format_dataset_verdict_analyst_line(entry: &DatasetPackageVerdictEntry) -> String {
    let scope = strongest_scope(entry);
    let top_reason = entry
        .strongest_reason
        .as_deref()
        .unwrap_or("no_strong_cause");
    format!(
        "[{verdict}] package={package} scope={scope} rule={rule} blast={blast} perms={perms} reason={reason} path={path}\n",
        verdict = entry.final_verdict,
        package = entry.package_id.as_deref().unwrap_or("unknown"),
        scope = scope,
        rule = entry.top_rule.as_deref().unwrap_or("none"),
        blast = entry
            .blast_radius
            .map(|level| level.to_string())
            .unwrap_or_else(|| "low".to_string()),
        perms = render_declared_permissions(&entry.declared_permissions),
        reason = top_reason,
        path = entry.representative_path,
    )
}

fn strongest_scope(entry: &DatasetPackageVerdictEntry) -> &'static str {
    if let Some(reason) = &entry.strongest_reason {
        if let Some(scope) = reason.split('/').next() {
            return match scope {
                "agent_entrypoint" => "agent_entrypoint",
                "supporting_artifact" => "supporting_artifact",
                "package_root_artifact" => "package_root_artifact",
                _ => "unknown",
            };
        }
    }
    if !entry.main_summary.is_empty() {
        "agent_entrypoint"
    } else if !entry.supporting_summary.is_empty() {
        "supporting_artifact"
    } else if !entry.package_root_summary.is_empty() {
        "package_root_artifact"
    } else {
        "unknown"
    }
}

fn render_declared_permissions(
    declared_permissions: &[skill_veil_core::DeclaredPermission],
) -> String {
    if declared_permissions.is_empty() {
        "none".to_string()
    } else {
        declared_permissions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn verdict_priority(verdict: &skill_veil_core::Verdict) -> u8 {
    match verdict {
        skill_veil_core::Verdict::Malicious => 3,
        skill_veil_core::Verdict::Suspicious => 2,
        skill_veil_core::Verdict::Benign => 1,
    }
}

fn signal_class_priority(signal_class: &skill_veil_core::SignalClass) -> u8 {
    match signal_class {
        skill_veil_core::SignalClass::MaliciousBehavior => 4,
        skill_veil_core::SignalClass::SuspiciousPackageBehavior => 3,
        skill_veil_core::SignalClass::ReviewSignal => 2,
        skill_veil_core::SignalClass::Hygiene => 1,
    }
}

fn action_priority(action: &skill_veil_core::RecommendedAction) -> u8 {
    match action {
        skill_veil_core::RecommendedAction::Log => 1,
        skill_veil_core::RecommendedAction::RequireApproval => 2,
        skill_veil_core::RecommendedAction::Block => 3,
    }
}

fn strongest_root_cause<'a>(
    group: &[&'a DatasetJsonEntry],
) -> Option<&'a skill_veil_core::RootCauseGroup> {
    group.iter().flat_map(|entry| entry.report.verdict_report.root_cause_groups.iter()).max_by(
        |left, right| {
            action_priority(&left.strongest_action)
                .cmp(&action_priority(&right.strongest_action))
                .then_with(|| signal_class_priority(&left.signal_class).cmp(&signal_class_priority(&right.signal_class)))
                .then_with(|| left.finding_count.cmp(&right.finding_count))
        },
    )
}

fn strongest_finding_rule(group: &[&DatasetJsonEntry]) -> Option<String> {
    group.iter()
        .flat_map(|entry| entry.report.findings.iter())
        .max_by(|left, right| {
            action_priority(&left.recommended_action)
                .cmp(&action_priority(&right.recommended_action))
                .then_with(|| signal_class_priority(&left.signal_class).cmp(&signal_class_priority(&right.signal_class)))
                .then_with(|| severity_priority(&left.severity).cmp(&severity_priority(&right.severity)))
        })
        .map(|finding| finding.rule_id.clone())
}

fn severity_priority(severity: &skill_veil_core::Severity) -> u8 {
    match severity {
        skill_veil_core::Severity::Low => 1,
        skill_veil_core::Severity::Medium => 2,
        skill_veil_core::Severity::High => 3,
        skill_veil_core::Severity::Critical => 4,
    }
}

fn aggregate_package_verdicts(entries: &[DatasetJsonEntry]) -> Vec<DatasetPackageVerdictEntry> {
    let mut grouped = BTreeMap::<String, Vec<&DatasetJsonEntry>>::new();
    for entry in entries {
        let key = entry
            .package_id
            .clone()
            .unwrap_or_else(|| entry.report.skill_path.clone());
        grouped.entry(key).or_default().push(entry);
    }

    let mut verdicts = Vec::new();
    for (key, group) in grouped {
        let representative = group
            .iter()
            .max_by(|left, right| {
                verdict_priority(&left.report.verdict)
                    .cmp(&verdict_priority(&right.report.verdict))
                    .then_with(|| left.report.summary.risk_score.cmp(&right.report.summary.risk_score))
                    .then_with(|| left.report.heuristic_score.cmp(&right.report.heuristic_score))
            })
            .expect("group is not empty");

        let final_verdict = group
            .iter()
            .map(|entry| entry.report.verdict)
            .max_by_key(verdict_priority)
            .unwrap_or(skill_veil_core::Verdict::Benign);
        let package_health = group
            .iter()
            .map(|entry| entry.report.verdict_report.package_health)
            .max_by_key(package_health_priority);
        let strongest_root_cause = strongest_root_cause(&group);
        verdicts.push(DatasetPackageVerdictEntry {
            package_id: Some(key),
            final_verdict,
            package_health,
            blast_radius: representative.report.verdict_report.blast_radius_summary.level,
            declared_permissions: representative
                .report
                .verdict_report
                .declared_permissions
                .clone(),
            strongest_reason: strongest_root_cause
                .map(|group| format!("{}/{}/{}", group.scope, group.category, group.signal_class)),
            top_rule: strongest_finding_rule(&group).or_else(|| {
                strongest_root_cause
                    .and_then(|group| group.representative_rules.first())
                    .cloned()
            }),
            representative_path: representative.report.skill_path.clone(),
            main_summary: summarize_scope(&group, skill_veil_core::ArtifactScope::AgentEntrypoint),
            supporting_summary: summarize_scope(&group, skill_veil_core::ArtifactScope::SupportingArtifact),
            package_root_summary: summarize_scope(&group, skill_veil_core::ArtifactScope::PackageRootArtifact),
        });
    }

    verdicts.sort_by(|left, right| {
        verdict_priority(&right.final_verdict)
            .cmp(&verdict_priority(&left.final_verdict))
            .then_with(|| {
                package_health_priority(&right.package_health.unwrap_or(skill_veil_core::PackageHealth::Healthy))
                    .cmp(&package_health_priority(&left.package_health.unwrap_or(skill_veil_core::PackageHealth::Healthy)))
            })
            .then_with(|| left.package_id.cmp(&right.package_id))
    });
    verdicts
}

fn summarize_scope(
    entries: &[&DatasetJsonEntry],
    scope: skill_veil_core::ArtifactScope,
) -> Vec<String> {
    let mut seen = BTreeSet::new();
    for entry in entries {
        for group in &entry.report.verdict_report.root_cause_groups {
            if group.scope == scope {
                seen.insert(format!("{}/{}", group.category, group.signal_class));
            }
        }
    }
    seen.into_iter().take(3).collect()
}

fn render_scope_summary(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(",")
    }
}

fn count_aggregated_verdicts(entries: &[DatasetPackageVerdictEntry]) -> (usize, usize, usize) {
    entries.iter().fold((0, 0, 0), |mut acc, entry| {
        match entry.final_verdict {
            skill_veil_core::Verdict::Benign => acc.0 += 1,
            skill_veil_core::Verdict::Suspicious => acc.1 += 1,
            skill_veil_core::Verdict::Malicious => acc.2 += 1,
        }
        acc
    })
}

fn package_health_priority(health: &skill_veil_core::PackageHealth) -> u8 {
    match health {
        skill_veil_core::PackageHealth::Healthy => 1,
        skill_veil_core::PackageHealth::NeedsReview => 2,
        skill_veil_core::PackageHealth::Elevated => 3,
    }
}

fn apply_scan_preset(mut args: ScanArgs) -> ScanArgs {
    match args.preset {
        Some(ScanPresetArg::Local) | None => {}
        Some(ScanPresetArg::Ci) => {
            args.quiet_summary = true;
            args.finding_limit.get_or_insert(10);
            args.profile.get_or_insert(PolicyProfileArg::Team);
        }
        Some(ScanPresetArg::Strict) => {
            args.quiet_summary = true;
            args.finding_limit.get_or_insert(10);
            args.profile.get_or_insert(PolicyProfileArg::Enterprise);
            args.fail_on.get_or_insert(SeverityArg::High);
            args.min_severity.get_or_insert(SeverityArg::Medium);
        }
        Some(ScanPresetArg::Enterprise) => {
            args.quiet_summary = true;
            args.finding_limit.get_or_insert(20);
            args.profile.get_or_insert(PolicyProfileArg::Enterprise);
            args.min_severity.get_or_insert(SeverityArg::Medium);
        }
    }
    args
}

fn run_benchmark(args: BenchmarkArgs) -> Result<()> {
    let scanner = Scanner::new().context("Failed to initialize scanner")?;
    let evaluation =
        evaluate_corpus(&scanner, &args.corpus).context("Failed to evaluate benchmark corpus")?;
    let mut dashboard_history = None;

    if let Some(history_path) = &args.history_file {
        let release_id = args
            .release_id
            .clone()
            .context("`--release-id` is required when `--history-file` is set")?;
        dashboard_history = Some(update_benchmark_history(history_path, &release_id, &evaluation)?);
    }

    if let Some(dashboard_path) = args.dashboard_output.as_ref() {
        let history = if let Some(history) = dashboard_history.clone() {
            history
        } else if let Some(history_path) = args.history_file.as_ref() {
            let content = std::fs::read_to_string(history_path)
                .with_context(|| format!("Failed to read {}", history_path.display()))?;
            serde_json::from_str::<BenchmarkHistory>(&content)
                .with_context(|| format!("Failed to parse {}", history_path.display()))?
        } else {
            BenchmarkHistory {
                schema_version: POLICY_SCHEMA_VERSION.to_string(),
                releases: Vec::new(),
            }
        };
        write_benchmark_dashboard(dashboard_path, &history, &evaluation)?;
        let tuning_path = dashboard_path.with_file_name("benchmark-tuning-report.md");
        write_benchmark_tuning_report(&tuning_path, &evaluation)?;
    } else if let Some(history_path) = args.history_file.as_ref() {
        let dashboard_path = history_path.with_file_name("benchmark-dashboard.md");
        let tuning_path = history_path.with_file_name("benchmark-tuning-report.md");
        let history = dashboard_history.unwrap_or_else(|| BenchmarkHistory {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            releases: Vec::new(),
        });
        write_benchmark_dashboard(&dashboard_path, &history, &evaluation)?;
        write_benchmark_tuning_report(&tuning_path, &evaluation)?;
    }

    let output_content = match args.format {
        OutputFormat::Json => serde_json::to_string_pretty(&evaluation)
            .context("Failed to serialize benchmark output")?,
        OutputFormat::Text => format_benchmark_text(&evaluation),
        OutputFormat::Sarif | OutputFormat::Shield => {
            anyhow::bail!("Benchmark only supports text or json output")
        }
    };

    if let Some(output_path) = args.output {
        std::fs::write(&output_path, output_content).context("Failed to write output file")?;
    } else {
        print!("{}", output_content);
    }

    Ok(())
}

fn update_benchmark_history(
    history_path: &PathBuf,
    release_id: &str,
    evaluation: &CorpusEvaluation,
) -> Result<BenchmarkHistory> {
    let mut history = if history_path.exists() {
        let content = std::fs::read_to_string(history_path)
            .with_context(|| format!("Failed to read {}", history_path.display()))?;
        serde_json::from_str::<BenchmarkHistory>(&content)
            .with_context(|| format!("Failed to parse {}", history_path.display()))?
    } else {
        BenchmarkHistory {
            schema_version: POLICY_SCHEMA_VERSION.to_string(),
            releases: Vec::new(),
        }
    };

    let entry = BenchmarkHistoryEntry {
        release_id: release_id.to_string(),
        generated_at: chrono::Utc::now(),
        metrics: evaluation.metrics,
        coverage: evaluation.coverage.clone(),
        deduplication: evaluation.deduplication,
        confidence_calibration: evaluation.confidence_calibration.clone(),
        threshold_recommendation: evaluation.threshold_recommendation.clone(),
        family_metrics: evaluation.family_metrics.clone(),
    };

    history.releases.retain(|existing| existing.release_id != release_id);
    history.releases.push(entry);
    history
        .releases
        .sort_by(|left, right| left.release_id.cmp(&right.release_id));

    let content =
        serde_json::to_string_pretty(&history).context("Failed to serialize benchmark history")?;
    if let Some(parent) = history_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    std::fs::write(history_path, content)
        .with_context(|| format!("Failed to write {}", history_path.display()))?;

    Ok(history)
}

fn write_benchmark_dashboard(
    dashboard_path: &Path,
    history: &BenchmarkHistory,
    evaluation: &CorpusEvaluation,
) -> Result<()> {
    if let Some(parent) = dashboard_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    std::fs::write(dashboard_path, render_benchmark_dashboard(history, evaluation))
        .with_context(|| format!("Failed to write {}", dashboard_path.display()))?;
    Ok(())
}

fn write_benchmark_tuning_report(report_path: &Path, evaluation: &CorpusEvaluation) -> Result<()> {
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }
    std::fs::write(report_path, render_benchmark_tuning_report(evaluation))
        .with_context(|| format!("Failed to write {}", report_path.display()))?;
    Ok(())
}

fn render_benchmark_dashboard(history: &BenchmarkHistory, evaluation: &CorpusEvaluation) -> String {
    let mut output = String::new();
    let benign = evaluation
        .samples
        .iter()
        .filter(|sample| sample.verdict == skill_veil_core::Verdict::Benign)
        .count();
    let suspicious = evaluation
        .samples
        .iter()
        .filter(|sample| sample.verdict == skill_veil_core::Verdict::Suspicious)
        .count();
    let malicious = evaluation
        .samples
        .iter()
        .filter(|sample| sample.verdict == skill_veil_core::Verdict::Malicious)
        .count();
    let primary_findings: usize = evaluation
        .samples
        .iter()
        .map(|sample| sample.primary_finding_count)
        .sum();
    let supporting_findings: usize = evaluation
        .samples
        .iter()
        .map(|sample| sample.supporting_finding_count)
        .sum();
    output.push_str("# Benchmark Dashboard\n\n");
    output.push_str("## Current Corpus\n\n");
    output.push_str(&format!(
        "- Samples: {}\n- Precision: {:.2}\n- Recall: {:.2}\n- False positive rate: {:.2}\n- Accuracy: {:.2}\n- Exact label accuracy: {:.2}\n- Deduplicated findings removed: {}\n\n",
        evaluation.coverage.total_samples,
        evaluation.metrics.precision,
        evaluation.metrics.recall,
        evaluation.metrics.false_positive_rate,
        evaluation.metrics.accuracy,
        evaluation.metrics.exact_label_accuracy,
        evaluation.deduplication.duplicates_removed
    ));
    output.push_str(&format!(
        "- Verdicts: benign={} suspicious={} malicious={}\n- Findings by scope: primary={} supporting={}\n\n",
        benign, suspicious, malicious, primary_findings, supporting_findings
    ));

    if !evaluation.coverage.by_label.is_empty() {
        output.push_str("### Coverage by Label\n\n");
        for bucket in &evaluation.coverage.by_label {
            output.push_str(&format!("- `{}`: {}\n", bucket.key, bucket.samples));
        }
        output.push('\n');
    }

    if !evaluation.coverage.by_focus_category.is_empty() {
        output.push_str("### Coverage by Focus Category\n\n");
        for bucket in &evaluation.coverage.by_focus_category {
            output.push_str(&format!("- `{}`: {}\n", bucket.key, bucket.samples));
        }
        output.push('\n');
    }

    if !evaluation.coverage.by_attack_family.is_empty() {
        output.push_str("### Coverage by Attack Family\n\n");
        for bucket in &evaluation.coverage.by_attack_family {
            output.push_str(&format!("- `{}`: {}\n", bucket.key, bucket.samples));
        }
        output.push('\n');
    }

    if !evaluation.family_metrics.is_empty() {
        output.push_str("### Family Metrics\n\n");
        output.push_str("| Family | Samples | Precision | Recall | FPR | Exact Label | Approval | Block |\n");
        output.push_str("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
        for family in &evaluation.family_metrics {
            output.push_str(&format!(
                "| {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {} | {} |\n",
                family.family,
                family.sample_count,
                family.metrics.precision,
                family.metrics.recall,
                family.metrics.false_positive_rate,
                family.metrics.exact_label_accuracy,
                family.threshold_recommendation.recommended_approval_threshold,
                family.threshold_recommendation.recommended_block_threshold,
            ));
        }
        output.push('\n');
    }

    output.push_str("### Threshold Recommendation\n\n");
    output.push_str(&format!(
        "- Approval: {} -> {}\n- Block: {} -> {}\n- Rationale: {}\n\n",
        evaluation.threshold_recommendation.current_approval_threshold,
        evaluation.threshold_recommendation.recommended_approval_threshold,
        evaluation.threshold_recommendation.current_block_threshold,
        evaluation.threshold_recommendation.recommended_block_threshold,
        evaluation.threshold_recommendation.rationale
    ));

    if !evaluation.confidence_calibration.by_signal_pair.is_empty() {
        output.push_str("### Strongest Signal Pairs\n\n");
        for bucket in evaluation
            .confidence_calibration
            .by_signal_pair
            .iter()
            .take(8)
        {
            output.push_str(&format!(
                "- `{}`: findings={} observed_precision={:.2} recommended_confidence={:.2}\n",
                bucket.key, bucket.findings, bucket.observed_precision, bucket.recommended_confidence
            ));
        }
        output.push('\n');
    }

    output.push_str("## Release History\n\n");
    if history.releases.is_empty() {
        output.push_str("_No release history yet._\n");
        return output;
    }

    output.push_str("| Release | Generated | Precision | Recall | FPR | Accuracy | Samples |\n");
    output.push_str("| --- | --- | ---: | ---: | ---: | ---: | ---: |\n");
    for entry in &history.releases {
        output.push_str(&format!(
            "| {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {} |\n",
            entry.release_id,
            entry.generated_at.format("%Y-%m-%d"),
            entry.metrics.precision,
            entry.metrics.recall,
            entry.metrics.false_positive_rate,
            entry.metrics.accuracy,
            entry.coverage.total_samples
        ));
    }

    if history.releases.len() >= 2 {
        let previous = &history.releases[history.releases.len() - 2];
        let current = &history.releases[history.releases.len() - 1];
        output.push_str("\n### Latest Delta\n\n");
        output.push_str(&format!(
            "- Precision delta: {:+.2}\n- Recall delta: {:+.2}\n- FPR delta: {:+.2}\n- Accuracy delta: {:+.2}\n",
            current.metrics.precision - previous.metrics.precision,
            current.metrics.recall - previous.metrics.recall,
            current.metrics.false_positive_rate - previous.metrics.false_positive_rate,
            current.metrics.accuracy - previous.metrics.accuracy
        ));
    }

    output
}

fn render_benchmark_tuning_report(evaluation: &CorpusEvaluation) -> String {
    let mut output = String::new();
    output.push_str("# Benchmark Tuning Report\n\n");
    output.push_str("## Global Recommendation\n\n");
    output.push_str(&format!(
        "- Approval threshold: {} -> {}\n- Block threshold: {} -> {}\n- Rationale: {}\n\n",
        evaluation.threshold_recommendation.current_approval_threshold,
        evaluation.threshold_recommendation.recommended_approval_threshold,
        evaluation.threshold_recommendation.current_block_threshold,
        evaluation.threshold_recommendation.recommended_block_threshold,
        evaluation.threshold_recommendation.rationale
    ));

    if !evaluation.family_metrics.is_empty() {
        output.push_str("## Family Recommendations\n\n");
        output.push_str("| Family | Samples | Precision | Recall | FPR | Exact Label | Approval | Block |\n");
        output.push_str("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n");
        for family in &evaluation.family_metrics {
            output.push_str(&format!(
                "| {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {} | {} |\n",
                family.family,
                family.sample_count,
                family.metrics.precision,
                family.metrics.recall,
                family.metrics.false_positive_rate,
                family.metrics.exact_label_accuracy,
                family.threshold_recommendation.recommended_approval_threshold,
                family.threshold_recommendation.recommended_block_threshold,
            ));
        }
        output.push('\n');
        for family in &evaluation.family_metrics {
            output.push_str(&format!("### {}\n\n", family.family));
            output.push_str(&format!(
                "- Samples: {}\n- Precision: {:.2}\n- Recall: {:.2}\n- False positive rate: {:.2}\n- Exact label accuracy: {:.2}\n- Recommended thresholds: approval {} block {}\n- Rationale: {}\n\n",
                family.sample_count,
                family.metrics.precision,
                family.metrics.recall,
                family.metrics.false_positive_rate,
                family.metrics.exact_label_accuracy,
                family.threshold_recommendation.recommended_approval_threshold,
                family.threshold_recommendation.recommended_block_threshold,
                family.threshold_recommendation.rationale
            ));
        }
    }

    output
}

fn run_baseline_create(args: BaselineCreateArgs) -> Result<()> {
    let reports = load_json_reports(&args.report)?;
    let baseline = baseline_from_reports(&reports);
    let content =
        serde_json::to_string_pretty(&baseline).context("Failed to serialize baseline")?;
    std::fs::write(&args.output, content).context("Failed to write baseline file")?;
    Ok(())
}

fn run_baseline_update(args: BaselineUpdateArgs) -> Result<()> {
    let reports = load_json_reports(&args.report)?;
    let existing = load_baseline(&args.baseline).context("Failed to load baseline file")?;
    let current = baseline_from_reports(&reports);

    let existing_map: std::collections::BTreeMap<_, _> = existing
        .entries
        .into_iter()
        .map(|entry| (entry.fingerprint.clone(), entry))
        .collect();
    let current_map: std::collections::BTreeMap<_, _> = current
        .entries
        .into_iter()
        .map(|entry| (entry.fingerprint.clone(), entry))
        .collect();

    let new_entries: Vec<_> = current_map
        .iter()
        .filter(|(fingerprint, _)| !existing_map.contains_key(*fingerprint))
        .map(|(_, entry)| entry.clone())
        .collect();

    if !new_entries.is_empty() && !args.allow_new_findings {
        anyhow::bail!(
            "Baseline update would add {} new finding(s). Re-run with --allow-new-findings to accept them.",
            new_entries.len()
        );
    }

    let merged_entries: Vec<BaselineEntry> = current_map.into_values().collect();
    let updated = BaselineFile {
        schema_version: POLICY_SCHEMA_VERSION.to_string(),
        entries: merged_entries,
    };
    let content =
        serde_json::to_string_pretty(&updated).context("Failed to serialize updated baseline")?;
    std::fs::write(&args.output, content).context("Failed to write updated baseline file")?;
    Ok(())
}

fn run_waivers_validate(args: WaiversValidateArgs) -> Result<()> {
    let waivers = load_waivers(&args.path).context("Failed to load waivers file")?;
    validate_waivers(&waivers).map_err(anyhow::Error::msg)?;
    println!("Waivers file is valid");
    Ok(())
}

fn run_policy_validate(args: PolicyValidateArgs) -> Result<()> {
    let content = std::fs::read_to_string(&args.path)
        .with_context(|| format!("Failed to read {}", args.path.display()))?;
    let policy: skill_veil_core::PolicyFile = serde_json::from_str(&content)
        .or_else(|_| serde_yaml::from_str(&content))
        .with_context(|| format!("Failed to parse {}", args.path.display()))?;
    validate_policy(&policy).map_err(anyhow::Error::msg)?;
    println!("Policy file is valid");
    Ok(())
}

fn run_diff(args: DiffArgs) -> Result<()> {
    let previous = load_json_reports(&args.previous)?;
    let current = load_json_reports(&args.current)?;
    let baseline = args
        .baseline
        .as_ref()
        .map(|path| load_baseline(path))
        .transpose()
        .context("Failed to load baseline file")?;
    let waivers = args
        .waivers
        .as_ref()
        .map(|path| load_waivers(path))
        .transpose()
        .context("Failed to load waivers file")?;
    let diff = diff_reports_with_policy_state(
        &previous,
        &current,
        baseline.as_ref(),
        waivers.as_ref(),
    );

    let output = match args.format {
        OutputFormat::Text => {
            if args.ci_summary {
                format_diff_ci_summary(&diff)
            } else {
                format_diff_text(&diff)
            }
        }
        OutputFormat::Json => {
            serde_json::to_string_pretty(&diff).context("Failed to serialize diff")?
        }
        OutputFormat::Sarif | OutputFormat::Shield => {
            anyhow::bail!("Diff only supports text or json output")
        }
    };

    print!("{}", output);
    if let Some(policy) = args.fail_on {
        match policy {
            DiffFailPolicyArg::NewActive if !diff.new_findings.is_empty() => {
                anyhow::bail!(
                    "Detected {} new active finding(s) in diff",
                    diff.new_findings.len()
                );
            }
            DiffFailPolicyArg::NewBlocking => {
                let has_new_blocking = current.iter().flat_map(|report| report.findings.iter()).any(|finding| {
                    diff.new_findings
                        .iter()
                        .any(|entry| entry.fingerprint == skill_veil_core::policy::finding_fingerprint(finding))
                        && finding.recommended_action == RecommendedAction::Block
                });
                if has_new_blocking {
                    anyhow::bail!("Detected new blocking findings in diff");
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn load_json_reports(path: &PathBuf) -> Result<Vec<JsonReport>> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON report {}", path.display()))
}

// ============================================================================
// Output formatting functions
// ============================================================================

#[derive(Copy, Clone, Default)]
struct TextOutputOptions {
    quiet_summary: bool,
    explain_policy: bool,
    finding_limit: Option<usize>,
}

/// Format results as human-readable text output
fn format_text_output(results: &[ScanResult], options: TextOutputOptions) -> String {
    let mut output = String::new();

    for result in results {
        output.push_str(&format!("\n=== {} ===\n", result.path.display()));
        if let Some(package_id) = &result.package_id {
            output.push_str(&format!("Package ID: {}\n", package_id));
        }
        output.push_str(&format!("Verdict: {}\n", result.verdict));
        output.push_str(&format!(
            "Package Health: {} (hygiene/posture, independent from verdict)\n",
            result.verdict_report.package_health
        ));
        output.push_str(&format!("Heuristic Score: {}\n", result.heuristic_score));
        output.push_str(&format!(
            "Package Risk: {} | Action: {}\n",
            result.summary.risk_score, result.summary.recommended_action
        ));
        output.push_str(&format!(
            "Primary Risk: {} | Action: {}\n",
            result.primary_summary.risk_score, result.primary_summary.recommended_action
        ));
        output.push_str(&format!(
            "Supporting Package Risk: {} | Action: {}\n\n",
            result.supporting_summary.risk_score, result.supporting_summary.recommended_action
        ));
        append_verdict_reasons(&mut output, result);

        if options.explain_policy {
            append_policy_reasons(&mut output, result);
            continue;
        }

        if options.quiet_summary {
            append_scope_counts(&mut output, result);
            output.push('\n');
        } else if result.findings.is_empty() {
            output.push_str("  No findings.\n");
        } else {
            append_findings_by_scope(&mut output, result, options.finding_limit);
        }

        append_policy_reasons(&mut output, result);
    }

    append_summary(&mut output, results, options);
    output
}

fn append_verdict_reasons(output: &mut String, result: &ScanResult) {
    if result.verdict_report.verdict_reasons.is_empty() {
        output.push_str("  Why: no strong causal drivers recorded\n\n");
        return;
    }

    output.push_str("  Why:\n");
    for reason in result.verdict_report.verdict_reasons.iter().take(3) {
        output.push_str(&format!(
            "    - {} / {} / {}: {}\n",
            reason.scope, reason.category, reason.signal_class, reason.rationale
        ));
    }

    if !result.verdict_report.root_cause_groups.is_empty() {
        output.push_str("  Root causes:\n");
        for group in result.verdict_report.root_cause_groups.iter().take(3) {
            output.push_str(&format!(
                "    - {} / {} / {} => {} finding(s), strongest action {}\n",
                group.scope,
                group.category,
                group.signal_class,
                group.finding_count,
                group.strongest_action
            ));
        }
    }

    if result.verdict_report.hygiene_summary.package_root_findings > 0
        || result.verdict_report.hygiene_summary.supporting_findings > 0
    {
        output.push_str(&format!(
            "  Package hygiene: package_root={} supporting={} top_rules={}\n",
            result.verdict_report.hygiene_summary.package_root_findings,
            result.verdict_report.hygiene_summary.supporting_findings,
            if result.verdict_report.hygiene_summary.top_rules.is_empty() {
                "none".to_string()
            } else {
                result.verdict_report.hygiene_summary.top_rules.join(",")
            }
        ));
    }

    if !result.verdict_report.declared_permissions.is_empty() {
        output.push_str(&format!(
            "  Declared permissions: {}\n",
            result
                .verdict_report
                .declared_permissions
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    if let Some(level) = result.verdict_report.blast_radius_summary.level {
        output.push_str(&format!("  Blast radius: {}\n", level));
        if !result.verdict_report.blast_radius_summary.factors.is_empty() {
            output.push_str(&format!(
                "  Blast factors: {}\n",
                result.verdict_report.blast_radius_summary.factors.join(",")
            ));
        }
        if !result
            .verdict_report
            .blast_radius_summary
            .network_targets
            .is_empty()
        {
            output.push_str(&format!(
                "  Network targets: {}\n",
                result
                    .verdict_report
                    .blast_radius_summary
                    .network_targets
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
    }

    output.push('\n');
}

fn append_scope_counts(output: &mut String, result: &ScanResult) {
    output.push_str(&format!(
        "  Primary findings: {}\n",
        result.primary_findings.len()
    ));
    output.push_str(&format!(
        "  Supporting findings: {}\n",
        result.supporting_findings.len()
    ));
    output.push_str(&format!("  Total findings: {}\n", result.findings.len()));
}

fn append_findings_by_scope(output: &mut String, result: &ScanResult, finding_limit: Option<usize>) {
    append_scope_counts(output, result);
    output.push('\n');

    if result.primary_findings.is_empty() {
        output.push_str("  Main artifact findings: none\n\n");
    } else {
        output.push_str("  Main artifact findings:\n");
        append_findings(output, &result.primary_findings, finding_limit);
    }

    if result.supporting_findings.is_empty() {
        output.push_str("  Supporting artifact findings: none\n\n");
    } else {
        output.push_str("  Supporting artifact findings:\n");
        append_findings(output, &result.supporting_findings, finding_limit);
    }
}

fn append_findings(
    output: &mut String,
    findings: &[skill_veil_core::Finding],
    finding_limit: Option<usize>,
) {
    let display_limit = finding_limit.unwrap_or(findings.len());
    for finding in findings.iter().take(display_limit) {
        let severity_icon = match finding.severity {
            Severity::Critical => "[CRIT]",
            Severity::High => "[HIGH]",
            Severity::Medium => "[MED] ",
            Severity::Low => "[LOW] ",
        };

        output.push_str(&format!(
            "  {} {} ({})\n",
            severity_icon, finding.rule_id, finding.category
        ));
        output.push_str(&format!("      {}\n", finding.reason));
        output.push_str(&format!("      Remediation: {}\n", finding.remediation));
        output.push_str(&format!("      Match: \"{}\"\n", finding.match_value));
        output.push_str(&format!("      Evidence: {}\n", finding.evidence_kind));
        output.push_str(&format!("      Action: {}\n", finding.recommended_action));
        output.push_str(&format!("      Artifact: {}", finding.artifact_kind));
        if let Some(path) = &finding.artifact_path {
            output.push_str(&format!(" ({})", path));
        }
        output.push('\n');
        if let Some(line) = finding.line_number {
            output.push_str(&format!("      Line: {}\n", line));
        }
        output.push('\n');
    }
    if findings.len() > display_limit {
        output.push_str(&format!(
            "      ... {} more finding(s) omitted\n\n",
            findings.len() - display_limit
        ));
    }
}

fn append_policy_reasons(output: &mut String, result: &ScanResult) {
    let report = result.to_json_report();
    output.push_str("  Policy precedence:\n");
    for stage in &report.policy_audit.precedence_order {
        output.push_str(&format!("    - {}\n", stage));
    }

    if result.summary.action_triggers.is_empty() {
        output.push_str("  No policy escalation reasons.\n");
    } else {
        output.push_str("  Policy escalation reasons:\n");
        for trigger in &result.summary.action_triggers {
            output.push_str(&format!(
                "    - {} via {}: {}\n",
                trigger.action, trigger.factor, trigger.rationale
            ));
        }
    }

    if !report.context_policies.is_empty() {
        output.push_str("  Context policies:\n");
        for policy in &report.context_policies {
            output.push_str(&format!(
                "    - {} => {}\n",
                serde_json::to_string(&policy.context)
                    .unwrap_or_else(|_| "\"unknown\"".to_string())
                    .trim_matches('"'),
                policy.action
            ));
        }
    }

    if !report.policy_audit.applied_overrides.is_empty() {
        output.push_str("  Applied overrides:\n");
        for applied in &report.policy_audit.applied_overrides {
            output.push_str(&format!(
                "    - {}: {} -> {} ({})\n",
                applied.rule_id, applied.original_action, applied.effective_action, applied.reason
            ));
        }
    }

    if let Some(fail_on) = report.policy_audit.effective_fail_on {
        output.push_str(&format!("  Effective fail_on: {}\n", fail_on));
    }

    if report.suppression_summary.baseline_suppressed > 0
        || report.suppression_summary.waiver_suppressed > 0
    {
        output.push_str(&format!(
            "  Suppressed findings: baseline={} waiver={}\n",
            report.suppression_summary.baseline_suppressed,
            report.suppression_summary.waiver_suppressed
        ));
    }

    output.push('\n');
}

fn append_summary(output: &mut String, results: &[ScanResult], options: TextOutputOptions) {
    let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
    let critical: usize = results.iter().map(|r| r.summary.by_severity.critical).sum();
    let high: usize = results.iter().map(|r| r.summary.by_severity.high).sum();
    let medium: usize = results.iter().map(|r| r.summary.by_severity.medium).sum();
    let low: usize = results.iter().map(|r| r.summary.by_severity.low).sum();
    let total_baseline_suppressed: usize = results
        .iter()
        .map(|r| r.suppression_summary.baseline_suppressed)
        .sum();
    let total_waiver_suppressed: usize = results
        .iter()
        .map(|r| r.suppression_summary.waiver_suppressed)
        .sum();
    let total_overrides: usize = results
        .iter()
        .map(|r| r.policy_audit.applied_overrides.len())
        .sum();
    let malicious_verdicts = results
        .iter()
        .filter(|r| r.verdict == skill_veil_core::Verdict::Malicious)
        .count();
    let suspicious_verdicts = results
        .iter()
        .filter(|r| r.verdict == skill_veil_core::Verdict::Suspicious)
        .count();
    let benign_verdicts = results
        .iter()
        .filter(|r| r.verdict == skill_veil_core::Verdict::Benign)
        .count();

    output.push_str(&format!(
        "\n--- Summary ---\nFiles scanned: {}\nVerdicts: benign={} suspicious={} malicious={}\nTotal findings: {} (Critical: {}, High: {}, Medium: {}, Low: {})\n",
        results.len(),
        benign_verdicts,
        suspicious_verdicts,
        malicious_verdicts,
        total_findings,
        critical,
        high,
        medium,
        low
    ));
    if total_baseline_suppressed > 0 || total_waiver_suppressed > 0 {
        output.push_str(&format!(
            "Suppressed findings: baseline={} waiver={}\n",
            total_baseline_suppressed, total_waiver_suppressed
        ));
    }
    if total_overrides > 0 {
        output.push_str(&format!("Applied overrides: {}\n", total_overrides));
    }

    if options.explain_policy {
        let final_action = results.iter().fold(RecommendedAction::Log, |current, result| {
            skill_veil_core::RecommendedAction::max(current, result.summary.recommended_action)
        });
        output.push_str(&format!("Final recommended action: {}\n", final_action));
    }

    let mut factor_totals = std::collections::BTreeMap::new();
    for result in results {
        for factor in &result.summary.score_breakdown {
            *factor_totals.entry(factor.factor.clone()).or_insert(0_u32) += factor.contribution;
        }
    }

    if !options.explain_policy && !factor_totals.is_empty() {
        output.push_str("Top score factors:\n");
        let mut ranked_factors: Vec<_> = factor_totals.into_iter().collect();
        ranked_factors.sort_by(|left, right| right.1.cmp(&left.1));
        for (factor, contribution) in ranked_factors.into_iter().take(5) {
            output.push_str(&format!("  - {} ({})\n", factor, contribution));
        }
    }

    let mut trigger_counts = std::collections::BTreeMap::new();
    for result in results {
        for trigger in &result.summary.action_triggers {
            *trigger_counts.entry(trigger.factor.clone()).or_insert(0_usize) += 1;
        }
    }

    if !trigger_counts.is_empty() {
        output.push_str("Policy escalation triggers:\n");
        let mut ranked_triggers: Vec<_> = trigger_counts.into_iter().collect();
        ranked_triggers.sort_by(|left, right| right.1.cmp(&left.1));
        for (factor, count) in ranked_triggers.into_iter().take(5) {
            output.push_str(&format!("  - {} ({} file(s))\n", factor, count));
        }
    }

    let mut context_counts = std::collections::BTreeMap::new();
    for result in results {
        for policy in &result.to_json_report().context_policies {
            *context_counts
                .entry(
                    serde_json::to_string(&policy.context)
                        .unwrap_or_else(|_| "\"unknown\"".to_string())
                        .trim_matches('"')
                        .to_string(),
                )
                .or_insert(0_usize) += 1;
        }
    }
    if !context_counts.is_empty() {
        output.push_str("Context coverage:\n");
        for (context, count) in context_counts {
            output.push_str(&format!("  - {} ({} file(s))\n", context, count));
        }
    }
}

fn format_benchmark_text(evaluation: &CorpusEvaluation) -> String {
    let mut output = String::new();
    let benign = evaluation
        .samples
        .iter()
        .filter(|sample| sample.verdict == skill_veil_core::Verdict::Benign)
        .count();
    let suspicious = evaluation
        .samples
        .iter()
        .filter(|sample| sample.verdict == skill_veil_core::Verdict::Suspicious)
        .count();
    let malicious = evaluation
        .samples
        .iter()
        .filter(|sample| sample.verdict == skill_veil_core::Verdict::Malicious)
        .count();
    let primary_findings: usize = evaluation
        .samples
        .iter()
        .map(|sample| sample.primary_finding_count)
        .sum();
    let supporting_findings: usize = evaluation
        .samples
        .iter()
        .map(|sample| sample.supporting_finding_count)
        .sum();
    output.push_str("--- Benchmark ---\n");
    output.push_str(&format!(
        "Precision: {:.2}\nRecall: {:.2}\nFalse positive rate: {:.2}\nAccuracy: {:.2}\nExact label accuracy: {:.2}\nVerdicts: benign={} suspicious={} malicious={}\nScope findings: primary={} supporting={}\nTP: {} FP: {} TN: {} FN: {}\n",
        evaluation.metrics.precision,
        evaluation.metrics.recall,
        evaluation.metrics.false_positive_rate
        ,
        evaluation.metrics.accuracy,
        evaluation.metrics.exact_label_accuracy,
        benign,
        suspicious,
        malicious,
        primary_findings,
        supporting_findings,
        evaluation.metrics.true_positive,
        evaluation.metrics.false_positive,
        evaluation.metrics.true_negative,
        evaluation.metrics.false_negative
    ));
    output.push_str(&format!("Samples: {}\n", evaluation.coverage.total_samples));
    if !evaluation.coverage.by_label.is_empty() {
        output.push_str("Coverage by label:\n");
        for bucket in &evaluation.coverage.by_label {
            output.push_str(&format!("  - {}={}\n", bucket.key, bucket.samples));
        }
    }
    if !evaluation.coverage.by_focus_category.is_empty() {
        output.push_str("Coverage by focus category:\n");
        for bucket in &evaluation.coverage.by_focus_category {
            output.push_str(&format!("  - {}={}\n", bucket.key, bucket.samples));
        }
    }
    if !evaluation.coverage.by_attack_family.is_empty() {
        output.push_str("Coverage by attack family:\n");
        for bucket in &evaluation.coverage.by_attack_family {
            output.push_str(&format!("  - {}={}\n", bucket.key, bucket.samples));
        }
    }
    if !evaluation.family_metrics.is_empty() {
        output.push_str("Family metrics:\n");
        for family in &evaluation.family_metrics {
            output.push_str(&format!(
                "  - {}: samples={} precision={:.2} recall={:.2} fpr={:.2} exact_label={:.2} thresholds={}→{}\n",
                family.family,
                family.sample_count,
                family.metrics.precision,
                family.metrics.recall,
                family.metrics.false_positive_rate,
                family.metrics.exact_label_accuracy,
                family.threshold_recommendation.recommended_approval_threshold,
                family.threshold_recommendation.recommended_block_threshold,
            ));
        }
    }
    output.push_str(&format!(
        "Deduplication: original={} unique={} removed={}\n",
        evaluation.deduplication.original_findings,
        evaluation.deduplication.unique_findings,
        evaluation.deduplication.duplicates_removed
    ));
    output.push_str(&format!(
        "Threshold recommendation: approval {} -> {} | block {} -> {}\n",
        evaluation.threshold_recommendation.current_approval_threshold,
        evaluation.threshold_recommendation.recommended_approval_threshold,
        evaluation.threshold_recommendation.current_block_threshold,
        evaluation.threshold_recommendation.recommended_block_threshold
    ));
    output.push_str(&format!(
        "Threshold rationale: {}\n",
        evaluation.threshold_recommendation.rationale
    ));
    if !evaluation.confidence_calibration.by_evidence_kind.is_empty() {
        output.push_str("Evidence calibration:\n");
        for bucket in &evaluation.confidence_calibration.by_evidence_kind {
            output.push_str(&format!(
                "  - {} | findings={} observed_precision={:.2} recommended_confidence={:.2}\n",
                bucket.key,
                bucket.findings,
                bucket.observed_precision,
                bucket.recommended_confidence
            ));
        }
    }
    if !evaluation.confidence_calibration.by_signal_pair.is_empty() {
        output.push_str("Signal-pair calibration:\n");
        for bucket in evaluation
            .confidence_calibration
            .by_signal_pair
            .iter()
            .take(6)
        {
            output.push_str(&format!(
                "  - {} | findings={} observed_precision={:.2} recommended_confidence={:.2}\n",
                bucket.key,
                bucket.findings,
                bucket.observed_precision,
                bucket.recommended_confidence
            ));
        }
    }
    output.push('\n');
    output.push_str("Samples:\n");
    for sample in &evaluation.samples {
        output.push_str(&format!(
            "  - {} | expected={} actual={} action={} score={} findings={} dedup_removed={}\n",
            sample.id,
            sample.expected,
            sample.actual,
            sample.recommended_action,
            sample.risk_score,
            sample.finding_count,
            sample.duplicates_removed
        ));
    }
    output
}

fn format_diff_text(diff: &skill_veil_core::DiffReport) -> String {
    let mut output = String::new();
    output.push_str("--- Diff ---\n");
    output.push_str(&format!(
        "New findings: {}\nResolved findings: {}\nWaived findings: {}\nBaselined findings: {}\nUnchanged findings: {}\n",
        diff.new_findings.len(),
        diff.resolved_findings.len(),
        diff.waived_findings.len(),
        diff.baselined_findings.len(),
        diff.unchanged_findings
    ));

    if !diff.new_findings.is_empty() {
        output.push_str("\nNew findings:\n");
        for entry in &diff.new_findings {
            output.push_str(&format!(
                "  - {} {} {}\n",
                entry.rule_id,
                entry.artifact_path.as_deref().unwrap_or("-"),
                entry.reason
            ));
        }
    }

    if !diff.resolved_findings.is_empty() {
        output.push_str("\nResolved findings:\n");
        for entry in &diff.resolved_findings {
            output.push_str(&format!(
                "  - {} {} {}\n",
                entry.rule_id,
                entry.artifact_path.as_deref().unwrap_or("-"),
                entry.reason
            ));
        }
    }

    if !diff.waived_findings.is_empty() {
        output.push_str("\nWaived findings:\n");
        for entry in &diff.waived_findings {
            output.push_str(&format!(
                "  - {} {} {}\n",
                entry.rule_id,
                entry.artifact_path.as_deref().unwrap_or("-"),
                entry.reason
            ));
        }
    }

    if !diff.baselined_findings.is_empty() {
        output.push_str("\nBaselined findings:\n");
        for entry in &diff.baselined_findings {
            output.push_str(&format!(
                "  - {} {} {}\n",
                entry.rule_id,
                entry.artifact_path.as_deref().unwrap_or("-"),
                entry.reason
            ));
        }
    }

    output
}

fn format_diff_ci_summary(diff: &skill_veil_core::DiffReport) -> String {
    format!(
        "DIFF new_active={} resolved={} waived={} baselined={} unchanged={}\n",
        diff.new_findings.len(),
        diff.resolved_findings.len(),
        diff.waived_findings.len(),
        diff.baselined_findings.len(),
        diff.unchanged_findings
    )
}

/// Format results as JSON output for CI integration
fn format_json_output(results: &[ScanResult]) -> Result<String> {
    let reports: Vec<_> = results.iter().map(|r| r.to_json_report()).collect();
    serde_json::to_string_pretty(&reports).context("Failed to serialize JSON")
}

/// Format results as SARIF output for GitHub Code Scanning
fn format_sarif_output(results: &[ScanResult]) -> Result<String> {
    if let Some(first) = results.first() {
        let mut sarif = first.to_sarif_report();

        for result in results.iter().skip(1) {
            let other = result.to_sarif_report();
            if let Some(run) = sarif.runs.first_mut() {
                if let Some(other_run) = other.runs.first() {
                    run.results.extend(other_run.results.clone());
                }
            }
        }

        serde_json::to_string_pretty(&sarif).context("Failed to serialize SARIF")
    } else {
        Ok("{}".to_string())
    }
}

/// Format results as SHIELD.md policy format
fn format_shield_output(results: &[ScanResult]) -> String {
    let mut output = String::new();
    for result in results {
        output.push_str(&result.to_shield_md());
        output.push_str("\n---\n\n");
    }
    output
}

/// Dispatch to the appropriate format handler based on output format
fn format_results(
    results: &[ScanResult],
    format: OutputFormat,
    text_options: TextOutputOptions,
) -> Result<String> {
    match format {
        OutputFormat::Text => Ok(format_text_output(results, text_options)),
        OutputFormat::Json => format_json_output(results),
        OutputFormat::Sarif => format_sarif_output(results),
        OutputFormat::Shield => Ok(format_shield_output(results)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_veil_core::{
        ArtifactCapability, ArtifactCapabilityFact, ArtifactCapabilitySource, ArtifactGraph,
        ArtifactKind, MatchTarget, RecommendedAction, ThreatCategory,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_temp_rules_dir() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("skill-veil-rules-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_format_text_output_includes_policy_escalation_reasons() {
        let findings = vec![skill_veil_core::Finding::builder("TEST_RULE", ThreatCategory::Generic)
            .matched_on(MatchTarget::Document)
            .match_value("note")
            .reason("note")
            .action(RecommendedAction::Log)
            .build()];

        let mut graph = ArtifactGraph::new();
        graph.add_node_with_capabilities(
            "docker-compose.yml",
            ArtifactKind::PackageManifest,
            vec![
                ArtifactCapabilityFact {
                    capability: ArtifactCapability::PrivilegedRuntime,
                    source: ArtifactCapabilitySource::Declared,
                },
                ArtifactCapabilityFact {
                    capability: ArtifactCapability::HostFilesystemAccess,
                    source: ArtifactCapabilitySource::Declared,
                },
            ],
        );

        let summary = skill_veil_core::findings::FindingSummary::from_findings_and_graph(
            &findings,
            &graph,
        );
        let result = ScanResult {
            path: PathBuf::from("SKILL.md"),
            name: "skill".to_string(),
            extension_kind: skill_veil_core::AgentExtensionKind::Skill,
            classification: skill_veil_core::ArtifactClassification::ConfirmedSkill,
            package_id: None,
            identity_source: skill_veil_core::ArtifactIdentitySource::ExplicitName,
            structural_validity: skill_veil_core::StructuralValidity::Confirmed,
            heuristic_score: 0,
            findings: findings.clone(),
            primary_findings: findings,
            supporting_findings: Vec::new(),
            primary_summary: summary.clone(),
            supporting_summary: skill_veil_core::findings::FindingSummary::from_findings(&[]),
            summary,
            verdict: skill_veil_core::Verdict::Malicious,
            verdict_report: skill_veil_core::PackageVerdictReport {
                verdict: skill_veil_core::Verdict::Malicious,
                package_health: skill_veil_core::PackageHealth::Healthy,
                hygiene_summary: skill_veil_core::HygieneSummary::default(),
                declared_permissions: Vec::new(),
                effective_capabilities: Vec::new(),
                blast_radius_summary: skill_veil_core::BlastRadiusSummary::default(),
                verdict_reasons: Vec::new(),
                root_cause_groups: Vec::new(),
                top_risk_drivers: Vec::new(),
            },
            deduplication_summary: Default::default(),
            artifact_graph: graph,
            profile: None,
            policy: None,
            suppression_summary: Default::default(),
            policy_audit: Default::default(),
            should_fail: false,
        };

        let output = format_text_output(&[result], TextOutputOptions::default());

        assert!(output.contains("Policy escalation reasons:"));
        assert!(output.contains("capability_combo:privileged_host_filesystem"));
        assert!(output.contains("Policy escalation triggers:"));
    }

    #[test]
    fn test_format_text_output_quiet_summary_hides_detailed_findings() {
        let findings = vec![skill_veil_core::Finding::builder("TEST_RULE", ThreatCategory::Generic)
            .matched_on(MatchTarget::Document)
            .match_value("note")
            .reason("note")
            .action(RecommendedAction::Log)
            .build()];

        let summary = skill_veil_core::findings::FindingSummary::from_findings(&findings);
        let result = ScanResult {
            path: PathBuf::from("SKILL.md"),
            name: "skill".to_string(),
            extension_kind: skill_veil_core::AgentExtensionKind::Skill,
            classification: skill_veil_core::ArtifactClassification::ConfirmedSkill,
            package_id: None,
            identity_source: skill_veil_core::ArtifactIdentitySource::ExplicitName,
            structural_validity: skill_veil_core::StructuralValidity::Confirmed,
            heuristic_score: 0,
            findings: findings.clone(),
            primary_findings: findings,
            supporting_findings: Vec::new(),
            primary_summary: summary.clone(),
            supporting_summary: skill_veil_core::findings::FindingSummary::from_findings(&[]),
            summary,
            verdict: skill_veil_core::Verdict::Benign,
            verdict_report: skill_veil_core::PackageVerdictReport {
                verdict: skill_veil_core::Verdict::Benign,
                package_health: skill_veil_core::PackageHealth::Healthy,
                hygiene_summary: skill_veil_core::HygieneSummary::default(),
                declared_permissions: Vec::new(),
                effective_capabilities: Vec::new(),
                blast_radius_summary: skill_veil_core::BlastRadiusSummary::default(),
                verdict_reasons: Vec::new(),
                root_cause_groups: Vec::new(),
                top_risk_drivers: Vec::new(),
            },
            deduplication_summary: Default::default(),
            artifact_graph: ArtifactGraph::new(),
            profile: None,
            policy: None,
            suppression_summary: Default::default(),
            policy_audit: Default::default(),
            should_fail: false,
        };

        let output = format_text_output(
            &[result],
            TextOutputOptions {
                quiet_summary: true,
                explain_policy: false,
                finding_limit: None,
            },
        );

        assert!(output.contains("Primary findings: 1"));
        assert!(output.contains("Supporting findings: 0"));
        assert!(output.contains("Total findings: 1"));
        assert!(!output.contains("Match: \"note\""));
    }

    #[test]
    fn test_format_text_output_explain_policy_focuses_on_policy_section() {
        let findings = vec![skill_veil_core::Finding::builder("TEST_RULE", ThreatCategory::Generic)
            .matched_on(MatchTarget::Document)
            .match_value("note")
            .reason("note")
            .action(RecommendedAction::Log)
            .build()];

        let mut graph = ArtifactGraph::new();
        graph.add_node_with_capabilities(
            "docker-compose.yml",
            ArtifactKind::PackageManifest,
            vec![
                ArtifactCapabilityFact {
                    capability: ArtifactCapability::PrivilegedRuntime,
                    source: ArtifactCapabilitySource::Declared,
                },
                ArtifactCapabilityFact {
                    capability: ArtifactCapability::HostFilesystemAccess,
                    source: ArtifactCapabilitySource::Declared,
                },
            ],
        );

        let summary = skill_veil_core::findings::FindingSummary::from_findings_and_graph(
            &findings,
            &graph,
        );
        let result = ScanResult {
            path: PathBuf::from("SKILL.md"),
            name: "skill".to_string(),
            extension_kind: skill_veil_core::AgentExtensionKind::Skill,
            classification: skill_veil_core::ArtifactClassification::ConfirmedSkill,
            package_id: None,
            identity_source: skill_veil_core::ArtifactIdentitySource::ExplicitName,
            structural_validity: skill_veil_core::StructuralValidity::Confirmed,
            heuristic_score: 0,
            findings: findings.clone(),
            primary_findings: findings,
            supporting_findings: Vec::new(),
            primary_summary: summary.clone(),
            supporting_summary: skill_veil_core::findings::FindingSummary::from_findings(&[]),
            summary,
            verdict: skill_veil_core::Verdict::Malicious,
            verdict_report: skill_veil_core::PackageVerdictReport {
                verdict: skill_veil_core::Verdict::Malicious,
                package_health: skill_veil_core::PackageHealth::Healthy,
                hygiene_summary: skill_veil_core::HygieneSummary::default(),
                declared_permissions: Vec::new(),
                effective_capabilities: Vec::new(),
                blast_radius_summary: skill_veil_core::BlastRadiusSummary::default(),
                verdict_reasons: Vec::new(),
                root_cause_groups: Vec::new(),
                top_risk_drivers: Vec::new(),
            },
            deduplication_summary: Default::default(),
            artifact_graph: graph,
            profile: None,
            policy: None,
            suppression_summary: Default::default(),
            policy_audit: Default::default(),
            should_fail: false,
        };

        let output = format_text_output(
            &[result],
            TextOutputOptions {
                quiet_summary: false,
                explain_policy: true,
                finding_limit: None,
            },
        );

        assert!(output.contains("Final recommended action: block"));
        assert!(output.contains("Policy escalation reasons:"));
        assert!(!output.contains("Match: \"note\""));
        assert!(!output.contains("Top score factors:"));
    }

    #[test]
    fn test_format_diff_ci_summary_is_compact() {
        let diff = skill_veil_core::DiffReport {
            new_findings: vec![skill_veil_core::DiffEntry {
                fingerprint: "a".to_string(),
                rule_id: "NEW_RULE".to_string(),
                artifact_path: Some("SKILL.md".to_string()),
                reason: "new".to_string(),
            }],
            resolved_findings: vec![skill_veil_core::DiffEntry {
                fingerprint: "b".to_string(),
                rule_id: "OLD_RULE".to_string(),
                artifact_path: None,
                reason: "old".to_string(),
            }],
            waived_findings: vec![skill_veil_core::DiffEntry {
                fingerprint: "c".to_string(),
                rule_id: "WAIVE_RULE".to_string(),
                artifact_path: None,
                reason: "waived".to_string(),
            }],
            baselined_findings: vec![skill_veil_core::DiffEntry {
                fingerprint: "d".to_string(),
                rule_id: "BASE_RULE".to_string(),
                artifact_path: None,
                reason: "baselined".to_string(),
            }],
            unchanged_findings: 3,
        };

        let output = format_diff_ci_summary(&diff);
        assert_eq!(
            output,
            "DIFF new_active=1 resolved=1 waived=1 baselined=1 unchanged=3\n"
        );
    }

    #[test]
    fn test_validate_rule_pack_reports_duplicates() {
        let dir = make_temp_rules_dir();
        fs::write(
            dir.join("rules.yaml"),
            r#"
schema_version: skill-veil.dev/rules/v1alpha1
metadata:
  name: duplicate-pack
  kind: official
  compatibility:
    - skill-veil.dev/rules/v1alpha1
rules:
  - id: DUP_RULE
    category: generic
    severity: medium
    confidence: 0.8
    when: !regex
      pattern: "dup"
    action: require_approval
    reason: "dup 1"
  - id: DUP_RULE
    category: generic
    severity: medium
    confidence: 0.8
    when: !regex
      pattern: "dup"
    action: require_approval
    reason: "dup 2"
"#,
        )
        .unwrap();

        let report = validate_rule_pack(&dir).unwrap();
        assert!(!report.valid);
        assert_eq!(report.duplicate_rule_ids, vec!["DUP_RULE".to_string()]);
    }

    #[test]
    fn test_build_rule_pack_info_summarizes_rules() {
        let dir = make_temp_rules_dir();
        fs::write(
            dir.join("rules.yaml"),
            r#"
schema_version: skill-veil.dev/rules/v1alpha1
metadata:
  name: info-pack
  kind: community
  compatibility:
    - skill-veil.dev/rules/v1alpha1
rules:
  - id: INFO_RULE
    category: tool_abuse
    severity: high
    confidence: 0.9
    when: !regex
      pattern: "tool"
    action: block
    reason: "tool"
    tags: ["official_pack", "tooling"]
"#,
        )
        .unwrap();

        let info = build_rule_pack_info(&dir).unwrap();
        assert_eq!(info.total_rules, 1);
        assert_eq!(info.enabled_rules, 1);
        assert_eq!(info.pack_files, 1);
        assert!(info.pack_names.contains("info-pack"));
        assert!(info.pack_kinds.contains("community"));
        assert_eq!(info.by_category.get("tool_abuse"), Some(&1));
        assert!(info.tags.contains("official_pack"));
    }

    #[test]
    fn test_validate_fixture_case_checks_full_expectations() {
        let findings = vec![skill_veil_core::Finding::builder(
            "TEST_RULE",
            ThreatCategory::ToolAbuse,
        )
        .severity(Severity::High)
        .action(RecommendedAction::RequireApproval)
        .matched_on(MatchTarget::Document)
        .match_value("extract cookies")
        .reason("tool abuse")
        .build()];
        let case = RuleFixtureCase {
            name: "case".to_string(),
            rule_id: "TEST_RULE".to_string(),
            content: "# Skill".to_string(),
            expect_match: Some(true),
            expected_count: Some(1),
            expected_severity: Some(Severity::High),
            expected_action: Some(RecommendedAction::RequireApproval),
            expected_category: Some("tool_abuse".to_string()),
        };

        validate_fixture_case(&case, &findings).unwrap();
    }

    #[test]
    fn test_update_benchmark_history_replaces_same_release() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let history_path = std::env::temp_dir().join(format!("skill-veil-history-{unique}.json"));

        let evaluation = CorpusEvaluation {
            metrics: skill_veil_core::RegressionMetrics {
                precision: 1.0,
                recall: 1.0,
                false_positive_rate: 0.0,
                accuracy: 1.0,
                exact_label_accuracy: 1.0,
                true_positive: 1,
                false_positive: 0,
                true_negative: 1,
                false_negative: 0,
            },
            coverage: skill_veil_core::CorpusCoverage {
                total_samples: 2,
                by_label: vec![
                    skill_veil_core::CoverageBucket {
                        key: "benign".to_string(),
                        samples: 1,
                    },
                    skill_veil_core::CoverageBucket {
                        key: "malicious".to_string(),
                        samples: 1,
                    },
                ],
                by_focus_category: vec![skill_veil_core::CoverageBucket {
                    key: "remote_exec".to_string(),
                    samples: 1,
                }],
                by_attack_family: vec![skill_veil_core::CoverageBucket {
                    key: "remote_exec".to_string(),
                    samples: 1,
                }],
            },
            deduplication: skill_veil_core::DeduplicationMetrics {
                original_findings: 2,
                unique_findings: 1,
                duplicates_removed: 1,
            },
            confidence_calibration: Default::default(),
            threshold_recommendation: skill_veil_core::ThresholdRecommendation {
                current_approval_threshold: 20,
                current_block_threshold: 50,
                recommended_approval_threshold: 25,
                recommended_block_threshold: 55,
                current_metrics: skill_veil_core::RegressionMetrics {
                    precision: 0.9,
                    recall: 1.0,
                    false_positive_rate: 0.1,
                    accuracy: 0.95,
                    exact_label_accuracy: 0.95,
                    true_positive: 2,
                    false_positive: 1,
                    true_negative: 8,
                    false_negative: 0,
                },
                recommended_metrics: skill_veil_core::RegressionMetrics {
                    precision: 1.0,
                    recall: 1.0,
                    false_positive_rate: 0.0,
                    accuracy: 1.0,
                    exact_label_accuracy: 1.0,
                    true_positive: 2,
                    false_positive: 0,
                    true_negative: 9,
                    false_negative: 0,
                },
                rationale: "thresholds tuned".to_string(),
            },
            family_metrics: vec![skill_veil_core::AttackFamilyMetrics {
                family: "remote_exec".to_string(),
                sample_count: 1,
                metrics: skill_veil_core::RegressionMetrics {
                    precision: 1.0,
                    recall: 1.0,
                    false_positive_rate: 0.0,
                    accuracy: 1.0,
                    exact_label_accuracy: 1.0,
                    true_positive: 1,
                    false_positive: 0,
                    true_negative: 0,
                    false_negative: 0,
                },
                threshold_recommendation: skill_veil_core::ThresholdRecommendation {
                    current_approval_threshold: 20,
                    current_block_threshold: 50,
                    recommended_approval_threshold: 24,
                    recommended_block_threshold: 54,
                    current_metrics: skill_veil_core::RegressionMetrics {
                        precision: 1.0,
                        recall: 1.0,
                        false_positive_rate: 0.0,
                        accuracy: 1.0,
                        exact_label_accuracy: 1.0,
                        true_positive: 1,
                        false_positive: 0,
                        true_negative: 0,
                        false_negative: 0,
                    },
                    recommended_metrics: skill_veil_core::RegressionMetrics {
                        precision: 1.0,
                        recall: 1.0,
                        false_positive_rate: 0.0,
                        accuracy: 1.0,
                        exact_label_accuracy: 1.0,
                        true_positive: 1,
                        false_positive: 0,
                        true_negative: 0,
                        false_negative: 0,
                    },
                    rationale: "family thresholds tuned".to_string(),
                },
            }],
            samples: Vec::new(),
        };

        update_benchmark_history(&history_path, "v0.1.0", &evaluation).unwrap();
        update_benchmark_history(&history_path, "v0.1.0", &evaluation).unwrap();

        let content = fs::read_to_string(&history_path).unwrap();
        let history: BenchmarkHistory = serde_json::from_str(&content).unwrap();
        assert_eq!(history.releases.len(), 1);
        assert_eq!(history.releases[0].coverage.total_samples, 2);
        assert!(!render_benchmark_dashboard(&history, &evaluation).is_empty());

        let _ = fs::remove_file(history_path);
    }

    #[test]
    fn test_format_dataset_verdicts_text_analyst_summary_is_compact() {
        let entry = DatasetPackageVerdictEntry {
            package_id: Some("abc123".to_string()),
            final_verdict: skill_veil_core::Verdict::Suspicious,
            package_health: Some(skill_veil_core::PackageHealth::NeedsReview),
            blast_radius: Some(skill_veil_core::BlastRadiusLevel::High),
            declared_permissions: vec![
                skill_veil_core::DeclaredPermission::NetworkAccess,
                skill_veil_core::DeclaredPermission::SecretsAccess,
            ],
            strongest_reason: Some(
                "supporting_artifact/remote_exec/malicious_behavior".to_string(),
            ),
            top_rule: Some("UNSAFE_USER_CONTROLLED_EXEC_SHELL".to_string()),
            representative_path: "dataset/pkg/SKILL.md".to_string(),
            main_summary: Vec::new(),
            supporting_summary: vec!["remote_exec/malicious_behavior".to_string()],
            package_root_summary: Vec::new(),
        };

        let output = format_dataset_verdicts_text(&[entry], true);

        assert!(output.contains("[suspicious] package=abc123"));
        assert!(output.contains("scope=supporting_artifact"));
        assert!(output.contains("rule=UNSAFE_USER_CONTROLLED_EXEC_SHELL"));
        assert!(output.contains("blast=high"));
        assert!(output.contains("perms=network_access,secrets_access"));
        assert!(output.contains("reason=supporting_artifact/remote_exec/malicious_behavior"));
        assert!(!output.contains("health="));
        assert!(!output.contains("main="));
    }

    #[test]
    fn test_format_dataset_verdicts_text_full_includes_detailed_fields() {
        let entry = DatasetPackageVerdictEntry {
            package_id: Some("pkg001".to_string()),
            final_verdict: skill_veil_core::Verdict::Malicious,
            package_health: Some(skill_veil_core::PackageHealth::Healthy),
            blast_radius: Some(skill_veil_core::BlastRadiusLevel::Medium),
            declared_permissions: vec![skill_veil_core::DeclaredPermission::ShellExec],
            strongest_reason: Some("agent_entrypoint/remote_exec/malicious_behavior".to_string()),
            top_rule: Some("SKILL_REMOTE_EXEC_CURL_BASH".to_string()),
            representative_path: "dataset/pkg001/SKILL.md".to_string(),
            main_summary: vec!["remote_exec/malicious_behavior".to_string()],
            supporting_summary: Vec::new(),
            package_root_summary: Vec::new(),
        };

        let output = format_dataset_verdicts_text(&[entry], false);

        assert!(output.contains("malicious package=pkg001"));
        assert!(output.contains("health=healthy"));
        assert!(output.contains("blast_radius=medium"));
        assert!(output.contains("declared_permissions=shell_exec"));
        assert!(output.contains("main=remote_exec/malicious_behavior"));
    }
}
