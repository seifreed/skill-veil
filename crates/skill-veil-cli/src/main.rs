//! skill-veil CLI
//!
//! Behavioral & Supply-Chain Security Analysis for Agent Skills

mod benchmark_output;
mod cli_args;
mod commands;
mod dataset;
mod rule_tools;
mod text_output;

use crate::cli_args::{
    BaselineAction, Cli, Commands, OutputFormat, PolicyAction, PolicyProfileArg,
    RecommendedActionArg, RulesAction, SeverityArg, WaiversAction,
};
use anyhow::{Context, Result};
use clap::Parser;
use dataset::run_scan_dataset;
use rule_tools::{
    build_rule_pack_info, format_rule_pack_info_text, format_rules_validation_text,
    validate_fixture_case, validate_rules_directory, RuleFixtureCase, RuleFixtureFile,
};
use skill_veil_core::{PolicyProfile, RecommendedAction, ScanTargetMode, Scanner, Severity};
#[cfg(test)]
mod main_tests;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

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
        Commands::Scan(args) => commands::run_scan(args, ScanTargetMode::Auto, cli.quiet)?,
        Commands::ScanFile(args) => commands::run_scan(args, ScanTargetMode::File, cli.quiet)?,
        Commands::ScanPackage(args) => {
            commands::run_scan(args, ScanTargetMode::Package, cli.quiet)?
        }
        Commands::ScanDataset(args) => run_scan_dataset(args, cli.quiet)?,
        Commands::Benchmark(args) => commands::run_benchmark(args)?,
        Commands::Baseline { action } => match action {
            BaselineAction::Create(args) => commands::run_baseline_create(args)?,
            BaselineAction::Update(args) => commands::run_baseline_update(args)?,
        },
        Commands::Diff(args) => commands::run_diff(args)?,
        Commands::Waivers { action } => match action {
            WaiversAction::Validate(args) => commands::run_waivers_validate(args)?,
        },
        Commands::Policy { action } => match action {
            PolicyAction::Validate(args) => commands::run_policy_validate(args)?,
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

                    let engine = commands::load_rule_engine_from_dir(&rules_dir)?;
                    let findings = engine
                        .test_rule(&rule_id, &test_content)
                        .with_context(|| format!("Failed to test rule {}", rule_id))?;
                    let case = RuleFixtureCase {
                        name: Some(rule_id.clone()),
                        rule_id: rule_id.clone(),
                        content: test_content,
                        file_name: None,
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
                RulesAction::TestPack {
                    rules_dir,
                    fixtures,
                } => {
                    let engine = commands::load_rule_engine_from_dir(&rules_dir)?;

                    let fixture_content =
                        std::fs::read_to_string(&fixtures).with_context(|| {
                            format!("Failed to read fixtures {}", fixtures.display())
                        })?;
                    let fixture_pack: RuleFixtureFile = serde_yaml::from_str(&fixture_content)
                        .context("Failed to parse rule fixtures")?;

                    let mut failures = Vec::new();
                    for case in fixture_pack.cases {
                        let findings = engine
                            .test_rule(&case.rule_id, &case.content)
                            .with_context(|| format!("Failed to test rule {}", case.rule_id))?;
                        if let Err(err) = validate_fixture_case(&case, &findings) {
                            failures.push(format!(
                                "{} ({})",
                                case.name.as_deref().unwrap_or(&case.rule_id),
                                err
                            ));
                        }
                    }

                    if failures.is_empty() {
                        println!("All rule fixtures passed");
                    } else {
                        anyhow::bail!("Fixture failures: {}", failures.join(", "));
                    }
                }
                RulesAction::Validate { rules_dir, format } => {
                    let report = validate_rules_directory(&rules_dir)?;
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
