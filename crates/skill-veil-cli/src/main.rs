//! skill-veil CLI
//!
//! Behavioral & Supply-Chain Security Analysis for Agent Skills

mod benchmark_output;
mod cli_args;
mod color;
mod commands;
mod config;
mod dataset;
mod llm;
mod rule_tools;
mod text_output;
mod vt;

use crate::cli_args::{
    BaselineAction, Cli, Commands, PolicyAction, PolicyProfileArg, RecommendedActionArg,
    SeverityArg, WaiversAction,
};
use anyhow::Result;
use clap::Parser;
use dataset::run_scan_dataset;
use skill_veil_core::{PolicyProfile, RecommendedAction, ScanTargetMode, Severity};
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
        Commands::Scan(args) => {
            if commands::run_scan(args, ScanTargetMode::Auto, cli.quiet, cli.color)? {
                #[allow(clippy::exit)]
                std::process::exit(1);
            }
        }
        Commands::ScanFile(args) => {
            if commands::run_scan(args, ScanTargetMode::File, cli.quiet, cli.color)? {
                #[allow(clippy::exit)]
                std::process::exit(1);
            }
        }
        Commands::ScanPackage(args) => {
            if commands::run_scan(args, ScanTargetMode::Package, cli.quiet, cli.color)? {
                #[allow(clippy::exit)]
                std::process::exit(1);
            }
        }
        Commands::ScanDataset(args) => {
            // Mirror the other scan commands: bubble the failure flag up to
            // main so we exit cleanly *after* tracing/output is flushed.
            if run_scan_dataset(args, cli.quiet, cli.color)? {
                #[allow(clippy::exit)]
                std::process::exit(1);
            }
        }
        Commands::Benchmark(args) => commands::run_benchmark(args)?,
        Commands::Baseline { action } => match action {
            BaselineAction::Create(args) => commands::run_baseline_create(args)?,
            BaselineAction::Update(args) => commands::run_baseline_update(args)?,
        },
        Commands::Diff(args) => commands::run_diff(args, cli.color)?,
        Commands::Waivers { action } => match action {
            WaiversAction::Validate(args) => commands::run_waivers_validate(args)?,
        },
        Commands::Policy { action } => match action {
            PolicyAction::Validate(args) => commands::run_policy_validate(args)?,
        },
        Commands::Rules { action } => commands::run_rules(action)?,
        Commands::Vt { action } => commands::run_vt(action)?,
    }

    Ok(())
}
