//! skill-veil CLI
//!
//! Behavioral & Supply-Chain Security Analysis for Agent Skills

mod abandoned;
mod benchmark_output;
mod cli_args;
mod color;
mod commands;
mod config;
mod dataset;
mod init;
mod llm;
mod observability;
mod osv;
mod overlap;
mod promptintel;
mod rule_dirs;
mod rule_tools;
#[cfg(feature = "sandbox")]
mod sandbox;
mod text_output;
mod threat_mapping;
mod util;
mod vt;

use crate::cli_args::{
    BaselineAction, Cli, Commands, PolicyAction, PolicyProfileArg, RecommendedActionArg,
    SeverityArg, WaiversAction,
};
use anyhow::Result;
use clap::Parser;
use dataset::run_scan_dataset;
use skill_veil_core::{PolicyProfile, RecommendedAction, ScanTargetMode, Severity};
use std::panic::{self, AssertUnwindSafe};
use std::process::ExitCode;
use std::time::Instant;
use util::terminal_safe::sanitise_for_terminal;
#[cfg(test)]
mod main_tests;

/// Exit code returned when the run produced findings that the configured
/// `fail_on` threshold flagged. CI tooling distinguishes this from a
/// runtime error (`ExitCode::from(2)`) so a failed gate doesn't look the
/// same as a crash.
const EXIT_FINDINGS_OVER_THRESHOLD: u8 = 1;
/// Exit code returned for runtime errors (panics caught at the boundary,
/// I/O failures, malformed config, etc.).
const EXIT_RUNTIME_ERROR: u8 = 2;

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

fn main() -> ExitCode {
    let cli = Cli::parse();
    observability::init(&observability::LogConfig::from_cli(&cli));
    install_panic_logger();
    let operation = operation_name(&cli.command);
    let invocation = tracing::info_span!(
        "command",
        service = "skill-veil",
        component = "cli",
        operation,
        environment = tracing::field::Empty,
        correlation_id = tracing::field::Empty,
    );
    if let Some(environment) = cli.environment.as_deref() {
        invocation.record("environment", tracing::field::display(environment));
    }
    if let Some(correlation_id) = cli.correlation_id.as_deref() {
        invocation.record("correlation_id", tracing::field::display(correlation_id));
    }
    let _entered = invocation.enter();
    tracing::info!(
        event_name = "command.started",
        status = "started",
        "command started"
    );
    let started = Instant::now();
    match panic::catch_unwind(AssertUnwindSafe(|| dispatch(cli))) {
        Ok(Ok(true)) => {
            tracing::warn!(
                event_name = "command.completed",
                status = "findings_over_threshold",
                outcome = "blocked",
                exit_code = EXIT_FINDINGS_OVER_THRESHOLD,
                duration_ms = elapsed_ms(started),
                "command completed with findings over threshold"
            );
            ExitCode::from(EXIT_FINDINGS_OVER_THRESHOLD)
        }
        Ok(Ok(false)) => {
            tracing::info!(
                event_name = "command.completed",
                status = "success",
                outcome = "success",
                exit_code = 0_u8,
                duration_ms = elapsed_ms(started),
                "command completed"
            );
            ExitCode::SUCCESS
        }
        Ok(Err(err)) => {
            tracing::error!(
                event_name = "command.completed",
                status = "error",
                outcome = "failed",
                exit_code = EXIT_RUNTIME_ERROR,
                duration_ms = elapsed_ms(started),
                error_type = "runtime",
                error_code = "SV_RUNTIME_ERROR",
                error = %terminal_error(&err),
                "command failed"
            );
            ExitCode::from(EXIT_RUNTIME_ERROR)
        }
        Err(_) => ExitCode::from(EXIT_RUNTIME_ERROR),
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn install_panic_logger() {
    panic::set_hook(Box::new(|panic_info| {
        let message = panic_info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| {
                panic_info
                    .payload()
                    .downcast_ref::<String>()
                    .map(String::as_str)
            })
            .unwrap_or("non-string panic payload");
        let location = panic_info
            .location()
            .map_or_else(|| "unknown".to_string(), ToString::to_string);
        tracing::error!(
            event_name = "process.panic",
            status = "error",
            outcome = "failed",
            error_type = "panic",
            error_code = "SV_RUNTIME_PANIC",
            location = %sanitise_for_terminal(&location),
            error = %sanitise_for_terminal(message),
            "unhandled panic"
        );
    }));
}

fn operation_name(command: &Commands) -> &'static str {
    match command {
        Commands::Scan(_) => "scan",
        Commands::ScanFile(_) => "scan_file",
        Commands::ScanPackage(_) => "scan_package",
        Commands::ScanDataset(_) => "scan_dataset",
        Commands::Benchmark(_) => "benchmark",
        Commands::Baseline { .. } => "baseline",
        Commands::Diff(_) => "diff",
        Commands::Waivers { .. } => "waivers",
        Commands::Policy { .. } => "policy",
        Commands::Rules { .. } => "rules",
        Commands::Gold { .. } => "gold",
        Commands::Disposition { .. } => "disposition",
        Commands::Vt { .. } => "vt",
        Commands::PromptIntel { .. } => "promptintel",
        Commands::Init(_) => "init",
        Commands::AdjudicationEval(_) => "adjudication_eval",
    }
}

fn terminal_error(err: &anyhow::Error) -> String {
    sanitise_for_terminal(&format!("{err:#}"))
}

/// Dispatch a parsed CLI invocation to the right command handler. The
/// boolean return mirrors the legacy contract: `Ok(true)` means findings
/// crossed the configured threshold (exit code 1), `Ok(false)` is a clean
/// run, and an error becomes exit code 2.
fn dispatch(cli: Cli) -> Result<bool> {
    match cli.command {
        Commands::Scan(args) => {
            commands::run_scan(args, ScanTargetMode::Auto, cli.quiet, cli.color)
        }
        Commands::ScanFile(args) => {
            commands::run_scan(args, ScanTargetMode::File, cli.quiet, cli.color)
        }
        Commands::ScanPackage(args) => {
            commands::run_scan(args, ScanTargetMode::Package, cli.quiet, cli.color)
        }
        Commands::ScanDataset(args) => run_scan_dataset(args, cli.quiet, cli.color),
        Commands::Benchmark(args) => commands::run_benchmark(args).map(|()| false),
        Commands::Baseline { action } => match action {
            BaselineAction::Create(args) => commands::run_baseline_create(args).map(|()| false),
            BaselineAction::Update(args) => commands::run_baseline_update(args).map(|()| false),
        },
        Commands::Diff(args) => commands::run_diff(args, cli.color).map(|()| false),
        Commands::Waivers { action } => match action {
            WaiversAction::Validate(args) => commands::run_waivers_validate(args).map(|()| false),
        },
        Commands::Policy { action } => match action {
            PolicyAction::Validate(args) => commands::run_policy_validate(args).map(|()| false),
        },
        Commands::Rules { action } => commands::run_rules(action).map(|()| false),
        Commands::Gold { action } => commands::run_gold(action).map(|()| false),
        Commands::Disposition { action } => commands::run_disposition(action).map(|()| false),
        Commands::Vt { action } => commands::run_vt(action).map(|()| false),
        Commands::PromptIntel { action } => commands::run_promptintel(action),
        Commands::Init(args) => commands::run_init(args).map(|()| false),
        Commands::AdjudicationEval(args) => commands::run_adjudication_eval(args).map(|()| false),
    }
}
