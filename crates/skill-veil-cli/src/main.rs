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
mod osv;
mod overlap;
mod promptintel;
mod rule_tools;
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
use std::io::{self, Write};
use std::process::ExitCode;
use util::terminal_safe::sanitise_for_terminal;
#[cfg(test)]
mod main_tests;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

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
    init_tracing(cli.quiet, cli.verbose);
    match dispatch(cli) {
        Ok(true) => ExitCode::from(EXIT_FINDINGS_OVER_THRESHOLD),
        Ok(false) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {}", terminal_error(&err));
            ExitCode::from(EXIT_RUNTIME_ERROR)
        }
    }
}

fn terminal_error(err: &anyhow::Error) -> String {
    sanitise_for_terminal(&format!("{err:#}"))
}

fn init_tracing(quiet: bool, verbose: bool) {
    let log_level = if quiet {
        "error"
    } else if verbose {
        "debug"
    } else {
        "info"
    };
    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_target(false)
                .without_time()
                .with_ansi(false)
                .with_writer(|| TerminalSafeStderr),
        )
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)))
        .init();
}

struct TerminalSafeStderr;

impl Write for TerminalSafeStderr {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let rendered = sanitise_log_chunk_for_terminal(buf);
        let last_index = rendered.chars().count().saturating_sub(1);
        debug_assert!(
            rendered
                .chars()
                .enumerate()
                .all(|(idx, c)| !c.is_control() || (c == '\n' && idx == last_index)),
            "sanitised tracing output must not contain terminal controls"
        );
        io::stderr().write_all(rendered.as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

fn sanitise_log_chunk_for_terminal(buf: &[u8]) -> String {
    let text = String::from_utf8_lossy(buf);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\n' && chars.peek().is_none() {
            out.push('\n');
        } else if c == '\t' {
            out.push(' ');
        } else if c.is_control() {
            out.push('?');
        } else {
            out.push(c);
        }
    }
    out
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
