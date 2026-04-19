use crate::text_output::{format_results, TextOutputOptions};
use crate::{
    cli_args::{ColorChoiceArg, PolicyProfileArg, ScanArgs, ScanPresetArg, SeverityArg},
    color::ColorMode,
};
use anyhow::{Context, Result};
use skill_veil_core::{ScanOptions, ScanTargetMode, Scanner};
use std::io::IsTerminal;
use std::path::Path;

pub(crate) fn load_rule_engine_from_dir(rules_dir: &Path) -> Result<skill_veil_core::RuleEngine> {
    let mut engine = skill_veil_core::RuleEngine::new();
    engine
        .load_from_dir(rules_dir)
        .with_context(|| format!("Failed to load rules from {}", rules_dir.display()))?;
    Ok(engine)
}

pub(crate) fn apply_scan_preset(mut args: ScanArgs) -> ScanArgs {
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

pub(crate) fn run_scan(
    args: ScanArgs,
    target_mode: ScanTargetMode,
    quiet: bool,
    color_choice: ColorChoiceArg,
) -> Result<bool> {
    let args = apply_scan_preset(args);
    let color = ColorMode::from_choice(
        color_choice,
        args.output.is_none() && std::io::stdout().is_terminal(),
    );
    let text_options = TextOutputOptions {
        quiet_summary: args.quiet_summary,
        explain_policy: args.explain_policy,
        finding_limit: args.finding_limit,
        color,
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
    let scan_result = scanner.scan(&args.path).context("Failed to scan path")?;

    if !scan_result.errors.is_empty() {
        for err_entry in &scan_result.errors {
            eprintln!(
                "Warning: Failed to scan {}: {}",
                err_entry.path.display(),
                err_entry.error
            );
        }
    }

    let output_content = format_results(&scan_result.results, args.format, text_options)?;

    if let Some(output_path) = args.output {
        std::fs::write(&output_path, &output_content).context("Failed to write output file")?;
        if !quiet {
            eprintln!("Output written to: {}", output_path.display());
        }
    } else {
        print!("{}", output_content);
    }

    let should_fail =
        !scan_result.errors.is_empty() || scan_result.results.iter().any(|r| r.should_fail);
    Ok(should_fail)
}
