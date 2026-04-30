use crate::config::resolve_llm_provider_override;
use crate::text_output::{format_results, TextOutputOptions};
use crate::{
    cli_args::{ColorChoiceArg, PolicyProfileArg, ScanArgs, ScanPresetArg, SeverityArg},
    color::ColorMode,
};
use anyhow::{Context, Result};
use skill_veil_core::{
    RegexPatternMatcher, ScanOptions, ScanTargetMode, Scanner, StdFileSystemProvider,
};
use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;

mod cache;
mod llm;
mod vt;

/// Shared cap for short error blurbs (LLM parse error, VT enrichment
/// error). Both sources are external strings whose authors might emit
/// a multi-paragraph stack trace; we want a single line.
pub(super) const ERROR_MESSAGE_DISPLAY_CHARS: usize = 80;

/// Finding-limit cap applied by `--preset ci` and the default branch of
/// `--preset strict`. Const-constructed so a zero literal would be a
/// compile-time error rather than a runtime `expect()` panic.
const FINDING_LIMIT_CI: std::num::NonZeroUsize = match std::num::NonZeroUsize::new(10) {
    Some(n) => n,
    None => panic!("FINDING_LIMIT_CI must be non-zero"),
};
/// Finding-limit cap applied by `--preset enterprise`. Higher than
/// `FINDING_LIMIT_CI` because enterprise reviewers expect more context
/// per package than CI gating does.
const FINDING_LIMIT_ENTERPRISE: std::num::NonZeroUsize = match std::num::NonZeroUsize::new(20) {
    Some(n) => n,
    None => panic!("FINDING_LIMIT_ENTERPRISE must be non-zero"),
};

pub(crate) fn load_rule_engine_from_dir(
    rules_dir: &Path,
) -> Result<skill_veil_core::RuleEngine<RegexPatternMatcher>> {
    let mut engine =
        skill_veil_core::RuleEngine::with_matcher(Arc::new(RegexPatternMatcher::new()));
    let fs = StdFileSystemProvider::new();
    engine
        .load_from_dir(&fs, rules_dir)
        .with_context(|| format!("Failed to load rules from {}", rules_dir.display()))?;
    Ok(engine)
}

pub(crate) fn apply_scan_preset(mut args: ScanArgs) -> ScanArgs {
    match args.preset {
        Some(ScanPresetArg::Local) | None => {}
        Some(ScanPresetArg::Ci) => {
            args.quiet_summary = true;
            args.finding_limit.get_or_insert(FINDING_LIMIT_CI);
            args.profile.get_or_insert(PolicyProfileArg::Team);
        }
        Some(ScanPresetArg::Strict) => {
            args.quiet_summary = true;
            args.finding_limit.get_or_insert(FINDING_LIMIT_CI);
            args.profile.get_or_insert(PolicyProfileArg::Enterprise);
            args.fail_on.get_or_insert(SeverityArg::High);
            args.min_severity.get_or_insert(SeverityArg::Medium);
        }
        Some(ScanPresetArg::Enterprise) => {
            args.quiet_summary = true;
            args.finding_limit.get_or_insert(FINDING_LIMIT_ENTERPRISE);
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
        finding_limit: args.finding_limit.map(std::num::NonZeroUsize::get),
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
        strict_rules: args.strict_rules,
        ..Default::default()
    };

    let scanner = Scanner::with_std_adapters(options).context("Failed to initialize scanner")?;
    let scan_result = scanner.scan(&args.path).context("Failed to scan path")?;

    if !scan_result.errors.is_empty() && !quiet {
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

    // VT + LLM enrichment. Both are opt-in-by-default-when-configured; the
    // shared contract is that neither may touch `scan_result`. A single
    // snapshot taken before either runs guards both in debug builds.
    //
    // CONTRACT (do not break): enrichment functions receive immutable
    // borrows of `scan_result` and may only *produce* rendered text blocks.
    // It is architecturally impossible for them to influence our verdict /
    // risk score / findings. See `vt/enrich.rs` and `llm/enrich.rs` docs.
    let verdict_snapshot: Vec<(Option<String>, skill_veil_core::Verdict, u32)> = scan_result
        .results
        .iter()
        .map(|r| {
            (
                r.metadata.package_id.clone(),
                r.verdict,
                r.summary.risk_score,
            )
        })
        .collect();

    if !args.no_vt_enrich {
        if let Some(vt_block) = vt::try_enrich_with_vt(
            &scan_result,
            &args.path,
            args.vt_submit_unknown,
            args.cache_dir.as_deref(),
            quiet,
        )? {
            print!("{vt_block}");
        }
    }

    if !args.no_llm_enrich {
        let llm_provider_override = resolve_llm_provider_override(args.llm_provider.as_deref())?;
        if let Some(llm_block) = llm::try_enrich_with_llm(
            &scan_result,
            &args.path,
            llm_provider_override,
            args.cache_dir.as_deref(),
            quiet,
        )? {
            print!("{llm_block}");
        }
    }

    debug_assert_eq!(
        verdict_snapshot,
        scan_result
            .results
            .iter()
            .map(|r| (
                r.metadata.package_id.clone(),
                r.verdict,
                r.summary.risk_score
            ))
            .collect::<Vec<_>>(),
        "enrichment must never modify our verdict or risk_score"
    );

    // Scan-level I/O errors are surfaced as warnings on stderr above. The
    // exit code only reflects the user-configured severity threshold via
    // `--fail-on` (resolved per-result by the filter service); a single
    // unreadable file must not unconditionally fail a scan when the user
    // asked for `--fail-on High` and no qualifying findings fired.
    let should_fail = scan_result.results.iter().any(|r| r.should_fail);
    Ok(should_fail)
}
