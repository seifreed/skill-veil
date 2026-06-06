use crate::config::{resolve_llm_provider_override, UnifiedConfig};
use crate::llm::providers::build_provider;
use crate::text_output::{format_results, TextOutputOptions};
use crate::util::output_file::write_output_file_atomic;
use crate::util::terminal_safe::sanitise_for_terminal;
use crate::{
    cli_args::{ColorChoiceArg, PolicyProfileArg, ScanArgs, ScanPresetArg, SeverityArg},
    color::ColorMode,
};
use anyhow::{Context, Result};
use nova_llm_eval::ProviderLlmEvaluator;
use skill_veil_core::{
    Finding, PackageScanResult, RegexPatternMatcher, ScanOptions, ScanResult, ScanTargetMode,
    Scanner, StdFileSystemProvider,
};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod cache;
pub(crate) mod llm;
mod nova_llm_eval;
mod nova_run;
// The cosine-math + trait layer is feature-independent but is only
// constructed by `fastembed_impl` (feature-gated) and the module's own
// contract tests. Compiling it exactly when the feature is on OR under
// `test` keeps default builds free of dead code without a blanket
// `#[allow(dead_code)]`, while still running the contract tests under a
// plain `cargo test`.
#[cfg(any(feature = "nova-semantics", test))]
mod nova_semantics_eval;
mod promptintel;
mod vt;
#[cfg(feature = "yara")]
mod yara_run;

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

/// Build the NOVA `llm:` evaluator from `~/.skill-veil.toml [llm]`,
/// honouring the same `--llm-provider` override the regular LLM
/// enrichment uses. Returns `None` (with a one-line operator note when
/// `quiet=false`) if config loading fails, no `[llm]` section is
/// present, the override string is invalid, or the provider can't be
/// constructed (e.g. missing API key). The caller falls back to the
/// `NotYetWiredLlm` stub on `None` so a misconfiguration cannot crash
/// the scan; the rule's `condition:` requirement still surfaces under
/// `skipped_capabilities`.
fn build_nova_llm_eval(
    provider_override_raw: Option<&str>,
    quiet: bool,
) -> Option<Box<ProviderLlmEvaluator>> {
    let cfg = match UnifiedConfig::load() {
        Ok(c) => c,
        Err(err) => {
            if !quiet {
                eprintln!(
                    "--nova-llm: config load failed, NOVA llm: patterns will be skipped: {err:#}"
                );
            }
            return None;
        }
    };
    let mut llm_section = cfg.llm?;
    let provider_override = match resolve_llm_provider_override(provider_override_raw) {
        Ok(v) => v,
        Err(err) => {
            if !quiet {
                eprintln!("--nova-llm: provider override invalid, NOVA llm: patterns will be skipped: {err:#}");
            }
            return None;
        }
    };
    if let Some(kind) = provider_override {
        llm_section.apply_provider_override(kind);
    }
    let provider: Arc<dyn crate::llm::client::LlmProvider> = match build_provider(&llm_section) {
        Ok(p) => Arc::from(p),
        Err(err) => {
            if !quiet {
                eprintln!(
                    "--nova-llm: provider build failed, NOVA llm: patterns will be skipped: {err}"
                );
            }
            return None;
        }
    };
    let max_prompt_chars =
        llm_section.effective_max_prompt_chars_with_probe(provider.probe_context_length());
    Some(Box::new(ProviderLlmEvaluator::with_max_prompt_chars(
        provider,
        max_prompt_chars,
    )))
}

/// Build the native NOVA `semantics:` evaluator. Returns `None` when
/// the binary was compiled without `--features nova-semantics` or the
/// model fails to initialise; the caller falls back to the
/// `NotYetWiredSemantic` stub so the scan keeps running and
/// `SkippedCapability::Semantics` still surfaces for any rule that
/// needed the channel. Now that semantics is default-on, the
/// no-feature path is silent (per-scan nagging would be spam on every
/// non-feature build); the skipped-capability label in the NOVA text
/// block is the single, non-repetitive place this is communicated.
/// A genuine model-init failure on a feature build IS surfaced.
#[cfg(feature = "nova-semantics")]
fn build_nova_semantic_eval(
    quiet: bool,
) -> Option<Box<dyn skill_veil_core::nova::SemanticEvaluator>> {
    use nova_semantics_eval::fastembed_impl::FastembedSentenceEmbedder;
    use nova_semantics_eval::CosineSemanticEvaluator;
    match FastembedSentenceEmbedder::try_new() {
        Ok(embedder) => Some(Box::new(CosineSemanticEvaluator::new(embedder))),
        Err(err) => {
            if !quiet {
                eprintln!("--nova-semantics: model initialisation failed, NOVA semantics: patterns will be skipped: {err:?}");
            }
            None
        }
    }
}

#[cfg(not(feature = "nova-semantics"))]
fn build_nova_semantic_eval(
    _quiet: bool,
) -> Option<Box<dyn skill_veil_core::nova::SemanticEvaluator>> {
    None
}

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

/// Best-effort startup notifier — checks GitHub once per 24h for
/// newer skill-veil-rules releases and NOVA commits. Never blocks,
/// never errors. Honours `--no-update-check` and the
/// `SKILL_VEIL_NO_UPDATE_CHECK` env var (handled internally).
fn run_update_notifier(args: &ScanArgs) {
    use crate::init::update_check::{maybe_notify, Behaviour};
    let behaviour = if args.no_update_check {
        Behaviour::Skipped
    } else {
        Behaviour::Notify
    };
    let cache_root = update_notifier_cache_root_from(args.cache_dir.as_deref(), dirs::cache_dir());
    let Some(cache_root) = cache_root else {
        return;
    };
    let install = match crate::init::current_install(Some(cache_root.clone())) {
        Ok(i) => i,
        Err(_) => return,
    };
    let sv_pin = install.skill_veil.as_ref().map(|s| s.version.as_str());
    let nova_pin = install.nova.as_ref().map(|n| n.commit_sha.as_str());
    maybe_notify(behaviour, &cache_root, sv_pin, nova_pin);
}

fn update_notifier_cache_root_from(
    _scan_cache_override: Option<&Path>,
    user_cache: Option<PathBuf>,
) -> Option<PathBuf> {
    user_cache.map(|d| d.join("skill-veil"))
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
        Some(ScanPresetArg::Triage) => {
            // Local + both LLM adjudication levers. A preset is a pure
            // CLI-args transform that never reaches core, so the
            // LLM-trust decision stays out of the immutable verdict
            // engine. The deterministic presets above are left
            // adjudication-OFF on purpose.
            args.llm_adjudicate_taint = true;
            args.llm_adjudicate_upgrade = true;
            args.llm_fp_review = true;
            args.llm_fp_adjudicate = true;
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

    // Best-effort startup notifier — checks once per 24h whether
    // either rule source has a newer pin upstream. Never blocks the
    // scan; failures degrade silently. Honours `--no-update-check`
    // and `SKILL_VEIL_NO_UPDATE_CHECK=1`.
    if !quiet {
        run_update_notifier(&args);
    }

    let text_options = TextOutputOptions {
        quiet_summary: args.quiet_summary,
        explain_policy: args.explain_policy,
        finding_limit: args.finding_limit.map(std::num::NonZeroUsize::get),
        color,
    };
    let options = ScanOptions {
        min_severity: args.min_severity.map(Into::into),
        fail_on: args.fail_on.map(Into::into),
        rules_dir: args.rules_dir.clone(),
        profile: args.profile.map(Into::into),
        baseline_path: args.baseline.clone(),
        waivers_path: args.waivers.clone(),
        policy_path: args.policy.clone(),
        disposition_path: args.disposition.clone(),
        recursive: !args.no_recursive,
        target_mode,
        strict_rules: args.strict_rules,
        runtime_overlay_dirs: crate::rule_dirs::default_external_rule_dirs(),
        ..Default::default()
    };

    // Cloned before `options` is moved into the scanner so the taint
    // adjudication (ADR 0029) can rebuild a `ScanFilterService` with
    // the operator's exact `--fail-on` to recompute exit-code
    // contribution for downgraded packages. Cheap; only used when
    // `--llm-adjudicate-taint` is set.
    let filter_options = options.clone();
    let scanner = Scanner::with_std_adapters(options).context("Failed to initialize scanner")?;
    let mut scan_result = scanner.scan(&args.path).context("Failed to scan path")?;

    let nova_report = evaluate_nova_channel(&args, quiet, &mut scan_result);

    #[cfg(feature = "yara")]
    let yara_report = evaluate_yara_channel(&args, quiet, &mut scan_result);

    #[cfg(feature = "sandbox")]
    let sandbox_report = evaluate_sandbox_channel(&args, quiet, &mut scan_result);
    #[cfg(not(feature = "sandbox"))]
    if (args.dynamic || args.sandbox_detonate_agent) && !quiet {
        eprintln!(
            "--dynamic/--sandbox-detonate-agent: this binary was built without \
             `--features sandbox`; skipping dynamic analysis"
        );
    }

    if !scan_result.errors.is_empty() && !quiet {
        for err_entry in &scan_result.errors {
            eprintln!(
                "Warning: Failed to scan {}: {}",
                terminal_path(&err_entry.path),
                terminal_text(&err_entry.error)
            );
        }
    }

    // Operator threat-mapping: overlay free-form `user_taxonomy` labels onto
    // findings before rendering. Communication-only — it never touches a
    // verdict, risk score, or action, so the `verdict_snapshot` assert below
    // stays valid.
    if let Some(mapping_path) = args.threat_mapping.as_deref() {
        let mapping = crate::threat_mapping::ThreatMapping::load(mapping_path)?;
        mapping.apply(&mut scan_result.results);
    }

    let output_content = format_results(&scan_result.results, args.format, text_options)?;

    if let Some(output_path) = args.output.as_deref() {
        write_scan_output(output_path, &output_content)?;
        if !quiet {
            eprintln!("Output written to: {}", terminal_path(output_path));
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

    run_read_only_enrichments(&scan_result, &args, quiet)?;

    let adjudicated = run_taint_adjudication_stage(&scan_result, &args, &filter_options, quiet)?;
    let fp_outcome = run_fp_review_stage(&scan_result, &args, &filter_options, quiet)?;

    run_promptintel_enrichment(&scan_result, &args, quiet)?;
    check_artifact_overlap(&scan_result, &args, quiet);

    // The text block is operator-friendly noise; suppress it for
    // JSON / SARIF / Shield output where it would pollute the
    // structured payload. NOVA findings still flow through those
    // formats via the injection above.
    if let Some(report) = nova_report.as_ref() {
        let render_text = !quiet && matches!(args.format, crate::cli_args::OutputFormat::Text);
        if render_text {
            print!("{}", nova_run::render_text_block(report));
        }
    }

    #[cfg(feature = "yara")]
    if let Some(report) = yara_report.as_ref() {
        let render_text = !quiet && matches!(args.format, crate::cli_args::OutputFormat::Text);
        if render_text {
            print!("{}", yara_run::render_text_block(report));
        }
    }

    #[cfg(feature = "sandbox")]
    if let Some(report) = sandbox_report.as_ref() {
        let render_text = !quiet && matches!(args.format, crate::cli_args::OutputFormat::Text);
        if render_text {
            print!("{}", crate::sandbox::render_text_block(report));
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

    Ok(compute_should_fail(
        &scan_result,
        adjudicated.as_ref(),
        fp_outcome.as_ref(),
    ))
}

/// Run the NOVA community-rule channel and inject its hits as first-class
/// findings on `scan_result`.
///
/// Done ONCE; the returned report feeds two consumers — the injected findings
/// (so JSON/SARIF/text surface NOVA hits) and the trailing text block rendered
/// later. Verdict / risk_score are NOT recomputed: NOVA findings carry
/// `SignalClass::ReviewSignal`, which by mapping contract does not inflate the
/// existing calibration, so the `verdict_snapshot` debug-assert still holds.
fn evaluate_nova_channel(
    args: &ScanArgs,
    quiet: bool,
    scan_result: &mut PackageScanResult,
) -> Option<nova_run::NovaScanReport> {
    if args.no_nova {
        return None;
    }
    // The provider-backed `llm:` evaluator is built iff the user opted in with
    // `--nova-llm` and `~/.skill-veil.toml` (or env) carries an `[llm]` section;
    // either gate failing falls back to `NotYetWiredLlm` so any rule needing
    // `llm.` surfaces under `skipped_capabilities` instead of firing.
    let nova_llm_eval = if args.nova_llm {
        build_nova_llm_eval(args.llm_provider.as_deref(), quiet)
    } else {
        None
    };
    let llm_eval_ref = nova_llm_eval
        .as_deref()
        .map(|e| e as &dyn skill_veil_core::nova::LlmEvaluator);
    // Native semantics runs by default (`--no-nova-semantics` opts out), still
    // gated by the `nova-semantics` build feature: with the feature off,
    // `build_nova_semantic_eval` returns None and rules needing the semantic
    // channel surface `SkippedCapability::Semantics` (Skipped → false preserved).
    let nova_sem_eval = if args.no_nova_semantics {
        None
    } else {
        build_nova_semantic_eval(quiet)
    };
    let sem_eval_ref = nova_sem_eval
        .as_deref()
        .map(|e| e as &dyn skill_veil_core::nova::SemanticEvaluator);
    let report = match nova_run::evaluate_against_target(
        &args.path,
        args.cache_dir.as_deref(),
        llm_eval_ref,
        sem_eval_ref,
    ) {
        Ok(r) => r,
        Err(err) => {
            if !quiet {
                eprintln!("warning: NOVA evaluation skipped: {err:#}");
            }
            None
        }
    };
    if let Some(report) = &report {
        attach_findings_by_path(&mut scan_result.results, &report.findings_by_path());
    }
    report
}

/// Run the YARA channel and inject its hits as first-class findings. Mirrors
/// NOVA: a post-verdict pass over the same artifacts that never recomputes the
/// verdict (the `verdict_snapshot` assert is taken after this injection).
#[cfg(feature = "yara")]
fn evaluate_yara_channel(
    args: &ScanArgs,
    quiet: bool,
    scan_result: &mut PackageScanResult,
) -> Option<yara_run::YaraScanReport> {
    if args.no_yara {
        return None;
    }
    let report = match yara_run::evaluate_against_target(&args.path, args.cache_dir.as_deref()) {
        Ok(report) => report,
        Err(err) => {
            if !quiet {
                eprintln!("warning: YARA evaluation skipped: {err:#}");
            }
            None
        }
    };
    if let Some(report) = &report {
        attach_findings_by_path(&mut scan_result.results, &report.findings_by_path());
    }
    report
}

/// Run the dynamic-behavior sandbox (gated behind `--dynamic` /
/// `--sandbox-detonate-agent` — it EXECUTES untrusted code) and inject advisory
/// findings. gVisor is required unless `--sandbox-allow-runc` is set; like
/// NOVA/YARA it never recomputes the verdict.
#[cfg(feature = "sandbox")]
fn evaluate_sandbox_channel(
    args: &ScanArgs,
    quiet: bool,
    scan_result: &mut PackageScanResult,
) -> Option<crate::sandbox::SandboxReport> {
    let report = if args.sandbox_detonate_agent {
        match crate::sandbox::evaluate_detonation_against_target(
            &args.path,
            !args.sandbox_allow_runc,
        ) {
            Ok(report) => report,
            Err(err) => {
                if !quiet {
                    eprintln!("warning: agent detonation skipped: {err:#}");
                }
                None
            }
        }
    } else if args.dynamic {
        match crate::sandbox::evaluate_against_target(
            &args.path,
            !args.sandbox_allow_runc,
            args.sandbox_record_network,
            args.llm_provider.as_deref(),
        ) {
            Ok(report) => report,
            Err(err) => {
                if !quiet {
                    eprintln!("warning: dynamic sandbox skipped: {err:#}");
                }
                None
            }
        }
    } else {
        None
    };
    if let Some(report) = &report {
        attach_findings_by_path(&mut scan_result.results, &report.findings_by_path());
    }
    report
}

/// Whether operator-facing trailing text blocks (VT / OSV / abandoned / LLM /
/// PromptIntel enrichment, taint adjudication) may be written to stdout.
/// Structured formats (JSON / SARIF / Shield / HTML) carry a machine-parseable
/// payload on the same stream that a trailing text block would corrupt — a CI
/// gate then fails to parse the report and may read it as "no findings",
/// passing a malicious package. So these blocks are emitted only for the
/// human-readable Text format, matching the NOVA / YARA / FP-review gating.
fn text_block_allowed(format: crate::cli_args::OutputFormat) -> bool {
    matches!(format, crate::cli_args::OutputFormat::Text)
}

/// Run the read-only enrichment channels (VT, OSV, abandoned-package, LLM) that
/// take an immutable `scan_result` and only print a trailing text block. None
/// may touch the verdict / risk score — the `verdict_snapshot` assert enforces
/// this in debug builds.
fn run_read_only_enrichments(
    scan_result: &PackageScanResult,
    args: &ScanArgs,
    quiet: bool,
) -> Result<()> {
    // The enrichment blocks are operator-friendly text. Printing them to the
    // stdout that already carries a JSON / SARIF / Shield / HTML payload makes
    // that payload unparseable — a CI gate that parses the report then reads it
    // as "no findings", silently passing a malicious package. Gate the prints
    // on the Text format, exactly like the NOVA / YARA / FP-review blocks. The
    // enrichment is still computed (so `--vt-submit-unknown` still submits); only
    // the trailing text is suppressed for structured formats.
    let render_block = text_block_allowed(args.format);
    if !args.no_vt_enrich {
        if let Some(vt_block) = vt::try_enrich_with_vt(
            scan_result,
            &args.path,
            args.vt_submit_unknown,
            args.cache_dir.as_deref(),
            quiet,
        )? {
            if render_block {
                print!("{vt_block}");
            }
        }
    }

    if let Some(osv_block) =
        crate::osv::try_enrich_with_osv(scan_result, args.osv, args.cache_dir.as_deref(), quiet)?
    {
        if render_block {
            print!("{osv_block}");
        }
    }

    if let Some(abandoned_block) = crate::abandoned::try_enrich_with_abandoned(
        scan_result,
        args.abandoned,
        args.cache_dir.as_deref(),
        quiet,
    )? {
        if render_block {
            print!("{abandoned_block}");
        }
    }

    if !args.no_llm_enrich {
        let llm_provider_override = resolve_llm_provider_override(args.llm_provider.as_deref())?;
        if let Some(llm_block) = llm::try_enrich_with_llm(
            scan_result,
            &args.path,
            llm_provider_override,
            args.cache_dir.as_deref(),
            quiet,
        )? {
            if render_block {
                print!("{llm_block}");
            }
        }
    }
    Ok(())
}

/// ADR 0029 + its symmetric FN upgrade: gated LLM taint adjudication. Each
/// direction is independently opt-in (default OFF) and needs LLM access, so it
/// is contradictory with `--no-llm-enrich`. Works on clones only — never
/// mutates `scan_result` — and affects only its printed block plus the exit
/// code via the returned outcome's `package_fail_overrides`.
fn run_taint_adjudication_stage(
    scan_result: &PackageScanResult,
    args: &ScanArgs,
    filter_options: &ScanOptions,
    quiet: bool,
) -> Result<Option<crate::llm::taint_adjudication::AdjudicationOutcome>> {
    let adjudicate_any = args.llm_adjudicate_taint || args.llm_adjudicate_upgrade;
    if adjudicate_any && !args.no_llm_enrich {
        match crate::llm::taint_adjudication::run_adjudication(
            scan_result,
            &args.path,
            args.cache_dir.as_deref(),
            filter_options,
            quiet,
            args.llm_adjudicate_taint,
            args.llm_adjudicate_upgrade,
        )? {
            Some(outcome) => {
                // Gate the text block on the Text format so it never corrupts a
                // JSON/SARIF stdout payload; the exit-code override in `outcome`
                // is returned regardless of format.
                if text_block_allowed(args.format) {
                    print!("{}", outcome.report_block);
                }
                Ok(Some(outcome))
            }
            None => Ok(None),
        }
    } else {
        if adjudicate_any && args.no_llm_enrich && !quiet {
            eprintln!(
                "LLM adjudication skipped: --llm-adjudicate-taint / \
                 --llm-adjudicate-upgrade need LLM access but --no-llm-enrich was set"
            );
        }
        Ok(None)
    }
}

/// LLM false-positive review. Works on clones, never affects the core verdict /
/// risk score / structured payload. Advisory by default; with
/// `--llm-fp-adjudicate` it additionally softens the exit code for
/// benign-consensus Suspicious packages via the returned `package_fail_overrides`.
/// The text block is text-format only; the machine-readable form is the opt-in
/// JSON sidecar.
fn run_fp_review_stage(
    scan_result: &PackageScanResult,
    args: &ScanArgs,
    filter_options: &ScanOptions,
    quiet: bool,
) -> Result<Option<crate::llm::fp_review::FpReviewOutcome>> {
    let fp_review_on = args.llm_fp_review || args.llm_fp_adjudicate;
    if fp_review_on && !args.no_llm_enrich {
        let outcome = crate::llm::fp_review::run_fp_review(
            scan_result,
            &args.path,
            args.cache_dir.as_deref(),
            filter_options,
            quiet,
            fp_review_on,
            args.llm_fp_adjudicate,
        )?;
        if let Some(outcome) = &outcome {
            if !quiet && matches!(args.format, crate::cli_args::OutputFormat::Text) {
                print!("{}", outcome.report_block);
            }
            if let Some(out) = args.llm_fp_review_out.as_deref() {
                let json = crate::llm::fp_review::to_json(outcome)?;
                write_scan_output(out, &json)?;
                if !quiet {
                    eprintln!("FP review written to: {}", terminal_path(out));
                }
            }
        }
        Ok(outcome)
    } else {
        if fp_review_on && args.no_llm_enrich && !quiet {
            eprintln!(
                "LLM FP review skipped: --llm-fp-review / --llm-fp-adjudicate need LLM \
                 access but --no-llm-enrich was set"
            );
        }
        Ok(None)
    }
}

/// PromptIntel enrichment channel: opt-in-by-default-when-configured, prints a
/// trailing block, never touches `scan_result`.
fn run_promptintel_enrichment(
    scan_result: &PackageScanResult,
    args: &ScanArgs,
    quiet: bool,
) -> Result<()> {
    if !args.no_promptintel_enrich {
        if let Some(pi_block) = promptintel::try_enrich_with_promptintel(
            scan_result,
            &args.path,
            args.cache_dir.as_deref(),
            quiet,
        )? {
            // Text-only: this block would corrupt a structured stdout payload.
            if text_block_allowed(args.format) {
                print!("{pi_block}");
            }
        }
    }
    Ok(())
}

/// Cross-skill artifact overlap. Advisory, CLI-local, report-only: it reads and
/// hashes files but never touches `scan_result`. Text format only — it would
/// pollute the structured payload otherwise.
fn check_artifact_overlap(scan_result: &PackageScanResult, args: &ScanArgs, quiet: bool) {
    if args.check_overlap && matches!(args.format, crate::cli_args::OutputFormat::Text) {
        if let Some(block) = crate::overlap::try_check_overlap(scan_result, true, quiet) {
            if !quiet {
                print!("{block}");
            }
        }
    }
}

/// Compute the process exit-code boolean. The exit code reflects the
/// user-configured `--fail-on` threshold (resolved per-result by the filter
/// service); a single unreadable file must not unconditionally fail a scan.
///
/// Both LLM adjudications expose per-package exit-code overrides for the
/// packages they changed (taint: Malicious; FP adjudicate: Suspicious —
/// disjoint classes). A package absent from both maps keeps its original
/// `should_fail`; with neither populated this is byte-identical to the legacy
/// `any(should_fail)`.
fn compute_should_fail(
    scan_result: &PackageScanResult,
    adjudicated: Option<&crate::llm::taint_adjudication::AdjudicationOutcome>,
    fp_outcome: Option<&crate::llm::fp_review::FpReviewOutcome>,
) -> bool {
    let mut fail_overrides: std::collections::BTreeMap<usize, bool> =
        std::collections::BTreeMap::new();
    if let Some(o) = adjudicated {
        fail_overrides.extend(o.package_fail_overrides.iter().map(|(&i, &f)| (i, f)));
    }
    if let Some(o) = fp_outcome {
        for (&i, &f) in &o.package_fail_overrides {
            fail_overrides.entry(i).or_insert(f);
        }
    }
    scan_result
        .results
        .iter()
        .enumerate()
        .any(|(i, r)| *fail_overrides.get(&i).unwrap_or(&r.should_fail))
}

/// Attaches a post-scan channel's findings (NOVA, YARA) to the `ScanResult`
/// that owns each matched file.
///
/// A channel walks every text artifact under the scan target, but the
/// scanner emits one `ScanResult` per discovered package entrypoint — so a
/// hit on a non-entrypoint file (e.g. `pkg/b/README.md`) has no result keyed
/// on its exact path. Each hit is attributed to the result whose entrypoint
/// path shares the longest leading path-component prefix with the hit: the
/// package that contains it. Both the entrypoint path (`metadata.path`) and
/// the hit `source_path` derive from the same scan-target base and neither
/// is canonicalised, so the prefix comparison is well-defined. The
/// longest-prefix rule keeps a multi-package scan from dumping unmatched
/// hits onto the lexicographically-first result, which would mis-attribute
/// findings to the wrong package in JSON / SARIF output.
fn attach_findings_by_path(
    results: &mut [ScanResult],
    by_path: &std::collections::HashMap<PathBuf, Vec<Finding>>,
) {
    for (hit_path, findings) in by_path {
        let Some(idx) = channel_attribution_index(results, hit_path) else {
            continue;
        };
        results[idx].findings.extend(findings.iter().cloned());
        results[idx]
            .primary_findings
            .extend(findings.iter().cloned());
    }
}

/// Index of the `ScanResult` whose entrypoint path shares the longest
/// leading component prefix with `hit_path`, or `None` when there are no
/// results. With a single result the answer is always that result, which
/// preserves single-file / single-package behaviour. When no result shares
/// any prefix (fully disjoint paths — not reachable for an in-tree scan),
/// the first result is the non-dropping fallback.
fn channel_attribution_index(results: &[ScanResult], hit_path: &Path) -> Option<usize> {
    longest_prefix_index(results.iter().map(|r| r.metadata.path.as_path()), hit_path)
}

/// Index of the entrypoint path sharing the longest leading path-component
/// prefix with `hit_path`. Returns the first entry as a non-dropping
/// fallback when none shares any prefix, and `None` for an empty iterator.
fn longest_prefix_index<'a>(
    entrypoints: impl Iterator<Item = &'a Path>,
    hit_path: &Path,
) -> Option<usize> {
    let mut best_idx: Option<usize> = None;
    let mut best_len = 0usize;
    for (idx, entry) in entrypoints.enumerate() {
        let shared = entry
            .components()
            .zip(hit_path.components())
            .take_while(|(a, b)| a == b)
            .count();
        if best_idx.is_none() || shared > best_len {
            best_idx = Some(idx);
            best_len = shared;
        }
    }
    best_idx
}

fn terminal_text(value: &str) -> String {
    sanitise_for_terminal(value)
}

fn write_scan_output(output_path: &Path, output_content: &str) -> Result<()> {
    write_output_file_atomic(output_path, output_content.as_bytes())
        .context("Failed to write output file")
}

fn terminal_path(path: &Path) -> String {
    terminal_text(&path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli_args::{Cli, Commands, OutputFormat};
    use clap::Parser;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Contract: trailing operator text blocks (VT/OSV/LLM/PromptIntel
    /// enrichment, taint adjudication) print ONLY for the Text format. Every
    /// structured format keeps stdout payload-only so a CI gate can parse the
    /// report — a leaked text block makes JSON/SARIF unparseable, which many
    /// wrappers read as "no findings" and pass a malicious package.
    #[test]
    fn structured_formats_suppress_trailing_text_blocks() {
        assert!(text_block_allowed(OutputFormat::Text));
        for (format, name) in [
            (OutputFormat::Json, "json"),
            (OutputFormat::Sarif, "sarif"),
            (OutputFormat::Shield, "shield"),
            (OutputFormat::Html, "html"),
        ] {
            assert!(
                !text_block_allowed(format),
                "{name} is a structured format and must not print trailing text blocks",
            );
        }
    }

    /// Contract: a NOVA hit on a non-entrypoint file in a multi-package
    /// scan is attributed to the package that contains it (longest shared
    /// entrypoint-path prefix), NOT the lexicographically-first result.
    /// Pre-fix the unmatched-hit fallback dumped every NOVA finding onto
    /// `results[0]`, mis-attributing it to the wrong package.
    #[test]
    fn nova_hit_attributed_to_owning_package_in_multi_package_scan() {
        let entrypoints = [
            Path::new("pkg/a/SKILL.md"),
            Path::new("pkg/b/SKILL.md"),
            Path::new("pkg/c/SKILL.md"),
        ];
        let hit = Path::new("pkg/b/README.md");
        assert_eq!(
            longest_prefix_index(entrypoints.iter().copied(), hit),
            Some(1),
            "hit under pkg/b must attach to result for pkg/b, not pkg/a",
        );
    }

    /// Contract: a NOVA hit on the entrypoint file itself attaches to that
    /// entrypoint's result.
    #[test]
    fn nova_hit_on_entrypoint_attaches_to_its_own_result() {
        let entrypoints = [Path::new("pkg/a/SKILL.md"), Path::new("pkg/b/SKILL.md")];
        assert_eq!(
            longest_prefix_index(entrypoints.iter().copied(), Path::new("pkg/b/SKILL.md")),
            Some(1),
        );
    }

    /// Contract: single-result (single-file / single-package) scans always
    /// attribute to that one result, and an empty result set yields `None`.
    #[test]
    fn nova_attribution_single_and_empty_result_sets() {
        let single = [Path::new("/tmp/SKILL.md")];
        assert_eq!(
            longest_prefix_index(single.iter().copied(), Path::new("/tmp/notes.md")),
            Some(0),
            "single result is always the target",
        );
        let empty: [&Path; 0] = [];
        assert_eq!(
            longest_prefix_index(empty.iter().copied(), Path::new("x.md")),
            None,
        );
    }

    #[test]
    fn terminal_path_removes_scan_warning_control_sequences() {
        let path = PathBuf::from("pkg\x1b[2J/SKILL.md");
        let cleaned = terminal_path(&path);

        assert!(!cleaned.contains('\x1b'));
        assert!(cleaned.contains("pkg?[2J"));
    }

    /// # Contract
    ///
    /// `scan --cache-dir` is the enrichment-cache override for VT, LLM,
    /// and PromptIntel lookups. The update notifier must ignore it and
    /// inspect the rules install cache under the OS user cache instead,
    /// matching the rule-loader search path.
    #[test]
    fn update_notifier_ignores_scan_cache_override() {
        let scan_cache = PathBuf::from("/tmp/package/.skill-veil-cache");
        let user_cache = PathBuf::from("/home/test/.cache");

        let resolved = update_notifier_cache_root_from(Some(&scan_cache), Some(user_cache.clone()))
            .expect("user cache root");

        assert_eq!(resolved, user_cache.join("skill-veil"));
        assert_ne!(resolved, scan_cache);
    }

    /// # Contract
    ///
    /// Without an OS user cache directory, the update notifier has no
    /// trusted place to read rule-install pins or write its TTL marker.
    /// It must not fall back to the scan enrichment cache override.
    #[test]
    fn update_notifier_rejects_missing_user_cache_even_with_scan_cache_override() {
        let scan_cache = PathBuf::from("/tmp/package/.skill-veil-cache");

        let resolved = update_notifier_cache_root_from(Some(&scan_cache), None);

        assert!(resolved.is_none());
    }

    /// # Contract
    ///
    /// `scan --output` MUST replace a symlink at the final report path
    /// without writing through to the symlink target.
    #[cfg(unix)]
    #[test]
    fn write_scan_output_replaces_symlink_without_touching_target() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("outside.json");
        let output = dir.path().join("scan.json");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, &output).unwrap();

        write_scan_output(&output, "{\"scan\":true}\n").unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert!(!std::fs::symlink_metadata(&output)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&output).unwrap(), b"{\"scan\":true}\n");
    }

    fn preset_args(preset: Option<&str>) -> crate::cli_args::ScanArgs {
        let mut argv = vec!["skill-veil", "scan"];
        if let Some(p) = preset {
            argv.push("--preset");
            argv.push(p);
        }
        argv.push("somepath");
        match Cli::try_parse_from(argv).expect("cli parse").command {
            Commands::Scan(a) => apply_scan_preset(a),
            _ => panic!("expected scan subcommand"),
        }
    }

    /// Contract: the `triage` preset turns ON both LLM adjudication
    /// levers and the advisory LLM false-positive review — the single
    /// explicit opt-in surface for analyst-facing LLM passes.
    #[test]
    fn triage_preset_enables_taint_adjudication() {
        let a = preset_args(Some("triage"));
        assert!(a.llm_adjudicate_taint, "triage must enable downgrade");
        assert!(a.llm_adjudicate_upgrade, "triage must enable upgrade");
        assert!(a.llm_fp_review, "triage must enable advisory FP review");
        assert!(a.llm_fp_adjudicate, "triage must enable FP adjudication");
    }

    /// Contract (negative): every deterministic preset — and the
    /// no-preset default — leaves BOTH adjudication levers AND the
    /// advisory FP review OFF, so CI verdicts never depend on an
    /// external LLM.
    #[test]
    fn local_ci_strict_enterprise_presets_leave_taint_adjudication_off() {
        for preset in [
            None,
            Some("local"),
            Some("ci"),
            Some("strict"),
            Some("enterprise"),
        ] {
            let a = preset_args(preset);
            assert!(
                !a.llm_adjudicate_taint
                    && !a.llm_adjudicate_upgrade
                    && !a.llm_fp_review
                    && !a.llm_fp_adjudicate,
                "preset {preset:?} must leave adjudication and FP review OFF",
            );
        }
    }

    /// Contract: `triage` is Local + the two flags ONLY — it must not
    /// silently pull in the Strict/CI bundle (quiet_summary, profile,
    /// fail_on, finding_limit).
    #[test]
    fn triage_preset_does_not_alter_unrelated_preset_fields() {
        let a = preset_args(Some("triage"));
        assert!(!a.quiet_summary, "triage must not set quiet_summary");
        assert!(a.profile.is_none(), "triage must not pin a policy profile");
        assert!(a.fail_on.is_none(), "triage must not set fail_on");
        assert!(a.finding_limit.is_none(), "triage must not cap findings");
    }

    fn scan_args(extra: &[&str]) -> crate::cli_args::ScanArgs {
        let mut argv = vec!["skill-veil", "scan"];
        argv.extend_from_slice(extra);
        argv.push("somepath");
        match Cli::try_parse_from(argv).expect("cli parse").command {
            Commands::Scan(a) => a,
            _ => panic!("expected scan subcommand"),
        }
    }

    /// Contract: NOVA semantics is default-ON (no opt-in flag needed);
    /// `--no-nova-semantics` opts OUT; the deprecated `--nova-semantics`
    /// flag still parses (hidden, one-release compat) and does NOT
    /// disable semantics. The dispatch wants semantics whenever
    /// `!no_nova_semantics`.
    #[test]
    fn nova_semantics_default_on_with_opt_out() {
        let default = scan_args(&[]);
        assert!(
            !default.no_nova_semantics,
            "semantics must be wanted by default (no opt-in flag)",
        );
        let opted_out = scan_args(&["--no-nova-semantics"]);
        assert!(opted_out.no_nova_semantics, "--no-nova-semantics opts out");
        // Legacy flag still parses and does not force semantics off.
        let legacy = scan_args(&["--nova-semantics"]);
        assert!(
            !legacy.no_nova_semantics,
            "deprecated --nova-semantics must not disable default-on semantics",
        );
    }
}
