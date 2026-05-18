use crate::config::{resolve_llm_provider_override, UnifiedConfig};
use crate::llm::providers::build_provider;
use crate::text_output::{format_results, TextOutputOptions};
use crate::{
    cli_args::{ColorChoiceArg, PolicyProfileArg, ScanArgs, ScanPresetArg, SeverityArg},
    color::ColorMode,
};
use anyhow::{Context, Result};
use nova_llm_eval::ProviderLlmEvaluator;
use skill_veil_core::{
    RegexPatternMatcher, ScanOptions, ScanTargetMode, Scanner, StdFileSystemProvider,
};
use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;

mod cache;
pub(crate) mod llm;
mod nova_llm_eval;
mod nova_run;
mod nova_semantics_eval;
mod promptintel;
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
        llm_section.provider = kind;
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
    Some(Box::new(ProviderLlmEvaluator::new(provider)))
}

/// Build the native NOVA `semantics:` evaluator. Returns `None` (and
/// emits a one-line operator note unless `quiet`) when the binary was
/// compiled without `--features nova-semantics` or when the underlying
/// model fails to initialise. The caller falls back to the
/// `NotYetWiredSemantic` stub on `None` so the scan keeps running and
/// `SkippedCapability::Semantics` still surfaces for any rule that
/// needed the channel.
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
    quiet: bool,
) -> Option<Box<dyn skill_veil_core::nova::SemanticEvaluator>> {
    if !quiet {
        eprintln!(
            "--nova-semantics: this binary was built without `--features nova-semantics`; \
             NOVA semantics: patterns will be skipped",
        );
    }
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
    let cache_root = args
        .cache_dir
        .clone()
        .or_else(|| dirs::cache_dir().map(|d| d.join("skill-veil")));
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

    // Cloned before `options` is moved into the scanner so the taint
    // adjudication (ADR 0029) can rebuild a `ScanFilterService` with
    // the operator's exact `--fail-on` to recompute exit-code
    // contribution for downgraded packages. Cheap; only used when
    // `--llm-adjudicate-taint` is set.
    let filter_options = options.clone();
    let scanner = Scanner::with_std_adapters(options).context("Failed to initialize scanner")?;
    let mut scan_result = scanner.scan(&args.path).context("Failed to scan path")?;

    // NOVA evaluation. Done ONCE; the report feeds two consumers:
    //   (a) findings injected into `scan_result` so JSON / SARIF /
    //       text output surface NOVA hits as first-class Findings.
    //   (b) the trailing `--- NOVA rule matches ---` text block
    //       printed after enrichment for human-readable summary.
    // Verdict / risk_score are NOT recomputed — NOVA is a community
    // pack we do not yet pin against the benchmark corpus, so its
    // findings carry SignalClass::ReviewSignal which by mapping
    // contract does not inflate the existing calibration. The
    // verdict_snapshot debug_assert below still passes because the
    // snapshot only fingerprints (package_id, verdict, risk_score).
    let nova_report = if args.no_nova {
        None
    } else {
        // Build the provider-backed NOVA `llm:` evaluator iff:
        //   1. The user opted in with `--nova-llm`; and
        //   2. `~/.skill-veil.toml` (or env vars) carries an `[llm]`
        //      section the provider chain can build from.
        // Either gate failing falls back to `NotYetWiredLlm` so the
        // scan keeps running and any rule whose `condition:` requires
        // `llm.` surfaces under `skipped_capabilities` with the
        // existing operator note.
        let nova_llm_eval = if args.nova_llm {
            build_nova_llm_eval(args.llm_provider.as_deref(), quiet)
        } else {
            None
        };
        let llm_eval_ref = nova_llm_eval
            .as_deref()
            .map(|e| e as &dyn skill_veil_core::nova::LlmEvaluator);
        // Build the native semantics evaluator iff the user opted in
        // AND the binary was compiled with the `nova-semantics`
        // feature. When the feature is off, `build_nova_semantic_eval`
        // emits a one-line note (unless `--quiet`) and returns None,
        // so the scan still runs and `SkippedCapability::Semantics`
        // surfaces for any rule that needed the semantic channel.
        let nova_sem_eval = if args.nova_semantics {
            build_nova_semantic_eval(quiet)
        } else {
            None
        };
        let sem_eval_ref = nova_sem_eval
            .as_deref()
            .map(|e| e as &dyn skill_veil_core::nova::SemanticEvaluator);
        match nova_run::evaluate_against_target(
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
        }
    };
    if let Some(report) = &nova_report {
        let by_path = report.findings_by_path();
        for result in &mut scan_result.results {
            let Some(path_str) = result
                .findings
                .first()
                .and_then(|f| f.artifact_path.clone())
                .or_else(|| {
                    result
                        .primary_findings
                        .first()
                        .and_then(|f| f.artifact_path.clone())
                })
            else {
                continue;
            };
            let key = std::path::PathBuf::from(&path_str);
            if let Some(findings) = by_path.get(&key) {
                result.findings.extend(findings.iter().cloned());
                result.primary_findings.extend(findings.iter().cloned());
            }
        }
        // If no ScanResult matched a hit's path (single-file mode
        // where the path-key match misses), append all NOVA hits to
        // the first result so they at least appear in JSON / SARIF
        // output rather than being silently dropped.
        let injected: usize = scan_result
            .results
            .iter()
            .map(|r| {
                r.findings
                    .iter()
                    .filter(|f| f.rule_id.starts_with("NOVA_"))
                    .count()
            })
            .sum();
        if injected == 0 && !report.hits.is_empty() {
            if let Some(first) = scan_result.results.first_mut() {
                for hit_findings in by_path.values() {
                    first.findings.extend(hit_findings.iter().cloned());
                    first.primary_findings.extend(hit_findings.iter().cloned());
                }
            }
        }
    }

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

    // ADR 0029: gated LLM-adjudicated taint downgrade. Opt-in
    // (default OFF) and contradictory with --no-llm-enrich (it needs
    // LLM access). Works on clones only — `scan_result` is never
    // mutated, so the `verdict_snapshot` debug-assert below stays
    // valid. Affects ONLY this appended block + the exit code.
    let adjudicated = if args.llm_adjudicate_taint && !args.no_llm_enrich {
        match crate::llm::taint_adjudication::run_taint_adjudication(
            &scan_result,
            &args.path,
            args.cache_dir.as_deref(),
            &filter_options,
            quiet,
        )? {
            Some(outcome) => {
                print!("{}", outcome.report_block);
                Some(outcome)
            }
            None => None,
        }
    } else {
        if args.llm_adjudicate_taint && args.no_llm_enrich && !quiet {
            eprintln!(
                "taint adjudication skipped: --llm-adjudicate-taint needs LLM access \
                 but --no-llm-enrich was set"
            );
        }
        None
    };

    if !args.no_promptintel_enrich {
        if let Some(pi_block) = promptintel::try_enrich_with_promptintel(
            &scan_result,
            args.cache_dir.as_deref(),
            quiet,
        )? {
            print!("{pi_block}");
        }
    }

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
    // When the ADR-0029 adjudication ran, its `effective_should_fail`
    // already ORs every non-downgraded `r.should_fail` with the
    // downgraded packages' recomputed (taint-Block→RequireApproval)
    // contribution under the operator's `--fail-on`. Otherwise the
    // legacy expression is byte-identical.
    let should_fail = match &adjudicated {
        Some(o) => o.effective_should_fail,
        None => scan_result.results.iter().any(|r| r.should_fail),
    };
    Ok(should_fail)
}
