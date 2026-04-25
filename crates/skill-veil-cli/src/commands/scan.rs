use crate::config::{LlmProviderKind, UnifiedConfig};
use crate::llm::enrich::{
    enrich_scan_result as llm_enrich_scan_result, LlmEnrichOptions, LlmEnrichment,
    LlmPackageResult, LlmStatus, PreparedBundle,
};
use crate::text_output::{format_results, TextOutputOptions};
use crate::vt::client::VtClient;
use crate::vt::config::VtConfig;
use crate::vt::enrich::{self, EnrichOptions, EnrichedIndicator, EnrichmentStatus, VtEnrichment};
use crate::{
    cli_args::{ColorChoiceArg, PolicyProfileArg, ScanArgs, ScanPresetArg, SeverityArg},
    color::ColorMode,
};
use anyhow::{Context, Result};
use skill_veil_core::{PackageScanResult, ScanOptions, ScanTargetMode, Scanner};
use std::fmt::Write as _;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

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
        if let Some(vt_block) =
            try_enrich_with_vt(&scan_result, &args.path, args.vt_submit_unknown, quiet)?
        {
            print!("{vt_block}");
        }
    }

    if !args.no_llm_enrich {
        let llm_provider_override = args
            .llm_provider
            .as_deref()
            .and_then(LlmProviderKind::from_str_ci);
        if let Some(llm_block) =
            try_enrich_with_llm(&scan_result, &args.path, llm_provider_override, quiet)?
        {
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

fn try_enrich_with_vt(
    scan_result: &PackageScanResult,
    scan_path: &Path,
    submit_unknown: bool,
    quiet: bool,
) -> Result<Option<String>> {
    let Ok(config) = VtConfig::load() else {
        return Ok(None); // no apikey configured → silent skip
    };
    let client = VtClient::new(config);
    let cache_root = cache_root_for(scan_path);
    let opts = EnrichOptions {
        cache_root,
        submit_unknown,
        ..EnrichOptions::new(PathBuf::new())
    };

    // Consolidate IOCs across every scan result before issuing VT lookups.
    // Without this, a URL or domain that appears in N artifacts would
    // produce N redundant API calls (the cache root is per-scan, so the
    // file-backed cache only helps across separate runs, not within one).
    let consolidated = consolidate_iocs(scan_result.results.iter().map(|r| &r.extracted_iocs));
    if consolidated.is_empty() {
        return Ok(None);
    }
    let enrichment = match enrich::enrich_iocs(&client, &consolidated, &opts) {
        Ok(e) => e,
        Err(e) => {
            if !quiet {
                eprintln!("VT enrichment warning: {e:#}");
            }
            return Ok(None);
        }
    };

    let aggregate = VtEnrichment {
        files: dedupe_indicators(enrichment.files),
        domains: dedupe_indicators(enrichment.domains),
        ips: dedupe_indicators(enrichment.ips),
        urls: dedupe_indicators(enrichment.urls),
    };

    if aggregate.files.is_empty()
        && aggregate.domains.is_empty()
        && aggregate.ips.is_empty()
        && aggregate.urls.is_empty()
    {
        return Ok(None);
    }

    Ok(Some(format_vt_enrichment(&aggregate)))
}

/// Decide whether `candidate` refers to the same artifact as `primary`.
///
/// `extracted_iocs.file_hashes` may carry paths in either relative
/// (`SKILL.md`) or absolute (`/tmp/pkg/SKILL.md`) form, depending on which
/// upstream pipeline added them. A naive `PathBuf` equality check misses
/// the cross-form case and lets the primary content leak into the LLM
/// `supporting` bundle, doubling its size and triggering false
/// `BundleTooLarge` skips.
///
/// We try, in order:
/// 1. Canonical-vs-canonical equality (most robust; requires both to exist
///    on disk so we accept it only when both canonicalize successfully).
/// 2. Direct `PathBuf` equality (lexical fast path).
/// 3. Relative-form match: `candidate` is relative AND `primary` ends with
///    it AND the basenames agree.
fn is_primary_artifact_path(
    candidate: &Path,
    primary: &Path,
    primary_canon: Option<&Path>,
) -> bool {
    if let (Some(canon_primary), Ok(canon_candidate)) = (primary_canon, candidate.canonicalize()) {
        if canon_candidate == canon_primary {
            return true;
        }
    }
    if candidate == primary {
        return true;
    }
    if candidate.is_relative()
        && candidate.file_name() == primary.file_name()
        && primary.ends_with(candidate)
    {
        return true;
    }
    false
}

fn cache_root_for(scan_path: &Path) -> PathBuf {
    if scan_path.is_dir() {
        scan_path.join(".vt-enrichment")
    } else {
        scan_path
            .parent()
            .map(|p| p.join(".vt-enrichment"))
            .unwrap_or_else(|| PathBuf::from(".vt-enrichment"))
    }
}

fn llm_cache_root_for(scan_path: &Path) -> PathBuf {
    if scan_path.is_dir() {
        scan_path.join(".llm-cache")
    } else {
        scan_path
            .parent()
            .map(|p| p.join(".llm-cache"))
            .unwrap_or_else(|| PathBuf::from(".llm-cache"))
    }
}

fn try_enrich_with_llm(
    scan_result: &PackageScanResult,
    scan_path: &Path,
    provider_override: Option<LlmProviderKind>,
    quiet: bool,
) -> Result<Option<String>> {
    let Ok(config) = UnifiedConfig::load() else {
        return Ok(None);
    };
    let Some(llm_section) = config.llm else {
        return Ok(None);
    };

    // Build supporting-artifact contents once per ScanResult. We re-read
    // from disk here (scanner already did; but keeping this in CLI avoids a
    // core-crate API change to expose cached contents).
    let mut bundles: Vec<PreparedBundle<'_>> = Vec::new();
    let mut primary_contents: Vec<String> = Vec::with_capacity(scan_result.results.len());
    // First pass: read primary contents and keep them alive for the prompt build.
    for res in &scan_result.results {
        primary_contents.push(std::fs::read_to_string(&res.metadata.path).unwrap_or_default());
    }
    for (res, primary) in scan_result.results.iter().zip(primary_contents.iter()) {
        let mut supporting: Vec<(PathBuf, String)> = Vec::new();
        if let Some(parent) = res.metadata.path.parent() {
            // Pre-compute the canonical primary path so we can detect the
            // primary file regardless of how `extracted_iocs.file_hashes`
            // expressed it (relative basename vs absolute path). A naive
            // PathBuf equality misses the case where `hash.path` is
            // `SKILL.md` (relative) and `metadata.path` is the absolute
            // form — letting the primary content slip into `supporting`
            // and doubling the bundle size.
            let primary_canon = res.metadata.path.canonicalize().ok();
            for hash in &res.extracted_iocs.file_hashes {
                if is_primary_artifact_path(
                    &hash.path,
                    &res.metadata.path,
                    primary_canon.as_deref(),
                ) {
                    continue;
                }
                if let Ok(c) = std::fs::read_to_string(&hash.path) {
                    supporting.push((hash.path.clone(), c));
                } else if hash.path.is_relative() {
                    let abs = parent.join(&hash.path);
                    if is_primary_artifact_path(&abs, &res.metadata.path, primary_canon.as_deref())
                    {
                        continue;
                    }
                    if let Ok(c) = std::fs::read_to_string(&abs) {
                        supporting.push((abs, c));
                    }
                }
            }
        }
        let _ = res; // res is paired via zip in enrich; kept here for clarity
        bundles.push(PreparedBundle {
            primary_content: primary.as_str(),
            supporting,
        });
    }

    let opts = LlmEnrichOptions {
        cache_root: llm_cache_root_for(scan_path),
        max_prompt_chars: llm_section.effective_max_prompt_chars(),
        provider_override,
    };

    let enrichment = match llm_enrich_scan_result(&llm_section, &opts, scan_result, bundles) {
        Ok(e) => e,
        Err(e) => {
            if !quiet {
                eprintln!("LLM enrichment error: {e:#}");
            }
            return Ok(None);
        }
    };

    if enrichment.packages.is_empty() {
        return Ok(None);
    }

    Ok(Some(format_llm_enrichment(&enrichment)))
}

fn format_llm_enrichment(e: &LlmEnrichment) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n=== LLM Enrichment (informational; does not affect skill-veil verdict) ===",
    );
    let _ = writeln!(
        out,
        "  provider={} model={} packages={} prompt_chars_total={}",
        e.provider,
        e.model,
        e.packages.len(),
        e.prompt_chars_total,
    );
    for pkg in &e.packages {
        let _ = writeln!(out);
        // Char-aware truncation: byte indexing (`&s[..12]`) panics on
        // multi-byte UTF-8 boundaries. Today `package_id` is always SHA
        // hex (ASCII) but the type is `Option<String>` with no
        // documented constraint — char-take is the safe form, and it
        // matches the rendering elsewhere in this file.
        let id_owned: String = pkg
            .package_id
            .as_deref()
            .map(|s| s.chars().take(12).collect())
            .unwrap_or_else(|| "no-id".to_string());
        let _ = writeln!(out, "  {id_owned}… {}", pkg.primary_path.display());
        format_llm_pkg(pkg, &mut out);
    }
    out
}

fn format_llm_pkg(pkg: &LlmPackageResult, out: &mut String) {
    let cached_tag = if pkg.cached { " (cached)" } else { "" };
    let turns_tag = format!(" turns={}", pkg.turns_used);
    match &pkg.status {
        LlmStatus::Ok => {
            if let Some(v) = &pkg.verdict {
                // Distinguish "field omitted by the LLM" from the three
                // valid values explicitly. Previously a missing field
                // rendered as `?`, indistinguishable from a value the
                // operator would interpret as "unknown but present".
                let agreement = match v.agreement_with_scanner.as_deref() {
                    Some(s @ ("agree" | "disagree" | "partial")) => s,
                    Some(other) => {
                        tracing::debug!(
                            value = %other,
                            "LLM returned agreement_with_scanner outside the schema; rendering as <invalid>"
                        );
                        "<invalid>"
                    }
                    None => "<unspecified>",
                };
                let _ = writeln!(
                    out,
                    "    llm verdict  : {} (confidence {:.2}) agreement={agreement}{turns_tag}{cached_tag}",
                    v.verdict, v.confidence
                );
                if !v.key_signals.is_empty() {
                    let _ = writeln!(out, "    key signals  : {}", v.key_signals.join("; "));
                }
                let _ = writeln!(
                    out,
                    "    analysis     : {}",
                    v.analysis.chars().take(400).collect::<String>()
                );
            }
        }
        LlmStatus::ParseError { message } => {
            let _ = writeln!(
                out,
                "    llm verdict  : <parse-error: {}>{cached_tag}",
                message.chars().take(80).collect::<String>()
            );
            if let Some(excerpt) = &pkg.raw_response_excerpt {
                let _ = writeln!(
                    out,
                    "    raw excerpt  : {}",
                    excerpt.chars().take(160).collect::<String>()
                );
            }
        }
        LlmStatus::ProviderError { message } => {
            let _ = writeln!(
                out,
                "    llm verdict  : <error: {}>{cached_tag}",
                message.chars().take(120).collect::<String>()
            );
        }
        LlmStatus::BundleTooLarge {
            user_json_chars,
            budget,
        } => {
            let _ = writeln!(
                out,
                "    llm verdict  : <skipped: bundle {user_json_chars} chars exceeds budget {budget}; scanner verdict applies>{cached_tag}",
            );
        }
    }
}

/// Merge multiple `ExtractedIocs` into a single deduplicated bundle. Used
/// before issuing VT lookups so the same indicator (URL/domain/IP/hash)
/// shared by N artifacts triggers a single API call instead of N.
fn consolidate_iocs<'a>(
    sources: impl IntoIterator<Item = &'a skill_veil_core::ioc_extraction::ExtractedIocs>,
) -> skill_veil_core::ioc_extraction::ExtractedIocs {
    use skill_veil_core::ioc_extraction::{ExtractedIocs, FileHash};
    use std::collections::BTreeSet;
    let mut urls = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut ipv4 = BTreeSet::new();
    let mut ipv6 = BTreeSet::new();
    // FileHash is Eq but not Hash/Ord; dedupe via sha256 string key.
    let mut file_hashes: std::collections::BTreeMap<String, FileHash> =
        std::collections::BTreeMap::new();
    for iocs in sources {
        urls.extend(iocs.urls.iter().cloned());
        domains.extend(iocs.domains.iter().cloned());
        ipv4.extend(iocs.ipv4.iter().cloned());
        ipv6.extend(iocs.ipv6.iter().cloned());
        for fh in &iocs.file_hashes {
            file_hashes
                .entry(fh.sha256.clone())
                .or_insert_with(|| fh.clone());
        }
    }
    ExtractedIocs {
        urls: urls.into_iter().collect(),
        domains: domains.into_iter().collect(),
        ipv4: ipv4.into_iter().collect(),
        ipv6: ipv6.into_iter().collect(),
        file_hashes: file_hashes.into_values().collect(),
    }
}

fn dedupe_indicators(list: Vec<EnrichedIndicator>) -> Vec<EnrichedIndicator> {
    let mut by_indicator: std::collections::BTreeMap<String, EnrichedIndicator> =
        std::collections::BTreeMap::new();
    for item in list {
        by_indicator.entry(item.indicator.clone()).or_insert(item);
    }
    by_indicator.into_values().collect()
}

fn format_vt_enrichment(agg: &VtEnrichment) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "\n=== VirusTotal Enrichment (informational; does not affect skill-veil verdict) ==="
    );
    let _ = writeln!(
        out,
        "  files={} domains={} ips={} urls={}",
        agg.files.len(),
        agg.domains.len(),
        agg.ips.len(),
        agg.urls.len()
    );

    fn format_kind(label: &str, items: &[EnrichedIndicator], out: &mut String) {
        if items.is_empty() {
            return;
        }
        let _ = writeln!(out, "\n  {label}:");
        for ind in items {
            let status = match &ind.status {
                EnrichmentStatus::Found => "found".to_string(),
                EnrichmentStatus::NotFound => "not_found".to_string(),
                EnrichmentStatus::Submitted { .. } => "submitted".to_string(),
                EnrichmentStatus::Error { message } => {
                    format!("error: {}", message.chars().take(80).collect::<String>())
                }
            };
            let summary = ind
                .summary
                .as_ref()
                .map(|s| {
                    let stats = s.last_analysis_stats.clone().unwrap_or_default();
                    let ai = s
                        .ai_verdicts
                        .iter()
                        .map(|a| format!("{}={}", a.source, a.verdict))
                        .collect::<Vec<_>>()
                        .join(",");
                    let rep = s
                        .reputation
                        .map(|r| format!(" rep={r}"))
                        .unwrap_or_default();
                    format!(
                        " mal={} susp={} harmless={}{}{}",
                        stats.malicious,
                        stats.suspicious,
                        stats.harmless,
                        rep,
                        if ai.is_empty() {
                            "".to_string()
                        } else {
                            format!(" ai=[{ai}]")
                        }
                    )
                })
                .unwrap_or_default();
            let _ = writeln!(out, "    - {} [{status}]{}", ind.indicator, summary);
        }
    }

    format_kind("Files", &agg.files, &mut out);
    format_kind("Domains", &agg.domains, &mut out);
    format_kind("IPs", &agg.ips, &mut out);
    format_kind("URLs", &agg.urls, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_veil_core::ioc_extraction::{ExtractedIocs, FileHash};
    use std::path::PathBuf;

    /// Contract: a relative path like `SKILL.md` with a matching basename
    /// MUST be treated as the primary artifact when the absolute primary
    /// ends with it. Without this, `try_enrich_with_llm` doubled the
    /// bundle size by including the primary content in `supporting`.
    #[test]
    fn is_primary_artifact_path_matches_relative_basename_against_absolute_primary() {
        let primary = std::path::PathBuf::from("/tmp/pkg/SKILL.md");
        let candidate = std::path::PathBuf::from("SKILL.md");
        assert!(super::is_primary_artifact_path(&candidate, &primary, None));
    }

    #[test]
    fn is_primary_artifact_path_rejects_unrelated_basename() {
        let primary = std::path::PathBuf::from("/tmp/pkg/SKILL.md");
        let candidate = std::path::PathBuf::from("scripts/install.sh");
        assert!(!super::is_primary_artifact_path(&candidate, &primary, None));
    }

    #[test]
    fn is_primary_artifact_path_rejects_same_basename_in_subdir() {
        // helpers/SKILL.md is a different file with the same basename;
        // primary "/tmp/pkg/SKILL.md" does NOT end with "helpers/SKILL.md",
        // so the multi-component check correctly rejects.
        let primary = std::path::PathBuf::from("/tmp/pkg/SKILL.md");
        let candidate = std::path::PathBuf::from("helpers/SKILL.md");
        assert!(!super::is_primary_artifact_path(&candidate, &primary, None));
    }

    #[test]
    fn is_primary_artifact_path_handles_lexical_equality() {
        let primary = std::path::PathBuf::from("/tmp/pkg/SKILL.md");
        let candidate = primary.clone();
        assert!(super::is_primary_artifact_path(&candidate, &primary, None));
    }

    #[test]
    fn consolidate_iocs_deduplicates_across_results() {
        let a = ExtractedIocs {
            urls: vec![
                "https://evil.com/x".to_string(),
                "https://example.org".to_string(),
            ],
            domains: vec!["evil.com".to_string()],
            ipv4: vec!["10.0.0.1".to_string()],
            ipv6: Vec::new(),
            file_hashes: vec![FileHash {
                path: PathBuf::from("a.py"),
                sha256: "deadbeef".to_string(),
            }],
        };
        let b = ExtractedIocs {
            urls: vec!["https://evil.com/x".to_string()], // dup of a
            domains: vec!["evil.com".to_string()],        // dup of a
            ipv4: vec!["10.0.0.2".to_string()],
            ipv6: Vec::new(),
            file_hashes: vec![FileHash {
                path: PathBuf::from("b.py"),
                sha256: "deadbeef".to_string(), // dup sha256 of a
            }],
        };
        let merged = consolidate_iocs([&a, &b]);
        assert_eq!(merged.urls.len(), 2, "duplicate URL must collapse");
        assert_eq!(merged.domains.len(), 1);
        assert_eq!(merged.ipv4.len(), 2);
        assert_eq!(merged.file_hashes.len(), 1, "same sha256 collapses");
    }
}
