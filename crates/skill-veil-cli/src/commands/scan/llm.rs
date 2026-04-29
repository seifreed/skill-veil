use super::cache::llm_cache_root_for;
use super::ERROR_MESSAGE_DISPLAY_CHARS;
use crate::config::{LlmProviderKind, UnifiedConfig};
use crate::llm::enrich::{
    enrich_scan_result as llm_enrich_scan_result, LlmEnrichOptions, LlmEnrichment,
    LlmPackageResult, LlmStatus, PreparedBundle,
};
use anyhow::{Context, Result};
use skill_veil_core::PackageScanResult;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Maximum chars of the SHA-256 package id rendered next to the package
/// path. 12 hex chars give ~6 bytes of entropy — enough to disambiguate
/// at human-eye scale without making the line wrap.
const PACKAGE_ID_DISPLAY_CHARS: usize = 12;
/// Maximum chars of the LLM analysis text shown in text-mode output.
/// Long enough to read the LLM's reasoning, short enough to keep a
/// terminal summary scannable; the full text is preserved in JSON.
const LLM_ANALYSIS_DISPLAY_CHARS: usize = 400;
/// Maximum chars of the raw LLM response excerpt shown when parsing
/// fails — enough to debug the schema mismatch without dumping a full
/// model response into the terminal.
const LLM_RAW_EXCERPT_DISPLAY_CHARS: usize = 160;
/// Maximum chars of an LLM provider error message before truncation.
/// Provider errors can include long backend traces; we cap them so they
/// stay readable on a single screen.
const LLM_PROVIDER_ERROR_DISPLAY_CHARS: usize = 120;

pub(super) fn try_enrich_with_llm(
    scan_result: &PackageScanResult,
    scan_path: &Path,
    provider_override: Option<LlmProviderKind>,
    cache_dir_override: Option<&Path>,
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
    // The primary SKILL.md content is the LLM's core evidence (see the
    // invariant doc-comment in `llm/prompt.rs`). A silent
    // `unwrap_or_default()` here would hand the LLM an empty string and
    // let it issue a verdict on findings alone — defeating the third-engine
    // purpose. Read fallibly and skip enrichment with a clear warning if any
    // primary cannot be read (TOCTOU between scan and enrich, permissions, etc).
    let primary_contents = match read_primary_contents_for_paths(
        scan_result
            .results
            .iter()
            .map(|r| r.metadata.path.as_path()),
    ) {
        Ok(c) => c,
        Err(err) => {
            if !quiet {
                eprintln!("LLM enrichment skipped: {err:#}");
            }
            return Ok(None);
        }
    };
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
        cache_root: llm_cache_root_for(scan_path, cache_dir_override),
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

/// Reads each path's contents, propagating any I/O failure with context.
///
/// # Contract
///
/// Returns `Err` on the first read failure — the caller MUST NOT substitute
/// an empty string for missing primary content. The LLM enrichment treats
/// `SKILL.md` as canonical evidence; a silent default would let the model
/// produce a verdict from findings only and violate the invariant in
/// `llm/prompt.rs`.
fn read_primary_contents_for_paths<I, P>(paths: I) -> Result<Vec<String>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    paths
        .into_iter()
        .map(|p| {
            let path = p.as_ref();
            std::fs::read_to_string(path).with_context(|| {
                format!(
                    "Failed to read primary SKILL.md for LLM enrichment: {}",
                    path.display()
                )
            })
        })
        .collect()
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
        // Char-aware truncation: byte indexing panics on multi-byte
        // UTF-8 boundaries. Today `package_id` is always SHA hex
        // (ASCII) but the type is `Option<String>` with no documented
        // constraint — char-take is the safe form, and it matches the
        // rendering elsewhere in this file.
        let id_owned: String = pkg
            .package_id
            .as_deref()
            .map(|s| s.chars().take(PACKAGE_ID_DISPLAY_CHARS).collect())
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
                    v.analysis
                        .chars()
                        .take(LLM_ANALYSIS_DISPLAY_CHARS)
                        .collect::<String>()
                );
            }
        }
        LlmStatus::ParseError { message } => {
            let _ = writeln!(
                out,
                "    llm verdict  : <parse-error: {}>{cached_tag}",
                message
                    .chars()
                    .take(ERROR_MESSAGE_DISPLAY_CHARS)
                    .collect::<String>()
            );
            if let Some(excerpt) = &pkg.raw_response_excerpt {
                let _ = writeln!(
                    out,
                    "    raw excerpt  : {}",
                    excerpt
                        .chars()
                        .take(LLM_RAW_EXCERPT_DISPLAY_CHARS)
                        .collect::<String>()
                );
            }
        }
        LlmStatus::ProviderError { message } => {
            let _ = writeln!(
                out,
                "    llm verdict  : <error: {}>{cached_tag}",
                message
                    .chars()
                    .take(LLM_PROVIDER_ERROR_DISPLAY_CHARS)
                    .collect::<String>()
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

#[cfg(test)]
mod tests {
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

    /// Contract: a missing primary `SKILL.md` MUST surface as an error so
    /// the caller can skip LLM enrichment. Returning an empty string would
    /// let the LLM produce a verdict on findings alone, violating the
    /// "core evidence" invariant.
    #[test]
    fn read_primary_contents_for_paths_propagates_io_error_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does_not_exist.md");
        let err = super::read_primary_contents_for_paths(std::iter::once(missing.as_path()))
            .expect_err("missing file must produce error, not empty string");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to read primary SKILL.md for LLM enrichment"),
            "error must mention LLM enrichment context: {msg}",
        );
    }

    /// Contract: existing files round-trip their contents in iteration order.
    #[test]
    fn read_primary_contents_for_paths_returns_contents_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.md");
        let b = dir.path().join("b.md");
        std::fs::write(&a, b"first").unwrap();
        std::fs::write(&b, b"second").unwrap();
        let contents =
            super::read_primary_contents_for_paths([a.as_path(), b.as_path()].iter().copied())
                .expect("both files exist");
        assert_eq!(contents, vec!["first".to_string(), "second".to_string()]);
    }
}
