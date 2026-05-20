use super::cache::llm_cache_root_for;
use super::ERROR_MESSAGE_DISPLAY_CHARS;
use crate::config::{LlmConfigSection, LlmProviderKind, UnifiedConfig};
use crate::llm::enrich::{
    enrich_scan_result as llm_enrich_scan_result, LlmEnrichOptions, LlmEnrichment,
    LlmPackageResult, LlmStatus, PreparedBundle,
};
use crate::util::terminal_safe::sanitise_for_terminal;
use anyhow::{Context, Result};
use skill_veil_core::PackageScanResult;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Truncate by char-count and strip terminal control bytes from an
/// LLM-provider-controlled string before it reaches the operator's
/// TTY.
///
/// Every field flowing out of [`LlmStatus`] (`verdict`, `analysis`,
/// `key_signals`, `raw_response_excerpt`, error `message`) is shaped
/// by the LLM provider's response body. A compromised endpoint
/// (Ollama-Cloud, LMStudio remote, MITM'd Anthropic / OpenAI) can
/// embed CSI / OSC-8 sequences in any of those fields to clear the
/// terminal, repaint a fake `Benign` verdict, or render an attacker
/// hyperlink that opens when the operator clicks the finding.
/// Mirrors the sanitisation that `commands/scan/vt.rs` applies to all
/// VirusTotal-derived strings — the LLM formatter must not be the
/// weak link in that contract.
fn safe_truncated(value: &str, max_chars: usize) -> String {
    sanitise_for_terminal(&value.chars().take(max_chars).collect::<String>())
}

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

/// Owned, borrow-free LLM enrichment inputs. Computed once
/// (`prepare_llm_inputs`) and reused across multiple
/// `enrich_scan_result` passes — the standard single-provider
/// enrichment AND, when `--llm-adjudicate-taint` is set, the
/// per-provider taint adjudication (ADR 0029). Owning the contents
/// (rather than the borrow-coupled `PreparedBundle`) is what lets the
/// adjudicator call the enrichment once per consensus provider
/// without re-reading the filesystem each time.
///
/// `primary_contents` and `supporting` are index-aligned with
/// `scan_result.results`.
pub(crate) struct LlmInputs {
    pub(crate) section: LlmConfigSection,
    pub(crate) primary_contents: Vec<String>,
    pub(crate) supporting: Vec<Vec<(PathBuf, String)>>,
    pub(crate) cache_root: PathBuf,
}

impl LlmInputs {
    /// Build a fresh `PreparedBundle` view borrowing the owned
    /// contents. `enrich_scan_result` consumes the `Vec` by value, so
    /// each provider pass needs its own view; `supporting` is cloned
    /// (already in memory — only the eligible subset reaches here
    /// under the opt-in flag).
    pub(crate) fn bundles(&self) -> Vec<PreparedBundle<'_>> {
        self.primary_contents
            .iter()
            .zip(self.supporting.iter())
            .map(|(p, s)| PreparedBundle {
                primary_content: p.as_str(),
                supporting: s.clone(),
            })
            .collect()
    }

    pub(crate) fn opts(&self, provider_override: Option<LlmProviderKind>) -> LlmEnrichOptions {
        LlmEnrichOptions {
            cache_root: self.cache_root.clone(),
            max_prompt_chars: self.section.effective_max_prompt_chars(),
            provider_override,
        }
    }
}

/// Load config + read primary and supporting artifact contents into
/// owned, borrow-free [`LlmInputs`]. `Ok(None)` (with a one-line
/// operator note unless `quiet`) when LLM enrichment is not
/// configured or a primary cannot be read — identical skip semantics
/// to the pre-refactor inline path.
pub(crate) fn prepare_llm_inputs(
    scan_result: &PackageScanResult,
    scan_path: &Path,
    cache_dir_override: Option<&Path>,
    quiet: bool,
) -> Result<Option<LlmInputs>> {
    let config = match UnifiedConfig::load() {
        Ok(cfg) => cfg,
        Err(err) => {
            if !quiet {
                eprintln!("LLM enrichment skipped: {err:#}");
            }
            return Ok(None);
        }
    };
    let Some(llm_section) = config.llm else {
        return Ok(None);
    };

    // Build supporting-artifact contents once per ScanResult. We re-read
    // from disk here (scanner already did; but keeping this in CLI avoids a
    // core-crate API change to expose cached contents).
    let mut supporting_per_result: Vec<Vec<(PathBuf, String)>> = Vec::new();
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
    for res in scan_result.results.iter() {
        let mut supporting: Vec<(PathBuf, String)> = Vec::new();
        if res.metadata.path.parent().is_some() {
            // Pre-compute the canonical primary path so we can detect the
            // primary file regardless of how `extracted_iocs.file_hashes`
            // expressed it (relative basename vs absolute path). A naive
            // PathBuf equality misses the case where `hash.path` is
            // `SKILL.md` (relative) and `metadata.path` is the absolute
            // form — letting the primary content slip into `supporting`
            // and doubling the bundle size. When canonicalization fails
            // (e.g. PermissionDenied on a restricted path), we log a
            // warning rather than silently discarding the error, since
            // the fallback path still works for exact matches.
            let primary_canon = match res.metadata.path.canonicalize() {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!(
                        "llm-enrich: cannot canonicalize {}: {e}; primary dedup may be incomplete",
                        res.metadata.path.display()
                    );
                    None
                }
            };
            for hash in &res.extracted_iocs.file_hashes {
                let support_path = match resolve_supporting_artifact_path(
                    &hash.path,
                    &res.metadata.path,
                    primary_canon.as_deref(),
                ) {
                    Ok(Some(path)) => path,
                    Ok(None) => continue,
                    Err(err) => {
                        tracing::warn!("llm-enrich: skipping {}: {err:#}", hash.path.display());
                        continue;
                    }
                };
                match std::fs::read_to_string(&support_path) {
                    Ok(c) => supporting.push((support_path, c)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                        tracing::error!(
                            "llm-enrich: permission denied reading {}: {e}",
                            support_path.display()
                        );
                    }
                    Err(e) => {
                        tracing::warn!("llm-enrich: skipping {}: {e}", support_path.display());
                    }
                }
            }
        }
        supporting_per_result.push(supporting);
    }

    Ok(Some(LlmInputs {
        section: llm_section,
        primary_contents,
        supporting: supporting_per_result,
        cache_root: llm_cache_root_for(scan_path, cache_dir_override),
    }))
}

/// Standard single-provider LLM enrichment: render the operator-
/// facing text block. Behaviour-preserving wrapper over
/// [`prepare_llm_inputs`] + [`enrich_scan_result`] +
/// [`format_llm_enrichment`].
pub(super) fn try_enrich_with_llm(
    scan_result: &PackageScanResult,
    scan_path: &Path,
    provider_override: Option<LlmProviderKind>,
    cache_dir_override: Option<&Path>,
    quiet: bool,
) -> Result<Option<String>> {
    let Some(inputs) = prepare_llm_inputs(scan_result, scan_path, cache_dir_override, quiet)?
    else {
        return Ok(None);
    };
    let opts = inputs.opts(provider_override);
    let enrichment =
        match llm_enrich_scan_result(&inputs.section, &opts, scan_result, inputs.bundles()) {
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
        && candidate.parent().is_none_or(|p| p.as_os_str().is_empty())
        && primary.ends_with(candidate)
    {
        return true;
    }
    false
}

fn resolve_supporting_artifact_path(
    candidate: &Path,
    primary: &Path,
    primary_canon: Option<&Path>,
) -> Result<Option<PathBuf>> {
    if is_primary_artifact_path(candidate, primary, primary_canon) {
        return Ok(None);
    }
    let Some(parent) = primary.parent() else {
        return Ok(None);
    };
    let package_root = parent
        .canonicalize()
        .with_context(|| format!("canonicalizing primary package dir {}", parent.display()))?;
    let candidate_path = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        parent.join(candidate)
    };
    let candidate_canon = match candidate_path.canonicalize() {
        Ok(path) => path,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "canonicalizing supporting artifact {}",
                    candidate_path.display()
                )
            });
        }
    };
    if !candidate_canon.starts_with(&package_root) {
        anyhow::bail!(
            "resolved outside primary package dir {} -> {}",
            package_root.display(),
            candidate_canon.display()
        );
    }
    if primary_canon.is_some_and(|primary| candidate_canon.as_path() == primary) {
        return Ok(None);
    }
    debug_assert!(
        candidate_canon.starts_with(&package_root),
        "supporting artifact path must stay under primary package dir"
    );
    Ok(Some(candidate_canon))
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
                // `v.verdict` is provider-controlled prose with a
                // recommended schema (`Benign|Suspicious|Malicious`)
                // but no enforcement at parse time, so it must be
                // sanitised before reaching the TTY.
                let _ = writeln!(
                    out,
                    "    llm verdict  : {} (confidence {:.2}) agreement={agreement}{turns_tag}{cached_tag}",
                    sanitise_for_terminal(&v.verdict),
                    v.confidence
                );
                if !v.key_signals.is_empty() {
                    let joined = v.key_signals.join("; ");
                    let _ = writeln!(out, "    key signals  : {}", sanitise_for_terminal(&joined));
                }
                let _ = writeln!(
                    out,
                    "    analysis     : {}",
                    safe_truncated(&v.analysis, LLM_ANALYSIS_DISPLAY_CHARS)
                );
            }
        }
        LlmStatus::ParseError { message } => {
            let _ = writeln!(
                out,
                "    llm verdict  : <parse-error: {}>{cached_tag}",
                safe_truncated(message, ERROR_MESSAGE_DISPLAY_CHARS)
            );
            if let Some(excerpt) = &pkg.raw_response_excerpt {
                let _ = writeln!(
                    out,
                    "    raw excerpt  : {}",
                    safe_truncated(excerpt, LLM_RAW_EXCERPT_DISPLAY_CHARS)
                );
            }
        }
        LlmStatus::ProviderError { message } => {
            let _ = writeln!(
                out,
                "    llm verdict  : <error: {}>{cached_tag}",
                safe_truncated(message, LLM_PROVIDER_ERROR_DISPLAY_CHARS)
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

    /// Contract: supporting artifacts inside the primary package resolve
    /// to their canonical path before content is sent to the LLM.
    #[test]
    fn resolve_supporting_artifact_path_accepts_nested_package_file() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("pkg");
        let scripts = package.join("scripts");
        std::fs::create_dir_all(&scripts).unwrap();
        let primary = package.join("SKILL.md");
        let helper = scripts.join("helper.sh");
        std::fs::write(&primary, "# skill").unwrap();
        std::fs::write(&helper, "echo ok").unwrap();
        let primary_canon = primary.canonicalize().unwrap();

        let resolved = super::resolve_supporting_artifact_path(
            std::path::Path::new("scripts/helper.sh"),
            &primary,
            Some(&primary_canon),
        )
        .unwrap()
        .expect("nested helper must resolve");

        assert_eq!(resolved, helper.canonicalize().unwrap());
    }

    /// Contract: `..` components that resolve outside the primary package
    /// are rejected before any supporting content can enter the LLM prompt.
    #[test]
    fn resolve_supporting_artifact_path_rejects_parent_escape() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("pkg");
        std::fs::create_dir_all(&package).unwrap();
        let primary = package.join("SKILL.md");
        let outside = dir.path().join("secret.txt");
        std::fs::write(&primary, "# skill").unwrap();
        std::fs::write(&outside, "secret").unwrap();
        let primary_canon = primary.canonicalize().unwrap();

        let err = super::resolve_supporting_artifact_path(
            std::path::Path::new("../secret.txt"),
            &primary,
            Some(&primary_canon),
        )
        .expect_err("parent escape must be rejected");

        assert!(format!("{err:#}").contains("outside primary package"));
    }

    /// Contract: the primary artifact itself is never included as a
    /// supporting artifact, regardless of whether it is expressed as a
    /// relative path.
    #[test]
    fn resolve_supporting_artifact_path_skips_primary_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("SKILL.md");
        std::fs::write(&primary, "# skill").unwrap();
        let primary_canon = primary.canonicalize().unwrap();

        let resolved = super::resolve_supporting_artifact_path(
            std::path::Path::new("SKILL.md"),
            &primary,
            Some(&primary_canon),
        )
        .unwrap();

        assert!(resolved.is_none());
    }

    /// Contract: symlinks in the scanned package may not smuggle outside
    /// files into the LLM prompt.
    #[cfg(unix)]
    #[test]
    fn resolve_supporting_artifact_path_rejects_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let package = dir.path().join("pkg");
        std::fs::create_dir_all(&package).unwrap();
        let primary = package.join("SKILL.md");
        let outside = dir.path().join("secret.txt");
        let link = package.join("secret-link.txt");
        std::fs::write(&primary, "# skill").unwrap();
        std::fs::write(&outside, "secret").unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        let primary_canon = primary.canonicalize().unwrap();

        let err = super::resolve_supporting_artifact_path(
            std::path::Path::new("secret-link.txt"),
            &primary,
            Some(&primary_canon),
        )
        .expect_err("symlink escape must be rejected");

        assert!(format!("{err:#}").contains("outside primary package"));
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

    use crate::llm::types::LlmVerdict;

    /// Helper: build an `LlmPackageResult` with every provider-controlled
    /// string field carrying terminal control bytes. Used by the
    /// sanitisation regression tests below.
    fn poisoned_pkg(
        status: super::LlmStatus,
        verdict: Option<LlmVerdict>,
    ) -> super::LlmPackageResult {
        use chrono::Utc;
        super::LlmPackageResult {
            package_id: Some("0123456789abcdef".to_string()),
            primary_path: std::path::PathBuf::from("/tmp/pkg/SKILL.md"),
            verdict,
            status,
            cached: false,
            prompt_chars: 0,
            raw_response_excerpt: Some("EXCERPT \x1b[2J\x1b[H FAKE OK".to_string()),
            fetched_at: Utc::now(),
            turns_used: 1,
        }
    }

    /// Contract: every provider-controlled string in a successful LLM
    /// verdict (`verdict`, `analysis`, joined `key_signals`) MUST be
    /// stripped of terminal control bytes before reaching the TTY.
    /// Pre-fix `format_llm_pkg` wrote these fields raw, so a
    /// compromised LLM endpoint (Ollama-Cloud, MITM'd OpenAI, poisoned
    /// LMStudio) could embed CSI / OSC-8 sequences to clear the
    /// terminal and repaint a fake `Benign` verdict over the operator's
    /// real output. The VT formatter already enforces this contract;
    /// the LLM formatter must mirror it.
    #[test]
    fn format_llm_pkg_strips_control_bytes_from_ok_verdict_fields() {
        let verdict = LlmVerdict {
            verdict: "malicious\x1b[2J".to_string(),
            confidence: 0.9,
            analysis: "looks bad\x07\x00 with \x1b[31m red\x1b[0m alert".to_string(),
            key_signals: vec![
                "exfil to attacker.invalid\x1b[2J".to_string(),
                "OSC8 \x1b]8;;https://evil.invalid\x07click\x1b]8;;\x07".to_string(),
            ],
            agreement_with_scanner: Some("agree".to_string()),
            insufficient_context: Vec::new(),
        };
        let pkg = poisoned_pkg(super::LlmStatus::Ok, Some(verdict));
        let mut out = String::new();
        super::format_llm_pkg(&pkg, &mut out);
        assert!(
            !out.contains('\x1b'),
            "ESC byte must not reach TTY: {out:?}"
        );
        assert!(
            !out.contains('\x07'),
            "BEL byte must not reach TTY: {out:?}"
        );
        assert!(
            !out.contains('\x00'),
            "NUL byte must not reach TTY: {out:?}"
        );
        // Printable content survives.
        assert!(out.contains("malicious"), "verdict text must remain: {out}");
        assert!(
            out.contains("looks bad"),
            "analysis text must remain: {out}"
        );
        assert!(
            out.contains("exfil to attacker.invalid"),
            "key signal text must remain: {out}"
        );
    }

    /// Contract: a `ParseError` branch renders the parser message AND
    /// the `raw_response_excerpt` — the excerpt is the raw provider
    /// body, so it MUST be sanitised. Pre-fix the excerpt was printed
    /// char-truncated but not control-stripped, so a malformed
    /// response whose first 160 chars carried CSI bytes would clear
    /// the terminal on every parse failure.
    #[test]
    fn format_llm_pkg_strips_control_bytes_from_parse_error_excerpt() {
        let pkg = poisoned_pkg(
            super::LlmStatus::ParseError {
                message: "bad json \x1b[31m at offset 12".to_string(),
            },
            None,
        );
        let mut out = String::new();
        super::format_llm_pkg(&pkg, &mut out);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
        assert!(out.contains("parse-error"));
        assert!(out.contains("EXCERPT"));
    }

    /// Contract: a `ProviderError` branch renders an error string
    /// derived from HTTP response bodies (`err.to_string()` →
    /// includes `body` from `LlmError::HttpStatus`). A hostile
    /// endpoint can return a 500 whose body is pure ANSI escapes;
    /// pre-fix this would land verbatim on the operator's TTY.
    #[test]
    fn format_llm_pkg_strips_control_bytes_from_provider_error_message() {
        let pkg = poisoned_pkg(
            super::LlmStatus::ProviderError {
                message: "HTTP 500\x1b[2J body=\x1b]8;;evil\x07click\x1b]8;;\x07".to_string(),
            },
            None,
        );
        let mut out = String::new();
        super::format_llm_pkg(&pkg, &mut out);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
        assert!(out.contains("error"));
    }
}
