//! Orchestrates LLM-based enrichment for a scan result, following the same
//! strict contract as the VT enrichment:
//!
//! # Architectural invariant — DO NOT BREAK
//!
//! **LLM enrichment is strictly additive and never modifies skill-veil's own
//! verdict, risk score, finding set, or any other field of `ScanResult`.**
//!
//! [`enrich_scan_result`] takes `&PackageScanResult` (read-only) and returns
//! a fresh [`LlmEnrichment`]. Callers render both sides separately; there is
//! no mutation pathway. If you ever find yourself wanting to tip the verdict
//! from LLM output, build it as a *separate* consumer that reads both and
//! composes its own combined decision — do not thread LLM values back into
//! `ScanResult`.
//!
//! # Safety contract (same as VT)
//!
//! 1. Enrichment is off unless `~/.skill-veil.toml` (or env vars) provide an
//!    LLM section AND the caller hasn't passed `--no-llm-enrich`.
//! 2. Cloud providers (OpenAI / Anthropic / Ollama Cloud) require an
//!    explicit API key from config or env. Local providers (Ollama local /
//!    LMStudio) default to localhost.
//! 3. Cache keys are content-addressed (SHA-256 of the prompt); re-scanning
//!    the same skill hits the cache instead of re-sending.

use super::client::LlmProvider;
use super::prompt::{
    build_followup_prompt, build_manifest_prompt, parse_verdict_json, SkillBundleInput,
};
use super::providers::build_provider;
use super::types::{LlmError, LlmPrompt, LlmVerdict};
use crate::config::{LlmConfigSection, LlmProviderKind};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use skill_veil_core::{PackageScanResult, ScanResult};
use std::path::{Path, PathBuf};

const CACHE_TTL_DAYS: i64 = 30;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct LlmEnrichment {
    pub provider: String,
    pub model: String,
    pub packages: Vec<LlmPackageResult>,
    pub prompt_chars_total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LlmPackageResult {
    pub package_id: Option<String>,
    pub primary_path: PathBuf,
    pub verdict: Option<LlmVerdict>,
    pub status: LlmStatus,
    pub cached: bool,
    pub prompt_chars: usize,
    pub raw_response_excerpt: Option<String>,
    pub fetched_at: DateTime<Utc>,
    /// 1 if the manifest prompt sufficed; 2 if the LLM requested a follow-up
    /// with full contents. Capped at 2 — no turn-3 loop.
    #[serde(default = "default_turns")]
    pub turns_used: u8,
}

fn default_turns() -> u8 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(crate) enum LlmStatus {
    Ok,
    ParseError {
        message: String,
    },
    ProviderError {
        message: String,
    },
    /// Bundle still exceeds the char budget after manifest truncation + caps.
    /// We skip the provider call to avoid HTTP 400 context overflow. The
    /// local scanner verdict remains authoritative.
    BundleTooLarge {
        user_json_chars: usize,
        budget: usize,
    },
}

pub(crate) struct LlmEnrichOptions {
    pub cache_root: PathBuf,
    pub max_prompt_chars: usize,
    pub provider_override: Option<LlmProviderKind>,
}

/// Build a bundle for a single `ScanResult`. The caller supplies the primary
/// content + supporting-artifact contents it already read during the scan.
pub(crate) struct PreparedBundle<'a> {
    pub primary_content: &'a str,
    pub supporting: Vec<(PathBuf, String)>,
}

pub(crate) fn enrich_scan_result(
    config: &LlmConfigSection,
    opts: &LlmEnrichOptions,
    scan_result: &PackageScanResult,
    bundles: Vec<PreparedBundle<'_>>,
) -> Result<LlmEnrichment> {
    // Build the provider once; reused across all packages in this scan.
    let mut effective_config = config.clone();
    if let Some(override_kind) = opts.provider_override {
        effective_config.provider = override_kind;
    }
    let provider = build_provider(&effective_config)
        .map_err(|e| anyhow::anyhow!("failed to initialise LLM provider: {e}"))?;
    let provider_name = provider.name().to_string();
    let model_name = provider.model().to_string();

    // Probe the real context window of the loaded model (Ollama / LMStudio
    // let users configure ctx at load-time, so the static model table is
    // often wrong for local providers). The probe is best-effort; the
    // config layer honors an explicit user override above the probe.
    let probed_tokens = provider.probe_context_length();
    let resolved_max_chars = effective_config.effective_max_prompt_chars_with_probe(probed_tokens);
    if let Some(tokens) = probed_tokens {
        if resolved_max_chars != opts.max_prompt_chars {
            tracing::debug!(
                "LLM probe updated max_prompt_chars: config={} → probed={resolved_max_chars} (tokens={tokens})",
                opts.max_prompt_chars,
            );
        }
    }
    let resolved_opts = LlmEnrichOptions {
        cache_root: opts.cache_root.clone(),
        max_prompt_chars: resolved_max_chars,
        provider_override: opts.provider_override,
    };

    crate::util::secure_fs::create_dir_secure(&resolved_opts.cache_root)
        .with_context(|| format!("creating {}", resolved_opts.cache_root.display()))?;

    let mut enrichment = LlmEnrichment {
        provider: provider_name.clone(),
        model: model_name.clone(),
        packages: Vec::new(),
        prompt_chars_total: 0,
    };

    // Zip results with bundles (index-matched).
    for (scan_res, bundle) in scan_result.results.iter().zip(bundles) {
        match enrich_one(
            provider.as_ref(),
            &provider_name,
            &model_name,
            &resolved_opts,
            scan_res,
            bundle,
        ) {
            Ok(pkg) => {
                enrichment.prompt_chars_total += pkg.prompt_chars;
                enrichment.packages.push(pkg);
            }
            Err(err) => {
                tracing::warn!("LLM enrichment error for result: {err:#}");
            }
        }
    }

    Ok(enrichment)
}

const MAX_REQUESTED_PATHS: usize = 10;

/// Build a provider response → (status, verdict, excerpt). Shared across
/// both turns.
fn call_provider(
    provider: &dyn LlmProvider,
    prompt: &super::types::LlmPrompt,
) -> (LlmStatus, Option<LlmVerdict>, Option<String>) {
    match provider.analyze(prompt) {
        Ok(raw) => match parse_verdict_json(&raw.content) {
            Ok(v) => (LlmStatus::Ok, Some(v), Some(trim_excerpt(&raw.content))),
            Err(msg) => (
                LlmStatus::ParseError { message: msg },
                None,
                Some(trim_excerpt(&raw.content)),
            ),
        },
        Err(LlmError::Unauthorized) => (
            LlmStatus::ProviderError {
                message: "unauthorized".into(),
            },
            None,
            None,
        ),
        Err(err) => (
            LlmStatus::ProviderError {
                message: err.to_string(),
            },
            None,
            None,
        ),
    }
}

fn enrich_one(
    provider: &dyn LlmProvider,
    provider_name: &str,
    model_name: &str,
    opts: &LlmEnrichOptions,
    scan_res: &ScanResult,
    bundle: PreparedBundle<'_>,
) -> Result<LlmPackageResult> {
    let bundle_input = SkillBundleInput {
        primary_path: &scan_res.metadata.path,
        primary_content: bundle.primary_content,
        supporting: bundle.supporting.clone(),
        our_verdict: scan_res.verdict,
        our_risk_score: scan_res.summary.risk_score,
        our_findings: &scan_res.findings,
        extracted_iocs: &scan_res.extracted_iocs,
    };

    // Turn 1: manifest prompt (path + size + preview per supporting file).
    let (manifest_prompt, manifest) = build_manifest_prompt(bundle_input, opts.max_prompt_chars);
    let combined_chars = manifest_prompt.user_json.len() + manifest_prompt.system.len();
    let mut prompt_chars = combined_chars;

    // Safety net: if the SYSTEM + USER payload exceeds the budget, skip the
    // provider call to avoid an HTTP 400 context overflow. We compare the
    // COMBINED length (system instructions are concatenated server-side
    // before tokenisation) — counting only `user_json` left ~1650 chars of
    // headroom on every call, enough to overflow tight local-provider
    // budgets when `user_json` exactly hit the cap.
    if combined_chars > opts.max_prompt_chars {
        return Ok(LlmPackageResult {
            package_id: scan_res.metadata.package_id.clone(),
            primary_path: scan_res.metadata.path.clone(),
            verdict: None,
            status: LlmStatus::BundleTooLarge {
                user_json_chars: combined_chars,
                budget: opts.max_prompt_chars,
            },
            cached: false,
            prompt_chars,
            raw_response_excerpt: None,
            fetched_at: Utc::now(),
            turns_used: 0,
        });
    }

    let cache_key_t1 = compute_cache_key(provider_name, model_name, &manifest_prompt);
    let cache_path_t1 = opts.cache_root.join(format!("{cache_key_t1}.json"));

    if let Some(fresh) = load_fresh(&cache_path_t1, Duration::days(CACHE_TTL_DAYS))? {
        return Ok(LlmPackageResult {
            cached: true,
            ..fresh
        });
    }

    let (mut status, mut verdict, mut excerpt) = call_provider(provider, &manifest_prompt);
    let mut turns_used: u8 = 1;
    let mut followup_files: Vec<(PathBuf, String)> = Vec::new();

    // Turn 2: only if turn-1 succeeded and the LLM asked for specific files
    // whose paths are in our manifest (filter out unknown paths). Capped at
    // MAX_REQUESTED_PATHS to avoid an LLM-driven DoS.
    if matches!(status, LlmStatus::Ok) {
        if let Some(v1) = &verdict {
            if !v1.insufficient_context.is_empty() {
                let manifest_paths: std::collections::BTreeSet<&str> =
                    manifest.iter().map(|m| m.path.as_str()).collect();
                let requested: Vec<String> = v1
                    .insufficient_context
                    .iter()
                    .filter(|p| manifest_paths.contains(p.as_str()))
                    .take(MAX_REQUESTED_PATHS)
                    .cloned()
                    .collect();
                if !requested.is_empty() {
                    // Look up the actual contents from the bundle.
                    let lookup: std::collections::BTreeMap<String, String> = bundle
                        .supporting
                        .iter()
                        .map(|(p, c)| (p.display().to_string(), c.clone()))
                        .collect();
                    // A path can be in `manifest_paths` (so it survived the
                    // first filter) yet absent from `lookup` if the bundle
                    // builder dropped it under the prompt-budget cap. The
                    // `filter_map` below would silently skip such requests;
                    // emit a debug trace so "turn-2 ignored my
                    // insufficient_context entry" is debuggable without
                    // re-running the whole pipeline.
                    let requested_with_contents: Vec<(PathBuf, String)> = requested
                        .into_iter()
                        .filter_map(|p| match lookup.get(&p) {
                            Some(c) => Some((PathBuf::from(&p), c.clone())),
                            None => {
                                tracing::debug!(
                                    "LLM-requested path {p:?} is in manifest but \
                                     was dropped from bundle (likely budget truncation); \
                                     skipping for turn-2"
                                );
                                None
                            }
                        })
                        .collect();
                    if !requested_with_contents.is_empty() {
                        let followup_input = SkillBundleInput {
                            primary_path: &scan_res.metadata.path,
                            primary_content: bundle.primary_content,
                            supporting: Vec::new(),
                            our_verdict: scan_res.verdict,
                            our_risk_score: scan_res.summary.risk_score,
                            our_findings: &scan_res.findings,
                            extracted_iocs: &scan_res.extracted_iocs,
                        };
                        let followup_prompt = build_followup_prompt(
                            &followup_input,
                            &requested_with_contents,
                            opts.max_prompt_chars,
                        );
                        prompt_chars +=
                            followup_prompt.user_json.len() + followup_prompt.system.len();
                        let (s2, v2, e2) = call_provider(provider, &followup_prompt);
                        status = s2;
                        verdict = v2;
                        excerpt = e2;
                        turns_used = 2;
                        followup_files = requested_with_contents;
                    }
                }
            }
        }
    }

    let result = LlmPackageResult {
        package_id: scan_res.metadata.package_id.clone(),
        primary_path: scan_res.metadata.path.clone(),
        verdict,
        status,
        cached: false,
        prompt_chars,
        raw_response_excerpt: excerpt,
        fetched_at: Utc::now(),
        turns_used,
    };

    // Persist under a key that reflects whether turn-2 fetched files.
    // Turn-1-only results stay under `cache_key_t1` so a follow-up scan
    // with the same manifest can reuse them directly. Turn-2 results
    // include the fetched-file digests in the key, so a future scan with
    // the same manifest but different turn-2 fileset (e.g. a script was
    // edited) does not get served the stale verdict.
    let cache_path = if turns_used == 2 {
        let key = compute_cache_key_with_followup(
            provider_name,
            model_name,
            &manifest_prompt,
            &followup_files,
        );
        opts.cache_root.join(format!("{key}.json"))
    } else {
        cache_path_t1
    };
    persist(&cache_path, &result)?;
    Ok(result)
}

fn compute_cache_key(provider: &str, model: &str, prompt: &LlmPrompt) -> String {
    let mut h = Sha256::new();
    h.update(provider.as_bytes());
    h.update(b"|");
    h.update(model.as_bytes());
    h.update(b"|");
    h.update(prompt.system.as_bytes());
    h.update(b"|");
    h.update(prompt.user_json.as_bytes());
    format!("{:x}", h.finalize())
}

/// Cache key that incorporates the contents of the turn-2 follow-up files
/// so a result derived from those files is not served back for a future
/// invocation that requested a *different* set of files.
///
/// Without this, two scans that produced the same manifest prompt but
/// asked the LLM for different `insufficient_context` paths would share
/// the same cache key. The first scan's turn-2 verdict (which incorporated
/// fileset A) would be served verbatim for the second (which would have
/// fetched fileset B), masking changes in those files for the full
/// `CACHE_TTL_DAYS`.
///
/// Files are sorted by path to produce a deterministic hash regardless of
/// the order the LLM listed them.
fn compute_cache_key_with_followup(
    provider: &str,
    model: &str,
    prompt: &LlmPrompt,
    followup: &[(PathBuf, String)],
) -> String {
    let mut h = Sha256::new();
    h.update(provider.as_bytes());
    h.update(b"|");
    h.update(model.as_bytes());
    h.update(b"|");
    h.update(prompt.system.as_bytes());
    h.update(b"|");
    h.update(prompt.user_json.as_bytes());
    h.update(b"|followup|");
    let mut sorted: Vec<&(PathBuf, String)> = followup.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (path, content) in sorted {
        h.update(path.display().to_string().as_bytes());
        h.update(b"=");
        let mut content_hash = Sha256::new();
        content_hash.update(content.as_bytes());
        h.update(format!("{:x}", content_hash.finalize()).as_bytes());
        h.update(b"\n");
    }
    format!("{:x}", h.finalize())
}

fn persist(path: &Path, result: &LlmPackageResult) -> Result<()> {
    if let Some(parent) = path.parent() {
        // Defensive: outer `enrich_scan_result` already creates the cache
        // root with `create_dir_secure`, but `persist` may run with a
        // path whose intermediate directory doesn't exist yet (turn-2
        // followups, future cache-path refactors). Use `create_dir_secure`
        // so any newly created intermediate is owner-only (0o700) and the
        // contract holds even when call sites diverge.
        crate::util::secure_fs::create_dir_secure(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(result).context("serialising LLM result")?;
    std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Short TTL applied to cached LLM error/parse-error records so a flapping
/// provider (rate limit, 5xx, malformed response) does not silence
/// enrichment for the full `CACHE_TTL_DAYS`. `load_fresh` re-attempts after
/// this window, while successful results keep the long TTL.
pub(crate) const ERROR_CACHE_TTL: Duration = Duration::minutes(5);

fn load_fresh(path: &Path, ttl: Duration) -> Result<Option<LlmPackageResult>> {
    let Some(bytes) = crate::util::cache_io::read_cache_file_bounded(path)? else {
        return Ok(None);
    };
    let Ok(record) = serde_json::from_slice::<LlmPackageResult>(&bytes) else {
        return Ok(None);
    };
    let age = Utc::now() - record.fetched_at;
    if age > ttl {
        return Ok(None);
    }
    // Don't poison the cache with transient errors. `BundleTooLarge` is
    // included because it usually depends on prompt-builder logic the user
    // can fix (raising the budget, simplifying the package); we want them to
    // see fresh feedback, not a 30-day-stale skip.
    if matches!(
        record.status,
        LlmStatus::ProviderError { .. }
            | LlmStatus::ParseError { .. }
            | LlmStatus::BundleTooLarge { .. }
    ) && age > ERROR_CACHE_TTL
    {
        return Ok(None);
    }
    Ok(Some(record))
}

fn trim_excerpt(s: &str) -> String {
    s.chars().take(500).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time witness: `enrich_scan_result` takes `&PackageScanResult`
    /// (shared reference), matching the VT contract. If someone changes it to
    /// `&mut` or consume-by-value, this test stops compiling.
    #[test]
    fn enrich_signature_is_read_only_on_scan_result() {
        fn assert_signature(
            _f: fn(
                &LlmConfigSection,
                &LlmEnrichOptions,
                &PackageScanResult,
                Vec<PreparedBundle<'_>>,
            ) -> Result<LlmEnrichment>,
        ) {
        }
        assert_signature(enrich_scan_result);
    }

    #[test]
    fn llm_enrichment_is_pure_value_type() {
        let e = LlmEnrichment::default();
        let _copy = e.clone();
        let _json = serde_json::to_string(&e).unwrap();
    }

    #[test]
    fn cache_key_is_stable_and_hex() {
        let p = LlmPrompt {
            system: "s".into(),
            user_json: "u".into(),
        };
        let k1 = compute_cache_key("openai", "gpt-4", &p);
        let k2 = compute_cache_key("openai", "gpt-4", &p);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 64);
        assert!(k1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn cache_key_changes_when_model_differs() {
        let p = LlmPrompt {
            system: "s".into(),
            user_json: "u".into(),
        };
        assert_ne!(
            compute_cache_key("openai", "gpt-4", &p),
            compute_cache_key("openai", "gpt-4o", &p)
        );
    }

    /// Contract: a turn-2 cache key MUST change when the contents of any
    /// follow-up file change. Without this, a future scan with the same
    /// manifest but updated supporting files would be served the stale
    /// turn-2 verdict from cache for the full TTL.
    #[test]
    fn cache_key_with_followup_changes_when_followup_files_change() {
        let p = LlmPrompt {
            system: "s".into(),
            user_json: "u".into(),
        };
        let files_v1 = vec![(
            std::path::PathBuf::from("scripts/install.sh"),
            "v1".to_string(),
        )];
        let files_v2 = vec![(
            std::path::PathBuf::from("scripts/install.sh"),
            "v2".to_string(),
        )];
        let k1 = compute_cache_key_with_followup("openai", "gpt-4", &p, &files_v1);
        let k2 = compute_cache_key_with_followup("openai", "gpt-4", &p, &files_v2);
        assert_ne!(k1, k2, "follow-up file content must change the cache key");
    }

    /// Contract: file ordering must NOT affect the key (sort by path).
    /// Two LLM responses listing the same files in different orders should
    /// reuse the same cache entry.
    #[test]
    fn cache_key_with_followup_is_stable_across_input_order() {
        let p = LlmPrompt {
            system: "s".into(),
            user_json: "u".into(),
        };
        let files_a = vec![
            (std::path::PathBuf::from("a.sh"), "x".into()),
            (std::path::PathBuf::from("b.sh"), "y".into()),
        ];
        let files_b = vec![
            (std::path::PathBuf::from("b.sh"), "y".into()),
            (std::path::PathBuf::from("a.sh"), "x".into()),
        ];
        let ka = compute_cache_key_with_followup("openai", "gpt-4", &p, &files_a);
        let kb = compute_cache_key_with_followup("openai", "gpt-4", &p, &files_b);
        assert_eq!(ka, kb);
    }

    /// Contract: turn-1-only and turn-2 keys for the same manifest MUST
    /// differ — otherwise a turn-2 result would overwrite a turn-1 cached
    /// entry under the same path, or vice versa.
    #[test]
    fn cache_key_with_empty_followup_differs_from_turn1_key() {
        let p = LlmPrompt {
            system: "s".into(),
            user_json: "u".into(),
        };
        let k_t1 = compute_cache_key("openai", "gpt-4", &p);
        let k_t2 = compute_cache_key_with_followup("openai", "gpt-4", &p, &[]);
        assert_ne!(
            k_t1, k_t2,
            "empty followup is still a turn-2 result and must use a distinct key"
        );
    }

    fn package_result_with_status(status: LlmStatus, age: chrono::Duration) -> LlmPackageResult {
        LlmPackageResult {
            primary_path: std::path::PathBuf::from("/tmp/skill.md"),
            package_id: None,
            status,
            verdict: None,
            raw_response_excerpt: None,
            cached: false,
            turns_used: 1,
            prompt_chars: 0,
            fetched_at: Utc::now() - age,
        }
    }

    /// Contract: cached `ProviderError` records expire after
    /// `ERROR_CACHE_TTL`, not the full `CACHE_TTL_DAYS` window. A flapping
    /// LLM provider must not silence enrichment for 30 days.
    #[test]
    fn load_fresh_expires_provider_errors_after_short_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("provider_err.json");
        let stale = package_result_with_status(
            LlmStatus::ProviderError {
                message: "503 upstream".into(),
            },
            // Past ERROR_CACHE_TTL but well within CACHE_TTL_DAYS.
            Duration::hours(1),
        );
        std::fs::write(&path, serde_json::to_string(&stale).unwrap()).unwrap();
        let ttl = Duration::days(super::CACHE_TTL_DAYS);
        assert!(
            load_fresh(&path, ttl).unwrap().is_none(),
            "ProviderError records older than ERROR_CACHE_TTL must expire"
        );
    }

    #[test]
    fn load_fresh_keeps_recent_errors_to_avoid_retry_storms() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("recent_err.json");
        let recent = package_result_with_status(
            LlmStatus::ProviderError {
                message: "transient".into(),
            },
            Duration::seconds(30),
        );
        std::fs::write(&path, serde_json::to_string(&recent).unwrap()).unwrap();
        let ttl = Duration::days(super::CACHE_TTL_DAYS);
        assert!(
            load_fresh(&path, ttl).unwrap().is_some(),
            "Recent errors must hit the cache to break tight retry loops"
        );
    }

    #[test]
    fn load_fresh_expires_parse_and_bundle_errors_after_short_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        for (name, status) in [
            (
                "parse",
                LlmStatus::ParseError {
                    message: "bad json".into(),
                },
            ),
            (
                "bundle",
                LlmStatus::BundleTooLarge {
                    user_json_chars: 100_000,
                    budget: 60_000,
                },
            ),
        ] {
            let path = tmp.path().join(format!("{name}.json"));
            let stale = package_result_with_status(status, Duration::hours(1));
            std::fs::write(&path, serde_json::to_string(&stale).unwrap()).unwrap();
            let ttl = Duration::days(super::CACHE_TTL_DAYS);
            assert!(
                load_fresh(&path, ttl).unwrap().is_none(),
                "{name} status older than ERROR_CACHE_TTL must expire"
            );
        }
    }

    #[test]
    fn load_fresh_keeps_successful_results_for_full_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ok.json");
        let aged_ok = package_result_with_status(LlmStatus::Ok, Duration::days(7));
        std::fs::write(&path, serde_json::to_string(&aged_ok).unwrap()).unwrap();
        let ttl = Duration::days(super::CACHE_TTL_DAYS);
        assert!(
            load_fresh(&path, ttl).unwrap().is_some(),
            "Ok results must keep the long TTL"
        );
    }

    /// # Contract
    ///
    /// `persist` MUST create any missing parent directory with owner-only
    /// permissions (`0o700` on Unix). Pre-fix the function used a bare
    /// `std::fs::create_dir_all`, honouring the process umask (typically
    /// `0o755`). On a shared host this exposed the LLM analysis cache —
    /// extracted IOCs, full LLM verdicts, primary path digests — to other
    /// local users. This test pins that the new parent directory is
    /// created via `secure_fs::create_dir_secure`.
    #[cfg(unix)]
    #[test]
    fn persist_creates_parent_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let nested = tmp.path().join("nested").join("further");
        let cache_path = nested.join("entry.json");

        let result = package_result_with_status(LlmStatus::Ok, Duration::seconds(0));
        persist(&cache_path, &result).expect("persist must succeed");

        let mode = std::fs::metadata(&nested)
            .expect("metadata on freshly created parent")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o700,
            "persist's newly created parent dir must be 0o700 (got {mode:o}); \
             this guards against a regression to bare std::fs::create_dir_all",
        );
        assert!(cache_path.exists(), "cache file must be written");
    }
}
