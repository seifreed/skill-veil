//! Persistent cache for LLM enrichment results.
//!
//! Extracted from `enrich.rs` so the orchestration layer stays focused on
//! turn coordination and the cache layer owns key derivation, TTL policy,
//! and on-disk I/O. The contract is unchanged from the inline version:
//!
//! - **Cache keys are content-addressed.** A SHA-256 of `(provider, model,
//!   sampling_fingerprint, system, user_json)` for turn-1; a follow-up
//!   variant additionally hashes the requested file set, sorted by path.
//!   The sampling fingerprint covers every per-call inference parameter
//!   the provider bakes into outbound requests (temperature, max_tokens,
//!   …). Without it, two scans with the same prompt but different
//!   `temperature` config would share a key and the second scan would
//!   reuse the first scan's verdict for the full `CACHE_TTL_DAYS` window.
//! - **Successful results live for `CACHE_TTL_DAYS`.** Provider errors,
//!   parse errors, and `BundleTooLarge` records expire after
//!   `ERROR_CACHE_TTL` so a flapping provider does not silence enrichment
//!   for the full long-TTL window.
//! - **Parents are created with `secure_fs::create_dir_secure`** (owner-only
//!   `0o700` on Unix) — the cache contains LLM verdicts and digested IOC
//!   payloads and must not leak to other local users on shared hosts.

use super::enrich::{LlmPackageResult, LlmStatus};
use super::types::LlmPrompt;
use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Long TTL applied to successful (`Ok`) enrichment records. Re-scanning the
/// same skill within this window reuses the cached verdict instead of
/// re-prompting the provider.
pub(crate) const CACHE_TTL_DAYS: i64 = 30;

/// Short TTL applied to cached error / parse-error / bundle-too-large
/// records so a flapping provider does not silence enrichment for the full
/// `CACHE_TTL_DAYS`. `load_fresh` re-attempts after this window, while
/// successful results keep the long TTL.
pub(crate) const ERROR_CACHE_TTL: Duration = Duration::minutes(5);

/// Compute the content-addressed cache key for a turn-1 manifest prompt.
///
/// `sampling_fingerprint` MUST encode every per-call inference parameter
/// the provider bakes into the outbound request (temperature, max_tokens,
/// top_p, …). Two scans whose prompt content is identical but whose
/// sampling parameters differ produce different keys, so a user who
/// changed `temperature` between scans does not get served the prior
/// verdict for the full `CACHE_TTL_DAYS` window.
pub(crate) fn compute_cache_key(
    provider: &str,
    model: &str,
    sampling_fingerprint: &str,
    prompt: &LlmPrompt,
) -> String {
    let mut h = Sha256::new();
    h.update(provider.as_bytes());
    h.update(b"|");
    h.update(model.as_bytes());
    h.update(b"|sampling=");
    h.update(sampling_fingerprint.as_bytes());
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
pub(crate) fn compute_cache_key_with_followup(
    provider: &str,
    model: &str,
    sampling_fingerprint: &str,
    prompt: &LlmPrompt,
    followup: &[(PathBuf, String)],
) -> String {
    let mut h = Sha256::new();
    h.update(provider.as_bytes());
    h.update(b"|");
    h.update(model.as_bytes());
    h.update(b"|sampling=");
    h.update(sampling_fingerprint.as_bytes());
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

/// Write `result` to `path`, creating any missing parent with owner-only
/// permissions on Unix. Defensive: outer callers already create the cache
/// root with `create_dir_secure`, but follow-up cache paths and future
/// refactors may write into not-yet-created intermediates — `persist` MUST
/// keep the `0o700` invariant on whatever directory it materialises.
///
/// # Atomicity contract
///
/// The serialised JSON is staged at `path.with_extension("tmp")` and then
/// renamed onto `path` via `cache_io::finalize_atomic_write`. A bare
/// `std::fs::write` truncates the destination before writing, so any
/// failure (SIGKILL, ENOSPC, power loss) leaves a zero-byte or partial
/// JSON at `path`; `load_fresh` then masks that corruption as a cache miss
/// and the provider is re-prompted on every subsequent run. The atomic
/// rename guarantees readers see either the prior complete bytes or the
/// new complete bytes — never the in-between state. Mirrors the
/// `vt::enrich::persist_indicator` contract pinned by
/// `persist_indicator_writes_to_dest_path_atomically`.
pub(crate) fn persist(path: &Path, result: &LlmPackageResult) -> Result<()> {
    if let Some(parent) = path.parent() {
        crate::util::secure_fs::create_dir_secure(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(result).context("serialising LLM result")?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, json).with_context(|| format!("writing {}", tmp.display()))?;
    crate::util::cache_io::finalize_atomic_write(&tmp, path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Read `path` if present and fresher than `ttl`, applying the
/// `ERROR_CACHE_TTL` short-circuit for non-`Ok` records.
///
/// Returns `Ok(None)` for missing files, malformed JSON, expired records,
/// or expired error records — callers re-prompt on `None` and reuse on
/// `Some`.
pub(crate) fn load_fresh(path: &Path, ttl: Duration) -> Result<Option<LlmPackageResult>> {
    let Some(bytes) = crate::util::cache_io::read_cache_file_bounded(path)? else {
        return Ok(None);
    };
    let Ok(record) = serde_json::from_slice::<LlmPackageResult>(&bytes) else {
        return Ok(None);
    };
    let age = Utc::now() - record.fetched_at;
    // A future-dated fetched_at (clock skew or tampering) produces a
    // negative age, which never exceeds the TTL — freezing the entry
    // forever. Treat negative ages as expired (fail-closed).
    if age > ttl || age < chrono::Duration::zero() {
        return Ok(None);
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn package_result_with_status(status: LlmStatus, age: Duration) -> LlmPackageResult {
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

    const TEST_SAMPLING_FP: &str = "max_tokens=1024;temperature=0.1";

    /// Contract: keys are deterministic SHA-256 hex digests (64 lowercase
    /// hex chars). Two calls with the same inputs MUST produce the same
    /// key — the cache reuse path depends on it.
    #[test]
    fn cache_key_is_stable_and_hex() {
        let p = LlmPrompt {
            system: "s".into(),
            user_json: "u".into(),
        };
        let k1 = compute_cache_key("openai", "gpt-4", TEST_SAMPLING_FP, &p);
        let k2 = compute_cache_key("openai", "gpt-4", TEST_SAMPLING_FP, &p);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 64);
        assert!(k1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Contract: the model component MUST participate in the key. A
    /// different model string MUST produce a different key — otherwise
    /// switching from `gpt-4` to `gpt-4o` would serve stale verdicts.
    #[test]
    fn cache_key_changes_when_model_differs() {
        let p = LlmPrompt {
            system: "s".into(),
            user_json: "u".into(),
        };
        assert_ne!(
            compute_cache_key("openai", "gpt-4", TEST_SAMPLING_FP, &p),
            compute_cache_key("openai", "gpt-4o", TEST_SAMPLING_FP, &p)
        );
    }

    /// Contract: the sampling fingerprint MUST participate in the key.
    /// Two scans with identical prompt content but different
    /// `temperature` / `max_tokens` config MUST hash to different keys —
    /// without this, the second scan would receive the first scan's
    /// verdict for the full `CACHE_TTL_DAYS` window despite the user
    /// having deliberately changed inference behaviour. Pre-fix the
    /// cache key omitted these values entirely.
    #[test]
    fn cache_key_changes_when_sampling_fingerprint_differs() {
        let p = LlmPrompt {
            system: "s".into(),
            user_json: "u".into(),
        };
        let lo = compute_cache_key("openai", "gpt-4", "max_tokens=1024;temperature=0.1", &p);
        let hi = compute_cache_key("openai", "gpt-4", "max_tokens=1024;temperature=0.7", &p);
        assert_ne!(
            lo, hi,
            "different temperature MUST produce a different cache key",
        );
        let mt = compute_cache_key("openai", "gpt-4", "max_tokens=2048;temperature=0.1", &p);
        assert_ne!(
            lo, mt,
            "different max_tokens MUST produce a different cache key",
        );
    }

    /// # Contract
    ///
    /// `base_url` MUST participate in the sampling fingerprint of every
    /// HTTP-based provider. Two scans against the same model at different
    /// endpoints (cloud vs a `127.0.0.1` mitm proxy, two Ollama daemons)
    /// MUST hash to different keys — otherwise a developer who reconfigures
    /// `base_url` to inspect prompts via a local proxy receives the prior
    /// run's cloud verdict for the full TTL window, defeating the proxy
    /// entirely. Pre-fix `sampling_fingerprint` covered only `max_tokens`
    /// and `temperature`. The fingerprints below mirror the values produced
    /// by the production providers; this test pins that future refactors
    /// do not silently drop `base_url` from the fingerprint.
    #[test]
    fn cache_key_changes_when_base_url_differs() {
        let p = LlmPrompt {
            system: "s".into(),
            user_json: "u".into(),
        };
        let cloud = "base_url=https://api.anthropic.com/v1;max_tokens=1024;temperature=0.1";
        let proxy = "base_url=http://127.0.0.1:8080;max_tokens=1024;temperature=0.1";
        assert_ne!(
            compute_cache_key("anthropic", "claude-sonnet-4-5", cloud, &p),
            compute_cache_key("anthropic", "claude-sonnet-4-5", proxy, &p),
            "different base_url MUST produce a different cache key",
        );
        // Same contract holds for the follow-up variant.
        assert_ne!(
            compute_cache_key_with_followup("anthropic", "claude-sonnet-4-5", cloud, &p, &[]),
            compute_cache_key_with_followup("anthropic", "claude-sonnet-4-5", proxy, &p, &[]),
            "different base_url MUST produce a different turn-2 cache key",
        );
    }

    /// Contract: same key applies to the turn-2 / follow-up variant —
    /// changing `temperature` between scans MUST produce a different key
    /// even when the manifest prompt and follow-up files are identical.
    #[test]
    fn cache_key_with_followup_changes_when_sampling_fingerprint_differs() {
        let p = LlmPrompt {
            system: "s".into(),
            user_json: "u".into(),
        };
        let files = vec![(std::path::PathBuf::from("a.sh"), "x".into())];
        let lo = compute_cache_key_with_followup(
            "openai",
            "gpt-4",
            "max_tokens=1024;temperature=0.1",
            &p,
            &files,
        );
        let hi = compute_cache_key_with_followup(
            "openai",
            "gpt-4",
            "max_tokens=1024;temperature=0.7",
            &p,
            &files,
        );
        assert_ne!(
            lo, hi,
            "different temperature MUST produce a different turn-2 cache key",
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
        let k1 =
            compute_cache_key_with_followup("openai", "gpt-4", TEST_SAMPLING_FP, &p, &files_v1);
        let k2 =
            compute_cache_key_with_followup("openai", "gpt-4", TEST_SAMPLING_FP, &p, &files_v2);
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
        let ka = compute_cache_key_with_followup("openai", "gpt-4", TEST_SAMPLING_FP, &p, &files_a);
        let kb = compute_cache_key_with_followup("openai", "gpt-4", TEST_SAMPLING_FP, &p, &files_b);
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
        let k_t1 = compute_cache_key("openai", "gpt-4", TEST_SAMPLING_FP, &p);
        let k_t2 = compute_cache_key_with_followup("openai", "gpt-4", TEST_SAMPLING_FP, &p, &[]);
        assert_ne!(
            k_t1, k_t2,
            "empty followup is still a turn-2 result and must use a distinct key"
        );
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
        let ttl = Duration::days(CACHE_TTL_DAYS);
        assert!(
            load_fresh(&path, ttl).unwrap().is_none(),
            "ProviderError records older than ERROR_CACHE_TTL must expire"
        );
    }

    /// Contract: a freshly written error record is reused on subsequent
    /// scans within `ERROR_CACHE_TTL`, breaking tight retry loops against
    /// a transiently-failing provider.
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
        let ttl = Duration::days(CACHE_TTL_DAYS);
        assert!(
            load_fresh(&path, ttl).unwrap().is_some(),
            "Recent errors must hit the cache to break tight retry loops"
        );
    }

    /// Contract: parse-error and bundle-too-large records share the
    /// `ERROR_CACHE_TTL` short window with provider errors — they all
    /// describe transient or fixable conditions, not stable verdicts.
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
            let ttl = Duration::days(CACHE_TTL_DAYS);
            assert!(
                load_fresh(&path, ttl).unwrap().is_none(),
                "{name} status older than ERROR_CACHE_TTL must expire"
            );
        }
    }

    /// Contract: `Ok` records honor the long TTL — they describe a stable
    /// verdict the provider already produced, so reuse for `CACHE_TTL_DAYS`
    /// is the desired behavior.
    #[test]
    fn load_fresh_keeps_successful_results_for_full_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("ok.json");
        let aged_ok = package_result_with_status(LlmStatus::Ok, Duration::days(7));
        std::fs::write(&path, serde_json::to_string(&aged_ok).unwrap()).unwrap();
        let ttl = Duration::days(CACHE_TTL_DAYS);
        assert!(
            load_fresh(&path, ttl).unwrap().is_some(),
            "Ok results must keep the long TTL"
        );
    }

    /// Contract: `persist` MUST land the serialised LLM result at
    /// `cache_path` via an atomic rename — never via a truncate-then-write
    /// path. Pre-fix `std::fs::write` truncated the destination before
    /// writing, so a SIGKILL / ENOSPC / power loss between truncate and
    /// completion left a zero-byte or partial JSON at the destination.
    /// `load_fresh` then served that as a cache miss and the LLM provider
    /// was re-prompted for every package on every subsequent run. The
    /// atomic rename pattern guarantees readers see either the prior
    /// complete bytes or the new complete bytes — never the in-between
    /// state. Mirrors `vt::enrich::persist_indicator_writes_to_dest_path_atomically`.
    #[test]
    fn persist_writes_to_dest_path_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_path = tmp.path().join("ok.json");
        let result = package_result_with_status(LlmStatus::Ok, Duration::seconds(0));

        persist(&cache_path, &result).expect("happy-path write must succeed");

        let tmp_sibling = cache_path.with_extension("tmp");
        assert!(
            !tmp_sibling.exists(),
            "the .tmp staging file must not survive a successful persist"
        );
        assert!(cache_path.exists(), "cache file must be present at dest");
        let bytes = std::fs::read(&cache_path).unwrap();
        let parsed: LlmPackageResult = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            parsed.primary_path,
            std::path::PathBuf::from("/tmp/skill.md")
        );
    }

    /// Contract: overwriting an existing cache entry MUST NOT leave a
    /// `.tmp` sibling on disk. Together with the atomicity test above,
    /// this pins that a future refactor swapping back to `std::fs::write`
    /// regresses here — the `.tmp` would either coexist with `dest` or
    /// land at the wrong path entirely.
    #[test]
    fn persist_overwrite_leaves_no_tmp_residue() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_path = tmp.path().join("ok.json");
        std::fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        std::fs::write(&cache_path, b"{}").unwrap();

        let fresh = package_result_with_status(LlmStatus::Ok, Duration::seconds(0));
        persist(&cache_path, &fresh).expect("overwrite must succeed");

        assert!(
            !cache_path.with_extension("tmp").exists(),
            ".tmp sibling must not survive an overwrite"
        );
        assert!(cache_path.exists(), "dest file must remain present");
    }

    /// Contract: `persist` MUST create any missing parent directory with
    /// owner-only permissions (`0o700` on Unix). Pre-fix the function used
    /// a bare `std::fs::create_dir_all`, honouring the process umask
    /// (typically `0o755`). On a shared host this exposed the LLM
    /// analysis cache — extracted IOCs, full LLM verdicts, primary path
    /// digests — to other local users. This test pins that the new parent
    /// directory is created via `secure_fs::create_dir_secure`.
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
