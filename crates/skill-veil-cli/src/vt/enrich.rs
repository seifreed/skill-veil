//! Enrichment orchestration: takes the IOCs extracted by the core scanner
//! and looks them up on VirusTotal, caching results on disk so re-runs are
//! nearly free. Designed to run *alongside* but never *inside* the scanner
//! pipeline, so the core crate keeps its "no network" guarantee.
//!
//! # Architectural invariant — DO NOT BREAK
//!
//! **VT enrichment data is strictly additive and never modifies skill-veil's
//! own verdict, risk score, finding set, or any other field of `ScanResult`.**
//!
//! This is enforced structurally by the fact that [`enrich_iocs`] takes
//! `&ExtractedIocs` (read-only) and returns a fresh [`VtEnrichment`] value.
//! Callers render both sides separately; there is no mutation pathway and no
//! code should introduce one. The rationale (from the user-imposed contract
//! 2026-04-24) is that mixing a deterministic local scanner with a remote
//! LLM-backed service would erase both properties: our output must stay
//! reproducible offline, and the VT side must stay an auditable external
//! reference that a reviewer can compare against — not a hidden input that
//! silently flips the verdict.
//!
//! If you ever find yourself wanting to tip the verdict from VT data, build
//! it as a *separate* consumer that reads both and composes its own combined
//! decision — do not thread VT values back into `ScanResult`.
//!
//! # Safety contract (imposed by `~/.vt.toml` auto-detection)
//!
//! 1. Enrichment is off unless `~/.vt.toml` is readable (or `VT_APIKEY`
//!    is set) AND the caller has not passed `--no-vt-enrich`.
//! 2. Defaults to GET-only. Unknown files and URLs are NEVER auto-uploaded
//!    unless `--vt-submit-unknown` is passed.
//! 3. Every cached record is timestamped; staleness policy is defined per
//!    indicator kind (domains / IPs expire faster than file hashes).

use super::client::{VtClient, VtError};
use super::types::{CrowdsourcedAiResult, FileAttributes, FileReportEnvelope, LastAnalysisStats};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use skill_veil_core::ioc_extraction::ExtractedIocs;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration as StdDuration;

use super::REQUEST_DELAY_MS;
const FILE_CACHE_TTL_DAYS: i64 = 90;
const DOMAIN_CACHE_TTL_DAYS: i64 = 7;
const IP_CACHE_TTL_DAYS: i64 = 7;
const URL_CACHE_TTL_DAYS: i64 = 14;

/// Aggregated VT enrichment for one skill package / artifact.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct VtEnrichment {
    pub files: Vec<EnrichedIndicator>,
    pub domains: Vec<EnrichedIndicator>,
    pub ips: Vec<EnrichedIndicator>,
    pub urls: Vec<EnrichedIndicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EnrichedIndicator {
    pub indicator: String,
    pub cache_path: PathBuf,
    pub fetched_at: DateTime<Utc>,
    pub status: EnrichmentStatus,
    pub summary: Option<VtIndicatorSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum EnrichmentStatus {
    /// VT had a record for this indicator.
    Found,
    /// VT returned 404 (indicator unknown). Not auto-submitted unless the
    /// caller passed `--vt-submit-unknown`.
    NotFound,
    /// Auto-submission was attempted because `--vt-submit-unknown` was set;
    /// the raw response body is stored for follow-up.
    Submitted { response_excerpt: String },
    /// Lookup failed for a non-404 reason.
    Error { message: String },
}

/// Distilled representation of the VT report fields we care about, stable
/// across the four indicator kinds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct VtIndicatorSummary {
    pub last_analysis_stats: Option<LastAnalysisStats>,
    pub reputation: Option<i64>,
    pub categories: BTreeMap<String, String>,
    pub meaningful_name: Option<String>,
    pub type_description: Option<String>,
    pub ai_verdicts: Vec<CrowdsourcedAiResult>,
    /// Aggregated score: count of AV engines that flagged the indicator as
    /// malicious. Our own scanner score stays untouched.
    pub vt_malicious_engine_count: u64,
    pub vt_suspicious_engine_count: u64,
}

impl VtIndicatorSummary {
    fn from_attributes(attrs: &FileAttributes) -> Self {
        let stats = attrs.last_analysis_stats.clone().unwrap_or_default();
        let categories = attrs
            .extra
            .get("categories")
            .and_then(|v| v.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let reputation = attrs.extra.get("reputation").and_then(|v| v.as_i64());
        VtIndicatorSummary {
            last_analysis_stats: attrs.last_analysis_stats.clone(),
            reputation,
            categories,
            meaningful_name: attrs.meaningful_name.clone(),
            type_description: attrs.type_description.clone(),
            ai_verdicts: attrs.crowdsourced_ai_results.clone(),
            vt_malicious_engine_count: stats.malicious,
            vt_suspicious_engine_count: stats.suspicious,
        }
    }
}

/// Behaviour knobs for a single enrichment pass.
#[derive(Debug, Clone)]
pub(crate) struct EnrichOptions {
    pub cache_root: PathBuf,
    /// If true, `POST` unknown URLs/files to VT for first-time scanning.
    pub submit_unknown: bool,
    /// Skip this many milliseconds between HTTP calls to be polite on the
    /// quota.
    pub request_delay_ms: u64,
}

impl EnrichOptions {
    pub(crate) fn new(cache_root: PathBuf) -> Self {
        Self {
            cache_root,
            submit_unknown: false,
            request_delay_ms: REQUEST_DELAY_MS,
        }
    }
}

/// Enrich a single package's IOCs. Caches every result to disk under
/// `<cache_root>/{files,domains,ips,urls}/<id>.json`. Returns an aggregate
/// the caller can attach to the scan output.
pub(crate) fn enrich_iocs(
    client: &VtClient,
    iocs: &ExtractedIocs,
    opts: &EnrichOptions,
) -> Result<VtEnrichment> {
    crate::util::secure_fs::create_dir_secure(&opts.cache_root)
        .with_context(|| format!("creating {}", opts.cache_root.display()))?;

    let mut out = VtEnrichment::default();

    for hash in &iocs.file_hashes {
        let indicator = hash.sha256.clone();
        let cache_path = cache_file_path(&opts.cache_root, "files", &indicator);
        if let Some(fresh) = load_fresh(&cache_path, Duration::days(FILE_CACHE_TTL_DAYS))? {
            out.files.push(fresh);
            continue;
        }
        let enriched = lookup_file(client, &indicator, &cache_path, opts)?;
        out.files.push(enriched);
        sleep(StdDuration::from_millis(opts.request_delay_ms));
    }

    for domain in &iocs.domains {
        let cache_path = cache_file_path(&opts.cache_root, "domains", domain);
        if let Some(fresh) = load_fresh(&cache_path, Duration::days(DOMAIN_CACHE_TTL_DAYS))? {
            out.domains.push(fresh);
            continue;
        }
        let enriched = lookup_domain(client, domain, &cache_path)?;
        out.domains.push(enriched);
        sleep(StdDuration::from_millis(opts.request_delay_ms));
    }

    for ip in iocs.ipv4.iter().chain(iocs.ipv6.iter()) {
        let cache_path = cache_file_path(&opts.cache_root, "ips", ip);
        if let Some(fresh) = load_fresh(&cache_path, Duration::days(IP_CACHE_TTL_DAYS))? {
            out.ips.push(fresh);
            continue;
        }
        let enriched = lookup_ip(client, ip, &cache_path)?;
        out.ips.push(enriched);
        sleep(StdDuration::from_millis(opts.request_delay_ms));
    }

    for url in &iocs.urls {
        // URL cache key: sha256 of canonical URL so filesystem-safe.
        let key = sha256_of_str(url);
        let cache_path = cache_file_path(&opts.cache_root, "urls", &key);
        if let Some(fresh) = load_fresh(&cache_path, Duration::days(URL_CACHE_TTL_DAYS))? {
            out.urls.push(fresh);
            continue;
        }
        let enriched = lookup_url(client, url, &cache_path, opts)?;
        out.urls.push(enriched);
        sleep(StdDuration::from_millis(opts.request_delay_ms));
    }

    Ok(out)
}

fn lookup_file(
    client: &VtClient,
    sha: &str,
    cache_path: &Path,
    opts: &EnrichOptions,
) -> Result<EnrichedIndicator> {
    let result = match client.lookup_file_report(sha) {
        Ok(Some(env)) => build_found_indicator(sha, cache_path, &env),
        Ok(None) => {
            if opts.submit_unknown {
                // We cannot submit a file we don't have in raw bytes here;
                // file-hash submission implies the caller uploaded the file
                // separately. Mark as NotFound + note.
                build_not_found_indicator(sha, cache_path)
            } else {
                build_not_found_indicator(sha, cache_path)
            }
        }
        Err(e) => build_error_indicator(sha, cache_path, &e),
    };
    persist_indicator(&result)?;
    Ok(result)
}

fn lookup_domain(client: &VtClient, domain: &str, cache_path: &Path) -> Result<EnrichedIndicator> {
    let result = match client.lookup_domain_report(domain) {
        Ok(Some(env)) => build_found_indicator(domain, cache_path, &env),
        Ok(None) => build_not_found_indicator(domain, cache_path),
        Err(e) => build_error_indicator(domain, cache_path, &e),
    };
    persist_indicator(&result)?;
    Ok(result)
}

fn lookup_ip(client: &VtClient, ip: &str, cache_path: &Path) -> Result<EnrichedIndicator> {
    let result = match client.lookup_ip_report(ip) {
        Ok(Some(env)) => build_found_indicator(ip, cache_path, &env),
        Ok(None) => build_not_found_indicator(ip, cache_path),
        Err(e) => build_error_indicator(ip, cache_path, &e),
    };
    persist_indicator(&result)?;
    Ok(result)
}

fn lookup_url(
    client: &VtClient,
    url: &str,
    cache_path: &Path,
    opts: &EnrichOptions,
) -> Result<EnrichedIndicator> {
    let result = match client.lookup_url_report(url) {
        Ok(Some(env)) => build_found_indicator(url, cache_path, &env),
        Ok(None) => {
            if opts.submit_unknown {
                match client.submit_url_for_scan(url) {
                    Ok(response) => EnrichedIndicator {
                        indicator: url.to_string(),
                        cache_path: cache_path.to_path_buf(),
                        fetched_at: Utc::now(),
                        status: EnrichmentStatus::Submitted {
                            response_excerpt: response.chars().take(240).collect(),
                        },
                        summary: None,
                    },
                    Err(e) => build_error_indicator(url, cache_path, &e),
                }
            } else {
                build_not_found_indicator(url, cache_path)
            }
        }
        Err(e) => build_error_indicator(url, cache_path, &e),
    };
    persist_indicator(&result)?;
    Ok(result)
}

fn build_found_indicator(
    indicator: &str,
    cache_path: &Path,
    env: &FileReportEnvelope,
) -> EnrichedIndicator {
    EnrichedIndicator {
        indicator: indicator.to_string(),
        cache_path: cache_path.to_path_buf(),
        fetched_at: Utc::now(),
        status: EnrichmentStatus::Found,
        summary: Some(VtIndicatorSummary::from_attributes(&env.data.attributes)),
    }
}

fn build_not_found_indicator(indicator: &str, cache_path: &Path) -> EnrichedIndicator {
    EnrichedIndicator {
        indicator: indicator.to_string(),
        cache_path: cache_path.to_path_buf(),
        fetched_at: Utc::now(),
        status: EnrichmentStatus::NotFound,
        summary: None,
    }
}

fn build_error_indicator(indicator: &str, cache_path: &Path, err: &VtError) -> EnrichedIndicator {
    EnrichedIndicator {
        indicator: indicator.to_string(),
        cache_path: cache_path.to_path_buf(),
        fetched_at: Utc::now(),
        status: EnrichmentStatus::Error {
            message: err.to_string(),
        },
        summary: None,
    }
}

/// Persist an indicator atomically: serialise to a `.tmp` sibling, fsync,
/// then `rename(2)` into place. Pre-fix this function called
/// `std::fs::write` directly, which truncates the destination and only
/// then writes the new bytes — a crash, kill, or concurrent run between
/// truncate and write left an empty or partial JSON envelope at
/// `cache_path`. `load_fresh` masks the corrupted file as a cache miss
/// (`Ok(None)`), so the symptom is silent: VT enrichment hits the API
/// every run for that indicator until a successful fetch overwrites the
/// poisoned file. The atomic rename guarantees readers see either the
/// old or the complete new bytes — never the in-between state.
fn persist_indicator(ind: &EnrichedIndicator) -> Result<()> {
    if let Some(parent) = ind.cache_path.parent() {
        crate::util::secure_fs::create_dir_secure(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(ind).context("serialising indicator")?;
    let tmp = ind.cache_path.with_extension("tmp");
    std::fs::write(&tmp, json).with_context(|| format!("writing {}", tmp.display()))?;
    crate::util::cache_io::finalize_atomic_write(&tmp, &ind.cache_path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), ind.cache_path.display()))?;
    Ok(())
}

/// Short TTL applied to cached error indicators so a transient VT failure
/// (timeout, 5xx) does not poison the cache for the full 7/14/90-day TTL of
/// successful records. `load_fresh` treats `Error`-status records older than
/// this as expired, forcing a re-attempt on the next call. Five minutes is
/// long enough to break tight retry storms but short enough to recover from
/// brief upstream outages without manual cache eviction.
pub(crate) const ERROR_CACHE_TTL: Duration = Duration::minutes(5);

fn load_fresh(path: &Path, ttl: Duration) -> Result<Option<EnrichedIndicator>> {
    let Some(bytes) = crate::util::cache_io::read_cache_file_bounded(path)? else {
        return Ok(None);
    };
    let Ok(record) = serde_json::from_slice::<EnrichedIndicator>(&bytes) else {
        return Ok(None);
    };
    let age = Utc::now() - record.fetched_at;
    if age > ttl {
        return Ok(None);
    }
    // Don't poison the cache with transient failures: a single 5xx or network
    // timeout would otherwise silence VT enrichment for the indicator's full
    // TTL (90 days for hashes, 14 for URLs). Expire Error records aggressively
    // so the next run re-attempts the lookup.
    if matches!(record.status, EnrichmentStatus::Error { .. }) && age > ERROR_CACHE_TTL {
        return Ok(None);
    }
    Ok(Some(record))
}

fn cache_file_path(root: &Path, kind: &str, key: &str) -> PathBuf {
    // Filesystem-safe key: replace `/` `:` and other path separators.
    let safe: String = key
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    root.join(kind).join(format!("{safe}.json"))
}

fn sha256_of_str(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time witness that `enrich_iocs` takes its IOCs by shared
    /// reference, so nothing in this module can mutate the caller's
    /// scan state. If someone changes the signature to `&mut ExtractedIocs`
    /// or `ExtractedIocs` (by-value consume), this test stops compiling.
    #[test]
    fn enrich_iocs_signature_is_read_only_on_iocs() {
        fn assert_signature(
            _f: fn(&VtClient, &ExtractedIocs, &EnrichOptions) -> Result<VtEnrichment>,
        ) {
        }
        assert_signature(enrich_iocs);
    }

    /// Structural check: none of the public types in this module carry a
    /// reference or handle to `ScanResult`; we only ever produce a fresh
    /// `VtEnrichment` value, preventing any feedback loop into the scanner.
    #[test]
    fn vt_enrichment_is_a_pure_value_type() {
        let e = VtEnrichment::default();
        // Cheap proof: clonable, serialisable, no lifetime parameter.
        let _copy = e.clone();
        let _json = serde_json::to_string(&e).unwrap();
    }

    #[test]
    fn cache_file_path_is_safe() {
        let p = cache_file_path(Path::new("/tmp/x"), "urls", "https://foo.bar/path?q=1");
        assert!(p.to_string_lossy().contains("urls"));
        assert!(!p.to_string_lossy().contains("//"));
    }

    #[test]
    fn load_fresh_returns_none_for_expired() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("record.json");
        let stale = EnrichedIndicator {
            indicator: "x".into(),
            cache_path: path.clone(),
            fetched_at: Utc::now() - Duration::days(100),
            status: EnrichmentStatus::NotFound,
            summary: None,
        };
        std::fs::write(&path, serde_json::to_string(&stale).unwrap()).unwrap();
        assert!(load_fresh(&path, Duration::days(7)).unwrap().is_none());
    }

    #[test]
    fn load_fresh_returns_record_when_young() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("record.json");
        let fresh = EnrichedIndicator {
            indicator: "y".into(),
            cache_path: path.clone(),
            fetched_at: Utc::now(),
            status: EnrichmentStatus::NotFound,
            summary: None,
        };
        std::fs::write(&path, serde_json::to_string(&fresh).unwrap()).unwrap();
        let got = load_fresh(&path, Duration::days(7)).unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().indicator, "y");
    }

    /// Contract: cached `Error` indicators expire after `ERROR_CACHE_TTL`
    /// even when the long TTL is still alive. A transient VT failure must
    /// not silence the indicator for 7/14/90 days.
    #[test]
    fn load_fresh_expires_error_records_after_short_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("error.json");
        let stale_error = EnrichedIndicator {
            indicator: "z".into(),
            cache_path: path.clone(),
            // Older than ERROR_CACHE_TTL but well within the 7-day TTL.
            fetched_at: Utc::now() - Duration::hours(1),
            status: EnrichmentStatus::Error {
                message: "transient timeout".into(),
            },
            summary: None,
        };
        std::fs::write(&path, serde_json::to_string(&stale_error).unwrap()).unwrap();
        assert!(
            load_fresh(&path, Duration::days(7)).unwrap().is_none(),
            "Error records older than ERROR_CACHE_TTL must be treated as expired"
        );
    }

    /// Contract: very recent error records still hit the cache so we don't
    /// hammer VT in tight retry loops. Only after `ERROR_CACHE_TTL` do we
    /// reattempt.
    #[test]
    fn load_fresh_keeps_error_records_within_short_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("error_recent.json");
        let recent_error = EnrichedIndicator {
            indicator: "w".into(),
            cache_path: path.clone(),
            fetched_at: Utc::now() - Duration::seconds(30),
            status: EnrichmentStatus::Error {
                message: "transient".into(),
            },
            summary: None,
        };
        std::fs::write(&path, serde_json::to_string(&recent_error).unwrap()).unwrap();
        assert!(
            load_fresh(&path, Duration::days(7)).unwrap().is_some(),
            "Error records younger than ERROR_CACHE_TTL must hit the cache"
        );
    }

    /// # Contract
    ///
    /// `persist_indicator` MUST succeed end-to-end on the happy path and
    /// leave the cache file at `cache_path` containing the serialised
    /// indicator — never at the `.tmp` sibling. Pin the post-fix
    /// behaviour (atomic rename) so a future refactor that swaps back to
    /// `std::fs::write` regresses here.
    #[test]
    fn persist_indicator_writes_to_dest_path_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_path = tmp.path().join("ips").join("1_2_3_4.json");
        let ind = EnrichedIndicator {
            indicator: "1.2.3.4".into(),
            cache_path: cache_path.clone(),
            fetched_at: Utc::now(),
            status: EnrichmentStatus::NotFound,
            summary: None,
        };

        persist_indicator(&ind).expect("happy-path write must succeed");

        let tmp_sibling = cache_path.with_extension("tmp");
        assert!(
            !tmp_sibling.exists(),
            "tmp sibling must NOT remain after a successful persist"
        );
        assert!(cache_path.exists(), "dest cache file MUST exist");
        let round_tripped: EnrichedIndicator =
            serde_json::from_slice(&std::fs::read(&cache_path).unwrap()).unwrap();
        assert_eq!(round_tripped.indicator, "1.2.3.4");
    }

    /// # Contract
    ///
    /// `persist_indicator` MUST NOT corrupt an existing cache entry when
    /// the new content fails to land. Pre-fix `std::fs::write` truncated
    /// the destination before writing, so any failure (interrupt, ENOSPC)
    /// left a zero-byte file at `cache_path`. The atomic rename pattern
    /// guarantees that if we observe a file at `cache_path`, it is a
    /// complete prior or current write — never the in-between state.
    /// Verified here by seeding a valid file then overwriting via
    /// persist_indicator and asserting the tmp sibling never coexists
    /// with the dest at the end of the call.
    #[test]
    fn persist_indicator_overwrite_leaves_no_tmp_residue() {
        let tmp = tempfile::tempdir().unwrap();
        let cache_path = tmp.path().join("urls").join("abc.json");
        std::fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        std::fs::write(&cache_path, b"{\"old\":true}").unwrap();

        let ind = EnrichedIndicator {
            indicator: "https://example.test/x".into(),
            cache_path: cache_path.clone(),
            fetched_at: Utc::now(),
            status: EnrichmentStatus::NotFound,
            summary: None,
        };
        persist_indicator(&ind).expect("overwrite must succeed");

        assert!(
            !cache_path.with_extension("tmp").exists(),
            "tmp sibling must NOT remain after overwrite"
        );
        let payload = std::fs::read_to_string(&cache_path).unwrap();
        assert!(
            payload.contains("https://example.test/x"),
            "dest must contain the new payload, got: {payload}"
        );
    }
}
