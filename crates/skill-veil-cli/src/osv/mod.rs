//! OSV.dev CVE lookup for declared dependencies (advisory enrichment).
//!
//! Consumes the offline dependency inventory the core attaches to each
//! `ScanResult` and queries the public OSV.dev API for known advisories.
//! Opt-in (`--osv` flag or `SKILL_VEIL_OSV=1`); no API key required.
//!
//! **Advisory only.** Like the VirusTotal block, this never mutates the
//! scan result and cannot influence the skill-veil verdict, risk score, or
//! exit code — it appends a human-readable text block. Any network failure
//! degrades to a one-line operator note and an empty result.
//!
//! Only dependencies pinned to an exact version are queried, so the API
//! answers the precise question "is *this* version affected"; range-only
//! specs are reported as skipped rather than producing noisy
//! package-wide advisory dumps.

mod cache;
mod client;
mod render;
mod types;

use anyhow::Result;
use skill_veil_core::{Ecosystem, PackageScanResult, ParsedDependency};
use std::collections::BTreeMap;
use std::path::Path;

use cache::OsvCache;
use client::OsvClient;
use types::{DependencyAdvisories, OsvQuery, ResolvedAdvisory};

use crate::config::{OsvSettings, UnifiedConfig};

const ACTIVATION_ENV_VAR: &str = "SKILL_VEIL_OSV";
const OFFLINE_ENV_VAR: &str = "SKILL_VEIL_OSV_OFFLINE";
/// Upper bound on unique advisory IDs hydrated with full details in one run,
/// so a package with a pathological advisory count cannot fan out unbounded
/// detail requests.
const MAX_ADVISORY_DETAILS: usize = 100;

fn env_truthy(var: &str) -> bool {
    std::env::var(var)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// Resolve whether OSV enrichment runs: the `--osv` flag, the
/// `SKILL_VEIL_OSV` env var, or `[osv] enable = true` in `~/.skill-veil.toml`.
#[must_use]
fn resolve_enabled(flag: bool, settings: &OsvSettings) -> bool {
    flag || settings.enabled || env_truthy(ACTIVATION_ENV_VAR)
}

/// Run OSV enrichment. Returns the rendered advisory block, or `None` when
/// disabled, when there are no pinned dependencies, or when the lookup fails
/// (the failure is reported to stderr unless `quiet`).
///
/// Results are cached on disk with a TTL (`[osv] cache_ttl_days`); in offline
/// mode (`[osv] offline` or `SKILL_VEIL_OSV_OFFLINE=1`) only the cache is
/// consulted and no network call is made.
pub(crate) fn try_enrich_with_osv(
    scan_result: &PackageScanResult,
    flag: bool,
    cache_dir_override: Option<&Path>,
    quiet: bool,
) -> Result<Option<String>> {
    let settings = UnifiedConfig::load().map(|c| c.osv).unwrap_or_default();
    if !resolve_enabled(flag, &settings) {
        return Ok(None);
    }

    let (pinned, skipped) = partition_dependencies(scan_result);
    if pinned.is_empty() {
        return Ok(None);
    }

    let offline = settings.offline || env_truthy(OFFLINE_ENV_VAR);
    let cache = OsvCache::new(cache_dir_override, settings.cache_ttl_days);

    let ids_per_dep = resolve_advisory_ids(&pinned, cache.as_ref(), offline, quiet);
    let advisories = hydrate_advisories(&pinned, &ids_per_dep, cache.as_ref(), offline);

    if advisories.is_empty() && offline {
        // Nothing cached yet and we are not allowed to fetch — stay silent
        // rather than emit an empty "0 advisories" block.
        return Ok(None);
    }
    Ok(Some(render::render(&advisories, pinned.len(), skipped)))
}

/// Resolve advisory IDs for every pinned dependency, serving cache hits first
/// and batching the misses into a single network call (unless offline).
fn resolve_advisory_ids(
    pinned: &[ParsedDependency],
    cache: Option<&OsvCache>,
    offline: bool,
    quiet: bool,
) -> Vec<Option<Vec<String>>> {
    let mut ids_per_dep: Vec<Option<Vec<String>>> = vec![None; pinned.len()];
    let mut misses = Vec::new();
    for (i, dep) in pinned.iter().enumerate() {
        let version = dep.version.as_deref().unwrap_or("");
        match cache.and_then(|c| c.get_query(dep.ecosystem, &dep.name, version)) {
            Some(ids) => ids_per_dep[i] = Some(ids),
            None => misses.push(i),
        }
    }

    if misses.is_empty() || offline {
        return ids_per_dep;
    }

    let queries: Vec<OsvQuery> = misses
        .iter()
        .map(|&i| OsvQuery {
            name: pinned[i].name.clone(),
            version: pinned[i].version.clone().unwrap_or_default(),
            ecosystem: pinned[i].ecosystem,
        })
        .collect();

    match OsvClient::new().query_batch(&queries) {
        Ok(batch) => {
            for (&i, ids) in misses.iter().zip(batch) {
                if let Some(cache) = cache {
                    let version = pinned[i].version.as_deref().unwrap_or("");
                    cache.put_query(pinned[i].ecosystem, &pinned[i].name, version, &ids);
                }
                ids_per_dep[i] = Some(ids);
            }
        }
        Err(e) => {
            if !quiet {
                eprintln!("OSV enrichment warning: {e:#}");
            }
        }
    }
    ids_per_dep
}

/// Hydrate advisory IDs into full advisories, using the details cache and
/// (unless offline) the network, deduplicating detail fetches across deps.
fn hydrate_advisories(
    pinned: &[ParsedDependency],
    ids_per_dep: &[Option<Vec<String>>],
    cache: Option<&OsvCache>,
    offline: bool,
) -> Vec<DependencyAdvisories> {
    let mut fetch = |id: &str| OsvClient::new().advisory_details(id).ok();
    hydrate_with(pinned, ids_per_dep, cache, offline, &mut fetch)
}

/// Core of [`hydrate_advisories`], generic over the detail fetcher so the
/// network-fetch budget can be exercised deterministically in tests.
///
/// The `MAX_ADVISORY_DETAILS` cap counts only actual network fetches: cache
/// hits and `id_only` fallbacks are memoised for dedup but never consume the
/// budget, so a large set of already-cached advisories cannot starve an
/// uncached one of its single fetch.
fn hydrate_with<F: FnMut(&str) -> Option<ResolvedAdvisory>>(
    pinned: &[ParsedDependency],
    ids_per_dep: &[Option<Vec<String>>],
    cache: Option<&OsvCache>,
    offline: bool,
    fetch: &mut F,
) -> Vec<DependencyAdvisories> {
    let mut memo: BTreeMap<String, ResolvedAdvisory> = BTreeMap::new();
    let mut fetched = 0usize;
    let mut out = Vec::new();
    for (dep, ids) in pinned.iter().zip(ids_per_dep) {
        let Some(ids) = ids else { continue };
        if ids.is_empty() {
            continue;
        }
        let mut resolved = Vec::new();
        for id in ids {
            resolved.push(resolve_one_detail(
                id,
                cache,
                offline,
                &mut memo,
                &mut fetched,
                fetch,
            ));
        }
        out.push(DependencyAdvisories {
            name: dep.name.clone(),
            version: dep.version.clone().unwrap_or_default(),
            ecosystem: dep.ecosystem,
            advisories: resolved,
        });
    }
    out
}

fn resolve_one_detail<F: FnMut(&str) -> Option<ResolvedAdvisory>>(
    id: &str,
    cache: Option<&OsvCache>,
    offline: bool,
    memo: &mut BTreeMap<String, ResolvedAdvisory>,
    fetched: &mut usize,
    fetch: &mut F,
) -> ResolvedAdvisory {
    if let Some(hit) = memo.get(id) {
        return hit.clone();
    }
    let detail = cache
        .and_then(|c| c.get_details(id))
        .or_else(|| fetch_and_cache_detail(id, cache, offline, fetched, fetch))
        .unwrap_or_else(|| ResolvedAdvisory::id_only(id));
    memo.insert(id.to_string(), detail.clone());
    detail
}

fn fetch_and_cache_detail<F: FnMut(&str) -> Option<ResolvedAdvisory>>(
    id: &str,
    cache: Option<&OsvCache>,
    offline: bool,
    fetched: &mut usize,
    fetch: &mut F,
) -> Option<ResolvedAdvisory> {
    if offline || *fetched >= MAX_ADVISORY_DETAILS {
        return None;
    }
    *fetched += 1;
    let detail = fetch(id)?;
    if let Some(cache) = cache {
        cache.put_details(id, &detail);
    }
    Some(detail)
}

/// Split the package's dependencies into exact-pinned (queryable) and
/// range/unpinned (skipped), deduplicating across all scanned artifacts.
fn partition_dependencies(scan_result: &PackageScanResult) -> (Vec<ParsedDependency>, usize) {
    partition_deps(
        scan_result
            .results
            .iter()
            .flat_map(|r| r.dependencies.iter().cloned()),
    )
}

/// Dedup `(ecosystem, name, version)` and split into exact-pinned (kept) and
/// unpinned (counted as skipped). Factored out of [`partition_dependencies`]
/// so the dedup/partition contract is testable without a full `ScanResult`.
fn partition_deps(deps: impl Iterator<Item = ParsedDependency>) -> (Vec<ParsedDependency>, usize) {
    let mut seen: BTreeMap<(Ecosystem, String, Option<String>), ParsedDependency> = BTreeMap::new();
    for dep in deps {
        let key = (dep.ecosystem, dep.name.clone(), dep.version.clone());
        seen.entry(key).or_insert(dep);
    }
    let mut pinned = Vec::new();
    let mut skipped = 0usize;
    for dep in seen.into_values() {
        if dep.version.is_some() {
            pinned.push(dep);
        } else {
            skipped += 1;
        }
    }
    (pinned, skipped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enablement_combines_flag_config_and_env() {
        let disabled = OsvSettings {
            enabled: false,
            cache_ttl_days: 30,
            offline: false,
        };
        let config_on = OsvSettings {
            enabled: true,
            ..disabled.clone()
        };
        std::env::remove_var(ACTIVATION_ENV_VAR);
        assert!(resolve_enabled(true, &disabled), "the --osv flag enables");
        assert!(!resolve_enabled(false, &disabled), "off by default");
        assert!(
            resolve_enabled(false, &config_on),
            "[osv] enable = true enables"
        );
        std::env::set_var(ACTIVATION_ENV_VAR, "1");
        assert!(
            resolve_enabled(false, &disabled),
            "SKILL_VEIL_OSV=1 enables"
        );
        std::env::set_var(ACTIVATION_ENV_VAR, "no");
        assert!(!resolve_enabled(false, &disabled));
        std::env::remove_var(ACTIVATION_ENV_VAR);
    }

    fn dep(name: &str, version: Option<&str>) -> ParsedDependency {
        ParsedDependency {
            name: name.to_string(),
            version: version.map(str::to_string),
            ecosystem: Ecosystem::PyPI,
            source_artifact: "/r.txt".to_string(),
        }
    }

    #[test]
    fn partition_separates_pinned_from_unpinned_and_dedups() {
        let deps = vec![
            dep("requests", Some("2.31.0")),
            dep("requests", Some("2.31.0")), // exact duplicate across artifacts
            dep("flask", None),              // range/unpinned -> skipped
        ];
        let (pinned, skipped) = partition_deps(deps.into_iter());
        assert_eq!(
            pinned.len(),
            1,
            "duplicate pinned dep collapses to one query"
        );
        assert_eq!(pinned[0].name, "requests");
        assert_eq!(skipped, 1, "the unpinned dep is counted as skipped");
    }

    #[test]
    fn empty_package_returns_none_without_network() {
        // An empty package has no pinned dependencies, so enrichment
        // short-circuits to `None` before any network/config access — the
        // flag value is irrelevant here.
        let pkg = PackageScanResult::new();
        assert!(try_enrich_with_osv(&pkg, true, None, true)
            .unwrap()
            .is_none());
    }

    fn full(id: &str) -> ResolvedAdvisory {
        ResolvedAdvisory {
            id: id.to_string(),
            aliases: vec![format!("CVE-{id}")],
            summary: Some("summary".to_string()),
            severity: Some("CVSS_V3:7.5".to_string()),
        }
    }

    #[test]
    fn cached_advisories_do_not_consume_the_network_fetch_budget() {
        // Contract: the MAX_ADVISORY_DETAILS cap bounds network fetches, not
        // total advisories. A run with the budget's worth of already-cached
        // advisories must still fetch a single uncached one — cache hits do
        // not spend the budget.
        let tmp = tempfile::tempdir().unwrap();
        let cache = OsvCache::new(Some(tmp.path()), 30).unwrap();
        let cached_ids: Vec<String> = (0..MAX_ADVISORY_DETAILS)
            .map(|i| format!("CACHED-{i:04}"))
            .collect();
        for id in &cached_ids {
            cache.put_details(id, &full(id));
        }
        let mut ids = cached_ids.clone();
        ids.push("UNCACHED-1".to_string());
        let ids_per_dep = vec![Some(ids)];
        let pinned = vec![dep("requests", Some("2.31.0"))];

        let calls = std::cell::RefCell::new(Vec::new());
        let mut fetch = |id: &str| {
            calls.borrow_mut().push(id.to_string());
            Some(full(id))
        };
        let out = hydrate_with(&pinned, &ids_per_dep, Some(&cache), false, &mut fetch);

        assert_eq!(
            *calls.borrow(),
            vec!["UNCACHED-1".to_string()],
            "only the uncached id is fetched; the cached ones never spent the budget"
        );
        let uncached = out[0]
            .advisories
            .iter()
            .find(|a| a.id == "UNCACHED-1")
            .unwrap();
        assert!(
            uncached.summary.is_some(),
            "the uncached advisory is hydrated with full detail, not degraded to id_only"
        );
    }

    #[test]
    fn network_fetch_budget_caps_uncached_advisories() {
        // The other direction: with more uncached advisories than the budget
        // and no cache, exactly MAX_ADVISORY_DETAILS are fetched and the rest
        // degrade to id_only.
        let overflow = 5;
        let ids: Vec<String> = (0..MAX_ADVISORY_DETAILS + overflow)
            .map(|i| format!("U-{i:04}"))
            .collect();
        let ids_per_dep = vec![Some(ids)];
        let pinned = vec![dep("requests", Some("2.31.0"))];

        let calls = std::cell::RefCell::new(0usize);
        let mut fetch = |id: &str| {
            *calls.borrow_mut() += 1;
            Some(full(id))
        };
        let out = hydrate_with(&pinned, &ids_per_dep, None, false, &mut fetch);

        assert_eq!(
            *calls.borrow(),
            MAX_ADVISORY_DETAILS,
            "network fetches are capped at MAX_ADVISORY_DETAILS"
        );
        let hydrated = out[0]
            .advisories
            .iter()
            .filter(|a| a.summary.is_some())
            .count();
        let id_only = out[0]
            .advisories
            .iter()
            .filter(|a| a.summary.is_none())
            .count();
        assert_eq!(hydrated, MAX_ADVISORY_DETAILS);
        assert_eq!(id_only, overflow);
    }
}
