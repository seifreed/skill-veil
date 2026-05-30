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

mod client;
mod render;
mod types;

use anyhow::Result;
use skill_veil_core::{Ecosystem, PackageScanResult, ParsedDependency};
use std::collections::BTreeMap;

use client::OsvClient;
use types::{DependencyAdvisories, OsvQuery, ResolvedAdvisory};

const ACTIVATION_ENV_VAR: &str = "SKILL_VEIL_OSV";
/// Upper bound on unique advisory IDs hydrated with full details in one run,
/// so a package with a pathological advisory count cannot fan out unbounded
/// detail requests.
const MAX_ADVISORY_DETAILS: usize = 100;

/// Whether OSV enrichment is active: the explicit `--osv` flag, or the
/// `SKILL_VEIL_OSV` environment variable set to a truthy value.
#[must_use]
pub(crate) fn is_enabled(flag: bool) -> bool {
    if flag {
        return true;
    }
    match std::env::var(ACTIVATION_ENV_VAR) {
        Ok(v) => matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        Err(_) => false,
    }
}

/// Run OSV enrichment. Returns the rendered advisory block, or `None` when
/// disabled, when there are no pinned dependencies, or when the lookup fails
/// (the failure is reported to stderr unless `quiet`).
pub(crate) fn try_enrich_with_osv(
    scan_result: &PackageScanResult,
    enabled: bool,
    quiet: bool,
) -> Result<Option<String>> {
    if !enabled {
        return Ok(None);
    }

    let (pinned, skipped) = partition_dependencies(scan_result);
    if pinned.is_empty() {
        return Ok(None);
    }

    let client = OsvClient::new();
    let queries: Vec<OsvQuery> = pinned
        .iter()
        .map(|d| OsvQuery {
            name: d.name.clone(),
            version: d.version.clone().unwrap_or_default(),
            ecosystem: d.ecosystem,
        })
        .collect();

    let batch = match client.query_batch(&queries) {
        Ok(b) => b,
        Err(e) => {
            if !quiet {
                eprintln!("OSV enrichment skipped: {e:#}");
            }
            return Ok(None);
        }
    };

    let mut advisories: Vec<DependencyAdvisories> = Vec::new();
    let mut details_cache: BTreeMap<String, ResolvedAdvisory> = BTreeMap::new();
    for (dep, ids) in pinned.iter().zip(batch) {
        if ids.is_empty() {
            continue;
        }
        let mut resolved = Vec::new();
        for id in ids {
            if let Some(cached) = details_cache.get(&id) {
                resolved.push(cached.clone());
                continue;
            }
            let detail = if details_cache.len() < MAX_ADVISORY_DETAILS {
                client
                    .advisory_details(&id)
                    .unwrap_or_else(|_| ResolvedAdvisory::id_only(&id))
            } else {
                ResolvedAdvisory::id_only(&id)
            };
            details_cache.insert(id.clone(), detail.clone());
            resolved.push(detail);
        }
        advisories.push(DependencyAdvisories {
            name: dep.name.clone(),
            version: dep.version.clone().unwrap_or_default(),
            ecosystem: dep.ecosystem,
            advisories: resolved,
        });
    }

    Ok(Some(render::render(&advisories, pinned.len(), skipped)))
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
    fn activation_respects_flag_and_env() {
        assert!(is_enabled(true));
        std::env::remove_var(ACTIVATION_ENV_VAR);
        assert!(!is_enabled(false));
        std::env::set_var(ACTIVATION_ENV_VAR, "1");
        assert!(is_enabled(false));
        std::env::set_var(ACTIVATION_ENV_VAR, "no");
        assert!(!is_enabled(false));
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
    fn disabled_returns_none_without_network() {
        let pkg = PackageScanResult::new();
        assert!(try_enrich_with_osv(&pkg, false, true).unwrap().is_none());
    }
}
