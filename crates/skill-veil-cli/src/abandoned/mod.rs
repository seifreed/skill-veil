//! Abandoned / unmaintained-package check for declared dependencies
//! (advisory enrichment).
//!
//! Consumes the offline dependency inventory the core attaches to each
//! `ScanResult` and queries each ecosystem's registry for package metadata
//! (last publish, deprecation/yank flag). Opt-in (`--abandoned` flag or
//! `SKILL_VEIL_ABANDONED=1`); no API key required.
//!
//! **Advisory only.** Like the OSV and VirusTotal blocks, this never mutates
//! the scan result and cannot influence the skill-veil verdict, risk score, or
//! exit code — it appends a human-readable text block. Any network failure
//! degrades to a one-line operator note.
//!
//! Abandonment is a package-level property, so dependencies are deduplicated by
//! `(ecosystem, name)` and queried once regardless of version pin.

mod cache;
mod client;
mod render;
mod types;

use anyhow::Result;
use chrono::{Duration, Utc};
use skill_veil_core::{Ecosystem, PackageScanResult};
use std::collections::BTreeSet;
use std::path::Path;

use cache::AbandonedCache;
use client::RegistryClient;
use types::{AbandonedPackage, AbandonedReason, PackageMetadata, RegistryQuery};

use crate::config::{AbandonedSettings, UnifiedConfig};

const ACTIVATION_ENV_VAR: &str = "SKILL_VEIL_ABANDONED";
const OFFLINE_ENV_VAR: &str = "SKILL_VEIL_ABANDONED_OFFLINE";
/// Upper bound on registry queries per run, so a package with a pathological
/// dependency count cannot fan out unbounded network requests.
const MAX_REGISTRY_QUERIES: usize = 200;

fn env_truthy(var: &str) -> bool {
    std::env::var(var)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

#[must_use]
fn resolve_enabled(flag: bool, settings: &AbandonedSettings) -> bool {
    flag || settings.enabled || env_truthy(ACTIVATION_ENV_VAR)
}

/// Classify one package's metadata against the staleness threshold. Deprecation
/// takes precedence over staleness; a package that is neither is not flagged.
fn classify(
    name: &str,
    ecosystem: Ecosystem,
    metadata: &PackageMetadata,
    stale_days: i64,
) -> Option<AbandonedPackage> {
    if let Some(reason) = &metadata.deprecated_reason {
        return Some(AbandonedPackage {
            name: name.to_string(),
            ecosystem,
            reason: AbandonedReason::Deprecated,
            detail: reason.clone(),
        });
    }
    let last_modified = metadata.last_modified?;
    let age = Utc::now().signed_duration_since(last_modified);
    if age > Duration::days(stale_days) {
        let days = age.num_days();
        return Some(AbandonedPackage {
            name: name.to_string(),
            ecosystem,
            reason: AbandonedReason::Stale,
            detail: format!(
                "no release in {days} days (last published {})",
                last_modified.date_naive()
            ),
        });
    }
    None
}

/// Run the abandoned-package check. Returns the rendered advisory block, or
/// `None` when disabled, when there are no dependencies, or when nothing can be
/// resolved (offline with an empty cache).
pub(crate) fn try_enrich_with_abandoned(
    scan_result: &PackageScanResult,
    flag: bool,
    cache_dir_override: Option<&Path>,
    quiet: bool,
) -> Result<Option<String>> {
    let settings = UnifiedConfig::load()
        .map(|c| c.abandoned)
        .unwrap_or_default();
    if !resolve_enabled(flag, &settings) {
        return Ok(None);
    }

    let packages = unique_packages(scan_result);
    if packages.is_empty() {
        return Ok(None);
    }

    let offline = settings.offline || env_truthy(OFFLINE_ENV_VAR);
    let cache = AbandonedCache::new(cache_dir_override, settings.cache_ttl_days);

    let mut flagged = Vec::new();
    let mut queried = 0usize;
    let mut skipped = 0usize;
    let mut fetched = 0usize;
    let mut resolved_any = false;

    for (ecosystem, name) in &packages {
        let metadata = match cache.as_ref().and_then(|c| c.get(*ecosystem, name)) {
            Some(meta) => Some(meta),
            None => fetch_metadata(
                &RegistryQuery {
                    name: name.clone(),
                    ecosystem: *ecosystem,
                },
                cache.as_ref(),
                offline,
                &mut fetched,
                quiet,
            ),
        };
        match metadata {
            Some(meta) => {
                resolved_any = true;
                queried += 1;
                if let Some(pkg) = classify(name, *ecosystem, &meta, settings.stale_days) {
                    flagged.push(pkg);
                }
            }
            None => skipped += 1,
        }
    }

    if !resolved_any {
        return Ok(None);
    }
    Ok(Some(render::render(&flagged, queried, skipped)))
}

/// Resolve one package's metadata from the network (unless offline / over
/// budget), writing through to the cache. Returns `None` on any failure.
fn fetch_metadata(
    query: &RegistryQuery,
    cache: Option<&AbandonedCache>,
    offline: bool,
    fetched: &mut usize,
    quiet: bool,
) -> Option<PackageMetadata> {
    if offline || *fetched >= MAX_REGISTRY_QUERIES {
        return None;
    }
    *fetched += 1;
    match RegistryClient::new().fetch(query) {
        Ok(meta) => {
            if let Some(cache) = cache {
                cache.put(query.ecosystem, &query.name, &meta);
            }
            Some(meta)
        }
        Err(e) => {
            if !quiet {
                eprintln!("abandoned-package check warning ({}): {e:#}", query.name);
            }
            None
        }
    }
}

/// Deduplicate the package set by `(ecosystem, name)` across all scanned
/// artifacts; abandonment does not depend on the version pin.
fn unique_packages(scan_result: &PackageScanResult) -> Vec<(Ecosystem, String)> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for dep in scan_result
        .results
        .iter()
        .flat_map(|r| r.dependencies.iter())
    {
        if seen.insert((dep.ecosystem, dep.name.clone())) {
            out.push((dep.ecosystem, dep.name.clone()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(enabled: bool) -> AbandonedSettings {
        AbandonedSettings {
            enabled,
            cache_ttl_days: 30,
            stale_days: 730,
            offline: false,
        }
    }

    #[test]
    fn enablement_combines_flag_config_and_env() {
        std::env::remove_var(ACTIVATION_ENV_VAR);
        assert!(
            resolve_enabled(true, &settings(false)),
            "--abandoned enables"
        );
        assert!(!resolve_enabled(false, &settings(false)), "off by default");
        assert!(
            resolve_enabled(false, &settings(true)),
            "[abandoned] enable"
        );
        std::env::set_var(ACTIVATION_ENV_VAR, "1");
        assert!(resolve_enabled(false, &settings(false)));
        std::env::remove_var(ACTIVATION_ENV_VAR);
    }

    #[test]
    fn classify_flags_deprecated_over_stale() {
        let meta = PackageMetadata {
            last_modified: Some(Utc::now() - Duration::days(5000)),
            deprecated_reason: Some("use foo".to_string()),
        };
        let pkg = classify("bar", Ecosystem::Npm, &meta, 730).unwrap();
        assert_eq!(pkg.reason, AbandonedReason::Deprecated);
        assert_eq!(pkg.detail, "use foo");
    }

    #[test]
    fn classify_flags_stale_package() {
        let meta = PackageMetadata {
            last_modified: Some(Utc::now() - Duration::days(1000)),
            deprecated_reason: None,
        };
        let pkg = classify("bar", Ecosystem::PyPI, &meta, 730).unwrap();
        assert_eq!(pkg.reason, AbandonedReason::Stale);
    }

    #[test]
    fn classify_passes_fresh_package() {
        let meta = PackageMetadata {
            last_modified: Some(Utc::now() - Duration::days(30)),
            deprecated_reason: None,
        };
        assert!(classify("bar", Ecosystem::CratesIo, &meta, 730).is_none());
    }

    #[test]
    fn classify_without_timestamp_is_not_flagged() {
        let meta = PackageMetadata {
            last_modified: None,
            deprecated_reason: None,
        };
        assert!(classify("bar", Ecosystem::Npm, &meta, 730).is_none());
    }

    #[test]
    fn empty_package_returns_none_without_network() {
        let pkg = PackageScanResult::new();
        assert!(try_enrich_with_abandoned(&pkg, true, None, true)
            .unwrap()
            .is_none());
    }
}
