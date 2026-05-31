//! Synchronous per-registry metadata client (no API key required).
//!
//! Mirrors the OSV client's `ureq` posture: bounded timeout, retry on transient
//! failures, typed errors. One GET per package, dispatched by ecosystem:
//!   - npm:      `GET https://registry.npmjs.org/<name>`
//!   - PyPI:     `GET https://pypi.org/pypi/<name>/json`
//!   - crates.io:`GET https://crates.io/api/v1/crates/<name>`
//!
//! Each registry's JSON is normalised into [`PackageMetadata`] by a pure parse
//! function so classification is exercised without the network.

use super::types::{PackageMetadata, RegistryQuery};
use chrono::{DateTime, Utc};
use skill_veil_core::Ecosystem;
use std::time::Duration;
use thiserror::Error;

const USER_AGENT: &str = concat!(
    "skill-veil/",
    env!("CARGO_PKG_VERSION"),
    " (+abandoned-package-check)"
);
const HTTP_TIMEOUT_SECS: u64 = 30;
const MAX_ADDITIONAL_ATTEMPTS: u32 = 2;
const INITIAL_BACKOFF_MS: u64 = 1_000;
const MAX_PACKAGE_NAME_LEN: usize = 214;

#[derive(Debug, Error)]
pub(super) enum RegistryError {
    #[error("registry HTTP {status}")]
    HttpStatus { status: u16 },
    #[error("registry transport error: {0}")]
    Transport(String),
    #[error("registry response decode error: {0}")]
    Decode(String),
    #[error("invalid package name: {0:?}")]
    InvalidName(String),
}

/// Whether `name` is safe to interpolate into a registry URL path. Package
/// names are taken from scanned manifests, so a value carrying path or query
/// metacharacters must be rejected before it can reshape the request URL into
/// an unintended same-host endpoint. npm scoped names (`@scope/pkg`) are
/// allowed; the single `/` is percent-encoded by [`path_segment`].
fn is_safe_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_PACKAGE_NAME_LEN {
        return false;
    }
    let scoped = name.strip_prefix('@').unwrap_or(name);
    let slash_count = scoped.bytes().filter(|&b| b == b'/').count();
    if slash_count > 1 {
        return false;
    }
    // Reject path-traversal shapes even though '.' and '/' are otherwise legal
    // in package names (`socket.io`, `@scope/pkg`).
    if scoped.contains("..") || scoped.starts_with(['.', '/']) || scoped.ends_with('/') {
        return false;
    }
    scoped
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}

/// Encode a package name into a single URL path segment, percent-encoding the
/// `/` of an npm scoped name (the only metacharacter `is_safe_package_name`
/// admits).
fn path_segment(name: &str) -> String {
    name.replace('/', "%2F")
}

pub(super) struct RegistryClient {
    agent: ureq::Agent,
}

impl RegistryClient {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .build();
        Self { agent }
    }

    pub fn fetch(&self, query: &RegistryQuery) -> Result<PackageMetadata, RegistryError> {
        if !is_safe_package_name(&query.name) {
            return Err(RegistryError::InvalidName(query.name.clone()));
        }
        let seg = path_segment(&query.name);
        let (url, parse): (String, fn(&serde_json::Value) -> PackageMetadata) =
            match query.ecosystem {
                Ecosystem::Npm => (format!("https://registry.npmjs.org/{seg}"), parse_npm),
                Ecosystem::PyPI => (format!("https://pypi.org/pypi/{seg}/json"), parse_pypi),
                Ecosystem::CratesIo => (
                    format!("https://crates.io/api/v1/crates/{seg}"),
                    parse_crates,
                ),
            };
        let json: serde_json::Value = self.get_json(&url)?;
        Ok(parse(&json))
    }

    fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, RegistryError> {
        let mut backoff = INITIAL_BACKOFF_MS;
        let mut attempt = 0;
        loop {
            match self.agent.get(url).call() {
                Ok(resp) => {
                    return resp
                        .into_json::<T>()
                        .map_err(|e| RegistryError::Decode(e.to_string()));
                }
                Err(ureq::Error::Status(status, _)) => {
                    if (status == 429 || status >= 500) && attempt < MAX_ADDITIONAL_ATTEMPTS {
                        attempt += 1;
                        std::thread::sleep(Duration::from_millis(backoff));
                        backoff = backoff.saturating_mul(2);
                        continue;
                    }
                    return Err(RegistryError::HttpStatus { status });
                }
                Err(ureq::Error::Transport(t)) => {
                    if attempt < MAX_ADDITIONAL_ATTEMPTS {
                        attempt += 1;
                        std::thread::sleep(Duration::from_millis(backoff));
                        backoff = backoff.saturating_mul(2);
                        continue;
                    }
                    return Err(RegistryError::Transport(t.to_string()));
                }
            }
        }
    }
}

fn parse_timestamp(value: Option<&str>) -> Option<DateTime<Utc>> {
    value
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
}

/// npm packument: `time.modified` is the last publish; the latest version's
/// `deprecated` string (if present) marks the package deprecated.
fn parse_npm(json: &serde_json::Value) -> PackageMetadata {
    let last_modified = parse_timestamp(json.get("time").and_then(|t| t["modified"].as_str()));
    let latest = json
        .get("dist-tags")
        .and_then(|d| d.get("latest"))
        .and_then(serde_json::Value::as_str);
    let deprecated_reason = latest
        .and_then(|v| json.get("versions").and_then(|vs| vs.get(v)))
        .and_then(|ver| ver.get("deprecated"))
        .and_then(|d| match d {
            serde_json::Value::String(s) => Some(s.clone()),
            serde_json::Value::Bool(true) => Some("deprecated".to_string()),
            _ => None,
        });
    PackageMetadata {
        last_modified,
        deprecated_reason,
    }
}

/// PyPI JSON: `info.yanked` marks the release removed; the latest version's
/// newest upload time is the last publish.
fn parse_pypi(json: &serde_json::Value) -> PackageMetadata {
    let info = json.get("info");
    let deprecated_reason = info
        .filter(|i| i["yanked"].as_bool().unwrap_or(false))
        .map(|i| {
            i["yanked_reason"]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or("yanked")
                .to_string()
        });
    let latest = info.and_then(|i| i["version"].as_str());
    let last_modified = latest
        .and_then(|v| json.get("releases").and_then(|r| r.get(v)))
        .and_then(serde_json::Value::as_array)
        .map(|files| {
            files
                .iter()
                .filter_map(|f| parse_timestamp(f["upload_time_iso_8601"].as_str()))
                .max()
        })
        .unwrap_or(None);
    PackageMetadata {
        last_modified,
        deprecated_reason,
    }
}

/// crates.io: `crate.updated_at` is the last publish. crates.io exposes no
/// package-level deprecation flag, so only staleness is derivable.
fn parse_crates(json: &serde_json::Value) -> PackageMetadata {
    let last_modified = parse_timestamp(json.get("crate").and_then(|c| c["updated_at"].as_str()));
    PackageMetadata {
        last_modified,
        deprecated_reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_name_accepts_real_names_and_rejects_url_shaping() {
        for ok in ["requests", "lodash", "@scope/pkg", "py-yaml", "serde_json"] {
            assert!(is_safe_package_name(ok), "{ok} should be accepted");
        }
        for bad in ["", "../etc", "a/b/c", "x?y", "x#z", "name space", "a%2e"] {
            assert!(!is_safe_package_name(bad), "{bad:?} should be rejected");
        }
        assert!(!is_safe_package_name(&"a".repeat(MAX_PACKAGE_NAME_LEN + 1)));
    }

    #[test]
    fn scoped_name_path_segment_encodes_slash() {
        assert_eq!(path_segment("@scope/pkg"), "@scope%2Fpkg");
        assert_eq!(path_segment("requests"), "requests");
    }

    #[test]
    fn parse_npm_extracts_modified_and_deprecation() {
        let json = serde_json::json!({
            "dist-tags": { "latest": "2.0.0" },
            "time": { "modified": "2019-04-01T12:00:00.000Z" },
            "versions": { "2.0.0": { "deprecated": "use foo instead" } }
        });
        let meta = parse_npm(&json);
        assert_eq!(meta.deprecated_reason.as_deref(), Some("use foo instead"));
        assert!(meta.last_modified.is_some());
    }

    #[test]
    fn parse_npm_without_deprecation_is_clean() {
        let json = serde_json::json!({
            "dist-tags": { "latest": "1.0.0" },
            "time": { "modified": "2024-01-01T00:00:00Z" },
            "versions": { "1.0.0": {} }
        });
        let meta = parse_npm(&json);
        assert!(meta.deprecated_reason.is_none());
        assert!(meta.last_modified.is_some());
    }

    #[test]
    fn parse_pypi_extracts_yanked_and_upload_time() {
        let json = serde_json::json!({
            "info": { "version": "1.2.3", "yanked": true, "yanked_reason": "security" },
            "releases": { "1.2.3": [ { "upload_time_iso_8601": "2017-06-01T10:00:00Z" } ] }
        });
        let meta = parse_pypi(&json);
        assert_eq!(meta.deprecated_reason.as_deref(), Some("security"));
        assert!(meta.last_modified.is_some());
    }

    #[test]
    fn parse_pypi_not_yanked_has_no_reason() {
        let json = serde_json::json!({
            "info": { "version": "1.0.0", "yanked": false },
            "releases": { "1.0.0": [ { "upload_time_iso_8601": "2024-05-01T00:00:00Z" } ] }
        });
        let meta = parse_pypi(&json);
        assert!(meta.deprecated_reason.is_none());
        assert!(meta.last_modified.is_some());
    }

    #[test]
    fn parse_crates_extracts_updated_at() {
        let json = serde_json::json!({
            "crate": { "updated_at": "2018-12-31T23:59:59+00:00" }
        });
        let meta = parse_crates(&json);
        assert!(meta.last_modified.is_some());
        assert!(meta.deprecated_reason.is_none());
    }
}
