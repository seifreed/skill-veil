//! OSV.dev request/response types and the resolved advisory view rendered to
//! the operator.

use serde::{Deserialize, Serialize};
use skill_veil_core::Ecosystem;

/// One dependency to look up.
pub(super) struct OsvQuery {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
}

/// Advisory identifiers returned by `querybatch`, then hydrated with details.
/// `Serialize`/`Deserialize` back the on-disk advisory-details cache.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ResolvedAdvisory {
    pub id: String,
    /// CVE / GHSA aliases (e.g. the canonical `CVE-…` for a `GHSA-…`).
    pub aliases: Vec<String>,
    pub summary: Option<String>,
    /// Best available severity label (e.g. a CVSS vector), if any.
    pub severity: Option<String>,
}

impl ResolvedAdvisory {
    /// Fallback when the detail fetch is skipped or fails: keep the ID so the
    /// operator can still look it up manually.
    pub fn id_only(id: &str) -> Self {
        Self {
            id: id.to_string(),
            aliases: Vec::new(),
            summary: None,
            severity: None,
        }
    }
}

/// All advisories affecting one pinned dependency.
pub(super) struct DependencyAdvisories {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub advisories: Vec<ResolvedAdvisory>,
}

#[derive(Deserialize)]
pub(super) struct BatchResponse {
    #[serde(default)]
    pub results: Vec<BatchResult>,
}

#[derive(Deserialize, Default)]
pub(super) struct BatchResult {
    #[serde(default)]
    pub vulns: Vec<VulnRef>,
}

#[derive(Deserialize)]
pub(super) struct VulnRef {
    pub id: String,
}

#[derive(Deserialize)]
pub(super) struct VulnDetails {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub severity: Vec<SeverityEntry>,
}

#[derive(Deserialize)]
pub(super) struct SeverityEntry {
    #[serde(rename = "type")]
    pub kind: String,
    pub score: String,
}

impl VulnDetails {
    pub fn into_resolved(self) -> ResolvedAdvisory {
        let severity = self
            .severity
            .into_iter()
            .next()
            .map(|s| format!("{}:{}", s.kind, s.score));
        ResolvedAdvisory {
            id: self.id,
            aliases: self.aliases,
            summary: self.summary,
            severity,
        }
    }
}
