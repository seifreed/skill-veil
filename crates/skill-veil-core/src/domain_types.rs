//! Shared domain value objects reused across provenance, reasoning, network, and reporting.
//!
//! This module is intentionally limited to reusable domain concepts.
//! It must not own final findings, observation batches, parsing logic, or scoring/report rendering.

use serde::{Deserialize, Serialize};
use strum_macros::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum HeuristicSeverity {
    Review,
    Elevated,
    Critical,
}

impl HeuristicSeverity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::Elevated => "elevated",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CalibrationAdjustment(i32);

impl CalibrationAdjustment {
    pub fn from_points(points: i32) -> Self {
        Self(points)
    }

    pub fn points(self) -> i32 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum RemoteRelationKind {
    ConnectsTo,
    Downloads,
}

impl RemoteRelationKind {
    pub fn relation(self) -> crate::artifact_graph::ArtifactRelation {
        match self {
            Self::ConnectsTo => crate::artifact_graph::ArtifactRelation::ConnectsTo,
            Self::Downloads => crate::artifact_graph::ArtifactRelation::Downloads,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackageIdentity {
    name: String,
    version: String,
}

impl PackageIdentity {
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
        }
    }

    pub fn workspace(name: impl Into<String>) -> Self {
        Self::new(name, "workspace")
    }

    pub fn package_name(&self) -> &str {
        &self.name
    }
}

impl std::fmt::Display for PackageIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.name, self.version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PackageIdentityLineage {
    pub identity: String,
    pub source_path: String,
}

impl PackageIdentityLineage {
    pub fn new(identity: impl Into<String>, source_path: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
            source_path: source_path.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum PackageLineageDrift {
    MixedPackageNames,
    RepeatedIdentityAcrossPaths,
}

impl PackageLineageDrift {
    pub fn note(self) -> &'static str {
        match self {
            Self::MixedPackageNames => "conflicting package names observed across manifests",
            Self::RepeatedIdentityAcrossPaths => {
                "same package identity is declared across multiple manifest paths"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display, Default)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ProvenanceTrustLevel {
    Trusted,
    #[default]
    Review,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display, Default)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum PublisherConsistency {
    Consistent,
    Mixed,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum DomainReputation {
    Trusted,
    Review,
    Untrusted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ProvenanceConfidence {
    High,
    Medium,
}

impl ProvenanceConfidence {
    pub fn is_review_weighted(self) -> bool {
        matches!(self, Self::Medium)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LockfileCoverageSummary {
    #[serde(default)]
    pub manifests_with_expected_lockfiles: usize,
    #[serde(default)]
    pub manifests_with_present_lockfiles: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_expected_lockfiles: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ManifestInventoryEntry {
    pub path: String,
    pub ecosystem: String,
    pub manifest_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_package_manager: Option<String>,
    #[serde(default)]
    pub direct_dependencies: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_lockfiles: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LockfileInventoryEntry {
    pub path: String,
    pub ecosystem: String,
    pub lockfile_kind: String,
    #[serde(default)]
    pub direct_dependencies: usize,
    #[serde(default)]
    pub transitive_dependencies: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_urls: Vec<String>,
    #[serde(default)]
    pub hashes_present: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_domain_types_expose_stable_labels_and_defaults() {
        assert_eq!(HeuristicSeverity::Critical.to_string(), "critical");
        assert_eq!(RemoteRelationKind::Downloads.to_string(), "downloads");
        assert_eq!(CalibrationAdjustment::from_points(0).points(), 0);
        assert!(ProvenanceConfidence::Medium.is_review_weighted());
        assert_eq!(ProvenanceTrustLevel::default(), ProvenanceTrustLevel::Review);
        assert_eq!(PublisherConsistency::default(), PublisherConsistency::Unknown);
    }

    #[test]
    fn package_identity_and_lineage_are_reusable_value_objects() {
        let identity = PackageIdentity::new("demo", "1.0.0");
        assert_eq!(identity.package_name(), "demo");
        assert_eq!(identity.to_string(), "demo@1.0.0");

        let lineage = PackageIdentityLineage::new(identity.to_string(), "/tmp/package.json");
        assert_eq!(lineage.identity, "demo@1.0.0");
        assert_eq!(PackageLineageDrift::MixedPackageNames.to_string(), "mixed_package_names");
    }

    #[test]
    fn inventory_value_objects_have_predictable_defaults() {
        let manifest = ManifestInventoryEntry::default();
        let lockfile = LockfileInventoryEntry::default();
        let coverage = LockfileCoverageSummary::default();

        assert!(manifest.path.is_empty());
        assert!(lockfile.resolved_urls.is_empty());
        assert_eq!(coverage.manifests_with_expected_lockfiles, 0);
        assert!(coverage.missing_expected_lockfiles.is_empty());
    }
}
