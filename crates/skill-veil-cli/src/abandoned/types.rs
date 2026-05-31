//! Types for the abandoned/unmaintained-package enrichment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use skill_veil_core::Ecosystem;

/// One package to look up (version-independent: abandonment is a property of
/// the package, not a single release).
pub(super) struct RegistryQuery {
    pub name: String,
    pub ecosystem: Ecosystem,
}

/// Registry metadata normalised across ecosystems. Backs the on-disk cache.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct PackageMetadata {
    /// Most recent publish/modification time, when the registry exposes one.
    pub last_modified: Option<DateTime<Utc>>,
    /// Deprecation / yank message when the registry marks the package
    /// (or its latest release) deprecated or yanked.
    pub deprecated_reason: Option<String>,
}

/// Why a package was flagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AbandonedReason {
    Deprecated,
    Stale,
}

/// A package the enrichment flagged, ready for rendering.
pub(super) struct AbandonedPackage {
    pub name: String,
    pub ecosystem: Ecosystem,
    pub reason: AbandonedReason,
    pub detail: String,
}
