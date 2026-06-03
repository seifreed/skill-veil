//! Manifest detectors: per-language and per-runtime analyses for
//! `package.json`, `pyproject.toml`, `Dockerfile`, `docker-compose.yml`,
//! `.npmrc`, `pip.conf`, `Makefile`, `Cargo.toml`, etc.
//!
//! Orchestration in `services::artifact_orchestration::manifests` dispatches
//! against these detectors based on artifact name; each detector owns
//! the rule-id / severity / capability mapping for its manifest kind.

use crate::artifact_graph::ArtifactCapabilityFact;
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};

pub(crate) mod build;
pub(crate) mod container;
pub(crate) mod javascript;
pub(crate) mod python;
pub(crate) mod rust_cargo;
pub(crate) mod version_pin;

/// Sort then dedup capability facts by capability kind. `Vec::dedup_by_key`
/// only collapses adjacent runs and detectors emit interleaved capabilities
/// (e.g. reqwest, nix, hyper, duct), so the sort must come first.
pub(crate) fn dedup_capabilities_by_kind(capabilities: &mut Vec<ArtifactCapabilityFact>) {
    capabilities.sort_by_key(|c| c.capability);
    capabilities.dedup_by_key(|c| c.capability);
}

/// Build the `Log`-severity finding emitted when a package manifest fails to
/// parse. The manifest ships but its structure can't be analyzed, so its
/// existence is recorded in the audit output rather than silently dropped.
/// `rule_id` and `reason` identify the manifest kind; `detail` carries the
/// parser's own error message.
pub(crate) fn manifest_parse_failure_finding(
    rule_id: &str,
    artifact_path: &str,
    detail: String,
    reason: &str,
) -> Finding {
    Finding::builder(rule_id, ThreatCategory::Generic)
        .severity(Severity::Low)
        .action(RecommendedAction::Log)
        .evidence_kind(EvidenceKind::Context)
        .matched_on(MatchTarget::ReferencedFile {
            path: artifact_path.to_string(),
        })
        .artifact(ArtifactKind::PackageManifest, Some(artifact_path.to_string()))
        .match_value(detail)
        .reason(reason)
        .build()
}
