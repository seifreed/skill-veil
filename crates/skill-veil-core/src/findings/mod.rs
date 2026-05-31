//! Finding data structures for security analysis results
//!
//! Defines the core types for representing detected security signals.

mod builder;
mod calibration;
mod capability_scoring;
mod consensus;
mod dedup;
mod enums;
mod mapping;
mod permissions;
mod summary;
mod taxonomy;
mod types;
mod weights;

pub use builder::FindingBuilder;
pub use calibration::default_operational_contexts;
pub(crate) use calibration::{calibrate_confidence, default_remediation};
pub use consensus::{ConsensusClass, ConsensusDiscrepancy, ProviderVote};
pub(crate) use dedup::deduplicate_findings;
pub(crate) use dedup::split_findings_by_scope;
pub use dedup::DeduplicationSummary;
pub use enums::*;
pub use mapping::{artifact_scope_for_kind, signal_class_for};
pub use permissions::{
    declared_permission_for_rule, is_declared_permission_rule, DeclaredPermission,
    DECLARED_PERMISSION_RULES,
};
pub use summary::{ActionTrigger, FindingSummary, RiskFactor, SeverityCounts};
pub use taxonomy::{TaxonomyTag, TAXONOMY_TAGS};
pub use types::{
    BlastRadiusSummary, Finding, HygieneSummary, PackageVerdictReport, RootCauseGroup,
    SuppressionRecord, VerdictCalibrationNote, VerdictReason,
};
pub use weights::*;

#[cfg(test)]
mod tests;
