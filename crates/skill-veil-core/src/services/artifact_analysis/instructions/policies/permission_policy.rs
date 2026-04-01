mod intent_policy;
mod persistence_policy;
mod profile_policy;

use super::super::signals::InstructionSignals;
use crate::findings::{ArtifactKind, Finding};
use std::path::Path;

pub(super) fn semantic_persistence_findings(
    path: &Path,
    signals: InstructionSignals,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    persistence_policy::semantic_persistence_findings(path, signals, artifact_kind)
}

pub(super) fn permission_findings(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    let mut findings = profile_policy::declared_permission_findings(path, content, artifact_kind);
    findings.extend(intent_policy::intent_mismatch_findings(path, content, artifact_kind));
    findings
}
