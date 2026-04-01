mod network_policy;
mod permission_policy;
mod webhook_policy;

use super::signals::InstructionSignals;
use crate::findings::{ArtifactKind, Finding};
use std::path::Path;

pub(super) fn semantic_persistence_findings(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    permission_policy::semantic_persistence_findings(
        path,
        InstructionSignals::inspect(content),
        artifact_kind,
    )
}

pub(super) fn permission_and_network_findings(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    let mut findings = permission_policy::permission_findings(path, content, artifact_kind);
    findings.extend(network_policy::network_findings(path, content, artifact_kind));
    findings.extend(webhook_policy::webhook_findings(path, content, artifact_kind));
    findings
}
