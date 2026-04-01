use super::super::super::network::{
    contains_internal_network_action, contains_internal_network_target, contains_ssrf_like_fetch_line,
    looks_like_local_control_plane_reference, looks_like_local_dev_reference, NetworkTarget,
};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, SignalClass,
    ThreatCategory,
};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SsrfPattern {
    target: NetworkTarget,
}

impl SsrfPattern {
    fn new(target: NetworkTarget) -> Self {
        Self { target }
    }

    fn is_actionable(self, content: &str) -> bool {
        contains_ssrf_like_fetch_line(content)
            && !looks_like_local_dev_reference(content)
            && !self.target.is_localhost_like()
            && !looks_like_local_control_plane_reference(content)
    }
}

pub(super) fn network_findings(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let mut findings = Vec::new();

    if let Some(target) = contains_internal_network_target(content) {
        if (matches!(
            artifact_kind,
            ArtifactKind::ReferencedArtifact | ArtifactKind::McpServerManifest
        ) || contains_internal_network_action(content))
            && !looks_like_local_dev_reference(content)
        {
            findings.push(
                Finding::builder(target.rule_id(), target.threat_category())
                    .severity(Severity::Medium)
                    .action(target.action())
                    .evidence_kind(EvidenceKind::Behavior)
                    .signal_class(target.signal_class())
                    .artifact(artifact_kind, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(target.label())
                    .reason(target.reason())
                    .build(),
            );
        }

        if SsrfPattern::new(target).is_actionable(content) {
            findings.push(
                Finding::builder("SSRF_LIKE_FETCH", ThreatCategory::ToolAbuse)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .signal_class(SignalClass::SuspiciousPackageBehavior)
                    .artifact(artifact_kind, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value("internal fetch target")
                    .reason("Artifact combines fetch-style behavior with internal network targets")
                    .build(),
            );
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_target_generates_metadata_service_finding() {
        let findings = network_findings(
            Path::new("server.py"),
            "requests.get('http://169.254.169.254/latest/meta-data')",
            ArtifactKind::ReferencedArtifact,
        );

        assert!(findings.iter().any(|f| f.rule_id == "METADATA_SERVICE_ACCESS"));
    }

    #[test]
    fn internal_fetch_line_generates_ssrf_signal() {
        let findings = network_findings(
            Path::new("server.py"),
            "requests.get('http://10.0.0.5/admin')",
            ArtifactKind::ReferencedArtifact,
        );

        assert!(findings.iter().any(|f| f.rule_id == "SSRF_LIKE_FETCH"));
    }
}
