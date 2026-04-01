use super::super::super::network::classify_webhook_exposure;
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WebhookRisk {
    severity: Severity,
    action: RecommendedAction,
}

impl WebhookRisk {
    fn elevated() -> Self {
        Self {
            severity: Severity::Medium,
            action: RecommendedAction::RequireApproval,
        }
    }
}

pub(super) fn webhook_findings(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    let Some(exposure) = classify_webhook_exposure(content) else {
        return Vec::new();
    };

    let artifact_path = path.display().to_string();
    let risk = WebhookRisk::elevated();
    vec![
        Finding::builder(exposure.finding_rule_id(), ThreatCategory::ToolAbuse)
            .severity(risk.severity)
            .action(risk.action)
            .evidence_kind(EvidenceKind::Context)
            .artifact(artifact_kind, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value(exposure.label())
            .reason(exposure.finding_reason())
            .build(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_inbound_endpoint_emits_webhook_finding() {
        let findings = webhook_findings(
            Path::new("README.md"),
            "webhook receiver listener on public endpoint 0.0.0.0 accept callbacks incoming webhooks",
            ArtifactKind::SkillDocument,
        );

        assert!(findings.iter().any(|f| f.rule_id == "PUBLIC_INBOUND_ENDPOINT"));
    }
}
