//! Finding constructors for network-target, SSRF-shaped fetch, and
//! exposed-webhook signals.
//!
//! These helpers belong here rather than in
//! `services::artifact_orchestration::instructions` because they
//! encode domain rules: severity, threat category, signal class, and
//! recommended action are all decided here. The orchestration layer
//! only chooses *when* to invoke them; the rules themselves live with
//! the rest of the network detectors.

use std::path::Path;

use crate::detectors::network::targets::{
    contains_internal_network_action, contains_internal_network_target,
    contains_ssrf_like_fetch_line, looks_like_local_control_plane_reference,
    looks_like_local_dev_reference,
};
use crate::detectors::network::webhook::{classify_webhook_exposure, WebhookExposure};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, SignalClass,
    ThreatCategory,
};

/// Emit a network-target finding when the artifact references an
/// internal/private host AND either the artifact kind is one that
/// commonly drives outbound traffic (referenced artifact, MCP server)
/// or the content contains an internal-network action keyword.
/// Local-dev style references are filtered out so `localhost:3000`
/// during tests does not light up the verdict.
pub(crate) fn check_internal_network_target(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Option<Finding> {
    let target = contains_internal_network_target(content)?;
    if !(matches!(
        artifact_kind,
        ArtifactKind::ReferencedArtifact | ArtifactKind::McpServerManifest
    ) || contains_internal_network_action(content))
        || looks_like_local_dev_reference(content)
    {
        return None;
    }
    let artifact_path = path.display().to_string();
    Some(
        Finding::builder(target.rule_id(), target.threat_category())
            .severity(Severity::Medium)
            .action(target.action())
            .evidence_kind(EvidenceKind::Behavior)
            .signal_class(target.signal_class())
            .artifact(artifact_kind, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value(target.label())
            .reason(target.reason())
            .build(),
    )
}

/// Emit `SSRF_LIKE_FETCH` when an artifact pairs a fetch-shaped line
/// with a previously-detected internal-target reference. Local-dev
/// and local-control-plane references are filtered to keep dev mocks
/// from tripping the high-severity SSRF rule.
pub(crate) fn check_ssrf_like_fetch(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
    has_internal_target: bool,
) -> Option<Finding> {
    if !contains_ssrf_like_fetch_line(content)
        || !has_internal_target
        || looks_like_local_dev_reference(content)
        || looks_like_local_control_plane_reference(content)
    {
        return None;
    }
    let artifact_path = path.display().to_string();
    Some(
        Finding::builder("SSRF_LIKE_FETCH", ThreatCategory::ToolAbuse)
            .severity(Severity::High)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Behavior)
            .signal_class(SignalClass::SuspiciousPackageBehavior)
            .artifact(artifact_kind, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value("internal fetch target")
            .reason("Artifact combines fetch-style behavior with internal network targets")
            .build(),
    )
}

/// Emit a webhook-exposure finding when an artifact registers an
/// inbound webhook receiver without authentication. `AuthBypass`
/// upgrades to `Block`; bare `PublicInboundEndpoint` stays at
/// `RequireApproval`.
pub(crate) fn check_webhook_without_auth(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Option<Finding> {
    let kind = classify_webhook_exposure(content)?;
    let artifact_path = path.display().to_string();
    let action = match kind {
        WebhookExposure::AuthBypass => RecommendedAction::Block,
        WebhookExposure::PublicInboundEndpoint => RecommendedAction::RequireApproval,
    };
    Some(
        Finding::builder(kind.finding_rule_id(), ThreatCategory::ToolAbuse)
            .severity(Severity::Medium)
            .action(action)
            .evidence_kind(EvidenceKind::Context)
            .artifact(artifact_kind, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path,
            })
            .match_value(kind.label())
            .reason(kind.finding_reason())
            .build(),
    )
}

/// Bundle the three network/intent detectors. Splitting their
/// invocation here keeps the orchestration layer thin.
pub(crate) fn network_and_intent_findings(
    path: &Path,
    content: &str,
    artifact_kind: ArtifactKind,
) -> Vec<Finding> {
    let has_internal_target = contains_internal_network_target(content).is_some();
    [
        check_internal_network_target(path, content, artifact_kind),
        check_ssrf_like_fetch(path, content, artifact_kind, has_internal_target),
        check_webhook_without_auth(path, content, artifact_kind),
    ]
    .into_iter()
    .flatten()
    .collect()
}
