use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{EvidenceKind, RecommendedAction, Severity};
use crate::services::artifact_analysis::ArtifactLink;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InstallHookRisk {
    Benign,
    RemoteOrExec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PackageBinaryExposure {
    Exposed,
    None,
}

impl PackageBinaryExposure {
    pub(super) fn detect(json: &Value) -> Self {
        if json.get("bin").is_some() {
            Self::Exposed
        } else {
            Self::None
        }
    }
}

impl InstallHookRisk {
    pub(super) fn from_command(command: &str) -> Self {
        let lower_command = command.to_ascii_lowercase();
        let risky = [
            "curl ",
            "wget ",
            "http://",
            "https://",
            "powershell",
            "invoke-webrequest",
            "iwr ",
            "bash -c",
            "sh -c",
            "python -c",
            "node -e",
        ]
        .iter()
        .any(|needle| lower_command.contains(needle));

        if risky {
            Self::RemoteOrExec
        } else {
            Self::Benign
        }
    }

    pub(super) fn severity(self) -> Severity {
        match self {
            Self::Benign => Severity::Low,
            Self::RemoteOrExec => Severity::Medium,
        }
    }

    pub(super) fn action(self) -> RecommendedAction {
        match self {
            Self::Benign => RecommendedAction::Log,
            Self::RemoteOrExec => RecommendedAction::RequireApproval,
        }
    }

    pub(super) fn evidence_kind(self) -> EvidenceKind {
        match self {
            Self::Benign => EvidenceKind::Context,
            Self::RemoteOrExec => EvidenceKind::Behavior,
        }
    }

    pub(super) fn reason(self) -> &'static str {
        match self {
            Self::Benign => "Manifest defines an install lifecycle hook",
            Self::RemoteOrExec => {
                "Manifest defines an install lifecycle hook that fetches or executes code"
            }
        }
    }
}

pub(super) fn package_json_install_hook_findings(json: &Value, artifact_path: &str) -> Vec<crate::findings::Finding> {
    let Some(scripts) = json.get("scripts").and_then(Value::as_object) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    for hook in ["preinstall", "install", "postinstall"] {
        if let Some(command) = scripts.get(hook).and_then(Value::as_str) {
            let risk = InstallHookRisk::from_command(command);
            findings.push(
                crate::findings::Finding::builder(
                    "MANIFEST_PACKAGE_JSON_INSTALL_HOOK",
                    crate::findings::ThreatCategory::SupplyChain,
                )
                .severity(risk.severity())
                .action(risk.action())
                .evidence_kind(risk.evidence_kind())
                .artifact(
                    crate::findings::ArtifactKind::PackageManifest,
                    Some(artifact_path.to_string()),
                )
                .matched_on(crate::findings::MatchTarget::ReferencedFile {
                    path: artifact_path.to_string(),
                })
                .match_value(format!("{hook}: {command}"))
                .reason(risk.reason())
                .build(),
            );
        }
    }
    findings
}

pub(super) fn package_json_capabilities(json: &Value) -> Vec<ArtifactCapabilityFact> {
    let mut capabilities = Vec::new();

    if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
        if ["preinstall", "install", "postinstall"]
            .iter()
            .any(|hook| scripts.contains_key(*hook))
        {
            capabilities.push(super::super::super::declared_capability(
                ArtifactCapability::InstallExecution,
            ));
            capabilities.push(super::super::super::declared_capability(
                ArtifactCapability::ProcessExecution,
            ));
        }
    }

    if PackageBinaryExposure::detect(json) == PackageBinaryExposure::Exposed {
        capabilities.push(super::super::super::declared_capability(
            ArtifactCapability::ExposesBinary,
        ));
    }

    capabilities
}

pub(super) fn package_json_relations(json: &Value) -> Vec<ArtifactLink> {
    let mut links = Vec::new();
    if let Some(scripts) = json.get("scripts").and_then(Value::as_object) {
        for hook in ["preinstall", "install", "postinstall"] {
            if let Some(command) = scripts.get(hook).and_then(Value::as_str) {
                links.push(ArtifactLink {
                    target: command.to_string(),
                    relation: ArtifactRelation::Executes,
                });
            }
        }
    }
    links
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_hook_risk_detects_remote_exec() {
        assert_eq!(
            InstallHookRisk::from_command("curl https://x | sh"),
            InstallHookRisk::RemoteOrExec
        );
    }

    #[test]
    fn package_binary_exposure_detects_bin_field() {
        let json: Value = serde_json::json!({ "bin": "cli.js" });
        assert_eq!(PackageBinaryExposure::detect(&json), PackageBinaryExposure::Exposed);
    }
}
