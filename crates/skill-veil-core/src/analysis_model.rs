//! Observation-layer analysis model.
//!
//! This module owns intermediate detector/analyzer observations before they are collapsed into
//! final findings. It must not own final scoring, risk factors, or report summaries.

use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSource {
    Detector(String),
    LegacyAnalyzer(String),
    Graph(String),
    Taint,
    Provenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationFinding {
    pub rule_id: String,
    pub category: ThreatCategory,
    pub severity: Severity,
    pub action: RecommendedAction,
    pub evidence_kind: EvidenceKind,
    pub artifact_kind: ArtifactKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_path: Option<String>,
    pub match_target: MatchTarget,
    pub match_value: String,
    pub reason: String,
}

impl ObservationFinding {
    #[must_use]
    pub fn from_finding(finding: &Finding) -> Self {
        Self {
            rule_id: finding.rule_id.clone(),
            category: finding.category,
            severity: finding.severity,
            action: finding.recommended_action,
            evidence_kind: finding.evidence_kind,
            artifact_kind: finding.artifact_kind,
            artifact_path: finding.artifact_path.clone(),
            match_target: finding.matched_on.clone(),
            match_value: finding.match_value.clone(),
            reason: finding.reason.clone(),
        }
    }

    #[must_use]
    pub fn into_finding(self) -> Finding {
        let mut builder = Finding::builder(self.rule_id, self.category)
            .severity(self.severity)
            .action(self.action)
            .evidence_kind(self.evidence_kind)
            .artifact(self.artifact_kind, self.artifact_path)
            .matched_on(self.match_target)
            .match_value(self.match_value)
            .reason(self.reason);
        if self.action == RecommendedAction::Block && self.severity < Severity::High {
            builder = builder.severity(Severity::High);
        }
        builder.build()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedBehavior {
    pub family: String,
    pub source: ObservationSource,
    pub finding: ObservationFinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedCapability {
    pub capability: String,
    pub source: ObservationSource,
    pub finding: ObservationFinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedProvenance {
    pub signal: String,
    pub source: ObservationSource,
    pub finding: ObservationFinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedIntent {
    pub intent: String,
    pub source: ObservationSource,
    pub finding: ObservationFinding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedEvidence {
    Behavior(ObservedBehavior),
    Capability(ObservedCapability),
    Provenance(ObservedProvenance),
    Intent(ObservedIntent),
}

impl ObservedEvidence {
    #[must_use]
    pub fn into_finding(self) -> Finding {
        match self {
            Self::Behavior(observation) => observation.finding.into_finding(),
            Self::Capability(observation) => observation.finding.into_finding(),
            Self::Provenance(observation) => observation.finding.into_finding(),
            Self::Intent(observation) => observation.finding.into_finding(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObservationBatch {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<ObservedEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<Finding>,
}

impl ObservationBatch {
    #[must_use]
    pub fn from_detector_findings(findings: Vec<Finding>, detector: impl Into<String>) -> Self {
        let detector = detector.into();
        let evidence = findings
            .iter()
            .map(|finding| classify_finding_observation(finding, detector.clone()))
            .collect();
        Self { evidence, findings }
    }

    #[must_use]
    pub fn from_findings(findings: Vec<Finding>, analyzer: impl Into<String>) -> Self {
        let analyzer = analyzer.into();
        Self {
            evidence: findings
                .iter()
                .cloned()
                .map(|finding| {
                    ObservedEvidence::Behavior(ObservedBehavior {
                        family: finding.rule_id.clone(),
                        source: ObservationSource::LegacyAnalyzer(analyzer.clone()),
                        finding: ObservationFinding {
                            rule_id: finding.rule_id.clone(),
                            category: finding.category,
                            severity: finding.severity,
                            action: finding.recommended_action,
                            evidence_kind: finding.evidence_kind,
                            artifact_kind: finding.artifact_kind,
                            artifact_path: finding.artifact_path.clone(),
                            match_target: finding.matched_on.clone(),
                            match_value: finding.match_value.clone(),
                            reason: finding.reason.clone(),
                        },
                    })
                })
                .collect(),
            findings,
        }
    }

    pub fn extend(&mut self, other: Self) {
        self.evidence.extend(other.evidence);
        self.findings.extend(other.findings);
    }

    pub fn push_observation(&mut self, observation: ObservedEvidence) {
        self.evidence.push(observation);
    }

    pub fn push_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    #[must_use]
    pub fn into_findings(self) -> Vec<Finding> {
        if self.findings.is_empty() {
            return self
                .evidence
                .into_iter()
                .map(ObservedEvidence::into_finding)
                .collect();
        }

        let mut findings = self.findings;
        let direct_fingerprint = |finding: &Finding| {
            (
                finding.rule_id.clone(),
                finding.artifact_path.clone(),
                finding.match_value.clone(),
            )
        };
        let mut seen: std::collections::BTreeSet<_> =
            findings.iter().map(direct_fingerprint).collect();
        for observation in self.evidence {
            let finding = observation.into_finding();
            if seen.insert(direct_fingerprint(&finding)) {
                findings.push(finding);
            }
        }
        findings
    }
}

fn classify_finding_observation(finding: &Finding, detector: String) -> ObservedEvidence {
    let observation_finding = ObservationFinding::from_finding(finding);
    let source = ObservationSource::Detector(detector);
    match finding.category {
        ThreatCategory::RemoteExec
        | ThreatCategory::DataExfiltration
        | ThreatCategory::SupplyChain
        | ThreatCategory::UnsafeBinary => ObservedEvidence::Behavior(ObservedBehavior {
            family: finding.rule_id.clone(),
            source,
            finding: observation_finding,
        }),
        ThreatCategory::ScopeCreep | ThreatCategory::PrivilegeEscalation => {
            ObservedEvidence::Capability(ObservedCapability {
                capability: finding.rule_id.clone(),
                source,
                finding: observation_finding,
            })
        }
        ThreatCategory::PersistentPromptTampering
        | ThreatCategory::PersuasiveLanguage
        | ThreatCategory::SocialManipulation
        | ThreatCategory::AutonomyEscalation
        | ThreatCategory::Obfuscation => ObservedEvidence::Intent(ObservedIntent {
            intent: finding.rule_id.clone(),
            source,
            finding: observation_finding,
        }),
        ThreatCategory::CredentialExposure
        | ThreatCategory::ToolAbuse
        | ThreatCategory::Generic => ObservedEvidence::Provenance(ObservedProvenance {
            signal: finding.rule_id.clone(),
            source,
            finding: observation_finding,
        }),
    }
}
