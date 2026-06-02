//! Map observed runtime behavior to advisory findings.
//!
//! Every sandbox finding is `SignalClass::ReviewSignal` /
//! `RecommendedAction::RequireApproval` — like NOVA, the dynamic channel
//! is advisory and never inflates the corpus-pinned static verdict. The
//! value it adds is *evidence of what actually happened at runtime*,
//! attributed to the analysed artifact.

use std::path::Path;

use skill_veil_core::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, SignalClass,
    ThreatCategory,
};

use super::observation::{BehaviorClass, BehaviorSource, ObservedBehavior, SandboxObservation};

struct BehaviorMapping {
    rule_id: &'static str,
    category: ThreatCategory,
    severity: Severity,
    summary: &'static str,
}

fn mapping_for(class: BehaviorClass) -> BehaviorMapping {
    match class {
        BehaviorClass::NetworkConnect => BehaviorMapping {
            rule_id: "SANDBOX_NETWORK_CONNECT",
            category: ThreatCategory::DataExfiltration,
            severity: Severity::High,
            summary: "attempted an outbound network connection at runtime",
        },
        BehaviorClass::DnsQuery => BehaviorMapping {
            rule_id: "SANDBOX_DNS_QUERY",
            category: ThreatCategory::DataExfiltration,
            severity: Severity::Medium,
            summary: "issued a DNS resolution at runtime",
        },
        BehaviorClass::ProcessSpawn => BehaviorMapping {
            rule_id: "SANDBOX_PROCESS_SPAWN",
            category: ThreatCategory::RemoteExec,
            severity: Severity::Medium,
            summary: "spawned a subprocess at runtime",
        },
        BehaviorClass::FileWrite => BehaviorMapping {
            rule_id: "SANDBOX_FILE_WRITE",
            category: ThreatCategory::Generic,
            severity: Severity::Low,
            summary: "wrote to the filesystem at runtime",
        },
        BehaviorClass::SensitiveFileRead => BehaviorMapping {
            rule_id: "SANDBOX_SENSITIVE_FILE_READ",
            category: ThreatCategory::CredentialExposure,
            severity: Severity::High,
            summary: "read a sensitive path (credential/key/dotfile) at runtime",
        },
        BehaviorClass::PersistenceWrite => BehaviorMapping {
            rule_id: "SANDBOX_PERSISTENCE_WRITE",
            category: ThreatCategory::PrivilegeEscalation,
            severity: Severity::High,
            summary: "wrote to a persistence surface (cron/rc/autostart) at runtime",
        },
        BehaviorClass::PrivilegeChange => BehaviorMapping {
            rule_id: "SANDBOX_PRIVILEGE_CHANGE",
            category: ThreatCategory::PrivilegeEscalation,
            severity: Severity::High,
            summary: "attempted to change privileges/capabilities at runtime",
        },
        BehaviorClass::AgentToolCall => BehaviorMapping {
            rule_id: "SANDBOX_AGENT_TOOL_CALL",
            category: ThreatCategory::ToolAbuse,
            severity: Severity::Medium,
            summary: "the instrumented agent invoked a tool at runtime",
        },
    }
}

fn source_label(source: BehaviorSource) -> &'static str {
    match source {
        BehaviorSource::Script => "script",
        BehaviorSource::Agent => "agent",
    }
}

fn behavior_to_finding(behavior: &ObservedBehavior, source_path: &Path) -> Finding {
    let m = mapping_for(behavior.class);
    let path = source_path.display().to_string();
    Finding::builder(m.rule_id, m.category)
        .severity(m.severity)
        .confidence(0.9)
        .action(RecommendedAction::RequireApproval)
        .signal_class(SignalClass::ReviewSignal)
        .evidence_kind(EvidenceKind::Behavior)
        .matched_on(MatchTarget::ReferencedFile { path: path.clone() })
        .artifact(ArtifactKind::ReferencedArtifact, Some(path))
        .match_value(behavior.detail.clone())
        .reason(format!(
            "Dynamic sandbox ({}): skill {}",
            source_label(behavior.source),
            m.summary
        ))
        .build()
}

/// Convert an observation into advisory findings attributed to
/// `source_path` (the scanned skill/artifact the sandbox ran).
pub(crate) fn observation_to_findings(
    observation: &SandboxObservation,
    source_path: &Path,
) -> Vec<Finding> {
    observation
        .behaviors
        .iter()
        .map(|behavior| behavior_to_finding(behavior, source_path))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::observation::BehaviorSource;

    fn obs(class: BehaviorClass, detail: &str) -> ObservedBehavior {
        ObservedBehavior {
            class,
            detail: detail.to_string(),
            source: BehaviorSource::Script,
        }
    }

    /// # Contract
    /// Sandbox findings are advisory: every one carries `ReviewSignal` and
    /// `RequireApproval`, so the dynamic channel never inflates the static
    /// verdict (mirrors NOVA/YARA injection semantics).
    #[test]
    fn all_findings_are_advisory_review_signals() {
        let observation = SandboxObservation {
            behaviors: vec![
                obs(BehaviorClass::NetworkConnect, "evil.invalid:443"),
                obs(BehaviorClass::SensitiveFileRead, "/root/.aws/credentials"),
            ],
            timed_out: false,
            truncated: false,
        };
        let findings = observation_to_findings(&observation, Path::new("pkg/SKILL.md"));
        assert_eq!(findings.len(), 2);
        for f in &findings {
            assert_eq!(f.signal_class, SignalClass::ReviewSignal);
            assert_eq!(f.recommended_action, RecommendedAction::RequireApproval);
        }
    }

    /// # Contract
    /// Each behavior class maps to its own stable rule id and is attributed
    /// to the analysed artifact path.
    #[test]
    fn behavior_classes_map_to_stable_rule_ids_and_path() {
        let observation = SandboxObservation {
            behaviors: vec![
                obs(BehaviorClass::NetworkConnect, "x"),
                obs(BehaviorClass::ProcessSpawn, "y"),
                obs(BehaviorClass::PersistenceWrite, "z"),
            ],
            timed_out: false,
            truncated: false,
        };
        let findings = observation_to_findings(&observation, Path::new("pkg/run.sh"));
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "SANDBOX_NETWORK_CONNECT",
                "SANDBOX_PROCESS_SPAWN",
                "SANDBOX_PERSISTENCE_WRITE"
            ]
        );
        assert!(findings[0].match_value == "x");
    }

    /// # Contract
    /// The privilege-change and DNS-query classes — now actively emitted by
    /// the enriched observer (setuid-to-root / capset / namespace / ptrace /
    /// runtime-socket connects, and port-53 connects) — map to their stable
    /// rule ids under the privilege-escalation and exfiltration categories.
    #[test]
    fn privilege_change_and_dns_query_map_to_stable_rule_ids() {
        let observation = SandboxObservation {
            behaviors: vec![
                obs(
                    BehaviorClass::PrivilegeChange,
                    "unix-socket: /var/run/docker.sock",
                ),
                obs(BehaviorClass::DnsQuery, "8.8.8.8:53"),
            ],
            timed_out: false,
            truncated: false,
        };
        let findings = observation_to_findings(&observation, Path::new("pkg/run.sh"));
        assert_eq!(findings[0].rule_id, "SANDBOX_PRIVILEGE_CHANGE");
        assert_eq!(findings[0].category, ThreatCategory::PrivilegeEscalation);
        assert_eq!(findings[1].rule_id, "SANDBOX_DNS_QUERY");
        assert_eq!(findings[1].category, ThreatCategory::DataExfiltration);
    }

    /// # Contract
    /// An empty observation yields no findings.
    #[test]
    fn empty_observation_yields_no_findings() {
        let observation = SandboxObservation::default();
        assert!(observation_to_findings(&observation, Path::new("x")).is_empty());
    }
}
