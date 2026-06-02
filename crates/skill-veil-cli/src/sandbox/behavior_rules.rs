//! Behavioral detection rules for the dynamic sandbox.
//!
//! A malware-sandbox-style signature layer: where [`super::mapping`] turns
//! each observed behavior into a `SANDBOX_*` finding one-to-one, a
//! [`BehaviorRule`] fires on a CO-OCCURRENCE of behaviors within one run —
//! e.g. a sensitive read *and* an outbound connection is the exfiltration
//! chain that no single behavior expresses. Rules are data, loaded from the
//! embedded `behavior_rules.yaml` baseline (the skill-veil-rules repo's
//! `behavioral/` pack is the upstream source).

use std::path::Path;

use serde::Deserialize;
use skill_veil_core::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, SignalClass,
    TaxonomyTag, ThreatCategory,
};

use super::observation::{BehaviorClass, SandboxObservation};

const EMBEDDED_RULES: &str = include_str!("behavior_rules.yaml");

fn default_confidence() -> f32 {
    0.85
}

fn default_enabled() -> bool {
    true
}

/// One condition: a behavior of `class` whose `detail` contains at least
/// one of `detail_any` (or any detail, when `detail_any` is empty).
#[derive(Debug, Clone, Deserialize)]
struct Condition {
    class: BehaviorClass,
    #[serde(default)]
    detail_any: Vec<String>,
}

impl Condition {
    fn matched_by(&self, behavior: &super::observation::ObservedBehavior) -> bool {
        behavior.class == self.class
            && (self.detail_any.is_empty()
                || self
                    .detail_any
                    .iter()
                    .any(|needle| behavior.detail.contains(needle.as_str())))
    }
}

/// A co-occurrence signature: every condition in `all_of` must be satisfied
/// by some observed behavior for the rule to fire.
#[derive(Debug, Clone, Deserialize)]
struct BehaviorRule {
    id: String,
    category: ThreatCategory,
    severity: Severity,
    #[serde(default = "default_confidence")]
    confidence: f32,
    all_of: Vec<Condition>,
    reason: String,
    #[serde(default)]
    taxonomy_tags: Vec<TaxonomyTag>,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

/// The compiled behavioral ruleset.
pub(crate) struct BehaviorRuleSet {
    rules: Vec<BehaviorRule>,
}

impl BehaviorRuleSet {
    /// The embedded baseline. The YAML is validated at build time by the
    /// `embedded_behavior_rules_parse` test, so parsing cannot fail here.
    pub(crate) fn embedded() -> Self {
        Self::parse(EMBEDDED_RULES).expect("embedded behavioral rules must parse")
    }

    fn parse(yaml: &str) -> Result<Self, serde_yaml::Error> {
        let rules: Vec<BehaviorRule> = serde_yaml::from_str(yaml)?;
        Ok(Self {
            rules: rules.into_iter().filter(|r| r.enabled).collect(),
        })
    }

    /// Findings for every rule whose `all_of` conditions are all satisfied
    /// by `observation`, attributed to `source_path`. Each finding's
    /// `match_value` lists the concrete behaviors that satisfied the rule.
    pub(crate) fn evaluate(
        &self,
        observation: &SandboxObservation,
        source_path: &Path,
    ) -> Vec<Finding> {
        let path = source_path.display().to_string();
        let mut findings = Vec::new();
        for rule in &self.rules {
            let mut matched_details = Vec::new();
            let satisfied = rule.all_of.iter().all(|cond| {
                match observation.behaviors.iter().find(|b| cond.matched_by(b)) {
                    Some(b) => {
                        matched_details.push(b.detail.clone());
                        true
                    }
                    None => false,
                }
            });
            if !satisfied {
                continue;
            }
            findings.push(
                Finding::builder(rule.id.clone(), rule.category)
                    .severity(rule.severity)
                    .confidence(rule.confidence)
                    .action(RecommendedAction::RequireApproval)
                    .signal_class(SignalClass::ReviewSignal)
                    .evidence_kind(EvidenceKind::Behavior)
                    .matched_on(MatchTarget::ReferencedFile { path: path.clone() })
                    .artifact(ArtifactKind::ReferencedArtifact, Some(path.clone()))
                    .match_value(matched_details.join(" ; "))
                    .reason(format!("Dynamic sandbox (behavior): {}", rule.reason))
                    .taxonomy_tags(rule.taxonomy_tags.clone())
                    .build(),
            );
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::observation::{BehaviorSource, ObservedBehavior};

    fn obs(behaviors: Vec<(BehaviorClass, &str)>) -> SandboxObservation {
        SandboxObservation {
            behaviors: behaviors
                .into_iter()
                .map(|(class, detail)| ObservedBehavior {
                    class,
                    detail: detail.to_string(),
                    source: BehaviorSource::Script,
                })
                .collect(),
            timed_out: false,
            truncated: false,
        }
    }

    /// # Contract
    /// The embedded baseline parses and yields enabled rules.
    #[test]
    fn embedded_behavior_rules_parse() {
        let set = BehaviorRuleSet::embedded();
        assert!(!set.rules.is_empty());
    }

    /// # Contract (positive)
    /// The exfiltration chain fires only when BOTH a sensitive read AND an
    /// outbound connection occur in the same run.
    #[test]
    fn exfil_chain_fires_on_secret_plus_network() {
        let set = BehaviorRuleSet::embedded();
        let o = obs(vec![
            (BehaviorClass::SensitiveFileRead, "/root/.ssh/id_rsa"),
            (BehaviorClass::NetworkConnect, "evil.invalid:443"),
        ]);
        assert!(set
            .evaluate(&o, Path::new("x"))
            .iter()
            .any(|f| f.rule_id == "SANDBOX_BEHAVIOR_EXFIL_SECRET_TO_NETWORK"));
    }

    /// # Contract (negative)
    /// A lone outbound connection (no secret read) does NOT trip the
    /// exfiltration chain — co-occurrence is required.
    #[test]
    fn exfil_chain_does_not_fire_on_network_alone() {
        let set = BehaviorRuleSet::embedded();
        let o = obs(vec![(BehaviorClass::NetworkConnect, "cdn.example.com:443")]);
        assert!(set
            .evaluate(&o, Path::new("x"))
            .iter()
            .all(|f| f.rule_id != "SANDBOX_BEHAVIOR_EXFIL_SECRET_TO_NETWORK"));
    }

    /// # Contract (positive + negative)
    /// The C2-port rule fires on a known C2 port and not on a benign one.
    #[test]
    fn c2_port_rule_is_port_specific() {
        let set = BehaviorRuleSet::embedded();
        let hit = obs(vec![(BehaviorClass::NetworkConnect, "198.51.100.7:4444")]);
        let miss = obs(vec![(BehaviorClass::NetworkConnect, "198.51.100.7:443")]);
        assert!(set
            .evaluate(&hit, Path::new("x"))
            .iter()
            .any(|f| f.rule_id == "SANDBOX_BEHAVIOR_C2_KNOWN_PORT"));
        assert!(set
            .evaluate(&miss, Path::new("x"))
            .iter()
            .all(|f| f.rule_id != "SANDBOX_BEHAVIOR_C2_KNOWN_PORT"));
    }

    /// # Contract
    /// A container-escape primitive (runtime socket) trips the escape rule
    /// and the finding is advisory (ReviewSignal / RequireApproval).
    #[test]
    fn escape_rule_fires_on_runtime_socket_and_is_advisory() {
        let set = BehaviorRuleSet::embedded();
        let o = obs(vec![(
            BehaviorClass::PrivilegeChange,
            "unix-socket: /var/run/docker.sock",
        )]);
        let findings = set.evaluate(&o, Path::new("x"));
        let f = findings
            .iter()
            .find(|f| f.rule_id == "SANDBOX_BEHAVIOR_CONTAINER_ESCAPE_ATTEMPT")
            .expect("escape rule must fire");
        assert_eq!(f.signal_class, SignalClass::ReviewSignal);
        assert_eq!(f.recommended_action, RecommendedAction::RequireApproval);
    }
}
