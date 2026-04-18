use super::{ContextPolicy, PolicyGenerator, PolicyProfile, ShieldPolicy, POLICY_EXPIRY_DAYS};
use crate::artifact_graph::ArtifactCapability;
use crate::findings::{
    default_operational_contexts, Finding, OperationalContext, RecommendedAction,
};
use chrono::Utc;
use std::collections::HashMap;

impl PolicyGenerator {
    pub(crate) fn generate_policies(&self) -> Vec<ShieldPolicy> {
        let mut policy_map: HashMap<String, ShieldPolicy> = HashMap::new();

        // Keyed by rule_id: each PolicyGenerator operates on a single skill, so
        // rule_id is sufficient for deduplication. The policy_id embeds skill_name
        // for external uniqueness but is not used as the merge key.
        for finding in self.findings() {
            let policy_id = format!("{}-{}", finding.rule_id.to_lowercase(), self.skill_name());
            let recommendation = format!(
                "{}: skill name equals \"{}\"",
                finding.severity.action_str(),
                self.skill_name()
            );

            policy_map
                .entry(finding.rule_id.clone())
                .and_modify(|p| {
                    if !p.recommendation_agent.contains(&recommendation) {
                        p.recommendation_agent.push(recommendation.clone());
                    }
                    if finding.severity > p.severity {
                        p.severity = finding.severity;
                    }
                    if finding.confidence > p.confidence {
                        p.confidence = finding.confidence;
                    }
                    p.action = p.action.max(finding.recommended_action);
                })
                .or_insert(ShieldPolicy {
                    id: policy_id,
                    category: finding.category,
                    severity: finding.severity,
                    confidence: finding.confidence,
                    action: finding.recommended_action,
                    recommendation_agent: vec![recommendation],
                    expires_at: Some(Utc::now() + chrono::Duration::days(POLICY_EXPIRY_DAYS)),
                    revoked: false,
                });
        }

        let mut policies: Vec<_> = policy_map.into_values().collect();
        policies.sort_by(|left, right| left.id.cmp(&right.id));
        policies
    }

    pub fn generate_context_policies(&self) -> Vec<ContextPolicy> {
        let mut context_map: HashMap<OperationalContext, ContextPolicy> = HashMap::new();

        for finding in self.findings() {
            for context in contexts_for_finding(finding) {
                let action = finding.recommended_action.max(
                    self.profile()
                        .map(|profile| resolve_context_action(self, profile, context))
                        .unwrap_or(RecommendedAction::Log),
                );
                let rationale = format!(
                    "{} via {} ({})",
                    finding.rule_id, finding.reason, finding.category
                );
                upsert_context_policy(&mut context_map, context, action, rationale);
            }
        }

        for node in &self.artifact_graph().nodes {
            for capability in &node.capabilities {
                for context in contexts_for_capability(capability.capability)
                    .iter()
                    .copied()
                {
                    let action = self
                        .profile()
                        .map(|profile| resolve_context_action(self, profile, context))
                        .unwrap_or(RecommendedAction::Log);
                    let rationale = format!(
                        "{} exposes {:?} ({:?})",
                        node.path, capability.capability, capability.source
                    );
                    upsert_context_policy(&mut context_map, context, action, rationale);
                }
            }
        }

        let mut policies: Vec<_> = context_map.into_values().collect();
        policies.sort_by_key(|policy| context_sort_key(policy.context));
        policies
    }
}

fn resolve_context_action(
    generator: &PolicyGenerator,
    profile: PolicyProfile,
    context: OperationalContext,
) -> RecommendedAction {
    generator.policy().map_or_else(
        || profile.default_action_for_context(context),
        |policy| policy.resolve_context_action(profile, context),
    )
}

fn upsert_context_policy(
    context_map: &mut HashMap<OperationalContext, ContextPolicy>,
    context: OperationalContext,
    action: RecommendedAction,
    rationale: String,
) {
    context_map
        .entry(context)
        .and_modify(|policy| {
            policy.action = policy.action.max(action);
            if !policy.rationale.contains(&rationale) {
                policy.rationale.push(rationale.clone());
            }
        })
        .or_insert(ContextPolicy {
            context,
            action,
            rationale: vec![rationale],
        });
}

fn context_sort_key(context: OperationalContext) -> u8 {
    match context {
        OperationalContext::Install => 0,
        OperationalContext::Network => 1,
        OperationalContext::Secrets => 2,
        OperationalContext::CodeModification => 3,
        OperationalContext::ExternalComms => 4,
    }
}

fn contexts_for_finding(finding: &Finding) -> Vec<OperationalContext> {
    if finding.operational_contexts.is_empty() {
        default_operational_contexts(finding.category, finding.artifact_kind)
    } else {
        finding.operational_contexts.clone()
    }
}

fn contexts_for_capability(capability: ArtifactCapability) -> &'static [OperationalContext] {
    match capability {
        ArtifactCapability::InstallExecution | ArtifactCapability::ExposesBinary => {
            &[OperationalContext::Install]
        }
        ArtifactCapability::NetworkAccess => &[
            OperationalContext::Network,
            OperationalContext::ExternalComms,
        ],
        ArtifactCapability::BrowserAccess => &[
            OperationalContext::Network,
            OperationalContext::CodeModification,
        ],
        ArtifactCapability::IdentityAccess => &[
            OperationalContext::Secrets,
            OperationalContext::ExternalComms,
        ],
        ArtifactCapability::InboundNetworkSurface => &[
            OperationalContext::Network,
            OperationalContext::ExternalComms,
        ],
        ArtifactCapability::PrivilegedRuntime | ArtifactCapability::HostFilesystemAccess => {
            &[OperationalContext::CodeModification]
        }
        ArtifactCapability::ProcessExecution | ArtifactCapability::FilesystemWrite => {
            &[OperationalContext::CodeModification]
        }
        ArtifactCapability::SecretAccess => &[OperationalContext::Secrets],
        ArtifactCapability::PersistenceSurface => &[
            OperationalContext::CodeModification,
            OperationalContext::ExternalComms,
        ],
    }
}
