use crate::artifact_graph::ArtifactCapability;
use crate::findings::{
    default_operational_contexts, Finding, OperationalContext as PolicyContext, RecommendedAction,
};
use crate::policy::{
    ContextPolicy, PolicyGenerator, PolicyProfile, ShieldPolicy, POLICY_EXPIRY_DAYS,
};
use chrono::Utc;
use std::collections::HashMap;

impl PolicyGenerator {
    pub(crate) fn generate_policies(&self) -> Vec<ShieldPolicy> {
        let mut policy_map: HashMap<String, ShieldPolicy> = HashMap::new();

        // Keyed by rule_id: each PolicyGenerator operates on a single skill, so
        // rule_id is sufficient for deduplication. The policy_id embeds skill_name
        // for external uniqueness but is not used as the merge key.
        for finding in &self.findings {
            let policy_id = format!("{}-{}", finding.rule_id.to_lowercase(), self.skill_name);
            let recommendation = format!(
                "{}: skill name equals \"{}\"",
                finding.severity.action_str(),
                self.skill_name
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
                    p.action = RecommendedAction::max(p.action, finding.recommended_action);
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

    pub(crate) fn generate_context_policies(&self) -> Vec<ContextPolicy> {
        let mut context_map: HashMap<PolicyContext, ContextPolicy> = HashMap::new();

        for finding in &self.findings {
            for context in contexts_for_finding(finding) {
                let action = RecommendedAction::max(
                    finding.recommended_action,
                    self.profile
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

        for node in &self.artifact_graph.nodes {
            for capability in &node.capabilities {
                for context in contexts_for_capability(capability.capability)
                    .iter()
                    .copied()
                {
                    let action = self
                        .profile
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
    context: PolicyContext,
) -> RecommendedAction {
    generator.policy.as_ref().map_or_else(
        || profile.default_action_for_context(context),
        |policy| policy.resolve_context_action(profile, context),
    )
}

fn upsert_context_policy(
    context_map: &mut HashMap<PolicyContext, ContextPolicy>,
    context: PolicyContext,
    action: RecommendedAction,
    rationale: String,
) {
    context_map
        .entry(context)
        .and_modify(|policy| {
            policy.action = RecommendedAction::max(policy.action, action);
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

fn context_sort_key(context: PolicyContext) -> u8 {
    match context {
        PolicyContext::Install => 0,
        PolicyContext::Network => 1,
        PolicyContext::Secrets => 2,
        PolicyContext::CodeModification => 3,
        PolicyContext::ExternalComms => 4,
    }
}

fn contexts_for_finding(finding: &Finding) -> Vec<PolicyContext> {
    if finding.policy_contexts.is_empty() {
        default_operational_contexts(finding.category, finding.artifact_kind)
    } else {
        finding.policy_contexts.clone()
    }
}

fn contexts_for_capability(capability: ArtifactCapability) -> &'static [PolicyContext] {
    match capability {
        ArtifactCapability::InstallExecution | ArtifactCapability::ExposesBinary => {
            &[PolicyContext::Install]
        }
        ArtifactCapability::NetworkAccess => {
            &[PolicyContext::Network, PolicyContext::ExternalComms]
        }
        ArtifactCapability::BrowserAccess => {
            &[PolicyContext::Network, PolicyContext::CodeModification]
        }
        ArtifactCapability::IdentityAccess => {
            &[PolicyContext::Secrets, PolicyContext::ExternalComms]
        }
        ArtifactCapability::InboundNetworkSurface => {
            &[PolicyContext::Network, PolicyContext::ExternalComms]
        }
        ArtifactCapability::PrivilegedRuntime | ArtifactCapability::HostFilesystemAccess => {
            &[PolicyContext::CodeModification]
        }
        ArtifactCapability::ProcessExecution | ArtifactCapability::FilesystemWrite => {
            &[PolicyContext::CodeModification]
        }
        ArtifactCapability::SecretAccess => &[PolicyContext::Secrets],
        ArtifactCapability::PersistenceSurface => &[
            PolicyContext::CodeModification,
            PolicyContext::ExternalComms,
        ],
    }
}
