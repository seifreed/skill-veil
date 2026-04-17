use std::collections::BTreeSet;

use crate::findings::{RecommendedAction, RootCauseGroup, ThreatCategory};

pub(super) fn derive_effective_capabilities(root_cause_groups: &[RootCauseGroup]) -> Vec<String> {
    let mut capabilities = BTreeSet::<String>::new();
    for group in root_cause_groups
        .iter()
        .filter(|g| g.strongest_action != RecommendedAction::Log)
    {
        let key = match group.category {
            ThreatCategory::RemoteExec => "process_execution",
            ThreatCategory::CredentialExposure => "secret_access",
            ThreatCategory::DataExfiltration => "data_exfiltration",
            ThreatCategory::PersistentPromptTampering => "persistence_surface",
            ThreatCategory::SupplyChain => "supply_chain_installation",
            ThreatCategory::ToolAbuse => "tool_abuse",
            ThreatCategory::AutonomyEscalation => "autonomous_actions",
            ThreatCategory::PrivilegeEscalation => "filesystem_or_runtime_escalation",
            ThreatCategory::ScopeCreep => "scope_creep",
            ThreatCategory::SocialManipulation | ThreatCategory::PersuasiveLanguage => {
                "trust_bypass"
            }
            ThreatCategory::Obfuscation => "obfuscation",
            ThreatCategory::UnsafeBinary => "unsafe_binary",
            ThreatCategory::Generic => "generic_review",
        };
        capabilities.insert(key.to_string());
    }
    capabilities.into_iter().collect()
}
