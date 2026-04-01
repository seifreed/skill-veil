pub(super) const RULES_SRC: &str = include_str!("../rules.rs");
pub(super) const FINDINGS_SRC: &str = include_str!("../findings.rs");
pub(super) const FINDINGS_REPORTING_SRC: &str = include_str!("../findings/reporting.rs");
pub(super) const ANALYSIS_MODEL_SRC: &str = include_str!("../analysis_model.rs");
pub(super) const ARTIFACT_ANALYSIS_SRC: &str = include_str!("../services/artifact_analysis.rs");
pub(super) const MANIFESTS_FACADE_SRC: &str =
    include_str!("../services/artifact_analysis/manifests.rs");
pub(super) const PACKAGE_POLICY_SRC: &str =
    include_str!("../services/artifact_analysis/manifests/package.rs");
pub(super) const PACKAGE_DEPENDENCY_POLICY_SRC: &str =
    include_str!("../services/artifact_analysis/manifests/package/dependency_policy.rs");
pub(super) const PACKAGE_LOCKFILE_POLICY_SRC: &str =
    include_str!("../services/artifact_analysis/manifests/package/lockfile_policy.rs");
pub(super) const DISPATCH_SRC: &str = include_str!("../services/artifact_analysis/dispatch.rs");
pub(super) const VERDICT_SRC: &str = include_str!("../verdict.rs");
pub(super) const INSTRUCTIONS_SRC: &str =
    include_str!("../services/artifact_analysis/instructions.rs");
pub(super) const INSTRUCTION_SIGNALS_SRC: &str =
    include_str!("../services/artifact_analysis/instructions/signals.rs");
pub(super) const INSTRUCTION_POLICIES_SRC: &str =
    include_str!("../services/artifact_analysis/instructions/policies.rs");
pub(super) const INSTRUCTION_PERMISSION_POLICY_SRC: &str =
    include_str!("../services/artifact_analysis/instructions/policies/permission_policy.rs");
pub(super) const INSTRUCTION_PERMISSION_PROFILE_SRC: &str = include_str!(
    "../services/artifact_analysis/instructions/policies/permission_policy/profile_policy.rs"
);
pub(super) const INSTRUCTION_PERMISSION_INTENT_SRC: &str = include_str!(
    "../services/artifact_analysis/instructions/policies/permission_policy/intent_policy.rs"
);
pub(super) const INSTRUCTION_PERMISSION_PERSISTENCE_SRC: &str = include_str!(
    "../services/artifact_analysis/instructions/policies/permission_policy/persistence_policy.rs"
);
pub(super) const INSTRUCTION_NETWORK_POLICY_SRC: &str =
    include_str!("../services/artifact_analysis/instructions/policies/network_policy.rs");
pub(super) const INSTRUCTION_WEBHOOK_POLICY_SRC: &str =
    include_str!("../services/artifact_analysis/instructions/policies/webhook_policy.rs");
pub(super) const NETWORK_SRC: &str = include_str!("../services/artifact_analysis/network.rs");
pub(super) const NETWORK_PATTERNS_SRC: &str =
    include_str!("../services/artifact_analysis/network/patterns.rs");
pub(super) const NETWORK_RELATIONS_SRC: &str =
    include_str!("../services/artifact_analysis/network/relations.rs");
pub(super) const NETWORK_TARGETS_SRC: &str =
    include_str!("../services/artifact_analysis/network/targets.rs");
pub(super) const NETWORK_TARGETS_MODEL_SRC: &str =
    include_str!("../services/artifact_analysis/network/targets/model.rs");
pub(super) const NETWORK_TARGETS_CLASSIFY_SRC: &str =
    include_str!("../services/artifact_analysis/network/targets/classify.rs");
pub(super) const NETWORK_TARGETS_SIGNALS_SRC: &str =
    include_str!("../services/artifact_analysis/network/targets/signals.rs");
pub(super) const NETWORK_WEBHOOK_SRC: &str =
    include_str!("../services/artifact_analysis/network/webhook.rs");
pub(super) const DOMAIN_TYPES_SRC: &str = include_str!("../domain_types.rs");
pub(super) const COMMANDS_SRC: &str = include_str!("../../../skill-veil-cli/src/commands.rs");
pub(super) const COMMANDS_BASELINE_SRC: &str =
    include_str!("../../../skill-veil-cli/src/commands/baseline.rs");
pub(super) const COMMANDS_DIFF_SRC: &str =
    include_str!("../../../skill-veil-cli/src/commands/diff.rs");
pub(super) const DATASET_SRC: &str = include_str!("../../../skill-veil-cli/src/dataset.rs");
pub(super) const COMMANDS_IO_SRC: &str =
    include_str!("../../../skill-veil-cli/src/commands/io.rs");
pub(super) const DATASET_OUTPUT_SRC: &str =
    include_str!("../../../skill-veil-cli/src/dataset/output.rs");
pub(super) const PROVENANCE_SRC: &str = include_str!("../verdict/provenance.rs");
pub(super) const PROVENANCE_ORIGIN_SRC: &str = include_str!("../verdict/provenance/origin.rs");
pub(super) const PROVENANCE_INVENTORY_SRC: &str =
    include_str!("../verdict/provenance/inventory.rs");
pub(super) const PROVENANCE_INVENTORY_IDENTITY_SRC: &str =
    include_str!("../verdict/provenance/inventory/identity.rs");
pub(super) const PROVENANCE_INVENTORY_MANIFESTS_SRC: &str =
    include_str!("../verdict/provenance/inventory/manifests.rs");
pub(super) const PROVENANCE_INVENTORY_LOCKFILES_SRC: &str =
    include_str!("../verdict/provenance/inventory/lockfiles.rs");
pub(super) const PROVENANCE_LINEAGE_SRC: &str = include_str!("../verdict/provenance/lineage.rs");
pub(super) const PROVENANCE_PUBLISHER_SRC: &str =
    include_str!("../verdict/provenance/publisher.rs");
pub(super) const REASONING_SRC: &str = include_str!("../verdict/reasoning.rs");
pub(super) const REASONING_MODEL_SRC: &str = include_str!("../verdict/reasoning/model.rs");
pub(super) const REASONING_EXPLAINABILITY_SRC: &str =
    include_str!("../verdict/reasoning/explainability.rs");
pub(super) const REASONING_EXPLAINABILITY_TRACES_SRC: &str =
    include_str!("../verdict/reasoning/explainability/traces.rs");
pub(super) const REASONING_EXPLAINABILITY_SOURCES_SRC: &str =
    include_str!("../verdict/reasoning/explainability/sources.rs");
pub(super) const REASONING_TOP_REASONS_SRC: &str =
    include_str!("../verdict/reasoning/top_reasons.rs");
pub(super) const REASONING_COMPOUNDS_SRC: &str =
    include_str!("../verdict/reasoning/compounds.rs");
pub(super) const REASONING_RISK_SRC: &str = include_str!("../verdict/reasoning/risk.rs");

pub(super) fn assert_no_forbidden_tokens(source: &str, file_label: &str, forbidden: &[&str]) {
    for token in forbidden {
        assert!(
            !source.contains(token),
            "{file_label} must not depend directly on {token}"
        );
    }
}
