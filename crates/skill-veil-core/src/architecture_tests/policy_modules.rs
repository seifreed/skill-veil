use super::shared::*;

#[test]
fn policy_modules_avoid_direct_filesystem_access() {
    let forbidden = ["std::fs", "std::io"];
    assert_no_forbidden_tokens(INSTRUCTIONS_SRC, "instructions.rs", &forbidden);
    assert_no_forbidden_tokens(NETWORK_SRC, "network.rs", &forbidden);
    assert_no_forbidden_tokens(PACKAGE_POLICY_SRC, "package.rs", &forbidden);
    assert_no_forbidden_tokens(
        INSTRUCTION_PERMISSION_POLICY_SRC,
        "permission_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        INSTRUCTION_PERMISSION_PROFILE_SRC,
        "profile_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        INSTRUCTION_PERMISSION_INTENT_SRC,
        "intent_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        INSTRUCTION_PERMISSION_PERSISTENCE_SRC,
        "persistence_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        INSTRUCTION_NETWORK_POLICY_SRC,
        "network_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        INSTRUCTION_WEBHOOK_POLICY_SRC,
        "webhook_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(NETWORK_SRC, "network.rs", &forbidden);
    assert_no_forbidden_tokens(NETWORK_TARGETS_SRC, "network/targets.rs", &forbidden);
    assert_no_forbidden_tokens(NETWORK_RELATIONS_SRC, "network/relations.rs", &forbidden);
}

#[test]
fn policy_modules_keep_regex_confined_to_signal_and_inventory_modules() {
    let forbidden = ["regex::Regex", "Regex::new"];
    assert_no_forbidden_tokens(VERDICT_SRC, "verdict.rs", &forbidden);
    assert_no_forbidden_tokens(ANALYSIS_MODEL_SRC, "analysis_model.rs", &forbidden);
    assert_no_forbidden_tokens(DOMAIN_TYPES_SRC, "domain_types.rs", &forbidden);
    assert_no_forbidden_tokens(ARTIFACT_ANALYSIS_SRC, "artifact_analysis.rs", &forbidden);
    assert_no_forbidden_tokens(INSTRUCTION_POLICIES_SRC, "instructions/policies.rs", &forbidden);
    assert_no_forbidden_tokens(
        INSTRUCTION_PERMISSION_POLICY_SRC,
        "permission_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        INSTRUCTION_PERMISSION_PROFILE_SRC,
        "profile_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        INSTRUCTION_PERMISSION_INTENT_SRC,
        "intent_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        INSTRUCTION_PERMISSION_PERSISTENCE_SRC,
        "persistence_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        INSTRUCTION_NETWORK_POLICY_SRC,
        "network_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        INSTRUCTION_WEBHOOK_POLICY_SRC,
        "webhook_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(NETWORK_SRC, "network.rs", &forbidden);
    assert!(
        INSTRUCTION_SIGNALS_SRC.contains("Regex::new"),
        "instruction signal regexes must live in instructions/signals.rs"
    );
    assert!(
        PROVENANCE_INVENTORY_LOCKFILES_SRC.contains("Regex::new"),
        "provenance inventory lockfiles should own lockfile URL extraction regex"
    );
    assert!(
        NETWORK_PATTERNS_SRC.contains("Regex::new"),
        "network/patterns.rs should own network regex definitions"
    );
    assert_no_forbidden_tokens(NETWORK_TARGETS_SRC, "network/targets.rs", &forbidden);
    assert_no_forbidden_tokens(
        REASONING_EXPLAINABILITY_TRACES_SRC,
        "reasoning/explainability/traces.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        REASONING_EXPLAINABILITY_SOURCES_SRC,
        "reasoning/explainability/sources.rs",
        &forbidden,
    );
}

#[test]
fn serde_and_toml_parsing_stay_in_explicit_parsing_modules() {
    let forbidden = ["serde_json::from_str", "toml::Value", "content.parse::<TomlValue>()"];
    assert_no_forbidden_tokens(MANIFESTS_FACADE_SRC, "manifests.rs", &forbidden);
    assert_no_forbidden_tokens(INSTRUCTIONS_SRC, "instructions.rs", &forbidden);
    assert_no_forbidden_tokens(DOMAIN_TYPES_SRC, "domain_types.rs", &forbidden);
    assert_no_forbidden_tokens(
        INSTRUCTION_PERMISSION_POLICY_SRC,
        "permission_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        INSTRUCTION_NETWORK_POLICY_SRC,
        "network_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        INSTRUCTION_WEBHOOK_POLICY_SRC,
        "webhook_policy.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(NETWORK_SRC, "network.rs", &forbidden);
    assert_no_forbidden_tokens(NETWORK_TARGETS_SRC, "network/targets.rs", &forbidden);
    assert!(
        PACKAGE_POLICY_SRC.contains("serde_json::from_str")
            || PACKAGE_POLICY_SRC.contains("content.parse::<TomlValue>()"),
        "package.rs should remain the manifest parsing entrypoint"
    );
    assert!(
        PROVENANCE_INVENTORY_MANIFESTS_SRC.contains("serde_json::from_str")
            || PROVENANCE_INVENTORY_MANIFESTS_SRC.contains("toml::from_str"),
        "provenance manifest inventory should own manifest parsing"
    );
    assert!(
        PROVENANCE_INVENTORY_LOCKFILES_SRC.contains("serde_json::from_str")
            || PROVENANCE_INVENTORY_LOCKFILES_SRC.contains("serde_yaml::from_str"),
        "provenance lockfile inventory should own lockfile parsing"
    );
    assert_no_forbidden_tokens(FINDINGS_REPORTING_SRC, "findings/reporting.rs", &forbidden);
    assert_no_forbidden_tokens(
        REASONING_EXPLAINABILITY_TRACES_SRC,
        "reasoning/explainability/traces.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        REASONING_EXPLAINABILITY_SOURCES_SRC,
        "reasoning/explainability/sources.rs",
        &forbidden,
    );
}

#[test]
fn scoring_and_confidence_ownership_stays_out_of_analysis_model() {
    let forbidden = [
        "weighted_score(",
        "signal_weight(",
        "calibrate_confidence(",
        "RiskFactor",
    ];
    assert_no_forbidden_tokens(ANALYSIS_MODEL_SRC, "analysis_model.rs", &forbidden);
    assert_no_forbidden_tokens(DOMAIN_TYPES_SRC, "domain_types.rs", &forbidden);
    assert!(
        FINDINGS_SRC.contains("FindingSummary")
            || include_str!("../findings/reporting.rs").contains("RiskFactor"),
        "findings should remain the home of final scoring/reporting artifacts"
    );
    assert!(
        REASONING_RISK_SRC.contains("composite_capability_risk_bonus")
            && REASONING_RISK_SRC.contains("composite_risk_factors"),
        "reasoning/risk.rs should remain the owner of risk composition entrypoints"
    );
}

#[test]
fn shared_domain_types_do_not_regress_into_observation_or_report_owners() {
    let forbidden = [
        "ObservationBatch",
        "ObservedEvidence",
        "ObservationFinding",
        "FindingSummary",
        "VerdictExplainability",
        "RiskFactor",
        "ObservationSource",
        "RecommendedAction",
    ];
    assert_no_forbidden_tokens(DOMAIN_TYPES_SRC, "domain_types.rs", &forbidden);
}

#[test]
fn scoring_logic_stays_confined_to_findings_and_reasoning() {
    let forbidden = ["weighted_score(", "signal_weight(", "calibrate_confidence("];
    assert_no_forbidden_tokens(ANALYSIS_MODEL_SRC, "analysis_model.rs", &forbidden);
    assert_no_forbidden_tokens(DOMAIN_TYPES_SRC, "domain_types.rs", &forbidden);
    assert_no_forbidden_tokens(NETWORK_RELATIONS_SRC, "network/relations.rs", &forbidden);
    assert_no_forbidden_tokens(PROVENANCE_INVENTORY_SRC, "provenance/inventory.rs", &forbidden);
    assert_no_forbidden_tokens(
        REASONING_EXPLAINABILITY_SOURCES_SRC,
        "reasoning/explainability/sources.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        REASONING_EXPLAINABILITY_TRACES_SRC,
        "reasoning/explainability/traces.rs",
        &forbidden,
    );
    assert!(
        FINDINGS_REPORTING_SRC.contains("RiskFactor"),
        "findings/reporting.rs should remain the owner of report-facing risk factors"
    );
    assert!(
        REASONING_RISK_SRC.contains("RiskContributionSpec"),
        "reasoning/risk.rs should remain the owner of verdict risk composition"
    );
}

#[test]
fn reporting_and_observation_layers_keep_exact_domain_boundaries() {
    let forbidden_reporting = ["ObservationBatch", "ObservedEvidence", "ObservationFinding"];
    assert_no_forbidden_tokens(
        FINDINGS_REPORTING_SRC,
        "findings/reporting.rs",
        &forbidden_reporting,
    );
    let forbidden_analysis = ["RiskFactor", "VerdictExplainability", "ProvenanceSummary"];
    assert_no_forbidden_tokens(ANALYSIS_MODEL_SRC, "analysis_model.rs", &forbidden_analysis);
    assert_no_forbidden_tokens(
        FINDINGS_SRC,
        "findings.rs",
        &["ObservationBatch", "ObservedEvidence", "ObservationSource"],
    );
    assert_no_forbidden_tokens(
        ANALYSIS_MODEL_SRC,
        "analysis_model.rs",
        &["LockfileCoverageSummary", "ManifestInventoryEntry", "ProvenanceTrustLevel"],
    );
    assert_no_forbidden_tokens(
        FINDINGS_SRC,
        "findings.rs",
        &["pub use crate::domain_types::HeuristicSeverity", "ObservedBehavior"],
    );
}

#[test]
fn provenance_inventory_stays_a_composition_layer_not_a_scoring_layer() {
    let forbidden = ["weighted_score(", "signal_weight(", "calibrate_confidence(", "RiskFactor"];
    assert_no_forbidden_tokens(PROVENANCE_INVENTORY_SRC, "provenance/inventory.rs", &forbidden);
    assert_no_forbidden_tokens(
        PROVENANCE_INVENTORY_IDENTITY_SRC,
        "provenance/inventory/identity.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        PROVENANCE_INVENTORY_MANIFESTS_SRC,
        "provenance/inventory/manifests.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        PROVENANCE_INVENTORY_LOCKFILES_SRC,
        "provenance/inventory/lockfiles.rs",
        &forbidden,
    );
    assert!(
        PROVENANCE_INVENTORY_SRC.contains("collect_node_inventory")
            && PROVENANCE_INVENTORY_SRC.contains("finalize_inventory"),
        "provenance/inventory.rs should remain an assembly layer over node collection and final normalization"
    );
}

#[test]
fn exact_domain_boundary_contracts_remain_in_place() {
    assert_no_forbidden_tokens(
        FINDINGS_SRC,
        "findings.rs",
        &["ObservationBatch", "ObservedEvidence", "ObservationSource"],
    );
    assert_no_forbidden_tokens(
        DOMAIN_TYPES_SRC,
        "domain_types.rs",
        &["ObservationBatch", "FindingSummary", "VerdictExplainability"],
    );
    assert_no_forbidden_tokens(
        ANALYSIS_MODEL_SRC,
        "analysis_model.rs",
        &["RiskFactor", "VerdictExplainability", "ProvenanceSummary"],
    );
}

#[test]
fn explainability_and_inventory_submodules_keep_exact_owned_helpers() {
    assert!(
        REASONING_EXPLAINABILITY_SOURCES_SRC.contains("fn source_bucket_for_normalized")
            && REASONING_EXPLAINABILITY_SOURCES_SRC.contains("fn accumulate_source_contribution"),
        "reasoning/explainability/sources.rs should own source bucketing and contribution aggregation helpers"
    );
    assert!(
        REASONING_EXPLAINABILITY_TRACES_SRC.contains("fn factor_traces")
            && REASONING_EXPLAINABILITY_TRACES_SRC.contains("fn root_cause_traces"),
        "reasoning/explainability/traces.rs should own trace assembly helpers"
    );
    assert!(
        PROVENANCE_INVENTORY_SRC.contains("fn ingest_graph_node")
            && PROVENANCE_INVENTORY_SRC.contains("fn finalize_inventory")
            && PROVENANCE_INVENTORY_SRC.contains("fn collect_package_identity"),
        "provenance/inventory.rs should own graph ingestion and inventory normalization helpers"
    );
    assert!(
        NETWORK_RELATIONS_SRC.contains("fn relation_kind_for_url")
            && NETWORK_RELATIONS_SRC.contains("fn artifact_link_for_remote_url"),
        "network/relations.rs should own relation-kind and link-assembly helpers"
    );
}

#[test]
fn shared_domain_boundary_stays_exact_even_for_small_helpers() {
    assert_no_forbidden_tokens(
        DOMAIN_TYPES_SRC,
        "domain_types.rs",
        &["ObservationSource", "ObservationBatch", "FindingSummary", "RiskFactor"],
    );
    assert_no_forbidden_tokens(
        ANALYSIS_MODEL_SRC,
        "analysis_model.rs",
        &[
            "ManifestInventoryEntry",
            "LockfileInventoryEntry",
            "RiskFactor",
            "VerdictExplainability",
        ],
    );
    assert_no_forbidden_tokens(
        FINDINGS_SRC,
        "findings.rs",
        &["ObservationBatch", "ObservedEvidence", "ObservationSource"],
    );
    assert!(
        FINDINGS_SRC.contains("DeduplicationSummary")
            && !FINDINGS_SRC.contains("ObservationFinding"),
        "findings.rs should keep dedup/final finding ownership only"
    );
    assert!(
        ANALYSIS_MODEL_SRC.contains("ObservedEvidence")
            && !ANALYSIS_MODEL_SRC.contains("FindingSummary"),
        "analysis_model.rs should keep observation evidence only, without final summary ownership"
    );
    assert_no_forbidden_tokens(
        ANALYSIS_MODEL_SRC,
        "analysis_model.rs",
        &["LockfileInventoryEntry", "DomainReputation", "PublisherConsistency"],
    );
    assert_no_forbidden_tokens(
        DOMAIN_TYPES_SRC,
        "domain_types.rs",
        &["Finding::builder", "derive_package_verdict", "ObservationBatch"],
    );
    assert_no_forbidden_tokens(
        FINDINGS_REPORTING_SRC,
        "findings/reporting.rs",
        &["ObservationSource", "ObservationBatch", "ObservedEvidence"],
    );
}
