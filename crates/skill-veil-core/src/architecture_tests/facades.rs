use super::shared::*;

#[test]
fn core_facades_do_not_embed_infrastructure_details() {
    let forbidden = ["std::fs", "serde_json", "serde_yaml", "toml::Value", "regex::Regex"];
    assert_no_forbidden_tokens(RULES_SRC, "rules.rs", &forbidden);
    assert_no_forbidden_tokens(FINDINGS_SRC, "findings.rs", &forbidden);
    assert_no_forbidden_tokens(ANALYSIS_MODEL_SRC, "analysis_model.rs", &forbidden);
    assert_no_forbidden_tokens(
        ARTIFACT_ANALYSIS_SRC,
        "services/artifact_analysis.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        MANIFESTS_FACADE_SRC,
        "services/artifact_analysis/manifests.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(
        DISPATCH_SRC,
        "services/artifact_analysis/dispatch.rs",
        &forbidden,
    );
    assert_no_forbidden_tokens(VERDICT_SRC, "verdict.rs", &forbidden);
    assert_no_forbidden_tokens(PROVENANCE_SRC, "verdict/provenance.rs", &forbidden);
}

#[test]
fn facade_modules_stay_thin() {
    assert!(
        FINDINGS_SRC.lines().count() <= 320,
        "findings.rs should remain a thin export and dedup facade"
    );
    assert!(
        VERDICT_SRC.lines().count() <= 240,
        "verdict.rs should remain a thin assembly facade"
    );
    assert!(
        MANIFESTS_FACADE_SRC.lines().count() <= 140,
        "manifests.rs should remain a thin routing facade"
    );
    assert!(
        INSTRUCTIONS_SRC.lines().count() <= 90,
        "instructions.rs should remain a thin routing facade"
    );
    assert!(
        INSTRUCTION_POLICIES_SRC.lines().count() <= 40,
        "instructions/policies.rs should remain a thin routing facade"
    );
    assert!(
        INSTRUCTION_PERMISSION_POLICY_SRC.lines().count() <= 30,
        "permission_policy.rs should remain a thin routing facade"
    );
    assert!(
        PROVENANCE_SRC.lines().count() <= 220,
        "provenance.rs should remain a thin assembly facade"
    );
    assert!(
        PROVENANCE_INVENTORY_SRC.lines().count() <= 320,
        "provenance/inventory.rs should remain a thin assembly facade"
    );
    assert!(
        REASONING_SRC.lines().count() <= 20,
        "reasoning.rs should remain a thin routing facade"
    );
    assert!(
        REASONING_EXPLAINABILITY_SRC.lines().count() <= 80,
        "reasoning/explainability.rs should remain a thin explainability assembly facade"
    );
    assert!(
        REASONING_EXPLAINABILITY_TRACES_SRC.lines().count() <= 405,
        "reasoning/explainability/traces.rs should stay focused on trace assembly"
    );
    assert!(
        REASONING_EXPLAINABILITY_SOURCES_SRC.lines().count() <= 330,
        "reasoning/explainability/sources.rs should stay focused on source attribution and drift heuristics"
    );
    assert!(
        NETWORK_SRC.lines().count() <= 20,
        "network.rs should remain a thin routing facade"
    );
    assert!(
        NETWORK_TARGETS_SRC.lines().count() <= 20,
        "network/targets.rs should remain a thin routing facade"
    );
    assert!(
        ANALYSIS_MODEL_SRC.lines().count() <= 260,
        "analysis_model.rs should remain focused on observations, not turn into another god module"
    );
    assert!(
        NETWORK_RELATIONS_SRC.lines().count() <= 250,
        "network/relations.rs should stay focused on relation classification, not grow into a large parser"
    );
    assert!(
        FINDINGS_REPORTING_SRC.lines().count() <= 680,
        "findings/reporting.rs should remain a reporting module, not absorb unrelated domain logic"
    );
    assert!(
        REASONING_RISK_SRC.lines().count() <= 360,
        "reasoning/risk.rs should stay focused on risk composition rather than absorb broader verdict logic"
    );
}
