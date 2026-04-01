use super::shared::*;

#[test]
fn instructions_and_network_use_explicit_signal_types() {
    assert!(
        INSTRUCTIONS_SRC.contains("InstructionSignals"),
        "instructions.rs must centralize heuristics behind InstructionSignals"
    );
    assert!(
        NETWORK_SRC.contains("NetworkTarget"),
        "network.rs must classify internal targets via NetworkTarget"
    );
    assert!(
        NETWORK_SRC.contains("RemoteRelationKind"),
        "network.rs must model remote relation kinds explicitly"
    );
    assert!(
        NETWORK_SRC.contains("mod patterns;"),
        "network.rs should delegate regex ownership to patterns.rs"
    );
    assert!(
        NETWORK_SRC.contains("mod relations;"),
        "network.rs should delegate relation ownership to relations.rs"
    );
    assert!(
        NETWORK_SRC.contains("mod targets;"),
        "network.rs should delegate internal target classification to targets.rs"
    );
    assert!(
        NETWORK_SRC.contains("mod webhook;"),
        "network.rs should delegate webhook heuristics to webhook.rs"
    );
    assert!(
        NETWORK_TARGETS_SRC.contains("mod classify;"),
        "network/targets.rs should delegate target classification to classify.rs"
    );
    assert!(
        NETWORK_TARGETS_SRC.contains("mod signals;"),
        "network/targets.rs should delegate local and SSRF signals to signals.rs"
    );
    assert!(
        NETWORK_TARGETS_SRC.contains("mod model;"),
        "network/targets.rs should delegate target modeling to model.rs"
    );
}

#[test]
fn manifest_policy_split_stays_explicit() {
    assert!(
        PACKAGE_DEPENDENCY_POLICY_SRC.contains("DependencyPinning"),
        "dependency pinning rules should live in package/dependency_policy.rs"
    );
    assert!(
        PACKAGE_LOCKFILE_POLICY_SRC.contains("PackageJsonLockPolicy"),
        "lockfile expectations should live in package/lockfile_policy.rs"
    );
}

#[test]
fn instruction_policy_split_stays_explicit() {
    assert!(
        INSTRUCTION_POLICIES_SRC.contains("permission_policy::permission_findings"),
        "instructions/policies.rs should delegate permission heuristics"
    );
    assert!(
        INSTRUCTION_POLICIES_SRC.contains("network_policy::network_findings"),
        "instructions/policies.rs should delegate network heuristics"
    );
    assert!(
        INSTRUCTION_POLICIES_SRC.contains("webhook_policy::webhook_findings"),
        "instructions/policies.rs should delegate webhook heuristics"
    );
    assert!(
        INSTRUCTION_PERMISSION_PROFILE_SRC.contains("DeclaredPermissionProfile"),
        "permission profile policy should own declared permission profiling"
    );
    assert!(
        INSTRUCTION_NETWORK_POLICY_SRC.contains("SsrfPattern"),
        "network policy should own SSRF modeling"
    );
    assert!(
        INSTRUCTION_PERMISSION_POLICY_SRC.contains("mod intent_policy;"),
        "permission_policy.rs should delegate intent evaluation"
    );
    assert!(
        INSTRUCTION_PERMISSION_POLICY_SRC.contains("mod profile_policy;"),
        "permission_policy.rs should delegate permission profiling"
    );
    assert!(
        INSTRUCTION_PERMISSION_POLICY_SRC.contains("mod persistence_policy;"),
        "permission_policy.rs should delegate persistence findings"
    );
}

#[test]
fn submodule_imports_stay_within_allowed_core_seams() {
    let forbidden_profile = ["super::super::super::network", "regex::Regex", "serde_json"];
    assert_no_forbidden_tokens(
        INSTRUCTION_PERMISSION_PROFILE_SRC,
        "permission profile policy",
        &forbidden_profile,
    );
    let forbidden_intent = ["super::super::super::network", "regex::Regex", "serde_json"];
    assert_no_forbidden_tokens(
        INSTRUCTION_PERMISSION_INTENT_SRC,
        "permission intent policy",
        &forbidden_intent,
    );
    let forbidden_persistence = ["serde_json", "toml::Value"];
    assert_no_forbidden_tokens(
        INSTRUCTION_PERMISSION_PERSISTENCE_SRC,
        "permission persistence policy",
        &forbidden_persistence,
    );
    let forbidden_network_targets = ["serde_json", "toml::from_str", "extract_http_urls("];
    assert_no_forbidden_tokens(
        NETWORK_TARGETS_SRC,
        "network/targets.rs",
        &forbidden_network_targets,
    );
    let forbidden_network_target_classify = ["serde_json", "toml::from_str", "RE_INTERNAL_ACTION"];
    assert_no_forbidden_tokens(
        NETWORK_TARGETS_CLASSIFY_SRC,
        "network/targets/classify.rs",
        &forbidden_network_target_classify,
    );
    let forbidden_network_target_signals = ["serde_json", "toml::from_str", "RE_RFC1918_10"];
    assert_no_forbidden_tokens(
        NETWORK_TARGETS_SIGNALS_SRC,
        "network/targets/signals.rs",
        &forbidden_network_target_signals,
    );
    let forbidden_network_webhook = ["serde_json", "toml::from_str", "extract_http_urls("];
    assert_no_forbidden_tokens(
        NETWORK_WEBHOOK_SRC,
        "network/webhook.rs",
        &forbidden_network_webhook,
    );
    assert!(
        NETWORK_RELATIONS_SRC.contains("use super::patterns::RE_HTTP_URL;")
            && NETWORK_RELATIONS_SRC.contains("use crate::domain_types::RemoteRelationKind;")
            && NETWORK_RELATIONS_SRC.contains("use super::super::ArtifactLink;"),
        "network/relations.rs should depend only on shared relation typing and owned regex patterns"
    );
    assert!(
        ANALYSIS_MODEL_SRC.contains("use crate::findings::{")
            && !ANALYSIS_MODEL_SRC.contains("use crate::domain_types::"),
        "analysis_model.rs should depend on final finding primitives but not own shared domain value objects"
    );
    assert!(
        FINDINGS_REPORTING_SRC.contains("use crate::domain_types::{")
            && !FINDINGS_REPORTING_SRC.contains("use crate::analysis_model::"),
        "findings/reporting.rs should depend on shared value objects without importing the observation layer"
    );
    assert!(
        FINDINGS_SRC.contains("pub use crate::domain_types::{")
            && !FINDINGS_SRC.contains("pub use crate::analysis_model::"),
        "findings.rs should only re-export shared domain types, not the observation layer"
    );
    assert!(
        !FINDINGS_SRC.contains("ObservationBatch")
            && !FINDINGS_SRC.contains("ObservedEvidence")
            && !FINDINGS_SRC.contains("ObservationSource"),
        "findings.rs should not re-own observation concepts that belong to analysis_model.rs"
    );
    assert!(
        REASONING_EXPLAINABILITY_TRACES_SRC.contains("use crate::findings::{")
            && !REASONING_EXPLAINABILITY_TRACES_SRC.contains("BTreeMap")
            && !REASONING_EXPLAINABILITY_TRACES_SRC.contains("trace_source_for_risk_factor"),
        "reasoning/explainability/traces.rs should import only trace-facing finding types and avoid source aggregation concerns"
    );
    assert!(
        REASONING_EXPLAINABILITY_SOURCES_SRC.contains("use std::collections::BTreeMap;")
            && !REASONING_EXPLAINABILITY_SOURCES_SRC.contains("RootCauseGroup")
            && !REASONING_EXPLAINABILITY_SOURCES_SRC.contains("VerdictCalibrationNote"),
        "reasoning/explainability/sources.rs should own source aggregation only"
    );
    assert!(
        PROVENANCE_INVENTORY_SRC.contains("fn finalize_inventory")
            && PROVENANCE_INVENTORY_SRC.contains("fn ingest_graph_node")
            && !PROVENANCE_INVENTORY_SRC.contains("RiskFactor"),
        "provenance/inventory.rs should finish inventory assembly without absorbing scoring concepts"
    );
    assert!(
        !DOMAIN_TYPES_SRC.contains("use crate::findings::")
            && !DOMAIN_TYPES_SRC.contains("use crate::analysis_model::"),
        "domain_types.rs must stay independent from observation and final finding layers"
    );
    assert!(
        ANALYSIS_MODEL_SRC.contains("use crate::findings::{")
            && !ANALYSIS_MODEL_SRC.contains("use crate::domain_types::"),
        "analysis_model.rs should depend on finding primitives only, not re-own shared value objects"
    );
    assert!(
        ANALYSIS_MODEL_SRC.contains("pub enum ObservationSource")
            && ANALYSIS_MODEL_SRC.contains("pub struct ObservationBatch")
            && !ANALYSIS_MODEL_SRC.contains("FindingSummary"),
        "analysis_model.rs should explicitly own observation taxonomy and nothing report-facing"
    );
    assert!(
        DOMAIN_TYPES_SRC.contains("use serde::{Deserialize, Serialize};")
            && DOMAIN_TYPES_SRC.contains("use strum_macros::Display;"),
        "domain_types.rs should only depend on serialization/display helpers, not internal layers"
    );
    assert!(
        REASONING_RISK_SRC.contains("fn provenance_bonus")
            && REASONING_RISK_SRC.contains("fn composite_specs_to_risk_factors"),
        "reasoning/risk.rs should keep risk helpers explicit instead of inlining all contribution flow"
    );
    assert!(
        FINDINGS_SRC.contains("mod model;")
            && FINDINGS_SRC.contains("mod reporting;")
            && FINDINGS_SRC.contains("pub use crate::domain_types::{"),
        "findings.rs should stay a thin facade over model/reporting plus shared domain reexports"
    );
    assert!(
        DOMAIN_TYPES_SRC.contains("pub enum HeuristicSeverity")
            && DOMAIN_TYPES_SRC.contains("pub enum RemoteRelationKind")
            && !DOMAIN_TYPES_SRC.contains("ObservationSource"),
        "domain_types.rs should own shared severity/relation value objects only"
    );
    assert!(
        FINDINGS_SRC.contains("pub use crate::verdict::derive_package_verdict;")
            && !FINDINGS_SRC.contains("pub use crate::analysis_model::"),
        "findings.rs should re-export final verdict assembly only, never observation-layer symbols"
    );
    assert!(
        ANALYSIS_MODEL_SRC.contains("use crate::findings::{")
            && ANALYSIS_MODEL_SRC.contains("ArtifactKind")
            && ANALYSIS_MODEL_SRC.contains("ThreatCategory")
            && !ANALYSIS_MODEL_SRC.contains("LockfileCoverageSummary")
            && !ANALYSIS_MODEL_SRC.contains("ProvenanceTrustLevel"),
        "analysis_model.rs should import only finding primitives needed for observations, never shared provenance/reporting value objects"
    );
    assert!(
        FINDINGS_SRC.contains("pub use crate::domain_types::{")
            && FINDINGS_SRC.contains("ProvenanceTrustLevel")
            && FINDINGS_SRC.contains("ManifestInventoryEntry")
            && !FINDINGS_SRC.contains("pub use crate::domain_types::HeuristicSeverity"),
        "findings.rs should re-export only report-facing shared domain types, not internal reasoning severity types"
    );
    assert!(
        DOMAIN_TYPES_SRC.contains("pub struct ManifestInventoryEntry")
            && DOMAIN_TYPES_SRC.contains("pub struct LockfileInventoryEntry")
            && !ANALYSIS_MODEL_SRC.contains("ManifestInventoryEntry")
            && !ANALYSIS_MODEL_SRC.contains("LockfileInventoryEntry"),
        "inventory/report-facing value objects must remain owned by domain_types and stay out of analysis_model.rs"
    );
    assert!(
        FINDINGS_REPORTING_SRC.contains("use crate::domain_types::{")
            && !FINDINGS_REPORTING_SRC.contains("ObservationSource")
            && !FINDINGS_REPORTING_SRC.contains("ObservationBatch"),
        "findings/reporting.rs should stay bound to shared report-facing value objects, never observation taxonomy"
    );
}

#[test]
fn provenance_split_stays_explicit() {
    assert!(
        PROVENANCE_SRC.contains("mod inventory;"),
        "provenance.rs should delegate inventory derivation"
    );
    assert!(
        PROVENANCE_SRC.contains("mod lineage;"),
        "provenance.rs should delegate lineage evaluation"
    );
    assert!(
        PROVENANCE_SRC.contains("mod origin;"),
        "provenance.rs should delegate origin classification"
    );
    assert!(
        PROVENANCE_SRC.contains("mod publisher;"),
        "provenance.rs should delegate publisher extraction"
    );
    assert!(
        PROVENANCE_SRC.contains("collect_provenance_inventory"),
        "provenance.rs should delegate filesystem-backed inventory collection"
    );
    assert!(
        PROVENANCE_INVENTORY_SRC.contains("mod identity;"),
        "provenance/inventory.rs should delegate package identity parsing"
    );
    assert!(
        PROVENANCE_INVENTORY_SRC.contains("mod manifests;"),
        "provenance/inventory.rs should delegate manifest inventory derivation"
    );
    assert!(
        PROVENANCE_INVENTORY_SRC.contains("mod lockfiles;"),
        "provenance/inventory.rs should delegate lockfile inventory derivation"
    );
    assert!(
        PROVENANCE_INVENTORY_IDENTITY_SRC.contains("PackageIdentity"),
        "inventory/identity.rs should use shared package identity modeling"
    );
    assert!(
        PROVENANCE_INVENTORY_MANIFESTS_SRC.contains("derive_manifest_inventory"),
        "inventory/manifests.rs should own manifest inventory derivation"
    );
    assert!(
        PROVENANCE_INVENTORY_LOCKFILES_SRC.contains("derive_lockfile_inventory"),
        "inventory/lockfiles.rs should own lockfile inventory derivation"
    );
    assert!(
        PROVENANCE_ORIGIN_SRC.contains("RemoteOriginAssessment"),
        "origin.rs should own provenance origin assessment"
    );
    assert!(
        PROVENANCE_LINEAGE_SRC.contains("derive_lockfile_coverage"),
        "lineage.rs should own lockfile coverage derivation"
    );
    assert!(
        PROVENANCE_PUBLISHER_SRC.contains("derive_publisher_consistency"),
        "publisher.rs should own publisher consistency evaluation"
    );
}

#[test]
fn reasoning_owns_risk_composition_value_objects() {
    assert!(
        REASONING_SRC.contains("mod explainability;"),
        "reasoning.rs should delegate explainability assembly"
    );
    assert!(
        REASONING_SRC.contains("mod top_reasons;"),
        "reasoning.rs should delegate top reason derivation"
    );
    assert!(
        REASONING_SRC.contains("mod compounds;"),
        "reasoning.rs should delegate compound verdict detection"
    );
    assert!(
        REASONING_SRC.contains("mod risk;"),
        "reasoning.rs should delegate risk amplification"
    );
    assert!(
        REASONING_MODEL_SRC.contains("HeuristicSeverity"),
        "reasoning/model.rs should re-export normalized heuristic severity"
    );
    assert!(
        REASONING_MODEL_SRC.contains("CalibrationAdjustment"),
        "reasoning/model.rs should re-export calibration adjustment modeling"
    );
    assert!(
        DOMAIN_TYPES_SRC.contains("enum HeuristicSeverity"),
        "domain_types.rs should own shared heuristic severity"
    );
    assert!(
        DOMAIN_TYPES_SRC.contains("struct CalibrationAdjustment"),
        "domain_types.rs should own shared calibration adjustment"
    );
    assert!(
        DOMAIN_TYPES_SRC.contains("enum RemoteRelationKind"),
        "domain_types.rs should own shared remote relation typing"
    );
    assert!(
        DOMAIN_TYPES_SRC.contains("struct PackageIdentity"),
        "domain_types.rs should own shared package identity modeling"
    );
    assert!(
        DOMAIN_TYPES_SRC.contains("enum ProvenanceTrustLevel"),
        "domain_types.rs should own reusable provenance trust levels"
    );
    assert!(
        DOMAIN_TYPES_SRC.contains("struct ManifestInventoryEntry"),
        "domain_types.rs should own reusable manifest inventory entries"
    );
    assert!(
        DOMAIN_TYPES_SRC.contains("struct LockfileInventoryEntry"),
        "domain_types.rs should own reusable lockfile inventory entries"
    );
    assert!(
        REASONING_RISK_SRC.contains("RiskContributionSpec"),
        "reasoning/risk.rs should own the risk contribution composition contract"
    );
    assert!(
        REASONING_TOP_REASONS_SRC.contains("map_factor_to_reason"),
        "reasoning/top_reasons.rs should own top-reason mapping"
    );
    assert!(
        REASONING_COMPOUNDS_SRC.contains("detect_compound_verdict_reasons"),
        "reasoning/compounds.rs should own compound verdict detection"
    );
    assert!(
        REASONING_EXPLAINABILITY_SRC.contains("mod traces;")
            && REASONING_EXPLAINABILITY_SRC.contains("mod sources;"),
        "reasoning/explainability.rs should explicitly route trace and source ownership"
    );
    assert!(
        REASONING_EXPLAINABILITY_TRACES_SRC.contains("collect_traces"),
        "reasoning/explainability/traces.rs should own trace assembly"
    );
    assert!(
        REASONING_EXPLAINABILITY_SOURCES_SRC.contains("summarize_source_contributions")
            && REASONING_EXPLAINABILITY_SOURCES_SRC.contains("trace_source_for_risk_factor"),
        "reasoning/explainability/sources.rs should own source attribution and drift heuristics"
    );
    assert!(
        REASONING_EXPLAINABILITY_TRACES_SRC.contains("use crate::findings::")
            && !REASONING_EXPLAINABILITY_TRACES_SRC.contains("BTreeMap"),
        "reasoning/explainability/traces.rs should stay focused on trace assembly, not source aggregation"
    );
    assert!(
        REASONING_EXPLAINABILITY_SOURCES_SRC.contains("use std::collections::BTreeMap;")
            && !REASONING_EXPLAINABILITY_SOURCES_SRC.contains("RootCauseGroup")
            && !REASONING_EXPLAINABILITY_SOURCES_SRC.contains("VerdictCalibrationNote"),
        "reasoning/explainability/sources.rs should own source aggregation and drift heuristics, not root-cause or calibration trace assembly"
    );
}

#[test]
fn analysis_model_owns_observations_while_findings_own_final_results() {
    assert!(
        ANALYSIS_MODEL_SRC.contains("enum ObservationSource"),
        "analysis_model.rs should own observation source taxonomy"
    );
    assert!(
        ANALYSIS_MODEL_SRC.contains("struct ObservationFinding"),
        "analysis_model.rs should own observation-level finding envelopes"
    );
    assert!(
        ANALYSIS_MODEL_SRC.contains("enum ObservedEvidence"),
        "analysis_model.rs should own observation evidence variants"
    );
    assert!(
        ANALYSIS_MODEL_SRC.contains("struct ObservationBatch"),
        "analysis_model.rs should own observation batch assembly"
    );
    assert!(
        !FINDINGS_SRC.contains("ObservationFinding")
            && !FINDINGS_SRC.contains("ObservedEvidence")
            && !FINDINGS_SRC.contains("ObservationBatch"),
        "findings.rs should not re-own observation-layer concepts"
    );
    assert!(
        FINDINGS_SRC.contains("pub use crate::domain_types::"),
        "findings.rs should re-export shared domain types without owning them"
    );
    assert!(
        FINDINGS_REPORTING_SRC.contains("pub struct ProvenanceSummary"),
        "findings/reporting.rs should remain the owner of final provenance report summaries"
    );
    assert!(
        FINDINGS_REPORTING_SRC.contains("use crate::domain_types::"),
        "findings/reporting.rs should consume shared domain types instead of redefining them"
    );
    assert!(
        !FINDINGS_REPORTING_SRC.contains("enum ProvenanceTrustLevel")
            && !FINDINGS_REPORTING_SRC.contains("enum PublisherConsistency")
            && !FINDINGS_REPORTING_SRC.contains("enum DomainReputation")
            && !FINDINGS_REPORTING_SRC.contains("struct ManifestInventoryEntry")
            && !FINDINGS_REPORTING_SRC.contains("struct LockfileInventoryEntry"),
        "findings/reporting.rs must not re-own shared provenance and inventory value objects"
    );
    assert!(
        !ANALYSIS_MODEL_SRC.contains("HeuristicSeverity")
            && !ANALYSIS_MODEL_SRC.contains("CalibrationAdjustment")
            && !ANALYSIS_MODEL_SRC.contains("ProvenanceTrustLevel"),
        "analysis_model.rs should stay focused on observations, not shared risk/provenance modeling"
    );
    assert!(
        !FINDINGS_SRC.contains("ObservationSource")
            && !FINDINGS_REPORTING_SRC.contains("ObservationSource"),
        "finding layers must not re-own observation source taxonomy"
    );
}

#[test]
fn shared_domain_taxonomy_stays_explicit() {
    assert!(
        DOMAIN_TYPES_SRC.contains("Shared domain value objects"),
        "domain_types.rs should document its shared-domain ownership"
    );
    assert!(
        ANALYSIS_MODEL_SRC.contains("Observation-layer analysis model"),
        "analysis_model.rs should document observation ownership"
    );
    assert!(
        FINDINGS_SRC.contains("final findings, deduplication, scoring summaries"),
        "findings.rs should document final-result ownership"
    );
    assert!(
        !DOMAIN_TYPES_SRC.contains("ObservationBatch")
            && !DOMAIN_TYPES_SRC.contains("VerdictExplainability")
            && !DOMAIN_TYPES_SRC.contains("FindingSummary"),
        "domain_types.rs must stay free of observation and final report concepts"
    );
    assert!(
        !ANALYSIS_MODEL_SRC.contains("VerdictExplainability")
            && !ANALYSIS_MODEL_SRC.contains("ProvenanceSummary"),
        "analysis_model.rs must stay free of final verdict/report summaries"
    );
    assert!(
        !DOMAIN_TYPES_SRC.contains("serde_json::from_str")
            && !DOMAIN_TYPES_SRC.contains("toml::from_str")
            && !DOMAIN_TYPES_SRC.contains("Regex::new"),
        "domain_types.rs must stay free of parsing and regex ownership"
    );
    assert!(
        !DOMAIN_TYPES_SRC.contains("FindingSummary")
            && !DOMAIN_TYPES_SRC.contains("VerdictReason")
            && !DOMAIN_TYPES_SRC.contains("ObservationSource"),
        "domain_types.rs must remain limited to shared value objects, not report or observation enums"
    );
    assert!(
        FINDINGS_REPORTING_SRC.contains("use crate::domain_types::"),
        "findings/reporting.rs should import shared domain types instead of redefining them"
    );
    assert!(
        !FINDINGS_REPORTING_SRC.contains("ObservationBatch")
            && !FINDINGS_REPORTING_SRC.contains("ObservedEvidence"),
        "findings/reporting.rs must stay free of observation-layer concepts"
    );
    assert!(
        !FINDINGS_SRC.contains("ObservationSource")
            && !FINDINGS_REPORTING_SRC.contains("ObservationSource"),
        "finding layers must stay free of observation taxonomy symbols"
    );
    assert!(
        FINDINGS_SRC.contains("pub use crate::domain_types::{")
            && !FINDINGS_SRC.contains("ObservationSource"),
        "findings.rs should only re-export shared domain types, not re-own observation taxonomy"
    );
}

#[test]
fn provenance_inventory_submodules_keep_stable_import_boundaries() {
    let forbidden_identity = ["regex::Regex", "serde_yaml::from_str", "super::super::origin"];
    assert_no_forbidden_tokens(
        PROVENANCE_INVENTORY_IDENTITY_SRC,
        "inventory/identity.rs",
        &forbidden_identity,
    );

    let forbidden_manifests = ["regex::Regex", "serde_yaml::from_str", "extract_publishers("];
    assert_no_forbidden_tokens(
        PROVENANCE_INVENTORY_MANIFESTS_SRC,
        "inventory/manifests.rs",
        &forbidden_manifests,
    );

    let forbidden_lockfiles = ["toml::from_str", "extract_publishers("];
    assert_no_forbidden_tokens(
        PROVENANCE_INVENTORY_LOCKFILES_SRC,
        "inventory/lockfiles.rs",
        &forbidden_lockfiles,
    );
}

#[test]
fn reasoning_submodules_keep_stable_import_boundaries() {
    let forbidden_explainability = ["serde_json", "toml::from_str", "regex::Regex"];
    assert_no_forbidden_tokens(
        REASONING_EXPLAINABILITY_SRC,
        "reasoning/explainability.rs",
        &forbidden_explainability,
    );
    assert_no_forbidden_tokens(
        REASONING_EXPLAINABILITY_TRACES_SRC,
        "reasoning/explainability/traces.rs",
        &forbidden_explainability,
    );
    assert_no_forbidden_tokens(
        REASONING_EXPLAINABILITY_SOURCES_SRC,
        "reasoning/explainability/sources.rs",
        &forbidden_explainability,
    );

    let forbidden_top_reasons = ["serde_json", "toml::from_str", "regex::Regex"];
    assert_no_forbidden_tokens(
        REASONING_TOP_REASONS_SRC,
        "reasoning/top_reasons.rs",
        &forbidden_top_reasons,
    );

    let forbidden_compounds = ["serde_json", "toml::from_str", "regex::Regex"];
    assert_no_forbidden_tokens(
        REASONING_COMPOUNDS_SRC,
        "reasoning/compounds.rs",
        &forbidden_compounds,
    );
}

#[test]
fn network_submodules_keep_stable_import_boundaries() {
    let forbidden_relations = ["serde_json", "toml::from_str", "RE_OPTIONAL_WEBHOOK_DOCS"];
    assert_no_forbidden_tokens(
        NETWORK_RELATIONS_SRC,
        "network/relations.rs",
        &forbidden_relations,
    );
    let forbidden_targets = ["serde_json", "toml::from_str", "extract_http_urls("];
    assert_no_forbidden_tokens(
        NETWORK_TARGETS_SRC,
        "network/targets.rs",
        &forbidden_targets,
    );
    assert!(
        NETWORK_TARGETS_MODEL_SRC.contains("enum NetworkTarget"),
        "network/targets/model.rs should own target modeling"
    );
    let forbidden_webhook = ["serde_json", "toml::from_str", "extract_http_urls("];
    assert_no_forbidden_tokens(
        NETWORK_WEBHOOK_SRC,
        "network/webhook.rs",
        &forbidden_webhook,
    );
    assert!(
        NETWORK_RELATIONS_SRC.contains("Self::Downloads")
            || NETWORK_RELATIONS_SRC.contains("RemoteRelationKind::Downloads"),
        "network/relations.rs should own connect-vs-download relation classification"
    );
    assert!(
        NETWORK_RELATIONS_SRC.contains("is_download_like_url"),
        "network/relations.rs should isolate download heuristics behind a dedicated helper"
    );
    assert!(
        NETWORK_RELATIONS_SRC.contains("trim_trailing_url_delimiters"),
        "network/relations.rs should isolate URL trimming behind a dedicated helper"
    );
}
