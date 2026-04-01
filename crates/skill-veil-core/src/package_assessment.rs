use crate::analyzer::{
    ArtifactClassification, ArtifactIdentitySource, EcosystemProfile, SkillDocument,
    StructuralValidity,
};
use crate::artifact_graph::ArtifactGraph;
use crate::behavior_graph::BehaviorGraph;
use crate::execution_model::ExecutionModel;
use crate::findings::{Finding, FindingSummary, PackageVerdictReport};
use crate::policy::{PolicyAudit, PolicyFile, PolicyInput};
use crate::policy_eval::PolicyEvaluator;
use crate::verdict::derive_package_verdict;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PackageAssessmentInput<'a> {
    pub path: &'a Path,
    pub doc: &'a SkillDocument,
    pub findings: &'a [Finding],
    pub package_summary: &'a FindingSummary,
    pub primary_summary: &'a FindingSummary,
    pub supporting_summary: &'a FindingSummary,
    pub artifact_graph: &'a ArtifactGraph,
    pub package_id: Option<String>,
    pub classification: ArtifactClassification,
    pub identity_source: ArtifactIdentitySource,
    pub structural_validity: StructuralValidity,
    pub heuristic_score: u8,
    pub ecosystem_profile: EcosystemProfile,
    pub base_policy_audit: PolicyAudit,
    pub policy: Option<PolicyFile>,
}

#[derive(Debug, Clone)]
pub struct PackageAssessment {
    pub verdict_report: PackageVerdictReport,
    pub behavior_graph: BehaviorGraph,
    pub execution_model: ExecutionModel,
    pub policy_audit: PolicyAudit,
}

pub struct PackageAssessmentPipeline;

impl PackageAssessmentPipeline {
    #[must_use]
    pub fn assess(input: PackageAssessmentInput<'_>) -> PackageAssessment {
        let verdict_report = derive_package_verdict(
            input.findings,
            input.primary_summary,
            input.supporting_summary,
            input.package_summary,
            input.artifact_graph,
        );
        let behavior_graph =
            BehaviorGraph::derive(input.path, input.artifact_graph, &verdict_report);
        let execution_model = ExecutionModel::derive(&behavior_graph);
        let policy_audit = evaluate_policy_audit(&input);

        PackageAssessment {
            verdict_report,
            behavior_graph,
            execution_model,
            policy_audit,
        }
    }
}

fn evaluate_policy_audit(input: &PackageAssessmentInput<'_>) -> PolicyAudit {
    let policy_input = PolicyInput {
        skill_name: input.doc.name.clone(),
        skill_path: input.path.to_string_lossy().into_owned(),
        extension_kind: input.doc.extension_kind,
        ecosystem_profile: input.ecosystem_profile,
        classification: input.classification,
        package_id: input.package_id.clone(),
        identity_source: input.identity_source,
        structural_validity: input.structural_validity,
        heuristic_score: input.heuristic_score,
        findings: input.findings.to_vec(),
        artifact_graph: input.artifact_graph.clone(),
        profile: None,
        policy: input.policy.clone(),
        suppression_summary: Default::default(),
        policy_audit: input.base_policy_audit.clone(),
        coverage_issues: Vec::new(),
        skipped_paths: Vec::new(),
    };

    PolicyEvaluator::evaluate(&policy_input).policy_audit
}
