use crate::findings::{
    derive_package_verdict, ArtifactKind, FindingSummary, RecommendedAction, Severity, Verdict,
};
use crate::policy::{
    context_label, severity_to_sarif_level, ContextPolicy, JsonReport, PolicyGenerator,
    SarifArtifactLocation, SarifConfiguration, SarifDriver, SarifLocation, SarifMessage,
    SarifPhysicalLocation, SarifRegion, SarifReport, SarifResult, SarifRule, SarifRun, SarifTool,
    ShieldPolicy,
};
use std::collections::HashMap;

pub(crate) fn generate_shield_md(generator: &PolicyGenerator) -> String {
    let mut output = String::new();
    output.push_str("# SHIELD Policy\n\n");
    output.push_str(&format!("Generated for: `{}`\n\n", generator.skill_name));
    output.push_str("---\n\n");

    let policies = generator.generate_policies();
    let context_policies = generator.generate_context_policies();

    for policy in &policies {
        append_shield_policy(&mut output, policy);
    }

    if !context_policies.is_empty() {
        output.push_str("## Context Policies\n\n");
        for policy in &context_policies {
            append_context_policy(&mut output, policy);
        }
        output.push('\n');
    }

    output.push_str("## Policy Precedence\n\n");
    for stage in &generator.policy_audit.precedence_order {
        output.push_str(&format!("- {}\n", stage));
    }
    output.push('\n');

    if !generator.policy_audit.applied_overrides.is_empty() {
        output.push_str("## Applied Overrides\n\n");
        for applied in &generator.policy_audit.applied_overrides {
            output.push_str(&format!(
                "- {}: {} -> {} ({})\n",
                applied.rule_id, applied.original_action, applied.effective_action, applied.reason
            ));
        }
        output.push('\n');
    }

    output
}

pub(crate) fn generate_json(generator: &PolicyGenerator) -> JsonReport {
    let summary =
        FindingSummary::from_findings_and_graph(&generator.findings, &generator.artifact_graph);
    let primary_findings = split_primary_findings(generator);
    let supporting_findings = split_supporting_findings(generator);
    let primary_summary = FindingSummary::from_findings(&primary_findings);
    let supporting_summary = FindingSummary::from_findings(&supporting_findings);
    let verdict_report = derive_package_verdict(
        &generator.findings,
        &primary_summary,
        &supporting_summary,
        &summary,
    );
    let policies = generator.generate_policies();
    let context_policies = generator.generate_context_policies();

    JsonReport {
        skill_name: generator.skill_name.clone(),
        skill_path: generator.skill_path.clone(),
        extension_kind: generator.extension_kind,
        classification: generator.classification,
        package_id: generator.package_id.clone(),
        identity_source: generator.identity_source,
        structural_validity: generator.structural_validity,
        heuristic_score: generator.heuristic_score,
        timestamp: chrono::Utc::now(),
        findings: generator.findings.clone(),
        primary_findings,
        supporting_findings,
        summary,
        primary_summary,
        supporting_summary,
        verdict: verdict_report.verdict,
        verdict_report,
        artifact_graph: generator.artifact_graph.clone(),
        policies,
        context_policies,
        profile: generator.profile,
        suppression_summary: generator.suppression_summary.clone(),
        policy_audit: generator.policy_audit.clone(),
    }
}

pub(crate) fn generate_sarif(generator: &PolicyGenerator) -> SarifReport {
    let mut rules_map: HashMap<String, _> = HashMap::new();
    for finding in &generator.findings {
        rules_map.entry(finding.rule_id.clone()).or_insert(finding);
    }

    let mut rules: Vec<SarifRule> = rules_map
        .iter()
        .map(|(id, finding)| SarifRule {
            id: id.clone(),
            name: id.clone(),
            short_description: SarifMessage {
                text: finding.reason.clone(),
            },
            full_description: SarifMessage {
                text: format!("{} (Category: {})", finding.reason, finding.category),
            },
            default_configuration: SarifConfiguration {
                level: severity_to_sarif_level(finding.severity),
            },
        })
        .collect();

    let summary =
        FindingSummary::from_findings_and_graph(&generator.findings, &generator.artifact_graph);
    if !summary.action_triggers.is_empty() {
        rules.push(SarifRule {
            id: "SKILL_VEIL_ACTION_TRIGGER".to_string(),
            name: "SKILL_VEIL_ACTION_TRIGGER".to_string(),
            short_description: SarifMessage {
                text: "Contextual policy escalation".to_string(),
            },
            full_description: SarifMessage {
                text:
                    "Explains why contextual artifact capabilities escalated the recommended action"
                        .to_string(),
            },
            default_configuration: SarifConfiguration {
                level: severity_to_sarif_level(match summary.recommended_action {
                    RecommendedAction::Block => Severity::High,
                    RecommendedAction::RequireApproval => Severity::Medium,
                    RecommendedAction::Log => Severity::Low,
                }),
            },
        });
    }

    let report = generate_json(generator);
    rules.push(SarifRule {
        id: "SKILL_VEIL_PACKAGE_VERDICT".to_string(),
        name: "SKILL_VEIL_PACKAGE_VERDICT".to_string(),
        short_description: SarifMessage {
            text: "Final package verdict".to_string(),
        },
        full_description: SarifMessage {
            text: "Explains the final benign/suspicious/malicious package judgment".to_string(),
        },
        default_configuration: SarifConfiguration {
            level: severity_to_sarif_level(match report.verdict {
                Verdict::Malicious => Severity::High,
                Verdict::Suspicious => Severity::Medium,
                Verdict::Benign => Severity::Low,
            }),
        },
    });

    let mut results: Vec<SarifResult> = generator
        .findings
        .iter()
        .map(|finding| SarifResult {
            rule_id: finding.rule_id.clone(),
            level: severity_to_sarif_level(finding.severity),
            message: SarifMessage {
                text: format!("{}: {}", finding.reason, finding.match_value),
            },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: finding
                            .artifact_path
                            .clone()
                            .unwrap_or_else(|| generator.skill_path.clone()),
                    },
                    region: finding
                        .line_number
                        .map(|line| SarifRegion { start_line: line }),
                },
            }],
            properties: Some(serde_json::json!({
                "artifact_kind": finding.artifact_kind,
                "artifact_scope": finding.artifact_scope,
                "signal_class": finding.signal_class,
                "evidence_kind": finding.evidence_kind,
                "recommended_action": finding.recommended_action,
                "package_verdict": report.verdict,
            })),
        })
        .collect();

    results.extend(summary.action_triggers.iter().map(|trigger| SarifResult {
        rule_id: "SKILL_VEIL_ACTION_TRIGGER".to_string(),
        level: severity_to_sarif_level(match trigger.action {
            RecommendedAction::Block => Severity::High,
            RecommendedAction::RequireApproval => Severity::Medium,
            RecommendedAction::Log => Severity::Low,
        }),
        message: SarifMessage {
            text: trigger.rationale.clone(),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: generator.skill_path.clone(),
                },
                region: None,
            },
        }],
        properties: Some(serde_json::json!({
            "recommended_action": trigger.action,
            "trigger_factor": trigger.factor,
            "package_verdict": report.verdict,
        })),
    }));

    results.push(SarifResult {
        rule_id: "SKILL_VEIL_PACKAGE_VERDICT".to_string(),
        level: severity_to_sarif_level(match report.verdict {
            Verdict::Malicious => Severity::High,
            Verdict::Suspicious => Severity::Medium,
            Verdict::Benign => Severity::Low,
        }),
        message: SarifMessage {
            text: format!("Final package verdict: {}", report.verdict),
        },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: generator.skill_path.clone(),
                },
                region: None,
            },
        }],
        properties: Some(serde_json::json!({
            "verdict": report.verdict,
            "verdict_reasons": report.verdict_report.verdict_reasons,
            "root_cause_groups": report.verdict_report.root_cause_groups,
            "top_risk_drivers": report.verdict_report.top_risk_drivers,
            "heuristic_score": report.heuristic_score,
            "artifact_scope": "package",
        })),
    });

    SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "skill-veil".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    information_uri: "https://github.com/seifreed/skill-veil".to_string(),
                    rules,
                },
            },
            results,
        }],
    }
}

fn split_primary_findings(generator: &PolicyGenerator) -> Vec<crate::findings::Finding> {
    generator
        .findings
        .iter()
        .filter(|finding| {
            finding
                .artifact_path
                .as_deref()
                .is_none_or(|artifact_path| artifact_path == generator.skill_path)
                && matches!(
                    finding.artifact_kind,
                    ArtifactKind::SkillDocument
                        | ArtifactKind::AgentInstruction
                        | ArtifactKind::PromptPackDocument
                        | ArtifactKind::McpServerManifest
                        | ArtifactKind::PackageManifest
                )
        })
        .cloned()
        .collect()
}

fn split_supporting_findings(generator: &PolicyGenerator) -> Vec<crate::findings::Finding> {
    generator
        .findings
        .iter()
        .filter(|finding| {
            !(finding
                .artifact_path
                .as_deref()
                .is_none_or(|artifact_path| artifact_path == generator.skill_path)
                && matches!(
                    finding.artifact_kind,
                    ArtifactKind::SkillDocument
                        | ArtifactKind::AgentInstruction
                        | ArtifactKind::PromptPackDocument
                        | ArtifactKind::McpServerManifest
                        | ArtifactKind::PackageManifest
                ))
        })
        .cloned()
        .collect()
}

fn append_shield_policy(output: &mut String, policy: &ShieldPolicy) {
    output.push_str(&format!("## {}\n\n", policy.id));
    output.push_str("```yaml\n");
    output.push_str(&format!("id: {}\n", policy.id));
    output.push_str(&format!("category: {}\n", policy.category));
    output.push_str(&format!("severity: {}\n", policy.severity));
    output.push_str(&format!("confidence: {:.2}\n", policy.confidence));
    output.push_str(&format!("action: {}\n", policy.action));
    output.push_str("recommendation_agent:\n");
    for rec in &policy.recommendation_agent {
        output.push_str(&format!("  - {}\n", rec));
    }
    if let Some(expires) = &policy.expires_at {
        output.push_str(&format!("expires_at: {}\n", expires.format("%Y-%m-%d")));
    }
    output.push_str(&format!("revoked: {}\n", policy.revoked));
    output.push_str("```\n\n");
}

fn append_context_policy(output: &mut String, policy: &ContextPolicy) {
    output.push_str(&format!(
        "- context: {}\n  action: {}\n",
        context_label(policy.context),
        policy.action
    ));
    for rationale in &policy.rationale {
        output.push_str(&format!("  rationale: {}\n", rationale));
    }
}
