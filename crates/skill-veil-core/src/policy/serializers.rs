use super::{
    context_label, severity_to_sarif_level, ContextPolicy, JsonReport, PolicyGenerator,
    SarifArtifactLocation, SarifConfiguration, SarifDriver, SarifLocation, SarifMessage,
    SarifPhysicalLocation, SarifRegion, SarifReport, SarifResult, SarifRule, SarifRun, SarifTool,
    ShieldPolicy,
};
use crate::findings::{
    Finding, FindingSummary, PackageVerdictReport, RecommendedAction, Severity, Verdict,
};
use crate::verdict::derive_package_verdict;
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;

pub(crate) fn generate_shield_md(generator: &PolicyGenerator) -> String {
    let mut output = String::new();
    output.push_str("# SHIELD Policy\n\n");
    output.push_str(&format!("Generated for: `{}`\n\n", generator.skill_name()));
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
    for stage in &generator.policy_audit().precedence_order {
        output.push_str(&format!("- {}\n", stage));
    }
    output.push('\n');

    if !generator.policy_audit().applied_overrides.is_empty() {
        output.push_str("## Applied Overrides\n\n");
        for applied in &generator.policy_audit().applied_overrides {
            output.push_str(&format!(
                "- {}: {} -> {} ({})\n",
                applied.rule_id, applied.original_action, applied.effective_action, applied.reason
            ));
        }
        output.push('\n');
    }

    output
}

fn scope_findings_and_summaries(
    generator: &PolicyGenerator,
) -> (Vec<Finding>, Vec<Finding>, FindingSummary, FindingSummary) {
    let skill_path = std::path::Path::new(generator.skill_path());
    let (primary_findings, supporting_findings) = crate::findings::split_findings_by_scope(
        skill_path,
        generator.primary_artifact_kind(),
        generator.findings(),
    );
    let primary_summary =
        FindingSummary::from_findings_and_graph(&primary_findings, generator.artifact_graph());
    let supporting_summary =
        FindingSummary::from_findings_and_graph(&supporting_findings, generator.artifact_graph());
    (
        primary_findings,
        supporting_findings,
        primary_summary,
        supporting_summary,
    )
}

pub(crate) fn generate_json(generator: &PolicyGenerator) -> JsonReport {
    let summary =
        FindingSummary::from_findings_and_graph(generator.findings(), generator.artifact_graph());
    let (primary_findings, supporting_findings, primary_summary, supporting_summary) =
        scope_findings_and_summaries(generator);
    let verdict_report = generator.verdict_report().cloned().unwrap_or_else(|| {
        derive_package_verdict(
            generator.findings(),
            &primary_summary,
            &supporting_summary,
            &summary,
        )
    });
    let policies = generator.generate_policies();
    let context_policies = generator.generate_context_policies();

    JsonReport {
        skill_name: generator.skill_name().to_string(),
        skill_path: generator.skill_path().to_string(),
        extension_kind: generator.extension_kind(),
        classification: generator.classification(),
        package_id: generator.package_id().map(ToString::to_string),
        identity_source: generator.identity_source(),
        structural_validity: generator.structural_validity(),
        heuristic_score: generator.heuristic_score(),
        timestamp: chrono::Utc::now(),
        findings: generator.findings().to_vec(),
        primary_findings,
        supporting_findings,
        summary,
        primary_summary,
        supporting_summary,
        verdict: verdict_report.verdict,
        verdict_report,
        artifact_graph: generator.artifact_graph().clone(),
        policies,
        context_policies,
        profile: generator.profile(),
        suppression_summary: generator.suppression_summary().clone(),
        policy_audit: generator.policy_audit().clone(),
    }
}

pub(crate) fn generate_sarif(generator: &PolicyGenerator) -> SarifReport {
    let summary =
        FindingSummary::from_findings_and_graph(generator.findings(), generator.artifact_graph());
    let verdict_report = resolve_verdict_report(generator, &summary);
    let rules = build_sarif_rules(generator.findings(), &summary, &verdict_report);
    let mut results = build_sarif_finding_results(
        generator.findings(),
        generator.skill_path(),
        &verdict_report,
    );
    results.extend(build_sarif_trigger_results(
        &summary,
        generator.skill_path(),
        &verdict_report,
    ));
    results.push(build_sarif_verdict_result(
        generator.skill_path(),
        generator.heuristic_score(),
        &verdict_report,
    ));
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

fn resolve_verdict_report(
    generator: &PolicyGenerator,
    summary: &FindingSummary,
) -> PackageVerdictReport {
    generator.verdict_report().cloned().unwrap_or_else(|| {
        let (_, _, primary_summary, supporting_summary) = scope_findings_and_summaries(generator);
        derive_package_verdict(
            generator.findings(),
            &primary_summary,
            &supporting_summary,
            summary,
        )
    })
}

fn build_sarif_rules(
    findings: &[Finding],
    summary: &FindingSummary,
    verdict_report: &PackageVerdictReport,
) -> Vec<SarifRule> {
    let mut rules_map: HashMap<String, &Finding> = HashMap::new();
    for finding in findings {
        rules_map
            .entry(finding.rule_id.clone())
            .and_modify(|existing| {
                if finding.severity > existing.severity {
                    *existing = finding;
                }
            })
            .or_insert(finding);
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
                level: severity_to_sarif_level(finding.severity).to_string(),
            },
        })
        .collect();
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
                })
                .to_string(),
            },
        });
    }
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
            level: severity_to_sarif_level(match verdict_report.verdict {
                Verdict::Malicious => Severity::High,
                Verdict::Suspicious => Severity::Medium,
                Verdict::Benign => Severity::Low,
            })
            .to_string(),
        },
    });
    rules
}

fn sarif_location(uri: String, region: Option<SarifRegion>) -> SarifLocation {
    SarifLocation {
        physical_location: Some(SarifPhysicalLocation {
            artifact_location: SarifArtifactLocation { uri },
            region,
        }),
    }
}

/// Build the SARIF `locations` array for a finding.
///
/// Returns an empty vector when the finding has no concrete `artifact_path`
/// — SARIF 2.1.0 permits omitting locations on `result` objects, and that
/// is more honest than the pre-fix behaviour of fabricating a location
/// that pointed at the package's `SKILL.md`. Viewers that group results
/// by file (CodeQL UI, GitHub Code Scanning) would otherwise attribute
/// these "graph-derived" findings to the wrong file.
fn sarif_locations_for_finding(finding: &Finding) -> Vec<SarifLocation> {
    finding
        .artifact_path
        .as_ref()
        .map(|path| {
            vec![sarif_location(
                path.clone(),
                finding
                    .line_number
                    .map(|line| SarifRegion { start_line: line }),
            )]
        })
        .unwrap_or_default()
}

fn build_sarif_finding_results(
    findings: &[Finding],
    skill_path: &str,
    verdict_report: &PackageVerdictReport,
) -> Vec<SarifResult> {
    let _ = skill_path; // kept for signature compatibility with sibling builders
    findings
        .iter()
        .map(|finding| SarifResult {
            rule_id: finding.rule_id.clone(),
            level: severity_to_sarif_level(finding.severity).to_string(),
            message: SarifMessage {
                text: format!("{}: {}", finding.reason, finding.match_value),
            },
            locations: sarif_locations_for_finding(finding),
            properties: Some(serde_json::json!({
                "artifact_kind": finding.artifact_kind,
                "artifact_scope": finding.artifact_scope,
                "signal_class": finding.signal_class,
                "evidence_kind": finding.evidence_kind,
                "recommended_action": finding.recommended_action,
                "package_verdict": verdict_report.verdict,
            })),
        })
        .collect()
}

fn build_sarif_trigger_results(
    summary: &FindingSummary,
    skill_path: &str,
    verdict_report: &PackageVerdictReport,
) -> Vec<SarifResult> {
    summary
        .action_triggers
        .iter()
        .map(|trigger| SarifResult {
            rule_id: "SKILL_VEIL_ACTION_TRIGGER".to_string(),
            level: severity_to_sarif_level(match trigger.action {
                RecommendedAction::Block => Severity::High,
                RecommendedAction::RequireApproval => Severity::Medium,
                RecommendedAction::Log => Severity::Low,
            })
            .to_string(),
            message: SarifMessage {
                text: trigger.rationale.clone(),
            },
            locations: vec![sarif_location(skill_path.to_string(), None)],
            properties: Some(serde_json::json!({
                "recommended_action": trigger.action,
                "trigger_factor": trigger.factor,
                "package_verdict": verdict_report.verdict,
            })),
        })
        .collect()
}

fn build_sarif_verdict_result(
    skill_path: &str,
    heuristic_score: u8,
    verdict_report: &PackageVerdictReport,
) -> SarifResult {
    SarifResult {
        rule_id: "SKILL_VEIL_PACKAGE_VERDICT".to_string(),
        level: severity_to_sarif_level(match verdict_report.verdict {
            Verdict::Malicious => Severity::High,
            Verdict::Suspicious => Severity::Medium,
            Verdict::Benign => Severity::Low,
        })
        .to_string(),
        message: SarifMessage {
            text: format!("Final package verdict: {}", verdict_report.verdict),
        },
        locations: vec![sarif_location(skill_path.to_string(), None)],
        properties: Some(serde_json::json!({
            "verdict": verdict_report.verdict,
            "verdict_reasons": verdict_report.verdict_reasons,
            "root_cause_groups": verdict_report.root_cause_groups,
            "top_risk_drivers": verdict_report.top_risk_drivers,
            "heuristic_score": heuristic_score,
            "artifact_scope": "package",
        })),
    }
}

fn append_shield_policy(output: &mut String, policy: &ShieldPolicy) {
    let _ = writeln!(output, "## {}\n", policy.id);
    output.push_str("```yaml\n");
    let _ = writeln!(output, "id: {}", policy.id);
    let _ = writeln!(output, "category: {}", policy.category);
    let _ = writeln!(output, "severity: {}", policy.severity);
    let _ = writeln!(output, "confidence: {:.2}", policy.confidence);
    let _ = writeln!(output, "action: {}", policy.action);
    output.push_str("recommendation_agent:\n");
    for rec in &policy.recommendation_agent {
        let _ = writeln!(output, "  - {rec}");
    }
    if let Some(expires) = &policy.expires_at {
        // RFC 3339 (instead of date-only) preserves the full `DateTime<Utc>`
        // precision so SHIELD output round-trips through any consumer that
        // parses `expires_at` as a timestamp. Pre-fix `%Y-%m-%d` truncated
        // hours / minutes / seconds, which:
        //   1) lost the precision present in the underlying `DateTime`,
        //   2) made SHIELD inconsistent with the JSON path (chrono emits
        //      RFC 3339 by default), and
        //   3) reconstructed values at midnight UTC on round-trip,
        //      silently extending or shortening the actual expiration.
        let _ = writeln!(output, "expires_at: {}", expires.to_rfc3339());
    }
    let _ = writeln!(output, "revoked: {}", policy.revoked);
    output.push_str("```\n\n");
}

fn append_context_policy(output: &mut String, policy: &ContextPolicy) {
    let _ = writeln!(
        output,
        "- context: {}\n  action: {}",
        context_label(policy.context),
        policy.action
    );
    for rationale in &policy.rationale {
        let _ = writeln!(output, "  rationale: {rationale}");
    }
}

/// Returns a minimal valid SARIF 2.1.0 document with no runs.
pub fn empty_sarif_report() -> SarifReport {
    SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![],
    }
}

#[cfg(test)]
mod sarif_location_tests {
    use super::*;
    use crate::findings::{ArtifactKind, ThreatCategory};

    fn finding_with_path(artifact_path: Option<&str>, line: Option<usize>) -> Finding {
        let mut builder = Finding::builder("RULE_X", ThreatCategory::Generic)
            .match_value("payload")
            .reason("test")
            .artifact(
                ArtifactKind::SkillDocument,
                artifact_path.map(ToOwned::to_owned),
            );
        if let Some(line) = line {
            builder = builder.line(line);
        }
        builder.build()
    }

    /// Contract: when a finding has no concrete `artifact_path`, the
    /// SARIF `result.locations` array MUST be empty rather than synthesise
    /// a location pointing at the package's `SKILL.md`. Pre-fix the
    /// serializer fell back to `skill_path`, which made viewers attribute
    /// graph-derived findings to the wrong file.
    #[test]
    fn sarif_locations_for_finding_returns_empty_when_no_artifact_path() {
        let finding = finding_with_path(None, None);
        let locations = sarif_locations_for_finding(&finding);
        assert!(
            locations.is_empty(),
            "findings without artifact_path must produce no SARIF locations; got {locations:?}"
        );
    }

    /// Contract: when a finding has an `artifact_path`, the location is
    /// emitted with a populated `physical_location.artifact_location.uri`
    /// equal to that path, and the optional `region.start_line` reflects
    /// `line_number`.
    #[test]
    fn sarif_locations_for_finding_emits_physical_location_when_path_present() {
        let finding = finding_with_path(Some("pkg/src/main.rs"), Some(42));
        let locations = sarif_locations_for_finding(&finding);
        assert_eq!(locations.len(), 1, "exactly one location expected");
        let phys = locations[0]
            .physical_location
            .as_ref()
            .expect("physical_location must be populated when artifact_path is Some");
        assert_eq!(phys.artifact_location.uri, "pkg/src/main.rs");
        assert_eq!(
            phys.region.as_ref().map(|r| r.start_line),
            Some(42),
            "line_number must propagate to region.startLine"
        );
    }

    /// Contract: the JSON form omits `physicalLocation` entirely when it
    /// is `None` (via `skip_serializing_if`). SARIF consumers that
    /// distinguish "no location" from "empty physicalLocation" rely on
    /// the field being absent, not present-but-empty.
    #[test]
    fn sarif_location_json_omits_physical_location_when_none() {
        let location = SarifLocation {
            physical_location: None,
        };
        let json = serde_json::to_string(&location).expect("serialize");
        assert!(
            !json.contains("physicalLocation"),
            "physicalLocation must be omitted from JSON when None; got {json}"
        );
        assert_eq!(
            json, "{}",
            "an empty SarifLocation must round-trip to an empty JSON object"
        );
    }
}
