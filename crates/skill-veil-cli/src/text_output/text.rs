use skill_veil_core::{RecommendedAction, ScanResult};

use super::limits::{
    MAX_DISPLAY_NETWORK_TARGETS, MAX_DISPLAY_POLICY_TRIGGERS, MAX_DISPLAY_ROOT_CAUSE_GROUPS,
    MAX_DISPLAY_TOP_FACTORS, MAX_DISPLAY_VERDICT_REASONS,
};
use super::TextOutputOptions;
use crate::color::ColorMode;
use crate::util::terminal_safe::sanitise_for_terminal;
use std::path::Path;

fn terminal_text(value: &str) -> String {
    sanitise_for_terminal(value)
}

fn terminal_path(path: &Path) -> String {
    terminal_text(&path.display().to_string())
}

pub(crate) fn format_text_output(results: &[ScanResult], options: TextOutputOptions) -> String {
    let mut output = String::new();

    for result in results {
        output.push_str(&format!(
            "\n{} {} {}\n",
            options.color.heading("==="),
            terminal_path(&result.metadata.path),
            options.color.heading("===")
        ));
        if let Some(package_id) = &result.metadata.package_id {
            output.push_str(&format!("Package ID: {}\n", terminal_text(package_id)));
        }
        output.push_str(&format!(
            "Verdict: {}\n",
            options.color.verdict(result.verdict)
        ));
        output.push_str(&format!(
            "Package Health: {} {}\n",
            options
                .color
                .package_health(result.verdict_report.package_health),
            options
                .color
                .muted("(hygiene/posture, independent from verdict)")
        ));
        output.push_str(&format!(
            "Heuristic Score: {}\n",
            result.metadata.heuristic_score
        ));
        output.push_str(&format!(
            "Package Risk: {} | Action: {}\n",
            result.summary.risk_score,
            options.color.action(result.summary.recommended_action)
        ));
        output.push_str(&format!(
            "Primary Risk: {} | Action: {}\n",
            result.primary_summary.risk_score,
            options
                .color
                .action(result.primary_summary.recommended_action)
        ));
        output.push_str(&format!(
            "Supporting Package Risk: {} | Action: {}\n\n",
            result.supporting_summary.risk_score,
            options
                .color
                .action(result.supporting_summary.recommended_action)
        ));
        append_verdict_reasons(&mut output, result);

        if options.explain_policy {
            append_scope_counts(&mut output, result);
            output.push('\n');
            append_policy_reasons(&mut output, result);
            continue;
        }

        if options.quiet_summary {
            append_scope_counts(&mut output, result);
            output.push('\n');
        } else if result.findings.is_empty() {
            output.push_str("  No findings.\n");
        } else {
            append_findings_by_scope(&mut output, result, options.finding_limit, options.color);
        }

        append_policy_reasons(&mut output, result);
    }

    append_summary(&mut output, results, options);
    output
}

fn append_verdict_reasons(output: &mut String, result: &ScanResult) {
    if result.verdict_report.verdict_reasons.is_empty() {
        output.push_str("  Why: no strong causal drivers recorded\n\n");
        return;
    }

    output.push_str("  Why:\n");
    for reason in result
        .verdict_report
        .verdict_reasons
        .iter()
        .take(MAX_DISPLAY_VERDICT_REASONS)
    {
        output.push_str(&format!(
            "    - {} / {} / {}: {}\n",
            reason.scope,
            reason.category,
            reason.signal_class,
            terminal_text(&reason.rationale)
        ));
    }

    if !result.verdict_report.root_cause_groups.is_empty() {
        output.push_str("  Root causes:\n");
        for group in result
            .verdict_report
            .root_cause_groups
            .iter()
            .take(MAX_DISPLAY_ROOT_CAUSE_GROUPS)
        {
            output.push_str(&format!(
                "    - {} / {} / {} => {} finding(s), strongest action {}\n",
                group.scope,
                group.category,
                group.signal_class,
                group.finding_count,
                group.strongest_action
            ));
        }
    }

    if result.verdict_report.hygiene_summary.package_root_findings > 0
        || result.verdict_report.hygiene_summary.entrypoint_findings > 0
        || result.verdict_report.hygiene_summary.supporting_findings > 0
    {
        output.push_str(&format!(
            "  Package hygiene: package_root={} entrypoint={} supporting={} top_rules={}\n",
            result.verdict_report.hygiene_summary.package_root_findings,
            result.verdict_report.hygiene_summary.entrypoint_findings,
            result.verdict_report.hygiene_summary.supporting_findings,
            if result.verdict_report.hygiene_summary.top_rules.is_empty() {
                "none".to_string()
            } else {
                result
                    .verdict_report
                    .hygiene_summary
                    .top_rules
                    .iter()
                    .map(|rule| terminal_text(rule))
                    .collect::<Vec<_>>()
                    .join(",")
            }
        ));
    }

    if !result.verdict_report.declared_permissions.is_empty() {
        output.push_str(&format!(
            "  Declared permissions: {}\n",
            result
                .verdict_report
                .declared_permissions
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    {
        let level = result.verdict_report.blast_radius_summary.level;
        output.push_str(&format!("  Blast radius: {}\n", level));
        if !result
            .verdict_report
            .blast_radius_summary
            .factors
            .is_empty()
        {
            output.push_str(&format!(
                "  Blast factors: {}\n",
                result
                    .verdict_report
                    .blast_radius_summary
                    .factors
                    .iter()
                    .map(|factor| terminal_text(factor))
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        if !result
            .verdict_report
            .blast_radius_summary
            .network_targets
            .is_empty()
        {
            output.push_str(&format!(
                "  Network targets: {}\n",
                result
                    .verdict_report
                    .blast_radius_summary
                    .network_targets
                    .iter()
                    .take(MAX_DISPLAY_NETWORK_TARGETS)
                    .map(|target| terminal_text(target))
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
    }

    output.push('\n');
}

fn append_scope_counts(output: &mut String, result: &ScanResult) {
    output.push_str(&format!(
        "  Primary findings: {}\n",
        result.primary_findings.len()
    ));
    output.push_str(&format!(
        "  Supporting findings: {}\n",
        result.supporting_findings.len()
    ));
    output.push_str(&format!("  Total findings: {}\n", result.findings.len()));
}

fn append_findings_by_scope(
    output: &mut String,
    result: &ScanResult,
    finding_limit: Option<usize>,
    color: ColorMode,
) {
    append_scope_counts(output, result);
    output.push('\n');

    // `finding_limit` is a per-package budget shared across the
    // `primary` and `supporting` scopes. Pre-fix the same limit was
    // passed independently to both calls, so a package with N findings
    // in each scope rendered up to `2 * finding_limit` entries —
    // breaking the documented per-package log-size cap of `--preset
    // ci` (`FINDING_LIMIT_CI = 10`). We thread the remaining budget
    // through both calls so the cap holds at the package level.
    let mut remaining = finding_limit;

    if result.primary_findings.is_empty() {
        output.push_str("  Main artifact findings: none\n\n");
    } else {
        output.push_str("  Main artifact findings:\n");
        let displayed = append_findings(output, &result.primary_findings, remaining, color);
        remaining = remaining.map(|r| r.saturating_sub(displayed));
    }

    if result.supporting_findings.is_empty() {
        output.push_str("  Supporting artifact findings: none\n\n");
    } else {
        output.push_str("  Supporting artifact findings:\n");
        append_findings(output, &result.supporting_findings, remaining, color);
    }
}

/// Render up to `finding_limit` findings into `output`. Returns the
/// number actually rendered so the caller can decrement a shared
/// per-package budget — when `finding_limit` is `Some(0)`, none are
/// rendered but the trailing "... N more finding(s) omitted" note
/// still surfaces so the operator sees the silenced count.
fn append_findings(
    output: &mut String,
    findings: &[skill_veil_core::Finding],
    finding_limit: Option<usize>,
    color: ColorMode,
) -> usize {
    let display_limit = finding_limit.unwrap_or(findings.len());
    for finding in findings.iter().take(display_limit) {
        output.push_str(&format!(
            "  {} {} ({})\n",
            color.severity_label(finding.severity),
            color.rule(terminal_text(&finding.rule_id)),
            finding.category
        ));
        output.push_str(&format!("      {}\n", terminal_text(&finding.reason)));
        output.push_str(&format!(
            "      Remediation: {}\n",
            terminal_text(&finding.remediation)
        ));
        output.push_str(&format!(
            "      Match: \"{}\"\n",
            terminal_text(&finding.match_value),
        ));
        output.push_str(&format!("      Evidence: {}\n", finding.evidence_kind));
        output.push_str(&format!("      Action: {}\n", finding.recommended_action));
        output.push_str(&format!("      Artifact: {}", finding.artifact_kind));
        if let Some(path) = &finding.artifact_path {
            output.push_str(&format!(" ({})", terminal_text(path)));
        }
        output.push('\n');
        if let Some(line) = finding.line_number {
            output.push_str(&format!("      Line: {}\n", line));
        }
        output.push('\n');
    }
    let displayed = display_limit.min(findings.len());
    if findings.len() > displayed {
        output.push_str(&format!(
            "      ... {} more finding(s) omitted\n\n",
            findings.len() - displayed
        ));
    }
    displayed
}

fn append_policy_reasons(output: &mut String, result: &ScanResult) {
    output.push_str("  Policy precedence:\n");
    for stage in &result.policy_audit.precedence_order {
        output.push_str(&format!("    - {}\n", terminal_text(stage)));
    }

    if result.summary.action_triggers.is_empty() {
        output.push_str("  No policy escalation reasons.\n");
    } else {
        output.push_str("  Policy escalation reasons:\n");
        for trigger in &result.summary.action_triggers {
            output.push_str(&format!(
                "    - {} via {}: {}\n",
                trigger.action,
                terminal_text(&trigger.factor),
                terminal_text(&trigger.rationale)
            ));
        }
    }

    let context_policies = result.policy_generator().generate_context_policies();
    if !context_policies.is_empty() {
        output.push_str("  Context policies:\n");
        for policy in &context_policies {
            output.push_str(&format!(
                "    - {} => {}\n",
                terminal_text(
                    serde_json::to_string(&policy.context)
                        .unwrap_or_else(|_| "\"unknown\"".to_string())
                        .trim_matches('"')
                ),
                policy.action
            ));
        }
    }

    if !result.policy_audit.applied_overrides.is_empty() {
        output.push_str("  Applied overrides:\n");
        for applied in &result.policy_audit.applied_overrides {
            output.push_str(&format!(
                "    - {}: {} -> {} ({})\n",
                terminal_text(&applied.rule_id),
                applied.original_action,
                applied.effective_action,
                terminal_text(&applied.reason)
            ));
        }
    }

    if let Some(fail_on) = result.policy_audit.effective_fail_on {
        output.push_str(&format!("  Effective fail_on: {}\n", fail_on));
    }

    if result.suppression_summary.baseline_suppressed > 0
        || result.suppression_summary.waiver_suppressed > 0
        || result.suppression_summary.inline_suppressed > 0
    {
        output.push_str(&format!(
            "  Suppressed findings: baseline={} waiver={} inline={}\n",
            result.suppression_summary.baseline_suppressed,
            result.suppression_summary.waiver_suppressed,
            result.suppression_summary.inline_suppressed
        ));
    }

    if !result.verdict_report.calibration_notes.is_empty() {
        output.push_str("  Calibration notes:\n");
        for note in &result.verdict_report.calibration_notes {
            output.push_str(&format!(
                "    - {} [{}]: {}\n",
                terminal_text(&note.rule_id),
                note.effect,
                terminal_text(&note.rationale)
            ));
        }
    }
    if result.verdict_report.calibration_risk_adjustment != 0 {
        output.push_str(&format!(
            "  Calibration risk adjustment: {}\n",
            result.verdict_report.calibration_risk_adjustment
        ));
    }

    output.push('\n');
}

fn append_summary(output: &mut String, results: &[ScanResult], options: TextOutputOptions) {
    append_verdict_counts(output, results);
    append_suppression_line(output, results);
    append_overrides_line(output, results);
    if options.explain_policy {
        append_final_action(output, results);
    } else {
        append_top_factors(output, results);
    }
    append_top_triggers(output, results);
    append_context_coverage(output, results);
}

fn append_verdict_counts(output: &mut String, results: &[ScanResult]) {
    let total_findings: usize = results.iter().map(|r| r.findings.len()).sum();
    let critical: usize = results.iter().map(|r| r.summary.by_severity.critical).sum();
    let high: usize = results.iter().map(|r| r.summary.by_severity.high).sum();
    let medium: usize = results.iter().map(|r| r.summary.by_severity.medium).sum();
    let low: usize = results.iter().map(|r| r.summary.by_severity.low).sum();
    let benign_verdicts = count_verdicts(results, skill_veil_core::Verdict::Benign);
    let suspicious_verdicts = count_verdicts(results, skill_veil_core::Verdict::Suspicious);
    let malicious_verdicts = count_verdicts(results, skill_veil_core::Verdict::Malicious);

    output.push_str(&format!(
        "\n--- Summary ---\nFiles scanned: {}\nVerdicts: benign={} suspicious={} malicious={}\nTotal findings: {} (Critical: {}, High: {}, Medium: {}, Low: {})\n",
        results.len(),
        benign_verdicts,
        suspicious_verdicts,
        malicious_verdicts,
        total_findings,
        critical,
        high,
        medium,
        low
    ));
}

fn count_verdicts(results: &[ScanResult], verdict: skill_veil_core::Verdict) -> usize {
    results.iter().filter(|r| r.verdict == verdict).count()
}

fn append_suppression_line(output: &mut String, results: &[ScanResult]) {
    let total_baseline_suppressed: usize = results
        .iter()
        .map(|r| r.suppression_summary.baseline_suppressed)
        .sum();
    let total_waiver_suppressed: usize = results
        .iter()
        .map(|r| r.suppression_summary.waiver_suppressed)
        .sum();
    let total_inline_suppressed: usize = results
        .iter()
        .map(|r| r.suppression_summary.inline_suppressed)
        .sum();
    if total_baseline_suppressed == 0
        && total_waiver_suppressed == 0
        && total_inline_suppressed == 0
    {
        return;
    }
    output.push_str(&format!(
        "Suppressed findings: baseline={} waiver={} inline={}\n",
        total_baseline_suppressed, total_waiver_suppressed, total_inline_suppressed
    ));
}

fn append_overrides_line(output: &mut String, results: &[ScanResult]) {
    let total_overrides: usize = results
        .iter()
        .map(|r| r.policy_audit.applied_overrides.len())
        .sum();
    if total_overrides == 0 {
        return;
    }
    output.push_str(&format!("Applied overrides: {}\n", total_overrides));
}

fn append_final_action(output: &mut String, results: &[ScanResult]) {
    let final_action = results
        .iter()
        .fold(RecommendedAction::Log, |current, result| {
            skill_veil_core::RecommendedAction::max(current, result.summary.recommended_action)
        });
    output.push_str(&format!("Final recommended action: {}\n", final_action));
}

fn append_top_factors(output: &mut String, results: &[ScanResult]) {
    let mut factor_totals = std::collections::BTreeMap::new();
    for result in results {
        for factor in &result.summary.score_breakdown {
            *factor_totals.entry(factor.factor.clone()).or_insert(0_u32) += factor.contribution;
        }
    }
    if factor_totals.is_empty() {
        return;
    }
    output.push_str("Top score factors:\n");
    let mut ranked_factors: Vec<_> = factor_totals.into_iter().collect();
    ranked_factors.sort_by_key(|right| std::cmp::Reverse(right.1));
    for (factor, contribution) in ranked_factors.into_iter().take(MAX_DISPLAY_TOP_FACTORS) {
        output.push_str(&format!(
            "  - {} ({})\n",
            terminal_text(&factor),
            contribution
        ));
    }
}

fn append_top_triggers(output: &mut String, results: &[ScanResult]) {
    let mut trigger_counts = std::collections::BTreeMap::new();
    for result in results {
        for trigger in &result.summary.action_triggers {
            *trigger_counts
                .entry(trigger.factor.clone())
                .or_insert(0_usize) += 1;
        }
    }
    if trigger_counts.is_empty() {
        return;
    }
    output.push_str("Policy escalation triggers:\n");
    let mut ranked_triggers: Vec<_> = trigger_counts.into_iter().collect();
    ranked_triggers.sort_by_key(|right| std::cmp::Reverse(right.1));
    for (factor, count) in ranked_triggers
        .into_iter()
        .take(MAX_DISPLAY_POLICY_TRIGGERS)
    {
        output.push_str(&format!(
            "  - {} ({} file(s))\n",
            terminal_text(&factor),
            count
        ));
    }
}

fn append_context_coverage(output: &mut String, results: &[ScanResult]) {
    let mut context_counts = std::collections::BTreeMap::new();
    for result in results {
        for policy in &result.policy_generator().generate_context_policies() {
            *context_counts
                .entry(
                    serde_json::to_string(&policy.context)
                        .unwrap_or_else(|_| "\"unknown\"".to_string())
                        .trim_matches('"')
                        .to_string(),
                )
                .or_insert(0_usize) += 1;
        }
    }
    if context_counts.is_empty() {
        return;
    }
    output.push_str("Context coverage:\n");
    // Match the rendering of `factor_totals` and `trigger_counts` above:
    // descending by count, alphabetical tie-breaker. Iterating the
    // BTreeMap directly previously forced lexicographic order, burying
    // the highest-frequency contexts.
    let mut ranked_contexts: Vec<_> = context_counts.into_iter().collect();
    ranked_contexts.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    for (context, count) in ranked_contexts {
        output.push_str(&format!(
            "  - {} ({} file(s))\n",
            terminal_text(&context),
            count
        ));
    }
}

// Sanitiser-level contract tests live with the helper itself in
// `crate::util::terminal_safe::tests` — pinning the byte-class filter
// at the boundary where attacker bytes cannot reach the TTY. The
// formatter-level tests below stay focused on the rendering contract.
