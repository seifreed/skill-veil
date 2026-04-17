use crate::color::ColorMode;

pub(crate) fn format_diff_text(diff: &skill_veil_core::DiffReport, color: ColorMode) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "{} Diff {}\n",
        color.heading("---"),
        color.heading("---")
    ));
    output.push_str(&format!(
        "New findings: {}\nResolved findings: {}\nWaived findings: {}\nBaselined findings: {}\nUnchanged findings: {}\n",
        diff.new_findings.len(),
        diff.resolved_findings.len(),
        diff.waived_findings.len(),
        diff.baselined_findings.len(),
        diff.unchanged_findings
    ));

    if !diff.new_findings.is_empty() {
        output.push_str("\nNew findings:\n");
        for entry in &diff.new_findings {
            output.push_str(&format!(
                "  - {} {} {}\n",
                color.rule(&entry.rule_id),
                entry.artifact_path.as_deref().unwrap_or("-"),
                entry.reason
            ));
        }
    }

    if !diff.resolved_findings.is_empty() {
        output.push_str("\nResolved findings:\n");
        for entry in &diff.resolved_findings {
            output.push_str(&format!(
                "  - {} {} {}\n",
                color.rule(&entry.rule_id),
                entry.artifact_path.as_deref().unwrap_or("-"),
                entry.reason
            ));
        }
    }

    if !diff.waived_findings.is_empty() {
        output.push_str("\nWaived findings:\n");
        for entry in &diff.waived_findings {
            output.push_str(&format!(
                "  - {} {} {}\n",
                color.rule(&entry.rule_id),
                entry.artifact_path.as_deref().unwrap_or("-"),
                entry.reason
            ));
        }
    }

    if !diff.baselined_findings.is_empty() {
        output.push_str("\nBaselined findings:\n");
        for entry in &diff.baselined_findings {
            output.push_str(&format!(
                "  - {} {} {}\n",
                color.rule(&entry.rule_id),
                entry.artifact_path.as_deref().unwrap_or("-"),
                entry.reason
            ));
        }
    }

    output
}

pub(crate) fn format_diff_ci_summary(diff: &skill_veil_core::DiffReport) -> String {
    format!(
        "DIFF new_active={} resolved={} waived={} baselined={} unchanged={}\n",
        diff.new_findings.len(),
        diff.resolved_findings.len(),
        diff.waived_findings.len(),
        diff.baselined_findings.len(),
        diff.unchanged_findings
    )
}
