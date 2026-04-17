use super::DatasetPackageVerdictEntry;
use crate::color::ColorMode;

pub(crate) fn format_dataset_verdicts_text(
    entries: &[DatasetPackageVerdictEntry],
    analyst_summary: bool,
    color: ColorMode,
) -> String {
    let mut lines = String::new();
    lines.push_str(&format!(
        "\n{} Verdict Triage {}\n",
        color.heading("---"),
        color.heading("---")
    ));

    for entry in entries {
        if analyst_summary {
            lines.push_str(&format_dataset_verdict_analyst_line(entry, color));
        } else {
            lines.push_str(&format!(
                "{} package={} health={} blast_radius={} declared_permissions={} rule={} why={} main={} supporting={} package_root={} path={}\n",
                color.verdict(entry.final_verdict),
                entry.package_id.as_deref().unwrap_or("unknown"),
                entry
                    .package_health
                    .map(|health| color.package_health(health))
                    .unwrap_or_else(|| "healthy".to_string()),
                entry
                    .blast_radius
                    .map(|level| color.blast_radius(level))
                    .unwrap_or_else(|| "low".to_string()),
                render_declared_permissions(&entry.declared_permissions),
                color.rule(entry.top_rule.as_deref().unwrap_or("none")),
                entry.strongest_reason.as_deref().unwrap_or("no_strong_cause"),
                color.scope(render_scope_summary(&entry.main_summary)),
                color.scope(render_scope_summary(&entry.supporting_summary)),
                color.scope(render_scope_summary(&entry.package_root_summary)),
                entry.representative_path
            ));
        }
    }

    lines
}

fn format_dataset_verdict_analyst_line(
    entry: &DatasetPackageVerdictEntry,
    color: ColorMode,
) -> String {
    let scope = strongest_scope(entry);
    let top_reason = entry
        .strongest_reason
        .as_deref()
        .unwrap_or("no_strong_cause");
    format!(
        "[{verdict}] package={package} health={health} blast={blast} scope={scope} rule={rule} perms={perms} reason={reason}\n",
        verdict = color.verdict(entry.final_verdict),
        package = entry.package_id.as_deref().unwrap_or("unknown"),
        health = entry
            .package_health
            .map(|health| color.package_health(health))
            .unwrap_or_else(|| "healthy".to_string()),
        scope = color.scope(scope),
        rule = color.rule(entry.top_rule.as_deref().unwrap_or("none")),
        blast = entry
            .blast_radius
            .map(|level| color.blast_radius(level))
            .unwrap_or_else(|| "low".to_string()),
        perms = render_declared_permissions(&entry.declared_permissions),
        reason = top_reason,
    )
}

fn strongest_scope(entry: &DatasetPackageVerdictEntry) -> &'static str {
    if let Some(reason) = &entry.strongest_reason {
        if let Some(scope) = reason.split('/').next() {
            return match scope {
                "agent_entrypoint" => "agent_entrypoint",
                "supporting_artifact" => "supporting_artifact",
                "package_root_artifact" => "package_root_artifact",
                _ => "unknown",
            };
        }
    }
    if !entry.main_summary.is_empty() {
        "agent_entrypoint"
    } else if !entry.supporting_summary.is_empty() {
        "supporting_artifact"
    } else if !entry.package_root_summary.is_empty() {
        "package_root_artifact"
    } else {
        "unknown"
    }
}

fn render_declared_permissions(
    declared_permissions: &[skill_veil_core::DeclaredPermission],
) -> String {
    if declared_permissions.is_empty() {
        "none".to_string()
    } else {
        declared_permissions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn render_scope_summary(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(",")
    }
}
