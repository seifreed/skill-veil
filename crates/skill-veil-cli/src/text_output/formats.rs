use anyhow::{Context, Result};
use skill_veil_core::ScanResult;

pub(crate) fn format_json_output(results: &[ScanResult]) -> Result<String> {
    let reports: Vec<_> = results
        .iter()
        .map(|r| r.policy_generator().generate_json())
        .collect();
    serde_json::to_string_pretty(&reports).context("Failed to serialize JSON")
}

pub(crate) fn format_sarif_output(results: &[ScanResult]) -> Result<String> {
    if let Some(first) = results.first() {
        let mut sarif = first.policy_generator().generate_sarif();

        for result in results.iter().skip(1) {
            let other = result.policy_generator().generate_sarif();
            if let Some(run) = sarif.runs.first_mut() {
                if let Some(other_run) = other.runs.first() {
                    run.results.extend(other_run.results.clone());
                    let existing_rule_ids: std::collections::HashSet<_> =
                        run.tool.driver.rules.iter().map(|r| r.id.clone()).collect();
                    for rule in &other_run.tool.driver.rules {
                        if !existing_rule_ids.contains(&rule.id) {
                            run.tool.driver.rules.push(rule.clone());
                        }
                    }
                }
            }
        }

        serde_json::to_string_pretty(&sarif).context("Failed to serialize SARIF")
    } else {
        Ok(
            serde_json::to_string_pretty(&skill_veil_core::empty_sarif_report())
                .context("Failed to serialize empty SARIF")?,
        )
    }
}

pub(crate) fn format_shield_output(results: &[ScanResult]) -> String {
    let mut output = String::new();
    for result in results {
        output.push_str(&result.policy_generator().generate_shield_md());
        output.push_str("\n---\n\n");
    }
    output
}
