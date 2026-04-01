use super::io::{load_json_reports, serialize_json_pretty};
use crate::cli_args::{ColorChoiceArg, DiffArgs, DiffFailPolicyArg, OutputFormat};
use crate::color::ColorMode;
use crate::text_output::{format_diff_ci_summary, format_diff_text};
use anyhow::{Context, Result};
use skill_veil_core::{
    diff_reports_with_policy_state, finding_fingerprint, load_baseline, load_waivers,
    RecommendedAction,
};
use std::io::IsTerminal;

pub(crate) fn run_diff(args: DiffArgs, color_choice: ColorChoiceArg) -> Result<()> {
    let previous = load_json_reports(&args.previous)?;
    let current = load_json_reports(&args.current)?;
    let baseline = args
        .baseline
        .as_ref()
        .map(|path| load_baseline(path))
        .transpose()
        .context("Failed to load baseline file")?;
    let waivers = args
        .waivers
        .as_ref()
        .map(|path| load_waivers(path))
        .transpose()
        .context("Failed to load waivers file")?;
    let diff =
        diff_reports_with_policy_state(&previous, &current, baseline.as_ref(), waivers.as_ref());

    let output = match args.format {
        OutputFormat::Text => {
            let color = ColorMode::from_choice(color_choice, std::io::stdout().is_terminal());
            if args.ci_summary {
                format_diff_ci_summary(&diff)
            } else {
                format_diff_text(&diff, color)
            }
        }
        OutputFormat::Json => serialize_json_pretty(&diff, "Failed to serialize diff")?,
        OutputFormat::Sarif | OutputFormat::Shield => {
            anyhow::bail!("Diff only supports text or json output")
        }
    };

    print!("{}", output);
    if let Some(policy) = args.fail_on {
        match policy {
            DiffFailPolicyArg::NewActive if !diff.new_findings.is_empty() => {
                anyhow::bail!(
                    "Detected {} new active finding(s) in diff",
                    diff.new_findings.len()
                );
            }
            DiffFailPolicyArg::NewBlocking => {
                let has_new_blocking = current
                    .iter()
                    .flat_map(|report| report.findings.iter())
                    .any(|finding| {
                        diff.new_findings
                            .iter()
                            .any(|entry| entry.fingerprint == finding_fingerprint(finding))
                            && finding.recommended_action == RecommendedAction::Block
                    });
                if has_new_blocking {
                    anyhow::bail!("Detected new blocking findings in diff");
                }
            }
            _ => {}
        }
    }
    Ok(())
}
