use crate::text_output::{format_diff_ci_summary, format_diff_text};
use crate::{
    cli_args::{
        ColorChoiceArg, DiffArgs, DiffFailPolicyArg, OutputFormat, PolicyValidateArgs,
        WaiversValidateArgs,
    },
    color::ColorMode,
    util::bounded_read::read_operator_text_file,
};
use anyhow::{Context, Result};
use skill_veil_core::{
    diff_reports_with_policy_state, finding_fingerprint, load_baseline, load_policy, load_waivers,
    validate_waivers, JsonReport, RecommendedAction, StdFileSystemProvider,
};
use std::io::IsTerminal;
use std::path::Path;

pub(crate) fn load_json_reports(path: &Path) -> Result<Vec<JsonReport>> {
    let content = read_operator_text_file(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse JSON report {}", path.display()))
}

pub(crate) fn run_waivers_validate(args: WaiversValidateArgs) -> Result<()> {
    let fs = StdFileSystemProvider::new();
    let waivers = load_waivers(&fs, &args.path).context("Failed to load waivers file")?;
    validate_waivers(&waivers).map_err(anyhow::Error::msg)?;
    println!("Waivers file is valid");
    Ok(())
}

pub(crate) fn run_policy_validate(args: PolicyValidateArgs) -> Result<()> {
    let fs = StdFileSystemProvider::new();
    load_policy(&fs, &args.path).context("Failed to load policy file")?;
    println!("Policy file is valid");
    Ok(())
}

pub(crate) fn run_diff(args: DiffArgs, color_choice: ColorChoiceArg) -> Result<()> {
    let previous = load_json_reports(&args.previous)?;
    let current = load_json_reports(&args.current)?;
    let fs = StdFileSystemProvider::new();
    let baseline = args
        .baseline
        .as_ref()
        .map(|path| load_baseline(&fs, path))
        .transpose()
        .context("Failed to load baseline file")?;
    let waivers = args
        .waivers
        .as_ref()
        .map(|path| load_waivers(&fs, path))
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
        OutputFormat::Json => {
            serde_json::to_string_pretty(&diff).context("Failed to serialize diff")?
        }
        OutputFormat::Sarif | OutputFormat::Shield | OutputFormat::Html => {
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
