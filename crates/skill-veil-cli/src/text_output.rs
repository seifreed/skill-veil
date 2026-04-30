use anyhow::Result;
use skill_veil_core::ScanResult;

use crate::cli_args::OutputFormat;
use crate::color::ColorMode;

mod diff;
mod formats;
mod limits;
mod text;

pub(crate) use diff::{format_diff_ci_summary, format_diff_text};
pub(crate) use formats::{format_json_output, format_sarif_output, format_shield_output};
pub(crate) use text::format_text_output;

#[derive(Copy, Clone)]
pub(crate) struct TextOutputOptions {
    pub(crate) quiet_summary: bool,
    pub(crate) explain_policy: bool,
    pub(crate) finding_limit: Option<usize>,
    pub(crate) color: ColorMode,
}

impl Default for TextOutputOptions {
    fn default() -> Self {
        Self {
            quiet_summary: false,
            explain_policy: false,
            finding_limit: None,
            color: ColorMode::from_choice(crate::cli_args::ColorChoiceArg::Never, false),
        }
    }
}

pub(crate) fn format_results(
    results: &[ScanResult],
    format: OutputFormat,
    text_options: TextOutputOptions,
) -> Result<String> {
    match format {
        OutputFormat::Text => Ok(format_text_output(results, text_options)),
        OutputFormat::Json => format_json_output(results),
        OutputFormat::Sarif => format_sarif_output(results),
        OutputFormat::Shield => Ok(format_shield_output(results)),
    }
}
