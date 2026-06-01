use crate::{
    cli_args::{OutputFormat, RecommendedActionArg, RulesAction, SeverityArg},
    rule_tools::{
        build_rule_pack_info, format_rule_pack_info_text, format_rules_validation_text,
        read_rule_text_file, validate_fixture_case, validate_rules_directory, RuleFixtureCase,
        RuleFixtureFile,
    },
    util::terminal_safe::sanitise_for_terminal,
};
use anyhow::{Context, Result};
use skill_veil_core::{PulldownMarkdownParser, ScanOptions, Scanner, Severity};
use std::path::PathBuf;

pub(crate) fn run_rules(action: RulesAction) -> Result<()> {
    match action {
        RulesAction::List {
            category,
            severity,
            format,
        } => {
            let options = ScanOptions {
                runtime_overlay_dirs: crate::rule_dirs::default_external_rule_dirs(),
                ..Default::default()
            };
            let scanner =
                Scanner::with_std_adapters(options).context("Failed to initialize scanner")?;
            rules_list(&scanner, category, severity, format)
        }
        RulesAction::Test {
            rule_id,
            file,
            content,
            rules_dir,
            expect_match,
            expected_count,
            expected_severity,
            expected_action,
            expected_category,
        } => rules_test(
            rule_id,
            file,
            content,
            rules_dir,
            RuleTestExpectations {
                expect_match,
                expected_count,
                expected_severity,
                expected_action,
                expected_category,
            },
        ),
        RulesAction::TestPack {
            rules_dir,
            fixtures,
        } => rules_test_pack(rules_dir, fixtures),
        RulesAction::Validate { rules_dir, format } => rules_validate(rules_dir, format),
        RulesAction::PackInfo { rules_dir, format } => rules_pack_info(rules_dir, format),
        RulesAction::Update(args) => super::init::run_rules_update(args),
        RulesAction::Status(args) => super::init::run_rules_status(args),
    }
}

fn rules_list(
    scanner: &Scanner,
    category: Option<String>,
    severity: Option<SeverityArg>,
    format: OutputFormat,
) -> Result<()> {
    let rules: Vec<_> = scanner
        .rules()
        .into_iter()
        .filter(|r| {
            if let Some(ref cat) = category {
                if r.category.to_string() != *cat {
                    return false;
                }
            }
            if let Some(sev) = severity {
                if r.severity != Severity::from(sev) {
                    return false;
                }
            }
            true
        })
        .collect();

    match format {
        OutputFormat::Text => {
            println!("Loaded {} rules:\n", rules.len());
            for rule in &rules {
                println!(
                    "  {} [{}/{}] - {}",
                    terminal_text(&rule.id),
                    rule.severity,
                    rule.category,
                    terminal_text(&rule.reason)
                );
            }
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&rules).context("Failed to serialize rules")?;
            println!("{json}");
        }
        _ => {
            println!("Format not supported for rules list");
        }
    }
    Ok(())
}

/// Optional expectations the user supplied via `--expect-*` flags. Grouped
/// here so `rules_test` stays under clippy's `too_many_arguments` limit
/// without needing a bypass.
struct RuleTestExpectations {
    expect_match: Option<bool>,
    expected_count: Option<usize>,
    expected_severity: Option<SeverityArg>,
    expected_action: Option<RecommendedActionArg>,
    expected_category: Option<String>,
}

fn rules_test(
    rule_id: String,
    file: Option<PathBuf>,
    content: Option<String>,
    rules_dir: PathBuf,
    expectations: RuleTestExpectations,
) -> Result<()> {
    let test_content = if let Some(file_path) = file {
        read_rule_text_file(&file_path).context("Failed to read test file")?
    } else if let Some(c) = content {
        c
    } else {
        anyhow::bail!("Either --file or --content must be provided");
    };

    let engine = super::scan::load_rule_engine_from_dir(&rules_dir)?;
    let parser = PulldownMarkdownParser::new();
    let findings = engine
        .test_rule(&rule_id, &test_content, &parser)
        .with_context(|| format!("Failed to test rule {rule_id}"))?;
    let case = RuleFixtureCase {
        name: Some(rule_id.clone()),
        rule_id: rule_id.clone(),
        content: test_content,
        file_name: None,
        expect_match: expectations.expect_match,
        expected_count: expectations.expected_count,
        expected_severity: expectations.expected_severity.map(Into::into),
        expected_action: expectations.expected_action.map(Into::into),
        expected_category: expectations.expected_category,
    };
    validate_fixture_case(&case, &findings)?;

    if findings.is_empty() {
        println!(
            "Rule '{}' did not match the content",
            terminal_text(&rule_id)
        );
    } else {
        println!(
            "Rule '{}' matched {} time(s):\n",
            terminal_text(&rule_id),
            findings.len()
        );
        for finding in findings {
            println!("  Match: \"{}\"", terminal_text(&finding.match_value));
            println!("  Severity: {}", finding.severity);
            println!("  Category: {}", finding.category);
            println!("  Action: {}", finding.recommended_action);
            println!("  Reason: {}", terminal_text(&finding.reason));
            if let Some(line) = finding.line_number {
                println!("  Line: {line}");
            }
            println!();
        }
    }
    Ok(())
}

fn rules_test_pack(rules_dir: PathBuf, fixtures: PathBuf) -> Result<()> {
    let engine = super::scan::load_rule_engine_from_dir(&rules_dir)?;
    let fixture_content = read_rule_text_file(&fixtures)
        .with_context(|| format!("Failed to read fixtures {}", fixtures.display()))?;
    let fixture_pack: RuleFixtureFile =
        serde_yaml::from_str(&fixture_content).context("Failed to parse rule fixtures")?;
    anyhow::ensure!(
        !fixture_pack.cases.is_empty(),
        "Fixture file {} contains no cases; an empty pack must not report success",
        fixtures.display()
    );

    let parser = PulldownMarkdownParser::new();
    let mut failures = Vec::new();
    for case in fixture_pack.cases {
        let findings = engine
            .test_rule(&case.rule_id, &case.content, &parser)
            .with_context(|| format!("Failed to test rule {}", case.rule_id))?;
        if let Err(err) = validate_fixture_case(&case, &findings) {
            failures.push(format!(
                "{} ({err})",
                terminal_text(case.name.as_deref().unwrap_or(&case.rule_id)),
            ));
        }
    }

    if failures.is_empty() {
        println!("All rule fixtures passed");
    } else {
        anyhow::bail!("Fixture failures: {}", failures.join(", "));
    }
    Ok(())
}

fn rules_validate(rules_dir: PathBuf, format: OutputFormat) -> Result<()> {
    let report = validate_rules_directory(&rules_dir)?;
    match format {
        OutputFormat::Text => {
            print!("{}", format_rules_validation_text(&report));
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report)
                    .context("Failed to serialize validation report")?
            );
        }
        OutputFormat::Sarif | OutputFormat::Shield | OutputFormat::Html => {
            anyhow::bail!("rules validate only supports text or json output");
        }
    }

    if !report.valid {
        anyhow::bail!("Rule pack validation failed");
    }
    Ok(())
}

fn rules_pack_info(rules_dir: PathBuf, format: OutputFormat) -> Result<()> {
    let info = build_rule_pack_info(&rules_dir)?;
    match format {
        OutputFormat::Text => {
            print!("{}", format_rule_pack_info_text(&info));
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&info).context("Failed to serialize pack info")?
            );
        }
        OutputFormat::Sarif | OutputFormat::Shield | OutputFormat::Html => {
            anyhow::bail!("rules pack-info only supports text or json output");
        }
    }
    Ok(())
}

fn terminal_text(value: &str) -> String {
    sanitise_for_terminal(value)
}

#[cfg(test)]
mod tests {
    use super::terminal_text;

    #[test]
    fn terminal_text_removes_rule_control_sequences() {
        let cleaned = terminal_text("RULE\x1b]8;;https://evil.invalid\x07click");

        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('\x07'));
    }
}
