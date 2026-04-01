use anyhow::{Context, Result};
use std::path::Path;

pub(crate) fn run_rules(action: crate::cli_args::RulesAction) -> Result<()> {
    use crate::cli_args::{OutputFormat, RulesAction};
    use crate::rule_tools::{
        build_rule_pack_info, format_rule_pack_info_text, format_rules_validation_text,
        validate_fixture_case, validate_rules_directory, RuleFixtureCase, RuleFixtureFile,
    };
    use skill_veil_core::Scanner;

    let scanner = Scanner::new().context("Failed to initialize scanner")?;

    match action {
        RulesAction::List {
            category,
            severity,
            format,
        } => {
            let rules: Vec<_> = scanner
                .rules()
                .into_iter()
                .filter(|r| {
                    category
                        .as_ref()
                        .is_none_or(|cat| r.category.to_string() == *cat)
                        && severity.is_none_or(|sev| {
                            r.severity == skill_veil_core::Severity::from(sev)
                        })
                })
                .collect();

            match format {
                OutputFormat::Text => {
                    println!("Loaded {} rules:\n", rules.len());
                    for rule in &rules {
                        println!(
                            "  {} [{}/{}] - {}",
                            rule.id, rule.severity, rule.category, rule.reason
                        );
                    }
                }
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&rules)
                            .context("Failed to serialize rules")?
                    );
                }
                _ => println!("Format not supported for rules list"),
            }
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
        } => {
            let test_content = if let Some(file_path) = file {
                std::fs::read_to_string(&file_path).context("Failed to read test file")?
            } else if let Some(c) = content {
                c
            } else {
                anyhow::bail!("Either --file or --content must be provided");
            };
            let engine = load_rule_engine_from_dir(&rules_dir)?;
            let findings = engine
                .test_rule(&rule_id, &test_content)
                .with_context(|| format!("Failed to test rule {rule_id}"))?;
            let case = RuleFixtureCase {
                name: Some(rule_id.clone()),
                rule_id: rule_id.clone(),
                content: test_content,
                file_name: None,
                expect_match,
                expected_count,
                expected_severity: expected_severity.map(Into::into),
                expected_action: expected_action.map(Into::into),
                expected_category,
            };
            validate_fixture_case(&case, &findings)?;
            if findings.is_empty() {
                println!("Rule '{rule_id}' did not match the content");
            } else {
                println!("Rule '{rule_id}' matched {} time(s):\n", findings.len());
                for f in findings {
                    println!("  Match: \"{}\"", f.match_value);
                    println!("  Severity: {}", f.severity);
                    println!("  Category: {}", f.category);
                    println!("  Action: {}", f.recommended_action);
                    println!("  Reason: {}", f.reason);
                    if let Some(line) = f.line_number {
                        println!("  Line: {line}");
                    }
                    println!();
                }
            }
        }
        RulesAction::TestPack {
            rules_dir,
            fixtures,
        } => {
            let engine = load_rule_engine_from_dir(&rules_dir)?;
            let fixture_content = std::fs::read_to_string(&fixtures)
                .with_context(|| format!("Failed to read fixtures {}", fixtures.display()))?;
            let fixture_pack: RuleFixtureFile =
                serde_yaml::from_str(&fixture_content).context("Failed to parse rule fixtures")?;
            let mut failures = Vec::new();
            for case in fixture_pack.cases {
                let findings = engine
                    .test_rule(&case.rule_id, &case.content)
                    .with_context(|| format!("Failed to test rule {}", case.rule_id))?;
                if let Err(err) = validate_fixture_case(&case, &findings) {
                    failures.push(format!(
                        "{} ({err})",
                        case.name.as_deref().unwrap_or(&case.rule_id)
                    ));
                }
            }
            if failures.is_empty() {
                println!("All rule fixtures passed");
            } else {
                anyhow::bail!("Fixture failures: {}", failures.join(", "));
            }
        }
        RulesAction::Validate { rules_dir, format } => {
            let report = validate_rules_directory(&rules_dir)?;
            match format {
                OutputFormat::Text => print!("{}", format_rules_validation_text(&report)),
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .context("Failed to serialize validation report")?
                ),
                _ => anyhow::bail!("rules validate only supports text or json output"),
            }
            if !report.valid {
                anyhow::bail!("Rule pack validation failed");
            }
        }
        RulesAction::PackInfo { rules_dir, format } => {
            let info = build_rule_pack_info(&rules_dir)?;
            match format {
                OutputFormat::Text => print!("{}", format_rule_pack_info_text(&info)),
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&info)
                        .context("Failed to serialize pack info")?
                ),
                _ => anyhow::bail!("rules pack-info only supports text or json output"),
            }
        }
    }
    Ok(())
}

fn load_rule_engine_from_dir(rules_dir: &Path) -> Result<skill_veil_core::RuleEngine> {
    let mut engine = skill_veil_core::RuleEngine::new();
    engine
        .load_from_dir(rules_dir)
        .with_context(|| format!("Failed to load rules from {}", rules_dir.display()))?;
    Ok(engine)
}
