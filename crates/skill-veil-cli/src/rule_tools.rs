use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use skill_veil_core::{
    parse_rules_file, IocFeedFile, RecommendedAction, Rule, RulePackFile, RulePackKind,
    RulePackMetadata, Severity,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

#[derive(Debug)]
pub enum ParsedRuleSource {
    RulePack(RulePackFile),
    IocFeed(IocFeedFile),
    PlainRules(Vec<Rule>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFixtureFile {
    pub cases: Vec<RuleFixtureCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFixtureCase {
    #[serde(default, alias = "id")]
    pub name: Option<String>,
    pub rule_id: String,
    pub content: String,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub expect_match: Option<bool>,
    #[serde(default)]
    pub expected_count: Option<usize>,
    #[serde(default)]
    pub expected_severity: Option<Severity>,
    #[serde(default)]
    pub expected_action: Option<RecommendedAction>,
    #[serde(default)]
    pub expected_category: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RulesValidationReport {
    pub rules_dir: String,
    pub total_rules: usize,
    pub pack_files: usize,
    pub duplicate_rule_ids: Vec<String>,
    pub schema_versions: BTreeSet<String>,
    pub pack_names: BTreeSet<String>,
    pub pack_kinds: BTreeSet<String>,
    pub issues: Vec<String>,
    pub valid: bool,
}

#[derive(Debug, Serialize)]
pub struct RulePackInfo {
    pub rules_dir: String,
    pub total_rules: usize,
    pub pack_files: usize,
    pub enabled_rules: usize,
    pub disabled_rules: usize,
    pub schema_versions: BTreeSet<String>,
    pub pack_names: BTreeSet<String>,
    pub pack_kinds: BTreeSet<String>,
    pub by_severity: BTreeMap<String, usize>,
    pub by_category: BTreeMap<String, usize>,
    pub tags: BTreeSet<String>,
}

pub fn parse_rule_source(content: &str) -> Result<ParsedRuleSource> {
    if let Ok(pack) = serde_yaml::from_str::<RulePackFile>(content) {
        if !pack.rules.is_empty() || !pack.metadata.name.is_empty() {
            return Ok(ParsedRuleSource::RulePack(pack));
        }
    }
    if let Ok(feed) = serde_yaml::from_str::<IocFeedFile>(content) {
        if !(feed.domains.is_empty() && feed.filenames.is_empty() && feed.ips.is_empty()) {
            return Ok(ParsedRuleSource::IocFeed(feed));
        }
    }
    Ok(ParsedRuleSource::PlainRules(parse_rules_file(content)?))
}

pub fn validate_rules_directory(rules_dir: &Path) -> Result<RulesValidationReport> {
    let mut issues = Vec::new();
    let mut total_rules = 0_usize;
    let mut pack_files = 0_usize;
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut schema_versions = BTreeSet::new();
    let mut pack_names = BTreeSet::new();
    let mut pack_kinds = BTreeSet::new();

    for entry in walkdir::WalkDir::new(rules_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "yaml" || ext == "yml")
                .unwrap_or(false)
        })
    {
        pack_files += 1;
        let path = entry.path();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let parsed = parse_rule_source(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;
        let mut metadata_issues = Vec::new();

        let rules = match parsed {
            ParsedRuleSource::RulePack(pack) => {
                schema_versions.insert(pack.schema_version);
                collect_pack_metadata(
                    &pack.metadata,
                    &mut pack_names,
                    &mut pack_kinds,
                    &mut metadata_issues,
                    path,
                );
                pack.rules
            }
            ParsedRuleSource::IocFeed(feed) => {
                schema_versions.insert(feed.schema_version);
                collect_pack_metadata(
                    &feed.metadata,
                    &mut pack_names,
                    &mut pack_kinds,
                    &mut metadata_issues,
                    path,
                );
                parse_rules_file(&content)?
            }
            ParsedRuleSource::PlainRules(rules) => rules,
        };

        issues.extend(metadata_issues);
        total_rules += rules.len();

        for rule in &rules {
            *seen.entry(rule.id.clone()).or_insert(0) += 1;
            if !(0.0..=1.0).contains(&rule.confidence) {
                issues.push(format!(
                    "Rule {} has invalid confidence {}",
                    rule.id, rule.confidence
                ));
            }
            if rule.reason.trim().is_empty() {
                issues.push(format!("Rule {} has an empty reason", rule.id));
            }
            if rule.tags.iter().any(|tag| tag.trim().is_empty()) {
                issues.push(format!("Rule {} contains empty tags", rule.id));
            }
        }
    }

    if total_rules == 0 {
        issues.push("No rules were loaded from the directory".to_string());
    }

    let duplicate_rule_ids: Vec<String> = seen
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(rule_id, _)| rule_id)
        .collect();

    let valid = issues.is_empty() && duplicate_rule_ids.is_empty();
    Ok(RulesValidationReport {
        rules_dir: rules_dir.display().to_string(),
        total_rules,
        pack_files,
        duplicate_rule_ids,
        schema_versions,
        pack_names,
        pack_kinds,
        issues,
        valid,
    })
}

pub fn build_rule_pack_info(rules_dir: &Path) -> Result<RulePackInfo> {
    let mut by_severity = BTreeMap::new();
    let mut by_category = BTreeMap::new();
    let mut tags = BTreeSet::new();
    let mut enabled_rules = 0_usize;
    let mut disabled_rules = 0_usize;
    let mut total_rules = 0_usize;
    let mut pack_files = 0_usize;
    let mut schema_versions = BTreeSet::new();
    let mut pack_names = BTreeSet::new();
    let mut pack_kinds = BTreeSet::new();

    for entry in walkdir::WalkDir::new(rules_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "yaml" || ext == "yml")
                .unwrap_or(false)
        })
    {
        pack_files += 1;
        let path = entry.path();
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let parsed = parse_rule_source(&content)
            .with_context(|| format!("Failed to parse {}", path.display()))?;
        let mut metadata_issues = Vec::new();

        let rules = match parsed {
            ParsedRuleSource::RulePack(pack) => {
                schema_versions.insert(pack.schema_version);
                collect_pack_metadata(
                    &pack.metadata,
                    &mut pack_names,
                    &mut pack_kinds,
                    &mut metadata_issues,
                    path,
                );
                pack.rules
            }
            ParsedRuleSource::IocFeed(feed) => {
                schema_versions.insert(feed.schema_version);
                collect_pack_metadata(
                    &feed.metadata,
                    &mut pack_names,
                    &mut pack_kinds,
                    &mut metadata_issues,
                    path,
                );
                parse_rules_file(&content)?
            }
            ParsedRuleSource::PlainRules(rules) => rules,
        };

        total_rules += rules.len();
        for rule in &rules {
            if rule.enabled {
                enabled_rules += 1;
            } else {
                disabled_rules += 1;
            }
            *by_severity.entry(rule.severity.to_string()).or_insert(0) += 1;
            *by_category.entry(rule.category.to_string()).or_insert(0) += 1;
            for tag in &rule.tags {
                tags.insert(tag.clone());
            }
        }
    }

    Ok(RulePackInfo {
        rules_dir: rules_dir.display().to_string(),
        total_rules,
        pack_files,
        enabled_rules,
        disabled_rules,
        schema_versions,
        pack_names,
        pack_kinds,
        by_severity,
        by_category,
        tags,
    })
}

pub fn validate_fixture_case(
    case: &RuleFixtureCase,
    findings: &[skill_veil_core::Finding],
) -> Result<()> {
    if let Some(expect_match) = case.expect_match {
        let matched = !findings.is_empty();
        if matched != expect_match {
            anyhow::bail!(
                "Rule {} expected match={} but got {}",
                case.rule_id,
                expect_match,
                matched
            );
        }
    }
    if let Some(expected_count) = case.expected_count {
        if findings.len() != expected_count {
            anyhow::bail!(
                "Rule {} expected {} findings but got {}",
                case.rule_id,
                expected_count,
                findings.len()
            );
        }
    }
    if let Some(expected_severity) = case.expected_severity {
        if findings
            .iter()
            .any(|finding| finding.severity != expected_severity)
        {
            anyhow::bail!(
                "Rule {} expected severity {}",
                case.rule_id,
                expected_severity
            );
        }
    }
    if let Some(expected_action) = case.expected_action {
        if findings
            .iter()
            .any(|finding| finding.recommended_action != expected_action)
        {
            anyhow::bail!("Rule {} expected action {}", case.rule_id, expected_action);
        }
    }
    if let Some(expected_category) = &case.expected_category {
        if findings
            .iter()
            .any(|finding| finding.category.to_string() != *expected_category)
        {
            anyhow::bail!(
                "Rule {} expected category {}",
                case.rule_id,
                expected_category
            );
        }
    }
    Ok(())
}

pub fn format_rules_validation_text(report: &RulesValidationReport) -> String {
    let mut output = String::new();
    output.push_str("--- Rules Validation ---\n");
    output.push_str(&format!(
        "Directory: {}\nPack files: {}\nTotal rules: {}\nValid: {}\n",
        report.rules_dir, report.pack_files, report.total_rules, report.valid
    ));
    if !report.schema_versions.is_empty() {
        output.push_str("Schema versions:\n");
        for version in &report.schema_versions {
            output.push_str(&format!("  - {}\n", version));
        }
    }
    if !report.pack_names.is_empty() {
        output.push_str("Pack names:\n");
        for name in &report.pack_names {
            output.push_str(&format!("  - {}\n", name));
        }
    }
    if !report.pack_kinds.is_empty() {
        output.push_str("Pack kinds:\n");
        for kind in &report.pack_kinds {
            output.push_str(&format!("  - {}\n", kind));
        }
    }
    if !report.duplicate_rule_ids.is_empty() {
        output.push_str("Duplicate rule IDs:\n");
        for rule_id in &report.duplicate_rule_ids {
            output.push_str(&format!("  - {}\n", rule_id));
        }
    }
    if !report.issues.is_empty() {
        output.push_str("Issues:\n");
        for issue in &report.issues {
            output.push_str(&format!("  - {}\n", issue));
        }
    }
    output
}

pub fn format_rule_pack_info_text(info: &RulePackInfo) -> String {
    let mut output = String::new();
    output.push_str("--- Rule Pack Info ---\n");
    output.push_str(&format!(
        "Directory: {}\nPack files: {}\nTotal rules: {}\nEnabled: {}\nDisabled: {}\n",
        info.rules_dir, info.pack_files, info.total_rules, info.enabled_rules, info.disabled_rules
    ));
    if !info.schema_versions.is_empty() {
        output.push_str("Schema versions:\n");
        for version in &info.schema_versions {
            output.push_str(&format!("  - {}\n", version));
        }
    }
    if !info.pack_names.is_empty() {
        output.push_str("Pack names:\n");
        for name in &info.pack_names {
            output.push_str(&format!("  - {}\n", name));
        }
    }
    if !info.pack_kinds.is_empty() {
        output.push_str("Pack kinds:\n");
        for kind in &info.pack_kinds {
            output.push_str(&format!("  - {}\n", kind));
        }
    }
    if !info.by_severity.is_empty() {
        output.push_str("By severity:\n");
        for (severity, count) in &info.by_severity {
            output.push_str(&format!("  - {}: {}\n", severity, count));
        }
    }
    if !info.by_category.is_empty() {
        output.push_str("By category:\n");
        for (category, count) in &info.by_category {
            output.push_str(&format!("  - {}: {}\n", category, count));
        }
    }
    if !info.tags.is_empty() {
        output.push_str("Tags:\n");
        for tag in &info.tags {
            output.push_str(&format!("  - {}\n", tag));
        }
    }
    output
}

fn collect_pack_metadata(
    metadata: &RulePackMetadata,
    pack_names: &mut BTreeSet<String>,
    pack_kinds: &mut BTreeSet<String>,
    issues: &mut Vec<String>,
    path: &Path,
) {
    if metadata.name.trim().is_empty() {
        issues.push(format!("Pack {} is missing metadata.name", path.display()));
    } else {
        pack_names.insert(metadata.name.clone());
    }

    if let Some(kind) = metadata.kind {
        let label = match kind {
            RulePackKind::Official => "official",
            RulePackKind::Community => "community",
            RulePackKind::IocFeed => "ioc_feed",
        };
        pack_kinds.insert(label.to_string());
    } else {
        issues.push(format!("Pack {} is missing metadata.kind", path.display()));
    }
}
