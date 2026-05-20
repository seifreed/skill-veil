use crate::util::terminal_safe::sanitise_for_terminal;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use skill_veil_core::{
    parse_rules_file, IocFeedFile, RecommendedAction, Rule, RulePackFile, RulePackKind,
    RulePackMetadata, Severity,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::Metadata;
use std::io::{self, Read};
use std::path::Path;

pub const MAX_RULE_TEXT_FILE_BYTES: u64 = 16 * 1024 * 1024;

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

pub fn read_rule_text_file(path: &Path) -> Result<String> {
    read_rule_text_file_with_cap(path, MAX_RULE_TEXT_FILE_BYTES)
}

fn read_rule_text_file_with_cap(path: &Path, cap: u64) -> Result<String> {
    read_text_file_with_cap(path, cap).with_context(|| format!("Failed to read {}", path.display()))
}

fn read_text_file_with_cap(path: &Path, cap: u64) -> io::Result<String> {
    let path_meta = std::fs::symlink_metadata(path)?;
    if !path_meta.is_file() || path_meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to read non-regular rule file {}", path.display()),
        ));
    }

    let file = std::fs::File::open(path)?;
    let meta = file.metadata()?;
    if !opened_file_matches_path(&meta, &path_meta) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to read swapped rule file {}", path.display()),
        ));
    }
    if meta.len() > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing to read {}: size {} exceeds limit {}",
                path.display(),
                meta.len(),
                cap
            ),
        ));
    }

    let mut bytes = Vec::with_capacity(usize::try_from(meta.len().min(cap)).unwrap_or(0));
    let mut limited = file.take(cap.saturating_add(1));
    limited.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "refusing to read {}: size exceeds limit {}",
                path.display(),
                cap
            ),
        ));
    }
    String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(unix)]
fn opened_file_matches_path(opened: &Metadata, path_meta: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    opened.dev() == path_meta.dev() && opened.ino() == path_meta.ino()
}

#[cfg(not(unix))]
fn opened_file_matches_path(_opened: &Metadata, _path_meta: &Metadata) -> bool {
    true
}

fn is_rule_yaml_file(entry: &walkdir::DirEntry) -> bool {
    entry.file_type().is_file() && has_yaml_extension(entry.path())
}

fn has_yaml_extension(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext == "yaml" || ext == "yml")
        .unwrap_or(false)
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
        .filter_map(|e| match e {
            Ok(e) => Some(e),
            Err(err) => {
                tracing::warn!("rules validate: skipping directory entry: {err}");
                None
            }
        })
        .filter(is_rule_yaml_file)
    {
        pack_files += 1;
        let path = entry.path();
        let content = read_rule_text_file(path)?;
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
        .filter_map(|e| match e {
            Ok(e) => Some(e),
            Err(err) => {
                tracing::warn!("rule-pack info: skipping directory entry: {err}");
                None
            }
        })
        .filter(is_rule_yaml_file)
    {
        pack_files += 1;
        let path = entry.path();
        let content = read_rule_text_file(path)?;
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
        terminal_text(&report.rules_dir),
        report.pack_files,
        report.total_rules,
        report.valid
    ));
    if !report.schema_versions.is_empty() {
        output.push_str("Schema versions:\n");
        for version in &report.schema_versions {
            output.push_str(&format!("  - {}\n", terminal_text(version)));
        }
    }
    if !report.pack_names.is_empty() {
        output.push_str("Pack names:\n");
        for name in &report.pack_names {
            output.push_str(&format!("  - {}\n", terminal_text(name)));
        }
    }
    if !report.pack_kinds.is_empty() {
        output.push_str("Pack kinds:\n");
        for kind in &report.pack_kinds {
            output.push_str(&format!("  - {}\n", terminal_text(kind)));
        }
    }
    if !report.duplicate_rule_ids.is_empty() {
        output.push_str("Duplicate rule IDs:\n");
        for rule_id in &report.duplicate_rule_ids {
            output.push_str(&format!("  - {}\n", terminal_text(rule_id)));
        }
    }
    if !report.issues.is_empty() {
        output.push_str("Issues:\n");
        for issue in &report.issues {
            output.push_str(&format!("  - {}\n", terminal_text(issue)));
        }
    }
    output
}

pub fn format_rule_pack_info_text(info: &RulePackInfo) -> String {
    let mut output = String::new();
    output.push_str("--- Rule Pack Info ---\n");
    output.push_str(&format!(
        "Directory: {}\nPack files: {}\nTotal rules: {}\nEnabled: {}\nDisabled: {}\n",
        terminal_text(&info.rules_dir),
        info.pack_files,
        info.total_rules,
        info.enabled_rules,
        info.disabled_rules
    ));
    if !info.schema_versions.is_empty() {
        output.push_str("Schema versions:\n");
        for version in &info.schema_versions {
            output.push_str(&format!("  - {}\n", terminal_text(version)));
        }
    }
    if !info.pack_names.is_empty() {
        output.push_str("Pack names:\n");
        for name in &info.pack_names {
            output.push_str(&format!("  - {}\n", terminal_text(name)));
        }
    }
    if !info.pack_kinds.is_empty() {
        output.push_str("Pack kinds:\n");
        for kind in &info.pack_kinds {
            output.push_str(&format!("  - {}\n", terminal_text(kind)));
        }
    }
    if !info.by_severity.is_empty() {
        output.push_str("By severity:\n");
        for (severity, count) in &info.by_severity {
            output.push_str(&format!("  - {}: {}\n", terminal_text(severity), count));
        }
    }
    if !info.by_category.is_empty() {
        output.push_str("By category:\n");
        for (category, count) in &info.by_category {
            output.push_str(&format!("  - {}: {}\n", terminal_text(category), count));
        }
    }
    if !info.tags.is_empty() {
        output.push_str("Tags:\n");
        for tag in &info.tags {
            output.push_str(&format!("  - {}\n", terminal_text(tag)));
        }
    }
    output
}

fn terminal_text(value: &str) -> String {
    sanitise_for_terminal(value)
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// # Contract
    ///
    /// Rule-pack text files under the byte cap MUST read normally.
    /// Validation, pack-info, and rule-test commands share this reader.
    #[test]
    fn read_rule_text_file_accepts_valid_text_under_cap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("rules.yaml");
        std::fs::write(&path, "rules: []\n").unwrap();

        let body = read_rule_text_file_with_cap(&path, 1024).unwrap();

        assert_eq!(body, "rules: []\n");
    }

    /// # Contract
    ///
    /// Rule-pack text reads MUST reject files over the configured cap
    /// before YAML parsing, so an external pack or fixture cannot force
    /// an unbounded allocation.
    #[test]
    fn read_rule_text_file_rejects_oversized_text() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("rules.yaml");
        std::fs::write(&path, vec![b'-'; 32]).unwrap();

        let err = read_rule_text_file_with_cap(&path, 8).unwrap_err();

        assert!(format!("{err:#}").contains("exceeds limit"));
    }

    /// # Contract
    ///
    /// Rule-pack text reads only accept regular files. A symlinked YAML
    /// path is not a rule-pack file, even when its target is readable.
    #[cfg(unix)]
    #[test]
    fn read_rule_text_file_rejects_symlinked_text() {
        let dir = TempDir::new().unwrap();
        let real = dir.path().join("real.yaml");
        let link = dir.path().join("rules.yaml");
        std::fs::write(&real, "rules: []\n").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = read_rule_text_file_with_cap(&link, 1024).unwrap_err();
        let kind = err.downcast_ref::<io::Error>().map(|err| err.kind());

        assert_eq!(kind, Some(io::ErrorKind::InvalidInput));
    }

    /// # Contract
    ///
    /// Directory validation only loads YAML entries that are regular
    /// files. Symlinked YAML entries are outside the rule-pack contract.
    #[cfg(unix)]
    #[test]
    fn validate_rules_directory_skips_symlinked_yaml_entries() {
        let dir = TempDir::new().unwrap();
        let rules_dir = dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();
        let real_rules = rules_dir.join("rules.yaml");
        let outside = dir.path().join("outside.yaml");
        let link = rules_dir.join("linked.yaml");
        std::fs::write(&real_rules, valid_rule_pack("REAL_RULE", "real")).unwrap();
        std::fs::write(&outside, valid_rule_pack("LINKED_RULE", "linked")).unwrap();
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        let report = validate_rules_directory(&rules_dir).unwrap();

        assert_eq!(report.total_rules, 1);
        assert_eq!(report.pack_files, 1);
        assert!(report.valid);
    }

    #[cfg(unix)]
    fn valid_rule_pack(rule_id: &str, pattern: &str) -> String {
        format!(
            r#"
schema_version: skill-veil.dev/rules/v1alpha1
metadata:
  name: test-pack
  kind: official
  compatibility:
    - skill-veil.dev/rules/v1alpha1
rules:
  - id: {rule_id}
    category: generic
    severity: medium
    confidence: 0.8
    when: !regex
      pattern: "{pattern}"
    action: require_approval
    reason: "test rule"
"#
        )
    }

    #[test]
    fn format_rules_validation_text_sanitises_control_sequences() {
        let report = RulesValidationReport {
            rules_dir: "rules\x1b[2J".to_string(),
            total_rules: 1,
            pack_files: 1,
            duplicate_rule_ids: BTreeSet::from(["RULE\x1b[2J".to_string()])
                .into_iter()
                .collect(),
            schema_versions: BTreeSet::from(["v1\x1b[2J".to_string()]),
            pack_names: BTreeSet::from(["pack\x1b[2J".to_string()]),
            pack_kinds: BTreeSet::from(["official\x1b[2J".to_string()]),
            issues: vec!["issue\x1b]8;;https://evil.invalid\x07click".to_string()],
            valid: false,
        };

        let rendered = format_rules_validation_text(&report);

        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains('\x07'));
    }

    #[test]
    fn format_rule_pack_info_text_sanitises_control_sequences() {
        let info = RulePackInfo {
            rules_dir: "rules\x1b[2J".to_string(),
            total_rules: 1,
            pack_files: 1,
            enabled_rules: 1,
            disabled_rules: 0,
            schema_versions: BTreeSet::from(["v1\x1b[2J".to_string()]),
            pack_names: BTreeSet::from(["pack\x1b[2J".to_string()]),
            pack_kinds: BTreeSet::from(["community\x1b[2J".to_string()]),
            by_severity: BTreeMap::from([("high\x1b[2J".to_string(), 1)]),
            by_category: BTreeMap::from([("remote_exec\x1b[2J".to_string(), 1)]),
            tags: BTreeSet::from(["tag\x1b]8;;https://evil.invalid\x07click".to_string()]),
        };

        let rendered = format_rule_pack_info_text(&info);

        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains('\x07'));
    }
}
