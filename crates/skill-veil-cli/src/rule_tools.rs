use crate::util::bounded_read::{has_single_hardlink, opened_file_matches_path};
use crate::util::secure_fs::is_real_dir;
use crate::util::terminal_safe::sanitise_for_terminal;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use skill_veil_core::{
    is_supported_rule_pack_schema, parse_rules_file, IocFeedFile, RecommendedAction, Rule,
    RulePackFile, RulePackKind, RulePackMetadata, Severity,
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
    // Mirror the schema-version gate in core's `parse_rules_file`: a pack
    // with an unsupported `schema_version` is unloadable at scan time, so
    // `rules validate` must reject it here too rather than report a green
    // pass for a pack the scanner will refuse.
    if let Ok(pack) = serde_yaml::from_str::<RulePackFile>(content) {
        if !pack.rules.is_empty() || !pack.metadata.name.is_empty() {
            if !is_supported_rule_pack_schema(&pack.schema_version) {
                anyhow::bail!(
                    "Unsupported rule pack schema version: {}",
                    pack.schema_version
                );
            }
            return Ok(ParsedRuleSource::RulePack(pack));
        }
    }
    if let Ok(feed) = serde_yaml::from_str::<IocFeedFile>(content) {
        if !(feed.domains.is_empty() && feed.filenames.is_empty() && feed.ips.is_empty()) {
            if !is_supported_rule_pack_schema(&feed.schema_version) {
                anyhow::bail!(
                    "Unsupported IOC feed schema version: {}",
                    feed.schema_version
                );
            }
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
    let path_meta = regular_rule_file_metadata(path)?;

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

fn regular_rule_file_metadata(path: &Path) -> io::Result<Metadata> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to read non-regular rule file {}", path.display()),
        ));
    }
    if !has_single_hardlink(&meta) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to read {}: multiple hard links", path.display()),
        ));
    }
    Ok(meta)
}

fn is_rule_yaml_file(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_file() || !has_yaml_extension(entry.path()) {
        return false;
    }
    match regular_rule_file_metadata(entry.path()) {
        Ok(_) => true,
        Err(err) => {
            tracing::warn!(
                "rules: skipping non-regular YAML entry {}: {err}",
                entry.path().display()
            );
            false
        }
    }
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

    if is_real_dir(rules_dir) {
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
    } else {
        issues.push(format!(
            "Rules directory {} is not a real directory",
            rules_dir.display()
        ));
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

    if is_real_dir(rules_dir) {
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
    // A case that declares no expectation asserts nothing, so it would pass
    // unconditionally — a silent hole that lets a truncated/under-specified
    // fixture mask a broken rule. Require at least one expectation.
    anyhow::ensure!(
        case.expect_match.is_some()
            || case.expected_count.is_some()
            || case.expected_severity.is_some()
            || case.expected_action.is_some()
            || case.expected_category.is_some(),
        "Rule fixture for {} declares no expectation; set at least one of \
         expect_match / expected_count / expected_severity / expected_action / \
         expected_category",
        case.rule_id
    );
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
    // An attribute expectation implies a finding exists: over an empty slice
    // `any()` is false, so without the `is_empty()` guard a rule that never
    // fired would vacuously satisfy `expected_severity`/`action`/`category`.
    if let Some(expected_severity) = case.expected_severity {
        if findings.is_empty()
            || findings
                .iter()
                .any(|finding| finding.severity != expected_severity)
        {
            anyhow::bail!(
                "Rule {} expected severity {} on a finding",
                case.rule_id,
                expected_severity
            );
        }
    }
    if let Some(expected_action) = case.expected_action {
        if findings.is_empty()
            || findings
                .iter()
                .any(|finding| finding.recommended_action != expected_action)
        {
            anyhow::bail!(
                "Rule {} expected action {} on a finding",
                case.rule_id,
                expected_action
            );
        }
    }
    if let Some(expected_category) = &case.expected_category {
        if findings.is_empty()
            || findings
                .iter()
                .any(|finding| finding.category.to_string() != *expected_category)
        {
            anyhow::bail!(
                "Rule {} expected category {} on a finding",
                case.rule_id,
                expected_category
            );
        }
    }
    Ok(())
}

/// Append a `Label:` heading followed by one terminal-sanitised `  - item`
/// line per entry, skipping the heading entirely when there are no items.
/// Shared by the rules-validation and rule-pack-info text renderers.
fn append_sanitized_bullet_list<'a>(
    output: &mut String,
    label: &str,
    items: impl IntoIterator<Item = &'a String>,
) {
    let mut items = items.into_iter().peekable();
    if items.peek().is_none() {
        return;
    }
    output.push_str(label);
    output.push_str(":\n");
    for item in items {
        output.push_str(&format!("  - {}\n", sanitise_for_terminal(item)));
    }
}

pub fn format_rules_validation_text(report: &RulesValidationReport) -> String {
    let mut output = String::new();
    output.push_str("--- Rules Validation ---\n");
    output.push_str(&format!(
        "Directory: {}\nPack files: {}\nTotal rules: {}\nValid: {}\n",
        sanitise_for_terminal(&report.rules_dir),
        report.pack_files,
        report.total_rules,
        report.valid
    ));
    append_sanitized_bullet_list(&mut output, "Schema versions", &report.schema_versions);
    append_sanitized_bullet_list(&mut output, "Pack names", &report.pack_names);
    append_sanitized_bullet_list(&mut output, "Pack kinds", &report.pack_kinds);
    append_sanitized_bullet_list(
        &mut output,
        "Duplicate rule IDs",
        &report.duplicate_rule_ids,
    );
    append_sanitized_bullet_list(&mut output, "Issues", &report.issues);
    output
}

pub fn format_rule_pack_info_text(info: &RulePackInfo) -> String {
    let mut output = String::new();
    output.push_str("--- Rule Pack Info ---\n");
    output.push_str(&format!(
        "Directory: {}\nPack files: {}\nTotal rules: {}\nEnabled: {}\nDisabled: {}\n",
        sanitise_for_terminal(&info.rules_dir),
        info.pack_files,
        info.total_rules,
        info.enabled_rules,
        info.disabled_rules
    ));
    append_sanitized_bullet_list(&mut output, "Schema versions", &info.schema_versions);
    append_sanitized_bullet_list(&mut output, "Pack names", &info.pack_names);
    append_sanitized_bullet_list(&mut output, "Pack kinds", &info.pack_kinds);
    if !info.by_severity.is_empty() {
        output.push_str("By severity:\n");
        for (severity, count) in &info.by_severity {
            output.push_str(&format!(
                "  - {}: {}\n",
                sanitise_for_terminal(severity),
                count
            ));
        }
    }
    if !info.by_category.is_empty() {
        output.push_str("By category:\n");
        for (category, count) in &info.by_category {
            output.push_str(&format!(
                "  - {}: {}\n",
                sanitise_for_terminal(category),
                count
            ));
        }
    }
    append_sanitized_bullet_list(&mut output, "Tags", &info.tags);
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
    /// Rule-pack text reads MUST reject hardlinked YAML files. A hardlink
    /// inside a rules directory can point at an inode outside that tree
    /// while passing symlink and lexical path checks.
    #[cfg(unix)]
    #[test]
    fn read_rule_text_file_rejects_hardlinked_text() {
        let dir = TempDir::new().unwrap();
        let rules_dir = dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();
        let outside = dir.path().join("outside.yaml");
        let linked = rules_dir.join("rules.yaml");
        std::fs::write(&outside, "rules: []\n").unwrap();
        std::fs::hard_link(&outside, &linked).unwrap();

        let err = read_rule_text_file_with_cap(&linked, 1024).unwrap_err();
        let kind = err.downcast_ref::<io::Error>().map(|err| err.kind());

        assert_eq!(kind, Some(io::ErrorKind::InvalidInput));
        assert!(format!("{err:#}").contains("multiple hard links"));
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

    /// # Contract
    ///
    /// Directory validation and pack-info summaries MUST skip hardlinked
    /// YAML entries for the same reason they skip symlinked entries: the
    /// file is not owned by the rule-pack tree being inspected.
    #[cfg(unix)]
    #[test]
    fn rule_directory_commands_skip_hardlinked_yaml_entries() {
        let dir = TempDir::new().unwrap();
        let rules_dir = dir.path().join("rules");
        std::fs::create_dir(&rules_dir).unwrap();
        let real_rules = rules_dir.join("rules.yaml");
        let outside = dir.path().join("outside.yaml");
        let linked = rules_dir.join("linked.yaml");
        std::fs::write(&real_rules, valid_rule_pack("REAL_RULE", "real")).unwrap();
        std::fs::write(&outside, valid_rule_pack("LINKED_RULE", "linked")).unwrap();
        std::fs::hard_link(&outside, &linked).unwrap();

        let report = validate_rules_directory(&rules_dir).unwrap();
        let info = build_rule_pack_info(&rules_dir).unwrap();

        assert_eq!(report.total_rules, 1);
        assert_eq!(report.pack_files, 1);
        assert!(report.valid);
        assert_eq!(info.total_rules, 1);
        assert_eq!(info.pack_files, 1);
    }

    /// # Contract
    ///
    /// Directory validation must not walk a symlink supplied as the rules
    /// root. A symlinked root can point outside the intended rule-pack
    /// directory while still presenting YAML files to `WalkDir`.
    #[cfg(unix)]
    #[test]
    fn validate_rules_directory_rejects_symlinked_root() {
        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let link = dir.path().join("rules");
        std::fs::write(
            outside.path().join("outside.yaml"),
            valid_rule_pack("OUTSIDE_RULE", "outside"),
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();

        let report = validate_rules_directory(&link).unwrap();

        assert_eq!(report.total_rules, 0);
        assert_eq!(report.pack_files, 0);
        assert!(!report.valid);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("not a real directory")),
            "expected real-directory issue, got {:?}",
            report.issues
        );
    }

    /// # Contract
    ///
    /// Pack-info summaries must not walk a symlink supplied as the rules
    /// root.
    #[cfg(unix)]
    #[test]
    fn build_rule_pack_info_rejects_symlinked_root() {
        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let link = dir.path().join("rules");
        std::fs::write(
            outside.path().join("outside.yaml"),
            valid_rule_pack("OUTSIDE_RULE", "outside"),
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();

        let info = build_rule_pack_info(&link).unwrap();

        assert_eq!(info.total_rules, 0);
        assert_eq!(info.pack_files, 0);
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

    /// Contract: `parse_rule_source` (the `rules validate` / `pack-info`
    /// parser) rejects a rule pack whose `schema_version` is unsupported,
    /// matching core's `parse_rules_file`. Pre-fix the CLI parser skipped
    /// the schema check, so `rules validate` reported a green pass for a
    /// pack the scanner refuses to load at scan time.
    #[test]
    fn parse_rule_source_rejects_unsupported_schema_version() {
        let bad = r#"
schema_version: skill-veil.dev/rules/v999-bogus
metadata:
  name: test-pack
rules:
  - id: SOME_RULE
    category: generic
    severity: medium
    confidence: 0.8
    when: !regex
      pattern: "evil"
    action: require_approval
    reason: "test rule"
"#;
        let err = parse_rule_source(bad).expect_err("unsupported schema must be rejected");
        assert!(
            err.to_string().contains("schema version"),
            "error must name the schema version mismatch; got {err}"
        );
    }

    /// Contract: a pack carrying the supported `schema_version` still
    /// parses as a `RulePack`. Pins the positive direction of the
    /// schema-version gate.
    #[test]
    fn parse_rule_source_accepts_supported_schema_version() {
        let good = r#"
schema_version: skill-veil.dev/rules/v1alpha1
metadata:
  name: test-pack
rules:
  - id: SOME_RULE
    category: generic
    severity: medium
    confidence: 0.8
    when: !regex
      pattern: "evil"
    action: require_approval
    reason: "test rule"
"#;
        assert!(matches!(
            parse_rule_source(good).unwrap(),
            ParsedRuleSource::RulePack(_)
        ));
    }
}
