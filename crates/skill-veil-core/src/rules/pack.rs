use crate::findings::{RecommendedAction, Severity, ThreatCategory};
use crate::rules::{IocFeedFile, RULE_PACK_SCHEMA_VERSION, Rule, RuleCondition, RuleError, RulePackFile};
use std::path::Path;

pub(super) fn get_builtin_rules(core_yaml: &str, behavioral_yaml: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    for embedded_pack in [core_yaml, behavioral_yaml] {
        let parsed =
            parse_rules_file(embedded_pack).expect("Failed to parse embedded official rules pack");
        rules.extend(parsed);
    }
    rules
}

pub(super) fn load_rules_path(path: &Path) -> Result<Vec<Rule>, RuleError> {
    let content = std::fs::read_to_string(path)?;
    parse_rules_file(&content)
}

pub fn parse_rules_file(content: &str) -> Result<Vec<Rule>, RuleError> {
    if let Ok(pack) = serde_yaml::from_str::<RulePackFile>(content) {
        if !pack.rules.is_empty() {
            if !is_supported_rule_pack_schema(&pack.schema_version) {
                return Err(RuleError::InvalidRule(format!(
                    "Unsupported rule pack schema version: {}",
                    pack.schema_version
                )));
            }
            return Ok(pack.rules);
        }
    }

    if let Ok(feed) = serde_yaml::from_str::<IocFeedFile>(content) {
        if !(feed.domains.is_empty() && feed.filenames.is_empty() && feed.ips.is_empty()) {
            if !is_supported_rule_pack_schema(&feed.schema_version) {
                return Err(RuleError::InvalidRule(format!(
                    "Unsupported IOC feed schema version: {}",
                    feed.schema_version
                )));
            }
            return Ok(ioc_feed_to_rules(&feed));
        }
    }

    let rules: Vec<Rule> = serde_yaml::from_str(content)?;
    Ok(rules)
}

pub fn is_supported_rule_pack_schema(schema_version: &str) -> bool {
    schema_version == RULE_PACK_SCHEMA_VERSION
}

pub fn default_external_rule_dirs() -> Vec<std::path::PathBuf> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    vec![cwd.join("rules").join("official")]
}

fn ioc_feed_to_rules(feed: &IocFeedFile) -> Vec<Rule> {
    let mut rules = Vec::new();

    if !feed.domains.is_empty() {
        rules.push(Rule {
            id: format!(
                "IOC_FEED_{}_DOMAINS",
                normalized_pack_name(&feed.metadata.name)
            ),
            category: ThreatCategory::SupplyChain,
            severity: Severity::Critical,
            confidence: 0.99,
            condition: RuleCondition::Regex {
                pattern: format!(
                    "(?i)({})",
                    feed.domains
                        .iter()
                        .map(|domain| regex::escape(domain))
                        .collect::<Vec<_>>()
                        .join("|")
                ),
            },
            action: RecommendedAction::Block,
            reason: "IOC feed matched a known malicious domain".to_string(),
            shield: None,
            enabled: true,
            tags: vec!["ioc".to_string(), "domain".to_string()],
        });
    }

    if !feed.ips.is_empty() {
        rules.push(Rule {
            id: format!("IOC_FEED_{}_IPS", normalized_pack_name(&feed.metadata.name)),
            category: ThreatCategory::DataExfiltration,
            severity: Severity::Critical,
            confidence: 0.99,
            condition: RuleCondition::Regex {
                pattern: format!(
                    "({})",
                    feed.ips
                        .iter()
                        .map(|ip| regex::escape(ip))
                        .collect::<Vec<_>>()
                        .join("|")
                ),
            },
            action: RecommendedAction::Block,
            reason: "IOC feed matched a known malicious IP".to_string(),
            shield: None,
            enabled: true,
            tags: vec!["ioc".to_string(), "ip".to_string()],
        });
    }

    if !feed.filenames.is_empty() {
        rules.push(Rule {
            id: format!(
                "IOC_FEED_{}_FILENAMES",
                normalized_pack_name(&feed.metadata.name)
            ),
            category: ThreatCategory::SupplyChain,
            severity: Severity::High,
            confidence: 0.95,
            condition: RuleCondition::Regex {
                pattern: format!(
                    "(?i)({})",
                    feed.filenames
                        .iter()
                        .map(|name| regex::escape(name))
                        .collect::<Vec<_>>()
                        .join("|")
                ),
            },
            action: RecommendedAction::Block,
            reason: "IOC feed matched a known malicious filename".to_string(),
            shield: None,
            enabled: true,
            tags: vec!["ioc".to_string(), "filename".to_string()],
        });
    }

    rules
}

fn normalized_pack_name(name: &str) -> String {
    if name.trim().is_empty() {
        "unnamed".to_string()
    } else {
        name.to_ascii_uppercase().replace([' ', '-'], "_")
    }
}
