use super::ioc::ioc_feed_to_rules;
use super::schema::{IocFeedFile, Rule, RulePackFile};
use super::{RuleError, RULE_PACK_SCHEMA_VERSION};
use std::path::PathBuf;

/// Parse a YAML rule file, attempting three formats in priority order:
/// `RulePackFile` (preferred), `IocFeedFile` (legacy IOC packs), and
/// finally a bare `Vec<Rule>`.
///
/// # Schema validation contract
///
/// When the YAML deserializes to a `RulePackFile` or `IocFeedFile`, the
/// `schema_version` is validated **before** the per-format emptiness
/// check (`pack.rules.is_empty()` / no IOC items). Pre-fix the order was
/// inverted: a pack with `schema_version: invalid-version` and `rules:
/// []` would silently fall through to the next format and ultimately
/// surface as the misleading `"Rule file is empty or contains no valid
/// rules"` instead of the actual schema error. Validating early gives
/// pack authors an actionable error and prevents the scanner from
/// accepting packs that may rely on schema-version-specific semantics
/// the engine does not yet understand.
pub fn parse_rules_file(content: &str) -> Result<Vec<Rule>, RuleError> {
    let mut errors = Vec::new();

    if let Ok(pack) = serde_yaml::from_str::<RulePackFile>(content) {
        if !is_supported_rule_pack_schema(&pack.schema_version) {
            return Err(RuleError::InvalidRule(format!(
                "Unsupported rule pack schema version: {}",
                pack.schema_version
            )));
        }
        if !pack.rules.is_empty() {
            return Ok(pack.rules);
        }
        // Recognised as RulePackFile but empty — push a label so the
        // final error message mentions this format was attempted.
        errors.push("RulePackFile format (empty rules)".to_string());
    } else if !content.trim().is_empty() {
        errors.push("RulePackFile format".to_string());
    }

    if let Ok(feed) = serde_yaml::from_str::<IocFeedFile>(content) {
        if !is_supported_rule_pack_schema(&feed.schema_version) {
            return Err(RuleError::InvalidRule(format!(
                "Unsupported IOC feed schema version: {}",
                feed.schema_version
            )));
        }
        if !(feed.domains.is_empty() && feed.filenames.is_empty() && feed.ips.is_empty()) {
            return ioc_feed_to_rules(&feed);
        }
    } else if !content.trim().is_empty() {
        errors.push("IocFeedFile format".to_string());
    }

    match serde_yaml::from_str::<Vec<Rule>>(content) {
        Ok(rules) => return Ok(rules),
        Err(e) => {
            errors.push(format!("rule list format: {}", e));
        }
    }

    if errors.is_empty() {
        Err(RuleError::InvalidRule(
            "Rule file is empty or contains no valid rules".to_string(),
        ))
    } else {
        Err(RuleError::InvalidRule(format!(
            "Failed to parse rules file. Attempted formats: {}",
            errors.join("; ")
        )))
    }
}

pub fn is_supported_rule_pack_schema(schema_version: &str) -> bool {
    schema_version == RULE_PACK_SCHEMA_VERSION
}

pub fn default_external_rule_dirs() -> Vec<PathBuf> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    vec![cwd.join("rules").join("official")]
}
