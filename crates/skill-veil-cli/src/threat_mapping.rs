//! Operator-supplied threat mapping (`--threat-mapping`).
//!
//! Cisco's skill-scanner lets operators overlay a custom taxonomy /
//! threat-mapping file. skill-veil's [`TaxonomyTag`](skill_veil_core::TaxonomyTag)
//! registry is frozen public API, so this provides the EXTENSIBLE half:
//! a JSON or YAML file mapping a rule id (or a `PREFIX*` glob) to free-form
//! labels that are stamped onto matching findings' `user_taxonomy`. The
//! labels are communication-only — surfaced in JSON output, never feeding
//! verdict scoring.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use skill_veil_core::ScanResult;

/// How one mapping entry matches a finding's `rule_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Matcher {
    Exact(String),
    /// `PREFIX*` — matches any rule id starting with `PREFIX`.
    Prefix(String),
}

impl Matcher {
    fn parse(key: &str) -> Self {
        key.strip_suffix('*').map_or_else(
            || Self::Exact(key.to_string()),
            |p| Self::Prefix(p.to_string()),
        )
    }

    fn matches(&self, rule_id: &str) -> bool {
        match self {
            Self::Exact(k) => rule_id == k,
            Self::Prefix(p) => rule_id.starts_with(p),
        }
    }
}

/// A loaded threat-mapping: ordered `(matcher, labels)` entries.
#[derive(Debug, Clone)]
pub(crate) struct ThreatMapping {
    entries: Vec<(Matcher, Vec<String>)>,
}

impl ThreatMapping {
    fn from_map(raw: BTreeMap<String, Vec<String>>) -> Self {
        let entries = raw
            .into_iter()
            .map(|(key, labels)| (Matcher::parse(&key), labels))
            .collect();
        Self { entries }
    }

    /// Load a mapping from a JSON or YAML file. The shape is an object of
    /// `rule_id_or_prefix -> [label, ...]`. YAML is a superset of JSON, so
    /// a single YAML parse accepts both.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text = crate::util::bounded_read::read_operator_text_file(path)
            .with_context(|| format!("reading threat-mapping file {}", path.display()))?;
        let raw: BTreeMap<String, Vec<String>> = serde_yaml::from_str(&text)
            .with_context(|| format!("parsing threat-mapping file {}", path.display()))?;
        Ok(Self::from_map(raw))
    }

    /// The deduplicated, sorted labels that apply to `rule_id` across every
    /// matching entry.
    #[must_use]
    pub(crate) fn labels_for(&self, rule_id: &str) -> Vec<String> {
        let mut labels: Vec<String> = self
            .entries
            .iter()
            .filter(|(matcher, _)| matcher.matches(rule_id))
            .flat_map(|(_, labels)| labels.iter().cloned())
            .collect();
        labels.sort();
        labels.dedup();
        labels
    }

    /// Stamp `user_taxonomy` onto every finding whose `rule_id` matches an
    /// entry. Communication-only — leaves verdict, risk score, and
    /// `recommended_action` untouched.
    pub(crate) fn apply(&self, results: &mut [ScanResult]) {
        for result in results {
            for finding in &mut result.findings {
                let labels = self.labels_for(&finding.rule_id);
                if !labels.is_empty() {
                    finding.user_taxonomy = labels;
                }
            }
            for finding in &mut result.primary_findings {
                let labels = self.labels_for(&finding.rule_id);
                if !labels.is_empty() {
                    finding.user_taxonomy = labels;
                }
            }
            for finding in &mut result.supporting_findings {
                let labels = self.labels_for(&finding.rule_id);
                if !labels.is_empty() {
                    finding.user_taxonomy = labels;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(pairs: &[(&str, &[&str])]) -> ThreatMapping {
        let raw = pairs
            .iter()
            .map(|(k, v)| {
                (
                    (*k).to_string(),
                    v.iter().map(|s| (*s).to_string()).collect(),
                )
            })
            .collect();
        ThreatMapping::from_map(raw)
    }

    #[test]
    fn exact_match_applies_labels() {
        let m = mapping(&[(
            "BYTECODE_PYC_SOURCELESS",
            &["mitre:T1027", "internal:bytecode"],
        )]);
        assert_eq!(
            m.labels_for("BYTECODE_PYC_SOURCELESS"),
            vec!["internal:bytecode".to_string(), "mitre:T1027".to_string()]
        );
        assert!(m.labels_for("OTHER_RULE").is_empty());
    }

    #[test]
    fn prefix_glob_matches_family() {
        let m = mapping(&[("BYTECODE_*", &["family:bytecode"])]);
        assert_eq!(
            m.labels_for("BYTECODE_PYC_INVALID_MAGIC"),
            vec!["family:bytecode".to_string()]
        );
        assert_eq!(
            m.labels_for("BYTECODE_PYC_SOURCELESS"),
            vec!["family:bytecode".to_string()]
        );
        assert!(m.labels_for("MCP_NO_AUTH_MODEL").is_empty());
    }

    #[test]
    fn overlapping_entries_union_and_dedup() {
        let m = mapping(&[
            ("BYTECODE_*", &["family:bytecode", "shared"]),
            ("BYTECODE_PYC_SOURCELESS", &["specific", "shared"]),
        ]);
        assert_eq!(
            m.labels_for("BYTECODE_PYC_SOURCELESS"),
            vec![
                "family:bytecode".to_string(),
                "shared".to_string(),
                "specific".to_string()
            ]
        );
    }

    #[test]
    fn matcher_parse_distinguishes_exact_and_prefix() {
        assert_eq!(Matcher::parse("ABC"), Matcher::Exact("ABC".to_string()));
        assert_eq!(Matcher::parse("ABC*"), Matcher::Prefix("ABC".to_string()));
    }

    #[test]
    fn yaml_and_json_both_parse() {
        let json = r#"{"RULE_A": ["x"], "PREF*": ["y"]}"#;
        let from_json: BTreeMap<String, Vec<String>> = serde_yaml::from_str(json).unwrap();
        let m = ThreatMapping::from_map(from_json);
        assert_eq!(m.labels_for("RULE_A"), vec!["x".to_string()]);
        assert_eq!(m.labels_for("PREFIXED"), vec!["y".to_string()]);
    }
}
