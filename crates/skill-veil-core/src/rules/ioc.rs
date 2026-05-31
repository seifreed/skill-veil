use super::condition::RuleCondition;
use super::schema::{IocFeedFile, Rule};
use super::RuleError;
use crate::findings::{RecommendedAction, Severity, ThreatCategory};

/// Hard cap on the number of IOC items that can be packed into a single
/// alternation regex. The motor `regex` compiles a DFA whose state count
/// scales with the alternation; a feed of 1M domains produces a ~20 MB
/// pattern that can balloon to hundreds of MB of compiled state. 10 000
/// items per kind is well above any legitimate feed (Unit42 / Mandiant
/// monthly drops are typically 200–2 000 indicators) while keeping the
/// compiled DFA bounded. Exceeding the cap is rejected explicitly so the
/// operator knows to split the feed instead of silently degrading
/// scanner throughput.
pub(super) const MAX_IOC_ITEMS_PER_KIND: usize = 10_000;

struct IocRuleSpec<'a> {
    id_suffix: &'a str,
    category: ThreatCategory,
    severity: Severity,
    confidence: f32,
    reason: &'a str,
    ioc_tag: &'a str,
}

pub(super) fn ioc_feed_to_rules(feed: &IocFeedFile) -> Result<Vec<Rule>, RuleError> {
    let mut rules = Vec::new();
    let pack_name = &feed.metadata.name;

    push_ioc_rule(
        &mut rules,
        &feed.domains,
        pack_name,
        IocRuleSpec {
            id_suffix: "DOMAINS",
            category: ThreatCategory::SupplyChain,
            severity: Severity::Critical,
            confidence: 0.99,
            reason: "IOC feed matched a known malicious domain",
            ioc_tag: "domain",
        },
    )?;
    push_ioc_rule(
        &mut rules,
        &feed.ips,
        pack_name,
        IocRuleSpec {
            id_suffix: "IPS",
            category: ThreatCategory::DataExfiltration,
            severity: Severity::Critical,
            confidence: 0.99,
            reason: "IOC feed matched a known malicious IP",
            ioc_tag: "ip",
        },
    )?;
    push_ioc_rule(
        &mut rules,
        &feed.filenames,
        pack_name,
        IocRuleSpec {
            id_suffix: "FILENAMES",
            category: ThreatCategory::SupplyChain,
            severity: Severity::High,
            confidence: 0.95,
            reason: "IOC feed matched a known malicious filename",
            ioc_tag: "filename",
        },
    )?;

    Ok(rules)
}

fn push_ioc_rule(
    rules: &mut Vec<Rule>,
    items: &[String],
    pack_name: &str,
    spec: IocRuleSpec<'_>,
) -> Result<(), RuleError> {
    if items.is_empty() {
        return Ok(());
    }
    if items.len() > MAX_IOC_ITEMS_PER_KIND {
        return Err(RuleError::InvalidRule(format!(
            "IOC feed '{}' has {} {} entries; the per-kind cap is {} \
             (split the feed into multiple packs to enforce the budget)",
            pack_name,
            items.len(),
            spec.ioc_tag,
            MAX_IOC_ITEMS_PER_KIND
        )));
    }
    // Drop empty entries before building the alternation: an empty string
    // escapes to `""`, producing `(?i)(|evil\.com)` whose empty branch matches
    // the zero-width string at every byte and flags every scanned document.
    let escaped: Vec<String> = items
        .iter()
        .filter(|item| !item.is_empty())
        .map(|item| regex::escape(item))
        .collect();
    if escaped.is_empty() {
        return Ok(());
    }
    rules.push(Rule {
        id: format!(
            "IOC_FEED_{}_{}",
            normalized_pack_name(pack_name),
            spec.id_suffix
        ),
        category: spec.category,
        severity: spec.severity,
        confidence: spec.confidence,
        condition: RuleCondition::Regex {
            pattern: format!("(?i)({})", escaped.join("|")),
        },
        action: RecommendedAction::Block,
        reason: spec.reason.to_string(),
        shield: None,
        enabled: true,
        tags: vec!["ioc".to_string(), spec.ioc_tag.to_string()],
        taxonomy_tags: Vec::new(),
        promptintel_threats: Vec::new(),
        requires_code_artifact: false,
        downgrade_when_confirmation_gate: false,
        downgrade_when_documentation_context: false,
    });
    Ok(())
}

/// Normalize a pack name for safe inclusion in a generated rule ID.
///
/// Keeps ASCII alphanumerics as-is (uppercased) and folds every other
/// character into `_`. This avoids letting feed authors smuggle
/// punctuation or whitespace into the rule ID surface — IDs flow into
/// SARIF, JSON reports, baselines, waivers, and policy overrides where
/// non-`[A-Z0-9_]` characters would either fail to parse downstream or
/// confuse path-based suppression matching.
fn normalized_pack_name(name: &str) -> String {
    if name.trim().is_empty() {
        return "UNNAMED".to_string();
    }
    name.to_ascii_uppercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::schema::{IocFeedFile, RulePackMetadata};

    fn feed_with_domains(count: usize) -> IocFeedFile {
        IocFeedFile {
            schema_version: super::super::RULE_PACK_SCHEMA_VERSION.to_string(),
            metadata: RulePackMetadata {
                name: "test-feed".to_string(),
                kind: None,
                compatibility: Vec::new(),
            },
            domains: (0..count)
                .map(|i| format!("evil-{i}.example.com"))
                .collect(),
            ips: Vec::new(),
            filenames: Vec::new(),
        }
    }

    /// Contract: a feed with exactly `MAX_IOC_ITEMS_PER_KIND` entries is
    /// accepted (the cap is inclusive). Pins the boundary so a future
    /// off-by-one in the comparison cannot tighten the cap silently.
    #[test]
    fn ioc_feed_accepts_exactly_max_items_per_kind() {
        let feed = feed_with_domains(MAX_IOC_ITEMS_PER_KIND);
        let result = ioc_feed_to_rules(&feed);
        assert!(
            result.is_ok(),
            "feed with exactly the cap MUST succeed; got {result:?}"
        );
    }

    /// Contract: a feed with one item over the cap is rejected with an
    /// explicit `InvalidRule` error mentioning the limit. Without this
    /// guard, a 1M-domain feed silently compiled into a multi-hundred-MB
    /// regex DFA and degraded the entire scan.
    #[test]
    fn ioc_feed_rejects_more_than_max_items_per_kind() {
        let feed = feed_with_domains(MAX_IOC_ITEMS_PER_KIND + 1);
        let err =
            ioc_feed_to_rules(&feed).expect_err("feed exceeding cap MUST fail with InvalidRule");
        let msg = err.to_string();
        assert!(
            msg.contains(&MAX_IOC_ITEMS_PER_KIND.to_string()),
            "error message MUST mention the cap so operators can act: {msg}"
        );
    }

    /// Contract: pack names with punctuation or whitespace fold to `_`
    /// in the generated rule ID. Non-`[A-Z0-9_]` characters in a rule
    /// ID would break baseline / waiver fingerprinting and SARIF
    /// downstream consumers.
    #[test]
    fn normalized_pack_name_folds_punctuation_to_underscore() {
        assert_eq!(super::normalized_pack_name("pack (v1!)"), "PACK__V1__");
        assert_eq!(super::normalized_pack_name("evil/feed"), "EVIL_FEED");
        assert_eq!(super::normalized_pack_name(""), "UNNAMED");
        assert_eq!(super::normalized_pack_name("   "), "UNNAMED");
    }

    /// Contract: an empty-string feed entry is dropped rather than compiled
    /// into an empty alternation `(?i)(|evil\.com)`, whose empty branch would
    /// match the zero-width string at every byte and flag every document.
    #[test]
    fn ioc_feed_drops_empty_entries() {
        let mut feed = feed_with_domains(0);
        feed.domains = vec![String::new(), "evil.example.com".to_string()];
        let rules = ioc_feed_to_rules(&feed).expect("feed must compile");
        assert_eq!(rules.len(), 1, "only the domains kind yields a rule");
        let RuleCondition::Regex { pattern } = &rules[0].condition else {
            panic!("IOC domain rule must be a Regex condition");
        };
        let re = regex::Regex::new(pattern).expect("pattern must compile");
        assert!(
            !re.is_match("a perfectly benign document with no IOCs"),
            "an empty entry must not become a match-everything regex; pattern={pattern}"
        );
        assert!(
            re.is_match("contact evil.example.com now"),
            "the real IOC entry must still match; pattern={pattern}"
        );
    }

    /// Contract: a feed whose entries are all empty strings emits no rule —
    /// there is nothing usable to match against.
    #[test]
    fn ioc_feed_with_only_empty_entries_emits_no_rule() {
        let mut feed = feed_with_domains(0);
        feed.domains = vec![String::new(), String::new()];
        let rules = ioc_feed_to_rules(&feed).expect("feed must compile");
        assert!(rules.is_empty(), "an all-empty feed must emit no rule");
    }
}
