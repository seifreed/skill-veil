use super::condition::RuleCondition;
use super::schema::{IocFeedFile, Rule};
use crate::findings::{RecommendedAction, Severity, ThreatCategory};

struct IocRuleSpec<'a> {
    id_suffix: &'a str,
    category: ThreatCategory,
    severity: Severity,
    confidence: f32,
    reason: &'a str,
    ioc_tag: &'a str,
}

pub(super) fn ioc_feed_to_rules(feed: &IocFeedFile) -> Vec<Rule> {
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
    );
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
    );
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
    );

    rules
}

fn push_ioc_rule(rules: &mut Vec<Rule>, items: &[String], pack_name: &str, spec: IocRuleSpec<'_>) {
    if items.is_empty() {
        return;
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
            pattern: format!(
                "(?i)({})",
                items
                    .iter()
                    .map(|s| regex::escape(s))
                    .collect::<Vec<_>>()
                    .join("|")
            ),
        },
        action: RecommendedAction::Block,
        reason: spec.reason.to_string(),
        shield: None,
        enabled: true,
        tags: vec!["ioc".to_string(), spec.ioc_tag.to_string()],
    });
}

fn normalized_pack_name(name: &str) -> String {
    if name.trim().is_empty() {
        "unnamed".to_string()
    } else {
        name.to_ascii_uppercase().replace([' ', '-'], "_")
    }
}
