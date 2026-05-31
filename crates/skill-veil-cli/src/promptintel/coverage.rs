//! Coverage report: which PromptIntel threats are tagged by at least
//! one rule in the loaded packs, and which are completely uncovered.
//!
//! The mapping comes from each rule's `promptintel_threats: [...]`
//! YAML field. Threats not covered by any rule appear with `0` rule
//! IDs so the operator can see the gap mechanically. Tags that name
//! a threat NOT in the canonical taxonomy are surfaced as a separate
//! `Drift` block so an upstream rename never silently passes.

use super::taxonomy::{bucket_for, TAXONOMY};
use anyhow::{Context, Result};
use serde::Serialize;
use skill_veil_core::{
    default_external_rule_dirs, RegexPatternMatcher, Rule, RuleEngine, StdFileSystemProvider,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct CoverageOptions {
    /// Optional explicit rule pack directory. `None` defers to the
    /// scanner's normal cwd-relative discovery.
    pub(crate) rules_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct CoverageReport {
    pub(crate) buckets: Vec<BucketCoverage>,
    /// Threat names referenced by rules but NOT present in the
    /// canonical taxonomy. Operator action: rename in the rule, or
    /// extend the taxonomy.
    pub(crate) drift: Vec<DriftCoverage>,
    pub(crate) total_rules: usize,
    pub(crate) tagged_rules: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct BucketCoverage {
    pub(crate) name: String,
    pub(crate) threats: Vec<ThreatCoverage>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct ThreatCoverage {
    pub(crate) threat: String,
    pub(crate) rule_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct DriftCoverage {
    pub(crate) threat: String,
    pub(crate) rule_ids: Vec<String>,
}

/// Build the coverage report from a freshly-loaded rule engine.
///
/// # Errors
/// - The scanner cannot construct the engine (rule pack invalid,
///   filesystem unreadable). The error is propagated unchanged so an
///   operator with a malformed pack sees the same diagnostic the
///   scanner would have surfaced.
pub(crate) fn build_report(opts: &CoverageOptions) -> Result<CoverageReport> {
    let fs = StdFileSystemProvider::new();
    let runtime_dirs: Vec<PathBuf> = match opts.rules_dir.as_ref() {
        Some(dir) => vec![dir.clone()],
        None => default_external_rule_dirs(),
    };
    let engine = RuleEngine::with_defaults_and_matcher(
        Arc::new(RegexPatternMatcher::new()),
        &fs,
        &runtime_dirs,
    )
    .context("loading rule packs")?;

    Ok(report_from_rules(engine.rules()))
}

/// Pure helper that builds a report from an in-memory rule list.
/// Split out so unit tests can exercise the bucketing logic without
/// touching the filesystem.
fn report_from_rules(rules: Vec<&Rule>) -> CoverageReport {
    let total_rules = rules.len();
    let mut tagged_rules = 0usize;

    let mut by_threat: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for rule in rules {
        if rule.promptintel_threats.is_empty() {
            continue;
        }
        tagged_rules += 1;
        for threat in &rule.promptintel_threats {
            by_threat
                .entry(threat.clone())
                .or_default()
                .push(rule.id.clone());
        }
    }

    let mut buckets: Vec<BucketCoverage> = TAXONOMY
        .iter()
        .map(|bucket| BucketCoverage {
            name: bucket.name.to_string(),
            threats: bucket
                .threats
                .iter()
                .map(|threat| ThreatCoverage {
                    threat: (*threat).to_string(),
                    rule_ids: by_threat.get(*threat).cloned().unwrap_or_default(),
                })
                .collect(),
        })
        .collect();

    // Inside each bucket, sort threats so the un-covered ones appear
    // first (the gap is the actionable signal). Tied counts fall
    // back to alphabetical for stability.
    for bucket in &mut buckets {
        bucket.threats.sort_by(|a, b| {
            a.rule_ids
                .len()
                .cmp(&b.rule_ids.len())
                .then_with(|| a.threat.cmp(&b.threat))
        });
    }

    let mut drift: Vec<DriftCoverage> = by_threat
        .iter()
        .filter(|(name, _)| bucket_for(name).is_none())
        .map(|(name, rule_ids)| DriftCoverage {
            threat: name.clone(),
            rule_ids: rule_ids.clone(),
        })
        .collect();
    drift.sort_by(|a, b| a.threat.cmp(&b.threat));

    CoverageReport {
        buckets,
        drift,
        total_rules,
        tagged_rules,
    }
}

/// Render `report` as a human-readable text block.
pub(crate) fn render_text(report: &CoverageReport) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str("=== PromptIntel Rule Coverage ===\n");
    out.push_str(&format!(
        "rules total: {}  with promptintel_threats tag: {}\n",
        report.total_rules, report.tagged_rules
    ));

    for bucket in &report.buckets {
        let covered = bucket
            .threats
            .iter()
            .filter(|t| !t.rule_ids.is_empty())
            .count();
        let total = bucket.threats.len();
        out.push_str(&format!(
            "\n  [{}]  {covered}/{total} threats covered\n",
            bucket.name
        ));
        for threat in &bucket.threats {
            let marker = if threat.rule_ids.is_empty() {
                "GAP "
            } else {
                "OK  "
            };
            out.push_str(&format!(
                "    [{marker}] {threat:<48}  rules: {}\n",
                if threat.rule_ids.is_empty() {
                    "(none)".to_string()
                } else {
                    threat.rule_ids.join(", ")
                },
                threat = threat.threat,
            ));
        }
    }

    if !report.drift.is_empty() {
        out.push_str(
            "\n  [Drift — promptintel_threats values that are NOT in taxonomy::TAXONOMY]\n",
        );
        for drift in &report.drift {
            out.push_str(&format!(
                "    {threat}  rules: {ids}\n",
                threat = drift.threat,
                ids = drift.rule_ids.join(", "),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use skill_veil_core::{RecommendedAction, RuleCondition, Severity, ThreatCategory};

    fn rule(id: &str, threats: &[&str]) -> Rule {
        Rule {
            id: id.to_string(),
            category: ThreatCategory::Generic,
            severity: Severity::Medium,
            confidence: 0.7,
            condition: RuleCondition::Regex {
                pattern: "x".to_string(),
            },
            action: RecommendedAction::Log,
            reason: "test".to_string(),
            shield: None,
            enabled: true,
            tags: Vec::new(),
            taxonomy_tags: Vec::new(),
            promptintel_threats: threats.iter().map(|s| (*s).to_string()).collect(),
            requires_code_artifact: false,
            downgrade_when_confirmation_gate: false,
            downgrade_when_documentation_context: false,
        }
    }

    /// Contract: every taxonomy bucket appears in the report,
    /// regardless of whether any rule tagged a threat under it.
    /// Pre-fix an aggregate that listed only buckets with hits would
    /// hide whole gap classes from the operator.
    #[test]
    fn report_lists_every_bucket_even_without_hits() {
        let rules: Vec<Rule> = Vec::new();
        let refs: Vec<&Rule> = rules.iter().collect();
        let report = report_from_rules(refs);
        assert_eq!(report.buckets.len(), TAXONOMY.len());
        for bucket in &report.buckets {
            for threat in &bucket.threats {
                assert!(threat.rule_ids.is_empty());
            }
        }
    }

    /// Contract: a rule tagged with multiple threats counts toward
    /// each one independently. Pre-fix a naive "first threat wins"
    /// implementation would under-count multi-tagged rules and
    /// inflate the gap report.
    #[test]
    fn rule_with_multiple_threats_counts_for_each() {
        let r = rule("R1", &["Jailbreak", "Direct prompt injection"]);
        let refs: Vec<&Rule> = vec![&r];
        let report = report_from_rules(refs);
        let prompt_manip = report
            .buckets
            .iter()
            .find(|b| b.name == "Prompt Manipulation")
            .unwrap();
        let jb = prompt_manip
            .threats
            .iter()
            .find(|t| t.threat == "Jailbreak")
            .unwrap();
        let dpi = prompt_manip
            .threats
            .iter()
            .find(|t| t.threat == "Direct prompt injection")
            .unwrap();
        assert_eq!(jb.rule_ids, vec!["R1".to_string()]);
        assert_eq!(dpi.rule_ids, vec!["R1".to_string()]);
        assert_eq!(report.tagged_rules, 1);
    }

    /// Contract: a rule tagging a name that is NOT in the canonical
    /// taxonomy MUST surface in the `drift` block, never silently
    /// drop. The operator must see it to either fix the rule or
    /// extend the taxonomy.
    #[test]
    fn unknown_threat_in_rule_surfaces_as_drift() {
        let r = rule("R1", &["future_only_threat"]);
        let refs: Vec<&Rule> = vec![&r];
        let report = report_from_rules(refs);
        assert_eq!(report.drift.len(), 1);
        assert_eq!(report.drift[0].threat, "future_only_threat");
        assert_eq!(report.drift[0].rule_ids, vec!["R1".to_string()]);
    }

    /// Contract: within a bucket, GAP threats (zero rules) sort
    /// BEFORE covered ones — the operator is shown the actionable
    /// gap first.
    #[test]
    fn threats_within_bucket_sort_gaps_first() {
        let r = rule("R1", &["Jailbreak"]);
        let refs: Vec<&Rule> = vec![&r];
        let report = report_from_rules(refs);
        let prompt_manip = report
            .buckets
            .iter()
            .find(|b| b.name == "Prompt Manipulation")
            .unwrap();
        let first_covered = prompt_manip
            .threats
            .iter()
            .position(|t| !t.rule_ids.is_empty())
            .expect("at least one threat is covered");
        let last_gap = prompt_manip
            .threats
            .iter()
            .rposition(|t| t.rule_ids.is_empty())
            .expect("at least one gap exists");
        assert!(
            last_gap < first_covered,
            "all GAP threats must precede covered ones; \
             last gap was at {last_gap}, first covered at {first_covered}"
        );
    }

    /// Contract: rules with no `promptintel_threats` field are
    /// counted in `total_rules` but NOT in `tagged_rules`. Pre-fix
    /// a single counter would conflate the two and overstate
    /// project-wide tagging completeness.
    #[test]
    fn untagged_rules_count_total_but_not_tagged() {
        let r1 = rule("R1", &["Jailbreak"]);
        let r2 = rule("R2", &[]);
        let refs: Vec<&Rule> = vec![&r1, &r2];
        let report = report_from_rules(refs);
        assert_eq!(report.total_rules, 2);
        assert_eq!(report.tagged_rules, 1);
    }
}
