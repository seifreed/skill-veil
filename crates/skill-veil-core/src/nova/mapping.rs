//! Map a [`NovaMatch`] into the canonical [`Finding`] shape so NOVA
//! results flow through the same pipeline as skill-veil-rules
//! findings (waivers, baselines, JSON / SARIF output, `--fail-on`).
//!
//! Conservative defaults for this first pass:
//!
//! - **`rule_id`** prefixed `NOVA_<rule_name>` so consumers can
//!   visually distinguish NOVA hits from skill-veil-rules hits and so
//!   waivers / baselines targeting NOVA can use a stable key.
//! - **`signal_class = ReviewSignal`** so NOVA matches show up in
//!   reports but do NOT inflate the verdict score the way a
//!   `MaliciousBehavior` from skill-veil-rules would. Operators
//!   pin the policy weight; promoting NOVA findings to higher
//!   signal classes is a per-rule decision that needs benchmark
//!   evidence per category, which we don't have yet.
//! - **`recommended_action = RequireApproval`** (never `Block`) for
//!   the same reason: NOVA is a community-driven pack we do not yet
//!   pin for false-positive rates against the skill-veil benchmark
//!   corpus.
//! - **`confidence`** is the per-pattern score the evaluator
//!   surfaced: `1.0` for keyword regex matches, the real cosine
//!   similarity for semantic matches, and the model confidence for
//!   LLM matches. When a fired pattern carries no score (e.g. a match
//!   deserialised from a pre-score-plumbing cache) the rule's declared
//!   threshold is used as the documented lower bound.

use super::condition::Section;
use super::model::{NovaMatch, NovaRule};
use crate::findings::{
    ArtifactKind, ArtifactScope, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity,
    SignalClass, ThreatCategory,
};
use std::path::Path;

/// Build a [`Finding`] for the NOVA match. The caller supplies the
/// artifact context (path / kind / scope) since NOVA evaluates raw
/// text and does not know which scope of the package it came from.
///
/// Returns an iterator of one Finding per matching pattern, so the
/// JSON/SARIF output mirrors NOVA's `--verbose` format where each
/// fired pattern is its own line.
#[must_use]
pub fn nova_match_to_findings(
    rule: &NovaRule,
    m: &NovaMatch,
    artifact_path: Option<&Path>,
    artifact_kind: ArtifactKind,
    artifact_scope: ArtifactScope,
) -> Vec<Finding> {
    if !m.matched {
        return Vec::new();
    }

    let severity = severity_from_meta(rule.severity_label());
    let category = category_from_meta(rule.category_label());
    let path_str = artifact_path.map(|p| p.display().to_string());

    let ctx = FindingCtx {
        rule,
        severity,
        category,
        artifact_kind,
        artifact_scope,
        path: path_str,
    };
    let mut out = Vec::new();
    for (var, hit) in &m.keyword_hits {
        if *hit {
            out.push(make_finding(&ctx, Section::Keywords, var, 1.0));
        }
    }
    for (var, hit) in &m.semantic_hits {
        if *hit {
            // Prefer the real cosine similarity the evaluator surfaced;
            // fall back to the rule's declared threshold (the lower
            // bound of "this hit") only when the score is absent — e.g.
            // a match deserialised from a pre-score-plumbing cache.
            let conf = m
                .semantic_scores
                .get(var)
                .copied()
                .unwrap_or_else(|| rule.semantics.get(var).map_or(0.5, |p| p.threshold));
            out.push(make_finding(&ctx, Section::Semantics, var, conf));
        }
    }
    for (var, hit) in &m.llm_hits {
        if *hit {
            let conf = m
                .llm_scores
                .get(var)
                .copied()
                .unwrap_or_else(|| rule.llm.get(var).map_or(0.5, |p| p.threshold));
            out.push(make_finding(&ctx, Section::Llm, var, conf));
        }
    }

    if out.is_empty() {
        // Rule fired by `condition: true` literal or all-empty maps —
        // emit a single placeholder finding so the match is still
        // visible in JSON/SARIF.
        out.push(make_finding(&ctx, Section::Keywords, "_condition", 0.7));
    }
    out
}

struct FindingCtx<'a> {
    rule: &'a NovaRule,
    severity: Severity,
    category: ThreatCategory,
    artifact_kind: ArtifactKind,
    artifact_scope: ArtifactScope,
    path: Option<String>,
}

fn make_finding(ctx: &FindingCtx<'_>, section: Section, var: &str, confidence: f32) -> Finding {
    let rule_id = format!("NOVA_{}_{section}_{var}", ctx.rule.name);
    let reason = ctx
        .rule
        .meta
        .get("description")
        .cloned()
        .unwrap_or_else(|| {
            format!(
                "NOVA rule `{}` matched on `{section}.${var}`",
                ctx.rule.name
            )
        });
    let mut builder = Finding::builder(rule_id, ctx.category)
        .severity(ctx.severity)
        .confidence(confidence)
        .reason(reason)
        .matched_on(MatchTarget::Document)
        .match_value(format!("nova:{section}.${var}"))
        .evidence_kind(EvidenceKind::Behavior)
        .artifact(ctx.artifact_kind, ctx.path.clone())
        .artifact_scope(ctx.artifact_scope)
        .signal_class(SignalClass::ReviewSignal)
        .action(RecommendedAction::RequireApproval);
    // Carry through the upstream NOVA UUID when present so operator
    // triage can link back to the source rule.
    if let Some(uuid) = ctx.rule.meta.get("uuid") {
        builder = builder.remediation(format!(
            "See NOVA rule `{}` (uuid {}). Consult github.com/Nova-Hunting/nova-rules.",
            ctx.rule.name, uuid,
        ));
    }
    builder.build()
}

/// Map a NOVA `severity = "..."` meta entry to the canonical
/// [`Severity`]. Unknown / missing values default to `Medium` —
/// the dominant severity in the upstream pack.
fn severity_from_meta(label: Option<&str>) -> Severity {
    match label.map(str::to_ascii_lowercase).as_deref() {
        Some("critical") => Severity::Critical,
        Some("high") => Severity::High,
        Some("low") | Some("info") | Some("informational") => Severity::Low,
        _ => Severity::Medium,
    }
}

/// Map a NOVA `category = "<bucket>/<name>"` meta entry to the
/// closest [`ThreatCategory`]. The mapping is conservative: NOVA's
/// taxonomy is finer-grained than ours, so several NOVA categories
/// collapse to the same `ThreatCategory`. Anything we cannot
/// classify falls into `Generic` rather than guessing.
fn category_from_meta(label: Option<&str>) -> ThreatCategory {
    let Some(raw) = label else {
        return ThreatCategory::Generic;
    };
    let lower = raw.to_ascii_lowercase();
    // Match on the LEAF of the slash-separated path first, then on
    // the bucket. Order matters for overlap (`prompt_injection`
    // takes precedence over the parent `prompt_manipulation`).
    let leaf = lower.rsplit('/').next().unwrap_or(&lower);
    match leaf {
        "remote_exec" | "remote_execution" => ThreatCategory::RemoteExec,
        "supply_chain" => ThreatCategory::SupplyChain,
        "credential_exposure" | "credentials" | "secret_disclosure" => {
            ThreatCategory::CredentialExposure
        }
        "tool_abuse" | "tool_misuse" | "agentic_misuse" => ThreatCategory::ToolAbuse,
        "autonomy_escalation" => ThreatCategory::AutonomyEscalation,
        "privilege_escalation" => ThreatCategory::PrivilegeEscalation,
        "data_exfiltration" | "exfiltration" | "exfil" => ThreatCategory::DataExfiltration,
        "social_engineering" | "social_manipulation" | "phishing" | "scam" => {
            ThreatCategory::SocialManipulation
        }
        "obfuscation" | "obfuscated" | "evasion" => ThreatCategory::Obfuscation,
        "jailbreak"
        | "direct_injection"
        | "prompt_injection"
        | "prompt_manipulation"
        | "policy_puppetry" => ThreatCategory::PersistentPromptTampering,
        "persuasion" | "persuasive_language" => ThreatCategory::PersuasiveLanguage,
        _ => {
            // Bucket fallback when the leaf isn't recognised.
            let bucket = lower.split('/').next().unwrap_or(&lower);
            match bucket {
                "abusing_functions" => ThreatCategory::ToolAbuse,
                "prompt_manipulation" => ThreatCategory::PersistentPromptTampering,
                "supply_chain" => ThreatCategory::SupplyChain,
                _ => ThreatCategory::Generic,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nova::condition::ConditionExpr;
    use std::collections::BTreeMap;

    fn rule(name: &str, severity: &str, category: &str) -> NovaRule {
        let mut meta = BTreeMap::new();
        meta.insert("description".into(), format!("rule {name} description"));
        meta.insert("severity".into(), severity.into());
        meta.insert("category".into(), category.into());
        meta.insert("uuid".into(), "00000000-0000-0000-0000-000000000001".into());
        NovaRule {
            name: name.into(),
            meta,
            keywords: BTreeMap::new(),
            semantics: BTreeMap::new(),
            llm: BTreeMap::new(),
            condition: ConditionExpr::Literal(true),
        }
    }

    fn match_with_keywords(name: &str, hits: &[(&str, bool)]) -> NovaMatch {
        NovaMatch {
            rule_name: name.into(),
            matched: true,
            keyword_hits: hits.iter().map(|(k, v)| ((*k).into(), *v)).collect(),
            semantic_hits: BTreeMap::new(),
            llm_hits: BTreeMap::new(),
            semantic_scores: BTreeMap::new(),
            llm_scores: BTreeMap::new(),
            skipped_capabilities: vec![],
        }
    }

    fn semantic_rule(var: &str, threshold: f32) -> NovaRule {
        let mut meta = BTreeMap::new();
        meta.insert("description".into(), "semantic rule".into());
        meta.insert("severity".into(), "medium".into());
        let mut semantics = BTreeMap::new();
        semantics.insert(
            var.to_string(),
            crate::nova::model::SemanticPattern {
                pattern: "ignore previous instructions".into(),
                threshold,
            },
        );
        NovaRule {
            name: "Sem".into(),
            meta,
            keywords: BTreeMap::new(),
            semantics,
            llm: BTreeMap::new(),
            condition: ConditionExpr::Literal(true),
        }
    }

    fn semantic_match(var: &str, score: Option<f32>) -> NovaMatch {
        let mut semantic_hits = BTreeMap::new();
        semantic_hits.insert(var.to_string(), true);
        let mut semantic_scores = BTreeMap::new();
        if let Some(s) = score {
            semantic_scores.insert(var.to_string(), s);
        }
        NovaMatch {
            rule_name: "Sem".into(),
            matched: true,
            keyword_hits: BTreeMap::new(),
            semantic_hits,
            llm_hits: BTreeMap::new(),
            semantic_scores,
            llm_scores: BTreeMap::new(),
            skipped_capabilities: vec![],
        }
    }

    /// Contract: when the evaluator surfaces a real cosine-similarity
    /// score for a fired `semantics:` pattern, the Finding confidence
    /// carries THAT score — not the rule's declared threshold. Pins the
    /// score-plumbing so a refactor cannot silently revert NOVA semantic
    /// findings to threshold-only confidence.
    #[test]
    fn semantic_finding_confidence_uses_real_score_not_threshold() {
        let r = semantic_rule("s", 0.4);
        let m = semantic_match("s", Some(0.83));
        let findings = nova_match_to_findings(
            &r,
            &m,
            None,
            ArtifactKind::SkillDocument,
            ArtifactScope::AgentEntrypoint,
        );
        assert_eq!(findings.len(), 1);
        assert!(
            (findings[0].raw_confidence - 0.83).abs() < f32::EPSILON,
            "expected real score 0.83, got {}",
            findings[0].raw_confidence
        );
    }

    /// Contract (negative): with no score plumbed (e.g. a match
    /// deserialised from a pre-score-plumbing cache), the Finding
    /// confidence falls back to the rule's declared threshold — the
    /// documented lower bound of "this hit".
    #[test]
    fn semantic_finding_confidence_falls_back_to_threshold_without_score() {
        let r = semantic_rule("s", 0.4);
        let m = semantic_match("s", None);
        let findings = nova_match_to_findings(
            &r,
            &m,
            None,
            ArtifactKind::SkillDocument,
            ArtifactScope::AgentEntrypoint,
        );
        assert_eq!(findings.len(), 1);
        assert!(
            (findings[0].raw_confidence - 0.4).abs() < f32::EPSILON,
            "expected threshold fallback 0.4, got {}",
            findings[0].raw_confidence
        );
    }

    /// Contract: a non-matching NovaMatch maps to ZERO findings.
    /// Otherwise we'd flood JSON/SARIF with "didn't match" entries.
    #[test]
    fn nonmatch_yields_no_findings() {
        let r = rule("X", "high", "prompt_manipulation/jailbreak");
        let m = NovaMatch {
            rule_name: "X".into(),
            matched: false,
            keyword_hits: BTreeMap::new(),
            semantic_hits: BTreeMap::new(),
            llm_hits: BTreeMap::new(),
            semantic_scores: BTreeMap::new(),
            llm_scores: BTreeMap::new(),
            skipped_capabilities: vec![],
        };
        let findings = nova_match_to_findings(
            &r,
            &m,
            None,
            ArtifactKind::SkillDocument,
            ArtifactScope::AgentEntrypoint,
        );
        assert!(findings.is_empty());
    }

    /// Contract: each matching keyword yields its own Finding. NOVA
    /// `--verbose` lists each fired pattern individually; our JSON
    /// output mirrors that granularity.
    #[test]
    fn each_matching_keyword_gets_its_own_finding() {
        let r = rule("Multi", "high", "abusing_functions/agentic_misuse");
        let m = match_with_keywords("Multi", &[("a", true), ("b", true), ("c", false)]);
        let findings = nova_match_to_findings(
            &r,
            &m,
            None,
            ArtifactKind::SkillDocument,
            ArtifactScope::AgentEntrypoint,
        );
        assert_eq!(findings.len(), 2);
        // rule_id format: NOVA_<name>_<section>_<var>
        let ids: Vec<&str> = findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(ids.contains(&"NOVA_Multi_keywords_a"));
        assert!(ids.contains(&"NOVA_Multi_keywords_b"));
        assert!(!ids.contains(&"NOVA_Multi_keywords_c"));
    }

    /// Contract: severity flows from NOVA `meta.severity`. Defaults
    /// to `Medium` when absent; informationals collapse to `Low`.
    /// Pinned because regressing this would silently inflate or
    /// understate the impact of every NOVA hit.
    #[test]
    fn severity_mapping_matches_nova_labels() {
        assert_eq!(severity_from_meta(Some("critical")), Severity::Critical);
        assert_eq!(severity_from_meta(Some("HIGH")), Severity::High);
        assert_eq!(severity_from_meta(Some("medium")), Severity::Medium);
        assert_eq!(severity_from_meta(Some("low")), Severity::Low);
        assert_eq!(severity_from_meta(Some("info")), Severity::Low);
        assert_eq!(severity_from_meta(None), Severity::Medium);
        assert_eq!(severity_from_meta(Some("nonsense")), Severity::Medium);
    }

    /// Contract: NOVA categories (slash-separated path) map to our
    /// canonical ThreatCategory. The mapping is conservative —
    /// unrecognised categories fall to `Generic`, never guessed.
    #[test]
    fn category_mapping_for_real_nova_buckets() {
        assert_eq!(
            category_from_meta(Some("prompt_manipulation/jailbreak")),
            ThreatCategory::PersistentPromptTampering
        );
        assert_eq!(
            category_from_meta(Some("abusing_functions/agentic_misuse")),
            ThreatCategory::ToolAbuse
        );
        assert_eq!(
            category_from_meta(Some("abusing_functions/social_engineering")),
            ThreatCategory::SocialManipulation
        );
        assert_eq!(
            category_from_meta(Some("supply_chain/dependency")),
            ThreatCategory::SupplyChain
        );
        assert_eq!(
            category_from_meta(Some("totally_unknown")),
            ThreatCategory::Generic
        );
        assert_eq!(category_from_meta(None), ThreatCategory::Generic);
    }

    /// Contract: every NOVA Finding lands as `ReviewSignal` /
    /// `RequireApproval`, never `Block`. Inflating the action would
    /// gate scans on a community pack we have not benchmarked for
    /// false positives. Guarded by a test so a "small" refactor
    /// cannot silently flip it.
    #[test]
    fn nova_findings_are_review_signal_require_approval() {
        let r = rule("Test", "critical", "prompt_manipulation/jailbreak");
        let m = match_with_keywords("Test", &[("a", true)]);
        let f = &nova_match_to_findings(
            &r,
            &m,
            None,
            ArtifactKind::SkillDocument,
            ArtifactScope::AgentEntrypoint,
        )[0];
        assert_eq!(f.signal_class, SignalClass::ReviewSignal);
        assert_eq!(f.recommended_action, RecommendedAction::RequireApproval);
        assert_eq!(f.severity, Severity::Critical); // severity still flows through
    }

    /// Contract: artifact path / kind / scope flow through verbatim
    /// from the caller — NOVA does not have its own concept of
    /// scope, so the scanner-side context is authoritative.
    #[test]
    fn artifact_metadata_flows_from_caller() {
        let r = rule("X", "medium", "tool_abuse");
        let m = match_with_keywords("X", &[("a", true)]);
        let path = Path::new("/tmp/foo/SKILL.md");
        let f = &nova_match_to_findings(
            &r,
            &m,
            Some(path),
            ArtifactKind::SkillDocument,
            ArtifactScope::SupportingArtifact,
        )[0];
        assert_eq!(f.artifact_path.as_deref(), Some("/tmp/foo/SKILL.md"));
        assert_eq!(f.artifact_scope, ArtifactScope::SupportingArtifact);
    }
}
