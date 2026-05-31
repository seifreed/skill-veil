//! Domain types for NOVA (Prompt Pattern Matching) rules.
//!
//! NOVA rules live in a separate ecosystem than skill-veil rules:
//! they target prompt content (jailbreaks, injection attempts, scam
//! generation, …) using three orthogonal matching modes — regex
//! keywords, semantic similarity over sentence embeddings, and LLM
//! judgement. skill-veil consumes the rule pack from
//! <https://github.com/Nova-Hunting/nova-rules> at install time and
//! evaluates them as an independent rule channel alongside its own.
//!
//! This module owns the parsed rule shape only; the parser lives in
//! `parser.rs`, the condition AST + evaluation in `condition.rs`, and
//! the per-section evaluators in `evaluators.rs`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A fully parsed NOVA rule. The three pattern maps are populated
/// according to which sections appeared in the source `.nov` file;
/// missing sections produce empty maps (not `None`) so condition
/// evaluation can treat absence as "no patterns of this kind ever
/// match" without a special case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NovaRule {
    pub name: String,
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
    #[serde(default)]
    pub keywords: BTreeMap<String, KeywordPattern>,
    #[serde(default)]
    pub semantics: BTreeMap<String, SemanticPattern>,
    #[serde(default)]
    pub llm: BTreeMap<String, LlmPattern>,
    pub condition: super::condition::ConditionExpr,
}

impl NovaRule {
    /// Convenience accessor for the `severity` meta key. NOVA rules
    /// commonly declare it but it is not part of the parser-level
    /// contract, so we do best-effort string lookup.
    #[must_use]
    pub fn severity_label(&self) -> Option<&str> {
        self.meta.get("severity").map(String::as_str)
    }

    /// Convenience accessor for the `category` meta key. The NOVA
    /// catalogue uses slash-separated paths like
    /// `prompt_manipulation/jailbreak`.
    #[must_use]
    pub fn category_label(&self) -> Option<&str> {
        self.meta.get("category").map(String::as_str)
    }
}

/// A single entry under `keywords:`. Accepts both literal substrings
/// (case-insensitive by default) and slash-delimited regular
/// expressions (`/pattern/` or `/pattern/i`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeywordPattern {
    pub pattern: String,
    pub is_regex: bool,
    pub case_sensitive: bool,
}

/// A single entry under `semantics:`. The threshold is the cosine
/// similarity floor at which the pattern is considered to match the
/// embedded prompt; the NOVA defaults vary per rule (typical: 0.1
/// broad, 0.35 balanced, 0.9 strict).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SemanticPattern {
    pub pattern: String,
    pub threshold: f32,
}

/// A single entry under `llm:`. The pattern is a natural-language
/// instruction the upstream LLM evaluates against the prompt; the
/// threshold is the LLM-confidence floor at which the pattern is
/// considered to match.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LlmPattern {
    pub pattern: String,
    pub threshold: f32,
}

/// The verdict for one rule against one prompt body. Carries the per-
/// section booleans the condition would have evaluated against, so
/// callers can render which patterns fired (matches NOVA's
/// `--verbose` output).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NovaMatch {
    pub rule_name: String,
    pub matched: bool,
    pub keyword_hits: BTreeMap<String, bool>,
    pub semantic_hits: BTreeMap<String, bool>,
    pub llm_hits: BTreeMap<String, bool>,
    /// Confidence score for each firing `semantics:` pattern (cosine
    /// similarity, `[0.0, 1.0]`). Only fired patterns are present, so a
    /// `var` in `semantic_hits` with value `true` has a corresponding
    /// entry here. Carried alongside the boolean so `mapping.rs` can
    /// surface the real similarity on the Finding instead of falling
    /// back to the rule's declared threshold.
    #[serde(default)]
    pub semantic_scores: BTreeMap<String, f32>,
    /// Confidence score for each firing `llm:` pattern (model
    /// confidence, `[0.0, 1.0]`). Same population contract as
    /// [`Self::semantic_scores`].
    #[serde(default)]
    pub llm_scores: BTreeMap<String, f32>,
    /// Patterns the rule references in its `condition` that we cannot
    /// evaluate yet (e.g. semantic / LLM matches when no evaluator is
    /// wired up). The rule still loads, the condition is still
    /// evaluated treating those references as `false`, and this list
    /// surfaces so operators understand WHY a rule did not fire.
    pub skipped_capabilities: Vec<SkippedCapability>,
}

/// Sections of NOVA matching that require capabilities skill-veil may
/// not have wired up yet. Rendered to operators with the
/// `nova-runtime` namespace so they understand which subsystem to
/// enable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkippedCapability {
    /// The `semantics:` section requires sentence-embedding inference.
    /// The CLI ships an `all-MiniLM-L6-v2` evaluator behind
    /// `--features nova-semantics`; without that build feature, or
    /// when the runtime model fails to load, semantic patterns
    /// surface here.
    Semantics,
    /// The `llm:` section requires routing to a configured LLM
    /// provider. The CLI wires NOVA `llm:` patterns into the
    /// existing `~/.skill-veil.toml [llm]` provider chain when the
    /// `--nova-llm` flag is passed; without that flag, or when the
    /// provider call fails, llm patterns surface here.
    Llm,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: `severity_label`/`category_label` return what the
    /// rule put in `meta`, never `Some("")` for missing keys. NOVA
    /// rules commonly omit severity for very-broad rules and we
    /// must let callers distinguish "absent" from "empty string".
    #[test]
    fn meta_accessors_return_none_for_missing_keys() {
        let rule = NovaRule {
            name: "t".into(),
            meta: BTreeMap::new(),
            keywords: BTreeMap::new(),
            semantics: BTreeMap::new(),
            llm: BTreeMap::new(),
            condition: super::super::condition::ConditionExpr::Literal(true),
        };
        assert!(rule.severity_label().is_none());
        assert!(rule.category_label().is_none());
    }

    #[test]
    fn meta_accessors_round_trip_present_keys() {
        let mut meta = BTreeMap::new();
        meta.insert("severity".into(), "high".into());
        meta.insert("category".into(), "prompt_manipulation/jailbreak".into());
        let rule = NovaRule {
            name: "t".into(),
            meta,
            keywords: BTreeMap::new(),
            semantics: BTreeMap::new(),
            llm: BTreeMap::new(),
            condition: super::super::condition::ConditionExpr::Literal(true),
        };
        assert_eq!(rule.severity_label(), Some("high"));
        assert_eq!(rule.category_label(), Some("prompt_manipulation/jailbreak"));
    }
}
