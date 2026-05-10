//! Run NOVA rules against a prompt body.
//!
//! The engine takes a parsed [`NovaRule`], the three section
//! evaluators, and the body to scan. It returns a [`NovaMatch`] that
//! carries the verdict + per-pattern hits + a list of capabilities
//! the rule wanted that we couldn't service. The result feeds the
//! scanner pipeline like any other finding source.

use super::condition::EvalContext;
use super::evaluators::{KeywordEvaluator, LlmEvaluator, Outcome, SemanticEvaluator};
use super::model::{NovaMatch, NovaRule, SkippedCapability};
use std::collections::BTreeMap;

/// Run one rule against `body`. Pure function — no I/O, no global
/// state — so the call site decides which evaluators to bring.
pub fn evaluate_rule<K, S, L>(
    rule: &NovaRule,
    body: &str,
    keyword_eval: &K,
    semantic_eval: &S,
    llm_eval: &L,
) -> Result<NovaMatch, super::condition::EvalError>
where
    K: KeywordEvaluator + ?Sized,
    S: SemanticEvaluator + ?Sized,
    L: LlmEvaluator + ?Sized,
{
    let mut ctx = EvalContext::default();
    let mut keyword_hits = BTreeMap::new();
    let mut semantic_hits = BTreeMap::new();
    let mut llm_hits = BTreeMap::new();
    let mut skipped: Vec<SkippedCapability> = Vec::new();

    for (var, pattern) in &rule.keywords {
        let outcome = keyword_eval.eval(var, pattern, body);
        ctx.keywords.insert(var.clone(), outcome.fired());
        keyword_hits.insert(var.clone(), outcome.fired());
    }
    for (var, pattern) in &rule.semantics {
        let outcome = semantic_eval.eval(var, pattern, body);
        if matches!(outcome, Outcome::Skipped) && !skipped.contains(&SkippedCapability::Semantics) {
            skipped.push(SkippedCapability::Semantics);
        }
        ctx.semantics.insert(var.clone(), outcome.fired());
        semantic_hits.insert(var.clone(), outcome.fired());
    }
    for (var, pattern) in &rule.llm {
        let outcome = llm_eval.eval(var, pattern, body);
        if matches!(outcome, Outcome::Skipped) && !skipped.contains(&SkippedCapability::Llm) {
            skipped.push(SkippedCapability::Llm);
        }
        ctx.llm.insert(var.clone(), outcome.fired());
        llm_hits.insert(var.clone(), outcome.fired());
    }

    let matched = rule.condition.eval(&ctx)?;

    Ok(NovaMatch {
        rule_name: rule.name.clone(),
        matched,
        keyword_hits,
        semantic_hits,
        llm_hits,
        skipped_capabilities: skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::super::evaluators::{NativeKeywordEvaluator, NotYetWiredLlm, NotYetWiredSemantic};
    use super::super::parser::parse_rules;
    use super::*;

    fn evaluate(rule_body: &str, prompt: &str) -> NovaMatch {
        let rule = parse_rules(rule_body).unwrap().pop().unwrap();
        evaluate_rule(
            &rule,
            prompt,
            &NativeKeywordEvaluator::new(),
            &NotYetWiredSemantic,
            &NotYetWiredLlm,
        )
        .unwrap()
    }

    /// Contract: a keyword-only rule fires on a matching prompt.
    /// Mirrors the canonical `InjectDynamicContext` rule from the
    /// upstream NOVA pack.
    #[test]
    fn keyword_only_rule_fires_on_match() {
        let body = r#"
            rule InjectDynamicContext {
                keywords:
                    $command_placeholder = /!\`.+?\`/
                condition:
                    keywords.$command_placeholder
            }
        "#;
        let m = evaluate(body, "Use !`whoami` to add context");
        assert!(m.matched);
        assert!(m.keyword_hits["command_placeholder"]);
        assert!(m.skipped_capabilities.is_empty());
    }

    /// Contract: when the prompt has no keyword hit, the rule does
    /// NOT fire and there are still no skipped capabilities.
    #[test]
    fn keyword_only_rule_does_not_fire_on_miss() {
        let body = r#"
            rule InjectDynamicContext {
                keywords:
                    $command_placeholder = /!\`.+?\`/
                condition:
                    keywords.$command_placeholder
            }
        "#;
        let m = evaluate(body, "Just plain prose, nothing to see");
        assert!(!m.matched);
        assert!(!m.keyword_hits["command_placeholder"]);
    }

    /// Contract: a rule whose condition *requires* a not-yet-wired
    /// section (semantics or LLM) does NOT fire AND lists the
    /// missing capability so an operator knows the rule was a
    /// no-op.
    #[test]
    fn semantics_required_rule_skips_with_capability_label() {
        let body = r#"
            rule SemReq {
                semantics:
                    $x = "phrase" (0.35)
                condition:
                    semantics.$x
            }
        "#;
        let m = evaluate(body, "anything");
        assert!(!m.matched);
        assert!(m
            .skipped_capabilities
            .contains(&SkippedCapability::Semantics));
        assert!(!m.semantic_hits["x"]);
    }

    /// Contract: a rule whose condition is `keywords.* OR semantics.*`
    /// can still fire on a keyword hit alone, even though the
    /// semantics evaluator is stubbed out. The skipped-capabilities
    /// list must still be populated so operators understand the
    /// degraded mode.
    #[test]
    fn or_with_keyword_hit_fires_despite_semantics_skip() {
        let body = r#"
            rule Mixed {
                keywords:
                    $kw = "hack"
                semantics:
                    $sem = "harmful intent" (0.35)
                condition:
                    keywords.$kw or semantics.$sem
            }
        "#;
        let m = evaluate(body, "I want to hack things");
        assert!(m.matched);
        assert!(m.keyword_hits["kw"]);
        assert!(!m.semantic_hits["sem"]);
        assert!(m
            .skipped_capabilities
            .contains(&SkippedCapability::Semantics));
    }

    /// Contract: `condition: A and B` where B is in a not-yet-wired
    /// section must NOT fire on A alone. Otherwise we'd be silently
    /// upgrading a maybe-malicious-with-LLM-corroboration rule into
    /// a "fires on keyword alone" rule.
    #[test]
    fn and_blocks_match_when_required_section_skipped() {
        let body = r#"
            rule MixedAnd {
                keywords:
                    $kw = "hack"
                semantics:
                    $sem = "harmful intent" (0.35)
                condition:
                    keywords.$kw and semantics.$sem
            }
        "#;
        let m = evaluate(body, "I want to hack things");
        assert!(!m.matched, "AND with skipped section must NOT fire");
        assert!(m
            .skipped_capabilities
            .contains(&SkippedCapability::Semantics));
    }
}
