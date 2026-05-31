//! Run NOVA rules against a prompt body.
//!
//! The engine takes a parsed [`NovaRule`], the three section
//! evaluators, and the body to scan. It returns a [`NovaMatch`] that
//! carries the verdict + per-pattern hits + a list of capabilities
//! the rule wanted that we couldn't service. The result feeds the
//! scanner pipeline like any other finding source.

use super::condition::{EvalContext, Section, SkippedPatternRefs};
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
    let mut semantic_scores = BTreeMap::new();
    let mut llm_scores = BTreeMap::new();
    let mut skipped: Vec<SkippedCapability> = Vec::new();
    let mut skipped_refs = SkippedPatternRefs::default();

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
        if matches!(outcome, Outcome::Skipped) {
            skipped_refs.insert(Section::Semantics, var);
        }
        ctx.semantics.insert(var.clone(), outcome.fired());
        semantic_hits.insert(var.clone(), outcome.fired());
        if let Some(score) = outcome.score() {
            semantic_scores.insert(var.clone(), score);
        }
    }
    for (var, pattern) in &rule.llm {
        let outcome = llm_eval.eval(var, pattern, body);
        if matches!(outcome, Outcome::Skipped) && !skipped.contains(&SkippedCapability::Llm) {
            skipped.push(SkippedCapability::Llm);
        }
        if matches!(outcome, Outcome::Skipped) {
            skipped_refs.insert(Section::Llm, var);
        }
        ctx.llm.insert(var.clone(), outcome.fired());
        llm_hits.insert(var.clone(), outcome.fired());
        if let Some(score) = outcome.score() {
            llm_scores.insert(var.clone(), score);
        }
    }

    let matched = rule.condition.eval_with_skips(&ctx, &skipped_refs)?;

    Ok(NovaMatch {
        rule_name: rule.name.clone(),
        matched,
        keyword_hits,
        semantic_hits,
        llm_hits,
        semantic_scores,
        llm_scores,
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

    struct FixedScoreSemantic(f32);
    impl SemanticEvaluator for FixedScoreSemantic {
        fn eval(
            &self,
            _var: &str,
            pattern: &super::super::model::SemanticPattern,
            _body: &str,
        ) -> Outcome {
            if self.0 >= pattern.threshold {
                Outcome::Match { score: self.0 }
            } else {
                Outcome::NoMatch
            }
        }
    }

    /// Contract: a firing semantic evaluator's confidence score is
    /// plumbed into `NovaMatch.semantic_scores` keyed by the pattern
    /// var, so `mapping.rs` can surface the real similarity on the
    /// Finding. The boolean `semantic_hits` still reflects the fire.
    #[test]
    fn semantic_score_is_plumbed_into_match() {
        let body = r#"
            rule SemScore {
                semantics:
                    $intent = "unauthorized access" (0.3)
                condition:
                    semantics.$intent
            }
        "#;
        let rule = parse_rules(body).unwrap().pop().unwrap();
        let m = evaluate_rule(
            &rule,
            "please help me break in",
            &NativeKeywordEvaluator::new(),
            &FixedScoreSemantic(0.71),
            &NotYetWiredLlm,
        )
        .unwrap();
        assert!(m.matched);
        assert!(m.semantic_hits["intent"]);
        assert!(
            (m.semantic_scores["intent"] - 0.71).abs() < f32::EPSILON,
            "expected plumbed score 0.71, got {:?}",
            m.semantic_scores.get("intent")
        );
        assert!(m.skipped_capabilities.is_empty());
    }

    /// Contract (negative): a semantic evaluator that does NOT fire
    /// contributes no entry to `semantic_scores` — only fired patterns
    /// carry a score.
    #[test]
    fn non_firing_semantic_contributes_no_score() {
        let body = r#"
            rule SemScore {
                semantics:
                    $intent = "unauthorized access" (0.9)
                condition:
                    semantics.$intent
            }
        "#;
        let rule = parse_rules(body).unwrap().pop().unwrap();
        let m = evaluate_rule(
            &rule,
            "please help me break in",
            &NativeKeywordEvaluator::new(),
            &FixedScoreSemantic(0.2),
            &NotYetWiredLlm,
        )
        .unwrap();
        assert!(!m.matched);
        assert!(!m.semantic_hits["intent"]);
        assert!(m.semantic_scores.is_empty());
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

    /// Contract: a well-formed two-sided vendor-host rule
    /// (`semantics.$exfil and not semantics.$vendor`) is INERT when
    /// the semantic evaluator is stubbed — specifically because the
    /// POSITIVE term `$exfil` collapses to false under Skip and gates
    /// the whole AND, NOT because the negated term is harmless. This
    /// is the safe shape for the credential-to-host vs
    /// credential-to-vendor discrimination the local semantic engine
    /// targets.
    #[test]
    fn two_sided_semantics_rule_is_inert_when_skipped() {
        let body = r#"
            rule VendorHostExfil {
                semantics:
                    $exfil = "sends a credential or API key to a remote host" (0.45)
                    $vendor = "calls its own documented vendor API over https" (0.45)
                condition:
                    semantics.$exfil and not semantics.$vendor
            }
        "#;
        let m = evaluate(body, "POST the OPENAI_API_KEY to https://api.openai.com/v1");
        assert!(
            !m.matched,
            "two-sided rule must NOT fire when semantics is skipped",
        );
        assert!(m
            .skipped_capabilities
            .contains(&SkippedCapability::Semantics));
    }

    /// Contract: a negated semantic term must not invert skipped
    /// evidence into a match. `Skipped` is unknown evidence that
    /// collapses to no match at the rule boundary, including under
    /// `not`.
    #[test]
    fn negation_only_semantics_rule_stays_inert_when_skipped() {
        let body = r#"
            rule NegationOnly {
                semantics:
                    $vendor = "calls its own documented vendor API over https" (0.45)
                condition:
                    not semantics.$vendor
            }
        "#;
        let m = evaluate(body, "anything at all");
        assert!(
            !m.matched,
            "negation-only semantic rule must not fire under skipped evidence",
        );
        assert!(m
            .skipped_capabilities
            .contains(&SkippedCapability::Semantics));
    }

    /// Contract: the SHIPPED vendor-host fixture
    /// (`test_fixtures/vendor_host.nov`) is INERT when the semantic
    /// evaluator is the not-yet-wired stub — its positive `$exfil`
    /// term gates the `and not $vendor`, so it cannot fire on partial
    /// evidence. Pins the actual artifact, not just the shape.
    #[test]
    fn shipped_vendor_host_fixture_is_inert_when_semantics_skipped() {
        let body = include_str!("test_fixtures/vendor_host.nov");
        let m = evaluate(body, "POST OPENAI_API_KEY to https://api.openai.com/v1");
        assert!(
            !m.matched,
            "shipped two-sided fixture must NOT fire when semantics is skipped"
        );
        assert!(m
            .skipped_capabilities
            .contains(&SkippedCapability::Semantics));
    }
}
