//! NOVA condition expression — AST + evaluator.
//!
//! The `condition:` section of a NOVA rule is a small boolean DSL
//! that combines per-pattern hits across the three pattern sections.
//!
//! Grammar (informal):
//!
//! ```text
//! cond     := or_expr
//! or_expr  := and_expr ("or" and_expr)*
//! and_expr := not_expr ("and" not_expr)*
//! not_expr := "not" not_expr | atom
//! atom     := quantifier | reference | "(" cond ")" | "true" | "false"
//! quantifier := ("any" | "all" | INTEGER) "of" target
//! target   := "(" cond ")" | wildcard | reference | "(" wildcard "," ... ")"
//! wildcard := SECTION "." "*"
//! reference := SECTION "." "$" IDENT
//! SECTION  := "keywords" | "semantics" | "llm"
//! ```
//!
//! In practice the NOVA samples we have to support reduce to:
//! `keywords.*`, `semantics.*`, `llm.*`, `keywords.$var`,
//! `semantics.$var`, `llm.$var`, `any of keywords.*`,
//! `any of semantics.*`, `any of llm.*`, plus boolean combinations
//! and parentheses. The parser intentionally accepts more than the
//! NOVA samples currently use (the published Python parser is
//! similarly liberal) so we don't reject a future rule that adds
//! `2 of keywords.*` or `all of semantics.$prefix*`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use thiserror::Error;

/// Section namespaces a reference / wildcard / quantifier-target can
/// belong to. Mirrors the three pattern dictionaries on `NovaRule`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    Keywords,
    Semantics,
    Llm,
}

impl Section {
    pub(crate) fn from_str(s: &str) -> Option<Self> {
        match s {
            "keywords" => Some(Self::Keywords),
            "semantics" => Some(Self::Semantics),
            "llm" => Some(Self::Llm),
            _ => None,
        }
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Keywords => "keywords",
            Self::Semantics => "semantics",
            Self::Llm => "llm",
        };
        f.write_str(s)
    }
}

/// Quantifier head over a wildcard or grouped target.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Quantifier {
    /// `any of …` — at least one pattern must match.
    Any,
    /// `all of …` — every pattern in the target group must match.
    All,
    /// `<N> of …` — at least `N` patterns must match. The Python
    /// parser supports this; current published rules don't use it
    /// but accepting it future-proofs us.
    AtLeast(u32),
}

/// Boolean / quantifier expression over per-section pattern hits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConditionExpr {
    /// Constant — only used by builders/tests.
    Literal(bool),
    /// Reference to a single named pattern, e.g. `keywords.$ipregex`.
    Reference {
        section: Section,
        var: String,
    },
    /// Wildcard over every pattern in a section, e.g. `keywords.*`.
    /// Equivalent to `any of <section>.*` per the NOVA semantics:
    /// when the wildcard appears bare (without an explicit
    /// quantifier) it means "at least one matched".
    Wildcard {
        section: Section,
    },
    /// Variable-prefix wildcard, e.g. `semantics.$injection*` matches
    /// every semantic pattern whose name starts with `injection`.
    /// Real-world NOVA rules in the canonical pack use this to group
    /// related patterns without enumerating each var (`ttps.nov`).
    PrefixWildcard {
        section: Section,
        prefix: String,
    },
    /// `any|all|N of <target>` where the target is a wildcard or
    /// (NOVA-rare) a parenthesised subexpression.
    Quantified {
        quantifier: Quantifier,
        target: Box<QuantifierTarget>,
    },
    Not(Box<ConditionExpr>),
    And(Vec<ConditionExpr>),
    Or(Vec<ConditionExpr>),
}

/// Targets a quantifier can sit over. We split this into its own enum
/// rather than reusing `ConditionExpr` because the legal grammar of a
/// quantifier target is narrower (`any of A and B` is illegal NOVA).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QuantifierTarget {
    /// `<section>.*` — every pattern in the section.
    SectionWildcard(Section),
    /// `(<expr>)` — a parenthesised inner expression. Used for
    /// patterns like `any of (keywords.$a, keywords.$b)` though the
    /// canonical NOVA parser treats commas as alternative spelling
    /// of `or`. We normalise both into a single `Or` node.
    Inner(Box<ConditionExpr>),
}

#[derive(Debug, Error, PartialEq)]
pub enum EvalError {
    #[error("condition references unknown variable `{section}.${var}`")]
    UnknownReference { section: Section, var: String },
}

/// Per-rule resolved facts the evaluator needs: did each named
/// pattern in each section match? Missing variables in the input
/// surface as `EvalError::UnknownReference` rather than silently
/// being treated as `false`, so a typo in a rule's condition fails
/// loudly at evaluation time.
#[derive(Debug, Default, Clone)]
pub struct EvalContext {
    pub keywords: BTreeMap<String, bool>,
    pub semantics: BTreeMap<String, bool>,
    pub llm: BTreeMap<String, bool>,
}

impl EvalContext {
    fn section(&self, section: Section) -> &BTreeMap<String, bool> {
        match section {
            Section::Keywords => &self.keywords,
            Section::Semantics => &self.semantics,
            Section::Llm => &self.llm,
        }
    }
}

impl ConditionExpr {
    /// Evaluate this expression against the resolved per-pattern hits.
    pub fn eval(&self, ctx: &EvalContext) -> Result<bool, EvalError> {
        match self {
            Self::Literal(b) => Ok(*b),
            Self::Reference { section, var } => match ctx.section(*section).get(var) {
                Some(b) => Ok(*b),
                None => Err(EvalError::UnknownReference {
                    section: *section,
                    var: var.clone(),
                }),
            },
            Self::Wildcard { section } => {
                let map = ctx.section(*section);
                Ok(map.values().any(|b| *b))
            }
            Self::PrefixWildcard { section, prefix } => {
                let map = ctx.section(*section);
                Ok(map
                    .iter()
                    .any(|(name, hit)| *hit && name.starts_with(prefix)))
            }
            Self::Not(inner) => Ok(!inner.eval(ctx)?),
            Self::And(items) => {
                for item in items {
                    if !item.eval(ctx)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Self::Or(items) => {
                for item in items {
                    if item.eval(ctx)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            Self::Quantified { quantifier, target } => {
                let hits = collect_target_hits(target, ctx)?;
                let count = hits.iter().filter(|b| **b).count() as u32;
                Ok(match quantifier {
                    Quantifier::Any => count >= 1,
                    Quantifier::All => !hits.is_empty() && count == hits.len() as u32,
                    Quantifier::AtLeast(n) => count >= *n,
                })
            }
        }
    }
}

fn collect_target_hits(
    target: &QuantifierTarget,
    ctx: &EvalContext,
) -> Result<Vec<bool>, EvalError> {
    match target {
        QuantifierTarget::SectionWildcard(section) => {
            Ok(ctx.section(*section).values().copied().collect())
        }
        QuantifierTarget::Inner(expr) => match expr.as_ref() {
            // The NOVA Python parser flattens commas inside
            // `any of (...)` into an Or node; we follow the same
            // convention. Each Or child contributes one boolean.
            ConditionExpr::Or(items) => items.iter().map(|i| i.eval(ctx)).collect(),
            other => Ok(vec![other.eval(ctx)?]),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(
        keywords: &[(&str, bool)],
        semantics: &[(&str, bool)],
        llm: &[(&str, bool)],
    ) -> EvalContext {
        let to_map = |entries: &[(&str, bool)]| {
            entries
                .iter()
                .map(|(k, v)| ((*k).to_string(), *v))
                .collect::<BTreeMap<_, _>>()
        };
        EvalContext {
            keywords: to_map(keywords),
            semantics: to_map(semantics),
            llm: to_map(llm),
        }
    }

    /// Contract: `keywords.*` is true iff at least one keyword
    /// matched. Mirrors NOVA's "wildcard means any" semantics.
    #[test]
    fn wildcard_keywords_any_match_is_true() {
        let c = ConditionExpr::Wildcard {
            section: Section::Keywords,
        };
        assert!(c
            .eval(&ctx(&[("a", false), ("b", true)], &[], &[]))
            .unwrap());
        assert!(!c
            .eval(&ctx(&[("a", false), ("b", false)], &[], &[]))
            .unwrap());
        // Empty section means "no patterns of this kind", so wildcard
        // resolves to false rather than vacuously true.
        assert!(!c.eval(&ctx(&[], &[], &[])).unwrap());
    }

    /// Contract: `any of keywords.*` matches "keywords.*" exactly.
    /// They are distinct AST shapes but produce identical results.
    #[test]
    fn any_of_wildcard_equivalent_to_bare_wildcard() {
        let bare = ConditionExpr::Wildcard {
            section: Section::Keywords,
        };
        let any_of = ConditionExpr::Quantified {
            quantifier: Quantifier::Any,
            target: Box::new(QuantifierTarget::SectionWildcard(Section::Keywords)),
        };
        for fixture in [
            ctx(&[("a", true)], &[], &[]),
            ctx(&[("a", false)], &[], &[]),
            ctx(&[("a", false), ("b", true)], &[], &[]),
        ] {
            assert_eq!(bare.eval(&fixture), any_of.eval(&fixture));
        }
    }

    /// Contract: `all of <section>.*` is true iff EVERY pattern in
    /// the section matched, AND there is at least one. An empty
    /// section is `false` to avoid vacuously satisfying a rule that
    /// genuinely needs evidence.
    #[test]
    fn all_of_section_requires_every_hit_and_nonempty() {
        let all = ConditionExpr::Quantified {
            quantifier: Quantifier::All,
            target: Box::new(QuantifierTarget::SectionWildcard(Section::Semantics)),
        };
        assert!(all
            .eval(&ctx(&[], &[("a", true), ("b", true)], &[]))
            .unwrap());
        assert!(!all
            .eval(&ctx(&[], &[("a", true), ("b", false)], &[]))
            .unwrap());
        assert!(!all.eval(&ctx(&[], &[], &[])).unwrap());
    }

    /// Contract: `2 of llm.*` requires exactly N=2 or more matches.
    /// Pinned because the Python parser supports integer quantifiers
    /// even though current rules don't use them.
    #[test]
    fn at_least_n_quantifier_counts_matches() {
        let two = ConditionExpr::Quantified {
            quantifier: Quantifier::AtLeast(2),
            target: Box::new(QuantifierTarget::SectionWildcard(Section::Llm)),
        };
        assert!(two
            .eval(&ctx(&[], &[], &[("a", true), ("b", true), ("c", false)]))
            .unwrap());
        assert!(!two
            .eval(&ctx(&[], &[], &[("a", true), ("b", false)]))
            .unwrap());
    }

    /// Contract: a typo in a rule like `keywords.$nonexistent` does
    /// NOT silently evaluate to `false`. Operators must see the
    /// reference error so they can fix the rule rather than ship a
    /// rule that never fires.
    #[test]
    fn unknown_reference_returns_named_error() {
        let r = ConditionExpr::Reference {
            section: Section::Keywords,
            var: "missing_var".into(),
        };
        let err = r
            .eval(&ctx(&[("present", true)], &[], &[]))
            .expect_err("typo must fail loudly");
        assert_eq!(
            err,
            EvalError::UnknownReference {
                section: Section::Keywords,
                var: "missing_var".into()
            }
        );
    }

    /// Contract: `not` flips the inner result; precedence with `and`
    /// matches NOVA (`not A and B` parses as `(not A) and B`). The
    /// parser enforces precedence; this test pins that the eval
    /// engine itself doesn't accidentally short-circuit wrong.
    #[test]
    fn boolean_combinators_short_circuit_correctly() {
        let kw_a = ConditionExpr::Reference {
            section: Section::Keywords,
            var: "a".into(),
        };
        let kw_b = ConditionExpr::Reference {
            section: Section::Keywords,
            var: "b".into(),
        };

        // (not a) and b
        let expr = ConditionExpr::And(vec![
            ConditionExpr::Not(Box::new(kw_a.clone())),
            kw_b.clone(),
        ]);
        assert!(expr
            .eval(&ctx(&[("a", false), ("b", true)], &[], &[]))
            .unwrap());
        assert!(!expr
            .eval(&ctx(&[("a", true), ("b", true)], &[], &[]))
            .unwrap());
        assert!(!expr
            .eval(&ctx(&[("a", false), ("b", false)], &[], &[]))
            .unwrap());

        // a or b
        let or_expr = ConditionExpr::Or(vec![kw_a, kw_b]);
        assert!(or_expr
            .eval(&ctx(&[("a", false), ("b", true)], &[], &[]))
            .unwrap());
        assert!(!or_expr
            .eval(&ctx(&[("a", false), ("b", false)], &[], &[]))
            .unwrap());
    }
}
