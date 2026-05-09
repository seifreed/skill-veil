//! NOVA (Prompt Pattern Matching) integration.
//!
//! NOVA is a separate rule ecosystem published at
//! <https://github.com/Nova-Hunting/nova-rules> by Thomas Roccia
//! (@fr0gger_). The rule format targets prompt content with three
//! orthogonal matching modes: regex keywords, semantic similarity
//! (sentence embeddings), and LLM judgement.
//!
//! skill-veil consumes NOVA rules as an additional channel alongside
//! its own. The integration owns:
//!
//! - [`parser`] — parses `.nov` files into [`NovaRule`].
//! - [`condition`] — boolean / quantifier AST + evaluator.
//! - [`evaluators`] — per-section trait + bundled implementations
//!   (native keywords + stubs for semantics / LLM until the heavier
//!   runtimes land).
//! - [`engine`] — runs one rule against one prompt body.
//! - [`model`] — domain types ([`NovaRule`], [`NovaMatch`], …).

pub mod condition;
pub mod engine;
pub mod evaluators;
pub mod model;
pub mod parser;

pub use condition::{ConditionExpr, EvalContext, EvalError, Quantifier, QuantifierTarget, Section};
pub use engine::evaluate_rule;
pub use evaluators::{
    KeywordEvaluator, LlmEvaluator, NativeKeywordEvaluator, NotYetWiredLlm, NotYetWiredSemantic,
    Outcome, SemanticEvaluator,
};
pub use model::{
    KeywordPattern, LlmPattern, NovaMatch, NovaRule, SemanticPattern, SkippedCapability,
};
pub use parser::{parse_rules, ParseError};
