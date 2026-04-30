//! Domain-facing facade over the pattern composition helpers.
//!
//! Domain modules (analyzer, detectors, deceptive_docs, …) need a
//! `LazyLock<CompiledPattern>` for hardcoded literals and a
//! `try_compile` shim for boundary code that validates user-supplied
//! patterns. The implementation lives in [`crate::adapters::pattern_helpers`]
//! because it is the composition seam that names the concrete default
//! [`crate::adapters::RegexPatternMatcher`]; that location is documented
//! and load-bearing for the [`lazy_pattern!`] macro expansion.
//!
//! This module re-exports the helpers under a neutral path so domain
//! code never writes `use crate::adapters::pattern_helpers::…`. Reaching
//! into the `adapters::` namespace from domain code is the C-1 violation
//! flagged in the clean-architecture audit; routing through this module
//! eliminates that import shape without relocating the singleton.
//!
//! Use [`crate::lazy_pattern!`] for module-scoped hardcoded literals,
//! [`compile_patterns`] for bulk compilation of literal slices, and
//! [`try_compile`] for boundary code that must propagate compile errors.

pub(crate) use crate::adapters::pattern_helpers::{compile_patterns, try_compile};
