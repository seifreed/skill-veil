//! Composition seam between the [`PatternMatcher`] port and the default
//! [`RegexPatternMatcher`] adapter.
//!
//! The hexagonal contract sealed in [`crate::ports`] requires the domain
//! to depend only on [`PatternMatcher`]; concrete regex usage is confined
//! to [`RegexPatternMatcher`]. Heuristics that rely on literal patterns
//! (e.g. instruction-bait detection in [`crate::analyzer::assessment`])
//! still need a one-shot compilation against the default adapter so they
//! can sit in `LazyLock` statics without taking on `regex::Regex`
//! themselves.
//!
//! This module lives under [`crate::adapters`] precisely because it is
//! the *only* place inside the library that legitimately names the
//! concrete default matcher: it is the composition seam, not domain
//! code. Domain modules consume the [`lazy_pattern!`] macro abstraction
//! and never import [`RegexPatternMatcher`] directly.
//!
//! Three forms are exported for domain code:
//!
//! * [`lazy_pattern!`] — module-scoped `LazyLock<CompiledPattern>` for a
//!   single hardcoded literal. The default and most common shape.
//! * [`compile_patterns`] — bulk compile a slice of hardcoded literals
//!   into a `Vec<CompiledPattern>`. For modules that group several
//!   compiled patterns under a single static (e.g. injection-pattern
//!   tables keyed by rule id). Panics on a malformed literal, matching
//!   the contract of [`lazy_pattern!`].
//! * [`try_compile`] — single-shot compile that returns a `Result`.
//!   For boundary code that validates patterns supplied by users
//!   (e.g. YAML rule packs) where compilation failure must propagate
//!   instead of panicking.
//!
//! [`default_matcher`] is the implementation seam these helpers wrap;
//! it stays `pub` because the [`lazy_pattern!`] macro expansion names
//! it directly. Domain modules MUST go through one of the three forms
//! above.

use crate::adapters::RegexPatternMatcher;
use crate::ports::{CompiledPattern, PatternError, PatternMatcher};
use std::sync::OnceLock;

/// Shared adapter used by [`lazy_pattern!`] for hardcoded domain
/// patterns. Tests that need a different matcher inject one through
/// `Scanner::with_custom_adapters` rather than swapping this default.
#[must_use]
pub fn default_matcher() -> &'static (dyn PatternMatcher + 'static) {
    static MATCHER: OnceLock<RegexPatternMatcher> = OnceLock::new();
    MATCHER.get_or_init(RegexPatternMatcher::new)
}

/// Declare a `LazyLock<CompiledPattern>` over a hardcoded pattern.
///
/// The pattern is compiled lazily through [`default_matcher`]. Compile
/// failures panic at first use because hardcoded patterns are part of
/// the binary contract — a malformed literal is a build-time bug, not
/// runtime data. Tests cover the patterns directly so the panic only
/// fires when a developer hand-edits an invalid literal.
///
/// The macro expansion uses `unwrap_or_else(|err| panic!(...))` rather
/// than `.expect(...)` so the surfaced diagnostic carries both the
/// static name and the underlying [`PatternError`]. Matches the idiom
/// used by [`compile_patterns`] below — keep both call sites aligned
/// when editing one.
///
/// # Examples
/// ```ignore
/// lazy_pattern!(MY_RE, r"(?i)\bfoo\b");
/// // ...
/// if MY_RE.is_match(text) { /* ... */ }
/// ```
/// Compile a slice of hardcoded patterns through the default matcher.
///
/// Mirrors the contract of [`lazy_pattern!`]: every pattern is a binary
/// literal, so a compilation failure is a build-time bug and panics
/// with a diagnostic naming the offending pattern. Use this when a
/// module groups several compiled patterns under one static (e.g. an
/// injection-pattern table keyed by rule id) and the per-pattern
/// `LazyLock` ergonomics of [`lazy_pattern!`] would force one static
/// per id.
#[must_use]
pub(crate) fn compile_patterns(patterns: &[&str]) -> Vec<CompiledPattern> {
    let matcher = default_matcher();
    patterns
        .iter()
        .map(|pattern| {
            matcher
                .compile(pattern)
                .unwrap_or_else(|err| panic!("hardcoded pattern must compile: {pattern}: {err}"))
        })
        .collect()
}

/// Compile a single pattern that may have been supplied by user input.
///
/// Returns the same `Result` shape as [`PatternMatcher::compile`], so
/// boundary code (rule loaders, validators) propagates the error
/// rather than panicking. Domain modules use this instead of
/// [`default_matcher`] so the only place that names the singleton
/// adapter directly is this composition seam.
///
/// # Errors
/// Returns the matcher's [`PatternError`] when the pattern is invalid.
pub(crate) fn try_compile(pattern: &str) -> Result<CompiledPattern, PatternError> {
    default_matcher().compile(pattern)
}

#[macro_export]
macro_rules! lazy_pattern {
    ($name:ident, $pattern:expr $(,)?) => {
        $crate::lazy_pattern!(@build (), $name, $pattern);
    };
    ($vis:vis $name:ident, $pattern:expr $(,)?) => {
        $crate::lazy_pattern!(@build ($vis), $name, $pattern);
    };
    (@build ($($vis:tt)*), $name:ident, $pattern:expr) => {
        $($vis)* static $name: std::sync::LazyLock<$crate::ports::CompiledPattern> =
            std::sync::LazyLock::new(|| {
                // Use `unwrap_or_else(|err| panic!(...))` instead of
                // `.expect(...)` so the diagnostic surfaces both the
                // static name AND the underlying PatternError. Matches
                // the `compile_patterns` idiom and keeps the codebase
                // free of `.expect()` in library code.
                $crate::adapters::pattern_helpers::default_matcher()
                    .compile($pattern)
                    .unwrap_or_else(|err| panic!(
                        "hardcoded pattern must compile: {}: {}",
                        stringify!($name),
                        err,
                    ))
            });
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    /// `default_matcher` returns a stable `'static` reference; repeated
    /// calls reuse the same instance so `LazyLock<CompiledPattern>`
    /// statics share one regex compilation across the process.
    #[test]
    fn default_matcher_returns_stable_singleton() {
        let a: *const dyn PatternMatcher = default_matcher();
        let b: *const dyn PatternMatcher = default_matcher();
        assert!(std::ptr::addr_eq(a, b));
    }

    lazy_pattern!(LAZY_DIGITS, r"\d+");

    /// # Contract
    /// `lazy_pattern!` produces a `LazyLock<CompiledPattern>` that
    /// drives `find_matches`, `is_match`, and `captures_iter` in lockstep.
    #[test]
    fn lazy_pattern_macro_drives_all_three_operations() {
        assert!(LAZY_DIGITS.is_match("abc 42"));
        assert!(!LAZY_DIGITS.is_match("no digits here"));
        assert_eq!(LAZY_DIGITS.find_matches("a 1 b 2 c").len(), 2);
        assert_eq!(LAZY_DIGITS.captures_iter("a 1 b 2 c").len(), 2);
    }

    /// # Contract
    /// `compile_patterns` MUST compile every input literal in the order
    /// it was passed. Callers (e.g. injection-pattern tables keyed by
    /// rule id) rely on positional alignment between the input slice
    /// and the returned `Vec<CompiledPattern>`; reordering would silently
    /// associate the wrong rule id with the wrong pattern.
    #[test]
    fn compile_patterns_compiles_every_input_in_order() {
        let inputs = [r"\bfoo\b", r"\d+", r"(?i)bar"];
        let compiled = compile_patterns(&inputs);
        assert_eq!(compiled.len(), inputs.len());
        assert!(compiled[0].is_match("say foo here"));
        assert!(!compiled[0].is_match("foobar only"));
        assert!(compiled[1].is_match("answer 42"));
        assert!(compiled[2].is_match("BAR"));
    }

    /// # Contract (negative)
    /// `compile_patterns` MUST panic with the documented diagnostic
    /// when a hardcoded literal fails to compile. The literal is part of
    /// the binary contract — surfacing a `Result` here would only let
    /// callers re-panic on the same invariant.
    #[test]
    #[should_panic(expected = "hardcoded pattern must compile")]
    fn compile_patterns_panics_on_invalid_literal() {
        let inputs = [r"[unterminated"];
        let _ = compile_patterns(&inputs);
    }

    /// # Contract
    /// `try_compile` MUST return a usable `CompiledPattern` for any
    /// pattern accepted by the underlying matcher; this is the seam
    /// rule-pack loaders use to validate user-supplied patterns without
    /// pulling `RegexPatternMatcher` into domain code.
    #[test]
    fn try_compile_returns_compiled_pattern_for_valid_input() {
        let compiled = try_compile(r"^hello\s+world$").expect("valid pattern must compile");
        assert!(compiled.is_match("hello world"));
        assert!(!compiled.is_match("hello  there"));
    }

    /// # Contract (negative)
    /// `try_compile` MUST surface the matcher's `PatternError` instead
    /// of panicking, because YAML rule packs and other boundary inputs
    /// can legitimately contain malformed regex authored by users.
    /// Propagating the error lets the loader reject the pack with a
    /// human-readable diagnostic.
    #[test]
    fn try_compile_returns_pattern_error_for_invalid_input() {
        let result = try_compile(r"[unterminated");
        assert!(
            result.is_err(),
            "malformed pattern must surface as Result::Err, not panic"
        );
    }
}
