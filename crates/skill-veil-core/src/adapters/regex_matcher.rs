//! Pattern matcher implementation using the regex crate

use crate::ports::{Captures, CompiledPattern, PatternError, PatternMatch, PatternMatcher};
use regex::{Regex, RegexBuilder};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Hard upper bound on the compiled NFA size for a single regex pattern,
/// in bytes. Mitigates ReDoS / state-explosion from user-supplied
/// rule-pack patterns by bounding the work the regex crate will accept
/// at compile time. The default in the `regex` crate is 10 MiB; we
/// tighten to 8 MiB so genuinely-complex curated IOC patterns
/// (`URL_PATTERN`, multi-MB IOC alternations) still compile while
/// catastrophic patterns (`a{1000000}{2}`) are rejected.
const REGEX_NFA_SIZE_LIMIT: usize = 8 * (1 << 20); // 8 MiB

/// Hard upper bound on the lazy DFA cache for a single compiled regex.
/// Bounds runtime memory growth on adversarial inputs in addition to
/// `REGEX_NFA_SIZE_LIMIT`, which only bounds compile-time NFA size.
const REGEX_DFA_SIZE_LIMIT: usize = 8 * (1 << 20); // 8 MiB

/// Compile `pattern` with the size-bounded `RegexBuilder`. Centralising
/// the construction in one helper means every code path — the cached
/// trait-method calls and the `compile()` port — applies the same
/// limits without forgetting one.
fn build_bounded_regex(pattern: &str) -> Result<Regex, regex::Error> {
    RegexBuilder::new(pattern)
        .size_limit(REGEX_NFA_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
        .build()
}

/// Pattern matcher implementation using the regex crate.
///
/// # Compile-cache contract
///
/// Each unique `pattern: &str` argument MUST be compiled at most once
/// per `RegexPatternMatcher` instance. Pre-fix the trait methods
/// (`find_matches`, `is_match`, `captures_iter`) called `Regex::new`
/// on every invocation, which on the rule-engine hot path recompiles
/// the same regex hundreds of times per scan and, with adversarial
/// rule packs, scales to a viable denial-of-service. The internal
/// `cache` is a `Mutex<HashMap>` so concurrent scanners observe a
/// single compiled `Arc<Regex>` per pattern; contention is minimal
/// because the cache is consulted on the (rare) cold path only.
#[derive(Debug, Default, Clone)]
pub struct RegexPatternMatcher {
    cache: Arc<Mutex<HashMap<String, Arc<Regex>>>>,
}

impl RegexPatternMatcher {
    /// Create a new regex-based pattern matcher
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up `pattern` in the compile cache, compiling it on miss.
    /// Returns `None` (and emits `tracing::warn`) when the pattern is
    /// invalid OR exceeds [`REGEX_NFA_SIZE_LIMIT`] /
    /// [`REGEX_DFA_SIZE_LIMIT`]; the trait methods then fall back to
    /// returning empty results to keep the rest of the rule pass alive.
    fn cached(&self, pattern: &str) -> Option<Arc<Regex>> {
        // Recover from poison: a panicked thread holding the lock should
        // not permanently degrade the cache from O(1) lookup to O(n)
        // recompilation per call. The data inside is still valid —
        // poison only signals that a thread panicked *while* holding
        // the lock, not that the HashMap is corrupt.
        //
        // NOTE: We deliberately use `into_inner()` without clearing the
        // poison flag. Rust's `Mutex` does not expose `clear_poison()`
        // on the guard, and `std::sync::RecoverableError` is unstable.
        // After recovery, subsequent lock acquisitions will also recover
        // via `into_inner()`, which is correct but takes the slow path.
        // A true poison-clear would require `parking_lot::Mutex` or the
        // unstable `std::sync::RecoverableError` API.
        let recover_poison = |e: std::sync::PoisonError<_>| e.into_inner();
        // Quick read path: most requests hit an already-compiled entry.
        if let Some(re) = self
            .cache
            .lock()
            .unwrap_or_else(recover_poison)
            .get(pattern)
        {
            return Some(Arc::clone(re));
        }
        // Cold path: compile through the bounded builder, then insert
        // into the cache so subsequent calls hit the warm path. We
        // re-acquire the lock here rather than holding it across the
        // potentially-expensive compile so a stuck compile cannot
        // serialise the entire matcher.
        let re = match build_bounded_regex(pattern) {
            Ok(re) => Arc::new(re),
            Err(e) => {
                tracing::warn!("Invalid or oversized regex pattern '{pattern}': {e}");
                return None;
            }
        };
        // If a concurrent compile inserted between our read and write,
        // the existing entry wins — both compiles produce semantically
        // identical `Regex` values, but reusing the existing Arc keeps
        // reference counts predictable.
        Some(Arc::clone(
            self.cache
                .lock()
                .unwrap_or_else(recover_poison)
                .entry(pattern.to_string())
                .or_insert_with(|| Arc::clone(&re)),
        ))
    }
}

fn match_to_pattern(m: regex::Match<'_>) -> PatternMatch {
    PatternMatch {
        start: m.start(),
        end: m.end(),
        matched_text: m.as_str().to_string(),
    }
}

fn captures_to_groups(caps: &regex::Captures<'_>) -> Captures {
    let groups = caps
        .iter()
        .map(|opt| opt.map(match_to_pattern))
        .collect::<Vec<_>>();
    Captures::new(groups)
}

impl PatternMatcher for RegexPatternMatcher {
    fn find_matches(&self, pattern: &str, text: &str) -> Vec<PatternMatch> {
        match self.cached(pattern) {
            Some(re) => re.find_iter(text).map(match_to_pattern).collect(),
            None => Vec::new(),
        }
    }

    fn is_match(&self, pattern: &str, text: &str) -> bool {
        match self.cached(pattern) {
            Some(re) => re.is_match(text),
            None => false,
        }
    }

    fn captures_iter(&self, pattern: &str, text: &str) -> Vec<Captures> {
        match self.cached(pattern) {
            Some(re) => re
                .captures_iter(text)
                .map(|c| captures_to_groups(&c))
                .collect(),
            None => Vec::new(),
        }
    }

    fn compile(&self, pattern: &str) -> Result<CompiledPattern, PatternError> {
        let re = Arc::new(
            build_bounded_regex(pattern)
                .map_err(|e| PatternError::InvalidPattern(e.to_string()))?,
        );
        let re_find = Arc::clone(&re);
        let re_is_match = Arc::clone(&re);
        let re_captures = re;

        Ok(CompiledPattern::new(
            Box::new(move |text: &str| re_find.find_iter(text).map(match_to_pattern).collect()),
            Box::new(move |text: &str| re_is_match.is_match(text)),
            Box::new(move |text: &str| {
                re_captures
                    .captures_iter(text)
                    .map(|c| captures_to_groups(&c))
                    .collect()
            }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    /// `find_matches` returns every regex hit in source order with byte
    /// offsets and the matched substring preserved verbatim.
    #[test]
    fn find_matches_returns_every_hit_in_source_order() {
        let matcher = RegexPatternMatcher::new();
        let matches = matcher.find_matches(r"\d+", "abc 123 def 456");

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].matched_text, "123");
        assert_eq!(matches[1].matched_text, "456");
    }

    /// # Contract
    /// `find_matches` returns an empty vector when the pattern does not
    /// occur in the text — never a sentinel match.
    #[test]
    fn find_matches_returns_empty_when_pattern_absent() {
        let matcher = RegexPatternMatcher::new();
        let matches = matcher.find_matches(r"\d+", "no numbers here");

        assert!(matches.is_empty());
    }

    /// # Contract
    /// A `CompiledPattern` reuses one compilation across `find_matches`,
    /// `is_match`, and `captures_iter`; all three answer consistently.
    #[test]
    fn compile_shares_state_across_three_operations() {
        let matcher = RegexPatternMatcher::new();
        let compiled = matcher.compile(r"hello\s+world").unwrap();

        let matches = compiled.find_matches("say hello   world!");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_text, "hello   world");

        assert!(compiled.is_match("say hello   world!"));
        assert!(!compiled.is_match("say goodbye"));

        let caps = compiled.captures_iter("say hello   world!");
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].get(0).unwrap().matched_text, "hello   world");
    }

    /// # Contract
    /// `compile` surfaces invalid regex syntax as `PatternError`; it must
    /// never panic so tests can drive validation via `is_err()`.
    #[test]
    fn compile_returns_err_for_invalid_regex_syntax() {
        let matcher = RegexPatternMatcher::new();
        let result = matcher.compile(r"[invalid");

        assert!(result.is_err());
    }

    /// # Contract
    ///
    /// Repeated calls to a trait method with the same `pattern` MUST
    /// reuse the same compiled `Regex` — no re-compilation per call.
    /// Pre-fix `find_matches` / `is_match` / `captures_iter` invoked
    /// `Regex::new` on every call, scaling to O(rules × calls × scans)
    /// regex compilations and producing a viable DoS surface for
    /// malicious rule packs. The cache stores compiled `Arc<Regex>`
    /// keyed by the pattern string; this test pins the contract by
    /// observing that the cache size grows by exactly one entry no
    /// matter how many times the same pattern is matched.
    #[test]
    fn repeated_calls_with_same_pattern_use_cached_regex() {
        let matcher = RegexPatternMatcher::new();
        let pattern = r"\b(curl|wget)\b\s+https?://";
        for _ in 0..16 {
            matcher.find_matches(pattern, "run curl https://example.com/install.sh");
            matcher.is_match(pattern, "fetch wget https://example.com/x");
            matcher.captures_iter(pattern, "exec curl https://attacker/x");
        }
        let cache = matcher.cache.lock().expect("cache mutex poisoned");
        assert_eq!(
            cache.len(),
            1,
            "trait methods must reuse one cached compile per pattern; got {} entries",
            cache.len()
        );
        assert!(cache.contains_key(pattern));
    }

    /// # Contract
    ///
    /// Different patterns produce distinct cache entries. Pins that the
    /// cache key is the pattern string, not the matcher instance.
    #[test]
    fn cache_keys_each_unique_pattern_separately() {
        let matcher = RegexPatternMatcher::new();
        matcher.find_matches(r"\d+", "a 1 b");
        matcher.find_matches(r"[a-z]+", "abc");
        matcher.find_matches(r"\d+", "c 2 d");
        let cache = matcher.cache.lock().expect("cache mutex poisoned");
        assert_eq!(
            cache.len(),
            2,
            "two distinct patterns must produce two cache entries; got {} entries",
            cache.len()
        );
    }

    /// # Contract
    ///
    /// `compile` and the trait methods MUST go through
    /// `build_bounded_regex`, which applies `RegexBuilder::size_limit`.
    /// Catastrophic patterns (`a{100000}{2}`) that exceed the bound MUST
    /// surface as `PatternError` from `compile` and as an empty result
    /// (with a tracing warning) from the trait methods. Pre-fix
    /// `Regex::new` had no size limit configured, so a malicious rule
    /// pack could ship a pattern that compiled but blew up the regex
    /// state machine at match time.
    #[test]
    fn compile_rejects_oversized_patterns() {
        let matcher = RegexPatternMatcher::new();
        // `a{1000000}{2}` requests an automaton with ~10^12 states; the
        // size_limit (1 MiB) rejects it well before that.
        let pathological = "a{1000000}{2}";
        let result = matcher.compile(pathological);
        assert!(
            result.is_err(),
            "compile MUST reject oversized regexes via size_limit"
        );
        // Trait methods fall back to empty / false on the same input.
        assert!(matcher.find_matches(pathological, "aaa").is_empty());
        assert!(!matcher.is_match(pathological, "aaa"));
    }

    /// # Contract
    /// `is_match` and `captures_iter` on the trait must agree with
    /// `find_matches` on whether a pattern occurs.
    #[test]
    fn is_match_and_captures_agree_with_find_matches() {
        let matcher = RegexPatternMatcher::new();
        let text = "user@example.com talks to admin@example.com";
        let pattern = r"(\w+)@example\.com";

        assert!(matcher.is_match(pattern, text));
        assert_eq!(matcher.find_matches(pattern, text).len(), 2);

        let caps = matcher.captures_iter(pattern, text);
        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].get(1).unwrap().matched_text, "user");
        assert_eq!(caps[1].get(1).unwrap().matched_text, "admin");
    }

    /// # Contract
    ///
    /// After a thread panics while holding the cache mutex, `cached` MUST
    /// recover from the poisoned lock rather than permanently degrading to
    /// recompiling every pattern on every call. Pre-fix the `if let Ok(map)`
    /// guards silently skipped both reads and writes on `Err(PoisonError)`,
    /// causing an O(n×rules) recompilation per scan instead of O(n) total.
    #[test]
    fn cached_recovers_from_poisoned_mutex() {
        let matcher = RegexPatternMatcher::new();
        // Warm the cache with a pattern.
        matcher.find_matches(r"\d+", "abc 123");
        assert_eq!(
            matcher
                .cache
                .lock()
                .expect("cache should be healthy after warm-up")
                .len(),
            1,
            "one pattern should be cached after first lookup"
        );
        // Poison the mutex by causing a panic while holding it.
        let cache_clone = Arc::clone(&matcher.cache);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cache_clone.lock().expect("lock before poison");
            panic!("intentional test panic to poison mutex");
        }));
        assert!(result.is_err(), "inner panic should have propagated");
        // Verify the mutex is poisoned.
        assert!(
            matcher.cache.is_poisoned(),
            "mutex must be poisoned after a panic while holding it"
        );
        // `cached` must still return a valid result despite the poison.
        let matches = matcher.find_matches(r"\d+", "xyz 456");
        assert_eq!(matches.len(), 1, "cached must recover from poison");
        assert_eq!(matches[0].matched_text, "456");
        // A new pattern must also work post-poison.
        let alpha_matches = matcher.find_matches(r"[a-z]+", "abc");
        assert_eq!(alpha_matches.len(), 1);
        assert_eq!(alpha_matches[0].matched_text, "abc");
    }
}
