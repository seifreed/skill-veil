// Without `--features nova-semantics`, the cosine math + trait
// abstraction is never constructed by the production dispatcher
// (`build_nova_semantic_eval` returns `None`), but the unit tests in
// this module still drive every contract via stub embedders. Allowing
// dead code here lets default builds stay quiet while preserving the
// contract-pinning tests.
#![allow(dead_code)]

//! Native [`SemanticEvaluator`] backed by sentence embeddings + cosine
//! similarity, gated behind the `nova-semantics` Cargo feature.
//!
//! # Two-layer design
//!
//! 1. [`SentenceEmbedder`] — a tiny trait that turns text into a
//!    fixed-dimension vector. The whole math layer (cosine, threshold
//!    comparison, pattern-embedding cache) sits in
//!    [`CosineSemanticEvaluator`] and consumes only the trait, so
//!    every contract here is testable with a stub embedder — no model
//!    download, no ONNX runtime, no network.
//! 2. [`fastembed_impl`] — the real `fastembed`-backed implementation
//!    (under `#[cfg(feature = "nova-semantics")]`). This is the only
//!    place that touches the heavy runtime; everything else is feature-
//!    independent and compiles in the default build.
//!
//! # Why a feature flag
//!
//! `fastembed` pulls the ONNX runtime native library (~30 MiB binary
//! delta) and downloads `all-MiniLM-L6-v2` (~90 MiB) on first use.
//! Mirrors the existing `yara` opt-in pattern: the runtime flag
//! `--nova-semantics` is always parseable so users don't see a
//! "unknown flag" diff between build variants — when the feature is
//! off, the CLI emits a one-line note and falls back to
//! `NotYetWiredSemantic` so any rule whose `condition:` requires the
//! `semantics.` namespace surfaces under `skipped_capabilities`.

use skill_veil_core::nova::{evaluators::Outcome, SemanticEvaluator, SemanticPattern};
use std::collections::HashMap;
use std::sync::Mutex;

/// Cap on the chars of `body` shipped to the embedder. `all-MiniLM-L6-v2`
/// has a 256-token sequence limit; conservative chars-per-token of 4
/// yields ~1024 chars before any tokenizer-side truncation kicks in.
/// We cap higher (4 × that) and let the tokenizer handle the rest, so
/// rules whose patterns target later-body content still get *some*
/// signal even if the head dominates. Patterns themselves are short
/// (~1 sentence) and never truncated.
pub(crate) const MAX_BODY_CHARS_FOR_EMBEDDING: usize = 4 * 1024;

/// Errors a [`SentenceEmbedder`] can surface. Keep narrow on purpose —
/// the caller only needs to distinguish "skip this rule" from
/// "succeed", and any structured error info should land in
/// `tracing::warn` at the producer.
#[derive(Debug)]
pub(crate) enum EmbedError {
    /// The embedder failed for a reason the caller cannot recover from
    /// (model not loaded, ONNX runtime error, hub fetch failed, …).
    /// Treated as `Outcome::Skipped` by the wrapper evaluator.
    Failed(String),
}

/// Sentence embedder contract. Implementations must produce a fixed-
/// dimension vector for any non-empty input; the dimension MUST be
/// identical across calls (cosine similarity is undefined otherwise).
pub(crate) trait SentenceEmbedder: Send + Sync {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError>;
}

/// `SemanticEvaluator` adapter that:
/// 1. embeds the pattern (cached per pattern string),
/// 2. embeds the body (truncated to [`MAX_BODY_CHARS_FOR_EMBEDDING`]
///    chars to stay within the model's sequence budget),
/// 3. computes cosine similarity, and
/// 4. fires when `cos_sim ≥ pattern.threshold`.
///
/// The pattern cache is keyed on the literal pattern string, so two
/// rules sharing a pattern (or one rule scanned across many bodies)
/// pay the embedding cost exactly once per evaluator lifetime. The
/// body is NOT cached: bodies can be megabytes (skill markdown) and
/// caching them would defeat the purpose of the truncation guard.
pub(crate) struct CosineSemanticEvaluator<E: SentenceEmbedder> {
    embedder: E,
    pattern_cache: Mutex<HashMap<String, Vec<f32>>>,
}

impl<E: SentenceEmbedder> CosineSemanticEvaluator<E> {
    pub(crate) fn new(embedder: E) -> Self {
        Self {
            embedder,
            pattern_cache: Mutex::new(HashMap::new()),
        }
    }

    fn embed_pattern(&self, pattern: &str) -> Result<Vec<f32>, EmbedError> {
        if let Ok(cache) = self.pattern_cache.lock() {
            if let Some(v) = cache.get(pattern) {
                return Ok(v.clone());
            }
        }
        let embedding = self.embedder.embed(pattern)?;
        if let Ok(mut cache) = self.pattern_cache.lock() {
            cache.insert(pattern.to_string(), embedding.clone());
        }
        Ok(embedding)
    }

    fn embed_body(&self, body: &str) -> Result<Vec<f32>, EmbedError> {
        let clipped = clip_body(body);
        self.embedder.embed(&clipped)
    }
}

impl<E: SentenceEmbedder> SemanticEvaluator for CosineSemanticEvaluator<E> {
    fn eval(&self, var: &str, pattern: &SemanticPattern, body: &str) -> Outcome {
        let pattern_emb = match self.embed_pattern(&pattern.pattern) {
            Ok(v) => v,
            Err(EmbedError::Failed(msg)) => {
                tracing::warn!(
                    rule_var = %var,
                    "NOVA semantic evaluator: pattern embedding failed: {msg}; treating as Skipped",
                );
                return Outcome::Skipped;
            }
        };
        let body_emb = match self.embed_body(body) {
            Ok(v) => v,
            Err(EmbedError::Failed(msg)) => {
                tracing::warn!(
                    rule_var = %var,
                    "NOVA semantic evaluator: body embedding failed: {msg}; treating as Skipped",
                );
                return Outcome::Skipped;
            }
        };
        let sim = match cosine_similarity(&pattern_emb, &body_emb) {
            Some(s) => s,
            None => {
                tracing::warn!(
                    rule_var = %var,
                    pattern_dim = pattern_emb.len(),
                    body_dim = body_emb.len(),
                    "NOVA semantic evaluator: embedding dimension mismatch or zero norm; treating as Skipped",
                );
                return Outcome::Skipped;
            }
        };
        if sim >= pattern.threshold {
            Outcome::Match
        } else {
            Outcome::NoMatch
        }
    }
}

fn clip_body(body: &str) -> String {
    if body.chars().count() <= MAX_BODY_CHARS_FOR_EMBEDDING {
        return body.to_string();
    }
    body.chars().take(MAX_BODY_CHARS_FOR_EMBEDDING).collect()
}

/// Cosine similarity. Returns `None` if vectors differ in dimension or
/// either has zero magnitude — both are unrecoverable for the caller
/// (no defined comparison) and surface as `Outcome::Skipped`.
fn cosine_similarity(a: &[f32], b: &[f32]) -> Option<f32> {
    if a.len() != b.len() || a.is_empty() {
        return None;
    }
    let mut dot = 0.0_f32;
    let mut norm_a = 0.0_f32;
    let mut norm_b = 0.0_f32;
    for (x, y) in a.iter().zip(b) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return None;
    }
    Some(dot / (norm_a.sqrt() * norm_b.sqrt()))
}

#[cfg(feature = "nova-semantics")]
pub(crate) mod fastembed_impl {
    //! `fastembed`-backed [`SentenceEmbedder`].
    //!
    //! Initializes `all-MiniLM-L6-v2` lazily on construction and holds
    //! it inside a `Mutex` because [`fastembed::TextEmbedding::embed`]
    //! takes `&mut self` (the model carries internal state for the
    //! ONNX session). Concurrent NOVA scans serialise on this lock; in
    //! practice `evaluate_against_target` is called once per scan and
    //! drives rules sequentially, so contention is non-existent.

    use super::{EmbedError, SentenceEmbedder};
    use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};
    use std::path::PathBuf;
    use std::sync::Mutex;

    pub(crate) struct FastembedSentenceEmbedder {
        model: Mutex<TextEmbedding>,
    }

    impl FastembedSentenceEmbedder {
        /// Loads `all-MiniLM-L6-v2`. The first call downloads the
        /// model (~90 MiB) into [`nova_model_cache_dir`]; subsequent
        /// calls (any working directory) reuse the cache. On failure
        /// (no network + no cache, disk full, hub error) returns
        /// `Err` so the CLI can fall back to the
        /// `NotYetWiredSemantic` stub WITHOUT failing the scan.
        pub(crate) fn try_new() -> Result<Self, EmbedError> {
            let cache_dir = nova_model_cache_dir();
            // fastembed delegates dir creation to hf-hub but only for
            // `<cache_dir>/blobs/`/`refs/`/`snapshots/` — the parent
            // `cache_dir` itself MUST already exist or the very first
            // download errors on `No such file or directory`. Pre-fix
            // (default cwd-relative `.fastembed_cache`) the parent was
            // always cwd which is implicitly present, so the bug only
            // surfaces with our explicit path. `create_dir_all` is
            // idempotent so this is safe across repeat invocations.
            std::fs::create_dir_all(&cache_dir).map_err(|e| {
                EmbedError::Failed(format!(
                    "create nova model cache dir {}: {e}",
                    cache_dir.display()
                ))
            })?;
            let opts =
                InitOptions::new(EmbeddingModel::AllMiniLML6V2).with_cache_dir(cache_dir.clone());
            let model = TextEmbedding::try_new(opts).map_err(|e| {
                EmbedError::Failed(format!("fastembed init at {}: {e}", cache_dir.display()))
            })?;
            Ok(Self {
                model: Mutex::new(model),
            })
        }
    }

    /// Canonical cache directory for the NOVA semantics model.
    /// Mirrors the placement convention used by VT and LLM caches:
    /// `dirs::cache_dir().join("skill-veil/nova-models/")` on macOS /
    /// Linux, with `std::env::temp_dir()` as a degraded fallback so
    /// the scanner still runs (re-downloading per session) on hosts
    /// where the user cache directory cannot be resolved.
    pub(crate) fn nova_model_cache_dir() -> PathBuf {
        match dirs::cache_dir() {
            Some(base) => base.join("skill-veil").join("nova-models"),
            None => std::env::temp_dir().join("skill-veil-nova-models"),
        }
    }

    impl SentenceEmbedder for FastembedSentenceEmbedder {
        fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
            let mut model = self
                .model
                .lock()
                .map_err(|e| EmbedError::Failed(format!("model lock poisoned: {e}")))?;
            let mut out = model
                .embed(vec![text], None)
                .map_err(|e| EmbedError::Failed(format!("embed: {e}")))?;
            out.pop()
                .ok_or_else(|| EmbedError::Failed("embed returned no vectors".into()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Contract: the cache dir is namespaced under `skill-veil/`
        /// inside the user's cache directory. The previous default
        /// (cwd-relative `.fastembed_cache`) polluted the project
        /// root and forced a re-download on every `cd`. Pinning the
        /// canonical path stops a future refactor from silently
        /// reverting to fastembed's default.
        #[test]
        fn nova_model_cache_dir_is_namespaced_under_skill_veil() {
            let p = nova_model_cache_dir();
            let s = p.to_string_lossy();
            assert!(
                s.contains("skill-veil"),
                "cache dir must be namespaced under skill-veil, got {s}",
            );
            assert!(
                s.ends_with("nova-models")
                    || s.ends_with("nova-models/")
                    || s.ends_with("nova-models\\"),
                "cache dir must end with nova-models, got {s}",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Stub embedder that returns a deterministic vector derived from
    /// the input string. Lets every contract on
    /// [`CosineSemanticEvaluator`] be exercised without a real model.
    /// The embedding is the byte-frequency vector over `[a-z]` so
    /// identical inputs yield identical vectors (cos_sim = 1.0),
    /// disjoint alphabets yield orthogonal vectors (cos_sim = 0.0),
    /// and partial overlap yields a value in between — exactly the
    /// property the cosine math relies on.
    struct DeterministicEmbedder {
        calls: AtomicUsize,
    }

    impl DeterministicEmbedder {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl SentenceEmbedder for DeterministicEmbedder {
        fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut v = vec![0.0_f32; 26];
            for c in text.chars().filter(|c| c.is_ascii_alphabetic()) {
                let idx = (c.to_ascii_lowercase() as u8 - b'a') as usize;
                v[idx] += 1.0;
            }
            Ok(v)
        }
    }

    /// Stub embedder that always errors. Used to pin the
    /// `Outcome::Skipped` branch of the evaluator.
    struct FailingEmbedder;

    impl SentenceEmbedder for FailingEmbedder {
        fn embed(&self, _text: &str) -> Result<Vec<f32>, EmbedError> {
            Err(EmbedError::Failed("test stub".into()))
        }
    }

    fn pat(pattern: &str, threshold: f32) -> SemanticPattern {
        SemanticPattern {
            pattern: pattern.to_string(),
            threshold,
        }
    }

    /// Contract: identical pattern + body produce cos_sim = 1.0, which
    /// must clear any threshold ≤ 1.0 and fire the rule. Without this,
    /// the evaluator would mis-rank the strongest possible match.
    #[test]
    fn identical_pattern_and_body_match() {
        let ev = CosineSemanticEvaluator::new(DeterministicEmbedder::new());
        let outcome = ev.eval(
            "$x",
            &pat("ignore previous instructions", 0.5),
            "ignore previous instructions",
        );
        assert_eq!(outcome, Outcome::Match);
    }

    /// Contract: a body whose embedding shares NO non-zero
    /// dimensions with the pattern's embedding produces cos_sim = 0.0
    /// and must NOT fire even at a permissive threshold. This pins
    /// the "false → no fire" half of the boundary that prevents
    /// NOVA semantics from over-firing. The body MUST be non-empty
    /// (otherwise zero magnitude → `Skipped`); the test embedder uses
    /// letter-frequency vectors so disjoint letter sets produce
    /// orthogonal non-zero vectors.
    #[test]
    fn disjoint_alphabets_do_not_match() {
        let ev = CosineSemanticEvaluator::new(DeterministicEmbedder::new());
        // Pattern uses only "aeiou"; body uses only "bcdfg" — both
        // produce non-zero embeddings, but with no shared dimension
        // their cosine similarity is exactly 0.
        let outcome = ev.eval("$x", &pat("aeiou", 0.1), "bcdfg");
        assert_eq!(outcome, Outcome::NoMatch);
    }

    /// Contract: when cos_sim sits BELOW the rule's threshold, the
    /// rule does NOT fire even though some signal exists. The NOVA
    /// pack's published thresholds (0.1 broad, 0.35 balanced, 0.9
    /// strict) all rely on this floor — collapsing it would let
    /// "balanced" rules fire as if they were "broad".
    #[test]
    fn similarity_below_threshold_does_not_fire() {
        // pattern: "abc", body: "abxy". Cos_sim is between 0 and 1.
        // We pick a threshold high enough to suppress the partial overlap.
        let ev = CosineSemanticEvaluator::new(DeterministicEmbedder::new());
        let outcome = ev.eval("$x", &pat("abc", 0.99), "abxy");
        assert_eq!(outcome, Outcome::NoMatch);
    }

    /// Contract: a failing embedder MUST surface `Outcome::Skipped`
    /// so the rule's condition cannot fire on garbage AND the
    /// scan-level report carries `SkippedCapability::Semantics` for
    /// the operator to see.
    #[test]
    fn failing_embedder_returns_skipped() {
        let ev = CosineSemanticEvaluator::new(FailingEmbedder);
        let outcome = ev.eval("$x", &pat("anything", 0.5), "any body");
        assert_eq!(outcome, Outcome::Skipped);
    }

    /// Contract: a pattern is embedded ONCE across many evaluations
    /// against different bodies. Without this cache, every rule across
    /// every scanned body would re-embed the same pattern string —
    /// the dominant cost of a NOVA scan with semantics enabled.
    #[test]
    fn pattern_embedding_is_cached_across_calls() {
        let embedder = DeterministicEmbedder::new();
        let ev = CosineSemanticEvaluator::new(embedder);
        let p = pat("constant pattern", 0.5);
        // Three calls against three different bodies.
        let _ = ev.eval("$x", &p, "body one");
        let _ = ev.eval("$x", &p, "body two");
        let _ = ev.eval("$x", &p, "body three");
        // Expect 1 pattern embed + 3 body embeds = 4 total calls.
        let total = ev.embedder.calls.load(Ordering::SeqCst);
        assert_eq!(
            total, 4,
            "expected 1 pattern embed + 3 body embeds, got {total}",
        );
    }

    /// Contract: bodies longer than [`MAX_BODY_CHARS_FOR_EMBEDDING`]
    /// MUST be clipped before the embedder sees them. Without this,
    /// a multi-megabyte SKILL.md could push past `all-MiniLM-L6-v2`'s
    /// tokeniser limits or burn enormous amounts of CPU on a single
    /// rule scan.
    #[test]
    fn body_is_clipped_before_embedding() {
        let body = "x".repeat(MAX_BODY_CHARS_FOR_EMBEDDING * 4);
        let clipped = clip_body(&body);
        assert_eq!(clipped.chars().count(), MAX_BODY_CHARS_FOR_EMBEDDING);
    }

    /// Contract: a body within the budget MUST pass through
    /// unchanged. The clip helper is the only producer for the
    /// truncation step, so an inverted boundary check would silently
    /// trim short bodies and skew similarity downward.
    #[test]
    fn short_body_is_not_clipped() {
        let body = "short body".to_string();
        assert_eq!(clip_body(&body), body);
    }

    /// Contract: cosine similarity rejects vectors of mismatched
    /// dimension. This is the contract that prevents an embedder swap
    /// (e.g. from MiniLM dim 384 to a different model dim 768) from
    /// silently producing nonsense rule decisions.
    #[test]
    fn cosine_similarity_rejects_mismatched_dimensions() {
        let a = vec![1.0_f32, 0.0, 0.0];
        let b = vec![1.0_f32, 0.0];
        assert!(cosine_similarity(&a, &b).is_none());
    }

    /// Contract: cosine similarity rejects zero-magnitude vectors (the
    /// formula has a 0-divisor in that case). Returning a sentinel
    /// value would let some rule fire on degenerate input; `None` →
    /// `Skipped` is the safe behaviour.
    #[test]
    fn cosine_similarity_rejects_zero_magnitude_input() {
        let zero = vec![0.0_f32; 4];
        let v = vec![1.0_f32, 2.0, 3.0, 4.0];
        assert!(cosine_similarity(&zero, &v).is_none());
        assert!(cosine_similarity(&v, &zero).is_none());
    }

    /// Contract: identical orthogonal-base vectors return cos_sim ≈ 1.
    /// Sanity-check the math itself rather than the trait wrapper.
    #[test]
    fn cosine_similarity_self_similar_is_one() {
        let v = vec![3.0_f32, 4.0, 0.0];
        let s = cosine_similarity(&v, &v).expect("must compute");
        assert!((s - 1.0).abs() < 1e-6, "got {s}");
    }

    /// Contract: orthogonal vectors return cos_sim ≈ 0.
    #[test]
    fn cosine_similarity_orthogonal_is_zero() {
        let a = vec![1.0_f32, 0.0];
        let b = vec![0.0_f32, 1.0];
        let s = cosine_similarity(&a, &b).expect("must compute");
        assert!(s.abs() < 1e-6, "got {s}");
    }

    /// Contract (integration): when the engine drives a NOVA rule
    /// whose `condition:` requires `semantics.$x`, an evaluator that
    /// returns cos_sim above the threshold MUST cause the rule to
    /// fire AND MUST NOT surface `SkippedCapability::Semantics` —
    /// the channel was actually serviced. Pre-wire the same rule
    /// would have collapsed to `Outcome::Skipped` (NotYetWiredSemantic)
    /// and the rule's condition would have evaluated to false.
    #[test]
    fn engine_fires_rule_when_semantic_evaluator_matches_above_threshold() {
        use skill_veil_core::nova::{
            evaluate_rule, parse_rules, NativeKeywordEvaluator, NotYetWiredLlm, SkippedCapability,
        };
        let rule_body = r#"
            rule SemanticsOnly {
                semantics:
                    $jail = "ignore previous instructions" (0.5)
                condition:
                    semantics.$jail
            }
        "#;
        let rule = parse_rules(rule_body).unwrap().pop().unwrap();
        let sem_eval = CosineSemanticEvaluator::new(DeterministicEmbedder::new());
        // Body identical to the pattern → cos_sim = 1.0, well above 0.5.
        let m = evaluate_rule(
            &rule,
            "ignore previous instructions",
            &NativeKeywordEvaluator::new(),
            &sem_eval,
            &NotYetWiredLlm,
        )
        .unwrap();
        assert!(
            m.matched,
            "rule must fire when semantic evaluator returns Match"
        );
        assert!(
            !m.skipped_capabilities
                .contains(&SkippedCapability::Semantics),
            "Semantics capability must NOT appear in skipped list when evaluator serviced the call",
        );
    }
}
