//! Cross-provider consensus discrepancy — a first-class signal.
//!
//! ADR 0029 lets an LLM consensus soften a Block. That opens a
//! prompt-injection vector: a skill that manipulates ONE provider into
//! voting benign. The validated downgrade already requires ≥2 distinct
//! benign votes, so a single flip cannot *trigger* a downgrade — this
//! type makes that single flip an ACTIVE signal instead of a silently
//! ignored one, closing (rather than opening) the vector.
//!
//! Pure value type: no orchestration. The CLI `llm/` layer builds it
//! from recorded provider votes; this is the shared domain shape
//! (mirrors the on-disk `residual-fn-consensus.jsonl` rollup).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use strum_macros::Display;

use super::Verdict;

/// One provider's vote in a consensus round.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderVote {
    pub provider: String,
    pub verdict: Verdict,
    #[serde(default)]
    pub confidence: f32,
}

/// Coarse classification of a consensus round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ConsensusClass {
    /// All usable votes agree (unanimous).
    Agree,
    /// Majority-benign with dissent — the FP-recovery shape ADR 0029
    /// targets.
    LlmFp,
    /// Exactly one provider flipped to benign while ≥2 disagree, no
    /// errors masking it — the prompt-injection signature.
    SingleProviderFlip,
    /// No clear consensus.
    Split,
}

/// Per-package cross-provider discrepancy.
///
/// # Identity contract
/// Provider identity is `provider.trim().to_ascii_lowercase()`.
/// Duplicate records from one provider count once; conflicting
/// duplicate verdicts count as one ambiguous error vote.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsensusDiscrepancy {
    pub votes: Vec<ProviderVote>,
    pub benign_votes: usize,
    pub non_benign_votes: usize,
    pub error_votes: usize,
}

impl ConsensusDiscrepancy {
    /// Build from usable votes plus a count of providers that errored
    /// / returned an unparseable verdict.
    #[must_use]
    pub fn from_votes(votes: Vec<ProviderVote>, error_votes: usize) -> Self {
        let mut provider_verdicts: BTreeMap<String, Option<Verdict>> = BTreeMap::new();
        for vote in &votes {
            provider_verdicts
                .entry(normalized_provider_key(&vote.provider))
                .and_modify(|existing| {
                    if *existing != Some(vote.verdict) {
                        *existing = None;
                    }
                })
                .or_insert(Some(vote.verdict));
        }

        let mut benign_votes = 0;
        let mut non_benign_votes = 0;
        let mut ambiguous_votes = 0;
        for verdict in provider_verdicts.values() {
            match verdict {
                Some(Verdict::Benign) => benign_votes += 1,
                Some(_) => non_benign_votes += 1,
                None => ambiguous_votes += 1,
            }
        }
        debug_assert_eq!(
            benign_votes + non_benign_votes + ambiguous_votes,
            provider_verdicts.len(),
            "consensus provider buckets must cover every normalized provider",
        );
        Self {
            votes,
            benign_votes,
            non_benign_votes,
            error_votes: error_votes + ambiguous_votes,
        }
    }

    /// The prompt-injection signature: exactly one provider says
    /// benign while ≥2 others disagree, with NO errors masking the
    /// picture. Fail-closed: an error vote makes this `false` (we do
    /// not manufacture an injection finding on an ambiguous round).
    #[must_use]
    pub fn is_single_provider_benign_flip(&self) -> bool {
        self.benign_votes == 1 && self.non_benign_votes >= 2 && self.error_votes == 0
    }

    /// Provider name that flipped benign, when this is a single-flip.
    #[must_use]
    pub fn flipped_provider(&self) -> Option<&str> {
        if !self.is_single_provider_benign_flip() {
            return None;
        }
        self.votes
            .iter()
            .find(|v| v.verdict == Verdict::Benign)
            .map(|v| v.provider.as_str())
    }

    #[must_use]
    pub fn classification(&self) -> ConsensusClass {
        if self.is_single_provider_benign_flip() {
            return ConsensusClass::SingleProviderFlip;
        }
        let usable = self.benign_votes + self.non_benign_votes;
        if usable == 0 {
            return ConsensusClass::Split;
        }
        if self.error_votes == 0 && (self.benign_votes == 0 || self.non_benign_votes == 0) {
            return ConsensusClass::Agree;
        }
        if self.benign_votes >= 2 {
            return ConsensusClass::LlmFp;
        }
        ConsensusClass::Split
    }
}

fn normalized_provider_key(provider: &str) -> String {
    provider.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vote(p: &str, v: Verdict) -> ProviderVote {
        ProviderVote {
            provider: p.to_string(),
            verdict: v,
            confidence: 0.9,
        }
    }

    /// Contract: exactly one benign vs ≥2 non-benign, no errors → the
    /// injection signature; the flipped provider is identified.
    #[test]
    fn single_provider_benign_flip_detected() {
        let d = ConsensusDiscrepancy::from_votes(
            vec![
                vote("openai", Verdict::Benign),
                vote("grok", Verdict::Malicious),
                vote("ollama-cloud", Verdict::Malicious),
            ],
            0,
        );
        assert!(d.is_single_provider_benign_flip());
        assert_eq!(d.classification(), ConsensusClass::SingleProviderFlip);
        assert_eq!(d.flipped_provider(), Some("openai"));
    }

    /// Contract (negative): ≥2 benign is the VALIDATED downgrade
    /// consensus — it MUST NOT be flagged as injection (this is the
    /// 15.75:1 trade ADR 0029 relies on).
    #[test]
    fn two_benign_is_not_a_flip() {
        let d = ConsensusDiscrepancy::from_votes(
            vec![
                vote("openai", Verdict::Benign),
                vote("grok", Verdict::Benign),
                vote("ollama-cloud", Verdict::Malicious),
            ],
            0,
        );
        assert!(!d.is_single_provider_benign_flip());
        assert_eq!(d.classification(), ConsensusClass::LlmFp);
        assert_eq!(d.flipped_provider(), None);
    }

    /// Contract: duplicate rows from one provider count once; a
    /// single benign provider plus one duplicated non-benign provider
    /// is not the two-provider disagreement shape.
    #[test]
    fn duplicate_non_benign_provider_does_not_create_flip() {
        let d = ConsensusDiscrepancy::from_votes(
            vec![
                vote("openai", Verdict::Benign),
                vote("grok", Verdict::Malicious),
                vote(" Grok ", Verdict::Malicious),
            ],
            0,
        );
        assert_eq!(d.benign_votes, 1);
        assert_eq!(d.non_benign_votes, 1);
        assert!(!d.is_single_provider_benign_flip());
        assert_eq!(d.classification(), ConsensusClass::Split);
    }

    /// Contract: duplicate benign rows from one provider cannot form
    /// the validated majority-benign class.
    #[test]
    fn duplicate_benign_provider_does_not_create_llm_fp() {
        let d = ConsensusDiscrepancy::from_votes(
            vec![
                vote("openai", Verdict::Malicious),
                vote("grok", Verdict::Benign),
                vote(" Grok ", Verdict::Benign),
            ],
            0,
        );
        assert_eq!(d.benign_votes, 1);
        assert_eq!(d.non_benign_votes, 1);
        assert_eq!(d.classification(), ConsensusClass::Split);
    }

    /// Contract: conflicting duplicate rows from one provider are
    /// ambiguous and mask the round instead of contributing either a
    /// benign or non-benign vote.
    #[test]
    fn conflicting_duplicate_provider_votes_are_ambiguous() {
        let d = ConsensusDiscrepancy::from_votes(
            vec![
                vote("openai", Verdict::Benign),
                vote(" OpenAI ", Verdict::Malicious),
                vote("grok", Verdict::Malicious),
                vote("ollama-cloud", Verdict::Malicious),
            ],
            0,
        );
        assert_eq!(d.benign_votes, 0);
        assert_eq!(d.non_benign_votes, 2);
        assert_eq!(d.error_votes, 1);
        assert!(!d.is_single_provider_benign_flip());
        assert_eq!(d.classification(), ConsensusClass::Split);
    }

    /// Contract (negative): an error vote masks the picture →
    /// fail-closed, NOT flagged as injection.
    #[test]
    fn error_masked_flip_is_not_flagged() {
        let d = ConsensusDiscrepancy::from_votes(
            vec![
                vote("openai", Verdict::Benign),
                vote("grok", Verdict::Malicious),
            ],
            1,
        );
        assert!(!d.is_single_provider_benign_flip());
    }

    /// Contract: a unanimous round is `Agree` and never a flip.
    #[test]
    fn unanimous_is_agree() {
        let d = ConsensusDiscrepancy::from_votes(
            vec![
                vote("openai", Verdict::Benign),
                vote("grok", Verdict::Benign),
                vote("ollama-cloud", Verdict::Benign),
            ],
            0,
        );
        assert!(!d.is_single_provider_benign_flip());
        assert_eq!(d.classification(), ConsensusClass::Agree);
    }
}
