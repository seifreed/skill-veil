//! Named threat taxonomy applied to findings as first-class labels.
//!
//! [`ThreatCategory`](super::ThreatCategory) classifies *what kind* of risk a
//! finding represents and feeds verdict scoring. [`TaxonomyTag`] is an
//! orthogonal, communication-oriented vocabulary: it maps a rule (and the
//! findings it produces) onto the named agent-skill threat categories shared by
//! the wider ecosystem, so coverage is demonstrable in JSON/SARIF output without
//! disturbing the scoring categories.
//!
//! # Stability contract
//!
//! The serialized (snake_case) names are public API on the same footing as the
//! `official` rule IDs: operators and downstream tooling key on them in
//! JSON/SARIF, so renaming or removing a variant is a breaking change.
//! [`TAXONOMY_TAGS`] is the frozen registry and the `taxonomy_registry_is_frozen`
//! test fails on any drift, forcing the change to be deliberate. The contract is
//! documented under "Named taxonomy tags" in `CLAUDE.md` / `AGENTS.md`.

use serde::{Deserialize, Serialize};
use strum_macros::Display;

/// A named threat-taxonomy label attached to a rule and propagated to findings.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Display,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum TaxonomyTag {
    /// Persistent injection into agent memory or long-lived context.
    MemoryPoisoning,
    /// Agent self-modification or session persistence beyond its mandate.
    RogueAgent,
    /// Capability or autonomy granted beyond what the task requires.
    ExcessiveAgency,
    /// Unvalidated or cross-context handling of model/tool output.
    OutputHandling,
    /// Overly broad triggers or keyword baiting that widen activation.
    TriggerAbuse,
    /// Direct or indirect leakage of the system prompt / hidden instructions.
    SystemPromptLeakage,
}

/// Frozen registry of every taxonomy tag. The `taxonomy_registry_is_frozen`
/// test pins the serialized names against this list.
pub const TAXONOMY_TAGS: &[TaxonomyTag] = &[
    TaxonomyTag::MemoryPoisoning,
    TaxonomyTag::RogueAgent,
    TaxonomyTag::ExcessiveAgency,
    TaxonomyTag::OutputHandling,
    TaxonomyTag::TriggerAbuse,
    TaxonomyTag::SystemPromptLeakage,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taxonomy_registry_is_frozen() {
        let mut actual: Vec<String> = TAXONOMY_TAGS.iter().map(ToString::to_string).collect();
        actual.sort();
        let expected = [
            "excessive_agency",
            "memory_poisoning",
            "output_handling",
            "rogue_agent",
            "system_prompt_leakage",
            "trigger_abuse",
        ];
        assert_eq!(
            actual, expected,
            "taxonomy tag registry changed — renaming or removing a public tag is a \
             breaking change; update the contract in CLAUDE.md / AGENTS.md and this \
             frozen list deliberately"
        );
    }

    #[test]
    fn taxonomy_tags_serialize_snake_case() {
        let json = serde_json::to_string(&TaxonomyTag::SystemPromptLeakage).unwrap();
        assert_eq!(json, "\"system_prompt_leakage\"");
        let parsed: TaxonomyTag = serde_json::from_str("\"memory_poisoning\"").unwrap();
        assert_eq!(parsed, TaxonomyTag::MemoryPoisoning);
    }
}
