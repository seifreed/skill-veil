//! The PromptIntel threat taxonomy as published by upstream curators.
//!
//! The taxonomy is the official 5-bucket / ~37-threat structure used
//! to classify entries in the PromptIntel curated corpus. We mirror
//! it verbatim here so:
//!
//! - the cross-check report can group threats under their parent
//!   bucket instead of an alphabetical jumble;
//! - rule authors can tag rules with `promptintel_threats: [...]`
//!   and have the value validated against a typed list;
//! - drift in the upstream taxonomy is surfaced as a warning the
//!   first time skill-veil sees an unfamiliar threat string.
//!
//! The list is intentionally kept as `&'static str` rather than a
//! Rust enum because the upstream allows occasional renames /
//! additions; treating each name as a string lets us update this
//! constant without breaking serialised on-disk artifacts that quote
//! the previous spelling.

/// One top-level bucket in the upstream taxonomy.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ThreatBucket {
    pub(crate) name: &'static str,
    pub(crate) threats: &'static [&'static str],
}

/// Full taxonomy in the canonical upstream order. The order is
/// load-bearing for the cross-check renderer: operators expect
/// `Prompt Manipulation` first because it is the largest and
/// highest-leverage class.
pub(crate) const TAXONOMY: &[ThreatBucket] = &[
    ThreatBucket {
        name: "Prompt Manipulation",
        threats: &[
            "Direct prompt injection",
            "Indirect prompt injection",
            "Jailbreak",
            "Hidden instruction in code or comments",
            "Recursive or translation trick",
            "Retrieval / RAG Poisoning",
            "Model Behavior Manipulation via Feedback Loops",
        ],
    },
    ThreatBucket {
        name: "Abusing Legitimate Functions",
        threats: &[
            "Disinformation campaign",
            "Malware generation",
            "Reconnaissance and target profiling",
            "Data exfiltration via prompt",
            "Fraud and social engineering",
            "Automation for crime",
            "AI driven attack enablement",
            "Model hijack via stolen keys",
            "Supply Chain Abuse (package-level prompts)",
            "Training Data Poisoning",
            "Agentic Misuse (tool/agent loops)",
            "Credential Harvesting Templates",
            "Contextual Exfiltration Patterns",
            "Privacy / PII Exfiltration Templates",
        ],
    },
    ThreatBucket {
        name: "Suspicious Prompt Patterns",
        threats: &[
            "Encoding and obfuscation",
            "Unicode tricks",
            "Chained prompts",
            "Prompt tunneling via roleplay",
            "Fragmentation",
            "Adversarial token perturbation",
            "Cross-Modal Attacks (image/audio→prompt)",
            "Multi-Agent Collusion",
            "Telemetry Evasion Techniques",
        ],
    },
    ThreatBucket {
        name: "Abnormal Outputs",
        threats: &[
            "System prompt leak",
            "Credential leak",
            "PII exposure",
            "Sensitive document disclosure",
            "Internal logic or filter disclosure",
            "Malicious content generation",
            "Exploit or payload output",
            "Harmful Automation Guidance",
        ],
    },
];

/// Find which bucket owns `threat`. Comparison is case-sensitive on
/// purpose: upstream names use exact capitalisation (e.g. `"Jailbreak"`
/// vs `"jailbreak"`) and we want a case difference to surface as drift,
/// not be silently normalised.
pub(crate) fn bucket_for(threat: &str) -> Option<&'static str> {
    for bucket in TAXONOMY {
        if bucket.threats.contains(&threat) {
            return Some(bucket.name);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Contract: every threat in the taxonomy is reachable through
    /// `bucket_for`. Pre-fix a typo in the iterator would silently
    /// drop a whole bucket; this test catches that regression.
    #[test]
    fn every_threat_resolves_to_its_bucket() {
        for bucket in TAXONOMY {
            for threat in bucket.threats {
                assert_eq!(
                    bucket_for(threat),
                    Some(bucket.name),
                    "{threat:?} did not resolve back to {:?}",
                    bucket.name
                );
            }
        }
    }

    /// Contract: threat names are unique across the entire taxonomy.
    /// Two buckets owning the same string would make `bucket_for`
    /// non-deterministic.
    #[test]
    fn threat_names_are_globally_unique() {
        let mut seen: HashSet<&'static str> = HashSet::new();
        for bucket in TAXONOMY {
            for threat in bucket.threats {
                assert!(
                    seen.insert(*threat),
                    "duplicate threat {threat:?} appears under multiple buckets"
                );
            }
        }
    }

    /// Contract: bucket names are also unique. A typo that creates
    /// two `Prompt Manipulation` buckets would silently double-count
    /// in coverage reports.
    #[test]
    fn bucket_names_are_unique() {
        let names: HashSet<&'static str> = TAXONOMY.iter().map(|b| b.name).collect();
        assert_eq!(names.len(), TAXONOMY.len());
    }

    /// Contract: comparison is case-sensitive. A future API rename
    /// from `"Jailbreak"` to `"jailbreak"` MUST surface as drift,
    /// not silently match the wrong bucket.
    #[test]
    fn lookup_is_case_sensitive() {
        assert_eq!(bucket_for("Jailbreak"), Some("Prompt Manipulation"));
        assert_eq!(bucket_for("jailbreak"), None);
        assert_eq!(bucket_for("JAILBREAK"), None);
    }

    /// Sanity: pin the published taxonomy shape (4 buckets / 38
    /// threats) so a future edit that silently drops a threat
    /// surfaces here.
    #[test]
    fn taxonomy_shape_matches_upstream() {
        assert_eq!(TAXONOMY.len(), 4);
        let total: usize = TAXONOMY.iter().map(|b| b.threats.len()).sum();
        assert_eq!(total, 38);
    }
}
