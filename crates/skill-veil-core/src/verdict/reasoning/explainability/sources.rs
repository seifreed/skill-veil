use crate::findings::{ExplainabilityContribution, ExplainabilityTrace, RiskFactor};
use std::collections::BTreeMap;

pub(super) fn summarize_source_contributions(
    top_risk_drivers: &[RiskFactor],
) -> Vec<ExplainabilityContribution> {
    let mut contributions = BTreeMap::<String, u32>::new();

    for factor in top_risk_drivers {
        accumulate_source_contribution(&mut contributions, factor);
    }

    contributions
        .into_iter()
        .map(|(source, contribution)| ExplainabilityContribution {
            source,
            contribution,
        })
        .collect()
}

pub(super) fn is_drift_sensitive_driver(factor: &RiskFactor) -> bool {
    drift_sensitive_keyword_matched(&normalized_factor_text(factor))
}

pub(super) fn risk_factor_trace(factor: &RiskFactor) -> ExplainabilityTrace {
    ExplainabilityTrace {
        source: trace_source_for_risk_factor(factor),
        label: factor.factor.clone(),
        rationale: factor.rationale.clone(),
        rule_ids: Vec::new(),
        scope: None,
        contribution: Some(factor.contribution),
    }
}

fn trace_source_for_risk_factor(factor: &RiskFactor) -> String {
    source_bucket_for_normalized(&normalized_factor_text(factor)).to_string()
}

fn accumulate_source_contribution(
    contributions: &mut BTreeMap<String, u32>,
    factor: &RiskFactor,
) {
    *contributions
        .entry(trace_source_for_risk_factor(factor))
        .or_default() += factor.contribution;
}

fn normalized_factor_text(factor: &RiskFactor) -> String {
    format!("{} {}", factor.factor, factor.rationale).to_ascii_lowercase()
}

fn source_bucket_for_normalized(normalized: &str) -> &'static str {
    source_bucket(normalized).unwrap_or("score_factor")
}

fn drift_sensitive_keyword_matched(normalized: &str) -> bool {
    [
        "registry",
        "publisher",
        "lockfile",
        "manifest",
        "provenance",
        "domain",
        "reputation",
    ]
    .iter()
    .any(|keyword| normalized.contains(keyword))
}

fn is_graph_source(normalized: &str) -> bool {
    normalized.contains("capability_combo:") || normalized.contains("composite:")
}

fn is_policy_source(normalized: &str) -> bool {
    normalized.contains("policy")
        || normalized.contains("approval")
        || normalized.contains("permission")
}

fn is_provenance_source(normalized: &str) -> bool {
    normalized.contains("provenance:")
        || normalized.contains("registry")
        || normalized.contains("lockfile")
        || normalized.contains("publisher")
        || normalized.contains("manifest")
}

fn is_network_source(normalized: &str) -> bool {
    normalized.contains("network")
        || normalized.contains("webhook")
        || normalized.contains("remote")
        || normalized.contains("download")
}

fn source_bucket(normalized: &str) -> Option<&'static str> {
    if is_graph_source(normalized) {
        Some("graph")
    } else if is_policy_source(normalized) {
        Some("policy")
    } else if is_provenance_source(normalized) {
        Some("provenance")
    } else if is_network_source(normalized) {
        Some("network")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explainability_tracks_source_buckets_and_calibration_points() {
        let contributions = summarize_source_contributions(&[
            RiskFactor {
                factor: "composite:remote_mcp_no_auth_exec".to_string(),
                contribution: 19,
                rationale: "critical: remote MCP exposure combines missing authentication with execution-capable tooling".to_string(),
            },
            RiskFactor {
                factor: "provenance:review".to_string(),
                contribution: 3,
                rationale: "review: external provenance requires review due to external origins".to_string(),
            },
        ]);

        assert_eq!(contributions.len(), 2);
        assert!(contributions.iter().any(|item| item.source == "graph" && item.contribution == 19));
        assert!(contributions.iter().any(|item| item.source == "provenance" && item.contribution == 3));
    }

    #[test]
    fn explainability_marks_registry_factors_as_drift_sensitive() {
        let factor = RiskFactor {
            factor: "registry:direct_url".to_string(),
            contribution: 5,
            rationale: "review: registry mirror changed".to_string(),
        };
        assert!(is_drift_sensitive_driver(&factor));
    }

    #[test]
    fn explainability_maps_graph_and_policy_sources() {
        let graph_factor = RiskFactor {
            factor: "capability_combo:install_network".to_string(),
            contribution: 8,
            rationale: "review: install-time networking is present".to_string(),
        };
        let policy_factor = RiskFactor {
            factor: "policy:approval_gap".to_string(),
            contribution: 4,
            rationale: "review: requested approval model is weaker than observed behavior".to_string(),
        };

        assert_eq!(trace_source_for_risk_factor(&graph_factor), "graph");
        assert_eq!(trace_source_for_risk_factor(&policy_factor), "policy");
    }

    #[test]
    fn explainability_tracks_calibration_trace_entries() {
        let trace = risk_factor_trace(&RiskFactor {
            factor: "provenance:review".to_string(),
            contribution: 3,
            rationale: "review: external provenance requires review".to_string(),
        });

        assert_eq!(trace.source, "provenance");
        assert_eq!(trace.label, "provenance:review");
        assert_eq!(trace.contribution, Some(3));
    }

    #[test]
    fn explainability_falls_back_to_score_factor_for_unknown_sources() {
        let factor = RiskFactor {
            factor: "misc:rare_signal".to_string(),
            contribution: 2,
            rationale: "review: unclassified heuristic".to_string(),
        };

        assert_eq!(trace_source_for_risk_factor(&factor), "score_factor");
    }

    #[test]
    fn explainability_aggregates_multiple_factors_into_one_source_bucket() {
        let contributions = summarize_source_contributions(&[
            RiskFactor {
                factor: "composite:secret_exfiltration".to_string(),
                contribution: 18,
                rationale: "critical: graph chain".to_string(),
            },
            RiskFactor {
                factor: "capability_combo:install_network".to_string(),
                contribution: 7,
                rationale: "review: graph combo".to_string(),
            },
        ]);

        assert_eq!(contributions.len(), 1);
        assert_eq!(contributions[0].source, "graph");
        assert_eq!(contributions[0].contribution, 25);
    }

    #[test]
    fn explainability_maps_remote_downloads_to_network_source() {
        let factor = RiskFactor {
            factor: "network:download".to_string(),
            contribution: 6,
            rationale: "review: remote download behavior".to_string(),
        };

        assert_eq!(trace_source_for_risk_factor(&factor), "network");
    }

    #[test]
    fn explainability_prefers_graph_source_when_factor_mentions_remote_behavior() {
        let factor = RiskFactor {
            factor: "composite:remote_mcp_exec".to_string(),
            contribution: 17,
            rationale: "critical: remote graph chain".to_string(),
        };

        assert_eq!(trace_source_for_risk_factor(&factor), "graph");
    }

    #[test]
    fn explainability_does_not_mark_plain_network_factors_as_drift_sensitive() {
        let factor = RiskFactor {
            factor: "network:download".to_string(),
            contribution: 6,
            rationale: "review: outbound fetch".to_string(),
        };

        assert!(!is_drift_sensitive_driver(&factor));
    }

    #[test]
    fn explainability_aggregates_policy_factors_under_one_bucket() {
        let contributions = summarize_source_contributions(&[
            RiskFactor {
                factor: "policy:approval_gap".to_string(),
                contribution: 4,
                rationale: "review: requested approval model is weaker".to_string(),
            },
            RiskFactor {
                factor: "permission:mismatch".to_string(),
                contribution: 5,
                rationale: "review: permissions exceed declared model".to_string(),
            },
        ]);

        assert_eq!(contributions.len(), 1);
        assert_eq!(contributions[0].source, "policy");
        assert_eq!(contributions[0].contribution, 9);
    }

    #[test]
    fn source_bucket_classifier_keeps_bucket_priority_explicit() {
        assert_eq!(
            source_bucket_for_normalized("composite:remote_mcp_exec critical remote chain"),
            "graph"
        );
        assert_eq!(
            source_bucket_for_normalized("policy approval permission gap"),
            "policy"
        );
        assert_eq!(
            source_bucket_for_normalized("publisher lockfile registry drift"),
            "provenance"
        );
        assert_eq!(
            source_bucket_for_normalized("network download remote fetch"),
            "network"
        );
    }

    #[test]
    fn provenance_bucket_wins_over_network_when_registry_signals_are_present() {
        assert_eq!(
            source_bucket_for_normalized("remote registry download publisher drift"),
            "provenance"
        );
    }

    #[test]
    fn unknown_bucket_falls_back_to_score_factor_even_with_generic_remote_wording() {
        assert_eq!(
            source_bucket_for_normalized("telemetry outbound channel without known taxonomy"),
            "score_factor"
        );
    }

    #[test]
    fn policy_bucket_wins_over_network_when_permission_language_is_present() {
        assert_eq!(
            source_bucket_for_normalized("remote permission approval gap"),
            "policy"
        );
    }

    #[test]
    fn source_bucket_returns_none_for_unknown_taxonomy() {
        assert_eq!(source_bucket("custom heuristic text"), None);
    }

    #[test]
    fn explicit_provenance_marker_still_yields_policy_when_permission_words_dominate() {
        assert_eq!(
            source_bucket_for_normalized("provenance:review permission approval gap"),
            "policy"
        );
    }

    #[test]
    fn explicit_provenance_marker_yields_provenance_when_registry_words_dominate() {
        assert_eq!(
            source_bucket_for_normalized("provenance:review lockfile registry drift"),
            "provenance"
        );
    }
}
