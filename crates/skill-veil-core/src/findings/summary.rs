use super::capability_scoring::graph_risk_context;
use super::{
    Finding, RecommendedAction, Severity, ThreatCategory, EXECUTABLE_SCRIPT_RISK_MULTIPLIER,
    MAX_RISK_SCORE, RISK_THRESHOLD_APPROVAL, RISK_THRESHOLD_BLOCK,
};
use crate::artifact_graph::ArtifactGraph;
use serde::{Deserialize, Serialize};

/// File extensions that mark an artifact as an executable script for the
/// `EXECUTABLE_SCRIPT_RISK_MULTIPLIER` amplifier. Lowercase, no dot.
const SCRIPT_EXTENSIONS: &[&str] = &[
    "py", "pyw", "js", "mjs", "cjs", "ts", "sh", "bash", "zsh", "ps1", "psm1", "rb", "pl", "php",
];

/// `true` when any graph artifact path carries a known script extension —
/// the structural "package ships an executable script" signal.
#[must_use]
fn graph_references_executable_script(graph: &ArtifactGraph) -> bool {
    graph.nodes.iter().any(|node| {
        node.path
            .rsplit('.')
            .next()
            .filter(|ext| *ext != node.path)
            .map(str::to_ascii_lowercase)
            .is_some_and(|ext| SCRIPT_EXTENSIONS.contains(&ext.as_str()))
    })
}

/// Summary of all findings for a skill
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    /// Total number of findings
    pub total_findings: usize,
    /// Breakdown by severity
    pub by_severity: SeverityCounts,
    /// Breakdown by category
    pub by_category: Vec<(ThreatCategory, usize)>,
    /// Overall risk score (0-100)
    pub risk_score: u32,
    /// Recommended action based on score
    pub recommended_action: RecommendedAction,
    /// Explainable score factors that contributed to the risk score
    pub score_breakdown: Vec<RiskFactor>,
    /// Contextual triggers that forced or escalated the recommended action.
    pub action_triggers: Vec<ActionTrigger>,
}

/// Count of findings by severity
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

/// Explainable score factor aggregated across findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor: String,
    pub contribution: u32,
    pub rationale: String,
}

/// Explicit contextual reason that escalated enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTrigger {
    pub action: RecommendedAction,
    pub factor: String,
    pub rationale: String,
}

impl FindingSummary {
    /// Calculate summary from a list of findings
    #[must_use]
    pub fn from_findings(findings: &[Finding]) -> Self {
        Self::from_findings_and_graph(findings, &ArtifactGraph::new())
    }

    /// Calculate summary from findings plus graph-derived contextual risk.
    #[must_use]
    pub fn from_findings_and_graph(findings: &[Finding], artifact_graph: &ArtifactGraph) -> Self {
        let (by_severity, category_map, mut factor_map, findings_score) =
            aggregate_findings(findings);

        let (graph_score, graph_action, graph_factors, mut action_triggers) =
            graph_risk_context(artifact_graph);

        for factor in graph_factors {
            factor_map
                .entry(factor.factor.clone())
                .and_modify(|existing| existing.contribution += factor.contribution)
                .or_insert(factor);
        }

        let base_score = findings_score + graph_score as f32;
        let total_score = if graph_references_executable_script(artifact_graph) {
            let amplified = base_score * EXECUTABLE_SCRIPT_RISK_MULTIPLIER;
            let added = (amplified - base_score).max(0.0).round() as u32;
            if added > 0 {
                let key = "artifact:executable_script".to_string();
                factor_map
                    .entry(key.clone())
                    .and_modify(|f| f.contribution += added)
                    .or_insert(RiskFactor {
                        factor: key,
                        contribution: added,
                        rationale: "Package references an executable script \
                                    (empirically 2.12x more likely to be vulnerable)"
                            .to_string(),
                    });
            }
            amplified
        } else {
            base_score
        };
        let risk_score = normalize_score(total_score);
        let recommended_action = select_recommended_action(risk_score, findings, graph_action);

        let mut by_category: Vec<_> = category_map.into_iter().collect();
        by_category.sort_by_key(|(category, _)| *category);
        let mut score_breakdown: Vec<_> = factor_map.into_values().collect();
        // Tie-breaker by `factor` keeps the order deterministic when two
        // entries share the same primary key (contribution / action).
        // Without it, `HashMap` iteration randomness leaks into JSON/SARIF
        // output and breaks reproducibility between runs.
        score_breakdown.sort_by(|left, right| {
            right
                .contribution
                .cmp(&left.contribution)
                .then_with(|| left.factor.cmp(&right.factor))
        });
        action_triggers.sort_by(|left, right| {
            right
                .action
                .cmp(&left.action)
                .then_with(|| left.factor.cmp(&right.factor))
        });

        Self {
            total_findings: findings.len(),
            by_severity,
            by_category,
            risk_score,
            recommended_action,
            score_breakdown,
            action_triggers,
        }
    }

    /// Return a clone with `risk_score` adjusted by `delta` (clamped to 0–100)
    /// AND `recommended_action` recomputed so the two stay coherent.
    ///
    /// # Coherence contract
    ///
    /// After this call, `(risk_score, recommended_action)` always satisfy the
    /// same threshold relationship that `from_findings_and_graph` produced
    /// originally: `Block ↔ score ≥ RISK_THRESHOLD_BLOCK`,
    /// `RequireApproval ↔ score ≥ RISK_THRESHOLD_APPROVAL`, else `Log`.
    /// Calibration only ever LOWERS the score, so we monotonically downgrade
    /// the action — never upgrade it past what the original aggregation
    /// produced. Without this recomputation, callers that read
    /// `recommended_action` on a calibrated clone would see the pre-
    /// calibration verdict and contradict the score.
    #[must_use]
    pub fn with_risk_adjustment(&self, delta: i32) -> Self {
        let mut adjusted = self.clone();
        let new_score = i64::from(self.risk_score)
            .saturating_add(i64::from(delta))
            .clamp(0, i64::from(MAX_RISK_SCORE)) as u32;
        adjusted.risk_score = new_score;
        let new_action = downgraded_action_for_score(self.recommended_action, new_score);
        adjusted.recommended_action = new_action;
        // Drop triggers that asserted an action stronger than the
        // post-calibration `recommended_action`. Otherwise the audit trail
        // contradicts itself: the summary says `RequireApproval` while a
        // trigger still claims "force Block because X". Triggers below or
        // equal to the new action remain truthful and are preserved.
        adjusted.action_triggers.retain(|t| t.action <= new_action);
        adjusted
    }
}

/// Compute the action that matches `score` AFTER calibration, never
/// upgrading past `original`. Calibration only weakens evidence, so the
/// post-adjustment action must be `<= original`.
fn downgraded_action_for_score(original: RecommendedAction, score: u32) -> RecommendedAction {
    let score_tier = score_to_action(score);
    score_tier.min(original)
}

type FactorMap = std::collections::HashMap<String, RiskFactor>;
type CategoryMap = std::collections::HashMap<ThreatCategory, usize>;

fn aggregate_findings(findings: &[Finding]) -> (SeverityCounts, CategoryMap, FactorMap, f32) {
    let mut by_severity = SeverityCounts::default();
    let mut category_map = CategoryMap::new();
    let mut factor_map = FactorMap::new();
    let mut total_score: f32 = 0.0;

    for finding in findings {
        match finding.severity {
            Severity::Low => by_severity.low += 1,
            Severity::Medium => by_severity.medium += 1,
            Severity::High => by_severity.high += 1,
            Severity::Critical => by_severity.critical += 1,
        }
        *category_map.entry(finding.category).or_insert(0) += 1;
        total_score += finding.weighted_score();
        accumulate_evidence_factor(&mut factor_map, finding);
        accumulate_artifact_factor(&mut factor_map, finding);
    }

    (by_severity, category_map, factor_map, total_score)
}

fn select_recommended_action(
    risk_score: u32,
    findings: &[Finding],
    graph_action: RecommendedAction,
) -> RecommendedAction {
    let score_based = score_to_action(risk_score);
    let finding_based = findings.iter().fold(RecommendedAction::Log, |acc, f| {
        acc.max(f.recommended_action)
    });
    score_based.max(finding_based).max(graph_action)
}

fn accumulate_evidence_factor(factors: &mut FactorMap, finding: &Finding) {
    let key = format!("evidence:{}", finding.evidence_kind);
    let weight = finding.evidence_kind.weight();
    factors
        .entry(key.clone())
        .and_modify(|f| f.contribution += weight)
        .or_insert(RiskFactor {
            factor: key,
            contribution: weight,
            rationale: finding.evidence_kind.description().to_string(),
        });
}

fn accumulate_artifact_factor(factors: &mut FactorMap, finding: &Finding) {
    let key = format!("artifact:{}", finding.artifact_kind);
    factors
        .entry(key.clone())
        .and_modify(|f| f.contribution += 1)
        .or_insert(RiskFactor {
            factor: key,
            contribution: 1,
            rationale: "Risk observed in this artifact class".to_string(),
        });
}

fn normalize_score(total: f32) -> u32 {
    if total.is_finite() {
        return total.clamp(0.0, MAX_RISK_SCORE as f32).round() as u32;
    }
    // Defense-in-depth: a non-finite total means an invariant up-stream
    // (sanitized confidence in the builder, finite severity weights) was
    // violated. `MAX_RISK_SCORE` is the right fail-safe for a security
    // scanner, but we MUST NOT pass silently — surface the breach so the
    // upstream bug can be diagnosed. Mirrors the `merge_into` invariant
    // guard in `findings/dedup.rs`.
    debug_assert!(
        total.is_finite(),
        "normalize_score: total must be finite (sanitized in builder); got {total}",
    );
    tracing::warn!(
        total = ?total,
        "normalize_score received non-finite total; defaulting to MAX_RISK_SCORE",
    );
    MAX_RISK_SCORE
}

fn score_to_action(risk_score: u32) -> RecommendedAction {
    if risk_score >= RISK_THRESHOLD_BLOCK {
        RecommendedAction::Block
    } else if risk_score >= RISK_THRESHOLD_APPROVAL {
        RecommendedAction::RequireApproval
    } else {
        RecommendedAction::Log
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_breakdown_and_action_triggers_use_factor_tie_breaker() {
        // Build two RiskFactors with identical contribution; sort_by must
        // resolve the tie via the `factor` field (alphabetical) instead of
        // leaving it to HashMap iteration order.
        let mut breakdown = [
            RiskFactor {
                factor: "z_factor".into(),
                contribution: 10,
                rationale: "x".into(),
            },
            RiskFactor {
                factor: "a_factor".into(),
                contribution: 10,
                rationale: "x".into(),
            },
        ];
        breakdown.sort_by(|left, right| {
            right
                .contribution
                .cmp(&left.contribution)
                .then_with(|| left.factor.cmp(&right.factor))
        });
        assert_eq!(breakdown[0].factor, "a_factor");
        assert_eq!(breakdown[1].factor, "z_factor");

        let mut triggers = [
            ActionTrigger {
                action: RecommendedAction::Block,
                factor: "z_trig".into(),
                rationale: "x".into(),
            },
            ActionTrigger {
                action: RecommendedAction::Block,
                factor: "a_trig".into(),
                rationale: "x".into(),
            },
        ];
        triggers.sort_by(|left, right| {
            right
                .action
                .cmp(&left.action)
                .then_with(|| left.factor.cmp(&right.factor))
        });
        assert_eq!(triggers[0].factor, "a_trig");
        assert_eq!(triggers[1].factor, "z_trig");
    }

    fn graph_with_path(path: &str, kind: crate::findings::ArtifactKind) -> ArtifactGraph {
        ArtifactGraph {
            nodes: vec![crate::artifact_graph::ArtifactNode {
                path: path.to_string(),
                kind,
                capabilities: Vec::new(),
            }],
            edges: Vec::new(),
        }
    }

    fn mid_band_finding() -> Finding {
        Finding::builder("R_MID", ThreatCategory::SupplyChain)
            .severity(Severity::Medium)
            .confidence(0.7)
            .build()
    }

    /// Contract: a package that references an executable script gets its
    /// aggregated risk score amplified by `EXECUTABLE_SCRIPT_RISK_MULTIPLIER`
    /// and an audited `artifact:executable_script` factor in the breakdown.
    #[test]
    fn executable_script_amplifies_risk_score() {
        use crate::findings::ArtifactKind;
        let findings = vec![mid_band_finding()];
        let plain = FindingSummary::from_findings_and_graph(
            &findings,
            &graph_with_path("README.md", ArtifactKind::GenericArtifact),
        );
        let scripted = FindingSummary::from_findings_and_graph(
            &findings,
            &graph_with_path("scripts/setup.py", ArtifactKind::ReferencedArtifact),
        );
        assert!(
            plain.risk_score < MAX_RISK_SCORE,
            "test base must stay sub-cap"
        );
        assert!(
            scripted.risk_score > plain.risk_score,
            "executable script must amplify: {} !> {}",
            scripted.risk_score,
            plain.risk_score
        );
        assert!(scripted
            .score_breakdown
            .iter()
            .any(|f| f.factor == "artifact:executable_script"));
    }

    /// Contract (negative): a package with no script artifact is scored
    /// identically to the no-graph path and carries no amplifier factor.
    #[test]
    fn no_executable_script_leaves_score_unamplified() {
        use crate::findings::ArtifactKind;
        let findings = vec![mid_band_finding()];
        let doc_graph = FindingSummary::from_findings_and_graph(
            &findings,
            &graph_with_path("SKILL.md", ArtifactKind::SkillDocument),
        );
        let no_graph = FindingSummary::from_findings(&findings);
        assert_eq!(doc_graph.risk_score, no_graph.risk_score);
        assert!(!doc_graph
            .score_breakdown
            .iter()
            .any(|f| f.factor == "artifact:executable_script"));
    }

    #[test]
    fn graph_references_executable_script_matches_scripts_only() {
        use crate::findings::ArtifactKind;
        assert!(graph_references_executable_script(&graph_with_path(
            "a/b/setup.py",
            ArtifactKind::ReferencedArtifact
        )));
        assert!(graph_references_executable_script(&graph_with_path(
            "hook.SH",
            ArtifactKind::ReferencedArtifact
        )));
        assert!(!graph_references_executable_script(&graph_with_path(
            "SKILL.md",
            ArtifactKind::SkillDocument
        )));
        assert!(!graph_references_executable_script(&graph_with_path(
            "Makefile",
            ArtifactKind::GenericArtifact
        )));
        assert!(!graph_references_executable_script(&ArtifactGraph::new()));
    }

    fn summary_with(score: u32, action: RecommendedAction) -> FindingSummary {
        FindingSummary {
            total_findings: 0,
            by_severity: SeverityCounts::default(),
            by_category: Vec::new(),
            risk_score: score,
            recommended_action: action,
            score_breakdown: Vec::new(),
            action_triggers: Vec::new(),
        }
    }

    /// Contract: `with_risk_adjustment` keeps `(risk_score, recommended_action)`
    /// coherent. A calibration delta that drops the score below
    /// `RISK_THRESHOLD_BLOCK` MUST also downgrade `Block` to `RequireApproval`
    /// (or `Log`), never leave the action stuck at the pre-calibration tier.
    #[test]
    fn with_risk_adjustment_downgrades_action_when_score_crosses_threshold() {
        let s = summary_with(55, RecommendedAction::Block);
        let adjusted = s.with_risk_adjustment(-20); // 55 - 20 = 35
        assert_eq!(adjusted.risk_score, 35);
        assert_eq!(
            adjusted.recommended_action,
            RecommendedAction::RequireApproval,
            "score below RISK_THRESHOLD_BLOCK must drop Block down to RequireApproval"
        );
    }

    #[test]
    fn with_risk_adjustment_drops_to_log_below_approval_threshold() {
        let s = summary_with(25, RecommendedAction::RequireApproval);
        let adjusted = s.with_risk_adjustment(-20); // 25 - 20 = 5
        assert_eq!(adjusted.risk_score, 5);
        assert_eq!(adjusted.recommended_action, RecommendedAction::Log);
    }

    /// Contract: calibration NEVER upgrades the action. A positive delta is
    /// not used today by the calibration pipeline, but if a future change
    /// passes a non-negative delta we still cap at the original action.
    #[test]
    fn with_risk_adjustment_never_upgrades_action() {
        let s = summary_with(10, RecommendedAction::Log);
        let adjusted = s.with_risk_adjustment(100); // clamps to 100, action would
                                                    // be Block per score_to_action
        assert_eq!(adjusted.risk_score, 100);
        assert_eq!(
            adjusted.recommended_action,
            RecommendedAction::Log,
            "calibration must not upgrade past the original action"
        );
    }

    #[test]
    fn with_risk_adjustment_clamps_score() {
        let s = summary_with(5, RecommendedAction::Log);
        let adjusted = s.with_risk_adjustment(-100);
        assert_eq!(adjusted.risk_score, 0);
        assert_eq!(adjusted.recommended_action, RecommendedAction::Log);
    }

    /// Contract: a finite `total` clamps into `[0, 100]` and rounds to u32.
    /// Positive-case regression guard before the non-finite branch.
    #[test]
    fn normalize_score_finite_input_clamps_and_rounds() {
        assert_eq!(normalize_score(0.0), 0);
        assert_eq!(normalize_score(50.4), 50);
        assert_eq!(normalize_score(50.6), 51);
        assert_eq!(normalize_score(100.0), 100);
        assert_eq!(normalize_score(150.0), 100);
        assert_eq!(normalize_score(-10.0), 0);
    }

    /// Contract: a non-finite `total` (NaN or ±Inf) MUST default to Block (100)
    /// — pre-existing fail-safe behaviour. The fix added a `tracing::warn!`
    /// and a `debug_assert!` so the upstream invariant breach surfaces, but
    /// the release-build return value is unchanged.
    ///
    /// The `debug_assert!` would fire under `cfg(debug_assertions)`, so we
    /// gate the test to only run when assertions are disabled (release
    /// profile / `--release` flag) or wrap it in a panic-catch under debug
    /// — choosing the simpler approach: only assert the release contract.
    #[test]
    #[cfg(not(debug_assertions))]
    fn normalize_score_non_finite_input_falls_back_to_block() {
        assert_eq!(normalize_score(f32::NAN), 100);
        assert_eq!(normalize_score(f32::INFINITY), 100);
        assert_eq!(normalize_score(f32::NEG_INFINITY), 100);
    }
}
