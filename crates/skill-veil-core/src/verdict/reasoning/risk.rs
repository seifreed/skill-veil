use super::model::{HeuristicSeverity, RiskContributionSpec};
use crate::domain_types::ProvenanceTrustLevel;
use crate::findings::{CompositeCapability, ProvenanceSummary};

pub(crate) fn composite_capability_risk_bonus(
    composite_capabilities: &[CompositeCapability],
    provenance: &ProvenanceSummary,
) -> u32 {
    let composite_specs = composite_factor_specs(composite_capabilities);

    composite_contribution_sum(&composite_specs) + provenance_bonus(provenance)
}

pub(crate) fn composite_risk_factors(
    composite_capabilities: &[CompositeCapability],
    provenance: &ProvenanceSummary,
) -> Vec<crate::findings::RiskFactor> {
    let mut specs = composite_factor_specs(composite_capabilities);
    push_provenance_factor(&mut specs, provenance);
    composite_specs_to_risk_factors(specs)
}

fn composite_factor_specs(
    composite_capabilities: &[CompositeCapability],
) -> Vec<RiskContributionSpec> {
    composite_capabilities
        .iter()
        .map(composite_factor_spec)
        .collect()
}

fn composite_factor_spec(capability: &CompositeCapability) -> RiskContributionSpec {
    match capability {
        CompositeCapability::SecretExfiltration => composite_spec(
            "composite:secret_exfiltration",
            18,
            HeuristicSeverity::Critical,
            "Secrets access is paired with outbound network behavior",
        ),
        CompositeCapability::ShellDownloadExec => composite_spec(
            "composite:shell_download_exec",
            14,
            HeuristicSeverity::Elevated,
            "Execution is paired with download or remote fetch behavior",
        ),
        CompositeCapability::BrowserWriteChain => composite_spec(
            "composite:browser_write_chain",
            10,
            HeuristicSeverity::Review,
            "Browser tooling is paired with local write capability",
        ),
        CompositeCapability::BrowserSessionExfiltration => composite_spec(
            "composite:browser_session_exfiltration",
            16,
            HeuristicSeverity::Critical,
            "Browser or session material is paired with outbound network behavior",
        ),
        CompositeCapability::RemoteMcpNoAuth => composite_spec(
            "composite:remote_mcp_no_auth",
            16,
            HeuristicSeverity::Critical,
            "Remote MCP access is paired with a missing authentication model",
        ),
        CompositeCapability::IdentityNetworkChain => composite_spec(
            "composite:identity_network_chain",
            12,
            HeuristicSeverity::Elevated,
            "Identity or OAuth access is paired with outbound network behavior",
        ),
        CompositeCapability::WorkflowRemoteExec => composite_spec(
            "composite:workflow_remote_exec",
            15,
            HeuristicSeverity::Elevated,
            "Workflow automation combines remote fetch behavior with execution",
        ),
        CompositeCapability::WorkflowExecPersistence => composite_spec(
            "composite:workflow_exec_persistence",
            18,
            HeuristicSeverity::Critical,
            "Workflow automation combines remote fetch, execution, and persistence behavior",
        ),
        CompositeCapability::InstallHookPersistence => composite_spec(
            "composite:install_hook_persistence",
            13,
            HeuristicSeverity::Elevated,
            "Install-hook execution is paired with persistence-like behavior",
        ),
        CompositeCapability::RemoteMcpExec => composite_spec(
            "composite:remote_mcp_exec",
            17,
            HeuristicSeverity::Critical,
            "Remote MCP exposure is paired with execution-capable tooling",
        ),
        CompositeCapability::RemoteMcpNoAuthExec => composite_spec(
            "composite:remote_mcp_no_auth_exec",
            19,
            HeuristicSeverity::Critical,
            "Remote MCP exposure combines missing authentication with execution-capable tooling",
        ),
        CompositeCapability::WritePersistenceChain => composite_spec(
            "composite:write_persistence_chain",
            11,
            HeuristicSeverity::Review,
            "Local writes are paired with durable persistence surfaces",
        ),
    }
}

fn provenance_factor_spec(provenance: &ProvenanceSummary) -> Option<RiskContributionSpec> {
    match provenance.trust_level {
        ProvenanceTrustLevel::Untrusted => Some(composite_spec(
            "provenance:untrusted",
            8,
            HeuristicSeverity::Elevated,
            "Remote provenance is untrusted due to opaque, transient, or direct-IP origins",
        )),
        ProvenanceTrustLevel::Review => Some(composite_spec(
            "provenance:review",
            3,
            HeuristicSeverity::Review,
            "Remote provenance requires review due to external origins",
        )),
        ProvenanceTrustLevel::Trusted => None,
    }
}

fn composite_spec(
    factor: &'static str,
    contribution: u32,
    severity: HeuristicSeverity,
    rationale: &'static str,
) -> RiskContributionSpec {
    RiskContributionSpec {
        factor,
        contribution,
        severity,
        rationale,
    }
}

fn provenance_bonus(provenance: &ProvenanceSummary) -> u32 {
    provenance_factor_spec(provenance)
        .map(|spec| spec.contribution)
        .unwrap_or(0)
}

fn composite_contribution_sum(specs: &[RiskContributionSpec]) -> u32 {
    specs.iter().map(spec_contribution).sum()
}

fn push_provenance_factor(
    factors: &mut Vec<RiskContributionSpec>,
    provenance: &ProvenanceSummary,
) {
    if let Some(provenance_factor) = provenance_factor_spec(provenance) {
        factors.push(provenance_factor);
    }
}

fn composite_specs_to_risk_factors(
    specs: Vec<RiskContributionSpec>,
) -> Vec<crate::findings::RiskFactor> {
    specs.into_iter()
        .map(RiskContributionSpec::into_risk_factor)
        .collect()
}

fn spec_contribution(spec: &RiskContributionSpec) -> u32 {
    spec.contribution
}

#[cfg(test)]
#[allow(dead_code)]
fn has_provenance_factor(specs: &[RiskContributionSpec]) -> bool {
    specs.iter()
        .any(|spec| spec.factor.starts_with("provenance:"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_types::{LockfileCoverageSummary, PublisherConsistency};
    fn empty_provenance(trust_level: ProvenanceTrustLevel) -> ProvenanceSummary {
        ProvenanceSummary {
            trust_level,
            publisher_consistency: PublisherConsistency::Unknown,
            lockfile_coverage: LockfileCoverageSummary::default(),
            ..ProvenanceSummary::default()
        }
    }

    #[test]
    fn composite_bonus_includes_provenance_amplification() {
        let bonus = composite_capability_risk_bonus(
            &[CompositeCapability::SecretExfiltration],
            &empty_provenance(ProvenanceTrustLevel::Untrusted),
        );
        assert_eq!(bonus, 26);
    }

    #[test]
    fn composite_risk_factors_include_normalized_severity_prefix() {
        let factors = composite_risk_factors(
            &[CompositeCapability::RemoteMcpNoAuthExec],
            &empty_provenance(ProvenanceTrustLevel::Review),
        );
        assert!(factors
            .iter()
            .any(|factor| factor.rationale.starts_with("critical:")));
        assert!(factors
            .iter()
            .any(|factor| factor.factor == "provenance:review"));
    }

    #[test]
    fn trusted_provenance_does_not_add_extra_risk_factor() {
        let factors = composite_risk_factors(
            &[CompositeCapability::BrowserWriteChain],
            &empty_provenance(ProvenanceTrustLevel::Trusted),
        );
        assert_eq!(factors.len(), 1);
        assert_eq!(factors[0].factor, "composite:browser_write_chain");
    }

    #[test]
    fn multiple_composites_and_untrusted_provenance_accumulate() {
        let bonus = composite_capability_risk_bonus(
            &[
                CompositeCapability::SecretExfiltration,
                CompositeCapability::RemoteMcpNoAuthExec,
            ],
            &empty_provenance(ProvenanceTrustLevel::Untrusted),
        );
        assert_eq!(bonus, 45);
    }

    #[test]
    fn composite_contribution_sum_adds_contributions_without_reinterpreting_severity() {
        let total = composite_contribution_sum(&[
            RiskContributionSpec {
                factor: "a",
                contribution: 5,
                severity: HeuristicSeverity::Review,
                rationale: "a",
            },
            RiskContributionSpec {
                factor: "b",
                contribution: 9,
                severity: HeuristicSeverity::Critical,
                rationale: "b",
            },
        ]);
        assert_eq!(total, 14);
    }

    #[test]
    fn composite_risk_factors_keep_composites_before_provenance_factor() {
        let factors = composite_risk_factors(
            &[
                CompositeCapability::SecretExfiltration,
                CompositeCapability::BrowserWriteChain,
            ],
            &empty_provenance(ProvenanceTrustLevel::Review),
        );
        assert_eq!(factors[0].factor, "composite:secret_exfiltration");
        assert_eq!(factors[1].factor, "composite:browser_write_chain");
        assert_eq!(factors[2].factor, "provenance:review");
    }

    #[test]
    fn push_provenance_factor_appends_only_when_needed() {
        let mut factors = composite_factor_specs(&[CompositeCapability::BrowserWriteChain]);
        push_provenance_factor(&mut factors, &empty_provenance(ProvenanceTrustLevel::Trusted));
        assert_eq!(factors.len(), 1);

        push_provenance_factor(&mut factors, &empty_provenance(ProvenanceTrustLevel::Review));
        assert_eq!(factors.len(), 2);
        assert_eq!(factors[1].factor, "provenance:review");
    }

    #[test]
    fn composite_specs_to_risk_factors_preserves_order() {
        let factors = composite_specs_to_risk_factors(vec![
            RiskContributionSpec {
                factor: "a",
                contribution: 1,
                severity: HeuristicSeverity::Review,
                rationale: "a",
            },
            RiskContributionSpec {
                factor: "b",
                contribution: 2,
                severity: HeuristicSeverity::Critical,
                rationale: "b",
            },
        ]);

        assert_eq!(factors[0].factor, "a");
        assert_eq!(factors[1].factor, "b");
        assert!(factors[1].rationale.starts_with("critical:"));
    }

    #[test]
    fn provenance_bonus_matches_optional_provenance_factor_contribution() {
        assert_eq!(provenance_bonus(&empty_provenance(ProvenanceTrustLevel::Trusted)), 0);
        assert_eq!(provenance_bonus(&empty_provenance(ProvenanceTrustLevel::Review)), 3);
        assert_eq!(provenance_bonus(&empty_provenance(ProvenanceTrustLevel::Untrusted)), 8);
    }

    #[test]
    fn review_provenance_bonus_is_added_to_composite_sum_without_reordering() {
        let bonus = composite_capability_risk_bonus(
            &[CompositeCapability::BrowserWriteChain, CompositeCapability::WritePersistenceChain],
            &empty_provenance(ProvenanceTrustLevel::Review),
        );
        assert_eq!(bonus, 24);
    }

    #[test]
    fn trusted_provenance_bonus_leaves_composite_sum_unchanged() {
        let bonus = composite_capability_risk_bonus(
            &[CompositeCapability::WritePersistenceChain],
            &empty_provenance(ProvenanceTrustLevel::Trusted),
        );
        assert_eq!(bonus, 11);
    }

    #[test]
    fn composite_specs_to_risk_factors_keeps_provenance_factor_last_when_appended() {
        let mut specs = composite_factor_specs(&[CompositeCapability::BrowserWriteChain]);
        push_provenance_factor(&mut specs, &empty_provenance(ProvenanceTrustLevel::Review));
        let factors = composite_specs_to_risk_factors(specs);
        assert_eq!(factors.last().map(|factor| factor.factor.as_str()), Some("provenance:review"));
    }

    #[test]
    fn spec_contribution_reads_contribution_without_touching_severity() {
        let spec = RiskContributionSpec {
            factor: "demo",
            contribution: 7,
            severity: HeuristicSeverity::Critical,
            rationale: "demo",
        };
        assert_eq!(spec_contribution(&spec), 7);
    }

    #[test]
    fn has_provenance_factor_only_matches_provenance_specs() {
        let mut specs = composite_factor_specs(&[CompositeCapability::BrowserWriteChain]);
        assert!(!has_provenance_factor(&specs));
        push_provenance_factor(&mut specs, &empty_provenance(ProvenanceTrustLevel::Review));
        assert!(has_provenance_factor(&specs));
    }
}
