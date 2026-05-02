use std::collections::BTreeMap;

use crate::findings::{ArtifactScope, Finding, HygieneSummary, SignalClass};

/// Cap on the number of hygiene rule ids surfaced in `HygieneSummary::top_rules`.
/// Keeps the verdict report's hygiene preview compact for downstream
/// renderers (text, SARIF, SHIELD) without losing the dominant signal.
const MAX_HYGIENE_TOP_RULES: usize = 5;

pub(super) fn build_hygiene_summary(findings: &[Finding]) -> HygieneSummary {
    let mut top_rules = BTreeMap::<String, usize>::new();
    let mut package_root_findings = 0_usize;
    let mut entrypoint_findings = 0_usize;
    let mut supporting_findings = 0_usize;

    for finding in findings {
        if finding.signal_class != SignalClass::Hygiene {
            continue;
        }
        if finding.suppression.is_some() {
            continue;
        }

        match finding.artifact_scope {
            ArtifactScope::PackageRootArtifact => package_root_findings += 1,
            ArtifactScope::SupportingArtifact => supporting_findings += 1,
            ArtifactScope::AgentEntrypoint => entrypoint_findings += 1,
        }
        *top_rules.entry(finding.rule_id.clone()).or_insert(0) += 1;
    }

    let mut top_rules: Vec<_> = top_rules.into_iter().collect();
    top_rules.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    HygieneSummary {
        package_root_findings,
        entrypoint_findings,
        supporting_findings,
        top_rules: top_rules
            .into_iter()
            .map(|(rule, _)| rule)
            .take(MAX_HYGIENE_TOP_RULES)
            .collect(),
    }
}
