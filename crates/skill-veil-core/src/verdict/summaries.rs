use std::collections::BTreeMap;

use crate::findings::{
    ArtifactScope, BlastRadiusLevel, BlastRadiusSummary, DeclaredPermission, Finding,
    HygieneSummary, RecommendedAction, RootCauseGroup, SignalClass, ThreatCategory,
};

pub(super) fn build_blast_radius_summary(
    findings: &[Finding],
    declared_permissions: &[DeclaredPermission],
) -> BlastRadiusSummary {
    let mut factors = Vec::new();
    let mut network_targets = Vec::new();
    let mut severe_count = 0_u32;

    for finding in findings {
        if finding.recommended_action != RecommendedAction::Log {
            severe_count += 1;
        }

        let value = finding.match_value.to_ascii_lowercase();
        if [
            "http://",
            "https://",
            "localhost",
            "127.0.0.1",
            "169.254.169.254",
            ".internal",
            ".local",
        ]
        .iter()
        .any(|needle| value.contains(needle))
        {
            network_targets.push(finding.match_value.clone());
        }

        let factor = match finding.category {
            ThreatCategory::RemoteExec => "remote execution",
            ThreatCategory::DataExfiltration => "data exfiltration",
            ThreatCategory::CredentialExposure => "secret access",
            ThreatCategory::PrivilegeEscalation => "privilege or filesystem impact",
            ThreatCategory::PersistentPromptTampering => "persistent behavior changes",
            ThreatCategory::ToolAbuse => "tool overreach",
            ThreatCategory::AutonomyEscalation => "autonomous high-impact actions",
            ThreatCategory::SupplyChain => "supply chain changes",
            _ => continue,
        };
        if !factors.iter().any(|existing| existing == factor) {
            factors.push(factor.to_string());
        }
    }

    network_targets.sort();
    network_targets.dedup();

    let level = if severe_count >= 3
        || factors
            .iter()
            .any(|factor| factor == "remote execution" || factor == "data exfiltration")
    {
        Some(BlastRadiusLevel::High)
    } else if severe_count >= 1 || !declared_permissions.is_empty() || !factors.is_empty() {
        Some(BlastRadiusLevel::Medium)
    } else {
        Some(BlastRadiusLevel::Low)
    };

    BlastRadiusSummary {
        level,
        factors,
        network_targets,
        declared_permissions: declared_permissions.to_vec(),
    }
}

pub(super) fn is_conclusive_supporting_malicious(finding: &Finding) -> bool {
    if finding.artifact_scope != ArtifactScope::SupportingArtifact
        || finding.signal_class != SignalClass::MaliciousBehavior
        || finding.recommended_action != RecommendedAction::Block
    {
        return false;
    }

    let value = finding.match_value.to_ascii_lowercase();
    let has_remote_indicator = [
        "http://",
        "https://",
        "curl ",
        "wget ",
        "fetch(",
        "requests.get",
        "urllib.request.urlopen",
        "invoke-webrequest",
        "iwr ",
    ]
    .iter()
    .any(|needle| value.contains(needle));
    let has_sensitive_payload = ["cookie", "token", "secret", "session"]
        .iter()
        .any(|needle| value.contains(needle));
    let has_transmit_verb = ["send", "post", "upload", "forward", "exfiltrate"]
        .iter()
        .any(|needle| value.contains(needle));
    let has_exfil_channel = [
        "discord.com/api/webhooks",
        "api.telegram.org/bot",
        "smtp.",
        "sendgrid",
        "mailgun",
    ]
    .iter()
    .any(|needle| value.contains(needle));

    match finding.category {
        ThreatCategory::RemoteExec => has_remote_indicator,
        ThreatCategory::DataExfiltration => {
            (has_sensitive_payload && has_transmit_verb) || has_exfil_channel
        }
        ThreatCategory::PersistentPromptTampering => true,
        _ => false,
    }
}

pub(super) fn build_root_cause_groups(findings: &[Finding]) -> Vec<RootCauseGroup> {
    let mut groups =
        BTreeMap::<(ArtifactScope, ThreatCategory, SignalClass), RootCauseGroup>::new();

    for finding in findings {
        let key = (
            finding.artifact_scope,
            finding.category,
            finding.signal_class,
        );
        groups
            .entry(key)
            .and_modify(|group| {
                group.finding_count += 1;
                group.strongest_action =
                    RecommendedAction::max(group.strongest_action, finding.recommended_action);
                if !group.representative_rules.contains(&finding.rule_id) {
                    group.representative_rules.push(finding.rule_id.clone());
                    group.representative_rules.sort();
                    group.representative_rules.truncate(5);
                }
            })
            .or_insert_with(|| RootCauseGroup {
                scope: finding.artifact_scope,
                category: finding.category,
                signal_class: finding.signal_class,
                finding_count: 1,
                strongest_action: finding.recommended_action,
                representative_rules: vec![finding.rule_id.clone()],
            });
    }

    let mut groups: Vec<_> = groups.into_values().collect();
    groups.sort_by(|left, right| {
        right
            .strongest_action
            .priority()
            .cmp(&left.strongest_action.priority())
            .then_with(|| right.finding_count.cmp(&left.finding_count))
    });
    groups
}

pub(super) fn build_hygiene_summary(findings: &[Finding]) -> HygieneSummary {
    let mut top_rules = BTreeMap::<String, usize>::new();
    let mut package_root_findings = 0_usize;
    let mut supporting_findings = 0_usize;

    for finding in findings {
        if finding.signal_class != SignalClass::Hygiene {
            continue;
        }

        match finding.artifact_scope {
            ArtifactScope::PackageRootArtifact | ArtifactScope::AgentEntrypoint => {
                package_root_findings += 1;
            }
            ArtifactScope::SupportingArtifact => supporting_findings += 1,
        }
        *top_rules.entry(finding.rule_id.clone()).or_insert(0) += 1;
    }

    let mut top_rules: Vec<_> = top_rules.into_iter().collect();
    top_rules.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));

    HygieneSummary {
        package_root_findings,
        supporting_findings,
        top_rules: top_rules
            .into_iter()
            .map(|(rule, _)| rule)
            .take(5)
            .collect(),
    }
}
