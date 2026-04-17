use crate::findings::{
    BlastRadiusLevel, BlastRadiusSummary, DeclaredPermission, Finding, RecommendedAction,
    SignalClass, ThreatCategory,
};

const LOCAL_INDICATORS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "[::1]",
    ".local",
    ".internal",
];
const EXTERNAL_PROTOCOLS: &[&str] = &["http://", "https://", "169.254.169.254"];

pub(super) fn build_blast_radius_summary(
    findings: &[Finding],
    declared_permissions: &[DeclaredPermission],
) -> BlastRadiusSummary {
    let mut factors = Vec::new();
    let mut severe_factors = Vec::new();
    let mut network_targets = Vec::new();
    let mut severe_count = 0_u32;

    for finding in findings {
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
        if finding.recommended_action != RecommendedAction::Log
            && finding.signal_class != SignalClass::Hygiene
            && !is_local_only_target(&value)
        {
            severe_count += 1;
            if !severe_factors.iter().any(|existing| existing == factor) {
                severe_factors.push(factor.to_string());
            }
        }
        if !factors.iter().any(|existing| existing == factor) {
            factors.push(factor.to_string());
        }
    }

    network_targets.sort();
    network_targets.dedup();

    let level = if severe_count >= 3
        || (severe_count >= 2
            && severe_factors
                .iter()
                .any(|factor| factor == "remote execution" || factor == "data exfiltration"))
    {
        BlastRadiusLevel::High
    } else if severe_count >= 1
        || !declared_permissions.is_empty()
        || findings.iter().any(|f| {
            f.signal_class != SignalClass::Hygiene && f.recommended_action != RecommendedAction::Log
        })
    {
        BlastRadiusLevel::Medium
    } else {
        BlastRadiusLevel::Low
    };

    BlastRadiusSummary {
        level,
        factors,
        network_targets,
        declared_permissions: declared_permissions.to_vec(),
    }
}

fn is_local_only_target(value: &str) -> bool {
    if !LOCAL_INDICATORS.iter().any(|ind| value.contains(ind)) {
        return false;
    }
    let has_non_local_external = value
        .split_whitespace()
        .any(|token| is_token_external(token) || token_has_embedded_external_url(token));
    !has_non_local_external
}

fn is_token_external(token: &str) -> bool {
    let is_local = LOCAL_INDICATORS.iter().any(|ind| token.contains(ind));
    let is_external = EXTERNAL_PROTOCOLS.iter().any(|ind| token.contains(ind))
        || (token.contains("://") && !is_local);
    is_external && !is_local
}

// A token like "http://localhost/redirect?to=https://evil.com" is local by hostname
// but embeds an external URL in query params — not local-only.
fn token_has_embedded_external_url(token: &str) -> bool {
    if !LOCAL_INDICATORS.iter().any(|ind| token.contains(ind)) {
        return false;
    }
    let lower = token.to_ascii_lowercase();
    let after_local = LOCAL_INDICATORS
        .iter()
        .filter_map(|ind| lower.find(ind).map(|pos| pos + ind.len()))
        .max()
        .unwrap_or(0);
    let remainder = &lower[after_local..];
    ["http://", "https://"].iter().any(|proto| {
        remainder.find(proto).is_some_and(|proto_pos| {
            let embedded = &remainder[proto_pos..];
            !LOCAL_INDICATORS.iter().any(|li| embedded.contains(li))
        })
    })
}
