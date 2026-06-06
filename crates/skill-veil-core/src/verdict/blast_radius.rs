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

// Bare external exfiltration / tunnel sinks that carry no URL scheme yet are
// unambiguously off-host. Without these, an exfil finding pairing a local
// marker with a scheme-less sink (`upload via telegram`, `post to discord
// webhook`) was misread as local-only and dropped from the severe blast-radius
// tally. Mirrors the sink vocabulary of `OFFICIAL_EXFIL_FILE_READ_TO_NETWORK`.
const EXTERNAL_SINK_KEYWORDS: &[&str] = &[
    "telegram",
    "discord",
    "ngrok",
    "bore.pub",
    "pastebin",
    "paste.",
    "transfer.sh",
    "0x0.st",
    "t.me",
];

// Cloud instance-metadata endpoints are credential-theft / SSRF targets, not
// benign local hosts. GCP's `metadata.google.internal` ends in `.internal`,
// which would otherwise match `LOCAL_INDICATORS` and be excluded from severe
// blast radius — the AWS/Azure form (`169.254.169.254`) is already external,
// so without this the two clouds are scored inconsistently.
const CLOUD_METADATA_HOSTS: &[&str] = &["metadata.google.internal", "metadata.goog"];

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
        if LOCAL_INDICATORS
            .iter()
            .chain(EXTERNAL_PROTOCOLS.iter())
            .any(|needle| value.contains(needle))
        {
            network_targets.push(value.clone());
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
            ThreatCategory::PersuasiveLanguage => "persuasive language",
            ThreatCategory::SocialManipulation => "social manipulation",
            ThreatCategory::ScopeCreep => "scope creep",
            ThreatCategory::Obfuscation => "obfuscation",
            ThreatCategory::UnsafeBinary => "unsafe binary execution",
            ThreatCategory::Generic => "generic security concern",
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
    if CLOUD_METADATA_HOSTS.iter().any(|host| value.contains(host)) {
        return false;
    }
    // Boundary-aware: a genuine local target needs at least one token that is
    // an EXACT local hostname, not merely a substring of an external domain
    // (`.internal-collector.evil.com` contains `.internal` but is external).
    // The loose `value.contains(..)` gate let such domains masquerade as local.
    let has_genuine_local = value.split_whitespace().any(|token| {
        LOCAL_INDICATORS
            .iter()
            .any(|ind| is_exact_local_indicator(token, ind))
    });
    if !has_genuine_local {
        return false;
    }
    let has_non_local_external = value
        .split_whitespace()
        .any(|token| is_token_external(token) || token_has_embedded_external_url(token));
    !has_non_local_external
}

fn is_token_external(token: &str) -> bool {
    let is_local = LOCAL_INDICATORS
        .iter()
        .any(|ind| is_exact_local_indicator(token, ind));
    if is_local {
        return false;
    }
    EXTERNAL_PROTOCOLS.iter().any(|ind| token.contains(ind))
        || EXTERNAL_SINK_KEYWORDS.iter().any(|kw| token.contains(kw))
        || token.contains("://")
}

/// Check whether `token` contains `indicator` as a genuine local-only marker
/// rather than a substring of an external domain. The local indicators
/// (`localhost`, `127.0.0.1`, etc.) are meaningful only when they appear as
/// a hostname — i.e. followed by a domain boundary (`:`, `/`, `?`, `#`,
/// end-of-string, or whitespace) rather than as a prefix of an external
/// domain like `localhost.evil.com`.
fn is_exact_local_indicator(token: &str, indicator: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    let mut start = 0;
    while let Some(pos) = lower[start..].find(indicator) {
        let abs_pos = start + pos;
        let indicator_end = abs_pos + indicator.len();
        let followed_by_boundary = lower
            .get(indicator_end..)
            .and_then(|rest| rest.chars().next())
            .is_none_or(|c| matches!(c, ':' | '/' | '?' | '#' | ' ' | '\t' | '\n' | '\r'));
        if followed_by_boundary {
            return true;
        }
        start = indicator_end;
    }
    false
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
        .filter_map(|ind| lower.rfind(ind).map(|pos| pos + ind.len()))
        .max()
        .unwrap_or(0);
    let remainder = &lower[after_local..];
    ["http://", "https://"].iter().any(|proto| {
        remainder.find(proto).is_some_and(|proto_pos| {
            let embedded = &remainder[proto_pos..];
            // Use boundary-aware checking (same logic as
            // `is_exact_local_indicator`) so that
            // `localhost.evil.com` embedded in a URL is not
            // treated as a genuine local indicator.
            !LOCAL_INDICATORS
                .iter()
                .any(|li| is_exact_local_indicator(embedded, li))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{
        ArtifactKind, ArtifactScope, EvidenceKind, MatchTarget, RecommendedAction, Severity,
        SignalClass,
    };

    /// # Contract
    ///
    /// `build_blast_radius_summary` MUST deduplicate `network_targets`
    /// case-insensitively. Two findings referencing the same URL with
    /// different casing (e.g. `"https://Evil.COM/x"` and
    /// `"https://evil.com/x"`) MUST appear as a single entry in
    /// `network_targets`. Pre-fix the original `match_value` was pushed
    /// (not the lowercased version), so case-sensitive `sort`/`dedup`
    /// failed to collapse them.
    #[test]
    fn blast_radius_deduplicates_case_variant_network_targets() {
        let make_finding = |match_value: &str| {
            Finding::builder("TEST_RULE", ThreatCategory::DataExfiltration)
                .severity(Severity::High)
                .confidence(0.8)
                .action(RecommendedAction::Block)
                .evidence_kind(EvidenceKind::Behavior)
                .matched_on(MatchTarget::Document)
                .match_value(match_value.to_string())
                .artifact(ArtifactKind::SkillDocument, None)
                .artifact_scope(ArtifactScope::AgentEntrypoint)
                .signal_class(SignalClass::MaliciousBehavior)
                .reason("test".to_string())
                .build()
        };

        let findings = vec![
            make_finding("https://Evil.COM/payload"),
            make_finding("https://evil.com/payload"),
        ];

        let summary = build_blast_radius_summary(&findings, &[]);
        assert_eq!(
            summary.network_targets.len(),
            1,
            "case-variant URLs MUST be deduplicated; got {:?}",
            summary.network_targets
        );
    }

    /// # Contract
    ///
    /// Cloud instance-metadata endpoints are external credential-theft
    /// targets, not local hosts. GCP's `metadata.google.internal` ends in
    /// `.internal` but MUST count toward severe blast radius — the same as
    /// AWS's `169.254.169.254` — while a genuine loopback host MUST NOT.
    #[test]
    fn gcp_metadata_host_is_not_local_only() {
        assert!(
            !is_local_only_target("http://metadata.google.internal/computeMetadata/v1/"),
            "GCP metadata endpoint must not be treated as local-only",
        );
        assert!(
            is_local_only_target("http://localhost:8080/health"),
            "a genuine loopback host must stay local-only",
        );

        let make_finding = |match_value: &str| {
            Finding::builder("TEST_RULE", ThreatCategory::DataExfiltration)
                .severity(Severity::High)
                .confidence(0.8)
                .action(RecommendedAction::Block)
                .evidence_kind(EvidenceKind::Behavior)
                .matched_on(MatchTarget::Document)
                .match_value(match_value.to_string())
                .artifact(ArtifactKind::SkillDocument, None)
                .artifact_scope(ArtifactScope::AgentEntrypoint)
                .signal_class(SignalClass::MaliciousBehavior)
                .reason("test".to_string())
                .build()
        };

        let gcp = build_blast_radius_summary(
            &[
                make_finding("http://metadata.google.internal/computeMetadata/v1/instance/"),
                make_finding("http://metadata.google.internal/computeMetadata/v1/project/"),
            ],
            &[],
        );
        let loopback = build_blast_radius_summary(
            &[
                make_finding("http://localhost:8080/health"),
                make_finding("http://127.0.0.1:9000/status"),
            ],
            &[],
        );
        assert_eq!(
            gcp.level,
            BlastRadiusLevel::High,
            "two data-exfiltration findings hitting GCP metadata must register High blast radius",
        );
        assert_eq!(
            loopback.level,
            BlastRadiusLevel::Medium,
            "loopback-only data-exfiltration findings stay below High (no severe targets)",
        );
        assert!(
            !gcp.network_targets.is_empty(),
            "GCP metadata target must be recorded",
        );
    }

    /// Contract: a finding whose match_value pairs a local marker with a
    /// scheme-less external sink (telegram/discord/ngrok/…) is NOT local-only —
    /// the exfil still leaves the host and MUST count toward severe blast
    /// radius. Genuinely loopback-only targets stay local-only.
    #[test]
    fn local_marker_with_scheme_less_external_sink_is_not_local_only() {
        assert!(
            !is_local_only_target(
                "read ~/.ssh/id_rsa on localhost then upload via telegram to attacker"
            ),
            "localhost + telegram exfil must not be treated as local-only",
        );
        assert!(
            !is_local_only_target("cat .env from 127.0.0.1 and post to discord webhook"),
            "loopback + discord exfil must not be treated as local-only",
        );
        assert!(
            is_local_only_target("http://localhost:8080/health"),
            "a genuine loopback health check stays local-only",
        );
    }

    /// Contract: a domain that merely contains a local indicator as a substring
    /// (`.internal-collector.evil.com` has `.internal`) is external, not local —
    /// the gate is boundary-aware, so it counts toward severe blast radius.
    #[test]
    fn substring_local_indicator_in_external_domain_is_not_local_only() {
        assert!(
            !is_local_only_target("exfiltrate to .internal-collector.evil.com"),
            "a `.internal`-substring external domain must not be local-only",
        );
        assert!(
            !is_local_only_target("send to localhost.attacker.com"),
            "a `localhost`-prefixed external domain must not be local-only",
        );
    }
}
