use crate::domain_types::{DomainReputation, ProvenanceConfidence};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RemoteOriginKind {
    TrustedRegistry,
    ReviewDomain,
    UntrustedHost,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RemoteOriginAssessment {
    pub(super) reputation: DomainReputation,
    pub(super) confidence: ProvenanceConfidence,
    pub(super) rationale: &'static str,
}

impl RemoteOriginAssessment {
    pub(super) fn from_domain(domain: &str) -> Self {
        match RemoteOriginKind::classify(domain) {
            RemoteOriginKind::UntrustedHost => Self {
                reputation: DomainReputation::Untrusted,
                confidence: ProvenanceConfidence::High,
                rationale: "transient tunnel, paste, direct IP, or raw hosting origin",
            },
            RemoteOriginKind::TrustedRegistry => Self {
                reputation: DomainReputation::Trusted,
                confidence: ProvenanceConfidence::High,
                rationale: "known package registry or package CDN domain",
            },
            RemoteOriginKind::ReviewDomain => Self {
                reputation: DomainReputation::Review,
                confidence: ProvenanceConfidence::Medium,
                rationale: "custom remote domain outside the built-in trusted registry set",
            },
        }
    }
}

impl RemoteOriginKind {
    pub(super) fn classify(domain: &str) -> Self {
        if is_untrusted_domain(domain) {
            Self::UntrustedHost
        } else if is_trusted_registry_domain(domain) {
            Self::TrustedRegistry
        } else {
            Self::ReviewDomain
        }
    }
}

pub(super) fn extract_domain(value: &str) -> Option<String> {
    let without_scheme = value
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(value);
    let host = without_scheme
        .split('/')
        .next()
        .unwrap_or_default()
        .split('@')
        .next_back()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .trim();
    (!host.is_empty()).then(|| host.to_string())
}

fn is_untrusted_domain(domain: &str) -> bool {
    [
        "ngrok.io",
        "ngrok-free.app",
        "trycloudflare.com",
        "workers.dev",
        "raw.githubusercontent.com",
        "pastebin.com",
    ]
    .iter()
    .any(|candidate| domain == *candidate || domain.ends_with(&format!(".{candidate}")))
        || domain.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
}

fn is_trusted_registry_domain(domain: &str) -> bool {
    [
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "crates.io",
        "static.crates.io",
        "rubygems.org",
        "proxy.golang.org",
        "sum.golang.org",
        "packagist.org",
    ]
    .iter()
    .any(|candidate| domain == *candidate || domain.ends_with(&format!(".{candidate}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_registry_domain_gets_high_confidence_assessment() {
        let assessment = RemoteOriginAssessment::from_domain("registry.npmjs.org");
        assert_eq!(assessment.reputation, DomainReputation::Trusted);
        assert_eq!(assessment.confidence, ProvenanceConfidence::High);
    }

    #[test]
    fn raw_host_domain_is_untrusted() {
        let assessment = RemoteOriginAssessment::from_domain("raw.githubusercontent.com");
        assert_eq!(assessment.reputation, DomainReputation::Untrusted);
    }
}
