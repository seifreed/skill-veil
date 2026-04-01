mod inventory;
mod lineage;
mod origin;
mod publisher;

use self::inventory::collect_provenance_inventory;
use crate::domain_types::{
    DomainReputation, PackageIdentity, ProvenanceTrustLevel, PublisherConsistency,
};
use self::lineage::{derive_lineage_notes, derive_lockfile_coverage};
use self::origin::{extract_domain, RemoteOriginAssessment};
use self::publisher::{derive_publisher_consistency, is_malicious_publisher};
use crate::artifact_graph::ArtifactGraph;
use crate::findings::{Finding, ProvenanceSummary, RemoteDomainSignal};

pub(super) fn derive_provenance_summary(
    findings: &[Finding],
    artifact_graph: &ArtifactGraph,
) -> ProvenanceSummary {
    let mut remote_domains = Vec::new();
    let mut source_kinds = Vec::new();
    let mut package_sources = Vec::new();
    let mut trust_factors = Vec::new();
    let mut remote_domain_signals = Vec::new();
    let mut source_mix_notes = Vec::new();
    let mut untrusted = false;
    let mut review = false;
    let mut unknown_remote = false;
    let inventory = collect_provenance_inventory(artifact_graph);
    let publishers = inventory.publishers;
    let package_identities = inventory.package_identities;
    let manifests = inventory.manifests;
    let lockfiles = inventory.lockfiles;
    let package_lineage = inventory.package_lineage;

    for edge in &artifact_graph.edges {
        let target = edge.to.to_ascii_lowercase();
        if target.starts_with("http://")
            || target.starts_with("https://")
            || target.starts_with("ws://")
            || target.starts_with("wss://")
        {
            if let Some(domain) = extract_domain(&edge.to) {
                if !remote_domains.contains(&domain) {
                    remote_domains.push(domain.clone());
                }
                let assessment = RemoteOriginAssessment::from_domain(&domain);
                remote_domain_signals.push(RemoteDomainSignal {
                    domain: domain.clone(),
                    reputation: assessment.reputation,
                    rationale: assessment.rationale.to_string(),
                });
                if assessment.confidence.is_review_weighted() {
                    trust_factors.push(format!("medium-confidence provenance: {domain}"));
                }
                if assessment.reputation == DomainReputation::Untrusted {
                    untrusted = true;
                    trust_factors.push(format!("untrusted domain: {domain}"));
                } else if assessment.reputation == DomainReputation::Trusted {
                    trust_factors.push(format!("trusted registry: {domain}"));
                    if !source_kinds.iter().any(|kind| kind == "package_registry") {
                        source_kinds.push("package_registry".to_string());
                    }
                } else {
                    review = true;
                    unknown_remote = true;
                }
            }
            if !source_kinds.iter().any(|kind| kind == "remote_url") {
                source_kinds.push("remote_url".to_string());
            }
        }
    }

    for finding in findings {
        match finding.rule_id.as_str() {
            "MANIFEST_NPMRC_CUSTOM_REGISTRY"
            | "MANIFEST_PIP_CONF_EXTRA_INDEX"
            | "MANIFEST_GO_MOD_REMOTE_REPLACE"
            | "MANIFEST_GEMFILE_REMOTE_SOURCE"
            | "MANIFEST_DOCKER_BAKE_REMOTE_CONTEXT"
            | "WORKFLOW_UNPINNED_ACTION_REF"
            | "PRE_COMMIT_LOCAL_HOOKS" => {
                review = true;
                package_sources.push(finding.rule_id.clone());
            }
            "MCP_OPAQUE_REMOTE_CONTROL_PLANE" | "MCP_NO_AUTH_MODEL" | "METADATA_SERVICE_ACCESS" => {
                untrusted = true;
                trust_factors.push(finding.rule_id.clone());
            }
            _ => {}
        }
    }

    for publisher in &publishers {
        if is_malicious_publisher(publisher) {
            untrusted = true;
            trust_factors.push(format!("malicious publisher: {publisher}"));
        }
    }

    remote_domains.sort();
    remote_domains.dedup();
    source_kinds.sort();
    source_kinds.dedup();
    package_sources.sort();
    package_sources.dedup();
    remote_domain_signals.sort_by(|left, right| left.domain.cmp(&right.domain));
    remote_domain_signals.dedup_by(|left, right| left.domain == right.domain);
    trust_factors.sort();
    trust_factors.dedup();

    let publisher_consistency = derive_publisher_consistency(&publishers);
    if publisher_consistency == PublisherConsistency::Mixed {
        trust_factors.push("mixed publishers declared across manifests".to_string());
        review = true;
    }

    let lockfile_coverage = derive_lockfile_coverage(&manifests, &lockfiles);
    if !lockfile_coverage.missing_expected_lockfiles.is_empty() {
        review = true;
        source_mix_notes.push(format!(
            "missing expected lockfiles for {} manifest(s)",
            lockfile_coverage.missing_expected_lockfiles.len()
        ));
    }
    if package_identities.len() > 1 {
        review = true;
        source_mix_notes.push("multiple package identities observed".to_string());
    }
    let lineage_notes = derive_lineage_notes(
        &manifests,
        &lockfiles,
        &package_identities,
        &package_lineage,
    );
    if !lineage_notes.is_empty() {
        review = true;
        trust_factors.extend(
            lineage_notes
                .iter()
                .map(|note| format!("lineage anomaly: {note}")),
        );
        source_mix_notes.extend(lineage_notes);
    }
    if remote_domain_signals
        .iter()
        .any(|signal| signal.reputation == DomainReputation::Review)
        && source_kinds.iter().any(|kind| kind == "package_registry")
    {
        source_mix_notes
            .push("registry-aligned package also reaches custom remote domains".to_string());
    }
    if remote_domain_signals
        .iter()
        .any(|signal| signal.reputation == DomainReputation::Untrusted)
        && remote_domain_signals
            .iter()
            .any(|signal| signal.reputation == DomainReputation::Trusted)
    {
        source_mix_notes
            .push("trusted registry traffic is mixed with untrusted remote origins".to_string());
    }
    source_mix_notes.sort();
    source_mix_notes.dedup();

    let trust_level = if untrusted {
        ProvenanceTrustLevel::Untrusted
    } else if review || unknown_remote || !package_sources.is_empty() {
        ProvenanceTrustLevel::Review
    } else {
        ProvenanceTrustLevel::Trusted
    };

    ProvenanceSummary {
        publishers,
        remote_domains,
        source_kinds,
        package_sources,
        trust_level,
        trust_factors,
        package_identities: package_identities
            .iter()
            .map(PackageIdentity::to_string)
            .collect(),
        publisher_consistency,
        remote_domain_signals,
        lockfile_coverage,
        source_mix_notes,
        manifests,
        lockfiles,
    }
}
