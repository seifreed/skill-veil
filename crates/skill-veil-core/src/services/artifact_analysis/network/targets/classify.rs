use super::model::NetworkTarget;
use crate::services::artifact_analysis::network::patterns::{
    RE_RFC1918_10, RE_RFC1918_172, RE_RFC1918_192,
};
use std::sync::LazyLock;

/// Hostname-shaped `*.local` matcher used by `classify_internal_network_target`.
///
/// A plain `lower.contains(".local")` substring check fired on filesystem
/// paths that happen to contain the literal four chars `.local` —
/// `~/.local/bin`, `node_modules/.local-cache`, `xdg.local-config`. These
/// are not mDNS hostnames and must not classify as `LocalDomain`. The
/// regex requires:
///
/// * A leading word boundary so we don't match suffixes inside identifiers.
/// * A label-shaped prefix (`[a-z0-9-]{1,63}`) before the dot.
/// * `.local` followed by a non-label, non-dash character or end-of-string,
///   keeping `printer.local` while rejecting `.local-cache`.
static RE_LOCAL_DOMAIN: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\b[a-z0-9][a-z0-9-]{0,62}\.local(?:[^a-z0-9-]|$)").unwrap());

/// Same shape for `.internal` mDNS-style hostnames.
static RE_INTERNAL_DOMAIN: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\b[a-z0-9][a-z0-9-]{0,62}\.internal(?:[^a-z0-9-]|$)").unwrap()
});

fn classify_internal_network_target(content: &str) -> Option<NetworkTarget> {
    let lower = content.to_ascii_lowercase();
    if lower.contains("169.254.169.254") {
        Some(NetworkTarget::MetadataService)
    } else if lower.contains("127.0.0.1") {
        Some(NetworkTarget::Loopback)
    } else if lower.contains("localhost") {
        Some(NetworkTarget::Localhost)
    } else if lower.contains("0.0.0.0") {
        Some(NetworkTarget::BindAll)
    } else if RE_RFC1918_10.is_match(&lower) {
        Some(NetworkTarget::Rfc1918_10)
    } else if RE_RFC1918_192.is_match(&lower) {
        Some(NetworkTarget::Rfc1918_192)
    } else if RE_RFC1918_172.is_match(&lower) {
        Some(NetworkTarget::Rfc1918_172)
    } else if RE_INTERNAL_DOMAIN.is_match(&lower) {
        Some(NetworkTarget::InternalDomain)
    } else if RE_LOCAL_DOMAIN.is_match(&lower) {
        Some(NetworkTarget::LocalDomain)
    } else {
        None
    }
}

pub(crate) fn contains_internal_network_target(content: &str) -> Option<NetworkTarget> {
    classify_internal_network_target(content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_metadata_service_as_special_target() {
        assert_eq!(
            contains_internal_network_target("fetch http://169.254.169.254/latest/meta-data"),
            Some(NetworkTarget::MetadataService)
        );
    }

    #[test]
    fn classify_rfc1918_and_local_domains() {
        assert_eq!(
            contains_internal_network_target("curl http://10.1.2.3/health"),
            Some(NetworkTarget::Rfc1918_10)
        );
        assert_eq!(
            contains_internal_network_target("curl http://db.internal/health"),
            Some(NetworkTarget::InternalDomain)
        );
    }

    /// Contract: filesystem paths containing the literal substring `.local`
    /// MUST NOT classify as `LocalDomain`. The naive `contains` check
    /// surfaced `~/.local/bin`, `node_modules/.local-cache`, etc as mDNS
    /// hostnames, polluting taint and risk analysis.
    #[test]
    fn classify_does_not_treat_dot_local_filesystem_paths_as_local_domain() {
        for path in [
            "config = ~/.local/bin",
            "loaded $HOME/.local/share/foo",
            "include node_modules/.local-cache",
        ] {
            assert_eq!(
                contains_internal_network_target(path),
                None,
                "Filesystem path '{path}' must NOT classify as LocalDomain"
            );
        }
    }

    /// Sanity: actual `*.local` hostnames still classify.
    #[test]
    fn classify_accepts_legitimate_mdns_hostnames() {
        assert_eq!(
            contains_internal_network_target("printer.local"),
            Some(NetworkTarget::LocalDomain)
        );
        assert_eq!(
            contains_internal_network_target("ssh user@build.local /tmp"),
            Some(NetworkTarget::LocalDomain)
        );
    }
}
