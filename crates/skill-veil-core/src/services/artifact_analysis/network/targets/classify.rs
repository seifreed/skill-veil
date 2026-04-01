use super::model::NetworkTarget;
use crate::services::artifact_analysis::network::patterns::{
    RE_RFC1918_10, RE_RFC1918_172, RE_RFC1918_192,
};

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
    } else if lower.contains(".internal") {
        Some(NetworkTarget::InternalDomain)
    } else if lower.contains(".local") {
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
}
