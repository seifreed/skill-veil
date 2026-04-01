use crate::services::artifact_analysis::network::patterns::{
    RE_INTERNAL_ACTION, RE_LOCAL_CONTROL_PLANE, RE_LOCAL_DEV_REFERENCE, RE_SSRF_FETCH_LINE,
};

pub(crate) fn contains_internal_network_action(content: &str) -> bool {
    RE_INTERNAL_ACTION.is_match(content)
}

pub(crate) fn looks_like_local_dev_reference(content: &str) -> bool {
    RE_LOCAL_DEV_REFERENCE.is_match(content)
}

pub(crate) fn looks_like_local_control_plane_reference(content: &str) -> bool {
    RE_LOCAL_CONTROL_PLANE.is_match(content)
}

pub(crate) fn contains_ssrf_like_fetch_line(content: &str) -> bool {
    content.lines().any(|line| RE_SSRF_FETCH_LINE.is_match(line))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_local_control_plane_and_dev_reference() {
        assert!(looks_like_local_control_plane_reference(
            "dashboard heartbeat browser open http://localhost:3000"
        ));
        assert!(looks_like_local_dev_reference(
            "run locally against localhost for testing"
        ));
    }

    #[test]
    fn detect_internal_actions_and_ssrf_fetches() {
        assert!(contains_internal_network_action(
            "curl http://localhost:8080 && POST http://10.0.0.1"
        ));
        assert!(contains_ssrf_like_fetch_line(
            "requests.get('http://service.internal/token')"
        ));
    }
}
