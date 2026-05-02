use crate::detectors::network::patterns::{
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
    content
        .lines()
        .any(|line| RE_SSRF_FETCH_LINE.is_match(line))
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

    /// Contract: IPv6 loopback (`::1`, `[::1]`) and IPv4-mapped IPv6
    /// (`::ffff:127.0.0.1`, `[::ffff:169.254.169.254]`) MUST trigger
    /// the same internal-action / SSRF detection as their IPv4
    /// equivalents. Pre-fix the patterns listed only IPv4 forms, so a
    /// script could swap its localhost or IMDS target into IPv6 form
    /// (`http://[::1]/`, `http://[::ffff:169.254.169.254]/latest/...`)
    /// and bypass detection while reaching the same sinks on a
    /// dual-stack client.
    #[test]
    fn detect_internal_actions_covers_ipv6_loopback_and_ipv4_mapped() {
        assert!(contains_internal_network_action(
            "curl http://[::1]:8080/healthz"
        ));
        assert!(contains_internal_network_action(
            "fetch('http://[::ffff:169.254.169.254]/latest/meta-data/iam/')"
        ));
        // Bare host form (no brackets) — appears in proxy-config strings.
        assert!(contains_internal_network_action(
            "POST ::1 with credentials"
        ));
    }

    #[test]
    fn detect_ssrf_like_fetches_covers_ipv6_loopback_and_ipv4_mapped() {
        assert!(contains_ssrf_like_fetch_line(
            "requests.get('http://[::1]:8080/admin')"
        ));
        assert!(contains_ssrf_like_fetch_line(
            "axios.get('http://[::ffff:169.254.169.254]/latest/meta-data/')"
        ));
        assert!(contains_ssrf_like_fetch_line(
            "httpx.get('http://[::ffff:10.0.0.1]/internal')"
        ));
    }

    /// # Contract
    ///
    /// `RE_SSRF_FETCH_LINE` MUST include `localhost`, `127.0.0.1`, and
    /// `0.0.0.0` in its IP address alternation. Pre-fix these three targets
    /// were present in `RE_INTERNAL_ACTION` but absent from
    /// `RE_SSRF_FETCH_LINE`, so SSRF payloads targeting localhost (e.g.
    /// `curl http://localhost:8080/admin`) fell through to the lower-severity
    /// `INTERNAL_NETWORK_ACCESS` finding instead of the high-severity
    /// `SSRF_LIKE_FETCH`.
    #[test]
    fn detect_ssrf_like_fetch_line_includes_localhost_and_loopback() {
        for sample in [
            "curl http://localhost:8080/admin",
            "requests.get('http://127.0.0.1/secret')",
            "wget http://0.0.0.0:9090/metrics",
        ] {
            assert!(
                contains_ssrf_like_fetch_line(sample),
                "SSRF-like fetch must match localhost/loopback target: {sample:?}"
            );
        }
    }
}
