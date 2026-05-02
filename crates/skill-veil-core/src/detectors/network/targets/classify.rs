use super::model::NetworkTarget;
use crate::detectors::network::patterns::{RE_RFC1918_10, RE_RFC1918_172, RE_RFC1918_192};
use crate::lazy_pattern;

// Hostname-shaped `*.local` matcher. A plain `lower.contains(".local")`
// substring check fired on filesystem paths that happen to contain the
// literal four chars `.local` — `~/.local/bin`,
// `node_modules/.local-cache`, `xdg.local-config`. These are not mDNS
// hostnames and must not classify as `LocalDomain`. The pattern requires:
// * A leading word boundary so we don't match suffixes inside identifiers.
// * A label-shaped prefix (`[a-z0-9-]{1,63}`) before the dot.
// * `.local` followed by a non-label, non-dash character or end-of-string,
//   keeping `printer.local` while rejecting `.local-cache`.
lazy_pattern!(
    RE_LOCAL_DOMAIN,
    r"\b[a-z0-9][a-z0-9-]{0,62}\.local(?:[^a-z0-9-]|$)"
);

// Same shape for `.internal` mDNS-style hostnames.
lazy_pattern!(
    RE_INTERNAL_DOMAIN,
    r"\b[a-z0-9][a-z0-9-]{0,62}\.internal(?:[^a-z0-9-]|$)"
);

// IPv6 loopback in any of its canonical forms. Pre-fix the classifier
// covered IPv4 only (`127.0.0.1`, RFC1918), so a request like
// `requests.get('http://[::1]:8080/admin')` did not produce
// `INTERNAL_NETWORK_ACCESS` or `SSRF_LIKE_FETCH` — both rules gated on
// `has_internal_target` which was driven by `classify_internal_network_target`.
// Recognised forms: `::1` (canonical), `[::1]` (URL bracket form),
// `0:0:0:0:0:0:0:1` (full uncompressed), and `::ffff:127.0.0.1`
// (IPv4-mapped IPv6 loopback). All require non-identifier-byte
// boundaries on either side so identifiers like `foo::1` or
// `bar::1abc` do not match.
lazy_pattern!(
    RE_IPV6_LOOPBACK,
    r"(?:^|[^A-Za-z0-9_:])(?:\[::1\]|::1|0:0:0:0:0:0:0:1|::ffff:127\.0\.0\.1)(?:[^A-Za-z0-9_:]|$)"
);

fn classify_internal_network_target(content: &str) -> Option<NetworkTarget> {
    let lower = content.to_ascii_lowercase();
    if lower.contains("169.254.169.254") {
        Some(NetworkTarget::MetadataService)
    } else if lower.contains("127.0.0.1") || RE_IPV6_LOOPBACK.is_match(&lower) {
        Some(NetworkTarget::Loopback)
    } else if lower.contains("localhost") {
        Some(NetworkTarget::Localhost)
    } else if looks_like_bind_all(&lower) {
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

/// Check whether `text` contains `0.0.0.0` as a standalone IP address
/// rather than as a substring of a longer dotted quad like `10.0.0.0`
/// or `100.0.0.0`. Pre-fix a plain `contains("0.0.0.0")` matched
/// `10.0.0.0` because the four-character substring appears starting at
/// index 1 (`1[0.0.0.0]`), misclassifying the RFC1918 /8 network address
/// as `BindAll`.
pub(crate) fn looks_like_bind_all(text: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = text[start..].find("0.0.0.0") {
        let abs = start + pos;
        let before_ok = abs == 0 || !text.as_bytes()[abs - 1].is_ascii_digit();
        let after = abs + "0.0.0.0".len();
        let after_ok = after >= text.len() || !text.as_bytes()[after].is_ascii_digit();
        if before_ok && after_ok {
            return true;
        }
        start = abs + 1;
    }
    false
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

    /// # Contract
    ///
    /// IPv6 loopback in every canonical form MUST classify as
    /// `Loopback`. Pre-fix the classifier handled IPv4 only, so an
    /// HTTP request to `[::1]:8080` did not produce
    /// `INTERNAL_NETWORK_ACCESS` or `SSRF_LIKE_FETCH` because
    /// `has_internal_target` (driven by this classifier) was `false`.
    /// IPv6-only deployments and dual-stack hosts that prefer `::1`
    /// over `127.0.0.1` were silently exempt from the internal-network
    /// detector.
    #[test]
    fn classify_recognises_ipv6_loopback_forms() {
        for sample in [
            "requests.get('http://[::1]:8080/admin')",
            "curl http://[::1]/health",
            "fetch('http://0:0:0:0:0:0:0:1/x')",
            "curl http://[::ffff:127.0.0.1]/x",
            "ssh ::1",
        ] {
            assert_eq!(
                contains_internal_network_target(sample),
                Some(NetworkTarget::Loopback),
                "IPv6 loopback in {sample:?} must classify as Loopback"
            );
        }
    }

    /// # Contract (negative)
    ///
    /// Identifier-shaped substrings that contain `::1` as a fragment
    /// of a larger token (Rust paths like `module::foo::1` are not
    /// possible because numeric segments are illegal there, but
    /// configuration tokens like `foo::1abc` exist in some YAMLs)
    /// MUST NOT classify as Loopback. Pins the boundary check on
    /// `RE_IPV6_LOOPBACK` so a future loosening cannot accidentally
    /// re-introduce identifier collisions.
    #[test]
    fn classify_does_not_treat_identifier_substrings_as_ipv6_loopback() {
        for sample in ["tag = foo::1abc", "version = ::1xy", "let x = id::1234"] {
            assert_eq!(
                contains_internal_network_target(sample),
                None,
                "identifier substring {sample:?} must NOT classify as Loopback"
            );
        }
    }

    /// # Contract
    ///
    /// `0.0.0.0` as a standalone IP MUST classify as `BindAll`. This is
    /// the happy path that existed before the word-boundary fix.
    #[test]
    fn classify_bind_all_ip() {
        assert_eq!(
            contains_internal_network_target("bind http://0.0.0.0:8080"),
            Some(NetworkTarget::BindAll)
        );
        assert_eq!(
            contains_internal_network_target("listen 0.0.0.0"),
            Some(NetworkTarget::BindAll)
        );
    }

    /// # Contract
    ///
    /// IPs that *contain* `0.0.0.0` as a substring (like `10.0.0.0`
    /// or `100.0.0.0`) MUST NOT classify as `BindAll`. Pre-fix a plain
    /// `contains("0.0.0.0")` matched `10.0.0.0` because the substring
    /// starts at index 1 (`1[0.0.0.0]`), misclassifying the RFC1918 /8
    /// network address.
    #[test]
    fn classify_does_not_misclassify_rfc1918_10_as_bind_all() {
        assert_eq!(
            contains_internal_network_target("http://10.0.0.0/"),
            Some(NetworkTarget::Rfc1918_10),
            "10.0.0.0 must classify as Rfc1918_10, not BindAll"
        );
        assert_eq!(
            contains_internal_network_target("100.0.0.0"),
            None,
            "100.0.0.0 must not classify as BindAll"
        );
    }

    /// # Contract
    ///
    /// `looks_like_bind_all` requires digit boundaries on both sides of
    /// `0.0.0.0`. The standalone address matches; substrings embedded in
    /// larger dotted quads do not.
    #[test]
    fn looks_like_bind_all_distinguishes_standalone_from_substring() {
        assert!(looks_like_bind_all("0.0.0.0"));
        assert!(looks_like_bind_all("http://0.0.0.0:8080"));
        assert!(
            !looks_like_bind_all("10.0.0.0"),
            "10.0.0.0 contains 0.0.0.0 but is not BindAll"
        );
        assert!(
            !looks_like_bind_all("100.0.0.0"),
            "100.0.0.0 contains 0.0.0.0 but is not BindAll"
        );
        assert!(
            !looks_like_bind_all("0.0.0.01"),
            "trailing digit makes this not 0.0.0.0"
        );
    }
}
