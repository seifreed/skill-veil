//! Pure host / IP-address string primitives shared by the network-aware
//! detectors and the taint trusted-host gate.
//!
//! Leaf helpers with no dependencies beyond `std::net`, so every module that
//! classifies a URL host (intent policy, rule refinement, network-target
//! classifier, taint trusted-host allowlist) shares one definition instead of
//! re-spelling the same trim / lowercase / loopback logic. Each caller keeps
//! its own *policy* — which suffixes count as documentation, private, or
//! internal — while the shared mechanics live here.

use std::net::Ipv6Addr;

/// Canonical host form for comparison: the trailing root-label dot is removed
/// and the host is ASCII-lowercased. `Example.COM.` and `example.com` both
/// normalise to `example.com`.
pub(crate) fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// True if `host` (already [`normalize_host`]-normalised) is the loopback name
/// `localhost` or a `*.localhost` subdomain (RFC 6761). Callers that have not
/// normalised should pass the output of [`normalize_host`] first.
pub(crate) fn host_is_localhost(host: &str) -> bool {
    host == "localhost" || host.ends_with(".localhost")
}

/// True if `addr` is the IPv6 loopback `::1` or an IPv4-mapped IPv6 address
/// whose embedded IPv4 is loopback (`::ffff:127.0.0.1`).
pub(crate) fn ipv6_is_loopback_or_mapped_loopback(addr: Ipv6Addr) -> bool {
    addr.is_loopback()
        || addr
            .to_ipv4_mapped()
            .is_some_and(|mapped| mapped.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_host_strips_root_dot_and_lowercases() {
        assert_eq!(normalize_host("Example.COM."), "example.com");
        assert_eq!(normalize_host("localhost"), "localhost");
    }

    #[test]
    fn host_is_localhost_matches_loopback_names_only() {
        assert!(host_is_localhost("localhost"));
        assert!(host_is_localhost("db.localhost"));
        assert!(!host_is_localhost("localhost.evil.com"));
        assert!(!host_is_localhost("example.com"));
    }

    #[test]
    fn ipv6_loopback_recognises_bare_and_mapped() {
        assert!(ipv6_is_loopback_or_mapped_loopback(Ipv6Addr::LOCALHOST));
        assert!(ipv6_is_loopback_or_mapped_loopback(
            "::ffff:127.0.0.1".parse().unwrap()
        ));
        assert!(!ipv6_is_loopback_or_mapped_loopback(
            "::ffff:8.8.8.8".parse().unwrap()
        ));
        assert!(!ipv6_is_loopback_or_mapped_loopback(
            "2001:db8::1".parse().unwrap()
        ));
    }
}
