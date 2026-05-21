//! Network-related orchestration: URL extraction and lockfile-source
//! recognition. Domain-rule logic for target classification and webhook
//! exposure lives in the sibling `targets` and `webhook` submodules,
//! which are in the process of being relocated under `crate::detectors`.

use crate::detectors::network::patterns::RE_HTTP_URL;

/// Trailing characters that the URL regex sometimes consumes in
/// markdown / HTML / JSON / shell contexts. `>` covers Markdown
/// reference-link `<URL>` syntax (the regex does not exclude `>`,
/// so the matched text includes the trailing `>` byte). `<`, `,`,
/// `.`, `;`, `!`, `?`, `]` cover prose-bound URLs like
/// `see https://example.com.` Trimming on extraction matches what
/// the IOC pipeline does and prevents downstream consumers — VT
/// integration, host-allowlist checks — from receiving malformed URLs.
const URL_TRIM_TRAILING: &[char] = &[
    '"', '\'', ')', '>', '<', ',', '.', ';', ':', '!', '?', ']', '}',
];

pub(crate) fn extract_http_urls(content: &str) -> Vec<String> {
    RE_HTTP_URL
        .find_matches(content)
        .into_iter()
        .map(|m| {
            m.matched_text
                .trim_end_matches(URL_TRIM_TRAILING)
                .to_string()
        })
        .collect()
}

pub(crate) fn is_common_lockfile_source(url: &str) -> bool {
    [
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "repo.yarnpkg.com",
        "mirrors.tencentyun.com",
        "registry.npmmirror.com",
        "registry.yarnpkg.cn",
        // GitHub Package Registry (`npm.pkg.github.com`) — used by
        // enterprise monorepos and individual orgs as the internal npm
        // registry. Pre-fix every `package-lock.json` resolved against
        // it produced a `LOCKFILE_PACKAGE_REMOTE_TARBALL` finding for
        // every dependency.
        "npm.pkg.github.com",
    ]
    .iter()
    .any(|host| host_matches_url(host, url))
}

/// Exact-host matching: `://host/`, `://host:`, or `@host/` (for
/// authenticated registry URLs like `https://user:pass@registry.npmjs.org/pkg`)
/// prevents substring false positives like `evil.registry.npmjs.org.attacker.com`
/// from matching `registry.npmjs.org`.
fn host_matches_url(host: &str, url: &str) -> bool {
    let lower_url = url.to_ascii_lowercase();
    lower_url.contains(&format!("://{host}/"))
        || lower_url.contains(&format!("://{host}:"))
        || lower_url.contains(&format!("@{host}/"))
        || lower_url.contains(&format!("@{host}:"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    ///
    /// `extract_http_urls` MUST strip a trailing `>` from URLs captured
    /// from Markdown reference-link syntax (`<https://example.com>`).
    /// Pre-fix the regex did not exclude `>` from the match body, so
    /// the returned string carried the trailing `>` and any downstream
    /// consumer that parses URL structure (VT cross-check, host
    /// allowlist) received malformed input.
    #[test]
    fn extract_http_urls_strips_trailing_markdown_reference_bracket() {
        let urls = extract_http_urls("see <https://example.com/path> for details");
        assert!(
            urls.iter().any(|u| u == "https://example.com/path"),
            "trailing `>` must be stripped; got {urls:?}"
        );
        assert!(
            !urls.iter().any(|u| u.ends_with('>')),
            "no extracted URL may end with `>`; got {urls:?}"
        );
    }

    /// # Contract
    ///
    /// URL scheme matching is case-insensitive. Case-variant schemes must
    /// still enter lockfile and IOC source classification.
    #[test]
    fn extract_http_urls_accepts_case_variant_schemes() {
        let urls =
            extract_http_urls("source = { git = \"HTTPS://packages.attacker.example/pkg.git\" }");

        assert_eq!(
            urls,
            vec!["HTTPS://packages.attacker.example/pkg.git".to_string()]
        );
    }

    /// # Contract (negative)
    ///
    /// Case-insensitive matching must not widen beyond HTTP(S) schemes.
    #[test]
    fn extract_http_urls_rejects_non_http_scheme_lookalikes() {
        let urls = extract_http_urls("fetch HTXP://packages.attacker.example/pkg.git");

        assert!(urls.is_empty(), "unexpected URLs: {urls:?}");
    }

    /// # Contract
    ///
    /// `is_common_lockfile_source` MUST accept GitHub Package Registry.
    /// Pins the allowlist so a future contraction does not silently
    /// re-introduce false-positive `LOCKFILE_PACKAGE_REMOTE_TARBALL`
    /// findings for orgs using GitHub Packages as their internal npm
    /// registry.
    #[test]
    fn is_common_lockfile_source_allows_github_packages() {
        assert!(is_common_lockfile_source(
            "https://npm.pkg.github.com/@myorg/tool/-/tool-1.0.0.tgz"
        ));
    }

    /// # Contract
    ///
    /// URL host matching is case-insensitive. Registry lockfile entries
    /// with uppercase host bytes must stay on the common-source path.
    #[test]
    fn is_common_lockfile_source_matches_case_insensitive_hosts() {
        assert!(is_common_lockfile_source(
            "https://REGISTRY.NPMJS.ORG/pkg/-/pkg-1.0.0.tgz"
        ));
    }

    /// # Contract (negative)
    ///
    /// Truly unknown registries are still rejected. Pins the allowlist
    /// boundary against a future loosening.
    #[test]
    fn is_common_lockfile_source_rejects_arbitrary_hosts() {
        assert!(!is_common_lockfile_source(
            "https://attacker.example.com/-/x.tgz"
        ));
    }

    /// # Contract
    ///
    /// `is_common_lockfile_source` MUST reject URLs that contain a known
    /// host as a substring inside a different hostname. An attacker URL
    /// like `https://evil.registry.npmjs.org.attacker.com/...` must NOT
    /// match `registry.npmjs.org`.
    #[test]
    fn is_common_lockfile_source_rejects_substring_host_evasion() {
        assert!(!is_common_lockfile_source(
            "https://evil.registry.npmjs.org.attacker.com/pkg/-/pkg-1.0.0.tgz"
        ));
        assert!(!is_common_lockfile_source(
            "https://my-registry.npmmirror.com.evil.com/pkg/-/pkg-1.0.0.tgz"
        ));
    }

    /// # Contract
    ///
    /// `host_matches_url` MUST match authenticated registry URLs where
    /// credentials precede the host (e.g. `https://user:pass@registry.npmjs.org/`).
    /// Pre-fix only `://{host}/` and `://{host}:` were checked, so URLs
    /// with `@`-delimited auth never matched known registries.
    #[test]
    fn host_matches_url_matches_authenticated_registry_urls() {
        assert!(
            host_matches_url(
                "registry.npmjs.org",
                "https://user:pass@registry.npmjs.org/pkg"
            ),
            "authenticated URL with @ must match known host"
        );
        assert!(
            host_matches_url(
                "registry.npmjs.org",
                "https://user:pass@registry.npmjs.org:443/pkg"
            ),
            "authenticated URL with @ and port must match known host"
        );
    }
}
