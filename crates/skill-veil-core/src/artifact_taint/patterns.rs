use crate::artifact_graph::{ArtifactEdge, EndpointKind};
use crate::detectors::scripts::references_dotenv_file;

use super::trusted_hosts::is_documentation_or_reserved_host;

pub(super) fn looks_like_secret_target(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    // Use the word-boundary-aware helper for `.env` so that `.envrc`,
    // `.envelope`, and `.environments/` do not produce false taint edges.
    // Pre-fix the bare `.env` substring matched all of these lookalikes.
    if references_dotenv_file(&lower) {
        return true;
    }
    // Specific secret file/variable patterns — match as substrings.
    let specific_patterns = [
        ".npmrc",
        ".ssh",
        "id_rsa",
        "known_hosts",
        "aws_secret_access_key",
        "aws_session_token",
        "openai_api_key",
        "github_token",
        "gh_token",
        "google_application_credentials",
        "slack_bot_token",
    ];
    if specific_patterns
        .iter()
        .any(|needle| lower.contains(needle))
    {
        return true;
    }
    // Generic keywords — require a word-boundary-like separator to avoid
    // matching substrings like "tokenizer", "session_config", etc.
    let generic_keywords = ["token", "secret", "cookie", "session"];
    generic_keywords
        .iter()
        .any(|keyword| lower.contains(keyword) && has_word_boundary(&lower, keyword))
}

/// Check that `keyword` appears in `text` at a word boundary: preceded and
/// followed by a non-alphanumeric character (or string start/end).
///
/// # Contract
///
/// Boundary checks must be Unicode-aware: a non-ASCII letter such as `ñ`
/// preceding the keyword is part of the surrounding word, NOT a boundary.
/// Pre-fix this used `text.as_bytes()[abs_pos - 1].is_ascii_alphanumeric()`
/// which read a UTF-8 continuation byte (0x80–0xBF) and treated it as
/// non-alphanumeric, so `"ñtoken"` was wrongly classified as a boundary
/// match.
pub(super) fn has_word_boundary(text: &str, keyword: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = text[start..].find(keyword) {
        let abs_pos = start + pos;
        let before_ok = text[..abs_pos]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric());
        let after_pos = abs_pos + keyword.len();
        let after_ok = text[after_pos..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_alphanumeric());
        if before_ok && after_ok {
            return true;
        }
        start = abs_pos + 1;
    }
    false
}

pub(super) fn looks_like_identity_target(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    // "oauth" and "identity" are specific enough to match as substrings.
    if lower.contains("oauth") || lower.contains("identity") {
        return true;
    }
    // Generic keywords require word boundaries to avoid false positives
    // like "tokenizer.py" or "credential_validator_test.py".
    let generic_keywords = ["token", "session", "cookie", "credential"];
    generic_keywords
        .iter()
        .any(|keyword| lower.contains(keyword) && has_word_boundary(&lower, keyword))
}

pub(super) fn looks_like_external_sink(edge: &ArtifactEdge) -> bool {
    // Known external endpoint kinds are conclusive
    if matches!(
        edge.endpoint_kind,
        Some(EndpointKind::Remote | EndpointKind::Transient | EndpointKind::ControlPlane)
    ) {
        return true;
    }
    // Registry and Local endpoints are not external sinks
    if matches!(
        edge.endpoint_kind,
        Some(EndpointKind::Registry | EndpointKind::Local)
    ) {
        return false;
    }
    // When endpoint_kind is None, fall back to string matching on the URL.
    // This is a best-effort heuristic that may miss some external sinks.
    let lower = edge.to.to_ascii_lowercase();

    // Known malicious patterns (high confidence)
    let known_external = [
        "discord.com/api/webhooks",
        "api.telegram.org/bot",
        "pastebin.com",
        "ngrok",
        "trycloudflare",
        "raw.githubusercontent.com",
        "sendgrid",
        "mailgun",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    // Webhook endpoints: match "/webhook" followed by a path separator (/,
    // ?, #) or end-of-string, or the dedicated "webhook.site" service.
    // The bare substring "webhook" matched documentation URLs like
    // "/webhook-setup-guide" — the boundary check prevents that.
    || lower.split('/').any(|segment| segment == "webhook" || segment.starts_with("webhook?") || segment.starts_with("webhook#"))
    || lower.contains("webhook.site");
    if known_external {
        return true;
    }

    // Generic HTTP/HTTPS URLs that aren't known-safe registries,
    // software-distribution downloads, or local endpoints.
    (lower.starts_with("http://") || lower.starts_with("https://"))
        && !looks_like_registry_url(&edge.to)
        && !looks_like_software_distribution_url(&lower)
        && !looks_like_local_endpoint(&lower)
}

pub(super) fn is_real_external_sink(edge: &ArtifactEdge) -> bool {
    looks_like_external_sink(edge) && !is_documentation_or_reserved_host(&edge.to)
}

/// `true` when `lower` (an already-lowercased URL) points at a
/// downloadable software/package artifact rather than an outbound
/// exfiltration endpoint.
///
/// # Why this is not an exfil sink
///
/// `ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK` and its identity
/// sibling fire on any node that reads a secret AND connects to an
/// external URL. Ops/devops skills routinely document
/// `yum install https://repo.vendor.com/pkg.rpm`,
/// `curl -LO https://github.com/org/repo/releases/download/v1/tool.tar.gz`,
/// or `pip install https://host/pkg.whl` next to example config that
/// mentions a password. That is an INBOUND artifact fetch — you do
/// not exfiltrate a credential *to* a `.rpm`. Cross-LLM triage on the
/// VT-clean corpus showed install-documentation is the single
/// largest benign class flagged by the secret→network rule.
///
/// Anchored on the URL **path** ending in a package/installer/archive
/// extension (after stripping query/fragment) or the GitHub
/// `releases/download/` path. Exfil endpoints (`/collect`,
/// `/api/log`, webhook receivers) do not end in these extensions, so
/// recall on real secret-to-network exfil is preserved. The
/// known-exfil short-circuit (`pastebin`, `discord webhook`,
/// `telegram bot`, `ngrok`, `raw.githubusercontent`, …) runs BEFORE
/// this check, so a `.rpm` hosted on a known drop host still fires.
pub(super) fn looks_like_software_distribution_url(lower: &str) -> bool {
    let after_scheme = lower
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(lower);
    let path = after_scheme
        .split(['?', '#'])
        .next()
        .unwrap_or(after_scheme)
        .trim_end_matches('/');
    if path.contains("/releases/download/") || path.contains("/dist/") {
        return true;
    }
    const ARTIFACT_EXTENSIONS: &[&str] = &[
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
        ".tar.zst",
        ".tgz",
        ".tbz2",
        ".txz",
        ".rpm",
        ".deb",
        ".pkg",
        ".dmg",
        ".msi",
        ".apk",
        ".appimage",
        ".whl",
        ".gem",
        ".jar",
        ".nupkg",
        ".crate",
        ".snap",
        ".flatpak",
        ".7z",
        ".zst",
    ];
    ARTIFACT_EXTENSIONS.iter().any(|ext| path.ends_with(ext))
}

pub(super) fn looks_like_local_endpoint(lower: &str) -> bool {
    lower.contains("localhost")
        || lower.contains("127.0.0.1")
        || looks_like_bind_all_address(lower)
        || lower.contains("::1")
        || lower.contains(".local/")
        || lower.contains(".local:")
        || lower.ends_with(".local")
        || lower.contains(".internal/")
        || lower.contains(".internal:")
        || lower.ends_with(".internal")
}

/// Check whether `text` contains `0.0.0.0` as a standalone IP address
/// rather than as a substring of a longer dotted quad like `10.0.0.0`
/// or `100.0.0.0`. A plain `contains("0.0.0.0")` matches those
/// substrings, misclassifying public IPs as local endpoints and
/// suppressing external-sink detection in taint analysis.
fn looks_like_bind_all_address(text: &str) -> bool {
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

pub(super) fn looks_like_registry_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    [
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "files.pythonhosted.org",
        "pypi.org/packages",
        "crates.io/api",
        "static.crates.io",
        "index.crates.io",
        "registry.hub.docker.com",
        "ghcr.io",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    /// `has_word_boundary` must NOT treat a non-ASCII alphanumeric char
    /// adjacent to the keyword as a word boundary. Pre-fix `as_bytes()`
    /// indexing read a UTF-8 continuation byte (0x80–0xBF), which is not
    /// `is_ascii_alphanumeric`, so the keyword falsely matched at a
    /// word boundary inside `"ñtoken"` / `"tokenñ"`.
    #[test]
    fn has_word_boundary_rejects_adjacent_non_ascii_letter() {
        assert!(
            !has_word_boundary("ñtoken", "token"),
            "non-ASCII letter before keyword must NOT be a word boundary",
        );
        assert!(
            !has_word_boundary("tokenñ", "token"),
            "non-ASCII letter after keyword must NOT be a word boundary",
        );
    }

    /// # Contract
    /// Positive: bare keyword and ASCII separators flanking the keyword
    /// must still be treated as word boundaries (regression guard so the
    /// Unicode-aware fix doesn't accidentally tighten the happy path).
    #[test]
    fn has_word_boundary_accepts_ascii_separators_and_bare_keyword() {
        assert!(has_word_boundary("token", "token"));
        assert!(has_word_boundary("/token=", "token"));
        assert!(has_word_boundary("auth_token foo", "token"));
        assert!(has_word_boundary("session.token", "token"));
    }

    /// # Contract
    /// `has_word_boundary` must reject ASCII-alphanumeric flanks (this is
    /// the ORIGINAL contract — the substring match is part of a larger
    /// word like `tokenizer`).
    #[test]
    fn has_word_boundary_rejects_ascii_alphanumeric_flanks() {
        assert!(!has_word_boundary("tokenizer", "token"));
        assert!(!has_word_boundary("mytoken", "token"));
        assert!(!has_word_boundary("token1", "token"));
    }

    /// # Contract
    /// `looks_like_external_sink` must NOT match documentation URLs that
    /// merely contain the word "webhook" in a path like "/webhook-setup-guide"
    /// or "/docs/webhook-integration". Only actual webhook endpoints (path
    /// component "/webhook" or the dedicated webhook.site service) should
    /// match. The negative test cases use localhost URLs so that only the
    /// `known_external` patterns determine the result — the generic HTTP
    /// check skips local endpoints.
    #[test]
    fn looks_like_external_sink_rejects_webhook_documentation_urls() {
        use crate::artifact_graph::{ArtifactEdge, ArtifactRelation};

        // Negative: localhost URL with webhook-setup-guide must not match
        let local_doc_url = ArtifactEdge {
            from: "a".to_string(),
            to: "http://localhost:3000/webhook-setup-guide".to_string(),
            relation: ArtifactRelation::ConnectsTo,
            endpoint_kind: None,
        };
        assert!(
            !looks_like_external_sink(&local_doc_url),
            "localhost URL with '/webhook-setup-guide' must NOT be classified as an external sink"
        );

        // Positive: actual webhook endpoint must still match
        let real_webhook = ArtifactEdge {
            from: "a".to_string(),
            to: "https://hooks.slack.com/services/webhook".to_string(),
            relation: ArtifactRelation::ConnectsTo,
            endpoint_kind: None,
        };
        assert!(
            looks_like_external_sink(&real_webhook),
            "actual webhook endpoint URL must be classified as an external sink"
        );

        // Positive: webhook.site must match
        let webhook_site = ArtifactEdge {
            from: "a".to_string(),
            to: "https://webhook.site/abc123".to_string(),
            relation: ArtifactRelation::ConnectsTo,
            endpoint_kind: None,
        };
        assert!(
            looks_like_external_sink(&webhook_site),
            "webhook.site URLs must be classified as an external sink"
        );

        // Positive: /webhook/ as a path segment must match
        let webhook_path = ArtifactEdge {
            from: "a".to_string(),
            to: "https://api.example.com/webhook/notify".to_string(),
            relation: ArtifactRelation::ConnectsTo,
            endpoint_kind: None,
        };
        assert!(
            looks_like_external_sink(&webhook_path),
            "/webhook/ as a path segment must be classified as an external sink"
        );

        // Negative: /webhook-setup-guide must NOT match (hyphen after webhook)
        let doc_path = ArtifactEdge {
            from: "a".to_string(),
            to: "http://localhost:8080/webhook-setup-guide".to_string(),
            relation: ArtifactRelation::ConnectsTo,
            endpoint_kind: None,
        };
        assert!(
            !looks_like_external_sink(&doc_path),
            "local URL with '/webhook-setup-guide' must NOT match the webhook pattern"
        );
    }

    /// # Contract
    /// A URL whose path ends in a package/installer/archive extension
    /// (or sits under a `releases/download/` path) is an inbound
    /// software fetch, NOT a secret-exfiltration sink. Pre-fix every
    /// `yum install https://repo.vendor.com/pkg.rpm` in ops docs
    /// flipped a benign skill to malicious via
    /// `ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK`.
    #[test]
    fn software_distribution_urls_are_not_exfil_sinks() {
        use crate::artifact_graph::ArtifactRelation;
        for url in [
            "https://repo.percona.com/yum/percona-release-latest.noarch.rpm",
            "https://github.com/org/tool/releases/download/v1.2.3/tool-linux.tar.gz",
            "https://host.example/pkg/app.whl",
            "https://downloads.vendor.io/cli/cli_amd64.deb",
            "https://get.example.org/installer.pkg?os=mac",
            "https://cdn.vendor.net/dist/bundle.zst",
        ] {
            assert!(
                looks_like_software_distribution_url(&url.to_ascii_lowercase()),
                "{url} must be classified as a software-distribution download"
            );
            let edge = ArtifactEdge {
                from: "a".to_string(),
                to: url.to_string(),
                relation: ArtifactRelation::ConnectsTo,
                endpoint_kind: None,
            };
            assert!(
                !looks_like_external_sink(&edge),
                "{url} must NOT be an external exfil sink"
            );
        }
    }

    /// # Contract (negative)
    /// Real exfil endpoints do not end in artifact extensions, so the
    /// distribution carve-out must NOT swallow them. Also pins that a
    /// `.rpm` hosted on a known drop host still fires via the
    /// known-exfil short-circuit that runs before the carve-out.
    #[test]
    fn distribution_carveout_preserves_exfil_recall() {
        use crate::artifact_graph::ArtifactRelation;
        for url in [
            "https://attacker.example/collect",
            "https://api.evil.net/v1/log?d=secret",
            "https://exfil.example/upload.php",
            "https://hooks.example.com/webhook/abc",
        ] {
            let edge = ArtifactEdge {
                from: "a".to_string(),
                to: url.to_string(),
                relation: ArtifactRelation::ConnectsTo,
                endpoint_kind: None,
            };
            assert!(
                looks_like_external_sink(&edge),
                "{url} must remain an external exfil sink"
            );
        }
        let rpm_on_pastebin = ArtifactEdge {
            from: "a".to_string(),
            to: "https://pastebin.com/raw/payload.rpm".to_string(),
            relation: ArtifactRelation::ConnectsTo,
            endpoint_kind: None,
        };
        assert!(
            looks_like_external_sink(&rpm_on_pastebin),
            "a package extension on a known drop host must still fire"
        );
    }
}
