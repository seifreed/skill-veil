use crate::artifact_graph::{ArtifactEdge, EndpointKind};

pub(super) fn looks_like_secret_target(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    // Specific secret file/variable patterns — match as substrings.
    let specific_patterns = [
        ".env",
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
pub(super) fn has_word_boundary(text: &str, keyword: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = text[start..].find(keyword) {
        let abs_pos = start + pos;
        let before_ok = abs_pos == 0 || !text.as_bytes()[abs_pos - 1].is_ascii_alphanumeric();
        let after_pos = abs_pos + keyword.len();
        let after_ok =
            after_pos >= text.len() || !text.as_bytes()[after_pos].is_ascii_alphanumeric();
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
        "webhook",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    if known_external {
        return true;
    }

    // Generic HTTP/HTTPS URLs that aren't known-safe registries or local endpoints
    (lower.starts_with("http://") || lower.starts_with("https://"))
        && !looks_like_registry_url(&edge.to)
        && !looks_like_local_endpoint(&lower)
}

pub(super) fn looks_like_local_endpoint(lower: &str) -> bool {
    lower.contains("localhost")
        || lower.contains("127.0.0.1")
        || lower.contains("0.0.0.0")
        || lower.contains("::1")
        || lower.contains(".local")
        || lower.contains(".internal")
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
