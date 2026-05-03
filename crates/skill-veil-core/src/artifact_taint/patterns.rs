use crate::artifact_graph::{ArtifactEdge, EndpointKind};
use crate::detectors::scripts::references_dotenv_file;

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
}
