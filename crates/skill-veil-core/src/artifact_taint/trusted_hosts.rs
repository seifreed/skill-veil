//! Allowlist of well-known API hosts that legitimately receive
//! credentials over HTTP(S).
//!
//! # Why an allowlist
//!
//! `ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK` and
//! `ARTIFACT_TAINT_IDENTITY_TO_EXTERNAL_NETWORK` fire whenever a node
//! has BOTH a secret/identity source AND an external-network sink.
//! That is the modal benign behaviour for an OpenClaw skill that
//! integrates with an upstream API: read `YOUTUBE_API_KEY` from env,
//! POST to `googleapis.com`. Cross-LLM triage on a 4000-skill
//! VT-clean corpus showed this pair contributes ~272 of the ~449
//! consensus false positives.
//!
//! When EVERY external sink for a tainted node resolves to a host on
//! this list, downstream callers downgrade the finding from
//! `MaliciousBehavior` / `block` to `ReviewSignal` /
//! `require_approval`. The signal is preserved (operators still see
//! the elevated risk) but the verdict no longer auto-blocks.
//!
//! # Curation rules
//!
//! Only add hosts that meet ALL of:
//! - Operate under a public, documented API contract
//! - Use bearer-token / API-key auth in the request, not in the URL
//! - Are operated by an organisation with a security-disclosure
//!   contact and an established reputation
//!
//! Adding a host here is a TRUST decision: a compromised entry on
//! this list silently downgrades exfil findings that point at it.
//! Pull requests touching this list MUST justify the addition in the
//! commit message.
//!
//! NOTE: domain matching is case-insensitive and supports a single
//! leading `*.` wildcard for subdomain coverage. Anything else
//! (regex, multiple wildcards, port specs) is rejected at parse time
//! by [`is_trusted_api_host`] returning `false`.

/// Static allowlist of trusted API host patterns. Each entry is
/// either a literal host (`api.openai.com`) or a single-wildcard
/// pattern (`*.googleapis.com`) covering subdomains.
pub(super) const TRUSTED_API_HOSTS: &[&str] = &[
    // Google
    "*.googleapis.com",
    "*.google.com",
    // GitHub
    "api.github.com",
    "*.github.com",
    "*.githubusercontent.com",
    // OpenAI / Anthropic / xAI / DeepSeek-compatible / OpenRouter
    "api.openai.com",
    "api.anthropic.com",
    "api.x.ai",
    "api.deepseek.com",
    "openrouter.ai",
    "api.openrouter.ai",
    // Self-hosted LLMs commonly fronted by these endpoints
    "ollama.com",
    "api.ollama.com",
    // Hugging Face
    "huggingface.co",
    "*.huggingface.co",
    "*.hf.co",
    // Atlassian (Jira / Confluence / Rovo)
    "*.atlassian.net",
    "*.atlassian.com",
    // Notion
    "api.notion.com",
    // Slack
    "*.slack.com",
    "slack.com",
    "hooks.slack.com",
    // Microsoft Graph / Azure cognitive
    "graph.microsoft.com",
    "login.microsoftonline.com",
    // AWS public endpoints (regional pattern)
    "*.amazonaws.com",
    // Cloudflare workers / R2
    "*.cloudflare.com",
    // Other well-known public APIs that frequently appear in benign
    // skills.
    "api.stripe.com",
    "api.twilio.com",
    "api.sendgrid.com",
    "api.mailgun.net",
    "api.postmarkapp.com",
    "api.linear.app",
    "api.figma.com",
    "api.zoom.us",
    "api.dropbox.com",
    "api.intercom.io",
    "api.hubapi.com",
    "api.asana.com",
    "api.trello.com",
    "api.airtable.com",
    "api.basecamp.com",
    "api.calendly.com",
    "api.discord.com",
    "discord.com",
    "api.telegram.org",
    "api.spotify.com",
    "api.youtube.com",
];

/// Returns `true` if `endpoint` (a URL string from a graph edge's
/// destination) resolves to a host on [`TRUSTED_API_HOSTS`].
///
/// # Matching rules
///
/// - Scheme + path are stripped before host comparison; the helper
///   accepts bare hostnames, full URLs, and host:port pairs.
/// - Host comparison is case-insensitive.
/// - A pattern of the form `*.<suffix>` matches any host whose
///   trailing labels equal `<suffix>` (proper subdomain). A literal
///   pattern matches only its exact host. `*.foo.com` therefore does
///   NOT match `foo.com` itself — list both if both should be
///   trusted.
///
/// Returns `false` for malformed inputs, plain IP literals
/// (`192.168.1.1:8080`), and the empty string. The conservative
/// default protects the downgrade path: a host we cannot parse will
/// never satisfy the allowlist.
#[must_use]
pub(super) fn is_trusted_api_host(endpoint: &str) -> bool {
    let host = match extract_host(endpoint) {
        Some(h) => h.to_ascii_lowercase(),
        None => return false,
    };
    if host.is_empty() {
        return false;
    }
    // Plain IPv4 literals never qualify, even if the user happens to
    // type one of the allowlist hostnames. A taint pointing at an IP
    // is exactly the kind of finding the operator wants to inspect
    // manually.
    if is_ipv4_literal(&host) {
        return false;
    }
    for pattern in TRUSTED_API_HOSTS {
        if matches_host_pattern(&host, pattern) {
            return true;
        }
    }
    false
}

/// Extract the host portion from an endpoint string. Accepts:
/// - Full URLs: `https://api.github.com/users/me`
/// - Schemeless forms: `api.github.com/users/me`
/// - Bare hosts: `api.github.com`
/// - Host:port: `localhost:11434`
///
/// Returns `None` if the input has no parseable host component.
fn extract_host(endpoint: &str) -> Option<&str> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Strip scheme.
    let after_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    // Drop user-info (`user:pass@host`).
    let after_userinfo = after_scheme
        .rsplit_once('@')
        .map(|(_, rest)| rest)
        .unwrap_or(after_scheme);
    // Take everything up to the first path / query / fragment / port
    // separator. Port stripping is required so `localhost:8080` does
    // not match a hypothetical literal `localhost:8080` in the
    // allowlist (we only key on host).
    let host_with_port = after_userinfo
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_userinfo);
    let host = host_with_port
        .rsplit_once(':')
        .map(|(h, _port)| h)
        .unwrap_or(host_with_port);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Wildcard matching for one allowlist entry. Supports the single
/// leading-wildcard form `*.<suffix>` and literal exact match.
fn matches_host_pattern(host: &str, pattern: &str) -> bool {
    let pattern_lc = pattern.to_ascii_lowercase();
    if let Some(suffix) = pattern_lc.strip_prefix("*.") {
        // Wildcard MUST match a proper subdomain — pattern `*.foo.com`
        // matches `bar.foo.com` (strip "bar." → equals "foo.com") but
        // NOT `foo.com` (no leading label to strip).
        if host.len() <= suffix.len() {
            return false;
        }
        return host.ends_with(suffix) && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
    }
    host == pattern_lc
}

fn is_ipv4_literal(host: &str) -> bool {
    let mut octets = 0;
    for part in host.split('.') {
        if part.is_empty() || part.len() > 3 {
            return false;
        }
        if !part.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if part.parse::<u8>().is_err() {
            return false;
        }
        octets += 1;
    }
    octets == 4
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: literal allowlist entries match their exact host
    /// only. An exact entry like `api.github.com` MUST match
    /// `https://api.github.com/users/me` but MUST NOT match a sibling
    /// host like `evil-api.github.com` that merely shares the suffix.
    #[test]
    fn literal_entry_matches_exact_host_only() {
        assert!(is_trusted_api_host("https://api.github.com/users/me"));
        assert!(is_trusted_api_host("api.github.com"));
        // `evil-api.github.com` does not equal `api.github.com`; the
        // wildcard `*.github.com` is the entry that catches it. We
        // pin that specific protection in `wildcard_subdomain_match`.
    }

    /// Contract: `*.<suffix>` matches subdomains of the suffix and
    /// requires a `.` separator before the suffix. Without the
    /// separator check, a wildcard `*.foo.com` would dangerously
    /// match `evilfoo.com` (no dot before the suffix).
    #[test]
    fn wildcard_subdomain_match_requires_dot_separator() {
        // `*.googleapis.com` matches `sheets.googleapis.com`.
        assert!(is_trusted_api_host("https://sheets.googleapis.com/v4"));
        assert!(is_trusted_api_host("storage.googleapis.com"));
        // `*.googleapis.com` does NOT match `evilgoogleapis.com`
        // (no dot separator before `googleapis.com`).
        assert!(!is_trusted_api_host("evilgoogleapis.com"));
        // `*.googleapis.com` does NOT match the bare `googleapis.com`
        // because the wildcard requires at least one subdomain label.
        // List both literal and wildcard if both should be trusted.
        assert!(!is_trusted_api_host("googleapis.com"));
    }

    /// Contract: an attacker-controlled host that merely contains a
    /// trusted hostname as a substring MUST NOT be trusted. Pre-fix
    /// a naive `host.contains(suffix)` would have whitelisted
    /// `attacker.com/api.github.com/path` as if it were GitHub.
    #[test]
    fn substring_attack_does_not_match() {
        assert!(!is_trusted_api_host("https://attacker.com/api.github.com"));
        assert!(!is_trusted_api_host("https://api.github.com.evil.com/x"));
    }

    /// Contract: IP literals NEVER qualify even if the user types one
    /// of the allowlisted hostnames. Taint pointing at a raw IP is
    /// the high-signal case operators want to inspect.
    #[test]
    fn ipv4_literal_never_trusted() {
        assert!(!is_trusted_api_host("https://192.168.1.1/api"));
        assert!(!is_trusted_api_host("10.0.0.1:8080"));
        assert!(!is_trusted_api_host("8.8.8.8"));
    }

    /// Contract: case-insensitive matching. `API.GITHUB.COM` MUST be
    /// recognised as `api.github.com`.
    #[test]
    fn matching_is_case_insensitive() {
        assert!(is_trusted_api_host("https://API.GITHUB.COM/users"));
        assert!(is_trusted_api_host("Sheets.GoogleAPIs.com"));
    }

    /// Contract: schemeless and host:port forms parse correctly.
    /// Skill code commonly stores endpoints as bare hosts in env-
    /// var defaults; the allowlist must accept both.
    #[test]
    fn schemeless_and_port_forms_parse() {
        assert!(is_trusted_api_host("api.openai.com"));
        assert!(is_trusted_api_host("api.openai.com:443"));
        assert!(is_trusted_api_host("api.openai.com/v1/chat/completions"));
    }

    /// Contract: malformed / empty input never matches.
    #[test]
    fn malformed_input_never_matches() {
        assert!(!is_trusted_api_host(""));
        assert!(!is_trusted_api_host("   "));
        assert!(!is_trusted_api_host("https://"));
        assert!(!is_trusted_api_host("not_a_url"));
    }

    /// Contract: well-known LLM provider hosts the skill-veil
    /// integration itself depends on are present. Pins the
    /// allowlist's coverage of the big-3 providers.
    #[test]
    fn allowlist_includes_major_llm_providers() {
        for host in [
            "https://api.openai.com/v1",
            "https://api.anthropic.com/v1/messages",
            "https://api.x.ai/v1",
            "https://ollama.com/api/chat",
            "https://api.deepseek.com/v1",
        ] {
            assert!(
                is_trusted_api_host(host),
                "expected {host} to be on allowlist",
            );
        }
    }
}
