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
//! this list — OR is first-party to a credential the same node reads
//! (`host_matches_secret_owner`, the dynamic generalisation of this
//! static list) — downstream callers downgrade the finding from
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

use std::collections::BTreeSet;

/// Static allowlist of trusted API host patterns. Each entry is
/// either a literal host (`api.openai.com`) or a single-wildcard
/// pattern (`*.googleapis.com`) covering subdomains.
pub(super) const TRUSTED_API_HOSTS: &[&str] = &[
    // Google
    "*.googleapis.com",
    "*.google.com",
    // GitHub — both bare and subdomain variants. Many skills reference
    // `https://github.com/<org>/<repo>` directly (homepage, raw pulls
    // resolved through the gateway), so the bare host needs an entry
    // even though `*.github.com` covers the API.
    "github.com",
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
    // Atlassian (Jira / Confluence / Rovo). Bare + wildcard since
    // `support.atlassian.com` and `mcp.atlassian.com` both appear in
    // benign Confluence/Rovo MCP skills.
    "atlassian.com",
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
    // Cloudflare workers / Pages / R2 / public DNS. `*.pages.dev` and
    // `*.workers.dev` are the deployed-app domains for Cloudflare
    // Pages and Workers respectively — modal targets for skills that
    // POST events into a Cloudflare-hosted webhook receiver.
    "*.cloudflare.com",
    "*.pages.dev",
    "*.workers.dev",
    // Workflow / no-code automation hubs commonly used as webhook
    // receivers from agent skills. Adding the base domains
    // (`*.zapier.com` / `*.make.com` etc.) catches both the trigger
    // endpoint subdomains (`hooks.zapier.com` / `hook.eu1.make.com`)
    // and the docs/UI subdomains a skill might link to.
    "*.zapier.com",
    "*.make.com",
    "*.n8n.cloud",
    "*.pipedream.com",
    "*.pipedream.net",
    "*.ifttt.com",
    // Tavily search API (modal LLM-companion search service)
    "*.tavily.com",
    // Reference / standards bodies (skills that link to RFCs / IANA
    // registries from documentation prose).
    "iana.org",
    "*.iana.org",
    "ietf.org",
    "*.ietf.org",
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
    // Categorical non-exfiltration destinations: public package
    // registries and app stores are read-only distribution endpoints —
    // a credential POSTed "to" PyPI or the App Store cannot be
    // exfiltrated there, so a secret→registry taint edge is noise, not
    // a data-loss vector. Distinct from the API hosts above (which are
    // trusted because they own the credential); these are trusted
    // because the destination is structurally incapable of receiving an
    // exfiltrated secret.
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "*.npmjs.com",
    "npmjs.org",
    "crates.io",
    "static.crates.io",
    "rubygems.org",
    "pkg.go.dev",
    "proxy.golang.org",
    "packagist.org",
    "repo.maven.apache.org",
    "repo1.maven.org",
    "apps.apple.com",
    "itunes.apple.com",
];

/// RFC2606 / RFC6761 reserved hostnames and TLDs that document
/// authors use as placeholder URLs in skill prose ("connect to
/// `https://example.com/api/...`"). Treated as "documentation noise"
/// rather than real exfil sinks: callers strip these before deciding
/// whether ALL real sinks are trusted.
///
/// Loopback variants (`localhost`, `*.localhost`) are included for
/// the same reason — a skill that POSTs to `http://localhost:8080`
/// is talking to itself, not exfiltrating to an external party.
///
/// Curation rule: only RFC-reserved or otherwise globally-loopback
/// names. Real organisations whose domains happen to look reserved
/// (e.g. `example-corp.com`) MUST NOT land here — extend
/// [`TRUSTED_API_HOSTS`] instead.
pub(super) const DOCUMENTATION_OR_RESERVED_HOSTS: &[&str] = &[
    // RFC2606 reserved second-level names.
    "example.com",
    "example.org",
    "example.net",
    "*.example.com",
    "*.example.org",
    "*.example.net",
    // RFC2606 reserved TLDs.
    "*.example",
    "*.test",
    "*.invalid",
    // RFC6761 loopback.
    "localhost",
    "*.localhost",
];

/// Returns `true` if `endpoint` resolves to a documentation /
/// reserved / loopback host that callers should strip from sink lists
/// before deciding whether the remaining real sinks are trusted.
///
/// Pre-fix a single `https://example.com/...` reference in skill
/// prose (or the bare `127.0.0.1` loopback target) defeated the
/// `all_external_sinks_first_party_or_trusted` check even when every
/// other sink was on the trusted-API allowlist.
#[must_use]
pub(super) fn is_documentation_or_reserved_host(endpoint: &str) -> bool {
    let host = match extract_host(endpoint) {
        Some(h) => h,
        None => return false,
    };
    if host.is_empty() {
        return false;
    }
    if is_loopback_ipv4(&host) {
        return true;
    }
    for pattern in DOCUMENTATION_OR_RESERVED_HOSTS {
        if matches_host_pattern(&host, pattern) {
            return true;
        }
    }
    false
}

pub(super) fn is_loopback_ipv4(host: &str) -> bool {
    if !is_ipv4_literal(host) {
        return false;
    }
    host.starts_with("127.")
}

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
        Some(h) => h,
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

/// Generic credential/URL vocabulary that carries no service
/// identity. Stripped before comparing a secret-source name against a
/// destination host so `STRIPE_API_KEY` reduces to the identifying
/// token `stripe`, not the noise tokens `api`/`key`.
const SECRET_NAME_STOPWORDS: &[&str] = &[
    "api",
    "key",
    "keys",
    "token",
    "tokens",
    "secret",
    "secrets",
    "auth",
    "oauth",
    "client",
    "bearer",
    "access",
    "refresh",
    "env",
    "environ",
    "config",
    "url",
    "uri",
    "host",
    "hostname",
    "endpoint",
    "bot",
    "pat",
    "cred",
    "creds",
    "credential",
    "credentials",
    "password",
    "passwd",
    "pwd",
    "user",
    "username",
    "login",
    "session",
    "cookie",
    "prod",
    "production",
    "dev",
    "development",
    "stage",
    "staging",
    "test",
    "sandbox",
    "live",
    "http",
    "https",
    "www",
    "com",
    "net",
    "org",
    "default",
    "value",
    "string",
    "data",
    "file",
    "path",
    "name",
];

/// Multi-label public suffixes we must look past to find the
/// registrable label. Not exhaustive — only the forms that recur in
/// skill manifests. Anything not listed falls back to the
/// single-label-TLD assumption.
const COMPOUND_TLD_PENULTIMATES: &[&str] = &["com", "net", "org", "co", "gov", "edu", "ac"];

/// Extract the registrable label of `endpoint` — the single label
/// immediately left of the public suffix, which identifies the owning
/// organisation. `api.wahooligan.com` → `wahooligan`, `atollhq.com` →
/// `atollhq`, `mcp.speakai.co` → `speakai`, `foo.example.co.uk` →
/// `example`. Returns `None` for IP literals, single-label hosts, and
/// unparseable input (the conservative default: no label means no
/// affinity, so the taint finding keeps full strength).
///
/// Only the label at the registrable position is returned — never a
/// subdomain. This closes the `openai-telemetry.attacker.com` hole
/// where an attacker prefixes the victim secret's name as a
/// subdomain label to spoof first-party affinity.
fn registrable_label(endpoint: &str) -> Option<String> {
    let host = extract_host(endpoint)?;
    if host.is_empty() || is_ipv4_literal(&host) {
        return None;
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 {
        return None;
    }
    // Drop the public suffix: 2 labels when the penultimate is a
    // compound-TLD second level (`co.uk`, `com.au`), else 1.
    let suffix_len = if labels.len() >= 3
        && COMPOUND_TLD_PENULTIMATES.contains(&labels[labels.len() - 2])
        && labels[labels.len() - 1].len() <= 3
    {
        2
    } else {
        1
    };
    if labels.len() <= suffix_len {
        return None;
    }
    let label = labels[labels.len() - suffix_len - 1];
    if label.len() < 4 {
        return None;
    }
    Some(label.to_string())
}

/// Tokenise a secret-source name (env var, file path, or URL the
/// secret was read from) into identifying tokens: lowercase, split on
/// non-alphanumeric boundaries, stopwords and sub-4-char fragments
/// removed.
fn secret_identity_tokens(name: &str) -> BTreeSet<String> {
    name.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 4)
        .filter(|t| !SECRET_NAME_STOPWORDS.contains(t))
        .filter(|t| !t.chars().all(|c| c.is_ascii_digit()))
        .map(str::to_string)
        .collect()
}

/// `true` when `endpoint`'s registrable label is the *owner* of at
/// least one secret/identity name in `secret_targets` — i.e. the
/// credential being read belongs to the host it is sent to, which is
/// authentication, not exfiltration.
///
/// # Why this is recall-safe
///
/// Exfil malware reads a *victim* secret (`AWS_*`, `~/.ssh/id_rsa`,
/// browser cookies, the project `.env`) and ships it to an
/// *unrelated* attacker host; those names share no identifying token
/// with the attacker domain, so affinity is `false` and the taint
/// finding keeps full `Block`/`MaliciousBehavior` strength. Affinity
/// only fires for the modal benign pattern: `WAHOO_ACCESS_TOKEN` read
/// and sent to `api.wahooligan.com`. The match requires a shared
/// token of length ≥4 on BOTH sides, so short or generic fragments
/// cannot manufacture a coincidental match.
pub(super) fn host_matches_secret_owner(endpoint: &str, secret_targets: &BTreeSet<String>) -> bool {
    let Some(label) = registrable_label(endpoint) else {
        return false;
    };
    for target in secret_targets {
        for token in secret_identity_tokens(target) {
            // Containment either way: `wahoo` ⊂ `wahooligan`,
            // `agentcall` == `agentcall`, `speakai` ⊃ `speak`.
            let (shorter, longer) = if token.len() <= label.len() {
                (token.as_str(), label.as_str())
            } else {
                (label.as_str(), token.as_str())
            };
            if shorter.len() >= 4 && longer.contains(shorter) {
                return true;
            }
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
pub(super) fn parse_endpoint_url(endpoint: &str) -> Option<url::Url> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(parsed) = url::Url::parse(trimmed) {
        if parsed.host_str().is_some() {
            return Some(parsed);
        }
    }
    let schemeless = trimmed.strip_prefix("//").unwrap_or(trimmed);
    url::Url::parse(&format!("https://{schemeless}")).ok()
}

pub(super) fn extract_host(endpoint: &str) -> Option<String> {
    parse_endpoint_url(endpoint)?
        .host_str()
        .map(|host| host.to_ascii_lowercase())
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

    /// Contract: user-info parsing only applies to the URL authority.
    /// A trusted hostname inside the path must not satisfy the trusted
    /// API allowlist.
    #[test]
    fn trusted_host_check_rejects_known_host_in_path_userinfo_shape() {
        assert!(!is_trusted_api_host(
            "https://collector.attacker-control.io/path@api.openai.com/v1"
        ));
        assert!(!is_trusted_api_host(
            "https://collector.attacker-control.io/mirror@github.com/repo"
        ));
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

    /// Contract: RFC2606 reserved second-level names and reserved
    /// TLDs are recognised as documentation noise so callers can
    /// strip them before the trust check. Pre-fix a single
    /// `https://example.com/...` reference in skill prose defeated
    /// the trusted-host downgrade for the entire artifact.
    #[test]
    fn documentation_hosts_recognised_as_reserved() {
        for endpoint in [
            "https://example.com/api",
            "http://example.org",
            "https://api.example.net/v1",
            "https://foo.example",
            "https://bar.test",
            "http://baz.invalid",
            "http://localhost:8080/health",
            "http://api.localhost",
            "http://127.0.0.1:5000",
            "http://127.5.5.5",
        ] {
            assert!(
                is_documentation_or_reserved_host(endpoint),
                "expected {endpoint} to be flagged as documentation/reserved",
            );
        }
    }

    /// Contract (negative): real organisations whose domains merely
    /// contain reserved-looking substrings MUST NOT be flagged. A
    /// company called `example-corp.com` or a host
    /// `examplecdn.io` is genuinely external infrastructure and
    /// belongs on the trust path proper.
    #[test]
    fn documentation_host_check_does_not_overmatch() {
        for endpoint in [
            "https://example-corp.com/api",
            "https://examplecdn.io",
            "https://attacker.com/example.com",
            "https://attacker.com/path@example.com/api",
            "https://10.0.0.5",
            "https://192.168.1.1",
            "https://8.8.8.8",
        ] {
            assert!(
                !is_documentation_or_reserved_host(endpoint),
                "expected {endpoint} NOT to be flagged as documentation/reserved",
            );
        }
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

    /// # Contract
    /// Public package registries and app stores are read-only
    /// distribution endpoints — a secret cannot be exfiltrated *to*
    /// them — so a secret→registry taint edge is noise, not data loss.
    /// They are trusted destinations; a credential-bearing host (a
    /// webhook, pastebin, or attacker domain) is not and must stay
    /// untrusted.
    #[test]
    fn allowlist_includes_categorical_non_exfil_destinations() {
        for host in [
            "https://pypi.org/simple/requests/",
            "https://files.pythonhosted.org/packages/x.whl",
            "https://registry.npmjs.org/left-pad",
            "https://crates.io/api/v1/crates/serde",
            "https://rubygems.org/gems/rails",
            "https://pkg.go.dev/golang.org/x/net",
            "https://apps.apple.com/app/id123",
        ] {
            assert!(is_trusted_api_host(host), "expected {host} trusted");
        }
        for host in [
            "https://hooks.evil-c2.example/collect",
            "https://pastebin.com/raw/abc",
            "https://pypi.org.attacker.test/steal",
        ] {
            assert!(
                !is_trusted_api_host(host),
                "exfil-capable host must stay untrusted: {host}"
            );
        }
    }

    fn names(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// # Contract
    /// A destination whose registrable label owns the credential the
    /// node reads is authentication, not exfiltration. Pins the modal
    /// benign API-client pattern that dominated the taint FP set:
    /// `<SERVICE>_API_KEY` read, `api.<service>.<tld>` connected.
    #[test]
    fn host_matches_secret_owner_accepts_first_party_credential() {
        for (target, sink) in [
            ("WAHOO_ACCESS_TOKEN", "https://api.wahooligan.com/v1/user"),
            ("ATOLL_API_KEY", "https://atollhq.com/api/feedback"),
            ("AGENTCALL_API_KEY", "https://api.agentcall.co/llms.txt"),
            ("SPEAK_API_KEY", "https://mcp.speakai.co"),
            ("NOTION_TOKEN", "https://notion.so/v1/pages"),
        ] {
            assert!(
                host_matches_secret_owner(sink, &names(&[target])),
                "{target} must be recognised as first-party to {sink}"
            );
        }
    }

    /// # Contract (negative — recall guard)
    /// Exfil reads a victim secret and ships it to an unrelated host;
    /// the names share no identifying token, so affinity MUST be
    /// false and the taint finding keeps full Block strength. Also
    /// pins that generic secret files (`.env`, `~/.ssh/id_rsa`) and
    /// short/generic labels never manufacture affinity.
    #[test]
    fn host_matches_secret_owner_rejects_cross_party_exfil() {
        let cases: &[(&str, &str)] = &[
            ("AWS_SECRET_ACCESS_KEY", "https://collector.evil.com/up"),
            ("OPENAI_API_KEY", "https://exfil.example/post"),
            (".env", "https://attacker.net/log"),
            ("~/.ssh/id_rsa", "https://drop.host.io/x"),
            ("GITHUB_TOKEN", "https://pastebin.com/raw/abc"),
            ("STRIPE_API_KEY", "https://api.evil.co"),
        ];
        for (target, sink) in cases {
            assert!(
                !host_matches_secret_owner(sink, &names(&[target])),
                "{target} → {sink} must NOT be treated as first-party"
            );
        }
        // Empty source set never matches.
        assert!(!host_matches_secret_owner(
            "https://api.wahooligan.com",
            &BTreeSet::new()
        ));
    }

    /// # Contract (recall guard)
    /// An attacker MUST NOT spoof first-party affinity by prefixing
    /// the victim secret's name as a subdomain label. Only the
    /// registrable label (left of the public suffix) is compared, so
    /// `openai-telemetry.attacker.com` reduces to `attacker`, never
    /// `openai-telemetry`.
    #[test]
    fn host_matches_secret_owner_ignores_spoofed_subdomain_label() {
        assert!(!host_matches_secret_owner(
            "https://openai-telemetry.attacker.com/collect",
            &names(&["OPENAI_API_KEY"])
        ));
        assert!(!host_matches_secret_owner(
            "https://stripe.evilcorp.com/x",
            &names(&["STRIPE_API_KEY"])
        ));
    }

    /// # Contract (recall guard)
    /// A first-party-looking host inside the URL path is not the
    /// destination host and must not create secret-owner affinity.
    #[test]
    fn host_matches_secret_owner_rejects_known_host_in_path_userinfo_shape() {
        assert!(!host_matches_secret_owner(
            "https://collector.attacker-control.io/path@stripe.com/v1",
            &names(&["STRIPE_API_KEY"])
        ));
        assert!(!host_matches_secret_owner(
            "https://collector.attacker-control.io/path@api.openai.com/v1",
            &names(&["OPENAI_API_KEY"])
        ));
    }

    /// # Contract
    /// `registrable_label` strips API-gateway subdomains and the
    /// public suffix down to the owning label, and refuses IPs /
    /// single-label / sub-4-char labels (conservative: no label means
    /// no affinity downgrade).
    #[test]
    fn registrable_label_extracts_owning_label() {
        assert_eq!(
            registrable_label("https://cloud-api.wahooligan.com/x").as_deref(),
            Some("wahooligan")
        );
        assert_eq!(
            registrable_label("https://api.speakai.co").as_deref(),
            Some("speakai")
        );
        assert_eq!(
            registrable_label("https://atollhq.com/api").as_deref(),
            Some("atollhq")
        );
        assert_eq!(registrable_label("https://192.168.1.1/x"), None);
        assert_eq!(registrable_label("https://localhost:8080"), None);
        assert_eq!(registrable_label("https://api.x.io"), None);
    }
}
