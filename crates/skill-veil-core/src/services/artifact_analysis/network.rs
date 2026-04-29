mod patterns;

use patterns::{
    RE_EXAMPLE_WEBHOOK, RE_HTTP_URL, RE_INTERNAL_ACTION, RE_LOCAL_CONTROL_PLANE,
    RE_LOCAL_DEV_REFERENCE, RE_OPTIONAL_WEBHOOK_DOCS, RE_RFC1918_10, RE_RFC1918_172,
    RE_RFC1918_192, RE_SSRF_FETCH_LINE,
};

pub(super) fn extract_http_urls(content: &str) -> Vec<String> {
    RE_HTTP_URL
        .find_matches(content)
        .into_iter()
        .map(|m| {
            m.matched_text
                .trim_end_matches(&['"', '\'', ')'][..])
                .to_string()
        })
        .collect()
}

pub(super) fn is_common_lockfile_source(url: &str) -> bool {
    [
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "repo.yarnpkg.com",
        "mirrors.tencentyun.com",
        "registry.npmmirror.com",
        "registry.yarnpkg.cn",
    ]
    .iter()
    .any(|host| url.contains(host))
}

pub(super) fn contains_internal_network_target(content: &str) -> Option<&'static str> {
    let lower = content.to_ascii_lowercase();
    if lower.contains("169.254.169.254") {
        Some("169.254.169.254")
    } else if lower.contains("127.0.0.1") {
        Some("127.0.0.1")
    } else if lower.contains("localhost") {
        Some("localhost")
    } else if lower.contains("0.0.0.0") {
        Some("0.0.0.0")
    } else if RE_RFC1918_10.is_match(&lower) {
        Some("rfc1918:10/8")
    } else if RE_RFC1918_192.is_match(&lower) {
        Some("rfc1918:192.168/16")
    } else if RE_RFC1918_172.is_match(&lower) {
        Some("rfc1918:172.16/12")
    } else if lower.contains(".internal") {
        Some(".internal")
    } else if lower.contains(".local") {
        Some(".local")
    } else {
        None
    }
}

pub(super) fn contains_internal_network_action(content: &str) -> bool {
    RE_INTERNAL_ACTION.is_match(content)
}

pub(super) fn looks_like_local_dev_reference(content: &str) -> bool {
    RE_LOCAL_DEV_REFERENCE.is_match(content)
}

pub(super) fn looks_like_local_control_plane_reference(content: &str) -> bool {
    RE_LOCAL_CONTROL_PLANE.is_match(content)
}

pub(super) fn looks_like_optional_webhook_docs(content: &str) -> bool {
    RE_OPTIONAL_WEBHOOK_DOCS.is_match(content)
}

pub(super) fn looks_like_webhook_receiver_without_auth(content: &str) -> Option<&'static str> {
    let lower = content.to_ascii_lowercase();
    if lower.contains("skip signature validation")
        || lower.contains("no verification required")
        || lower.contains("accept any payload")
        || lower.contains("unsigned webhook")
        || lower.contains("without auth")
    {
        Some("webhook_auth_bypass")
    } else if lower.contains("webhook")
        && (lower.contains("listener")
            || lower.contains("receiver")
            || lower.contains("inbound")
            || lower.contains("callback endpoint")
            || lower.contains("listen on all interfaces")
            || lower.contains("post /api/webhook"))
        && (lower.contains("public endpoint")
            || lower.contains("publicly reachable")
            || lower.contains("0.0.0.0")
            || lower.contains("accept callbacks")
            || lower.contains("incoming webhooks"))
        && !(lower.contains("verify signature")
            || lower.contains("signature verification")
            || lower.contains("hmac")
            || lower.contains("shared secret")
            || lower.contains("signing secret")
            || lower.contains("webhook secret")
            || lower.contains("validate signature"))
        && !looks_like_optional_webhook_docs(content)
        && !RE_EXAMPLE_WEBHOOK.is_match(content)
    {
        Some("public_inbound_endpoint")
    } else {
        None
    }
}

pub(super) fn contains_ssrf_like_fetch_line(content: &str) -> bool {
    content
        .lines()
        .any(|line| RE_SSRF_FETCH_LINE.is_match(line))
}
