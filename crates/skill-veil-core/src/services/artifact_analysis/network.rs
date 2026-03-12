use regex::Regex;

pub(super) fn extract_http_urls(content: &str) -> Vec<String> {
    let regex = Regex::new(r#"https?://[^\s"'`)]+"#).expect("valid url regex");
    regex
        .find_iter(content)
        .map(|m| {
            m.as_str()
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
    } else if Regex::new(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        .expect("valid regex")
        .is_match(&lower)
    {
        Some("rfc1918:10/8")
    } else if Regex::new(r"\b192\.168\.\d{1,3}\.\d{1,3}\b")
        .expect("valid regex")
        .is_match(&lower)
    {
        Some("rfc1918:192.168/16")
    } else if Regex::new(r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b")
        .expect("valid regex")
        .is_match(&lower)
    {
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
    Regex::new(
        r#"(?is)(curl|wget|fetch|requests\.(get|post)|axios\.(get|post)|invoke-webrequest|invoke-restmethod|httpx\.(get|post)|aiohttp|net/http|client\.get|client\.post|open websocket|connect to|proxy to|query|call|POST|GET).{0,180}(169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|\.internal|\.local)"#,
    )
    .expect("valid regex")
    .is_match(content)
}

pub(super) fn looks_like_local_dev_reference(content: &str) -> bool {
    Regex::new(
        r#"(?i)(local development|for local dev|development server|run locally|example endpoint|sample endpoint|localhost for testing|dev server)"#,
    )
    .expect("valid regex")
    .is_match(content)
}

pub(super) fn looks_like_local_control_plane_reference(content: &str) -> bool {
    Regex::new(
        r#"(?i)(dashboard|reload|register|heartbeat|local service|local api|development server|run locally|browser open http://localhost|http://localhost:\d+|serve_forever|httpserver)"#,
    )
    .expect("valid regex")
    .is_match(content)
}

pub(super) fn looks_like_optional_webhook_docs(content: &str) -> bool {
    Regex::new(
        r#"(?is)(alternative:\s*webhook|see\s+/docs/webhooks|for details|if your agent has a publicly reachable endpoint|optional webhook|want real-time push notifications|fallback|polling system|no exposed ip needed|architecture)"#,
    )
    .expect("valid regex")
    .is_match(content)
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
        && !Regex::new(
            r#"(?i)(example webhook|sample webhook|documentation only|for testing only)"#,
        )
        .expect("valid regex")
        .is_match(content)
    {
        Some("public_inbound_endpoint")
    } else {
        None
    }
}

pub(super) fn contains_ssrf_like_fetch_line(content: &str) -> bool {
    let regex = Regex::new(
        r#"(?i)(curl|wget|fetch|requests\.(get|post)|axios\.(get|post)|invoke-webrequest|invoke-restmethod|httpx\.(get|post)|aiohttp|client\.get|client\.post).{0,180}(169\.254\.169\.254|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|[A-Za-z0-9._-]+\.internal|[A-Za-z0-9._-]+\.local)"#,
    )
    .expect("valid regex");
    content.lines().any(|line| regex.is_match(line))
}
