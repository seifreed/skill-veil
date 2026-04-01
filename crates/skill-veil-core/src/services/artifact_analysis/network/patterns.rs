use regex::Regex;
use std::sync::LazyLock;

pub(super) static RE_HTTP_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s"'`)]+"#).expect("valid url regex"));
pub(super) static RE_RFC1918_10: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").expect("valid regex"));
pub(super) static RE_RFC1918_192: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b192\.168\.\d{1,3}\.\d{1,3}\b").expect("valid regex"));
pub(super) static RE_RFC1918_172: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b").expect("valid regex")
});
pub(super) static RE_INTERNAL_ACTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)(curl|wget|fetch|requests\.(get|post)|axios\.(get|post)|invoke-webrequest|invoke-restmethod|httpx\.(get|post)|aiohttp|net/http|client\.get|client\.post|open websocket|connect to|proxy to|query|call|POST|GET).{0,180}(169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|\.internal|\.local)"#,
    )
    .expect("valid regex")
});
pub(super) static RE_LOCAL_DEV_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(local development|for local dev|development server|run locally|example endpoint|sample endpoint|localhost for testing|dev server)"#,
    )
    .expect("valid regex")
});
pub(super) static RE_LOCAL_CONTROL_PLANE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(dashboard|reload|register|heartbeat|local service|local api|development server|run locally|browser open http://localhost|http://localhost:\d+|serve_forever|httpserver)"#,
    )
    .expect("valid regex")
});
pub(super) static RE_OPTIONAL_WEBHOOK_DOCS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)(alternative:\s*webhook|see\s+/docs/webhooks|for details|if your agent has a publicly reachable endpoint|optional webhook|want real-time push notifications|fallback|polling system|no exposed ip needed|architecture)"#,
    )
    .expect("valid regex")
});
pub(super) static RE_EXAMPLE_WEBHOOK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(example webhook|sample webhook|documentation only|for testing only)"#)
        .expect("valid regex")
});
pub(super) static RE_SSRF_FETCH_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)(curl|wget|fetch|requests\.(get|post)|axios\.(get|post)|invoke-webrequest|invoke-restmethod|httpx\.(get|post)|aiohttp|client\.get|client\.post).{0,180}(169\.254\.169\.254|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|[A-Za-z0-9._-]+\.internal|[A-Za-z0-9._-]+\.local)"#,
    )
    .expect("valid regex")
});
