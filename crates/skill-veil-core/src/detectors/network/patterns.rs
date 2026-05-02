use crate::lazy_pattern;

lazy_pattern!(pub(crate) RE_HTTP_URL, r#"https?://[^\s"'`)]+"#);
lazy_pattern!(pub(crate) RE_RFC1918_10, r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
lazy_pattern!(pub(crate) RE_RFC1918_192, r"\b192\.168\.\d{1,3}\.\d{1,3}\b");
lazy_pattern!(
    pub(crate) RE_RFC1918_172,
    r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b"
);
// IPv6 loopback and IPv4-mapped IPv6 forms must be matched alongside
// their IPv4 equivalents — `http://[::1]/` and
// `http://[::ffff:169.254.169.254]/` reach the same sinks as their
// `127.0.0.1` / `169.254.169.254` counterparts on dual-stack clients,
// so omitting them lets a script swap its localhost / IMDS target
// into IPv6 form and bypass the pattern. The bracket-optional
// alternation accepts both URL forms (`[::1]`) and bare host forms
// (`::1`) since both shapes appear in real exploit code.
lazy_pattern!(
    pub(crate) RE_INTERNAL_ACTION,
    r"(?is)(curl|wget|fetch|requests\.(get|post)|axios\.(get|post)|invoke-webrequest|invoke-restmethod|httpx\.(get|post)|aiohttp|net/http|client\.get|client\.post|open websocket|connect to|proxy to|query|call|\bPOST\b|\bGET\b).{0,180}(169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|\[?::1\]?|\[?::ffff:\d{1,3}(\.\d{1,3}){3}\]?|[A-Za-z0-9._-]+\.internal|[A-Za-z0-9._-]+\.local)"
);
lazy_pattern!(
    pub(crate) RE_LOCAL_DEV_REFERENCE,
    r"(?i)(local development|for local dev|development server|run locally|example endpoint|sample endpoint|localhost for testing|dev server)"
);
lazy_pattern!(
    pub(crate) RE_LOCAL_CONTROL_PLANE,
    r"(?i)(dashboard|reload|register|heartbeat|local service|local api|development server|run locally|browser open http://localhost|http://localhost:\d+|serve_forever|httpserver)"
);
lazy_pattern!(
    pub(crate) RE_OPTIONAL_WEBHOOK_DOCS,
    r"(?is)(alternative:\s*webhook|see\s+/docs/webhooks|for details|if your agent has a publicly reachable endpoint|optional webhook|want real-time push notifications|fallback|polling system|no exposed ip needed|architecture)"
);
lazy_pattern!(
    pub(crate) RE_EXAMPLE_WEBHOOK,
    r"(?i)(example webhook|sample webhook|documentation only|for testing only)"
);
lazy_pattern!(
    pub(crate) RE_SSRF_FETCH_LINE,
    r"(?i)(curl|wget|fetch|requests\.(get|post)|axios\.(get|post)|invoke-webrequest|invoke-restmethod|httpx\.(get|post)|aiohttp|client\.get|client\.post).{0,180}(169\.254\.169\.254|127\.0\.0\.1|localhost|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|\[?::1\]?|\[?::ffff:\d{1,3}(\.\d{1,3}){3}\]?|[A-Za-z0-9._-]+\.internal|[A-Za-z0-9._-]+\.local)"
);
