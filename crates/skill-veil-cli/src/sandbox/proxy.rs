//! Parse the recording proxy's capture log into structured network captures.
//!
//! The proxy (`image/proxy.py`) writes one JSON object per intercepted
//! request to stdout, collected via `docker logs`. Each is parsed into a
//! [`NetworkCapture`] carrying the destination, request headers, and the
//! payload the skill tried to send — the exfil *data*, not just the
//! destination an unproxied `connect()` would reveal. HTTPS is
//! MITM-decrypted by the proxy, so its captures carry the URL, headers, and
//! body too; only when the TLS interception fails does an entry fall back to
//! the destination host alone.
//!
//! Each capture flattens into a `network_connect` behavior
//! ([`NetworkCapture::to_behavior`]) for the mapping → finding path, while
//! the full structured capture is retained for the dynamic report's
//! `network_captures` section.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::observation::{BehaviorClass, BehaviorSource, ObservedBehavior};

const MAX_BODY_IN_DETAIL: usize = 256;

/// One structured request the recording proxy intercepted. Serialized
/// verbatim into the dynamic report's `network_captures` section so an
/// operator sees the full destination, request headers, and payload — not
/// only the flattened one-line `detail` that becomes a behavior/finding.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct NetworkCapture {
    pub(crate) method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) url: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) host: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) body: String,
    /// Full request headers (BTreeMap so the serialized order is stable).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) headers: BTreeMap<String, String>,
    /// Present when TLS interception failed (the destination still survives).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tls_error: Option<String>,
    /// Present when an allowlisted forward attempt failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) forward_error: Option<String>,
}

impl NetworkCapture {
    fn destination(&self) -> &str {
        if self.url.is_empty() {
            &self.host
        } else {
            &self.url
        }
    }

    /// Flatten into the one-line behavior the mapping turns into a
    /// `SANDBOX_NETWORK_CONNECT` finding: `METHOD dest [body=…]`.
    pub(crate) fn to_behavior(&self) -> ObservedBehavior {
        let dest = self.destination();
        let detail = if self.body.is_empty() {
            format!("{} {dest}", self.method)
        } else {
            format!(
                "{} {dest} body={}",
                self.method,
                truncate(&self.body, MAX_BODY_IN_DETAIL)
            )
        };
        ObservedBehavior {
            class: BehaviorClass::NetworkConnect,
            detail,
            source: BehaviorSource::Script,
        }
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let head: String = text.chars().take(max).collect();
    format!("{head}…")
}

/// Parse the proxy's JSON-lines capture log into deduped structured
/// captures. Non-JSON lines (daemon/startup noise in `docker logs`) are
/// skipped, captures with no destination are dropped, and entries that
/// flatten to an identical behavior `detail` collapse.
pub(crate) fn parse_proxy_log(log: &str) -> Vec<NetworkCapture> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in log.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(capture) = serde_json::from_str::<NetworkCapture>(line) else {
            continue;
        };
        if capture.destination().is_empty() {
            continue;
        }
        if seen.insert(capture.to_behavior().detail) {
            out.push(capture);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    /// An HTTP capture with a body parses into a structured capture carrying
    /// the destination URL, request headers, AND the exfiltrated payload, and
    /// flattens into a network behavior carrying destination + payload.
    #[test]
    fn http_capture_includes_destination_headers_and_payload() {
        let log = r#"{"method":"POST","url":"http://c2.invalid/upload","host":"c2.invalid","body":"stolen=token123","headers":{"User-Agent":"evil/1.0","Authorization":"Bearer X"}}"#;
        let captures = parse_proxy_log(log);
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].url, "http://c2.invalid/upload");
        assert_eq!(captures[0].body, "stolen=token123");
        assert_eq!(
            captures[0].headers.get("Authorization").map(String::as_str),
            Some("Bearer X")
        );
        let behavior = captures[0].to_behavior();
        assert_eq!(behavior.class, BehaviorClass::NetworkConnect);
        assert!(behavior.detail.contains("http://c2.invalid/upload"));
        assert!(behavior.detail.contains("stolen=token123"));
    }

    /// # Contract
    /// A MITM-decrypted HTTPS capture carries the `https://` URL, headers,
    /// AND the payload — the proxy recovers the exfil data over TLS, not just
    /// the destination.
    #[test]
    fn https_mitm_capture_includes_url_headers_and_payload() {
        let log = r#"{"method":"POST","url":"https://c2.invalid/drop","host":"c2.invalid","body":"token=AKIA123","headers":{"Content-Type":"application/json"}}"#;
        let captures = parse_proxy_log(log);
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].url, "https://c2.invalid/drop");
        assert_eq!(captures[0].body, "token=AKIA123");
        assert_eq!(
            captures[0].headers.get("Content-Type").map(String::as_str),
            Some("application/json")
        );
    }

    /// # Contract
    /// When TLS interception fails the proxy still emits the CONNECT
    /// destination host AND the `tls_error`; the structured capture retains
    /// the error while the behavior keeps the destination (never lost).
    #[test]
    fn connect_fallback_yields_destination_and_tls_error() {
        let log = r#"{"method":"CONNECT","url":"evil.invalid:443","host":"evil.invalid:443","body":"","tls_error":"pinned"}"#;
        let captures = parse_proxy_log(log);
        assert_eq!(captures.len(), 1);
        assert_eq!(captures[0].tls_error.as_deref(), Some("pinned"));
        let behavior = captures[0].to_behavior();
        assert!(behavior.detail.contains("evil.invalid:443"));
        assert!(!behavior.detail.contains("body="));
    }

    /// # Contract
    /// Non-JSON daemon/startup noise is ignored; captures that flatten to an
    /// identical behavior collapse.
    #[test]
    fn skips_noise_and_dedups() {
        let log = "starting proxy...\n\
            {\"method\":\"GET\",\"url\":\"http://a/x\",\"host\":\"a\",\"body\":\"\"}\n\
            garbage line\n\
            {\"method\":\"GET\",\"url\":\"http://a/x\",\"host\":\"a\",\"body\":\"\"}\n";
        let captures = parse_proxy_log(log);
        assert_eq!(captures.len(), 1, "noise skipped + duplicates collapsed");
    }
}
