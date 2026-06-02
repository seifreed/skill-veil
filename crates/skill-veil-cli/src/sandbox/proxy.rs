//! Parse the recording proxy's capture log into network behaviors.
//!
//! The proxy (`image/proxy.py`) writes one JSON object per intercepted
//! request to stdout, collected via `docker logs`. Each becomes a
//! `network_connect` behavior carrying the destination and the payload
//! the skill tried to send — the exfil *data*, not just the destination
//! an unproxied `connect()` would reveal. HTTPS is MITM-decrypted by the
//! proxy, so its captures carry the URL and body too; only when the TLS
//! interception fails does an entry fall back to the destination host
//! alone.

use serde::Deserialize;

use super::observation::{BehaviorClass, BehaviorSource, ObservedBehavior};

const MAX_BODY_IN_DETAIL: usize = 256;

#[derive(Debug, Deserialize)]
struct ProxyCapture {
    method: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    host: String,
    #[serde(default)]
    body: String,
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let head: String = text.chars().take(max).collect();
    format!("{head}…")
}

/// Convert the proxy's JSON-lines capture log into deduped
/// `network_connect` behaviors. Non-JSON lines (daemon/startup noise in
/// `docker logs`) are skipped.
pub(crate) fn parse_proxy_log(log: &str) -> Vec<ObservedBehavior> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in log.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(capture) = serde_json::from_str::<ProxyCapture>(line) else {
            continue;
        };
        let dest = if capture.url.is_empty() {
            capture.host.clone()
        } else {
            capture.url.clone()
        };
        if dest.is_empty() {
            continue;
        }
        let detail = if capture.body.is_empty() {
            format!("{} {dest}", capture.method)
        } else {
            format!(
                "{} {dest} body={}",
                capture.method,
                truncate(&capture.body, MAX_BODY_IN_DETAIL)
            )
        };
        if seen.insert(detail.clone()) {
            out.push(ObservedBehavior {
                class: BehaviorClass::NetworkConnect,
                detail,
                source: BehaviorSource::Script,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    /// An HTTP capture with a body yields a network behavior carrying the
    /// destination URL AND the exfiltrated payload — the data, not just
    /// the destination.
    #[test]
    fn http_capture_includes_destination_and_payload() {
        let log = r#"{"method":"POST","url":"http://c2.invalid/upload","host":"c2.invalid","body":"stolen=token123"}"#;
        let behaviors = parse_proxy_log(log);
        assert_eq!(behaviors.len(), 1);
        assert_eq!(behaviors[0].class, BehaviorClass::NetworkConnect);
        assert!(behaviors[0].detail.contains("http://c2.invalid/upload"));
        assert!(behaviors[0].detail.contains("stolen=token123"));
    }

    /// # Contract
    /// A MITM-decrypted HTTPS capture carries the `https://` URL AND the
    /// payload — the proxy recovers the exfil data over TLS, not just the
    /// destination.
    #[test]
    fn https_mitm_capture_includes_url_and_payload() {
        let log = r#"{"method":"POST","url":"https://c2.invalid/drop","host":"c2.invalid","body":"token=AKIA123"}"#;
        let behaviors = parse_proxy_log(log);
        assert_eq!(behaviors.len(), 1);
        assert_eq!(behaviors[0].class, BehaviorClass::NetworkConnect);
        assert!(behaviors[0].detail.contains("https://c2.invalid/drop"));
        assert!(behaviors[0].detail.contains("token=AKIA123"));
    }

    /// # Contract
    /// When TLS interception fails the proxy still emits the CONNECT
    /// destination host (the `tls_error` field is ignored by the parser),
    /// so the destination is never lost.
    #[test]
    fn connect_fallback_yields_destination_host() {
        let log = r#"{"method":"CONNECT","url":"evil.invalid:443","host":"evil.invalid:443","body":"","tls_error":"pinned"}"#;
        let behaviors = parse_proxy_log(log);
        assert_eq!(behaviors.len(), 1);
        assert!(behaviors[0].detail.contains("evil.invalid:443"));
        assert!(!behaviors[0].detail.contains("body="));
    }

    /// # Contract
    /// Non-JSON daemon/startup noise is ignored; identical captures dedup.
    #[test]
    fn skips_noise_and_dedups() {
        let log = "starting proxy...\n\
            {\"method\":\"GET\",\"url\":\"http://a/x\",\"host\":\"a\",\"body\":\"\"}\n\
            garbage line\n\
            {\"method\":\"GET\",\"url\":\"http://a/x\",\"host\":\"a\",\"body\":\"\"}\n";
        let behaviors = parse_proxy_log(log);
        assert_eq!(behaviors.len(), 1, "noise skipped + duplicates collapsed");
    }
}
