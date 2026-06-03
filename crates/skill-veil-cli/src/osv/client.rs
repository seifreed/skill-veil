//! Synchronous OSV.dev API client (no API key required).
//!
//! Mirrors the VirusTotal client's `ureq` posture: bounded timeouts, retry
//! on transient failures, and typed errors. Two endpoints are used:
//! `POST /v1/querybatch` (one call for all dependencies) and
//! `GET /v1/vulns/{id}` (advisory details).

use super::types::{BatchResponse, OsvQuery, ResolvedAdvisory, VulnDetails};
use std::time::Duration;
use thiserror::Error;

const BASE_URL: &str = "https://api.osv.dev/v1";
const USER_AGENT: &str = concat!(
    "skill-veil/",
    env!("CARGO_PKG_VERSION"),
    " (+osv-integration)"
);
const HTTP_TIMEOUT_SECS: u64 = 30;
const MAX_ADDITIONAL_ATTEMPTS: u32 = 2;
const INITIAL_BACKOFF_MS: u64 = 1_000;
const MAX_ADVISORY_ID_LEN: usize = 128;
/// Cap on an OSV API response body. A compromised or misbehaving endpoint
/// could otherwise stream an unbounded body into memory; every other API
/// client in this crate bounds its response the same way.
const MAX_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Error)]
pub(super) enum OsvError {
    #[error("OSV HTTP {status}")]
    HttpStatus { status: u16 },
    #[error("OSV transport error: {0}")]
    Transport(String),
    #[error("OSV response decode error: {0}")]
    Decode(String),
    #[error("invalid OSV advisory id: {0:?}")]
    InvalidAdvisoryId(String),
}

/// Whether `id` is the shape of an OSV advisory identifier (e.g. `GHSA-…`,
/// `CVE-2021-1234`, `PYSEC-2022-43012`). The IDs are taken from the network
/// `querybatch` response and interpolated into the `/vulns/{id}` path, so a
/// value carrying path or query metacharacters (`/`, `..`, `?`, `#`,
/// whitespace) must be rejected before it can shape the request URL rather
/// than being percent-mangled into an unintended same-host endpoint.
fn is_valid_advisory_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ADVISORY_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub(super) struct OsvClient {
    agent: ureq::Agent,
}

impl OsvClient {
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .build();
        Self { agent }
    }

    /// Look up every query in a single batch request. The returned vector is
    /// index-aligned with `queries`; each entry is the advisory IDs affecting
    /// that dependency (empty when none).
    pub fn query_batch(&self, queries: &[OsvQuery]) -> Result<Vec<Vec<String>>, OsvError> {
        let body = serde_json::json!({
            "queries": queries
                .iter()
                .map(|q| serde_json::json!({
                    "package": { "name": q.name, "ecosystem": q.ecosystem.osv_name() },
                    "version": q.version,
                }))
                .collect::<Vec<_>>(),
        });
        let url = format!("{BASE_URL}/querybatch");
        let parsed: BatchResponse = self.post_json(&url, &body)?;
        Ok(parsed
            .results
            .into_iter()
            .map(|r| r.vulns.into_iter().map(|v| v.id).collect())
            .collect())
    }

    /// Fetch full details for one advisory ID.
    pub fn advisory_details(&self, id: &str) -> Result<ResolvedAdvisory, OsvError> {
        if !is_valid_advisory_id(id) {
            return Err(OsvError::InvalidAdvisoryId(id.to_string()));
        }
        let url = format!("{BASE_URL}/vulns/{id}");
        let details: VulnDetails = self.get_json(&url)?;
        Ok(details.into_resolved())
    }

    fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<T, OsvError> {
        // `ureq::Error` is a large enum; box it at the closure boundary so the
        // retry helper's `Err` variant stays small (clippy::result_large_err).
        self.with_retry(|| {
            self.agent
                .post(url)
                .send_json(body.clone())
                .map_err(Box::new)
        })
    }

    fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str) -> Result<T, OsvError> {
        self.with_retry(|| self.agent.get(url).call().map_err(Box::new))
    }

    fn with_retry<T: serde::de::DeserializeOwned>(
        &self,
        mut send: impl FnMut() -> Result<ureq::Response, Box<ureq::Error>>,
    ) -> Result<T, OsvError> {
        let mut backoff = INITIAL_BACKOFF_MS;
        let mut attempt = 0;
        loop {
            let outcome = send();
            match outcome.map_err(|boxed| *boxed) {
                Ok(resp) => {
                    return decode_json_with_cap(resp, MAX_RESPONSE_BYTES);
                }
                Err(ureq::Error::Status(status, _)) => {
                    // Retry only on rate-limit / server errors.
                    if (status == 429 || status >= 500) && attempt < MAX_ADDITIONAL_ATTEMPTS {
                        attempt += 1;
                        std::thread::sleep(Duration::from_millis(backoff));
                        backoff = backoff.saturating_mul(2);
                        continue;
                    }
                    return Err(OsvError::HttpStatus { status });
                }
                Err(ureq::Error::Transport(t)) => {
                    if attempt < MAX_ADDITIONAL_ATTEMPTS {
                        attempt += 1;
                        std::thread::sleep(Duration::from_millis(backoff));
                        backoff = backoff.saturating_mul(2);
                        continue;
                    }
                    return Err(OsvError::Transport(t.to_string()));
                }
            }
        }
    }
}

/// Read an OSV response body with a size cap, then decode it as JSON. Bounds
/// the body before allocation so a hostile or misbehaving endpoint cannot
/// stream an unbounded payload into memory, matching the other API clients.
fn decode_json_with_cap<T: serde::de::DeserializeOwned>(
    resp: ureq::Response,
    cap: u64,
) -> Result<T, OsvError> {
    let body = crate::util::bounded_read::read_response_with_cap(resp, cap)
        .map_err(|e| OsvError::Decode(e.to_string()))?;
    serde_json::from_str::<T>(&body).map_err(|e| OsvError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_with_body(body: &str) -> ureq::Response {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
        .parse()
        .expect("synthetic response must parse")
    }

    /// Contract: a normal OSV response under the cap decodes as JSON. Guards
    /// the capped read path against breaking ordinary decoding.
    #[test]
    fn decode_json_with_cap_accepts_body_under_cap() {
        let value: serde_json::Value =
            decode_json_with_cap(response_with_body("{\"ok\":true}"), 1024).unwrap();
        assert_eq!(value["ok"], serde_json::Value::Bool(true));
    }

    /// Contract: a body larger than the cap is rejected before JSON decoding,
    /// so a hostile endpoint cannot exhaust memory through the OSV channel.
    #[test]
    fn decode_json_with_cap_rejects_body_over_cap() {
        let err = decode_json_with_cap::<serde_json::Value>(response_with_body("{\"x\":12345}"), 4)
            .expect_err("oversized OSV body must be rejected before decode");
        assert!(matches!(err, OsvError::Decode(_)));
    }

    #[test]
    fn advisory_id_validation_accepts_real_ids_and_rejects_url_shaping() {
        for ok in [
            "GHSA-xxxx-yyyy-zzzz",
            "CVE-2021-1234",
            "PYSEC-2022-43012",
            "OSV-2020-1.0_x",
        ] {
            assert!(is_valid_advisory_id(ok), "{ok} should be accepted");
        }
        for bad in [
            "",
            "../querybatch",
            "id with space",
            "a/b",
            "x?y",
            "x#frag",
            "a@b",
            "name%2e",
            "GHSA\u{0000}",
        ] {
            assert!(!is_valid_advisory_id(bad), "{bad:?} should be rejected");
        }
        assert!(
            !is_valid_advisory_id(&"a".repeat(MAX_ADVISORY_ID_LEN + 1)),
            "oversized id should be rejected"
        );
    }
}
