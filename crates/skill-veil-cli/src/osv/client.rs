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

#[derive(Debug, Error)]
pub(super) enum OsvError {
    #[error("OSV HTTP {status}")]
    HttpStatus { status: u16 },
    #[error("OSV transport error: {0}")]
    Transport(String),
    #[error("OSV response decode error: {0}")]
    Decode(String),
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
                    return resp
                        .into_json::<T>()
                        .map_err(|e| OsvError::Decode(e.to_string()));
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
