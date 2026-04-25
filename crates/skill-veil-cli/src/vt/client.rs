//! Synchronous VirusTotal v3 API client.
//!
//! Built on `ureq` so the CLI gains HTTPS without dragging in an async
//! runtime. Only the endpoints skill-veil actually needs are exposed:
//! Intelligence search, file report, and file download. Rate-limit responses
//! (HTTP 429) are retried with exponential backoff; other non-2xx statuses
//! surface as typed errors so the caller can distinguish auth failures (401),
//! quota exhaustion, and transient network faults.

use super::config::VtConfig;
use super::types::{FileReportEnvelope, SearchResponse};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

const BASE_URL: &str = "https://www.virustotal.com/api/v3";
const USER_AGENT: &str = concat!(
    "skill-veil/",
    env!("CARGO_PKG_VERSION"),
    " (+vt-integration)"
);
const MAX_RETRIES: u32 = 3;
const INITIAL_BACKOFF_MS: u64 = 2_000;
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 60;
const DOWNLOAD_HTTP_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Error)]
pub(crate) enum VtError {
    #[error("VirusTotal rejected the request (HTTP {status}): {body}")]
    HttpStatus { status: u16, body: String },
    #[error("VirusTotal authentication failed (check your apikey)")]
    Unauthorized,
    #[error("VirusTotal rate limit exceeded after {retries} retries")]
    RateLimited { retries: u32 },
    #[error("network error talking to VirusTotal: {0}")]
    Network(String),
    #[error("failed to decode VirusTotal response: {0}")]
    Decode(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub(crate) struct VtClient {
    apikey: String,
    agent: ureq::Agent,
    download_agent: ureq::Agent,
}

impl VtClient {
    pub(crate) fn new(config: VtConfig) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .build();
        let download_agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(30))
            .timeout_read(Duration::from_secs(DOWNLOAD_HTTP_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .build();
        Self {
            apikey: config.apikey,
            agent,
            download_agent,
        }
    }

    pub(crate) fn search(&self, query: &str, limit: usize) -> Result<SearchResponse, VtError> {
        let url = format!("{BASE_URL}/intelligence/search");
        self.get_json_with_retry(&url, &[("query", query), ("limit", &limit.to_string())])
    }

    pub(crate) fn search_page(
        &self,
        query: &str,
        limit: usize,
        cursor: &str,
    ) -> Result<SearchResponse, VtError> {
        let url = format!("{BASE_URL}/intelligence/search");
        self.get_json_with_retry(
            &url,
            &[
                ("query", query),
                ("limit", &limit.to_string()),
                ("cursor", cursor),
            ],
        )
    }

    pub(crate) fn get_file_report(&self, sha256: &str) -> Result<FileReportEnvelope, VtError> {
        let url = format!("{BASE_URL}/files/{sha256}");
        self.get_json_with_retry(&url, &[])
    }

    /// Lookup-only file report. Returns `Ok(None)` if VT has never seen the
    /// hash (HTTP 404); any other error propagates. Used when enrichment
    /// must never auto-submit unknown files — see `--vt-submit-unknown`.
    pub(crate) fn lookup_file_report(
        &self,
        sha256: &str,
    ) -> Result<Option<FileReportEnvelope>, VtError> {
        match self.get_file_report(sha256) {
            Ok(r) => Ok(Some(r)),
            Err(VtError::HttpStatus { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn get_domain_report(
        &self,
        domain: &str,
    ) -> Result<super::types::FileReportEnvelope, VtError> {
        // Domains share the envelope shape: `data: { attributes: {...} }`.
        // We intentionally reuse `FileReportEnvelope` since we only read the
        // generic `last_analysis_stats`, `reputation`, `categories` fields.
        let url = format!("{BASE_URL}/domains/{domain}");
        self.get_json_with_retry(&url, &[])
    }

    pub(crate) fn lookup_domain_report(
        &self,
        domain: &str,
    ) -> Result<Option<super::types::FileReportEnvelope>, VtError> {
        match self.get_domain_report(domain) {
            Ok(r) => Ok(Some(r)),
            Err(VtError::HttpStatus { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn get_ip_report(
        &self,
        ip: &str,
    ) -> Result<super::types::FileReportEnvelope, VtError> {
        let url = format!("{BASE_URL}/ip_addresses/{ip}");
        self.get_json_with_retry(&url, &[])
    }

    pub(crate) fn lookup_ip_report(
        &self,
        ip: &str,
    ) -> Result<Option<super::types::FileReportEnvelope>, VtError> {
        match self.get_ip_report(ip) {
            Ok(r) => Ok(Some(r)),
            Err(VtError::HttpStatus { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(crate) fn get_url_report(
        &self,
        url: &str,
    ) -> Result<super::types::FileReportEnvelope, VtError> {
        // VT addresses URLs by the base64url(no-pad) of their canonical
        // string. The `/urls/{id}` endpoint accepts either the id or the raw
        // URL (we pass the id for robustness against strange characters).
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let id = URL_SAFE_NO_PAD.encode(url.as_bytes());
        let path = format!("{BASE_URL}/urls/{id}");
        self.get_json_with_retry(&path, &[])
    }

    pub(crate) fn lookup_url_report(
        &self,
        url: &str,
    ) -> Result<Option<super::types::FileReportEnvelope>, VtError> {
        match self.get_url_report(url) {
            Ok(r) => Ok(Some(r)),
            Err(VtError::HttpStatus { status: 404, .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Submit a URL to VT for scanning. Returns the raw JSON response. This
    /// is the *only* method in the client that uploads data to VT and is
    /// gated behind the `--vt-submit-unknown` CLI flag.
    pub(crate) fn submit_url_for_scan(&self, url: &str) -> Result<String, VtError> {
        let encoded: String = url::form_urlencoded::byte_serialize(url.as_bytes()).collect();
        let body = format!("url={encoded}");
        let resp = self
            .agent
            .post(&format!("{BASE_URL}/urls"))
            .set("x-apikey", &self.apikey)
            .set("content-type", "application/x-www-form-urlencoded")
            .send_string(&body);
        match resp {
            Ok(r) => {
                let txt = r
                    .into_string()
                    .map_err(|e| VtError::Decode(e.to_string()))?;
                Ok(txt)
            }
            Err(ureq::Error::Status(s, r)) => {
                let body = r.into_string().unwrap_or_default();
                Err(VtError::HttpStatus { status: s, body })
            }
            Err(ureq::Error::Transport(e)) => Err(VtError::Network(e.to_string())),
        }
    }

    /// Download the raw file bytes to `dest`. `dest`'s parent must already
    /// exist. Writes to a `.tmp` sibling and renames on success to avoid
    /// leaving half-written files when the connection drops.
    pub(crate) fn download_file(&self, sha256: &str, dest: &Path) -> Result<(), VtError> {
        let url = format!("{BASE_URL}/files/{sha256}/download");
        let response = self.request_with_retry(&self.download_agent, &url, &[])?;
        let tmp = dest.with_extension("tmp");
        {
            let mut out = std::fs::File::create(&tmp)?;
            let mut reader = response.into_reader();
            let mut buf = [0u8; 64 * 1024];
            loop {
                let read = reader.read(&mut buf)?;
                if read == 0 {
                    break;
                }
                out.write_all(&buf[..read])?;
            }
            out.flush()?;
        }
        std::fs::rename(&tmp, dest)?;
        Ok(())
    }

    fn get_json_with_retry<T>(&self, url: &str, query: &[(&str, &str)]) -> Result<T, VtError>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self.request_with_retry(&self.agent, url, query)?;
        let text = response
            .into_string()
            .map_err(|err| VtError::Decode(err.to_string()))?;
        serde_json::from_str::<T>(&text).map_err(|err| VtError::Decode(err.to_string()))
    }

    fn request_with_retry(
        &self,
        agent: &ureq::Agent,
        url: &str,
        query: &[(&str, &str)],
    ) -> Result<ureq::Response, VtError> {
        let mut attempt: u32 = 0;
        loop {
            let mut req = agent.get(url).set("x-apikey", &self.apikey);
            for (k, v) in query {
                req = req.query(k, v);
            }
            match req.call() {
                Ok(resp) => return Ok(resp),
                Err(ureq::Error::Status(status, resp)) => {
                    if status == 401 || status == 403 {
                        return Err(VtError::Unauthorized);
                    }
                    // 429 + 5xx are transient — VT's gateway returns 502/503
                    // during regional failovers and overload. 4xx other than
                    // auth indicate a permanent caller error and MUST NOT
                    // retry.
                    let is_retryable = status == 429 || (500..600).contains(&status);
                    if is_retryable {
                        if attempt >= MAX_RETRIES {
                            return if status == 429 {
                                Err(VtError::RateLimited { retries: attempt })
                            } else {
                                let body = resp.into_string().unwrap_or_default();
                                Err(VtError::HttpStatus { status, body })
                            };
                        }
                        let delay = Duration::from_millis(INITIAL_BACKOFF_MS * 2u64.pow(attempt));
                        tracing::warn!(
                            "VT returned status {} (attempt {}/{}), sleeping {:?}",
                            status,
                            attempt + 1,
                            MAX_RETRIES,
                            delay
                        );
                        std::thread::sleep(delay);
                        attempt += 1;
                        continue;
                    }
                    let body = resp.into_string().unwrap_or_default();
                    return Err(VtError::HttpStatus { status, body });
                }
                Err(ureq::Error::Transport(err)) => {
                    if attempt >= MAX_RETRIES {
                        return Err(VtError::Network(err.to_string()));
                    }
                    let delay = Duration::from_millis(INITIAL_BACKOFF_MS * 2u64.pow(attempt));
                    tracing::warn!(
                        "VT transport error {:?} (attempt {}/{}), sleeping {:?}",
                        err,
                        attempt + 1,
                        MAX_RETRIES,
                        delay
                    );
                    std::thread::sleep(delay);
                    attempt += 1;
                }
            }
        }
    }
}
