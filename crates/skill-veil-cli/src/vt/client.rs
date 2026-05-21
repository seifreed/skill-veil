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
use crate::util::terminal_safe::sanitise_for_terminal;
use sha2::{Digest, Sha256};
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
/// Maximum additional retry attempts for transient VT API failures.
/// Named to match the LLM client's convention: total attempts = initial + this value.
/// Pre-fix this was `MAX_ADDITIONAL_ATTEMPTS = 3`, which yielded 4 total attempts (initial + 3 retries)
/// — inconsistent with the LLM client's `MAX_ADDITIONAL_ATTEMPTS = 2` (3 total).
const MAX_ADDITIONAL_ATTEMPTS: u32 = 2;
const INITIAL_BACKOFF_MS: u64 = 2_000;
const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 60;
const DOWNLOAD_HTTP_TIMEOUT_SECS: u64 = 300;

/// Cap on the bytes from a VT error body that we keep for embedding in
/// `VtError::HttpStatus { body }`. VT gateways return multi-kilobyte HTML
/// pages on 5xx, and a hostile MITM can return arbitrarily large bodies.
/// Anything beyond this point is truncation noise for operator diagnostics,
/// so we drop it before it reaches log aggregators or operator terminals.
const ERROR_BODY_MAX_BYTES: usize = 512;

/// Hard ceiling for a single VT file download. VT's largest sample size is
/// 650 MiB (per the public quota table); 768 MiB leaves headroom for that
/// edge while preventing a hostile/misconfigured CDN or MITM from streaming
/// an unbounded body into the operator's disk. The cap is enforced during
/// streaming (`stream_response_to`) so the temporary file never exceeds
/// the limit and an attacker cannot fill the disk before the producer
/// notices.
const MAX_DOWNLOAD_BYTES: u64 = 768 * 1024 * 1024;

/// Cap on VT JSON API response bodies to prevent unbounded memory allocation
/// from a compromised or misconfigured endpoint. Mirrors the LLM client's
/// `MAX_RESPONSE_BODY_BYTES` (10 MiB). VT JSON responses are typically under
/// 100 KiB; 10 MiB is a generous ceiling that covers large report objects.
const MAX_JSON_RESPONSE_BYTES: u64 = 10 * 1024 * 1024;

/// Truncate `body` to at most [`ERROR_BODY_MAX_BYTES`] bytes, ending on a
/// UTF-8 char boundary, appending `"...[truncated]"` when shortened.
fn truncate_error_body(body: String) -> String {
    let body = sanitise_for_terminal(&body);
    if body.len() <= ERROR_BODY_MAX_BYTES {
        debug_assert!(
            !body.chars().any(|c| c.is_control()),
            "VT error bodies must be terminal-safe"
        );
        return body;
    }
    let mut end = ERROR_BODY_MAX_BYTES;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + 14);
    out.push_str(&body[..end]);
    out.push_str("...[truncated]");
    debug_assert!(
        !out.chars().any(|c| c.is_control()),
        "VT error bodies must be terminal-safe"
    );
    out
}

/// Drain `resp` into a string for embedding in an error.
///
/// Mirrors `crate::llm::client::drain_error_body`: pre-fix the call sites
/// used `unwrap_or_default()`, which silently erased decode/transport
/// errors and operators saw `VtError::HttpStatus { status, body: "" }`
/// with no clue why the body was missing (gateway 502s, mid-stream
/// disconnects). The warning preserves that diagnostic context while
/// keeping the public error shape unchanged. Bodies are truncated to
/// [`ERROR_BODY_MAX_BYTES`] so a hostile gateway cannot push large blobs
/// into operator logs.
fn drain_error_body(status: u16, resp: ureq::Response) -> String {
    match bounded_read_response(resp) {
        Ok(body) => truncate_error_body(body),
        Err(err) => {
            tracing::warn!(
                "VT returned HTTP {} but the response body could not be read: {}",
                status,
                err
            );
            String::new()
        }
    }
}

/// Read an HTTP response body with a size cap to prevent unbounded memory
/// allocation from a compromised or misconfigured endpoint. Mirrors the
/// LLM client's `bounded_read_response` — pre-fix `drain_error_body` used
/// `resp.into_string()` which allocates the entire body before truncation,
/// allowing a hostile endpoint to cause OOM.
fn bounded_read_response(resp: ureq::Response) -> Result<String, io::Error> {
    read_response_with_cap(resp, MAX_JSON_RESPONSE_BYTES)
}

fn read_response_with_cap(resp: ureq::Response, cap: u64) -> Result<String, io::Error> {
    let mut buf = String::new();
    resp.into_reader()
        .take(cap.saturating_add(1))
        .read_to_string(&mut buf)?;
    if buf.len() as u64 > cap {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("response body exceeds {cap} byte limit"),
        ));
    }
    debug_assert!(
        buf.len() as u64 <= cap,
        "bounded response reader must reject bodies over the cap"
    );
    Ok(buf)
}

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
    #[error(
        "VirusTotal download integrity mismatch: requested SHA-256 {expected} but received {actual}"
    )]
    IntegrityMismatch { expected: String, actual: String },
    #[error(
        "VirusTotal download exceeded the {limit_bytes}-byte cap before reaching end of stream"
    )]
    DownloadTooLarge { limit_bytes: u64 },
    #[error("invalid VirusTotal SHA-256 identifier")]
    InvalidSha256,
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub(crate) struct VtClient {
    apikey: String,
    agent: ureq::Agent,
    download_agent: ureq::Agent,
}

/// Outcome of the first hop in `/files/{sha}/download`. VT either sends the
/// payload back directly (rare) or, more typically, replies with HTTP 302
/// pointing at a signed Google Storage URL the caller must follow without
/// the `x-apikey` header. `Direct` is boxed because `ureq::Response` is
/// ~264 bytes whereas `Redirect(String)` is ~24 — boxing equalises the
/// enum variant footprint and silences `clippy::large_enum_variant`.
enum DownloadResponse {
    Direct(Box<ureq::Response>),
    Redirect(String),
}

/// Allow-list for the second hop of `download_file`. VT's signed storage
/// targets resolve to one of these hosts; anything else means the redirect
/// was tampered with (DNS hijack, transparent proxy) and we refuse to
/// follow it. Update this list if VT introduces a new storage backend.
const ALLOWED_STORAGE_HOSTS: &[&str] = &[
    "vtsamples.commondatastorage.googleapis.com",
    "www.virustotal.com",
];

fn is_allowed_storage_target(url: &str) -> bool {
    let parsed = match url::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return false,
    };
    // Only allow HTTPS redirects.
    if parsed.scheme() != "https" {
        return false;
    }
    let host = match parsed.host_str() {
        Some(h) => h,
        None => return false,
    };
    // Exact host match — prevents prefix attacks like
    // `vtsamples.commondatastorage.googleapis.com.evil.com`.
    ALLOWED_STORAGE_HOSTS.contains(&host)
}

impl VtClient {
    pub(crate) fn new(config: VtConfig) -> Self {
        // `redirects(0)` is critical: every request sets the `x-apikey`
        // header (see `request_with_retry`), and ureq 2.10's default of
        // five redirects forwards custom headers verbatim to the
        // redirect target. VT's API never returns 3xx in normal use, so
        // any redirect in production is a sign of DNS hijack, transparent
        // proxy interception, or a misrouted CI gateway — silently
        // following it would exfiltrate the API key to that destination.
        // Failing fast surfaces the misroute instead of leaking the key.
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .redirects(0)
            .build();
        let download_agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(30))
            .timeout_read(Duration::from_secs(DOWNLOAD_HTTP_TIMEOUT_SECS))
            .user_agent(USER_AGENT)
            .redirects(0)
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
        let sha256 = super::normalize_sha256_hex(sha256).ok_or(VtError::InvalidSha256)?;
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
        let encoded = urlencoding::encode(domain);
        let url = format!("{BASE_URL}/domains/{encoded}");
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
        let encoded = urlencoding::encode(ip);
        let url = format!("{BASE_URL}/ip_addresses/{encoded}");
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
        // string. The `/urls/{id}` endpoint accepts either the id or the
        // raw URL; the id avoids URL-encoding ambiguity for arbitrary
        // input characters.
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
    ///
    /// Goes through [`Self::post_form_with_retry`] so transient 429/5xx
    /// responses get the same exponential-backoff treatment as the read
    /// path (`request_with_retry`). Pre-fix this method issued a single
    /// `send_string` and a 429 from VT's submission endpoint silently
    /// failed, then got cached as `EnrichmentStatus::Error` for 5 minutes —
    /// exactly the window when `--vt-submit-unknown` is most useful.
    pub(crate) fn submit_url_for_scan(&self, url: &str) -> Result<String, VtError> {
        let encoded: String = url::form_urlencoded::byte_serialize(url.as_bytes()).collect();
        let body = format!("url={encoded}");
        let endpoint = format!("{BASE_URL}/urls");
        let resp = self.post_form_with_retry(&endpoint, &body)?;
        let buf = bounded_read_response(resp).map_err(|e| VtError::Decode(e.to_string()))?;
        Ok(buf)
    }

    /// Download the raw file bytes to `dest`. `dest`'s parent must already
    /// exist as a real directory. Writes through a same-directory tempfile
    /// and renames on success to avoid leaving half-written files when the
    /// connection drops.
    ///
    /// VT's `/files/{sha}/download` endpoint replies with HTTP 302 to a
    /// time-bounded, query-signed Google Storage URL. The storage host
    /// authenticates via the `Signature` query parameter, so the second
    /// hop must NOT carry the `x-apikey` header. We therefore handle the
    /// redirect manually: first request with apikey, then a clean fetch
    /// of the redirect target without apikey, after host-allowlisting.
    pub(crate) fn download_file(&self, sha256: &str, dest: &Path) -> Result<(), VtError> {
        let sha256 = super::normalize_sha256_hex(sha256).ok_or(VtError::InvalidSha256)?;
        let url = format!("{BASE_URL}/files/{sha256}/download");
        let resp = self.request_download_redirect(&url)?;

        let location = match resp {
            DownloadResponse::Direct(r) => {
                return Self::stream_response_to(dest, *r, &sha256, MAX_DOWNLOAD_BYTES);
            }
            DownloadResponse::Redirect(loc) => loc,
        };

        if !is_allowed_storage_target(&location) {
            return Err(VtError::Decode(format!(
                "VT download redirect target is not allow-listed: {location}"
            )));
        }

        // Second hop: fetch the signed storage URL with the same agent
        // (timeouts/UA preserved) but no apikey header. ureq's `redirects(0)`
        // is fine here — the storage URL goes straight to bytes.
        let response = self
            .download_agent
            .get(&location)
            .call()
            .map_err(|err| match err {
                ureq::Error::Status(status, r) => {
                    let body = drain_error_body(status, r);
                    VtError::HttpStatus { status, body }
                }
                ureq::Error::Transport(e) => VtError::Network(e.to_string()),
            })?;
        Self::stream_response_to(dest, response, &sha256, MAX_DOWNLOAD_BYTES)
    }

    fn request_download_redirect(&self, url: &str) -> Result<DownloadResponse, VtError> {
        let resp = self
            .download_agent
            .get(url)
            .set("x-apikey", &self.apikey)
            .call()
            .map_err(|err| match err {
                ureq::Error::Status(401 | 403, _) => VtError::Unauthorized,
                ureq::Error::Status(status, r) => {
                    let body = drain_error_body(status, r);
                    VtError::HttpStatus { status, body }
                }
                ureq::Error::Transport(e) => VtError::Network(e.to_string()),
            })?;
        let status = resp.status();
        if (200..300).contains(&status) {
            return Ok(DownloadResponse::Direct(Box::new(resp)));
        }
        if (300..400).contains(&status) {
            let location = resp
                .header("Location")
                .ok_or_else(|| {
                    VtError::Decode(format!(
                        "VT returned HTTP {status} without `Location` header"
                    ))
                })?
                .to_string();
            return Ok(DownloadResponse::Redirect(location));
        }
        let body = drain_error_body(status, resp);
        Err(VtError::HttpStatus { status, body })
    }

    /// Stream `response` body to `dest` while enforcing two contracts:
    ///
    /// 1. **Integrity**: bytes are SHA-256 hashed in-flight and the digest is
    ///    compared against `expected_sha256` (case-insensitive hex). VT's
    ///    download endpoint is keyed by SHA-256, so a mismatch means the
    ///    storage layer, the redirect target, or the network path delivered
    ///    a different sample than the one requested. For a malware analysis
    ///    pipeline this is an unrecoverable trust violation: the tempfile is
    ///    removed and `VtError::IntegrityMismatch` propagates so the caller
    ///    never observes a `dest` whose contents disagree with the name that
    ///    indexed it.
    ///
    /// 2. **Size cap**: writes abort once the cumulative body exceeds
    ///    `max_bytes`. VT's allowlisted storage hosts are trusted, but a
    ///    misconfigured CDN or a MITM with a valid cert could otherwise
    ///    stream an unbounded body and fill the operator's disk before
    ///    `timeout_read` fires (the timer measures inactivity per read,
    ///    not total transfer). The check is on bytes already written, not
    ///    on `Content-Length`, because chunked-transfer responses can lie.
    fn stream_response_to(
        dest: &Path,
        response: ureq::Response,
        expected_sha256: &str,
        max_bytes: u64,
    ) -> Result<(), VtError> {
        let parent = dest.parent().ok_or_else(|| {
            VtError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} has no parent directory", dest.display()),
            ))
        })?;
        Self::ensure_real_download_parent(parent)?;
        let result = (|| -> Result<(String, tempfile::NamedTempFile), VtError> {
            let mut out = tempfile::NamedTempFile::new_in(parent)?;
            let mut reader = response.into_reader();
            let mut hasher = Sha256::new();
            let mut buf = [0u8; 64 * 1024];
            let mut total: u64 = 0;
            loop {
                let read = reader.read(&mut buf)?;
                if read == 0 {
                    break;
                }
                total = total.saturating_add(read as u64);
                if total > max_bytes {
                    return Err(VtError::DownloadTooLarge {
                        limit_bytes: max_bytes,
                    });
                }
                hasher.update(&buf[..read]);
                out.write_all(&buf[..read])?;
            }
            out.flush()?;
            out.as_file_mut().sync_all()?;
            Ok((format!("{:x}", hasher.finalize()), out))
        })();

        match result {
            Ok((actual, tmp)) if actual.eq_ignore_ascii_case(expected_sha256) => {
                tmp.persist(dest).map_err(|err| VtError::Io(err.error))?;
                Ok(())
            }
            Ok((actual, _tmp)) => Err(VtError::IntegrityMismatch {
                expected: expected_sha256.to_string(),
                actual,
            }),
            Err(err) => Err(err),
        }
    }

    fn ensure_real_download_parent(parent: &Path) -> Result<(), VtError> {
        let meta = std::fs::symlink_metadata(parent)?;
        if meta.is_dir() && !meta.file_type().is_symlink() {
            Ok(())
        } else {
            Err(VtError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} is not a real download directory", parent.display()),
            )))
        }
    }

    fn get_json_with_retry<T>(&self, url: &str, query: &[(&str, &str)]) -> Result<T, VtError>
    where
        T: serde::de::DeserializeOwned,
    {
        let response = self.request_with_retry(&self.agent, url, query)?;
        let buf =
            bounded_read_response(response).map_err(|err| VtError::Decode(err.to_string()))?;
        serde_json::from_str::<T>(&buf).map_err(|err| VtError::Decode(err.to_string()))
    }

    /// POST a form-encoded body with retry semantics matching
    /// [`Self::request_with_retry`]. Used by `submit_url_for_scan` so write
    /// paths share the same 429/5xx exponential-backoff envelope as the
    /// read paths instead of failing on the first transient error.
    fn post_form_with_retry(&self, url: &str, body: &str) -> Result<ureq::Response, VtError> {
        let mut attempt: u32 = 0;
        loop {
            let resp = self
                .agent
                .post(url)
                .set("x-apikey", &self.apikey)
                .set("content-type", "application/x-www-form-urlencoded")
                .send_string(body);
            match resp {
                Ok(resp) => {
                    let status = resp.status();
                    if !(200..300).contains(&status) {
                        let drained = drain_error_body(status, resp);
                        return Err(VtError::HttpStatus {
                            status,
                            body: drained,
                        });
                    }
                    return Ok(resp);
                }
                Err(ureq::Error::Status(status, resp)) => {
                    if status == 401 || status == 403 {
                        return Err(VtError::Unauthorized);
                    }
                    let is_retryable = status == 429 || (500..600).contains(&status);
                    if is_retryable {
                        if attempt >= MAX_ADDITIONAL_ATTEMPTS {
                            return if status == 429 {
                                Err(VtError::RateLimited { retries: attempt })
                            } else {
                                let drained = drain_error_body(status, resp);
                                Err(VtError::HttpStatus {
                                    status,
                                    body: drained,
                                })
                            };
                        }
                        let delay = Duration::from_millis(
                            INITIAL_BACKOFF_MS.saturating_mul(2u64.saturating_pow(attempt)),
                        );
                        tracing::warn!(
                            "VT POST returned status {} (attempt {}/{}), sleeping {:?}",
                            status,
                            attempt + 1,
                            MAX_ADDITIONAL_ATTEMPTS,
                            delay
                        );
                        std::thread::sleep(delay);
                        attempt += 1;
                        continue;
                    }
                    let drained = drain_error_body(status, resp);
                    return Err(VtError::HttpStatus {
                        status,
                        body: drained,
                    });
                }
                Err(ureq::Error::Transport(err)) => {
                    if attempt >= MAX_ADDITIONAL_ATTEMPTS {
                        return Err(VtError::Network(err.to_string()));
                    }
                    let delay = Duration::from_millis(
                        INITIAL_BACKOFF_MS.saturating_mul(2u64.saturating_pow(attempt)),
                    );
                    tracing::warn!(
                        "VT POST transport error {:?} (attempt {}/{}), sleeping {:?}",
                        err,
                        attempt + 1,
                        MAX_ADDITIONAL_ATTEMPTS,
                        delay
                    );
                    std::thread::sleep(delay);
                    attempt += 1;
                }
            }
        }
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
                Ok(resp) => {
                    // With `redirects(0)` set on the agent (see
                    // `VtClient::new`), ureq returns 3xx responses as
                    // `Ok(resp)` rather than `Err::Status`. We must
                    // surface these as errors so the caller never tries
                    // to JSON-decode the redirect body, and — more
                    // critically — never re-issues the request to the
                    // `Location` target with the `x-apikey` header
                    // attached. VT API never legitimately returns 3xx,
                    // so any such response signals DNS hijack, MITM, or
                    // a misrouted gateway.
                    let status = resp.status();
                    if !(200..300).contains(&status) {
                        let body = drain_error_body(status, resp);
                        return Err(VtError::HttpStatus { status, body });
                    }
                    return Ok(resp);
                }
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
                        if attempt >= MAX_ADDITIONAL_ATTEMPTS {
                            return if status == 429 {
                                Err(VtError::RateLimited { retries: attempt })
                            } else {
                                let body = drain_error_body(status, resp);
                                Err(VtError::HttpStatus { status, body })
                            };
                        }
                        let delay = Duration::from_millis(
                            INITIAL_BACKOFF_MS.saturating_mul(2u64.saturating_pow(attempt)),
                        );
                        tracing::warn!(
                            "VT returned status {} (attempt {}/{}), sleeping {:?}",
                            status,
                            attempt + 1,
                            MAX_ADDITIONAL_ATTEMPTS,
                            delay
                        );
                        std::thread::sleep(delay);
                        attempt += 1;
                        continue;
                    }
                    let body = drain_error_body(status, resp);
                    return Err(VtError::HttpStatus { status, body });
                }
                Err(ureq::Error::Transport(err)) => {
                    if attempt >= MAX_ADDITIONAL_ATTEMPTS {
                        return Err(VtError::Network(err.to_string()));
                    }
                    let delay = Duration::from_millis(
                        INITIAL_BACKOFF_MS.saturating_mul(2u64.saturating_pow(attempt)),
                    );
                    tracing::warn!(
                        "VT transport error {:?} (attempt {}/{}), sleeping {:?}",
                        err,
                        attempt + 1,
                        MAX_ADDITIONAL_ATTEMPTS,
                        delay
                    );
                    std::thread::sleep(delay);
                    attempt += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod redirect_tests {
    use super::*;
    use crate::vt::config::VtConfig;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn file_report_rejects_invalid_sha_before_request() {
        let client = VtClient::new(VtConfig {
            apikey: "test-key".to_string(),
        });

        let result = client.get_file_report("../escape");

        assert!(matches!(result, Err(VtError::InvalidSha256)));
    }

    #[test]
    fn file_download_rejects_invalid_sha_before_path_or_request() {
        let client = VtClient::new(VtConfig {
            apikey: "test-key".to_string(),
        });
        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("sample");

        let result = client.download_file("../escape", &dest);

        assert!(matches!(result, Err(VtError::InvalidSha256)));
        assert!(!dest.exists());
    }

    /// # Contract
    ///
    /// The VT agent MUST NOT follow HTTP redirects. Every request sets
    /// the `x-apikey` header (`request_with_retry`), and ureq 2.10's
    /// default of five redirects forwards custom headers verbatim to the
    /// redirect target. VT never returns 3xx in normal use, so any
    /// redirect signals DNS hijack, transparent proxy interception, or a
    /// misrouted CI gateway — silently following it would exfiltrate the
    /// API key. This test pins the post-fix behaviour by serving a 302
    /// from a localhost listener and asserting the call surfaces as
    /// `VtError::HttpStatus { status: 302, .. }` rather than chasing the
    /// `Location` header.
    #[test]
    fn agent_surfaces_302_as_error_instead_of_following_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
        let port = listener.local_addr().unwrap().port();

        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let cloned = stream.try_clone().expect("clone");
            let mut reader = BufReader::new(cloned);
            // Drain the request headers (read until empty line) so we
            // don't write back before the client finishes sending.
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if line == "\r\n" {
                    break;
                }
            }
            let body = "should not be observed";
            let resp = format!(
                "HTTP/1.1 302 Found\r\n\
                 Location: http://attacker.example/leak\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        });

        let client = VtClient::new(VtConfig {
            apikey: "test-key-MUST-NOT-LEAK".into(),
        });
        let url = format!("http://127.0.0.1:{port}/v3/files/abc");
        let result: Result<serde_json::Value, _> = client.get_json_with_retry(&url, &[]);

        // Accept either the typed `HttpStatus { 302 }` (preferred) or any
        // non-Ok outcome that did NOT successfully decode a JSON body —
        // the contract is "do not follow", not a specific error shape.
        assert!(
            matches!(&result, Err(VtError::HttpStatus { status: 302, .. })),
            "agent must surface 302 instead of following the redirect; got {result:?}"
        );

        let _ = server.join();
    }
}

#[cfg(test)]
mod truncate_error_body_tests {
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

    /// Contract: a body shorter than [`ERROR_BODY_MAX_BYTES`] is preserved
    /// verbatim. Pins the no-truncate branch so the cap doesn't silently
    /// shorten ordinary VT error messages (operator diagnostics need
    /// the gateway's actual hint when it's already small).
    #[test]
    fn truncate_keeps_short_payloads_intact() {
        let body = "VT quota exceeded for this hour".to_string();
        assert_eq!(truncate_error_body(body.clone()), body);
    }

    /// Contract: VT error bodies are terminal-safe before they become
    /// `VtError::HttpStatus`; scan enrichment prints those errors to
    /// stderr when VT is configured but the remote side fails.
    #[test]
    fn truncate_sanitises_control_bytes() {
        let body = "VT gateway \x1b[2J\x1b[Hfake ok".to_string();

        let cleaned = truncate_error_body(body);

        assert!(!cleaned.contains('\x1b'));
        assert!(cleaned.contains("VT gateway "));
    }

    /// Contract: a body longer than [`ERROR_BODY_MAX_BYTES`] is truncated
    /// with a visible suffix. Pre-fix `VtError::HttpStatus` embedded the
    /// full body uncapped, so an attacker-controlled MITM (or a VT gateway
    /// outage page) could push multi-KB HTML into operator logs and
    /// terminals. The cap is enforced at the producer (`drain_error_body`)
    /// so every downstream consumer (`tracing::warn`, `eprintln!`,
    /// structured-output formatters) inherits the bound.
    #[test]
    fn truncate_caps_long_payloads_with_suffix() {
        let huge = "Y".repeat(ERROR_BODY_MAX_BYTES * 4);
        let truncated = truncate_error_body(huge);
        assert!(
            truncated.len() <= ERROR_BODY_MAX_BYTES + "...[truncated]".len(),
            "truncated body must be capped, got len={}",
            truncated.len()
        );
        assert!(
            truncated.ends_with("...[truncated]"),
            "truncated body must carry the suffix; got tail: {:?}",
            &truncated[truncated.len().saturating_sub(20)..]
        );
    }

    /// Contract: a VT JSON response exactly at the byte cap is accepted.
    #[test]
    fn bounded_read_response_accepts_body_at_cap() {
        let body = read_response_with_cap(response_with_body("abcd"), 4).unwrap();

        assert_eq!(body, "abcd");
    }

    /// Contract: a VT JSON response beyond the cap fails instead of
    /// returning a truncated prefix that could be parsed as complete
    /// JSON by a downstream caller.
    #[test]
    fn bounded_read_response_rejects_body_over_cap() {
        let err = read_response_with_cap(response_with_body("abcde"), 4)
            .expect_err("oversized response must fail");

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}

#[cfg(test)]
mod download_integrity_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        format!("{:x}", h.finalize())
    }

    fn serve_once(port_tx: std::sync::mpsc::Sender<u16>, body: Vec<u8>) -> thread::JoinHandle<()> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind localhost");
        let port = listener.local_addr().unwrap().port();
        port_tx.send(port).unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let cloned = stream.try_clone().expect("clone");
            let mut reader = BufReader::new(cloned);
            let mut line = String::new();
            loop {
                line.clear();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if line == "\r\n" {
                    break;
                }
            }
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
        })
    }

    fn fetch_response(port: u16) -> ureq::Response {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(5))
            .build();
        agent
            .get(&format!("http://127.0.0.1:{port}/"))
            .call()
            .expect("connect")
    }

    /// # Contract
    ///
    /// `stream_response_to` MUST hash bytes as they stream to disk and
    /// reject the download when the resulting digest differs from the
    /// caller-supplied `expected_sha256`. Pre-fix the function trusted
    /// VT/Google Storage to deliver the requested sample, so a corrupt
    /// CDN response or a MITM with a valid cert could substitute a
    /// different file under the same SHA-controlled filename. For a
    /// malware analysis pipeline the SHA-256 is the trust anchor — accepting
    /// mismatched bytes silently poisons every downstream consumer
    /// (taint analysis, manual review, dataset corpora). On rejection,
    /// the temporary file must be removed so the operator's disk never
    /// holds a partial, unverified blob.
    #[test]
    fn stream_response_to_rejects_sha_mismatch() {
        let body = b"actual file bytes that hash differently".to_vec();
        let bogus_sha = "0".repeat(64);
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let dest = tmpdir.path().join("sample");

        let (port_tx, port_rx) = std::sync::mpsc::channel();
        let server = serve_once(port_tx, body);
        let port = port_rx.recv().unwrap();
        let response = fetch_response(port);

        let result = VtClient::stream_response_to(&dest, response, &bogus_sha, MAX_DOWNLOAD_BYTES);

        assert!(
            matches!(&result, Err(VtError::IntegrityMismatch { expected, actual })
                if expected == &bogus_sha && actual.len() == 64),
            "expected IntegrityMismatch for diverging SHA; got {result:?}"
        );
        assert!(
            !dest.exists(),
            "dest must not be created when the digest mismatches"
        );
        assert!(
            !dest.with_extension("tmp").exists(),
            "tmp sibling must be removed on integrity failure to avoid leaking unverified bytes"
        );
        let _ = server.join();
    }

    /// # Contract
    ///
    /// `stream_response_to` MUST commit `dest` only when the streamed body's
    /// SHA-256 matches the caller's `expected_sha256` (case-insensitive).
    /// Pins the happy path so a future refactor cannot silently disable
    /// verification by short-circuiting the comparison.
    #[test]
    fn stream_response_to_accepts_matching_sha() {
        let body = b"contents whose digest is computed and matched".to_vec();
        let expected = sha256_hex(&body);
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let dest = tmpdir.path().join("sample");

        let (port_tx, port_rx) = std::sync::mpsc::channel();
        let server = serve_once(port_tx, body.clone());
        let port = port_rx.recv().unwrap();
        let response = fetch_response(port);

        VtClient::stream_response_to(&dest, response, &expected, MAX_DOWNLOAD_BYTES)
            .expect("matching SHA must succeed");

        assert!(dest.exists(), "dest must be present after atomic finalize");
        let written = std::fs::read(&dest).expect("read dest");
        assert_eq!(written, body, "dest contents must match streamed body");
        let _ = server.join();
    }

    /// # Contract
    ///
    /// A pre-existing symlink at `dest` must be replaced as a directory
    /// entry after integrity verification, not followed and overwritten.
    #[cfg(unix)]
    #[test]
    fn stream_response_to_replaces_symlink_without_touching_target() {
        let body = b"verified bytes".to_vec();
        let expected = sha256_hex(&body);
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let outside = tmpdir.path().join("outside.bin");
        let dest = tmpdir.path().join("sample");
        std::fs::write(&outside, b"keep").unwrap();
        std::os::unix::fs::symlink(&outside, &dest).unwrap();

        let (port_tx, port_rx) = std::sync::mpsc::channel();
        let server = serve_once(port_tx, body.clone());
        let port = port_rx.recv().unwrap();
        let response = fetch_response(port);

        VtClient::stream_response_to(&dest, response, &expected, MAX_DOWNLOAD_BYTES)
            .expect("matching SHA must succeed");

        assert_eq!(std::fs::read(&outside).unwrap(), b"keep");
        assert!(!std::fs::symlink_metadata(&dest)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&dest).unwrap(), body);
        let _ = server.join();
    }

    /// # Contract
    ///
    /// `stream_response_to` must reject a symlinked parent directory before
    /// creating its temporary file. Otherwise a reused caller could redirect
    /// verified malware samples outside the intended download root.
    #[cfg(unix)]
    #[test]
    fn stream_response_to_rejects_symlinked_parent_dir() {
        let body = b"verified bytes".to_vec();
        let expected = sha256_hex(&body);
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let outside = tmpdir.path().join("outside");
        let parent = tmpdir.path().join("downloads");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, &parent).unwrap();
        let dest = parent.join("sample");

        let (port_tx, port_rx) = std::sync::mpsc::channel();
        let server = serve_once(port_tx, body);
        let port = port_rx.recv().unwrap();
        let response = fetch_response(port);

        let err = VtClient::stream_response_to(&dest, response, &expected, MAX_DOWNLOAD_BYTES)
            .expect_err("symlinked parent must be rejected");

        assert!(format!("{err:#}").contains("not a real download directory"));
        assert!(!outside.join("sample").exists());
        let _ = server.join();
    }

    /// # Contract
    ///
    /// `stream_response_to` MUST stop writing once the cumulative body
    /// exceeds `max_bytes`, returning `VtError::DownloadTooLarge`. Pre-fix
    /// the loop read until EOF unbounded; a chunked-transfer response
    /// (where `Content-Length` is absent) could fill the operator's disk
    /// before `timeout_read` ever fired, since that timer measures
    /// inactivity per read, not total transfer. The cap also defends
    /// against MITM attempts that ignore the requested SHA's known size.
    #[test]
    fn stream_response_to_aborts_when_body_exceeds_cap() {
        let body = vec![0xABu8; 4096];
        let expected = sha256_hex(&body);
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let dest = tmpdir.path().join("sample");

        let (port_tx, port_rx) = std::sync::mpsc::channel();
        let server = serve_once(port_tx, body);
        let port = port_rx.recv().unwrap();
        let response = fetch_response(port);

        let cap: u64 = 1024;
        let result = VtClient::stream_response_to(&dest, response, &expected, cap);

        assert!(
            matches!(&result, Err(VtError::DownloadTooLarge { limit_bytes }) if *limit_bytes == cap),
            "expected DownloadTooLarge at cap {cap}; got {result:?}"
        );
        assert!(
            !dest.exists(),
            "dest must not be finalized when the cap aborts the stream"
        );
        assert!(
            !dest.with_extension("tmp").exists(),
            "tmp sibling must be removed on cap-abort to bound disk use"
        );
        let _ = server.join();
    }
}

#[cfg(test)]
mod allowlist_tests {
    use super::*;

    /// # Contract
    ///
    /// `is_allowed_storage_target` MUST accept legitimate VT storage URLs
    /// with exact host matching.
    #[test]
    fn allows_legitimate_vt_storage_hosts() {
        assert!(is_allowed_storage_target(
            "https://vtsamples.commondatastorage.googleapis.com/some/path?hash=abc"
        ));
        assert!(is_allowed_storage_target(
            "https://www.virustotal.com/some/path"
        ));
    }

    /// # Contract
    ///
    /// `is_allowed_storage_target` MUST reject URLs whose host is a
    /// subdomain of an allowed host (e.g. `evil.vtsamples.commondatastorage.googleapis.com`)
    /// or that append a dot and attacker domain
    /// (e.g. `vtsamples.commondatastorage.googleapis.com.evil.com`).
    #[test]
    fn rejects_subdomain_prefix_attack() {
        assert!(!is_allowed_storage_target(
            "https://vtsamples.commondatastorage.googleapis.com.evil.com/path"
        ));
        assert!(!is_allowed_storage_target(
            "https://evil.vtsamples.commondatastorage.googleapis.com/path"
        ));
    }

    /// # Contract
    ///
    /// `is_allowed_storage_target` MUST reject non-HTTPS schemes (HTTP,
    /// no scheme).
    #[test]
    fn rejects_non_https_schemes() {
        assert!(!is_allowed_storage_target(
            "http://vtsamples.commondatastorage.googleapis.com/path"
        ));
        assert!(!is_allowed_storage_target(
            "ftp://vtsamples.commondatastorage.googleapis.com/path"
        ));
    }

    /// # Contract
    ///
    /// `is_allowed_storage_target` MUST reject completely unrelated hosts.
    #[test]
    fn rejects_unrelated_hosts() {
        assert!(!is_allowed_storage_target("https://evil.com/path"));
        assert!(!is_allowed_storage_target("https://example.com/"));
    }

    /// # Contract
    ///
    /// `is_allowed_storage_target` MUST reject malformed URLs.
    #[test]
    fn rejects_malformed_urls() {
        assert!(!is_allowed_storage_target("not-a-url"));
        assert!(!is_allowed_storage_target(""));
    }
}
