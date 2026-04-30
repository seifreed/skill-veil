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
use crate::util::cache_io::finalize_atomic_write;
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

/// Cap on the bytes from a VT error body that we keep for embedding in
/// `VtError::HttpStatus { body }`. VT gateways return multi-kilobyte HTML
/// pages on 5xx, and a hostile MITM can return arbitrarily large bodies.
/// Anything beyond this point is truncation noise for operator diagnostics,
/// so we drop it before it reaches log aggregators or operator terminals.
const ERROR_BODY_MAX_BYTES: usize = 512;

/// Truncate `body` to at most [`ERROR_BODY_MAX_BYTES`] bytes, ending on a
/// UTF-8 char boundary, appending `"...[truncated]"` when shortened.
fn truncate_error_body(body: String) -> String {
    if body.len() <= ERROR_BODY_MAX_BYTES {
        return body;
    }
    let mut end = ERROR_BODY_MAX_BYTES;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + 14);
    out.push_str(&body[..end]);
    out.push_str("...[truncated]");
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
    match resp.into_string() {
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
    let prefixes = ALLOWED_STORAGE_HOSTS
        .iter()
        .map(|host| format!("https://{host}/"));
    prefixes.into_iter().any(|p| url.starts_with(&p))
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
        resp.into_string()
            .map_err(|e| VtError::Decode(e.to_string()))
    }

    /// Download the raw file bytes to `dest`. `dest`'s parent must already
    /// exist. Writes to a `.tmp` sibling and renames on success to avoid
    /// leaving half-written files when the connection drops. The atomic-
    /// rename helper (`util::cache_io::finalize_atomic_write`) preserves
    /// `tmp` cleanup semantics on rename failure.
    ///
    /// VT's `/files/{sha}/download` endpoint replies with HTTP 302 to a
    /// time-bounded, query-signed Google Storage URL. The storage host
    /// authenticates via the `Signature` query parameter, so the second
    /// hop must NOT carry the `x-apikey` header. We therefore handle the
    /// redirect manually: first request with apikey, then a clean fetch
    /// of the redirect target without apikey, after host-allowlisting.
    pub(crate) fn download_file(&self, sha256: &str, dest: &Path) -> Result<(), VtError> {
        let url = format!("{BASE_URL}/files/{sha256}/download");
        let resp = self.request_download_redirect(&url)?;

        let location = match resp {
            DownloadResponse::Direct(r) => return Self::stream_response_to(dest, *r),
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
        Self::stream_response_to(dest, response)
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

    fn stream_response_to(dest: &Path, response: ureq::Response) -> Result<(), VtError> {
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
        finalize_atomic_write(&tmp, dest)?;
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
                        if attempt >= MAX_RETRIES {
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
                        let delay = Duration::from_millis(INITIAL_BACKOFF_MS * 2u64.pow(attempt));
                        tracing::warn!(
                            "VT POST returned status {} (attempt {}/{}), sleeping {:?}",
                            status,
                            attempt + 1,
                            MAX_RETRIES,
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
                    if attempt >= MAX_RETRIES {
                        return Err(VtError::Network(err.to_string()));
                    }
                    let delay = Duration::from_millis(INITIAL_BACKOFF_MS * 2u64.pow(attempt));
                    tracing::warn!(
                        "VT POST transport error {:?} (attempt {}/{}), sleeping {:?}",
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
                        if attempt >= MAX_RETRIES {
                            return if status == 429 {
                                Err(VtError::RateLimited { retries: attempt })
                            } else {
                                let body = drain_error_body(status, resp);
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
                    let body = drain_error_body(status, resp);
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

#[cfg(test)]
mod redirect_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread;

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

    /// Contract: a body shorter than [`ERROR_BODY_MAX_BYTES`] is preserved
    /// verbatim. Pins the no-truncate branch so the cap doesn't silently
    /// shorten ordinary VT error messages (operator diagnostics need
    /// the gateway's actual hint when it's already small).
    #[test]
    fn truncate_keeps_short_payloads_intact() {
        let body = "VT quota exceeded for this hour".to_string();
        assert_eq!(truncate_error_body(body.clone()), body);
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
}
