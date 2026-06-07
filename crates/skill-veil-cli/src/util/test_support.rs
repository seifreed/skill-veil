//! Test-only helpers shared across CLI subsystem unit tests.

/// Build a minimal well-formed `ureq::Response` carrying `body` as a
/// `200 OK` payload. Shared by the HTTP-client and bounded-reader tests so
/// the synthetic-response construction lives in one place.
pub(crate) fn response_with_body(body: &str) -> ureq::Response {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .parse()
    .expect("synthetic response must parse")
}
