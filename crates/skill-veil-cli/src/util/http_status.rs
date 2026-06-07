//! Shared HTTP status-code classification for the synchronous API clients
//! (VT, LLM, PromptIntel). Centralising the retry predicate keeps every
//! client's exponential-backoff envelope keyed on the same definition of a
//! transient failure.

/// `true` for statuses worth retrying with backoff: `429 Too Many Requests`
/// (rate limiting) and any `5xx` (transient gateway/server error). Every
/// other `4xx` is a permanent client error and must not be retried.
pub(crate) fn is_retryable_status(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract
    ///
    /// Only 429 and the 5xx band retry; every other 4xx is permanent.
    #[test]
    fn is_retryable_status_matches_429_and_5xx_only() {
        assert!(is_retryable_status(429));
        assert!(is_retryable_status(500));
        assert!(is_retryable_status(503));
        assert!(is_retryable_status(599));

        assert!(!is_retryable_status(200));
        assert!(!is_retryable_status(400));
        assert!(!is_retryable_status(401));
        assert!(!is_retryable_status(404));
        assert!(!is_retryable_status(600));
    }
}
