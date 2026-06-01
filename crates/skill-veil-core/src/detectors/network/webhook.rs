use super::patterns::{RE_EXAMPLE_WEBHOOK, RE_OPTIONAL_WEBHOOK_DOCS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WebhookExposure {
    AuthBypass,
    PublicInboundEndpoint,
}

impl WebhookExposure {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::AuthBypass => "webhook_auth_bypass",
            Self::PublicInboundEndpoint => "public_inbound_endpoint",
        }
    }

    pub(crate) fn finding_rule_id(self) -> &'static str {
        match self {
            Self::AuthBypass => "WEBHOOK_AUTH_BYPASS",
            Self::PublicInboundEndpoint => "PUBLIC_INBOUND_ENDPOINT",
        }
    }

    pub(crate) fn finding_reason(self) -> &'static str {
        match self {
            Self::AuthBypass => {
                "Artifact appears to define a webhook or inbound endpoint without verification or signature checks"
            }
            Self::PublicInboundEndpoint => {
                "Artifact appears to expose a public inbound endpoint without visible authentication controls"
            }
        }
    }
}

fn looks_like_optional_webhook_docs(content: &str) -> bool {
    RE_OPTIONAL_WEBHOOK_DOCS.is_match(content)
}

pub(crate) fn classify_webhook_exposure(content: &str) -> Option<WebhookExposure> {
    let lower = content.to_ascii_lowercase();
    // A bypass phrase only signals webhook auth-bypass in a webhook /
    // receiver context. Mirrors the `OFFICIAL_UNSIGNED_WEBHOOK_RECEIVER`
    // YAML rule, which anchors the phrase to a webhook/receiver/listener/
    // callback-endpoint token. Without the anchor (and the example/doc
    // suppression the public-endpoint branch already applies) this fired
    // `Block` on benign prose — `"without auth"` is a substring of "without
    // authentication" and `"accept any payload"` appears in ordinary parser
    // documentation.
    let has_webhook_context = lower.contains("webhook")
        || lower.contains("receiver")
        || lower.contains("listener")
        || lower.contains("callback endpoint");
    let has_auth_bypass_phrase = lower.contains("skip signature validation")
        || lower.contains("no verification required")
        || lower.contains("accept any payload")
        || lower.contains("unsigned webhook")
        || lower.contains("without auth");
    if has_auth_bypass_phrase
        && has_webhook_context
        && !looks_like_optional_webhook_docs(content)
        && !RE_EXAMPLE_WEBHOOK.is_match(content)
    {
        Some(WebhookExposure::AuthBypass)
    } else if lower.contains("webhook")
        && (lower.contains("listener")
            || lower.contains("receiver")
            || lower.contains("inbound")
            || lower.contains("callback endpoint")
            || lower.contains("listen on all interfaces")
            || lower.contains("post /api/webhook"))
        && (lower.contains("public endpoint")
            || lower.contains("publicly reachable")
            || crate::detectors::network::targets::looks_like_bind_all(&lower)
            || lower.contains("accept callbacks")
            || lower.contains("incoming webhooks"))
        && !(lower.contains("verify signature")
            || lower.contains("signature verification")
            || lower.contains("hmac")
            || lower.contains("shared secret")
            || lower.contains("signing secret")
            || lower.contains("webhook secret")
            || lower.contains("validate signature"))
        && !looks_like_optional_webhook_docs(content)
        && !RE_EXAMPLE_WEBHOOK.is_match(content)
    {
        Some(WebhookExposure::PublicInboundEndpoint)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_docs_do_not_trigger_public_exposure() {
        let content =
            "optional webhook: if your agent has a publicly reachable endpoint, see /docs/webhooks";
        assert!(looks_like_optional_webhook_docs(content));
        assert_eq!(classify_webhook_exposure(content), None);
    }

    #[test]
    fn unsigned_public_webhook_is_detected() {
        let content = "webhook listener public endpoint 0.0.0.0 accept callbacks without auth";
        assert_eq!(
            classify_webhook_exposure(content),
            Some(WebhookExposure::AuthBypass)
        );
    }

    /// # Contract
    ///
    /// An auth-bypass phrase outside any webhook/receiver context MUST NOT
    /// classify as webhook auth-bypass. Pre-fix the bare substrings fired a
    /// `Block` finding on benign prose: `"without auth"` is a substring of
    /// "without authentication", and `"accept any payload"` appears in
    /// ordinary parser/API documentation.
    #[test]
    fn auth_bypass_phrase_without_webhook_context_does_not_fire() {
        for content in [
            "The parser will accept any payload format including JSON, XML and CSV.",
            "This local cache utility runs without authentication against ~/.cache.",
            "No verification required to read the bundled sample data.",
        ] {
            assert_eq!(
                classify_webhook_exposure(content),
                None,
                "benign prose must not classify as webhook auth-bypass: {content:?}",
            );
        }
    }

    /// # Contract
    ///
    /// A webhook auth-bypass framed as an explicit example / documentation
    /// snippet is suppressed, matching the public-endpoint branch.
    #[test]
    fn example_webhook_auth_bypass_is_suppressed() {
        let content =
            "Example webhook (for example/testing only): accept any payload, no verification required.";
        assert_eq!(classify_webhook_exposure(content), None);
    }

    /// # Contract
    ///
    /// Generic documentation words do not suppress a public webhook
    /// endpoint. The optional-webhook suppression is only for specific
    /// webhook documentation phrases.
    #[test]
    fn generic_doc_words_do_not_suppress_public_webhook_exposure() {
        for content in [
            "webhook listener public endpoint accept callbacks for details",
            "webhook receiver public endpoint accept callbacks architecture notes",
            "webhook listener public endpoint accept callbacks fallback path",
        ] {
            assert_eq!(
                classify_webhook_exposure(content),
                Some(WebhookExposure::PublicInboundEndpoint),
                "must classify public webhook exposure: {content:?}",
            );
        }
    }
}
