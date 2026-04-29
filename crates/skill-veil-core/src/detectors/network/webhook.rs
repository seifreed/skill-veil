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
    if lower.contains("skip signature validation")
        || lower.contains("no verification required")
        || lower.contains("accept any payload")
        || lower.contains("unsigned webhook")
        || lower.contains("without auth")
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
            || lower.contains("0.0.0.0")
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
}
