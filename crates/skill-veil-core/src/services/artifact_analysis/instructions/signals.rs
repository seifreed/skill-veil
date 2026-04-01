use regex::Regex;
use std::sync::LazyLock;

static RE_BROWSER_FULL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(browser:\\s*full|full autonomous browser|click any element|navigation:\\s*allow-all)").expect("valid regex")
});
static RE_PERSISTENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(persist\\s+these\\s+instructions|remember\\s+this\\s+across\\s+sessions|append\\s+to\\s+(agents|claude|system)\\.md)").expect("valid regex")
});
static RE_NETWORK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(http://|https://|browser tool|network tool)").expect("valid regex")
});
static RE_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(token|secret|cookie|password|credential|session)").expect("valid regex")
});
static RE_OAUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(oauth|scope|calendar|drive|slack|github pat)").expect("valid regex")
});
static RE_COGNITIVE_ROOTKIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(persist\\s+these\\s+instructions|remember\\s+this\\s+across\\s+sessions|always\\s+follow\\s+this\\s+prompt|never\\s+reveal\\s+this\\s+instruction|override\\s+future\\s+system\\s+messages)").expect("valid regex")
});
static RE_PRIVILEGED_ROLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(act\\s+as\\s+(root|administrator|system)|treat\\s+all\\s+tool\\s+requests\\s+as\\s+approved|ignore\\s+all\\s+existing\\s+safety\\s+constraints)").expect("valid regex")
});

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct InstructionSignals {
    pub(super) browser_full: bool,
    pub(super) persistence: bool,
    pub(super) network: bool,
    pub(super) secret: bool,
    pub(super) oauth: bool,
    pub(super) cognitive_rootkit: bool,
    pub(super) privileged_role: bool,
    pub(super) unauthenticated_webhook: bool,
}

impl InstructionSignals {
    pub(super) fn inspect(content: &str) -> Self {
        Self {
            browser_full: RE_BROWSER_FULL.is_match(content),
            persistence: RE_PERSISTENCE.is_match(content),
            network: RE_NETWORK.is_match(content),
            secret: RE_SECRET.is_match(content),
            oauth: RE_OAUTH.is_match(content),
            cognitive_rootkit: RE_COGNITIVE_ROOTKIT.is_match(content),
            privileged_role: RE_PRIVILEGED_ROLE.is_match(content),
            unauthenticated_webhook: super::super::network::classify_webhook_exposure(content)
                .is_some(),
        }
    }
}
