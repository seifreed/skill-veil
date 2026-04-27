use regex::Regex;
use std::sync::LazyLock;

pub(super) static RE_BROWSER_FULL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        "(?i)(browser:\\s*full|full autonomous browser|click any element|navigation:\\s*allow-all)",
    )
    .expect("valid regex")
});
pub(super) static RE_PERSISTENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(persist\\s+these\\s+instructions|remember\\s+this\\s+across\\s+sessions|append\\s+to\\s+(agents|claude|system)\\.md)").expect("valid regex")
});
pub(super) static RE_NETWORK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(http://|https://|browser tool|network tool)").expect("valid regex")
});
pub(super) static RE_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(token|secret|cookie|password|credential|session)").expect("valid regex")
});
pub(super) static RE_OAUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(oauth|scope|calendar|drive|slack|github pat)").expect("valid regex")
});
pub(super) static RE_COGNITIVE_ROOTKIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(persist\\s+these\\s+instructions|remember\\s+this\\s+across\\s+sessions|always\\s+follow\\s+this\\s+prompt|never\\s+reveal\\s+this\\s+instruction|override\\s+future\\s+system\\s+messages)").expect("valid regex")
});
pub(super) static RE_PRIVILEGED_ROLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?i)(act\\s+as\\s+(root|administrator|system)|treat\\s+all\\s+tool\\s+requests\\s+as\\s+approved|ignore\\s+all\\s+existing\\s+safety\\s+constraints)").expect("valid regex")
});

// `InstructionSignals` and its `inspect()` constructor power an alternate
// permission/persistence policy chain in `policies/permission_policy/`
// that is not wired into the production `analyze_with_kind` pipeline
// (which uses the inlined `semantic_persistence_findings` in this file's
// parent `instructions.rs:138`). The allows below acknowledge the
// unfinished refactor: the chain is kept compiling and tested so it can
// be wired up in a future change without re-introducing the code from
// scratch. Do NOT remove these allows without first deleting the
// `policies/permission_policy/persistence_policy.rs` chain or
// connecting it to `analyze_with_kind`.
#[allow(dead_code)]
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
    #[allow(dead_code)]
    pub(super) fn inspect(content: &str) -> Self {
        Self {
            browser_full: RE_BROWSER_FULL.is_match(content),
            persistence: RE_PERSISTENCE.is_match(content),
            network: RE_NETWORK.is_match(content),
            secret: RE_SECRET.is_match(content),
            oauth: RE_OAUTH.is_match(content),
            cognitive_rootkit: RE_COGNITIVE_ROOTKIT.is_match(content),
            privileged_role: RE_PRIVILEGED_ROLE.is_match(content),
            unauthenticated_webhook:
                super::super::network::looks_like_webhook_receiver_without_auth(content).is_some(),
        }
    }
}
