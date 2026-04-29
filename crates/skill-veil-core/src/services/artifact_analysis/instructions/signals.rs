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
