use regex::Regex;
use std::sync::LazyLock;

pub(super) static RE_OPAQUE_MCP_ENDPOINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        "(?i)(ngrok|trycloudflare|workers\\.dev|raw\\.githubusercontent\\.com|pastebin\\.com)",
    )
    .expect("valid regex: opaque MCP endpoint")
});
pub(super) static RE_MCP_NO_AUTH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?is)(\"auth\"\\s*:\\s*\"none\"|authentication\\s*:\\s*none|no auth|without auth|auth\\s*:\\s*none)")
        .expect("valid regex: MCP no auth")
});
pub(super) static RE_MCP_INLINE_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?is)(bearer\\s+[A-Za-z0-9._-]{8,}|authorization\\s*:\\s*bearer|api[_-]?key|_authtoken=|token\\s*[:=]\\s*[A-Za-z0-9._-]{8,})")
        .expect("valid regex: MCP inline secret")
});
pub(super) static RE_MCP_PERMISSIVE_TOOLS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("(?is)(\"tools\"\\s*:\\s*\\[[^\\]]*\"\\*\"|allow_all_tools|all_tools|tool_permissions\\s*:\\s*\"all\"|expose all tools)")
        .expect("valid regex: MCP permissive tools")
});
pub(super) static RE_QUOTED_TOOL_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#""([A-Za-z0-9._:-]{2,})""#).expect("valid regex: quoted tool name")
});
pub(super) static RE_MCP_TOOLS_ARRAY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)"tools"\s*:\s*\[([^\]]+)\]"#).expect("valid regex: MCP tools array")
});
pub(super) static RE_GENERIC_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s"']+"#).expect("valid regex: generic URL"));
pub(super) static RE_SHELL_SOURCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^\s*\.\s+\S").expect("valid regex: shell source command"));
