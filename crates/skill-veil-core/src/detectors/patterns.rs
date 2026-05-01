use crate::lazy_pattern;

lazy_pattern!(
    pub(crate) RE_OPAQUE_MCP_ENDPOINT,
    r"(?i)(ngrok|trycloudflare|workers\.dev|raw\.githubusercontent\.com|pastebin\.com)"
);
lazy_pattern!(
    pub(crate) RE_MCP_NO_AUTH,
    r#"(?is)("auth"\s*:\s*"none"|authentication\s*:\s*none|no auth|without auth|auth\s*:\s*none)"#
);
// Each alternative MUST require an actual secret value (>=8 char
// run) — pre-fix `authorization\s*:\s*bearer` and `api[_-]?key`
// matched the bare keyword with no value, raising
// `MCP_INLINE_SECRET` for documentation, README prose, comments,
// and variable-name mentions like `# Set up your api_key`.
// `_authtoken=` keeps the bare form because the trailing `=` is
// the npm-config syntax marker — even an empty value is a
// declaration of an auth-token slot.
lazy_pattern!(
    pub(crate) RE_MCP_INLINE_SECRET,
    r#"(?is)(bearer\s+[A-Za-z0-9._-]{8,}|authorization\s*:\s*bearer\s+[A-Za-z0-9._-]{8,}|api[_-]?key["']?\s*[:=]\s*["']?[A-Za-z0-9._-]{8,}|_authtoken=|token["']?\s*[:=]\s*["']?[A-Za-z0-9._-]{8,})"#
);
lazy_pattern!(
    pub(crate) RE_MCP_PERMISSIVE_TOOLS,
    r#"(?is)("tools"\s*:\s*\[[^\]]*"\*"|allow_all_tools|all_tools|tool_permissions\s*:\s*"all"|expose all tools)"#
);
lazy_pattern!(pub(crate) RE_QUOTED_TOOL_NAME, r#""([A-Za-z0-9._:-]{2,})""#);
lazy_pattern!(pub(crate) RE_MCP_TOOLS_ARRAY, r#"(?is)"tools"\s*:\s*\[([^\]]+)\]"#);
lazy_pattern!(pub(crate) RE_GENERIC_URL, r#"https?://[^\s"']+"#);
lazy_pattern!(pub(crate) RE_SHELL_SOURCE, r"(?m)^\s*\.\s+\S");

/// Whether `line` invokes a shell or interpreter as a command — `bash`, `sh`,
/// `dash`, `zsh`, `pwsh`, `powershell`, `python`, or `node`. Detection looks
/// at whitespace-delimited tokens and compares the lowercased basename
/// (stripped of a case-insensitive `.exe` suffix, leading `/` or `\` path
/// components) against a known set.
///
/// Avoids false positives on English words ending in "-sh" like `publish`,
/// `finish`, `wash`, `polish` — those words appear inside a single token
/// (e.g. `"publish"`) whose basename is the word itself, which is not in the
/// matched set. Handles `bash`, `/bin/bash`, `\tbash`,
/// `C:\Windows\System32\bash.exe`, `POWERSHELL.EXE`. Does not match
/// `python3` or `node22` (basename comparison is exact) — consistent with the
/// prior `contains("python ")` substring behavior.
///
/// Acceptable misses: quoted commands like `"bash" install.sh` (rare in
/// real fixtures) and backtick command substitution. Comments containing
/// `bash` text are out of scope here — comment filtering is the caller's
/// responsibility.
pub(crate) fn line_invokes_shell_or_interpreter(line: &str) -> bool {
    line.split_whitespace().any(|token| {
        let basename = token.rsplit(['/', '\\']).next().unwrap_or(token);
        let basename = basename
            .strip_suffix(".exe")
            .or_else(|| basename.strip_suffix(".EXE"))
            .or_else(|| basename.strip_suffix(".Exe"))
            .unwrap_or(basename);
        let basename_lower = basename.to_ascii_lowercase();
        matches!(
            basename_lower.as_str(),
            "bash" | "sh" | "dash" | "zsh" | "pwsh" | "powershell" | "python" | "node"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: `bash install.sh` at column 0 must be detected.
    #[test]
    fn line_invokes_shell_or_interpreter_detects_bash_at_column_zero() {
        assert!(line_invokes_shell_or_interpreter("bash install.sh"));
    }

    /// Contract: `sh install.sh` at column 0 must be detected (this was the
    /// false-negative under the old conservative `" sh "` pattern).
    #[test]
    fn line_invokes_shell_or_interpreter_detects_sh_at_column_zero() {
        assert!(line_invokes_shell_or_interpreter("sh install.sh"));
    }

    /// Contract: an absolute interpreter path resolves to its basename.
    #[test]
    fn line_invokes_shell_or_interpreter_detects_absolute_interpreter_path() {
        assert!(line_invokes_shell_or_interpreter("/bin/bash setup.sh"));
        assert!(line_invokes_shell_or_interpreter("/usr/bin/python -c 'x'"));
    }

    /// Contract: Windows interpreter path with `.exe` suffix resolves to the
    /// stem, after the input has been lower-cased by the caller.
    #[test]
    fn line_invokes_shell_or_interpreter_strips_exe_suffix() {
        assert!(line_invokes_shell_or_interpreter(
            "c:\\windows\\python.exe -c x"
        ));
    }

    /// Contract: case-insensitive `.exe` stripping. Windows filenames commonly
    /// use `.EXE` or `.Exe`; an attacker can evade detection by using an
    /// uppercase extension. Pre-fix `strip_suffix(".exe")` was case-sensitive
    /// and missed `POWERSHELL.EXE`, `bash.EXE`, etc.
    #[test]
    fn line_invokes_shell_or_interpreter_strips_exe_suffix_case_insensitive() {
        assert!(line_invokes_shell_or_interpreter(
            "C:\\Windows\\System32\\POWERSHELL.EXE -c x"
        ));
        assert!(line_invokes_shell_or_interpreter("bash.EXE script.sh"));
        assert!(line_invokes_shell_or_interpreter("python.Exe -c x"));
    }

    /// Contract: Windows backslash separators are handled in addition to `/`.
    #[test]
    fn line_invokes_shell_or_interpreter_handles_windows_backslash_path() {
        assert!(line_invokes_shell_or_interpreter("c:\\python\\python -c x"));
    }

    /// Contract: English words containing `sh` like `publish` must NOT
    /// match — this is the regression anchor for the `"sh "` substring bug.
    #[test]
    fn line_invokes_shell_or_interpreter_rejects_publish_word() {
        assert!(!line_invokes_shell_or_interpreter("publish docs"));
    }

    /// Contract: words like `finish`, `wash`, `polish` must NOT match.
    #[test]
    fn line_invokes_shell_or_interpreter_rejects_finish_word() {
        assert!(!line_invokes_shell_or_interpreter("finish setup"));
        assert!(!line_invokes_shell_or_interpreter("wash assets"));
        assert!(!line_invokes_shell_or_interpreter("polish reports"));
    }

    /// Contract: `python3` is a different basename from `python` and must
    /// NOT match — preserves prior behavior of `contains("python ")` which
    /// also did not match `"python3 "`.
    #[test]
    fn line_invokes_shell_or_interpreter_rejects_python3_basename() {
        assert!(!line_invokes_shell_or_interpreter("python3 -c x"));
        assert!(!line_invokes_shell_or_interpreter("node22 server.js"));
    }

    /// Contract: tab-indented Make recipes are handled — `split_whitespace`
    /// treats tabs and spaces equivalently.
    #[test]
    fn line_invokes_shell_or_interpreter_handles_tab_indented_makefile_recipe() {
        assert!(line_invokes_shell_or_interpreter("\tbash install.sh"));
        assert!(line_invokes_shell_or_interpreter("\tsh install.sh"));
    }

    /// Contract: empty / whitespace-only lines never match.
    #[test]
    fn line_invokes_shell_or_interpreter_rejects_empty_line() {
        assert!(!line_invokes_shell_or_interpreter(""));
        assert!(!line_invokes_shell_or_interpreter("   \t  "));
    }

    /// Contract: extended interpreter set (zsh, dash, pwsh, powershell) is
    /// also detected. Pins the "expanded token list" decision so a future
    /// reader doesn't shrink it back to bash/sh/python/node only.
    #[test]
    fn line_invokes_shell_or_interpreter_detects_extended_interpreter_set() {
        assert!(line_invokes_shell_or_interpreter("zsh script.zsh"));
        assert!(line_invokes_shell_or_interpreter("dash setup.sh"));
        assert!(line_invokes_shell_or_interpreter("pwsh -c 'x'"));
        assert!(line_invokes_shell_or_interpreter("powershell -c 'x'"));
    }

    /// Contract: `RE_MCP_INLINE_SECRET` requires an actual secret value,
    /// not just a keyword. `authorization: bearer <TOKEN>` and
    /// `api_key: "<TOKEN>"` (≥8 chars) MUST match because they declare a
    /// real credential.
    #[test]
    fn re_mcp_inline_secret_matches_real_credentials() {
        assert!(RE_MCP_INLINE_SECRET.is_match("authorization: bearer abc12345xyz"));
        assert!(RE_MCP_INLINE_SECRET.is_match(r#""api_key": "sk-abc12345xyz""#));
        assert!(RE_MCP_INLINE_SECRET.is_match("api-key=sk_live_abc12345"));
        assert!(RE_MCP_INLINE_SECRET.is_match("token=abc12345xyz"));
        assert!(RE_MCP_INLINE_SECRET.is_match("_authtoken="));
    }

    /// Contract: `RE_MCP_INLINE_SECRET` MUST NOT match keyword-only mentions
    /// (documentation prose, comments, variable names). Pre-fix the bare
    /// `authorization\s*:\s*bearer` and `api[_-]?key` alternatives matched
    /// any prose that mentioned the token, raising false positives on
    /// READMEs and configuration docs.
    #[test]
    fn re_mcp_inline_secret_rejects_keyword_only_mentions() {
        assert!(
            !RE_MCP_INLINE_SECRET.is_match("# Set up your api_key from the dashboard"),
            "prose mentioning `api_key` without a value must not match",
        );
        assert!(
            !RE_MCP_INLINE_SECRET.is_match("// authorization: bearer (described later)"),
            "documentation mentioning `authorization: bearer` without a token must not match",
        );
        assert!(
            !RE_MCP_INLINE_SECRET.is_match("Field name: api_key"),
            "field-name documentation must not match",
        );
    }
}
