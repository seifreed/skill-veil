use regex::Regex;
use std::sync::LazyLock;

pub(super) static REMOTE_BINARY_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(
    || {
        vec![
            (
                "SCRIPT_REMOTE_BINARY_DOWNLOAD",
                Regex::new(
                    "(?i)(curl|wget).*(\\.sh|\\.ps1|\\.py|\\.js|\\.exe|\\.pkg|\\.dmg|\\.deb|\\.rpm)",
                )
                .expect("valid regex: remote binary download"),
            ),
            (
                "SCRIPT_POWERSHELL_REMOTE_DOWNLOAD",
                Regex::new("(?i)invoke-webrequest.+(\\.ps1|\\.exe|\\.zip)")
                    .expect("valid regex: powershell remote download"),
            ),
        ]
    },
);

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
                Regex::new(r#"(?i)(bash|sh)\s+-c\s+["']?\$[A-Za-z_][A-Za-z0-9_]*"#)
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
                "COMMAND_INJECTION_SINK_POWERSHELL",
                Regex::new(r#"(?i)invoke-expression\s+\$[A-Za-z_][A-Za-z0-9_]*"#)
                    .expect("valid regex: powershell command injection"),
            ),
            (
                "UNSAFE_USER_CONTROLLED_EXEC_POWERSHELL",
                Regex::new(r#"(?i)start-process\s+\$[A-Za-z_][A-Za-z0-9_]*"#)
                    .expect("valid regex: powershell unsafe user exec"),
            ),
        ]
    });
