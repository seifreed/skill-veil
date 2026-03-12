use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity,
    ThreatCategory,
};
use crate::services::ArtifactAnalysisService;
use regex::Regex;
use std::path::Path;

pub(crate) fn analyze_script(
    artifact_analysis: &ArtifactAnalysisService,
    path: &Path,
    content: &str,
) -> Vec<Finding> {
    let artifact_path = path.display().to_string();
    let language = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let lower = content.to_ascii_lowercase();
    let mut findings = Vec::new();

    let remote_binary_patterns = [
        ("SCRIPT_REMOTE_BINARY_DOWNLOAD", "(?i)(curl|wget).*(\\.sh|\\.ps1|\\.py|\\.js|\\.exe|\\.pkg|\\.dmg|\\.deb|\\.rpm)"),
        ("SCRIPT_POWERSHELL_REMOTE_DOWNLOAD", "(?i)invoke-webrequest.+(\\.ps1|\\.exe|\\.zip)"),
    ];
    for (rule_id, pattern) in remote_binary_patterns {
        let regex = Regex::new(pattern).expect("valid regex");
        for matched in regex.find_iter(content) {
            findings.push(
                Finding::builder(rule_id, ThreatCategory::SupplyChain)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(matched.as_str())
                    .reason("Script downloads a remote script or binary payload")
                    .build(),
            );
        }
    }

    let deferred_patterns = [
        ("SCRIPT_DEFERRED_EXECUTION", "(?i)(crontab|schtasks|at\\s+\\d|systemd-run|launchctl\\s+load)"),
        ("SCRIPT_PERSISTENCE", "(?i)(/etc/cron|~/\\.config/autostart|launchagents|startup\\\\|runonce)"),
    ];
    for (rule_id, pattern) in deferred_patterns {
        let regex = Regex::new(pattern).expect("valid regex");
        for matched in regex.find_iter(content) {
            findings.push(
                Finding::builder(rule_id, ThreatCategory::PrivilegeEscalation)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(matched.as_str())
                    .reason("Script configures deferred execution or persistence")
                    .build(),
            );
        }
    }

    if matches!(language.as_str(), "js" | "ts")
        && (lower.contains("child_process") || lower.contains("exec(") || lower.contains("spawn("))
    {
        let risky_process_exec = [
            "curl ",
            "wget ",
            "http://",
            "https://",
            "bash",
            "sh ",
            "powershell",
            "cmd.exe",
            "invoke-webrequest",
        ]
        .iter()
        .any(|needle| lower.contains(needle));
        findings.push(
            Finding::builder("SCRIPT_NODE_PROCESS_EXEC", ThreatCategory::RemoteExec)
                .severity(if risky_process_exec {
                    Severity::Medium
                } else {
                    Severity::Low
                })
                .action(if risky_process_exec {
                    RecommendedAction::RequireApproval
                } else {
                    RecommendedAction::Log
                })
                .evidence_kind(if risky_process_exec {
                    EvidenceKind::Behavior
                } else {
                    EvidenceKind::Context
                })
                .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value("child_process")
                .reason(if risky_process_exec {
                    "Node script spawns subprocesses with shell or network execution semantics"
                } else {
                    "Node script spawns local subprocesses"
                })
                .build(),
        );
    }

    if language == "py"
        && (lower.contains("subprocess.") || lower.contains("os.system(") || lower.contains("requests.get("))
    {
        findings.push(
            Finding::builder("SCRIPT_PYTHON_EXEC_NETWORK", ThreatCategory::RemoteExec)
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Behavior)
                .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value("subprocess/requests")
                .reason("Python script combines execution or network primitives")
                .build(),
        );
    }

    if language == "py"
        && (lower.contains("open(\"/etc/")
            || lower.contains("open('/etc/")
            || lower.contains("os.getenv(")
            || lower.contains("pathlib.path.home()")
            || lower.contains("os.environ"))
    {
        findings.push(
            Finding::builder(
                "SCRIPT_PYTHON_SECRET_OR_SYSTEM_ACCESS",
                ThreatCategory::CredentialExposure,
            )
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Behavior)
            .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .match_value("python secret/system access")
            .reason("Python script reads environment variables, home paths, or system files")
            .build(),
        );
    }

    if language == "ps1"
        && (lower.contains("start-process")
            || lower.contains("invoke-expression")
            || lower.contains("iex "))
    {
        findings.push(
            Finding::builder("SCRIPT_POWERSHELL_EXEC", ThreatCategory::RemoteExec)
                .severity(Severity::High)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Behavior)
                .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value("Start-Process/IEX")
                .reason("PowerShell script executes commands dynamically")
                .build(),
        );
    }

    if language == "ps1"
        && (lower.contains("new-itemproperty")
            || lower.contains("set-itemproperty")
            || lower.contains("scheduledtask")
            || lower.contains("register-scheduledtask"))
    {
        findings.push(
            Finding::builder("SCRIPT_POWERSHELL_PERSISTENCE", ThreatCategory::PrivilegeEscalation)
                .severity(Severity::High)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Behavior)
                .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value("registry/scheduled task persistence")
                .reason("PowerShell script configures persistence via registry or scheduled tasks")
                .build(),
        );
    }

    if matches!(language.as_str(), "sh" | "bash" | "zsh")
        && (lower.contains("chmod +x") || lower.contains("nohup ") || lower.contains("/dev/tcp/"))
    {
        findings.push(
            Finding::builder("SCRIPT_SHELL_INSTALL_SIDE_EFFECT", ThreatCategory::SupplyChain)
                .severity(Severity::Low)
                .action(RecommendedAction::Log)
                .evidence_kind(EvidenceKind::Context)
                .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.clone(),
                })
                .match_value("shell side effects")
                .reason("Shell script changes execution mode or runs detached install-time commands")
                .build(),
        );
    }

    if matches!(language.as_str(), "sh" | "bash" | "zsh")
        && (lower.contains("> /etc/")
            || lower.contains("tee /etc/")
            || lower.contains("echo ") && lower.contains(">> ~/."))
    {
        findings.push(
            Finding::builder(
                "SCRIPT_SHELL_PERSISTENCE_WRITE",
                ThreatCategory::PrivilegeEscalation,
            )
            .severity(Severity::High)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Behavior)
            .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .match_value("shell persistence write")
            .reason("Shell script writes to startup or system configuration paths")
            .build(),
        );
    }

    if matches!(language.as_str(), "js" | "ts")
        && ((lower.contains("process.env")
            && (lower.contains("token")
                || lower.contains("secret")
                || lower.contains("cookie")
                || lower.contains("session")
                || lower.contains("auth")))
            || lower.contains("fs.readfilesync(process.env")
            || lower.contains("fs.readfilesync(\"/etc/")
            || lower.contains("fs.readfilesync('/etc/"))
    {
        findings.push(
            Finding::builder(
                "SCRIPT_NODE_SECRET_OR_FS_ACCESS",
                ThreatCategory::CredentialExposure,
            )
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Behavior)
            .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.clone(),
            })
            .match_value("process.env/fs access")
            .reason("Node script accesses environment variables or sensitive filesystem paths")
            .build(),
        );
    }

    let shell_injection_patterns = [
        (
            "COMMAND_INJECTION_SINK_SHELL",
            r#"(?i)(bash|sh)\s+-c\s+["']?\$[A-Za-z_][A-Za-z0-9_]*"#,
        ),
        (
            "UNSAFE_USER_CONTROLLED_EXEC_SHELL",
            r#"(?i)(curl|wget)[^\n]{0,180}(\$[1-9]|\$\{?[A-Za-z_]*(INPUT|USER_INPUT|CMD|COMMAND|ARGS?|REQUEST_URL|TARGET_URL)\}?)"#,
        ),
    ];
    let python_injection_patterns = [
        (
            "COMMAND_INJECTION_SINK_PYTHON",
            r#"(?i)subprocess\.(run|popen|call)\([^)]*shell\s*=\s*true"#,
        ),
        (
            "UNSAFE_USER_CONTROLLED_EXEC_PYTHON",
            r#"(?i)os\.system\(f?["'][^"']*\{[A-Za-z_][A-Za-z0-9_]*\}"#,
        ),
    ];
    let node_injection_patterns = [
        (
            "COMMAND_INJECTION_SINK_NODE",
            r#"(?i)child_process\.(exec|spawn)\([^)]*(req\.|process\.argv|userInput|input|cmd|command)"#,
        ),
        (
            "UNSAFE_USER_CONTROLLED_EXEC_NODE",
            r#"(?i)child_process\.(exec|spawn)\([^)]*(req\.|process\.argv|userInput|input)"#,
        ),
    ];
    let powershell_injection_patterns = [
        (
            "COMMAND_INJECTION_SINK_POWERSHELL",
            r#"(?i)invoke-expression\s+\$[A-Za-z_][A-Za-z0-9_]*"#,
        ),
        (
            "UNSAFE_USER_CONTROLLED_EXEC_POWERSHELL",
            r#"(?i)start-process\s+\$[A-Za-z_][A-Za-z0-9_]*"#,
        ),
    ];

    let patterns = match language.as_str() {
        "sh" | "bash" | "zsh" => &shell_injection_patterns[..],
        "py" => &python_injection_patterns[..],
        "js" | "ts" => &node_injection_patterns[..],
        "ps1" => &powershell_injection_patterns[..],
        _ => &[][..],
    };
    for (rule_id, pattern) in patterns {
        let regex = Regex::new(pattern).expect("valid regex");
        for matched in regex.find_iter(content) {
            findings.push(
                Finding::builder(*rule_id, ThreatCategory::RemoteExec)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.clone()))
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.clone(),
                    })
                    .match_value(matched.as_str())
                    .reason("Script contains an execution sink that appears to be influenced by variable or user-controlled input")
                    .build(),
            );
        }
    }

    findings.extend(artifact_analysis.permission_and_network_findings(
        path,
        content,
        ArtifactKind::ReferencedArtifact,
    ));

    findings
}
