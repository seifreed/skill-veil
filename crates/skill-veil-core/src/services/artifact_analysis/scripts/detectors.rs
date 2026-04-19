use super::patterns::{
    DEFERRED_PATTERNS, NODE_INJECTION_PATTERNS, POWERSHELL_INJECTION_PATTERNS,
    PYTHON_INJECTION_PATTERNS, REMOTE_BINARY_PATTERNS, SHELL_INJECTION_PATTERNS,
};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};

pub(super) fn detect_remote_binary_downloads(content: &str, artifact_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rule_id, regex) in REMOTE_BINARY_PATTERNS.iter() {
        for matched in regex.find_iter(content) {
            findings.push(
                Finding::builder(*rule_id, ThreatCategory::SupplyChain)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.to_string(),
                    })
                    .artifact(
                        ArtifactKind::ReferencedArtifact,
                        Some(artifact_path.to_string()),
                    )
                    .match_value(matched.as_str())
                    .reason("Script downloads a remote script or binary payload")
                    .build(),
            );
        }
    }
    findings
}

pub(super) fn detect_deferred_execution(content: &str, artifact_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rule_id, regex) in DEFERRED_PATTERNS.iter() {
        for matched in regex.find_iter(content) {
            findings.push(
                Finding::builder(*rule_id, ThreatCategory::PrivilegeEscalation)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.to_string(),
                    })
                    .artifact(
                        ArtifactKind::ReferencedArtifact,
                        Some(artifact_path.to_string()),
                    )
                    .match_value(matched.as_str())
                    .reason("Script configures deferred execution or persistence")
                    .build(),
            );
        }
    }
    findings
}

pub(super) fn detect_node_process_exec(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if !matches!(language, "js" | "ts" | "mjs" | "cjs" | "mts" | "cts")
        || !(content_lower.contains("child_process")
            || content_lower.contains("exec(")
            || content_lower.contains("spawn("))
    {
        return Vec::new();
    }
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
    .any(|needle| content_lower.contains(needle));
    vec![
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
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.to_string(),
            })
            .artifact(
                ArtifactKind::ReferencedArtifact,
                Some(artifact_path.to_string()),
            )
            .match_value("child_process")
            .reason(if risky_process_exec {
                "Node script spawns subprocesses with shell or network execution semantics"
            } else {
                "Node script spawns local subprocesses"
            })
            .build(),
    ]
}

pub(super) fn detect_python_exec_network(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if language != "py" {
        return Vec::new();
    }
    let has_exec = content_lower.contains("subprocess.") || content_lower.contains("os.system(");
    let has_network = content_lower.contains("requests.get(")
        || content_lower.contains("requests.post(")
        || content_lower.contains("urllib.request")
        || content_lower.contains("httpx.");
    if has_exec && has_network {
        vec![
            Finding::builder("SCRIPT_PYTHON_EXEC_NETWORK", ThreatCategory::RemoteExec)
                .severity(Severity::Medium)
                .action(RecommendedAction::RequireApproval)
                .evidence_kind(EvidenceKind::Behavior)
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.to_string(),
                })
                .artifact(
                    ArtifactKind::ReferencedArtifact,
                    Some(artifact_path.to_string()),
                )
                .match_value("subprocess+network")
                .reason("Python script combines execution and network primitives")
                .build(),
        ]
    } else if has_exec {
        vec![
            Finding::builder("SCRIPT_PYTHON_EXEC", ThreatCategory::RemoteExec)
                .severity(Severity::Low)
                .action(RecommendedAction::Log)
                .evidence_kind(EvidenceKind::Context)
                .matched_on(MatchTarget::ReferencedFile {
                    path: artifact_path.to_string(),
                })
                .artifact(
                    ArtifactKind::ReferencedArtifact,
                    Some(artifact_path.to_string()),
                )
                .match_value("subprocess")
                .reason("Python script uses execution primitives")
                .build(),
        ]
    } else {
        Vec::new()
    }
}

pub(super) fn detect_python_secret_system_access(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if language != "py"
        || !(content_lower.contains("open(\"/etc/")
            || content_lower.contains("open('/etc/")
            || content_lower.contains("os.getenv(")
            || content_lower.contains("pathlib.path.home()")
            || content_lower.contains("os.environ"))
    {
        return Vec::new();
    }
    vec![Finding::builder(
        "SCRIPT_PYTHON_SECRET_OR_SYSTEM_ACCESS",
        ThreatCategory::CredentialExposure,
    )
    .severity(Severity::Medium)
    .action(RecommendedAction::RequireApproval)
    .evidence_kind(EvidenceKind::Behavior)
    .matched_on(MatchTarget::ReferencedFile {
        path: artifact_path.to_string(),
    })
    .artifact(
        ArtifactKind::ReferencedArtifact,
        Some(artifact_path.to_string()),
    )
    .match_value("python secret/system access")
    .reason("Python script reads environment variables, home paths, or system files")
    .build()]
}

pub(super) fn detect_powershell_dynamic_exec(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if language != "ps1"
        || !(content_lower.contains("start-process")
            || content_lower.contains("invoke-expression")
            || content_lower.contains("iex "))
    {
        return Vec::new();
    }
    vec![
        Finding::builder("SCRIPT_POWERSHELL_EXEC", ThreatCategory::RemoteExec)
            .severity(Severity::High)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Behavior)
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.to_string(),
            })
            .artifact(
                ArtifactKind::ReferencedArtifact,
                Some(artifact_path.to_string()),
            )
            .match_value("Start-Process/IEX")
            .reason("PowerShell script executes commands dynamically")
            .build(),
    ]
}

pub(super) fn detect_powershell_persistence(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if language != "ps1"
        || !(content_lower.contains("new-itemproperty")
            || content_lower.contains("set-itemproperty")
            || content_lower.contains("scheduledtask")
            || content_lower.contains("register-scheduledtask"))
    {
        return Vec::new();
    }
    vec![Finding::builder(
        "SCRIPT_POWERSHELL_PERSISTENCE",
        ThreatCategory::PrivilegeEscalation,
    )
    .severity(Severity::High)
    .action(RecommendedAction::RequireApproval)
    .evidence_kind(EvidenceKind::Behavior)
    .matched_on(MatchTarget::ReferencedFile {
        path: artifact_path.to_string(),
    })
    .artifact(
        ArtifactKind::ReferencedArtifact,
        Some(artifact_path.to_string()),
    )
    .match_value("registry/scheduled task persistence")
    .reason("PowerShell script configures persistence via registry or scheduled tasks")
    .build()]
}

pub(super) fn detect_shell_side_effects(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if !matches!(language, "sh" | "bash" | "zsh")
        || !(content_lower.contains("chmod +x")
            || content_lower.contains("nohup ")
            || content_lower.contains("/dev/tcp/"))
    {
        return Vec::new();
    }
    vec![Finding::builder(
        "SCRIPT_SHELL_INSTALL_SIDE_EFFECT",
        ThreatCategory::SupplyChain,
    )
    .severity(Severity::Low)
    .action(RecommendedAction::Log)
    .evidence_kind(EvidenceKind::Context)
    .matched_on(MatchTarget::ReferencedFile {
        path: artifact_path.to_string(),
    })
    .artifact(
        ArtifactKind::ReferencedArtifact,
        Some(artifact_path.to_string()),
    )
    .match_value("shell side effects")
    .reason("Shell script changes execution mode or runs detached install-time commands")
    .build()]
}

pub(super) fn detect_shell_persistence_write(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if !matches!(language, "sh" | "bash" | "zsh")
        || !(content_lower.contains("> /etc/")
            || content_lower.contains("tee /etc/")
            || content_lower
                .lines()
                .any(|line| line.contains("echo ") && line.contains(">> ~/.")))
    {
        return Vec::new();
    }
    vec![Finding::builder(
        "SCRIPT_SHELL_PERSISTENCE_WRITE",
        ThreatCategory::PrivilegeEscalation,
    )
    .severity(Severity::High)
    .action(RecommendedAction::RequireApproval)
    .evidence_kind(EvidenceKind::Behavior)
    .matched_on(MatchTarget::ReferencedFile {
        path: artifact_path.to_string(),
    })
    .artifact(
        ArtifactKind::ReferencedArtifact,
        Some(artifact_path.to_string()),
    )
    .match_value("shell persistence write")
    .reason("Shell script writes to startup or system configuration paths")
    .build()]
}

pub(super) fn detect_node_secret_fs_access(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if !matches!(language, "js" | "ts" | "mjs" | "cjs" | "mts" | "cts")
        || !((content_lower.contains("process.env")
            && (content_lower.contains("token")
                || content_lower.contains("secret")
                || content_lower.contains("cookie")
                || content_lower.contains("session")
                || content_lower.contains("auth")))
            || content_lower.contains("fs.readfilesync(process.env")
            || content_lower.contains("fs.readfilesync(\"/etc/")
            || content_lower.contains("fs.readfilesync('/etc/"))
    {
        return Vec::new();
    }
    vec![Finding::builder(
        "SCRIPT_NODE_SECRET_OR_FS_ACCESS",
        ThreatCategory::CredentialExposure,
    )
    .severity(Severity::Medium)
    .action(RecommendedAction::RequireApproval)
    .evidence_kind(EvidenceKind::Behavior)
    .matched_on(MatchTarget::ReferencedFile {
        path: artifact_path.to_string(),
    })
    .artifact(
        ArtifactKind::ReferencedArtifact,
        Some(artifact_path.to_string()),
    )
    .match_value("process.env/fs access")
    .reason("Node script accesses environment variables or sensitive filesystem paths")
    .build()]
}

pub(super) fn detect_injection_patterns(
    content: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    let patterns: &[(&str, regex::Regex)] = match language {
        "sh" | "bash" | "zsh" => &SHELL_INJECTION_PATTERNS,
        "py" => &PYTHON_INJECTION_PATTERNS,
        "js" | "ts" | "mjs" | "cjs" | "mts" | "cts" => &NODE_INJECTION_PATTERNS,
        "ps1" => &POWERSHELL_INJECTION_PATTERNS,
        _ => &[],
    };
    let mut findings = Vec::new();
    for (rule_id, regex) in patterns {
        for matched in regex.find_iter(content) {
            findings.push(
                Finding::builder(*rule_id, ThreatCategory::RemoteExec)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.to_string(),
                    })
                    .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.to_string()))
                    .match_value(matched.as_str())
                    .reason("Script contains an execution sink that appears to be influenced by variable or user-controlled input")
                    .build(),
            );
        }
    }
    findings
}
