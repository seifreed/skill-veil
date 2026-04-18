use super::patterns::RE_SHELL_SOURCE;
use super::ArtifactLink;
use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::services::ArtifactAnalysisService;
use regex::Regex;
use std::path::Path;
use std::sync::LazyLock;

static REMOTE_BINARY_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
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
});

static DEFERRED_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
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

static SHELL_INJECTION_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
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
});

static PYTHON_INJECTION_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
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

static NODE_INJECTION_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
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
});

static POWERSHELL_INJECTION_PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
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

    findings.extend(detect_remote_binary_downloads(content, &artifact_path));
    findings.extend(detect_deferred_execution(content, &artifact_path));
    findings.extend(detect_node_process_exec(&lower, &language, &artifact_path));
    findings.extend(detect_python_exec_network(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_python_secret_system_access(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_powershell_dynamic_exec(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_powershell_persistence(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_shell_side_effects(&lower, &language, &artifact_path));
    findings.extend(detect_shell_persistence_write(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_node_secret_fs_access(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_injection_patterns(
        content,
        &language,
        &artifact_path,
    ));
    findings.extend(artifact_analysis.permission_and_network_findings(
        path,
        content,
        ArtifactKind::ReferencedArtifact,
    ));

    findings
}

fn detect_remote_binary_downloads(content: &str, artifact_path: &str) -> Vec<Finding> {
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

fn detect_deferred_execution(content: &str, artifact_path: &str) -> Vec<Finding> {
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

fn detect_node_process_exec(
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

fn detect_python_exec_network(
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

fn detect_python_secret_system_access(
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

fn detect_powershell_dynamic_exec(
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

fn detect_powershell_persistence(
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

fn detect_shell_side_effects(
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

fn detect_shell_persistence_write(
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

fn detect_node_secret_fs_access(
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

fn detect_injection_patterns(content: &str, language: &str, artifact_path: &str) -> Vec<Finding> {
    let patterns: &[(&str, Regex)] = match language {
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

pub(crate) fn script_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let lower = content.to_ascii_lowercase();
    let mut capabilities = Vec::new();

    if lower.contains("curl ")
        || lower.contains("wget ")
        || lower.contains("invoke-webrequest")
        || lower.contains("http://")
        || lower.contains("https://")
    {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }

    if lower.contains("bash ")
        || lower.contains(" sh ")
        || lower.contains("node ")
        || lower.contains("python ")
        || lower.contains("npm install")
        || lower.contains("pip install")
        || lower.contains("cargo install")
    {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::InstallExecution,
        ));
    }

    if lower.contains("subprocess.")
        || lower.contains("os.system(")
        || lower.contains("exec(")
        || lower.contains("spawn(")
        || lower.contains("start-process")
        || lower.contains("iex ")
    {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::ProcessExecution,
        ));
    }

    if lower.contains("process.env")
        || lower.contains("os.environ")
        || lower.contains("getenv(")
        || lower.contains(".env")
        || lower.contains("access_token")
        || lower.contains("api_token")
        || lower.contains("auth_token")
        || lower.contains("bearer_token")
        || lower.contains("secret_key")
        || lower.contains("client_secret")
        || lower.contains("_authtoken")
    {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::SecretAccess,
        ));
    }

    if lower.contains("crontab")
        || lower.contains("schtasks")
        || lower.contains("launchctl")
        || lower.contains("runonce")
        || lower.contains("autostart")
        || lower.contains("register-scheduledtask")
    {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::PersistenceSurface,
        ));
    }

    if lower.contains("writefilesync(")
        || lower.contains("tee ")
        || lower.contains(">>")
        || lower.contains("> /etc/")
        || lower.contains("set-content")
    {
        capabilities.push(ArtifactAnalysisService::observed_capability(
            ArtifactCapability::FilesystemWrite,
        ));
    }

    capabilities
}

pub(crate) fn script_relations(content: &str) -> Vec<ArtifactLink> {
    let lower = content.to_ascii_lowercase();
    let mut links = Vec::new();
    if lower.contains("curl ") || lower.contains("wget ") || lower.contains("invoke-webrequest") {
        links.push(ArtifactLink {
            target: "remote-resource".to_string(),
            relation: ArtifactRelation::Downloads,
        });
    }
    if lower.contains("bash ")
        || lower.contains("sh ")
        || lower.contains("python ")
        || lower.contains("node ")
        || lower.contains("start-process")
        || lower.contains("subprocess.")
        || lower.contains("child_process")
    {
        links.push(ArtifactLink {
            target: "process".to_string(),
            relation: ArtifactRelation::Executes,
        });
    }
    if lower.contains("import ")
        || lower.contains("require(")
        || lower.contains("source ")
        || RE_SHELL_SOURCE.is_match(&lower)
    {
        links.push(ArtifactLink {
            target: "runtime-module".to_string(),
            relation: ArtifactRelation::Loads,
        });
    }
    if lower.contains("crontab")
        || lower.contains("schtasks")
        || lower.contains("launchctl")
        || lower.contains("autostart")
    {
        links.push(ArtifactLink {
            target: "persistence-surface".to_string(),
            relation: ArtifactRelation::Persists,
        });
    }
    if lower.contains("http://") || lower.contains("https://") || lower.contains("socket.") {
        links.push(ArtifactLink {
            target: "network".to_string(),
            relation: ArtifactRelation::ConnectsTo,
        });
    }
    if lower.contains("open(")
        || lower.contains("readfilesync(")
        || lower.contains("cat ")
        || lower.contains("rg ")
    {
        links.push(ArtifactLink {
            target: "filesystem".to_string(),
            relation: ArtifactRelation::Reads,
        });
    }
    if lower.contains("writefilesync(")
        || lower.contains("tee ")
        || lower.contains(">>")
        || lower.contains("set-content")
    {
        links.push(ArtifactLink {
            target: "filesystem".to_string(),
            relation: ArtifactRelation::Writes,
        });
    }
    if lower.contains("process.env")
        || lower.contains("os.environ")
        || lower.contains("getenv(")
        || lower.contains(".env")
    {
        links.push(ArtifactLink {
            target: "secrets".to_string(),
            relation: ArtifactRelation::AccessesSecrets,
        });
    }
    links
}
