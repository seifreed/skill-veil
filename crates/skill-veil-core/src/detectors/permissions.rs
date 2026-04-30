use crate::findings::{
    ArtifactKind, EvidenceKind, Finding, MatchTarget, RecommendedAction, Severity, ThreatCategory,
};

/// Permission-rule count above which an artifact crosses into
/// `SCOPE_OVERPROVISIONING`. Three is the empirical knee where benign
/// "I declare browser + network + file write" overlaps with malicious
/// over-provisioning patterns from the corpus; raising it lets
/// over-broad declarations slip through, lowering it floods the verdict
/// with hygiene-grade noise.
pub(crate) const BROAD_PERMISSION_THRESHOLD: usize = 3;

/// Emit `SCOPE_OVERPROVISIONING` when an artifact declares at least
/// [`BROAD_PERMISSION_THRESHOLD`] distinct permission scopes. The check
/// is purely on the count of declared rule kinds — the per-rule
/// findings are emitted separately by the orchestration layer.
pub(crate) fn over_provisioning_finding(
    permission_rules: &[(&str, &str, &str)],
    artifact_path: &str,
    artifact_kind: ArtifactKind,
) -> Option<Finding> {
    (permission_rules.len() >= BROAD_PERMISSION_THRESHOLD).then(|| {
        Finding::builder("SCOPE_OVERPROVISIONING", ThreatCategory::ScopeCreep)
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Context)
            .artifact(artifact_kind, Some(artifact_path.to_string()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.to_string(),
            })
            .match_value("broad declared permissions")
            .reason("Artifact declares broad permissions or scopes relative to its apparent task")
            .build()
    })
}

/// Emit `CAPABILITY_PERMISSION_MISMATCH` when an artifact's declared
/// intent is narrow but its declared permissions include one of the
/// dangerous capability triggers (full browser, file write, shell exec).
/// Mismatched intent vs. capability scope is the canonical "trojan
/// helper" pattern — a tool that *says* it does one small thing but
/// asks for broad authority.
pub(crate) fn capability_permission_mismatch_finding(
    permission_rules: &[(&str, &str, &str)],
    content: &str,
    artifact_path: &str,
    artifact_kind: ArtifactKind,
) -> Option<Finding> {
    let (intent_kind, intent_strength) = infer_declared_intent(content);
    let has_dangerous_permission_combo = permission_rules.iter().any(|(rule_id, _, _)| {
        matches!(
            *rule_id,
            "DECLARED_PERMISSION_BROWSER_FULL"
                | "DECLARED_PERMISSION_FILE_WRITE"
                | "DECLARED_PERMISSION_SHELL_EXEC"
        )
    });
    (intent_kind == "narrow" && intent_strength > 0 && has_dangerous_permission_combo).then(|| {
        Finding::builder("CAPABILITY_PERMISSION_MISMATCH", ThreatCategory::ScopeCreep)
            .severity(Severity::Medium)
            .action(RecommendedAction::RequireApproval)
            .evidence_kind(EvidenceKind::Intent)
            .artifact(artifact_kind, Some(artifact_path.to_string()))
            .matched_on(MatchTarget::ReferencedFile {
                path: artifact_path.to_string(),
            })
            .match_value("narrow intent with broad capability request")
            .reason(
                "Artifact intent appears narrower than the capabilities or permissions it requests",
            )
            .build()
    })
}

/// Build a context excerpt around any line that hints at permission or
/// capability declarations.
///
/// # Dedup contract
///
/// A single line that satisfies multiple heuristics (e.g. `- permissions:
/// capabilities: full` matches both the bullet prefix AND the substring
/// keywords) MUST emit its surrounding window only ONCE. Without the
/// `emitted_anchors` guard, downstream substring matching in
/// `explicit_declared_permission_rules` counts the same permission keyword
/// N times per anchor, which can falsely cross the
/// `SCOPE_OVERPROVISIONING` threshold from a single source line.
pub(crate) fn permission_context(content: &str) -> String {
    let lines: Vec<_> = content.lines().collect();
    let mut buffer = String::new();
    // Dedup by EMITTED LINE INDEX, not by anchor index. Adjacent anchor
    // lines (distance < window_size) produce overlapping windows where the
    // shared lines would otherwise appear twice, double-counting any
    // permission keyword in those overlap zones — the very inflation that
    // could push `SCOPE_OVERPROVISIONING` past its threshold from a single
    // multi-line block. Per-emitted-line dedup resolves both the multi-
    // condition single anchor and the adjacent-anchor overlap cases.
    let mut emitted_lines: std::collections::BTreeSet<usize> = Default::default();
    for (index, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        let trimmed = line.trim_start();
        let is_anchor = lower.contains("permission")
            || lower.contains("capabilit")
            || trimmed.starts_with("- ")
            || trimmed.starts_with("* ");
        if !is_anchor {
            continue;
        }
        const LINES_BEFORE: usize = 1;
        const LINES_AFTER: usize = 2;
        let start = index.saturating_sub(LINES_BEFORE);
        let end = (index + 1 + LINES_AFTER).min(lines.len());
        for (i, snippet) in lines.iter().enumerate().take(end).skip(start) {
            if emitted_lines.insert(i) {
                buffer.push_str(snippet);
                buffer.push('\n');
            }
        }
    }
    if buffer.is_empty() {
        content.to_string()
    } else {
        buffer
    }
}

pub(crate) fn intent_context(content: &str) -> String {
    let mut buffer = String::new();
    let lines: Vec<_> = content.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("intent")
            || lower.contains("goal")
            || lower.contains("purpose")
            || lower.contains("summary")
            || lower.contains("workflow")
        {
            let start = index;
            let end = (index + 4).min(lines.len());
            for snippet in &lines[start..end] {
                buffer.push_str(snippet);
                buffer.push('\n');
            }
        }
    }
    if buffer.is_empty() {
        content.to_string()
    } else {
        buffer
    }
}

pub(crate) fn infer_declared_intent(content: &str) -> (&'static str, usize) {
    let context = intent_context(content).to_ascii_lowercase();
    let narrow_terms = [
        "read-only",
        "summarize",
        "list",
        "inspect",
        "audit",
        "review",
        "search",
        "lookup",
    ];
    let broad_terms = [
        "modify",
        "delete",
        "write",
        "execute",
        "deploy",
        "install",
        "full access",
        "admin",
    ];
    let narrow_score = narrow_terms
        .iter()
        .filter(|term| context.contains(**term))
        .count();
    let broad_score = broad_terms
        .iter()
        .filter(|term| context.contains(**term))
        .count();
    if narrow_score > broad_score && narrow_score > 0 {
        ("narrow", narrow_score)
    } else if broad_score > 0 {
        ("broad", broad_score)
    } else {
        ("unknown", 0)
    }
}

pub(crate) fn explicit_declared_permission_rules(
    content: &str,
) -> Vec<(&'static str, &'static str, &'static str)> {
    let context = permission_context(content).to_ascii_lowercase();
    let mut rules = Vec::new();

    if context.contains("browser: full")
        || context.contains("full autonomous browser")
        || context.contains("allow-all browser")
        || context.contains("click any element")
    {
        rules.push((
            "DECLARED_PERMISSION_BROWSER_FULL",
            "browser full",
            "Artifact declares broad browser automation permissions",
        ));
    }
    if context.contains("write file")
        || context.contains("write files")
        || context.contains("modify files")
        || context.contains("delete file")
        || context.contains("delete files")
    {
        rules.push((
            "DECLARED_PERMISSION_FILE_WRITE",
            "file write",
            "Artifact declares file modification or deletion capability",
        ));
    }
    if has_shell_exec_signal(&context) {
        rules.push((
            "DECLARED_PERMISSION_SHELL_EXEC",
            "shell exec",
            "Artifact declares shell or command execution capability",
        ));
    }
    if context.contains("network")
        || context.contains("external api")
        || context.contains("webhook")
        || context.contains("internet")
        || context.contains("outbound request")
    {
        rules.push((
            "DECLARED_PERMISSION_NETWORK_ACCESS",
            "network access",
            "Artifact declares outbound network access",
        ));
    }
    if context.contains("token")
        || context.contains("secret")
        || context.contains("password")
        || context.contains("credential")
        || context.contains("cookie")
    {
        rules.push((
            "DECLARED_PERMISSION_SECRETS_ACCESS",
            "secrets access",
            "Artifact declares access to secrets, tokens, or credentials",
        ));
    }
    if has_oauth_scope_signal(&context) {
        rules.push((
            "DECLARED_PERMISSION_OAUTH_SCOPES",
            "oauth scopes",
            "Artifact declares OAuth scopes or broad SaaS permissions",
        ));
    }

    rules
}

/// Whether a permission-context buffer carries a real shell/exec
/// declaration.
///
/// Pre-fix the trigger included `context.contains("shell")` as a bare
/// substring, which fired on benign English prose: `"seashell"`,
/// `"eggshell"`, `"in a nutshell"`, or `"Unlike a conventional shell
/// script, this does not …"`. False positives here flow into both the
/// per-rule finding and the cross-rule
/// `CAPABILITY_PERMISSION_MISMATCH` / `SCOPE_OVERPROVISIONING`
/// aggregates, so a single chatty sentence could push an artifact into
/// `RequireApproval`.
///
/// The replacement requires either:
///
/// - a specific shell-execution phrase (`"shell exec"`, `"shell
///   access"`, `"shell command"`, `"shell script"`, `"run shell"`,
///   `"spawn shell"`, `"system shell"`, `"open shell"`, `"opens a
///   shell"`, `"shell: true"`), or
/// - one of the unambiguous non-`shell` synonyms that already shipped
///   pre-fix (`"terminal command"`, `"run command"`, `"execute
///   command"`, `"stdio"`).
fn has_shell_exec_signal(context: &str) -> bool {
    const SHELL_PHRASES: &[&str] = &[
        "shell exec",
        "shell access",
        "shell command",
        "shell script",
        "run shell",
        "spawn shell",
        "system shell",
        "open shell",
        "opens a shell",
        "shell: true",
        "terminal command",
        "run command",
        "execute command",
        "stdio",
    ];
    SHELL_PHRASES.iter().any(|phrase| context.contains(phrase))
}

/// Whether a permission-context buffer carries a real OAuth-scope or
/// broad SaaS-permission declaration.
///
/// Pre-fix the trigger included `context.contains("scope")` as a bare
/// substring, which fired on common prose: `"the scope of this tool"`,
/// `"in scope"`, `"out of scope"`. Combined with two other declared
/// rules this could escalate to `SCOPE_OVERPROVISIONING` on benign
/// content. The new rule keeps the unambiguous SaaS triggers
/// (`"oauth"`, `"calendar"`, `"drive"`, `"slack"`, `"read/write"`)
/// and replaces bare `"scope"` with `"oauth scope"` (which also
/// matches `"oauth scopes"`).
fn has_oauth_scope_signal(context: &str) -> bool {
    context.contains("oauth")
        || context.contains("oauth scope")
        || context.contains("calendar")
        || context.contains("drive")
        || context.contains("slack")
        || context.contains("read/write")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Contract: a single source line that satisfies multiple anchor
    /// heuristics emits its context window exactly once. Without dedup, a
    /// line like "- permissions: capabilities: full" appended its window 4
    /// times (bullet prefix + "permission" + "capabilit" + asterisk
    /// fallback), inflating the keyword count seen by downstream rules.
    #[test]
    fn permission_context_does_not_duplicate_window_for_multi_match_line() {
        let content = "header\n- permissions: capabilities: full\nbody1\nbody2\nfooter\n";
        let ctx = permission_context(content);
        // Count how many times the multi-match line appears in the buffer.
        let occurrences = ctx.matches("- permissions: capabilities: full").count();
        assert_eq!(
            occurrences, 1,
            "Multi-condition line '{}' must appear exactly once in the context buffer; \
             got {} occurrences. Buffer was:\n{}",
            "- permissions: capabilities: full", occurrences, ctx
        );
    }

    /// Distinct anchor lines still emit independent windows.
    #[test]
    fn permission_context_emits_distinct_windows_for_different_anchors() {
        let content = "permission line one\nbody\ncapability line two\nbody\n";
        let ctx = permission_context(content);
        assert!(ctx.contains("permission line one"));
        assert!(ctx.contains("capability line two"));
    }

    #[test]
    fn permission_context_falls_back_to_full_content_when_no_anchor() {
        let content = "no anchors here\njust prose\n";
        let ctx = permission_context(content);
        assert_eq!(ctx, content);
    }

    /// Contract: when two anchor lines sit close enough that their
    /// emission windows overlap, the shared lines MUST appear only ONCE
    /// in the buffer. Otherwise downstream substring matching would
    /// double-count keywords on those lines, inflating
    /// `SCOPE_OVERPROVISIONING` from a single multi-line block.
    #[test]
    fn permission_context_does_not_double_count_overlapping_window_lines() {
        // Two anchor lines at indices 0 and 1; both emit windows that
        // share line 1, line 2 (LINES_BEFORE=1, LINES_AFTER=2).
        let content = "- permissions: A\n- capabilities: B\nshared line\nmore\n";
        let ctx = permission_context(content);
        let occurrences = ctx.matches("shared line").count();
        assert_eq!(
            occurrences, 1,
            "Overlapping window line must appear exactly once; buffer:\n{ctx}"
        );
    }

    /// Contract: `has_shell_exec_signal` MUST NOT fire on common English
    /// prose that incidentally contains the four bytes `shell`. Pre-fix
    /// the substring trigger fired on `"seashell"`, `"eggshell"`, `"in a
    /// nutshell"`, and `"shell script"` discussions even when the
    /// artifact never asked for shell execution. The false positives
    /// then propagated into `CAPABILITY_PERMISSION_MISMATCH` and
    /// `SCOPE_OVERPROVISIONING`, pushing benign artifacts toward
    /// `RequireApproval`.
    #[test]
    fn shell_exec_signal_does_not_fire_on_prose_lookalikes() {
        let benign = [
            "permissions: read seashells from the corpus",
            "capabilities include eggshell calcium analysis",
            "in a nutshell, this tool inspects logs",
            "permission to summarise without a shell",
            "* permissions: eggshell-thin error margins",
        ];
        for sample in benign {
            assert!(
                !has_shell_exec_signal(&sample.to_ascii_lowercase()),
                "must NOT classify benign prose as shell-exec: {sample:?}"
            );
        }
    }

    /// Contract: `has_shell_exec_signal` MUST fire when an artifact
    /// genuinely declares shell or command execution. Pin the canonical
    /// declaration phrases so a future tightening doesn't silently lose
    /// the positive signal.
    #[test]
    fn shell_exec_signal_fires_on_genuine_declarations() {
        let positive = [
            "- permissions: shell exec",
            "capabilities: shell access on the host",
            "- run shell commands as the agent",
            "permissions: shell: true",
            "capabilities: terminal command execution",
            "- run command on the operator's machine",
            "executes commands via stdio",
        ];
        for sample in positive {
            assert!(
                has_shell_exec_signal(&sample.to_ascii_lowercase()),
                "must classify genuine declaration as shell-exec: {sample:?}"
            );
        }
    }

    /// Contract: `has_oauth_scope_signal` MUST NOT fire on common
    /// English prose that uses `"scope"` in its everyday sense. Pre-fix
    /// the substring trigger fired on `"in scope"`, `"out of scope"`,
    /// `"the scope of this task"`, and would emit
    /// `DECLARED_PERMISSION_OAUTH_SCOPES`. Combined with two other
    /// declared rules this crossed `SCOPE_OVERPROVISIONING`'s threshold
    /// from a single benign sentence.
    #[test]
    fn oauth_scope_signal_does_not_fire_on_prose_lookalikes() {
        let benign = [
            "this tool's scope is limited to read-only inspection",
            "tasks that fall out of scope go to the human",
            "the scope of work here is well-defined",
            "permissions: in scope for review",
        ];
        for sample in benign {
            assert!(
                !has_oauth_scope_signal(&sample.to_ascii_lowercase()),
                "must NOT classify benign prose as oauth-scopes: {sample:?}"
            );
        }
    }

    /// Contract: `has_oauth_scope_signal` MUST fire on genuine OAuth /
    /// SaaS-permission declarations. Pin the unambiguous triggers that
    /// shipped pre-fix so a future tightening of the heuristic does not
    /// silently lose them.
    #[test]
    fn oauth_scope_signal_fires_on_genuine_declarations() {
        let positive = [
            "- permissions: oauth tokens",
            "capabilities: oauth scope spreadsheets.readonly",
            "permissions: calendar.read",
            "capabilities: drive.file write",
            "permissions: slack messages.write",
            "capabilities: read/write to the user's vault",
        ];
        for sample in positive {
            assert!(
                has_oauth_scope_signal(&sample.to_ascii_lowercase()),
                "must classify genuine declaration as oauth-scopes: {sample:?}"
            );
        }
    }

    /// End-to-end pin: the public `explicit_declared_permission_rules`
    /// MUST NOT emit either `DECLARED_PERMISSION_SHELL_EXEC` or
    /// `DECLARED_PERMISSION_OAUTH_SCOPES` on prose that uses `"shell"`
    /// or `"scope"` only in their everyday English sense. Three such
    /// false positives pre-fix would have crossed
    /// `SCOPE_OVERPROVISIONING`'s threshold from a single benign block.
    #[test]
    fn explicit_declared_permission_rules_does_not_misclassify_benign_prose() {
        let benign = "\
# Capabilities

- This tool's scope is limited to read-only inspection.
- In a nutshell, no shell or browser access required.
- Permissions: nothing more than reading the file index.
";
        let rules = explicit_declared_permission_rules(benign);
        let ids: Vec<&str> = rules.iter().map(|(id, _, _)| *id).collect();
        assert!(
            !ids.contains(&"DECLARED_PERMISSION_SHELL_EXEC"),
            "benign prose MUST NOT trigger SHELL_EXEC; got rules={ids:?}"
        );
        assert!(
            !ids.contains(&"DECLARED_PERMISSION_OAUTH_SCOPES"),
            "benign prose MUST NOT trigger OAUTH_SCOPES; got rules={ids:?}"
        );
    }

    /// Contract: `DECLARED_PERMISSION_FILE_WRITE` MUST fire on canonical
    /// file-deletion declarations. Pre-fix the substring trigger was the
    /// nonsense `"delete work"` (apparent typo) which never matched any
    /// real artifact prose, so a skill that genuinely declared "delete
    /// files" or "delete file" silently slipped past the FileWrite gate.
    /// The replacement keeps both phrasings; pin them so a future
    /// tightening of the keyword list cannot silently drop the signal.
    #[test]
    fn file_write_signal_fires_on_genuine_file_deletion_declarations() {
        let positive = [
            "permissions: delete file from disk",
            "capabilities: delete files in the workspace",
            "- permissions: write files and delete file entries",
            "- capabilities: modify files; delete files when required",
        ];
        for sample in positive {
            let rules = explicit_declared_permission_rules(sample);
            let ids: Vec<&str> = rules.iter().map(|(id, _, _)| *id).collect();
            assert!(
                ids.contains(&"DECLARED_PERMISSION_FILE_WRITE"),
                "must classify genuine file-deletion declaration as FileWrite: {sample:?} \
                 (got rules={ids:?})"
            );
        }
    }

    /// Contract: `DECLARED_PERMISSION_FILE_WRITE` MUST NOT fire on prose
    /// that uses the verb "delete" against a non-filesystem noun. Pre-fix
    /// the substring trigger was `"delete work"`, so prose like
    /// `"delete work items in Jira"` or `"delete workflow steps"` falsely
    /// flagged FileWrite even though no filesystem mutation was implied.
    /// The fix narrows to `"delete file"` / `"delete files"` so unrelated
    /// "delete work …" prose no longer triggers the rule.
    #[test]
    fn file_write_signal_does_not_fire_on_delete_work_prose() {
        let benign = [
            "capabilities: delete work items from the Jira backlog",
            "permissions: delete workflow steps owned by the user",
            "- this skill helps delete work orders in the queue",
            "capabilities: delete workspace metadata via the API",
        ];
        for sample in benign {
            let rules = explicit_declared_permission_rules(sample);
            let ids: Vec<&str> = rules.iter().map(|(id, _, _)| *id).collect();
            assert!(
                !ids.contains(&"DECLARED_PERMISSION_FILE_WRITE"),
                "benign 'delete work …' prose MUST NOT trigger FileWrite: {sample:?} \
                 (got rules={ids:?})"
            );
        }
    }
}
