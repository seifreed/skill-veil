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
        || context.contains("delete work")
    {
        rules.push((
            "DECLARED_PERMISSION_FILE_WRITE",
            "file write",
            "Artifact declares file modification or deletion capability",
        ));
    }
    if context.contains("shell")
        || context.contains("terminal command")
        || context.contains("run command")
        || context.contains("execute command")
        || context.contains("stdio")
    {
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
    if context.contains("oauth")
        || context.contains("scope")
        || context.contains("calendar")
        || context.contains("drive")
        || context.contains("slack")
        || context.contains("read/write")
    {
        rules.push((
            "DECLARED_PERMISSION_OAUTH_SCOPES",
            "oauth scopes",
            "Artifact declares OAuth scopes or broad SaaS permissions",
        ));
    }

    rules
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
}
