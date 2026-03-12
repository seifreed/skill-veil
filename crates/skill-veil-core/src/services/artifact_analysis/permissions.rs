pub(super) fn permission_context(content: &str) -> String {
    let mut buffer = String::new();
    let lines: Vec<_> = content.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("permission")
            || lower.contains("capabilit")
            || lower.starts_with("- ")
            || lower.starts_with("* ")
        {
            let start = index.saturating_sub(1);
            let end = (index + 3).min(lines.len());
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

pub(super) fn intent_context(content: &str) -> String {
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

pub(super) fn infer_declared_intent(content: &str) -> (&'static str, usize) {
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

pub(super) fn explicit_declared_permission_rules(
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
