use crate::findings::{ArtifactScope, DeclaredPermission, Finding, FindingSummary};

pub(super) fn collect_explicit_permissions(findings: &[Finding]) -> Vec<DeclaredPermission> {
    let mut permissions = Vec::new();
    for finding in findings
        .iter()
        .filter(|f| f.artifact_scope == ArtifactScope::AgentEntrypoint)
    {
        if let Some(permission) = crate::findings::declared_permission_for_rule(&finding.rule_id) {
            if !permissions.contains(&permission) {
                permissions.push(permission);
            }
        }
    }
    permissions
}

pub(super) fn infer_permissions_from_keywords(
    findings: &[Finding],
    supporting_summary: &FindingSummary,
) -> Vec<DeclaredPermission> {
    // Only infer from declared-permission, capability, or official rules to avoid
    // false positives from broad generic rule substrings.
    let relevant: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.artifact_scope == ArtifactScope::AgentEntrypoint
                && (f.rule_id.starts_with("DECLARED_PERMISSION_")
                    || f.rule_id.starts_with("CAPABILITY_")
                    || f.rule_id.starts_with("OFFICIAL_"))
        })
        .collect();

    // Match keywords against match_value only (not rule_id/reason) to avoid false positives.
    let matches_any = |keywords: &[&str]| -> bool {
        relevant.iter().any(|f| {
            let text = f.match_value.to_ascii_lowercase();
            keywords.iter().any(|kw| text.contains(kw))
        })
    };

    let has_factor = |needle: &str| -> bool {
        supporting_summary
            .score_breakdown
            .iter()
            .any(|factor| factor.factor.contains(needle))
    };

    let mut permissions = Vec::new();
    let add_if = |permissions: &mut Vec<DeclaredPermission>, cond: bool, permission| {
        if cond && !permissions.contains(&permission) {
            permissions.push(permission);
        }
    };

    add_if(
        &mut permissions,
        matches_any(&[
            "browser",
            "navigation",
            "click any element",
            "full autonomous browser",
            "allow-all",
        ]),
        DeclaredPermission::BrowserFull,
    );
    // Natural-language synonyms for file modification / deletion. The
    // commit-47839ce fix introduced `delete file/files`; subsequent
    // synonyms (`remove`, `wipe`, `erase`, `unlink`) had been omitted,
    // letting a skill that declared "remove files from workspace"
    // escape inference. Symmetric with `detectors::permissions`.
    add_if(
        &mut permissions,
        matches_any(&[
            "write file",
            "delete file",
            "delete files",
            "modify file",
            "modify disk",
            "modify local",
            "remove file",
            "remove files",
            "wipe file",
            "wipe files",
            "erase file",
            "erase files",
            "unlink file",
            "unlink files",
        ]),
        DeclaredPermission::FileWrite,
    );
    add_if(
        &mut permissions,
        matches_any(&[
            "shell",
            "command",
            "run command",
            "execute command",
            "shell command",
            "stdio",
        ]) || has_factor("process_execution"),
        DeclaredPermission::ShellExec,
    );
    add_if(
        &mut permissions,
        matches_any(&[
            "http://",
            "https://",
            "webhook",
            "network",
            "api endpoint",
            "api access",
            "external api",
            "api_key",
        ]) || has_factor("network_access"),
        DeclaredPermission::NetworkAccess,
    );
    add_if(
        &mut permissions,
        matches_any(&[
            "token",
            "access_token",
            "api_token",
            "auth token",
            "bearer token",
            "secret",
            "password",
            "credential",
            "cookie",
        ]) || has_factor("secret_access"),
        DeclaredPermission::SecretsAccess,
    );
    add_if(
        &mut permissions,
        matches_any(&[
            "oauth",
            "oauth scope",
            "api scope",
            "drive.scope",
            "calendar.scope",
            "read/write",
            "admin scope",
            "google calendar",
            "calendar.events",
            "google drive",
            "drive.file",
            "slack.com",
            "slack api",
            "slack scope",
        ]),
        DeclaredPermission::OAuthScopes,
    );

    permissions
}

pub(super) fn derive_declared_permissions(
    findings: &[Finding],
    supporting_summary: &FindingSummary,
) -> Vec<DeclaredPermission> {
    let mut permissions = collect_explicit_permissions(findings);
    for perm in infer_permissions_from_keywords(findings, supporting_summary) {
        if !permissions.contains(&perm) {
            permissions.push(perm);
        }
    }
    permissions.sort();
    permissions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{MatchTarget, ThreatCategory};

    fn finding_with_match_value(rule_id: &str, match_value: &str) -> Finding {
        Finding::builder(rule_id, ThreatCategory::Generic)
            .matched_on(MatchTarget::Document)
            .match_value(match_value)
            .reason("test")
            .build()
    }

    /// Contract: `infer_permissions_from_keywords` MUST classify
    /// `match_value`s carrying genuine file-deletion phrases (`"delete
    /// file"`, `"delete files"`) as [`DeclaredPermission::FileWrite`].
    /// Pre-fix the keyword list contained the nonsense `"delete work"`
    /// (apparent typo), so a finding whose `match_value` was `"delete
    /// files"` never triggered the inferred FileWrite permission and the
    /// downstream verdict missed the file-mutation capability.
    #[test]
    fn infer_keywords_classifies_delete_file_phrases_as_file_write() {
        for value in ["delete file", "delete files"] {
            let findings = vec![finding_with_match_value("DECLARED_PERMISSION_X", value)];
            let permissions =
                infer_permissions_from_keywords(&findings, &FindingSummary::from_findings(&[]));
            assert!(
                permissions.contains(&DeclaredPermission::FileWrite),
                "match_value {value:?} MUST infer FileWrite; got {permissions:?}"
            );
        }
    }

    /// # Contract
    ///
    /// `infer_permissions_from_keywords` MUST classify natural-language
    /// synonyms for file modification / deletion (`remove`, `wipe`,
    /// `erase`, `unlink`) as [`DeclaredPermission::FileWrite`]. The
    /// previous fix only added `delete file/files`, leaving an asymmetric
    /// gap where a skill declaring `"remove files from workspace"` did
    /// not infer the FileWrite permission and the verdict layer missed
    /// the file-mutation capability.
    #[test]
    fn infer_keywords_classifies_file_write_synonyms() {
        for value in [
            "remove file",
            "remove files",
            "wipe file",
            "wipe files",
            "erase file",
            "erase files",
            "unlink file",
            "unlink files",
        ] {
            let findings = vec![finding_with_match_value("DECLARED_PERMISSION_X", value)];
            let permissions =
                infer_permissions_from_keywords(&findings, &FindingSummary::from_findings(&[]));
            assert!(
                permissions.contains(&DeclaredPermission::FileWrite),
                "match_value {value:?} MUST infer FileWrite; got {permissions:?}"
            );
        }
    }

    /// Contract: `infer_permissions_from_keywords` MUST NOT classify
    /// match values whose `"delete"` verb targets a non-filesystem noun
    /// as [`DeclaredPermission::FileWrite`]. Pre-fix the keyword
    /// `"delete work"` matched any prose containing that substring —
    /// `"delete work items"`, `"delete workflow steps"`,
    /// `"delete workspace"` — so unrelated workflow-management
    /// declarations falsely escalated the verdict to FileWrite.
    #[test]
    fn infer_keywords_does_not_classify_delete_work_prose_as_file_write() {
        for value in [
            "delete work items in the queue",
            "delete workflow steps owned by the user",
            "delete workspace metadata via the API",
        ] {
            let findings = vec![finding_with_match_value("DECLARED_PERMISSION_X", value)];
            let permissions =
                infer_permissions_from_keywords(&findings, &FindingSummary::from_findings(&[]));
            assert!(
                !permissions.contains(&DeclaredPermission::FileWrite),
                "match_value {value:?} MUST NOT infer FileWrite; got {permissions:?}"
            );
        }
    }
}
