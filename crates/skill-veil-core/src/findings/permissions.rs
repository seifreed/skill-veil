use serde::{Deserialize, Serialize};
use strum_macros::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum DeclaredPermission {
    BrowserFull,
    FileWrite,
    ShellExec,
    NetworkAccess,
    SecretsAccess,
    OAuthScopes,
}

/// Canonical mapping from rule IDs to declared permissions.
///
/// Single source of truth used by `derive_declared_permissions` in
/// `verdict.rs` and `is_permission_model_rule` in `verdict_calibration.rs`.
pub const DECLARED_PERMISSION_RULES: &[(&str, DeclaredPermission)] = &[
    (
        "DECLARED_PERMISSION_BROWSER_FULL",
        DeclaredPermission::BrowserFull,
    ),
    (
        "DECLARED_PERMISSION_FILE_WRITE",
        DeclaredPermission::FileWrite,
    ),
    (
        "DECLARED_PERMISSION_SHELL_EXEC",
        DeclaredPermission::ShellExec,
    ),
    (
        "DECLARED_PERMISSION_NETWORK_ACCESS",
        DeclaredPermission::NetworkAccess,
    ),
    (
        "DECLARED_PERMISSION_SECRETS_ACCESS",
        DeclaredPermission::SecretsAccess,
    ),
    (
        "DECLARED_PERMISSION_OAUTH_SCOPES",
        DeclaredPermission::OAuthScopes,
    ),
];

/// Look up the declared permission for a given rule ID.
pub fn declared_permission_for_rule(rule_id: &str) -> Option<DeclaredPermission> {
    DECLARED_PERMISSION_RULES
        .iter()
        .find(|(id, _)| *id == rule_id)
        .map(|(_, perm)| *perm)
}

/// Check whether a rule ID corresponds to a declared permission rule.
pub fn is_declared_permission_rule(rule_id: &str) -> bool {
    DECLARED_PERMISSION_RULES
        .iter()
        .any(|(id, _)| *id == rule_id)
}
