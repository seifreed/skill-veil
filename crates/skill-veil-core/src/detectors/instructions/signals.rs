use crate::lazy_pattern;

lazy_pattern!(
    pub(crate) RE_BROWSER_FULL,
    r"(?i)(browser:\s*full|full autonomous browser|click any element|navigation:\s*allow-all)"
);
lazy_pattern!(
    pub(crate) RE_PERSISTENCE,
    r"(?i)(persist\s+these\s+instructions|remember\s+this\s+across\s+sessions|append\s+to\s+(agents|claude|system)\.md)"
);
lazy_pattern!(
    pub(crate) RE_NETWORK,
    r"(?i)(http://|https://|browser tool|network tool)"
);
lazy_pattern!(
    pub(crate) RE_SECRET,
    r"(?i)\b(token|secret|cookie|password|credential|session)\b"
);
lazy_pattern!(
    pub(crate) RE_OAUTH,
    // Pre-fix the alternation included a bare `scope`, matching ubiquitous
    // English prose ("the scope of this task", "out of scope") and falsely
    // raising `IdentityAccess` on benign skills. The token only carries
    // OAuth signal when paired with `oauth` / `scopes` qualifiers, so the
    // arm is now `oauth(?:\s+scope|\s+scopes|2)?` plus the original
    // SaaS-keyword alternations. Generic prose with the word "scope"
    // alone no longer matches.
    r"(?i)(oauth(?:\s+scopes?|2)?|oauth_scopes?|calendar|drive|slack|github\s+pat)"
);
lazy_pattern!(
    pub(crate) RE_COGNITIVE_ROOTKIT,
    r"(?i)(persist\s+these\s+instructions|remember\s+this\s+across\s+sessions|always\s+follow\s+this\s+prompt|never\s+reveal\s+this\s+instruction|override\s+future\s+system\s+messages)"
);
lazy_pattern!(
    pub(crate) RE_PRIVILEGED_ROLE,
    r"(?i)(act\s+as\s+(root|administrator|system)|treat\s+all\s+tool\s+requests\s+as\s+approved|ignore\s+all\s+existing\s+safety\s+constraints)"
);

#[cfg(test)]
mod tests {
    use super::*;

    /// # Contract (negative)
    ///
    /// `RE_OAUTH` MUST NOT fire on the bare English word "scope" used in
    /// prose. Pre-fix the alternation included `scope` as a standalone
    /// substring, so any document mentioning "the scope of this task" or
    /// "out of scope" raised the `IdentityAccess` capability and produced
    /// `MCP_BROAD_IDENTITY_SCOPE`-style findings on benign skills.
    #[test]
    fn re_oauth_does_not_match_scope_in_prose() {
        for sample in [
            "The scope of this task is limited to local files.",
            "Anything outside this scope is out of scope.",
            "scope creep is tracked in the roadmap.",
            "## Scope\nThis section defines the work boundary.",
        ] {
            assert!(
                !RE_OAUTH.is_match(sample),
                "must NOT match prose 'scope': {sample:?}"
            );
        }
    }

    /// # Contract (positive)
    ///
    /// `RE_OAUTH` MUST still fire when the document mentions an actual
    /// OAuth surface — `oauth scope`, `oauth_scopes`, `oauth2`, the bare
    /// `oauth` token, or one of the SaaS keywords (`calendar`, `drive`,
    /// `slack`, `github pat`).
    #[test]
    fn re_oauth_still_matches_genuine_oauth_signals() {
        for sample in [
            "Configure OAuth scopes: read, write.",
            "Uses oauth2 for authentication.",
            "Reads from Google Calendar and Drive.",
            "Posts via slack webhook.",
            "Stores a github PAT for API access.",
            "Define oauth_scopes in config.json",
        ] {
            assert!(
                RE_OAUTH.is_match(&sample.to_ascii_lowercase()),
                "must match genuine OAuth/SaaS signal: {sample:?}"
            );
        }
    }
}
