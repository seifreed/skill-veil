use super::condition::RuleCondition;
use crate::findings::{RecommendedAction, Severity, TaxonomyTag, ThreatCategory};
use serde::{Deserialize, Serialize};

/// Shield hint for policy generation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShieldHint {
    /// Scope for the shield policy
    pub scope: String,
}

/// A security detection rule
///
/// Rules define security patterns to detect in skill documents. Each rule
/// specifies a condition to match, the threat category, severity level, and
/// recommended action when matched.
///
/// Rules are typically defined in YAML format and loaded by the [`super::RuleEngine`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Unique rule identifier
    pub id: String,
    /// Threat category
    pub category: ThreatCategory,
    /// Severity level
    pub severity: Severity,
    /// Confidence score (0.0 - 1.0)
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    /// Condition that triggers the rule
    #[serde(rename = "when")]
    pub condition: RuleCondition,
    /// Recommended action
    pub action: RecommendedAction,
    /// Human-readable reason
    pub reason: String,
    /// Shield policy hint
    #[serde(default)]
    pub shield: Option<ShieldHint>,
    /// Whether the rule is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Tags for filtering
    #[serde(default)]
    pub tags: Vec<String>,
    /// Named threat-taxonomy labels (e.g. `memory_poisoning`,
    /// `system_prompt_leakage`). Orthogonal to `category`: propagated onto
    /// findings for demonstrable coverage in JSON/SARIF, never feeds scoring.
    #[serde(default)]
    pub taxonomy_tags: Vec<TaxonomyTag>,
    /// Optional list of upstream PromptIntel threat names this rule
    /// covers (e.g. `["Jailbreak", "Hidden instruction in code or
    /// comments"]`). Used by the `promptintel coverage` command to
    /// build a per-threat audit table; left empty for rules that do
    /// not target prompt-layer attacks. Validation against the
    /// canonical taxonomy happens in the CLI, not at parse time, so
    /// an upstream rename does not brick rule loading.
    #[serde(default)]
    pub promptintel_threats: Vec<String>,
    /// When `true`, a regex match in the SKILL.md prose body that is
    /// NOT corroborated by an occurrence inside any markdown code
    /// block is downgraded from the rule's natural action /
    /// signal-class to `RequireApproval` / `ReviewSignal`. Used for
    /// vocabulary-only rules (`SKILL_PAYMENT_ACCESS`,
    /// `SKILL_TOKEN_SCAM`, …) that legitimately fire on documentation
    /// or coaching skills which only DESCRIBE the pattern they
    /// detect. Cross-LLM triage on a 4000-skill VT-clean corpus
    /// confirmed prose-only matches drive ~30-50 FPs per affected
    /// rule.
    ///
    /// Defaults to `false` — opt-in per rule, never global. The
    /// downgrade applies AFTER the regex matched; matches inside
    /// code blocks (or in any artifact whose `MatchTarget` is
    /// `CodeBlock` / `ReferencedFile`) keep full strength.
    #[serde(default)]
    pub requires_code_artifact: bool,

    /// When `true`, a finding is downgraded if the surrounding
    /// document contains explicit human-in-the-loop confirmation
    /// gate markers (e.g. `confirmation_token`, "user types YES",
    /// "two-step gate", "propose → user"). Used for autonomy /
    /// payment / deferred-execution rules whose risk model assumes
    /// no human gate. Cross-LLM triage on a 4000-skill VT-clean
    /// corpus showed `okx-trading`-style skills with strict
    /// propose→confirm workflows trip these rules even though the
    /// gate is exactly the safety control the rule was designed to
    /// require.
    ///
    /// Defaults to `false`. Marker list lives in
    /// `compiled::CONFIRMATION_GATE_MARKERS` and is intentionally
    /// case-insensitive so authors don't have to predict the exact
    /// phrasing.
    #[serde(default)]
    pub downgrade_when_confirmation_gate: bool,

    /// When `true`, a finding is downgraded if the document declares
    /// itself as an educational / detection / anti-pattern catalogue
    /// (e.g. `## What it checks`, `## Anti-patterns`, "this skill
    /// detects", "examples of bad code"). Used for vocabulary
    /// rules whose patterns appear in security scanners that
    /// document the very behaviours they detect.
    ///
    /// Defaults to `false`. Marker list lives in
    /// `compiled::DOCUMENTATION_CONTEXT_MARKERS`.
    #[serde(default)]
    pub downgrade_when_documentation_context: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RulePackKind {
    Official,
    Community,
    IocFeed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RulePackMetadata {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub kind: Option<RulePackKind>,
    #[serde(default)]
    pub compatibility: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulePackFile {
    pub schema_version: String,
    #[serde(default)]
    pub metadata: RulePackMetadata,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct IocFeedFile {
    pub schema_version: String,
    #[serde(default)]
    pub metadata: RulePackMetadata,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub filenames: Vec<String>,
    #[serde(default)]
    pub ips: Vec<String>,
}

fn default_confidence() -> f32 {
    super::DEFAULT_RULE_CONFIDENCE
}

fn default_enabled() -> bool {
    true
}

#[cfg(test)]
mod deny_unknown_fields_tests {
    use super::*;

    /// # Contract
    ///
    /// `Rule` MUST reject unknown fields so that typos in optional fields
    /// (e.g. `confedence` instead of `confidence`, `enabeld` instead of
    /// `enabled`) produce a clear error rather than silently falling back
    /// to defaults. Pre-fix, `#[serde(deny_unknown_fields)]` was absent,
    /// so a rule pack author who wrote `confedence: 0.5` got a rule firing
    /// at confidence 0.9 (the default) with no error or warning.
    #[test]
    fn rule_rejects_unknown_fields() {
        let yaml = r#"
id: TEST_RULE
category: RemoteExec
severity: High
when:
  regex:
    pattern: "curl"
action: Block
reason: test
confedence: 0.5
"#;
        let result: Result<Rule, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_err(),
            "Rule MUST reject unknown field 'confedence'; \
             pre-fix, this was silently accepted and confidence defaulted to 0.9"
        );
    }

    /// # Contract
    ///
    /// `ShieldHint` MUST reject unknown fields so that typos like
    /// `scop` instead of `scope` are caught at load time.
    #[test]
    fn shield_hint_rejects_unknown_fields() {
        let yaml = "scop: package\n";
        let result: Result<ShieldHint, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_err(),
            "ShieldHint MUST reject unknown field 'scop'; \
             pre-fix, this was silently accepted and scope was missing"
        );
    }

    /// # Contract
    ///
    /// `RulePackFile` MUST reject unknown fields so that typos in
    /// top-level keys (e.g. `ruels` instead of `rules`) are caught.
    #[test]
    fn rule_pack_file_rejects_unknown_fields() {
        let yaml = "schema_version: \"1\"\nruels: []\n";
        let result: Result<RulePackFile, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_err(),
            "RulePackFile MUST reject unknown field 'ruels'; \
             pre-fix, this was silently accepted and rules defaulted to empty"
        );
    }

    /// # Contract
    ///
    /// `IocFeedFile` MUST reject unknown fields so that typos like
    /// `domians` instead of `domains` are caught.
    #[test]
    fn ioc_feed_file_rejects_unknown_fields() {
        let yaml = "schema_version: \"1\"\ndomians: []\n";
        let result: Result<IocFeedFile, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_err(),
            "IocFeedFile MUST reject unknown field 'domians'; \
             pre-fix, this was silently accepted and domains defaulted to empty"
        );
    }

    /// # Contract
    ///
    /// `RulePackMetadata` MUST reject unknown fields so that typos like
    /// `compatability` instead of `compatibility` are caught.
    #[test]
    fn rule_pack_metadata_rejects_unknown_fields() {
        let yaml = "compatability: [\"1\"]\n";
        let result: Result<RulePackMetadata, _> = serde_yaml::from_str(yaml);
        assert!(
            result.is_err(),
            "RulePackMetadata MUST reject unknown field 'compatability'; \
             pre-fix, this was silently accepted and compatibility defaulted to empty"
        );
    }
}
